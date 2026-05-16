from flask import Flask, render_template, request, redirect, url_for, session, make_response, flash, jsonify, Response
import pyotp
import requests
from requests.exceptions import RequestException
import base64
import re
import os
import logging
from functools import wraps
from urllib.parse import urljoin, urlparse, quote, urlunparse
from config import Config
from users import (
    get_user, verify_password, is_admin, is_super_admin, add_user, 
    update_user, delete_user, get_all_users
)
from generate_totp import generate_totp_secret, generate_qr_code
from captcha import generate_captcha_text, generate_captcha_image
from database import init_db
from notification import send_login_notification

if Config.LOG_ENABLED:
    os.makedirs(Config.LOG_DIR, exist_ok=True)
    
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[]
    )
    
    file_handler = logging.FileHandler(Config.LOG_FILE, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    
    error_file_handler = logging.FileHandler(Config.ERROR_LOG_FILE, encoding='utf-8')
    error_file_handler.setLevel(logging.WARNING)
    error_file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    
    login_file_handler = logging.FileHandler(Config.LOGIN_LOG_FILE, encoding='utf-8')
    login_file_handler.setLevel(logging.INFO)
    login_file_handler.setFormatter(logging.Formatter(
        '%(asctime)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    
    logger = logging.getLogger()
    logger.handlers = []
    logger.addHandler(file_handler)
    logger.addHandler(error_file_handler)
    logger.addHandler(console_handler)
    
    login_logger = logging.getLogger('login')
    login_logger.handlers = []
    login_logger.addHandler(login_file_handler)
    login_logger.propagate = False
else:
    logger = None
    login_logger = None

app = Flask(__name__)
app.config.from_object(Config)

init_db(app)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('user_login'))
        return f(*args, **kwargs)
    return decorated_function

def log_login_event(username, success=True, message='', request=None):
    """记录登录事件"""
    if not Config.LOG_ENABLED or not login_logger:
        return
    
    if not success:
        return
    
    client_ip = 'unknown'
    user_agent = 'unknown'
    accept_language = 'unknown'
    
    if request:
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown')
        if client_ip and ',' in client_ip:
            client_ip = client_ip.split(',')[0].strip()
        
        user_agent = request.headers.get('User-Agent', 'unknown')
        accept_language = request.headers.get('Accept-Language', 'unknown')
        
        if len(user_agent) > 200:
            user_agent = user_agent[:200] + '...'
    
    log_message = f"{username} | {client_ip} | {user_agent} | {accept_language} | {message}"
    login_logger.info(log_message)

def is_authenticated():
    return 'username' in session and session.get('totp_verified')

@app.route('/')
def index():
    if 'username' in session and session.get('totp_verified'):
        return redirect(url_for('systems'))
    return redirect(url_for('user_login'))

@app.route('/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        captcha = request.form.get('captcha', '').lower()
        
        if session.get('captcha_text', '').lower() != captcha:
            flash('验证码错误', 'error')
            return render_template('login.html')
        
        if is_admin(username):
            flash('管理员请通过管理后台登录', 'error')
            return render_template('login.html')
        
        user = get_user(username)
        if not user:
            flash('用户名不存在', 'error')
            return render_template('login.html')
        
        if not verify_password(user.password, password):
            flash('密码错误', 'error')
            return render_template('login.html')
        
        session['username'] = username
        session['user_id'] = user.id
        
        log_login_event(username, success=True, message='用户登录成功', request=request)
        
        return redirect(url_for('verify_totp'))
    
    session['captcha_text'] = generate_captcha_text()
    return render_template('login.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not is_admin(username):
            flash('用户名或密码错误', 'error')
            return render_template('admin_login.html')
        
        user = get_user(username)
        if not user:
            flash('用户名或密码错误', 'error')
            return render_template('admin_login.html')
        
        if not verify_password(user.password, password):
            flash('用户名或密码错误', 'error')
            return render_template('admin_login.html')
        
        session['username'] = username
        session['user_id'] = user.id
        
        log_login_event(username, success=True, message='管理员登录成功', request=request)
        
        return redirect(url_for('admin'))
    
    return render_template('admin_login.html')

@app.route('/verify_totp', methods=['GET', 'POST'])
def verify_totp():
    if 'username' not in session:
        return redirect(url_for('user_login'))
    
    user = get_user(session['username'])
    if not user:
        return redirect(url_for('user_login'))
    
    if request.method == 'POST':
        totp_code = request.form.get('totp_code', '').strip()
        
        if len(totp_code) != 6:
            flash('动态码必须是6位数字', 'error')
            return render_template('verify_totp.html')
        
        totp = pyotp.TOTP(user.totp_secret)
        try:
            if totp.verify(totp_code, valid_window=1):
                session['totp_verified'] = True
                flash('动态码验证成功', 'success')
                # 记录登录日志
                log_login_event(username=session['username'], success=True, message='2FA 验证成功', request=request)
                # 发送登录通知
                send_login_notification(username=session['username'], request=request, success=True, message='2FA 验证成功')
                return redirect(url_for('systems'))
            else:
                flash('动态码错误', 'error')
        except Exception as e:
            flash('动态码验证失败', 'error')
            if logger:
                logger.error(f"TOTP 验证异常: {str(e)}")
    
    return render_template('verify_totp.html')

@app.route('/systems')
@login_required
def systems():
    if not session.get('totp_verified'):
        return redirect(url_for('verify_totp'))
    return render_template('systems.html', systems=Config.SYSTEMS)

@app.route('/admin')
@login_required
def admin():
    if not is_admin(session.get('username')):
        return redirect(url_for('systems'))
    
    users = get_all_users()
    return render_template('admin.html', users=users, is_super_admin=is_super_admin(session.get('username')))

@app.route('/admin/add_user', methods=['POST'])
@login_required
def admin_add_user():
    if not is_super_admin(session.get('username')):
        return jsonify({'success': False, 'message': '无权限'}), 403
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    name = data.get('name', '')
    
    if not username or not password:
        return jsonify({'success': False, 'message': '用户名和密码不能为空'})
    
    if get_user(username):
        return jsonify({'success': False, 'message': '用户名已存在'})
    
    totp_secret = generate_totp_secret()
    qr_code = generate_qr_code(username, totp_secret)
    
    success = add_user(username, password, totp_secret, name=name)
    if success:
        return jsonify({
            'success': True, 
            'message': '用户添加成功',
            'qr_code': qr_code
        })
    else:
        return jsonify({'success': False, 'message': '添加失败'})

@app.route('/admin/reset_totp/<int:user_id>', methods=['POST'])
@login_required
def admin_reset_totp(user_id):
    if not is_super_admin(session.get('username')):
        return jsonify({'success': False, 'message': '无权限'}), 403
    
    user = get_user(None, user_id)
    if not user:
        return jsonify({'success': False, 'message': '用户不存在'}), 404
    
    new_secret = generate_totp_secret()
    new_qr_code = generate_qr_code(user.username, new_secret)
    
    success = update_user(user_id, totp_secret=new_secret)
    if success:
        return jsonify({
            'success': True,
            'message': 'TOTP 已重置',
            'qr_code': new_qr_code
        })
    else:
        return jsonify({'success': False, 'message': '重置失败'}), 500

def get_system_by_prefix(prefix):
    for system in Config.SYSTEMS:
        if system.get('prefix') == prefix:
            return system
    return None

def proxy_request(prefix, path):
    system = get_system_by_prefix(prefix)
    if not system:
        if logger:
            logger.warning(f"未找到系统: prefix={prefix}")
        return "System not found", 404
    
    base_url = system.get('base_url', '').rstrip('/')
    target_path = path.lstrip('/') if path else ''
    target_url = f"{base_url}/{target_path}" if target_path else base_url
    
    if logger:
        logger.debug(f"代理请求: prefix={prefix}, path={path}, method={request.method}")
        logger.debug(f"目标URL: `{target_url}`")
    
    try:
        headers = {key: value for key, value in request.headers if key.lower() not in ['host', 'connection']}
        headers['X-Forwarded-Host'] = request.host
        headers['X-Forwarded-For'] = request.remote_addr
        headers['X-Forwarded-Proto'] = request.scheme
        
        if request.method in ['POST', 'PUT', 'PATCH']:
            response = requests.request(
                method=request.method,
                url=target_url,
                headers=headers,
                data=request.get_data(),
                cookies=request.cookies,
                allow_redirects=False,
                timeout=30,
                stream=True
            )
        else:
            response = requests.request(
                method=request.method,
                url=target_url,
                headers=headers,
                cookies=request.cookies,
                allow_redirects=False,
                timeout=30,
                stream=True
            )
        
        if logger:
            logger.debug(f"`{target_url}` \"{request.method} /{path} HTTP/1.1\" {response.status_code} {response.headers.get('Content-Length', 'None')}")
        
        if response.status_code in [301, 302, 303, 307, 308]:
            location = response.headers.get('Location')
            if location:
                if logger:
                    logger.debug(f"重定向 {response.status_code}: {location}")
                
                parsed_location = urlparse(location)
                
                if not parsed_location.scheme:
                    gateway_path = f"/{prefix}"
                    if target_path:
                        gateway_path += f"/{target_path}"
                    
                    if parsed_location.path:
                        path_parts = parsed_location.path.rstrip('/').split('/')
                        if path_parts[-1] == '' or '.' not in path_parts[-1]:
                            new_path = parsed_location.path.rstrip('/') if parsed_location.path != '/' else ''
                        else:
                            new_path = parsed_location.path
                        
                        if new_path.startswith('/'):
                            location = f"/{prefix}{new_path}"
                        else:
                            location = f"/{prefix}/{new_path}"
                    else:
                        location = gateway_path
                    
                    if parsed_location.query:
                        location += f"?{parsed_location.query}"
                
                if logger:
                    logger.debug(f"转换后重定向: {location}")
                
                response.headers['Location'] = location
        
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        resp_headers = {key: value for key, value in response.headers.items() 
                       if key.lower() not in excluded_headers}
        
        if response.status_code == 200 and 'text/html' in response.headers.get('Content-Type', ''):
            content = response.content
            gateway_base = f"{request.scheme}://{request.host}/{prefix}"
            current_page_path = f"/{target_path}" if target_path else "/"
            if not current_page_path.endswith('/'):
                current_page_path += '/'
            
            def fix_paths(match):
                attr = match.group(1)
                quote_char = match.group(2)
                value = match.group(3)
                
                if attr in ['integrity', 'crossorigin']:
                    return match.group(0)
                
                if attr in ['src', 'href', 'action', 'srcset', 'data-src']:
                    if '?' in value:
                        path_part, query_part = value.split('?', 1)
                        query_part = '?' + query_part
                    else:
                        path_part = value
                        query_part = ''
                    
                    if path_part.startswith(gateway_base):
                        return match.group(0)
                    
                    if path_part.startswith('/') and not path_part.startswith(gateway_base):
                        return f'{attr}={quote_char}{gateway_base}{path_part}{query_part}{quote_char}'
                    elif not path_part.startswith('/') and not path_part.startswith('http') and not path_part.startswith('data:') and not path_part.startswith('#') and not path_part.startswith('mailto:'):
                        base_dir = current_page_path.rstrip('/')
                        
                        if base_dir:
                            new_path = f'{base_dir}/{path_part}{query_part}'
                        else:
                            new_path = f'/{path_part}{query_part}'
                        return f'{attr}={quote_char}{gateway_base}{new_path}{quote_char}'
                return match.group(0)
            
            content_str = content.decode('utf-8', errors='replace')
            
            content_str = re.sub(
                r'(src|href|action|srcset|data-src)=([\'"])([^"\'\s]+)\2',
                fix_paths,
                content_str
            )
            
            base_pattern = rf'<base\s+href=([\'"])([^"\']*)\1'
            base_match = re.search(base_pattern, content_str)
            if base_match:
                base_href = base_match.group(2)
                if logger:
                    logger.debug(f"发现 base href: {base_href}")
            
            content = content_str.encode('utf-8')
            resp_headers['Content-Length'] = str(len(content))
            
            if logger:
                logger.debug(f"已修复内容中的相对路径")
        
        return Response(response.content, response.status_code, resp_headers)
        
    except RequestException as e:
        if logger:
            logger.error(f"代理请求失败: {str(e)}")
        return f"Proxy error: {str(e)}", 502
    except Exception as e:
        if logger:
            logger.error(f"代理异常: {str(e)}")
        return f"Proxy error: {str(e)}", 500

@app.route('/<prefix>/<path:path>')
@login_required
def proxy_with_path(prefix, path):
    return proxy_request(prefix, path)

@app.route('/<prefix>/')
@login_required
def proxy_root(prefix):
    return proxy_request(prefix, '')