from flask import Flask, render_template, request, redirect, url_for, session, make_response, flash, jsonify
import pyotp
import requests
import base64
import re
import os
import logging
from functools import wraps
from urllib.parse import urljoin, urlparse, quote
from config import Config
from users import (
    get_user, verify_password, is_admin, is_super_admin, add_user, 
    update_user, delete_user, get_all_users
)
from generate_totp import generate_totp_secret, generate_qr_code
from captcha import generate_captcha_text, generate_captcha_image
from database import init_db

# 日志配置
if Config.LOG_ENABLED:
    os.makedirs(Config.LOG_DIR, exist_ok=True)
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(Config.LOG_FILE, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    logger = logging.getLogger(__name__)
else:
    logger = None

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY

@app.before_request
def log_request():
    """每个请求前打印日志"""
    print(f"[DEBUG] 收到请求: {request.method} {request.path}")
    if Config.LOG_ENABLED:
        import logging
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.DEBUG)

# 初始化数据库
init_db(app)

def find_system_by_prefix(prefix):
    """根据路径前缀查找系统配置"""
    for system in Config.SYSTEMS:
        if system["prefix"] == prefix:
            return system
    return None

def rewrite_html_content(html_content, prefix, is_css=False):
    """重写内容中的路径，添加系统前缀"""
    if not html_content:
        return html_content
    
    if is_css:
        # 处理 CSS 中的 url()
        # 绝对路径
        pattern_css_absolute = r'url\(\s*["\']?(/[^"\')\s]+)["\']?\s*\)'
        def replace_css_absolute_path(match):
            path = match.group(1)
            # 对路径进行 URL 编码
            encoded_path = quote(path, safe='/')
            return f'url("/{prefix}{encoded_path}")'
        
        # 相对路径
        pattern_css_relative = r'url\(\s*["\']?((?!(?:https?:|/|data:))[^"\')\s]+)["\']?\s*\)'
        def replace_css_relative_path(match):
            path = match.group(1)
            # 对路径进行 URL 编码
            encoded_path = quote(path, safe='/')
            return f'url("/{prefix}/{encoded_path}")'
        
        rewritten = re.sub(pattern_css_absolute, replace_css_absolute_path, html_content)
        rewritten = re.sub(pattern_css_relative, replace_css_relative_path, rewritten)
        return rewritten
    
    # 需要重写的 HTML 属性列表
    attributes = [
        'href', 'src', 'action', 'content',
        'data-src', 'data-href', 'data-url'
    ]
    
    # 先处理绝对路径（以 / 开头）
    pattern_absolute = r'(' + '|'.join(attributes) + r')\s*=\s*["\'](/[^"\'\s]+)["\']'
    
    def replace_absolute_path(match):
        attr = match.group(1)
        path = match.group(2)
        # 对路径进行 URL 编码
        encoded_path = quote(path, safe='/')
        return f'{attr}="/{prefix}{encoded_path}"'
    
    # 再处理相对路径（不以 /、http、https、#、javascript: 开头）
    pattern_relative = r'(' + '|'.join(attributes) + r')\s*=\s*["\']((?!(?:https?:|/|#|javascript:))[^"\'\s]+)["\']'
    
    def replace_relative_path(match):
        attr = match.group(1)
        path = match.group(2)
        # 对路径进行 URL 编码
        encoded_path = quote(path, safe='/')
        return f'{attr}="/{prefix}/{encoded_path}"'
    
    # 先替换绝对路径，再替换相对路径
    rewritten = re.sub(pattern_absolute, replace_absolute_path, html_content)
    rewritten = re.sub(pattern_relative, replace_relative_path, rewritten)
    
    return rewritten

def is_authenticated():
    return session.get('authenticated') == True

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_authenticated():
            return redirect(url_for('admin_login'))
        if not is_admin(session.get('username')):
            flash('您没有权限访问此页面', 'error')
            return redirect(url_for('user_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/', methods=['GET', 'POST'])
def user_login():
    # 已认证用户显示系统列表
    if is_authenticated() and not is_admin(session.get('username')):
        username = session.get('username')
        return render_template('systems.html', systems=Config.SYSTEMS, username=username)
    
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        totp_code = request.form.get('totp_code', '').strip()
        
        if not username or not totp_code:
            error = '请填写所有字段'
        else:
            user = get_user(username)
            if not user:
                error = '用户名不存在'
            elif user.get('is_admin', False):
                error = '管理员账户请从后台登录'
            else:
                totp = pyotp.TOTP(user['totp_secret'])
                if totp.verify(totp_code, valid_window=1):
                    session['authenticated'] = True
                    session['username'] = username
                    return render_template('systems.html', systems=Config.SYSTEMS, username=username)
                else:
                    error = '验证码错误或已过期'
    
    return render_template('login.html', error=error)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if is_authenticated() and is_admin(session.get('username')):
        return redirect(url_for('admin'))
    
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        captcha_code = request.form.get('captcha_code', '').strip()
        
        if not username or not password or not captcha_code:
            error = '请填写所有字段'
        elif session.get('captcha_code', '').upper() != captcha_code.upper():
            error = '图形验证码错误'
            session.pop('captcha_code', None)
        else:
            user = get_user(username)
            if user and user.get('is_admin', False):
                if verify_password(username, password):
                    session['authenticated'] = True
                    session['username'] = username
                    session.pop('captcha_code', None)
                    return redirect(url_for('admin'))
                else:
                    error = '密码错误'
            else:
                error = '管理员用户名或密码错误'
    
    return render_template('admin_login.html', error=error)

@app.route('/admin/captcha')
def admin_captcha():
    text = generate_captcha_text(4)
    session['captcha_code'] = text
    img_base64 = generate_captcha_image(text)
    img_data = base64.b64decode(img_base64)
    response = make_response(img_data)
    response.headers['Content-Type'] = 'image/png'
    return response

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('user_login'))

@app.route('/admin')
@admin_required
def admin():
    users = get_all_users()
    return render_template('admin.html', users=users)

@app.route('/admin/users', methods=['POST'])
@admin_required
def create_user():
    username = request.form.get('username', '').strip()
    name = request.form.get('name', '').strip()
    password = request.form.get('password', '').strip()
    is_sub_admin = request.form.get('is_sub_admin', '0') == '1'
    current_user = session.get('username')
    
    if not username or not name:
        flash('请填写所有必填字段', 'error')
        return redirect(url_for('admin'))
    
    if get_user(username):
        flash('用户名已存在', 'error')
        return redirect(url_for('admin'))
    
    if is_sub_admin and not is_super_admin(current_user):
        flash('只有超级管理员可以创建子管理员', 'error')
        return redirect(url_for('admin'))
    
    if is_sub_admin and not password:
        flash('创建子管理员必须设置密码', 'error')
        return redirect(url_for('admin'))
    
    user_data = {
        'password': password,
        'totp_secret': generate_totp_secret() if not is_sub_admin else None,
        'name': name,
        'is_admin': is_sub_admin,
        'is_super_admin': False
    }
    
    add_user(username, user_data)
    
    if is_sub_admin:
        flash(f'子管理员 {username} 创建成功', 'success')
        return redirect(url_for('admin'))
    else:
        qr_base64, _ = generate_qr_code(username, user_data['totp_secret'])
        flash(f'用户 {username} 创建成功', 'success')
        return render_template('admin.html', 
                             users=get_all_users(),
                             new_user_qr=qr_base64,
                             new_user_secret=user_data['totp_secret'],
                             new_user_username=username)

@app.route('/admin/users/<username>', methods=['DELETE'])
@admin_required
def delete_user_route(username):
    current_user = session.get('username')
    
    if username == 'admin':
        return jsonify({'error': '不能删除内置管理员'}), 400
    
    target_user = get_user(username)
    if not target_user:
        return jsonify({'error': '用户不存在'}), 404
    
    if target_user.get('is_admin') and not is_super_admin(current_user):
        return jsonify({'error': '只有超级管理员可以删除管理员账户'}), 403
    
    if delete_user(username):
        return jsonify({'success': True})
    return jsonify({'error': '删除失败'}), 400

@app.route('/admin/users/<username>/totp', methods=['POST'])
@admin_required
def reset_totp(username):
    current_user = session.get('username')
    target_user = get_user(username)
    
    if not target_user:
        return jsonify({'error': '用户不存在'}), 404
    
    if target_user.get('is_admin') and not is_super_admin(current_user):
        return jsonify({'error': '只有超级管理员可以重置管理员账户的动态码'}), 403
    
    new_secret = generate_totp_secret()
    update_user(username, {'totp_secret': new_secret})
    
    qr_base64, _ = generate_qr_code(username, new_secret)
    
    return jsonify({
        'success': True,
        'secret': new_secret,
        'qr_code': f'data:image/png;base64,{qr_base64}'
    })

@app.route('/<prefix>', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'], strict_slashes=False)
@app.route('/<prefix>/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'], strict_slashes=False)
def proxy(prefix, path):
    print(f"[PROXY] 函数被调用: prefix={prefix}, path={path}")
    
    if logger:
        logger.debug(f"代理请求: prefix={prefix}, path={path}, method={request.method}")
    
    if not is_authenticated():
        return redirect(url_for('user_login'))
    
    if is_admin(session.get('username')):
        return redirect(url_for('admin'))
    
    # 查找系统配置
    system = find_system_by_prefix(prefix)
    if not system:
        if logger:
            logger.debug(f"系统不存在: {prefix}")
        return '系统不存在', 404
    
    target_url = urljoin(f"{system['base_url']}/", path)
    if logger:
        logger.debug(f"目标URL: {target_url}")
    
    if request.query_string:
        target_url += '?' + request.query_string.decode('utf-8')
    
    try:
        headers = {key: value for key, value in request.headers if key.lower() not in ['host', 'content-length']}
        cms_host = urlparse(system['base_url']).netloc
        headers['Host'] = cms_host
        
        # 手动处理重定向，最多跟随3次
        max_redirects = 3
        redirect_count = 0
        
        while redirect_count < max_redirects:
            if request.method == 'GET':
                resp = requests.get(target_url, headers=headers, cookies=request.cookies, timeout=30, allow_redirects=False)
            elif request.method == 'POST':
                resp = requests.post(target_url, headers=headers, data=request.get_data(), cookies=request.cookies, timeout=30, allow_redirects=False)
            elif request.method == 'PUT':
                resp = requests.put(target_url, headers=headers, data=request.get_data(), cookies=request.cookies, timeout=30, allow_redirects=False)
            elif request.method == 'DELETE':
                resp = requests.delete(target_url, headers=headers, cookies=request.cookies, timeout=30, allow_redirects=False)
            else:
                resp = requests.request(request.method, target_url, headers=headers, data=request.get_data(), cookies=request.cookies, timeout=30, allow_redirects=False)
            
            # 检查是否是重定向响应
            if resp.status_code in [301, 302, 303, 307, 308]:
                location = resp.headers.get('Location', '')
                if logger:
                    logger.debug(f"重定向响应: status={resp.status_code}, Location={location}")
                if location:
                    parsed_location = urlparse(location)
                    parsed_system = urlparse(system['base_url'])
                    
                    if parsed_location.netloc:
                        if parsed_location.netloc == parsed_system.netloc:
                            # 同一系统的绝对URL，重写路径
                            new_path = parsed_location.path
                            if new_path.startswith('/'):
                                new_location = f'/{prefix}{new_path}'
                            else:
                                new_location = f'/{prefix}/{new_path}'
                            if parsed_location.query:
                                new_location += f'?{parsed_location.query}'
                            if logger:
                                logger.debug(f"同一系统重定向: {location} -> {new_location}")
                            return redirect(new_location)
                        else:
                            # 外部URL，直接重定向
                            if logger:
                                logger.debug(f"外部URL重定向: {location}")
                            return redirect(location)
                    else:
                        # 相对路径，添加前缀
                        if location.startswith('/'):
                            new_location = f'/{prefix}{location}'
                        else:
                            new_location = f'/{prefix}/{location}'
                        if logger:
                            logger.debug(f"相对路径重定向: {location} -> {new_location}")
                        return redirect(new_location)
            
            # 不是重定向，处理响应
            content = resp.content
            
            # 如果是 HTML 或 CSS 响应，重写资源路径
            content_type = resp.headers.get('Content-Type', '')
            if 'text/html' in content_type:
                try:
                    content_str = content.decode('utf-8')
                    content = rewrite_html_content(content_str, prefix).encode('utf-8')
                except Exception as e:
                    pass
            elif 'text/css' in content_type:
                try:
                    content_str = content.decode('utf-8')
                    content = rewrite_html_content(content_str, prefix, is_css=True).encode('utf-8')
                except Exception as e:
                    pass
            
            response = make_response(content, resp.status_code)
            
            # 处理响应头
            for key, value in resp.headers.items():
                key_lower = key.lower()
                if key_lower in ['content-encoding', 'transfer-encoding', 'content-length', 'connection', 'location']:
                    continue
                response.headers[key] = value
            
            return response
        
        return '重定向次数过多', 502
        
    except requests.exceptions.RequestException as e:
        return f'无法连接到系统: {str(e)}', 502

if __name__ == '__main__':
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
