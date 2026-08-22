from flask import Flask, render_template, request, redirect, url_for, session, make_response, flash, jsonify, Response
import pyotp
import requests
from requests.exceptions import RequestException
import base64
import json
import re
import os
import secrets
import logging
from functools import wraps
from urllib.parse import urljoin, urlparse, quote, urlunparse, quote_plus, unquote
from config import Config
from users import (
    get_user, verify_password, is_admin, is_super_admin, add_user,
    update_user, delete_user, get_all_users
)
from generate_totp import generate_totp_secret, generate_qr_code
from captcha import generate_captcha_text, generate_captcha_image
from database import init_db
from models import db
from datetime import datetime
from notification import send_login_notification
from werkzeug.middleware.proxy_fix import ProxyFix
from rate_limit import LoginRateLimiter

if Config.LOG_ENABLED:
    os.makedirs(Config.LOG_DIR, exist_ok=True)
    
    logging.basicConfig(
        level=getattr(logging, Config.LOG_LEVEL),
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[]
    )
    
    file_handler = logging.FileHandler(Config.LOG_FILE, encoding='utf-8')
    file_handler.setLevel(getattr(logging, Config.LOG_LEVEL))
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    
    error_file_handler = logging.FileHandler(Config.ERROR_LOG_FILE, encoding='utf-8')
    error_file_handler.setLevel(logging.WARNING)
    error_file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    
    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, Config.LOG_LEVEL))
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

# 前置代理层由 PROXY_COUNT 控制，超出信任层数的转发头会被忽略，防止直连时伪造
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=Config.PROXY_COUNT,
    x_proto=Config.PROXY_COUNT,
    x_host=Config.PROXY_COUNT
)

init_db(app)

@app.context_processor
def inject_csrf_token():
    return {'csrf_token': session.get('csrf_token', '')}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('user_login'))
        return f(*args, **kwargs)
    return decorated_function

def csrf_required(f):
    """管理端写操作 CSRF 校验：接受 X-CSRF-Token 头或表单 csrf_token 字段"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = session.get('csrf_token')
        sent = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
        if not token or not sent or not secrets.compare_digest(token, sent):
            message = 'CSRF 校验失败，请刷新页面后重试'
            return jsonify({'success': False, 'error': message, 'message': message}), 403
        return f(*args, **kwargs)
    return decorated_function

def log_login_event(username, success=True, message='', request=None):
    """记录登录事件（成功与失败均记录）"""
    if not Config.LOG_ENABLED or not login_logger:
        return

    client_ip = 'unknown'
    user_agent = 'unknown'
    accept_language = 'unknown'

    if request:
        client_ip = request.remote_addr or 'unknown'
        user_agent = request.headers.get('User-Agent', 'unknown')
        accept_language = request.headers.get('Accept-Language', 'unknown')

        if len(user_agent) > 200:
            user_agent = user_agent[:200] + '...'
    
    log_message = f"{username} | {client_ip} | {user_agent} | {accept_language} | {message}"
    login_logger.info(log_message)


login_limiter = LoginRateLimiter(Config.LOGIN_MAX_ATTEMPTS, Config.LOGIN_LOCKOUT_SECONDS)


def _login_attempt_keys(username):
    ip = request.remote_addr or 'unknown'
    return (f'user:{username}', f'ip:{ip}')


def _login_blocked(username):
    return any(login_limiter.is_blocked(key) for key in _login_attempt_keys(username))


def _login_failed(username, message):
    """记录一次登录失败：按用户名与 IP 计数，并写入登录日志"""
    for key in _login_attempt_keys(username):
        login_limiter.record_failure(key)
    log_login_event(username, success=False, message=message, request=request)


def _login_succeeded(username):
    for key in _login_attempt_keys(username):
        login_limiter.clear(key)

def is_authenticated():
    return 'username' in session and session.get('totp_verified')


def get_external_scheme():
    return request.scheme


def get_external_host():
    return request.host


def get_gateway_base(prefix):
    return f"{get_external_scheme()}://{get_external_host()}/{prefix}"


@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        totp_code = request.form.get('totp_code', '').strip()

        if not username or not totp_code:
            flash('请填写用户名和动态码', 'error')
            return render_template('login.html')

        if _login_blocked(username):
            log_login_event(username, success=False, message='登录失败: 尝试过于频繁已被限流', request=request)
            flash('尝试次数过多，请稍后再试', 'error')
            return render_template('login.html')

        if is_admin(username):
            _login_failed(username, '登录失败: 管理员账号不允许在此登录')
            flash('管理员请通过管理后台登录', 'error')
            return render_template('login.html')

        user = get_user(username)
        if not user:
            _login_failed(username, '登录失败: 用户名不存在或不允许登录')
            flash('用户名不存在或不允许登录', 'error')
            return render_template('login.html')

        totp_secret = user.totp_secret
        if not totp_secret:
            _login_failed(username, '登录失败: 用户未配置动态码')
            flash('当前用户未配置动态码', 'error')
            return render_template('login.html')

        totp = pyotp.TOTP(totp_secret)
        if not totp.verify(totp_code, valid_window=1):
            _login_failed(username, '登录失败: 动态码错误或已过期')
            flash('动态码错误或已过期', 'error')
            return render_template('login.html')

        session['username'] = username
        session['totp_verified'] = True
        session.permanent = True
        session['csrf_token'] = secrets.token_hex(32)
        _login_succeeded(username)

        user.last_login_at = datetime.utcnow()
        db.session.commit()

        log_login_event(username, success=True, message='用户动态码登录成功', request=request)
        send_login_notification(username=username, request=request, success=True, message='用户动态码登录成功')

        return redirect(url_for('systems'))

    if 'username' in session and session.get('totp_verified'):
        return redirect(url_for('systems'))

    return render_template('login.html')

@app.route('/admin_login', methods=['GET', 'POST'])
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        captcha_code = request.form.get('captcha_code', '').strip()

        if not username or not password or not captcha_code:
            return render_template('admin_login.html', error='请填写所有字段', gateway_name=Config.GATEWAY_NAME)

        if _login_blocked(username):
            log_login_event(username, success=False, message='登录失败: 尝试过于频繁已被限流', request=request)
            return render_template('admin_login.html', error='尝试次数过多，请稍后再试', gateway_name=Config.GATEWAY_NAME)

        if session.get('captcha_code', '').upper() != captcha_code.upper():
            session.pop('captcha_code', None)
            _login_failed(username, '管理员登录失败: 图形验证码错误')
            return render_template('admin_login.html', error='图形验证码错误', gateway_name=Config.GATEWAY_NAME)

        if not is_admin(username):
            _login_failed(username, '管理员登录失败: 非管理员账号')
            return render_template('admin_login.html', error='用户名或密码错误', gateway_name=Config.GATEWAY_NAME)

        user = get_user(username)
        if not user:
            _login_failed(username, '管理员登录失败: 用户名不存在')
            return render_template('admin_login.html', error='用户名或密码错误', gateway_name=Config.GATEWAY_NAME)

        if not verify_password(username, password):
            _login_failed(username, '管理员登录失败: 密码错误')
            return render_template('admin_login.html', error='用户名或密码错误', gateway_name=Config.GATEWAY_NAME)

        session['username'] = username
        session.pop('totp_verified', None)
        session.pop('captcha_code', None)
        session.permanent = True
        session['csrf_token'] = secrets.token_hex(32)
        _login_succeeded(username)

        user.last_login_at = datetime.utcnow()
        db.session.commit()

        log_login_event(username, success=True, message='管理员登录成功', request=request)

        return redirect(url_for('admin'))

    return render_template('admin_login.html', gateway_name=Config.GATEWAY_NAME)

@app.route('/admin/captcha')
def admin_captcha():
    text = generate_captcha_text(4)
    session['captcha_code'] = text
    img_base64 = generate_captcha_image(text)
    img_data = base64.b64decode(img_base64)
    response = make_response(img_data)
    response.headers['Content-Type'] = 'image/png'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response

@app.route('/verify_totp', methods=['GET', 'POST'])
def verify_totp():
    return redirect(url_for('user_login'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('user_login'))

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

    current_is_super_admin = is_super_admin(session.get('username'))
    users = get_all_users(include_super_admin=current_is_super_admin)
    return render_template('admin.html', users=users, is_super_admin=current_is_super_admin, gateway_name=Config.GATEWAY_NAME)

@app.route('/admin/add_user', methods=['POST'])
@app.route('/admin/users', methods=['POST'])
@login_required
@csrf_required
def admin_add_user():
    if not is_super_admin(session.get('username')):
        return jsonify({'success': False, 'message': '无权限'}), 403

    data = request.get_json(silent=True)
    if data:
        username = data.get('username')
        password = data.get('password')
        name = data.get('name', '')
        is_sub_admin = data.get('is_sub_admin', False)
    else:
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        name = request.form.get('name', '').strip()
        is_sub_admin = request.form.get('is_sub_admin', '0') == '1'

    if not username or not name:
        message = '用户名和姓名不能为空'
        if data:
            return jsonify({'success': False, 'message': message}), 400
        flash(message, 'error')
        return redirect(url_for('admin'))

    if is_sub_admin and not password:
        message = '子管理员密码不能为空'
        if data:
            return jsonify({'success': False, 'message': message}), 400
        flash(message, 'error')
        return redirect(url_for('admin'))
    
    if get_user(username):
        message = '用户名已存在'
        if data:
            return jsonify({'success': False, 'message': message}), 400
        flash(message, 'error')
        return redirect(url_for('admin'))
    
    totp_secret = generate_totp_secret()
    qr_code = generate_qr_code(username, totp_secret)
    
    success = add_user(username, password, totp_secret, name=name, is_admin=is_sub_admin)
    if success:
        if data:
            return jsonify({
                'success': True,
                'message': '用户添加成功',
                'qr_code': f'data:image/png;base64,{qr_code[0]}'
            })

        if is_sub_admin:
            flash(f'子管理员 {username} 创建成功', 'success')
            return redirect(url_for('admin'))

        flash(f'用户 {username} 创建成功', 'success')
        current_is_super_admin = is_super_admin(session.get('username'))
        return render_template(
            'admin.html',
            users=get_all_users(include_super_admin=current_is_super_admin),
            is_super_admin=current_is_super_admin,
            gateway_name=Config.GATEWAY_NAME,
            new_user_qr=qr_code[0],
            new_user_secret=totp_secret,
            new_user_username=username
        )
    else:
        if data:
            return jsonify({'success': False, 'message': '添加失败'}), 500
        flash('添加失败', 'error')
        return redirect(url_for('admin'))

@app.route('/admin/reset_totp/<int:user_id>', methods=['POST'])
@login_required
@csrf_required
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
            'qr_code': f'data:image/png;base64,{new_qr_code[0]}'
        })
    else:
        return jsonify({'success': False, 'message': '重置失败'}), 500


@app.route('/admin/users/<username>/password', methods=['PUT'])
@login_required
@csrf_required
def admin_update_password(username):
    current_username = session.get('username')
    data = request.get_json(silent=True) or {}
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')

    if not new_password:
        return jsonify({'success': False, 'message': '新密码不能为空'}), 400

    target_user = get_user(username)
    if not target_user:
        return jsonify({'success': False, 'message': '用户不存在'}), 404

    if username == current_username:
        if not verify_password(username, current_password):
            return jsonify({'success': False, 'message': '当前密码错误'}), 400
        if not target_user.is_admin:
            return jsonify({'success': False, 'message': '无权限'}), 403
    else:
        if not is_super_admin(current_username):
            return jsonify({'success': False, 'message': '无权限'}), 403
        if not target_user.is_admin or target_user.is_super_admin:
            return jsonify({'success': False, 'message': '仅可修改子管理员密码'}), 403

    if not update_user(username, password=new_password):
        return jsonify({'success': False, 'message': '修改失败'}), 500

    return jsonify({'success': True, 'message': '密码修改成功'})


@app.route('/admin/users/<username>/name', methods=['PUT'])
@login_required
@csrf_required
def admin_update_name(username):
    data = request.get_json(silent=True) or {}
    name = data.get('name', '').strip()
    current_username = session.get('username')
    target_user = get_user(username)

    if not name:
        return jsonify({'error': '姓名不能为空'}), 400
    if not target_user:
        return jsonify({'error': '用户不存在'}), 404
    if username != current_username and not is_super_admin(current_username):
        return jsonify({'error': '无权限'}), 403

    if not update_user(username, name=name):
        return jsonify({'error': '修改失败'}), 500

    return jsonify({'success': True})


@app.route('/admin/users/<username>/totp', methods=['POST'])
@login_required
@csrf_required
def admin_reset_totp_by_username(username):
    if not is_super_admin(session.get('username')):
        return jsonify({'error': '无权限'}), 403

    user = get_user(username)
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    if user.is_admin:
        return jsonify({'error': '管理员不使用 TOTP 登录'}), 400

    new_secret = generate_totp_secret()
    if not update_user(username, totp_secret=new_secret):
        return jsonify({'error': '重置失败'}), 500

    qr_code = generate_qr_code(username, new_secret)
    return jsonify({
        'success': True,
        'secret': new_secret,
        'qr_code': f'data:image/png;base64,{qr_code[0]}'
    })


@app.route('/admin/users/<username>', methods=['DELETE'])
@login_required
@csrf_required
def admin_delete_user(username):
    current_username = session.get('username')
    target_user = get_user(username)

    if username == 'admin':
        return jsonify({'error': '不能删除内置管理员'}), 400
    if not target_user:
        return jsonify({'error': '用户不存在'}), 404
    if target_user.is_admin and not is_super_admin(current_username):
        return jsonify({'error': '只有超级管理员可以删除管理员账户'}), 403

    if not delete_user(username):
        return jsonify({'error': '删除失败'}), 400

    return jsonify({'success': True})

def get_system_by_prefix(prefix):
    for system in Config.SYSTEMS:
        if system.get('prefix') == prefix:
            return system
    return None


def _normalize_host(host):
    if not host:
        return ''
    return host.split(':', 1)[0].strip().lower().rstrip('.')


def _is_allowed_attachment_host(system, host):
    normalized_host = _normalize_host(host)
    if not normalized_host:
        return False

    allowed_hosts = system.get('attachment_hosts') or []
    for rule in allowed_hosts:
        normalized_rule = _normalize_host(rule)
        if not normalized_rule:
            continue
        if normalized_host == normalized_rule or normalized_host.endswith(f".{normalized_rule}"):
            return True
    return False


def _build_ext_proxy_url(prefix, full_url):
    return f"{get_external_scheme()}://{get_external_host()}/{prefix}/__ext__/{quote(full_url, safe='')}"


def _is_base_target_host(system, host):
    base_url = (system or {}).get('base_url', '')
    if not base_url:
        return False
    base_host = _normalize_host(urlparse(base_url).netloc)
    target_host = _normalize_host(host)
    return bool(base_host and target_host and base_host == target_host)


def _resolve_external_url(raw_url, base_url):
    if not raw_url:
        return None

    candidate = raw_url.strip()
    if not candidate:
        return None

    if candidate.startswith('//'):
        parsed_base = urlparse(base_url)
        candidate = f"{parsed_base.scheme}:{candidate}"
    elif not urlparse(candidate).scheme:
        candidate = urljoin(base_url.rstrip('/') + '/', candidate)

    parsed = urlparse(candidate)
    if parsed.scheme not in ('http', 'https'):
        return None
    if not parsed.netloc:
        return None
    return candidate


def _rewrite_external_response_url(value, prefix, system, base_url):
    resolved = _resolve_external_url(value, base_url)
    if not resolved:
        return value

    parsed = urlparse(resolved)
    if _is_base_target_host(system, parsed.netloc):
        return value
    if not _is_allowed_attachment_host(system, parsed.netloc):
        return value

    return _build_ext_proxy_url(prefix, resolved)


def _rewrite_json_urls(payload, prefix, system, base_url):
    changed = False

    def visit(node):
        nonlocal changed

        if isinstance(node, dict):
            new_node = {}
            for key, value in node.items():
                if isinstance(value, str) and key.lower().endswith('url'):
                    rewritten = _rewrite_external_response_url(value, prefix, system, base_url)
                    if rewritten != value:
                        changed = True
                    new_node[key] = rewritten
                else:
                    new_node[key] = visit(value)
            return new_node

        if isinstance(node, list):
            return [visit(item) for item in node]

        return node

    return visit(payload), changed


def _proxy_to_target_url(target_url, base_url, prefix):
    try:
        headers = {key: value for key, value in request.headers if key.lower() not in ['host', 'connection']}
        headers['Host'] = urlparse(target_url).netloc
        headers['X-Forwarded-Host'] = get_external_host()
        headers['X-Forwarded-For'] = request.remote_addr
        headers['X-Forwarded-Proto'] = get_external_scheme()

        if request.method in ['POST', 'PUT', 'PATCH']:
            outbound_data = request.get_data()
            headers['Content-Length'] = str(len(outbound_data))
            response = requests.request(
                method=request.method,
                url=target_url,
                headers=headers,
                params=request.args,
                data=outbound_data,
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
                params=request.args,
                cookies=request.cookies,
                allow_redirects=False,
                timeout=30,
                stream=True
            )

        if response.status_code in [301, 302, 303, 307, 308]:
            location = response.headers.get('Location')
            if location:
                resolved_location = _resolve_external_url(location, target_url)
                if resolved_location:
                    parsed_location = urlparse(resolved_location)
                    system = get_system_by_prefix(prefix)
                    if system and (not _is_base_target_host(system, parsed_location.netloc)) and _is_allowed_attachment_host(system, parsed_location.netloc):
                        response.headers['Location'] = _build_ext_proxy_url(prefix, resolved_location)

        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        resp_headers = {
            key: value for key, value in response.headers.items()
            if key.lower() not in excluded_headers
        }
        content = response.content
        resp_headers['Content-Length'] = str(len(content))
        return Response(content, response.status_code, resp_headers)
    except RequestException as e:
        if logger:
            logger.error(f"外链代理请求失败: {str(e)}")
        return f"Proxy error: {str(e)}", 502
    except Exception as e:
        if logger:
            logger.error(f"外链代理异常: {str(e)}")
        return f"Proxy error: {str(e)}", 500

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
        headers['Host'] = urlparse(base_url).netloc
        headers['X-Forwarded-Host'] = get_external_host()
        headers['X-Forwarded-For'] = request.remote_addr
        headers['X-Forwarded-Proto'] = get_external_scheme()
        
        if request.method in ['POST', 'PUT', 'PATCH']:
            outbound_data = request.get_data()
            headers['Content-Length'] = str(len(outbound_data))
            response = requests.request(
                method=request.method,
                url=target_url,
                headers=headers,
                params=request.args,
                data=outbound_data,
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
                params=request.args,
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
                
                target_base = urlparse(base_url)
                is_same_target = (
                    parsed_location.scheme in ('http', 'https') and
                    parsed_location.netloc == target_base.netloc
                )

                if not parsed_location.scheme or is_same_target:
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
        content = response.content
        
        content_type = response.headers.get('Content-Type', '')

        if response.status_code == 200 and 'text/html' in content_type:
            gateway_base = get_gateway_base(prefix)
            target_base = base_url
            current_page_path = f"/{target_path}" if target_path else "/"
            if not current_page_path.endswith('/'):
                current_page_path = current_page_path.rsplit('/', 1)[0] + '/'
            
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
                    elif not path_part.startswith('/') and not path_part.startswith('http') and not path_part.startswith('data:') and not path_part.startswith('#') and not path_part.startswith('mailto:') and not path_part.lower().startswith('javascript:'):
                        if attr in ['src', 'data-src', 'srcset']:
                            new_path = f'/{path_part}{query_part}'
                        else:
                            new_path = f'{current_page_path}{path_part}{query_part}'
                        return f'{attr}={quote_char}{gateway_base}{new_path}{quote_char}'
                return match.group(0)
            
            content_str = content.decode('utf-8', errors='replace')
            
            content_str = re.sub(
                r'(src|href|action|srcset|data-src)=([\'"])([^"\'\s]+)\2',
                fix_paths,
                content_str
            )
            content_str = content_str.replace(f"{target_base}/", f"{gateway_base}/")
            if target_base.startswith('http://'):
                content_str = content_str.replace(
                    f"https://{target_base[len('http://'):]}/",
                    f"{gateway_base}/"
                )
            elif target_base.startswith('https://'):
                content_str = content_str.replace(
                    f"http://{target_base[len('https://'):]}/",
                    f"{gateway_base}/"
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

        elif response.status_code == 200 and 'text/css' in content_type:
            css_text = content.decode('utf-8', errors='replace')
            css_text = re.sub(
                r'url\(([^)]+)\)',
                lambda m: _rewrite_css_url(m.group(1), prefix),
                css_text,
                flags=re.IGNORECASE
            )
            content = css_text.encode('utf-8')
            resp_headers['Content-Length'] = str(len(content))

        elif response.status_code == 200 and 'text/plain' in content_type:
            text_content = content.decode('utf-8', errors='replace')
            gateway_base = get_gateway_base(prefix)
            target_base = base_url

            def rewrite_ajax_redirect(match):
                field_length = match.group(1)
                encoded_url = match.group(2)
                try:
                    decoded_url = requests.utils.unquote(encoded_url)
                except Exception:
                    return match.group(0)

                parsed_decoded = urlparse(decoded_url)
                parsed_target = urlparse(target_base)
                if parsed_decoded.netloc != parsed_target.netloc:
                    return match.group(0)

                rewritten = decoded_url.replace(
                    f"{parsed_decoded.scheme}://{parsed_decoded.netloc}",
                    gateway_base,
                    1
                )
                rewritten_encoded = quote(rewritten, safe='')
                return f"{len(rewritten_encoded)}|pageRedirect||{rewritten_encoded}|"

            text_content = re.sub(
                r'(\d+)\|pageRedirect\|\|([^|]+)\|',
                rewrite_ajax_redirect,
                text_content,
                flags=re.IGNORECASE
            )

            text_content = text_content.replace(f"{target_base}/", f"{gateway_base}/")
            if target_base.startswith('http://'):
                text_content = text_content.replace(
                    f"https://{target_base[len('http://'):]}/",
                    f"{gateway_base}/"
                )
            elif target_base.startswith('https://'):
                text_content = text_content.replace(
                    f"http://{target_base[len('https://'):]}/",
                    f"{gateway_base}/"
                )
            text_content = text_content.replace(
                quote(target_base + '/', safe=''),
                quote(gateway_base + '/', safe='')
            )
            text_content = text_content.replace(
                quote_plus(target_base + '/'),
                quote_plus(gateway_base + '/')
            )
            content = text_content.encode('utf-8')
            resp_headers['Content-Length'] = str(len(content))

        elif response.status_code == 200 and (
            'application/json' in content_type or
            'text/json' in content_type or
            'javascript' in content_type
        ):
            text_content = content.decode('utf-8', errors='replace')
            text_content = text_content.replace('"/signalr"', f'"/{prefix}/signalr"')
            text_content = text_content.replace("'/signalr'", f"'/{prefix}/signalr'")
            if 'application/json' in content_type or 'text/json' in content_type:
                try:
                    payload = json.loads(text_content)
                    payload, changed = _rewrite_json_urls(payload, prefix, system, target_url)
                    if changed:
                        if logger:
                            logger.debug("JSON 响应中的外链 URL 已改写为 gateway ext")
                        text_content = json.dumps(payload, ensure_ascii=False)
                except Exception as e:
                    if logger:
                        logger.error(f"JSON 响应 URL 改写失败: {str(e)}")
            content = text_content.encode('utf-8')
            resp_headers['Content-Length'] = str(len(content))
        
        return Response(content, response.status_code, resp_headers)
        
    except RequestException as e:
        if logger:
            logger.error(f"代理请求失败: {str(e)}")
        return f"Proxy error: {str(e)}", 502
    except Exception as e:
        if logger:
            logger.error(f"代理异常: {str(e)}")
        return f"Proxy error: {str(e)}", 500


def _infer_prefix_from_referer():
    referer = request.headers.get('Referer', '')
    if not referer:
        return None

    try:
        ref_path = urlparse(referer).path or ''
        parts = [p for p in ref_path.split('/') if p]
        if not parts:
            return None
        candidate = parts[0]
        if get_system_by_prefix(candidate):
            return candidate
    except Exception:
        return None

    return None


def _get_fallback_prefix_or_404():
    prefix = _infer_prefix_from_referer()
    if not prefix:
        return None, ("System not found", 404)
    return prefix, None

# 基础设施回退路由（ASP.NET 及 SignalR）
@app.route('/ScriptResource.axd', methods=['GET', 'POST'])
@app.route('/WebResource.axd', methods=['GET', 'POST'])
@app.route('/signalr', methods=['GET', 'POST'])
@app.route('/signalr/<path:path>', methods=['GET', 'POST'])
@login_required
def proxy_fallback_infrastructure_assets(path=''):
    prefix, error = _get_fallback_prefix_or_404()
    if error:
        return error

    target_path = request.path.lstrip('/')
    return proxy_request(prefix, target_path)


# 特殊项目回退路由（业务资源路径）
@app.route('/htxx/<path:path>', methods=['GET', 'POST'])
@app.route('/action/<path:path>', methods=['GET', 'POST'])
@app.route('/jquery/<path:path>', methods=['GET', 'POST'])
@app.route('/Statics/<path:path>', methods=['GET', 'POST'])
@app.route('/Scripts/<path:path>', methods=['GET', 'POST'])
@login_required
def proxy_fallback_project_assets(path=''):
    prefix, error = _get_fallback_prefix_or_404()
    if error:
        return error

    if request.path.startswith('/Scripts/'):
        target_path = f"Scripts/{path}"
    elif request.path.startswith('/action/'):
        target_path = f"action/{path}"
    elif request.path.startswith('/htxx/'):
        target_path = f"htxx/{path}"
    elif request.path.startswith('/jquery/'):
        target_path = f"jquery/{path}"
    elif request.path.startswith('/Statics/'):
        target_path = f"Statics/{path}"
    else:
        target_path = request.path.lstrip('/')

    return proxy_request(prefix, target_path)


@app.route('/<prefix>/__ext__/<path:encoded_url>', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'])
@login_required
def proxy_external_url(prefix, encoded_url):
    system = get_system_by_prefix(prefix)
    if not system:
        return "System not found", 404

    full_url = unquote(encoded_url)
    if not re.match(r'^https?://', full_url, re.IGNORECASE):
        return "Invalid external URL", 400

    parsed = urlparse(full_url)
    if parsed.scheme not in ('http', 'https') or not parsed.netloc:
        return "Invalid external URL", 400

    if not _is_allowed_attachment_host(system, parsed.netloc):
        return "External host not allowed", 403

    return _proxy_to_target_url(full_url, system.get('base_url', ''), prefix)

@app.route('/<prefix>/<path:path>', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'])
@login_required
def proxy_with_path(prefix, path):
    return proxy_request(prefix, path)

@app.route('/<prefix>/', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'])
@login_required
def proxy_root(prefix):
    return proxy_request(prefix, '')


def _rewrite_css_url(raw_value, prefix):
    value = raw_value.strip()
    quote = ''
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        quote = value[0]
        value = value[1:-1].strip()

    if not value or value.startswith('data:') or value.startswith('http://') or value.startswith('https://'):
        return f"url({raw_value})"

    if value.startswith(f'/{prefix}/') or value == f'/{prefix}':
        return f"url({raw_value})"

    if value.startswith('/'):
        new_value = f"/{prefix}{value}"
    else:
        new_value = value

    if quote:
        return f"url({quote}{new_value}{quote})"
    return f"url({new_value})"
