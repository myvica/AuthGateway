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
    
    # 配置根日志记录器
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[]
    )
    
    # 所有级别日志处理器
    file_handler = logging.FileHandler(Config.LOG_FILE, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    
    # 错误日志处理器 (WARNING及以上)
    error_file_handler = logging.FileHandler(Config.ERROR_LOG_FILE, encoding='utf-8')
    error_file_handler.setLevel(logging.WARNING)
    error_file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    
    # 控制台输出处理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    
    # 登录日志处理器（INFO 级别，单独记录）
    login_file_handler = logging.FileHandler(Config.LOGIN_LOG_FILE, encoding='utf-8')
    login_file_handler.setLevel(logging.INFO)
    login_file_handler.setFormatter(logging.Formatter(
        '%(asctime)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    
    # 登录日志记录器
    login_logger = logging.getLogger('login')
    login_logger.setLevel(logging.INFO)
    login_logger.addHandler(login_file_handler)
    login_logger.propagate = False
    
    # 获取根记录器并添加处理器
    root_logger = logging.getLogger()
    root_logger.addHandler(file_handler)
    root_logger.addHandler(error_file_handler)
    root_logger.addHandler(console_handler)
    
    # 应用日志记录器
    logger = logging.getLogger(__name__)
else:
    logger = None

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY


@app.context_processor
def inject_gateway_config():
    return {
        'gateway_name': app.config['GATEWAY_NAME']
    }

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

@app.errorhandler(Exception)
def handle_exception(e):
    """全局异常处理"""
    if logger:
        logger.error(f"未处理异常: {str(e)}", exc_info=True)
    return "服务器内部错误", 500

@app.errorhandler(404)
def handle_404(e):
    """404 错误处理"""
    if logger:
        logger.warning(f"404 错误 - 路径: {request.path}")
    return "页面不存在", 404

@app.errorhandler(500)
def handle_500(e):
    """500 错误处理"""
    if logger:
        logger.error(f"500 错误 - 路径: {request.path}, 错误: {str(e)}", exc_info=True)
    return "服务器内部错误", 500

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
            return f'url("/{prefix}{path}")'
        
        # 相对路径
        pattern_css_relative = r'url\(\s*["\']?((?!(?:https?:|/|data:))[^"\')\s]+)["\']?\s*\)'
        def replace_css_relative_path(match):
            path = match.group(1)
            return f'url("/{prefix}/{path}")'
        
        rewritten = re.sub(pattern_css_absolute, replace_css_absolute_path, html_content)
        rewritten = re.sub(pattern_css_relative, replace_css_relative_path, rewritten)
        return rewritten
    
    # 需要重写的 HTML 属性列表
    attributes = [
        'href', 'src', 'action', 'content',
        'data-src', 'data-href', 'data-url'
    ]
    
    # 先处理绝对路径（以 / 开头）
    pattern_absolute = r'(' + '|'.join(attributes) + r')\s*=\s*["\'](/[^"\'\s]*)["\']'
    
    def replace_absolute_path(match):
        attr = match.group(1)
        path = match.group(2)
        return f'{attr}="/{prefix}{path}"'
    
    # 再处理相对路径（不以 /、http、https、#、javascript: 开头）
    pattern_relative = r'(' + '|'.join(attributes) + r')\s*=\s*["\']((?!(?:https?:|/|#|javascript:))[^"\'\s]*)["\']'
    
    def replace_relative_path(match):
        attr = match.group(1)
        path = match.group(2)
        return f'{attr}="/{prefix}/{path}"'
    
    # 先替换绝对路径，再替换相对路径
    rewritten = re.sub(pattern_absolute, replace_absolute_path, html_content)
    rewritten = re.sub(pattern_relative, replace_relative_path, rewritten)
    
    # 额外处理 JavaScript 和字符串中的路径
    # 专门处理 ASP.NET WebResource 和 ScriptResource
    # 使用更宽松的匹配模式，匹配所有 /WebResource.axd... 和 /ScriptResource.axd...
    
    # 处理单引号、双引号、还有 ASP.NET UpdatePanel 的管道符 |...|
    # 匹配模式: '...' 或 "..." 或 |...|
    pattern_aspnet_web = r'(?<=[\'|])(/WebResource\.axd[^\"\'|\s]*)(?=[\'|])'
    def replace_webresource(match):
        path = match.group(1)
        return f"/{prefix}{path}"
    
    pattern_aspnet_script = r'(?<=[\'|])(/ScriptResource\.axd[^\"\'|\s]*)(?=[\'|])'
    def replace_scriptresource(match):
        path = match.group(1)
        return f"/{prefix}{path}"
    
    rewritten = re.sub(pattern_aspnet_web, replace_webresource, rewritten)
    rewritten = re.sub(pattern_aspnet_script, replace_scriptresource, rewritten)
    
    # 额外处理：可能有更简单的情况，没有 ? 查询参数
    pattern_js_webresource = r'(?<=[\'|])(/WebResource\.axd)(?=[\'|])'
    def replace_js_webresource(match):
        return f"/{prefix}/WebResource.axd"
    
    pattern_js_scriptresource = r'(?<=[\'|])(/ScriptResource\.axd)(?=[\'|])'
    def replace_js_scriptresource(match):
        return f"/{prefix}/ScriptResource.axd"
    
    rewritten = re.sub(pattern_js_webresource, replace_js_webresource, rewritten)
    rewritten = re.sub(pattern_js_scriptresource, replace_js_scriptresource, rewritten)
    
    return rewritten

def log_login_event(username, success=True, message='', request=None):
    """记录登录事件"""
    try:
        if not Config.LOG_ENABLED or 'login_logger' not in globals() or not login_logger:
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
    except Exception as e:
        if logger:
            logger.warning(f"登录日志记录失败: {str(e)}")

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
                    log_login_event(username, success=True, message='登录成功', request=request)
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
        qr_base64, _ = generate_qr_code(
            username,
            user_data['totp_secret'],
            app.config['TOTP_ISSUER_NAME']
        )
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

@app.route('/admin/users/<username>/name', methods=['PUT'])
@admin_required
def update_user_name(username):
    if username == 'admin':
        return jsonify({'error': '不能修改内置管理员信息'}), 400
    
    data = request.get_json()
    if not data or 'name' not in data:
        return jsonify({'error': '缺少姓名参数'}), 400
    
    name = data['name'].strip()
    if not name:
        return jsonify({'error': '姓名不能为空'}), 400
    
    if update_user(username, {'name': name}):
        return jsonify({'success': True})
    return jsonify({'error': '修改失败'}), 400

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
    
    qr_base64, _ = generate_qr_code(
        username,
        new_secret,
        app.config['TOTP_ISSUER_NAME']
    )
    
    return jsonify({
        'success': True,
        'secret': new_secret,
        'qr_code': f'data:image/png;base64,{qr_base64}'
    })

@app.route('/<prefix>', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'], strict_slashes=False)
@app.route('/<prefix>/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'], strict_slashes=False)
def proxy(prefix, path):
    
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
        headers['X-Forwarded-For'] = request.remote_addr or ''
        cms_host = urlparse(system['base_url']).netloc
        headers['Host'] = cms_host
        
        # 处理 Cookie：只转发非 session 的 cookie，保留网关 session
        cookie_header = request.headers.get('Cookie', '')
        if cookie_header:
            filtered_cookies = []
            for cookie in cookie_header.split(';'):
                cookie = cookie.strip()
                if cookie and not cookie.startswith('session='):
                    filtered_cookies.append(cookie)
            if filtered_cookies:
                headers['Cookie'] = '; '.join(filtered_cookies)
        
        # 处理请求数据
        req_data = None
        req_files = None
        if request.method in ['POST', 'PUT', 'PATCH']:
            if request.content_type and 'multipart/form-data' in request.content_type:
                req_files = request.files
                req_data = request.form
            elif request.form:
                req_data = request.form
            else:
                req_data = request.get_data()
        
        if request.method == 'GET':
            resp = requests.get(target_url, headers=headers, timeout=30, allow_redirects=False)
        elif request.method == 'POST':
            resp = requests.post(target_url, headers=headers, data=req_data, files=req_files, timeout=30, allow_redirects=False)
        elif request.method == 'PUT':
            resp = requests.put(target_url, headers=headers, data=req_data, files=req_files, timeout=30, allow_redirects=False)
        elif request.method == 'DELETE':
            resp = requests.delete(target_url, headers=headers, timeout=30, allow_redirects=False)
        else:
            resp = requests.request(request.method, target_url, headers=headers, data=req_data, files=req_files, timeout=30, allow_redirects=False)
        
        # 调试：记录登录 POST 的响应内容
        if request.method == 'POST' and 'login.aspx' in target_url:
            if logger:
                logger.debug(f"[DEBUG] Login POST response - status: {resp.status_code}, Content-Type: {resp.headers.get('Content-Type', '')}, length: {len(resp.content)}")
                # 尝试解码并记录完整内容（针对 text/plain）
                try:
                    debug_content = resp.content.decode('utf-8', errors='replace')
                    if 'text/plain' in resp.headers.get('Content-Type', ''):
                        logger.debug(f"[DEBUG] Full UpdatePanel response: {debug_content}")
                    else:
                        preview_len = min(500, len(debug_content))
                        logger.debug(f"[DEBUG] Login response preview: {debug_content[:preview_len]}...")
                except Exception as e:
                    logger.debug(f"[DEBUG] Failed to decode response: {e}")
        
        redirect_count = 0
        while resp.status_code in [301, 302, 303, 307, 308] and redirect_count < 3:
            redirect_count += 1
            location = resp.headers.get('Location', '')
            if not location:
                break
            if logger:
                logger.debug(f"重定向 {redirect_count}: status={resp.status_code}, Location={location}")
            
            parsed_location = urlparse(location)
            parsed_system = urlparse(system['base_url'])
            
            if parsed_location.netloc:
                if parsed_location.netloc == parsed_system.netloc:
                    new_path = parsed_location.path
                    new_location = f'/{prefix}{new_path}' if new_path.startswith('/') else f'/{prefix}/{new_path}'
                    if parsed_location.query:
                        new_location += f'?{parsed_location.query}'
                    if logger:
                        logger.debug(f"同域重写: {location} -> {new_location}")
                    return redirect(new_location)
                else:
                    if logger:
                        logger.debug(f"外部URL重定向: {location}")
                    return redirect(location)
            else:
                new_path = location
                new_location = f'/{prefix}{new_path}' if new_path.startswith('/') else f'/{prefix}/{new_path}'
                if logger:
                    logger.debug(f"相对路径: {location} -> {new_location}")
                return redirect(new_location)
        
        if redirect_count >= 3:
            return '重定向次数过多', 502
        
        content = resp.content
        
        content_type = resp.headers.get('Content-Type', '')
        # 重写所有文本类型的资源路径 - 包括 text/plain (ASP.NET UpdatePanel)
        text_content_types = ['text/html', 'text/css', 'application/javascript', 'text/javascript', 'text/plain']
        should_rewrite = any(ct in content_type for ct in text_content_types)
        
        if should_rewrite:
            try:
                content_str = content.decode('utf-8', errors='replace')
                
                # 调试日志：记录原始内容中是否包含 WebResource/ScriptResource
                if 'WebResource.axd' in content_str or 'ScriptResource.axd' in content_str:
                    if logger:
                        logger.debug(f"[REWRITER] Found ASP.NET resource references found in content (prefix={prefix}, Content-Type={content_type})")
                        # 记录一小段内容，帮助调试
                        preview_len = min(200, len(content_str))
                        logger.debug(f"[REWRITER] Content preview: {content_str[:preview_len]}...")
                
                is_css = 'text/css' in content_type
                rewritten_str = rewrite_html_content(content_str, prefix, is_css=is_css)
                content = rewritten_str.encode('utf-8')
                
                # 调试日志：对比重写前后对比
                if 'ScriptResource.axd' in content_str:
                    if logger:
                        count_original = content_str.count('ScriptResource.axd')
                        logger.debug(f"[REWRITER] Original has ScriptResource: {count_original} times")
                        if rewritten_str != content_str:
                            count_rewritten = rewritten_str.count('ScriptResource.axd')
                            logger.debug(f"[REWRITER] Rewrite successful (after: {count_rewritten})")
                            # 验证是否有路径被正确重写
                            if f'/{prefix}/ScriptResource.axd' in rewritten_str:
                                logger.debug(f"[REWRITER] Success: Found prefixed ScriptResource")
                            else:
                                logger.debug(f"[REWRITER] Warning: NO prefixed ScriptResource found after rewrite!")
            except Exception as e:
                if logger:
                    logger.warning(f"重写内容失败: {str(e)}")
                pass
        
        response = make_response(content, resp.status_code)
        
        # 处理响应头
        for key, value in resp.headers.items():
            key_lower = key.lower()
            if key_lower in ['content-encoding', 'transfer-encoding', 'content-length', 'connection']:
                continue
            # 处理 Set-Cookie，添加 Path 前缀
            if key_lower == 'set-cookie':
                # 解析并修改 Cookie 的 Path 属性
                cookie_parts = value.split(';')
                new_cookie = []
                path_found = False
                
                for part in cookie_parts:
                    part = part.strip()
                    if part.lower().startswith('path='):
                        # 修改现有 Path
                        orig_path = part.split('=', 1)[1]
                        new_path = f'/{prefix}{orig_path}' if orig_path.startswith('/') else f'/{prefix}/{orig_path}'
                        new_cookie.append(f'Path={new_path}')
                        path_found = True
                    else:
                        new_cookie.append(part)
                
                # 如果没有 Path 属性，添加一个
                if not path_found:
                    new_cookie.append(f'Path=/{prefix}')
                
                response.headers.add(key, '; '.join(new_cookie))
            else:
                response.headers[key] = value
        
        return response
        
    except requests.exceptions.RequestException as e:
        error_msg = f"无法连接到系统: {str(e)}"
        if logger:
            logger.error(error_msg, exc_info=True)
        return error_msg, 502

if __name__ == '__main__':
    if logger:
        logger.info(f"服务启动 - 监听地址: {Config.HOST}:{Config.PORT}, 调试模式: {Config.DEBUG}")
    try:
        app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
    except Exception as e:
        if logger:
            logger.error(f"服务启动失败: {str(e)}", exc_info=True)
        raise
