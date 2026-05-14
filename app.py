from flask import Flask, render_template, request, redirect, url_for, session, make_response, flash, jsonify
import pyotp
import requests
import base64
from functools import wraps
from urllib.parse import urljoin
from config import Config
from users import (
    get_user, verify_password, is_admin, is_super_admin, add_user, 
    update_user, delete_user, get_all_users
)
from generate_totp import generate_totp_secret, generate_qr_code
from captcha import generate_captcha_text, generate_captcha_image
from database import init_db

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY

# 初始化数据库
init_db(app)

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
    if is_authenticated() and not is_admin(session.get('username')):
        return redirect(url_for('proxy'))
    
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        totp_code = request.form.get('totp_code', '').strip()
        
        if not username or not totp_code:
            error = '请填写所有字段'
        else:
            user = get_user(username)
            if user and not user.get('is_admin', False):
                totp = pyotp.TOTP(user['totp_secret'])
                if totp.verify(totp_code, valid_window=1):
                    session['authenticated'] = True
                    session['username'] = username
                    return redirect(url_for('proxy', path=''))
                else:
                    error = '验证码错误或已过期'
            else:
                error = '用户名不存在或不允许登录'
    
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
    user = get_user(username)
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    
    new_secret = generate_totp_secret()
    update_user(username, {'totp_secret': new_secret})
    
    qr_base64, _ = generate_qr_code(username, new_secret)
    
    return jsonify({
        'success': True,
        'secret': new_secret,
        'qr_code': f'data:image/png;base64,{qr_base64}'
    })

@app.route('/cms', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
@app.route('/cms/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def proxy(path):
    if not is_authenticated():
        return redirect(url_for('user_login'))
    
    if is_admin(session.get('username')):
        return redirect(url_for('admin'))
    
    target_url = urljoin(f"{Config.CMS_BASE_URL}/", path)
    
    if request.query_string:
        target_url += '?' + request.query_string.decode('utf-8')
    
    try:
        headers = {key: value for key, value in request.headers if key.lower() not in ['host', 'content-length']}
        headers['Host'] = 'htims.xxx.ht'
        
        if request.method == 'GET':
            resp = requests.get(target_url, headers=headers, cookies=request.cookies, timeout=30)
        elif request.method == 'POST':
            resp = requests.post(target_url, headers=headers, data=request.get_data(), cookies=request.cookies, timeout=30)
        elif request.method == 'PUT':
            resp = requests.put(target_url, headers=headers, data=request.get_data(), cookies=request.cookies, timeout=30)
        elif request.method == 'DELETE':
            resp = requests.delete(target_url, headers=headers, cookies=request.cookies, timeout=30)
        else:
            resp = requests.request(request.method, target_url, headers=headers, data=request.get_data(), cookies=request.cookies, timeout=30)
        
        response = make_response(resp.content, resp.status_code)
        
        for key, value in resp.headers.items():
            if key.lower() not in ['content-encoding', 'transfer-encoding', 'content-length', 'connection']:
                response.headers[key] = value
        
        return response
        
    except requests.exceptions.RequestException as e:
        return f'无法连接到CMS系统: {str(e)}', 502

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=Config.DEBUG)
