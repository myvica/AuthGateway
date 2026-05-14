from models import db, User
from flask import current_app

def get_user(username):
    """获取用户信息"""
    user = User.query.filter_by(username=username).first()
    if user:
        return {
            'username': user.username,
            'name': user.name,
            'totp_secret': user.totp_secret,
            'is_admin': user.is_admin,
            'password': user.password_hash
        }
    return None

def verify_password(username, password):
    """验证用户密码"""
    user = User.query.filter_by(username=username).first()
    if user:
        return user.check_password(password)
    return False

def is_admin(username):
    """检查用户是否为管理员"""
    user = User.query.filter_by(username=username).first()
    return user is not None and user.is_admin

def add_user(username, user_data):
    """添加新用户"""
    user = User(
        username=username,
        name=user_data.get('name', ''),
        totp_secret=user_data.get('totp_secret', ''),
        is_admin=user_data.get('is_admin', False)
    )
    
    # 如果提供了密码，设置密码哈希
    if 'password' in user_data and user_data['password']:
        user.set_password(user_data['password'])
    else:
        # 设置一个空密码哈希，后续需要重置
        user.set_password('')
    
    db.session.add(user)
    db.session.commit()

def update_user(username, user_data):
    """更新用户信息"""
    user = User.query.filter_by(username=username).first()
    if not user:
        return False
    
    # 更新字段
    if 'name' in user_data:
        user.name = user_data['name']
    if 'totp_secret' in user_data:
        user.totp_secret = user_data['totp_secret']
    if 'is_admin' in user_data:
        user.is_admin = user_data['is_admin']
    if 'password' in user_data:
        user.set_password(user_data['password'])
    
    db.session.commit()
    return True

def delete_user(username):
    """删除用户"""
    if username == 'admin':
        return False
    
    user = User.query.filter_by(username=username).first()
    if not user:
        return False
    
    db.session.delete(user)
    db.session.commit()
    return True

def get_all_users():
    """获取所有用户"""
    users = User.query.all()
    result = {}
    for user in users:
        result[user.username] = {
            'username': user.username,
            'name': user.name,
            'totp_secret': user.totp_secret,
            'is_admin': user.is_admin,
            'password': user.password_hash
        }
    return result
