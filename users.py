from models import db, User

def get_user(username=None, user_id=None):
    """获取用户信息"""
    if user_id is not None:
        return User.query.filter_by(id=user_id).first()
    if username is None:
        return None
    return User.query.filter_by(username=username).first()

def verify_password(username, password):
    """验证用户密码"""
    user = User.query.filter_by(username=username).first()
    if user:
        return user.check_password(password)
    return False

def is_admin(username):
    """检查用户是否为管理员（包括子管理员和超级管理员）"""
    user = User.query.filter_by(username=username).first()
    return user is not None and user.is_admin

def is_super_admin(username):
    """检查用户是否为超级管理员（内置管理员）"""
    user = User.query.filter_by(username=username).first()
    return user is not None and user.is_super_admin

def add_user(username, password, totp_secret=None, name='', is_admin=False, is_super_admin=False):
    """添加新用户"""
    user = User(
        username=username,
        name=name,
        totp_secret=totp_secret,
        is_admin=is_admin,
        is_super_admin=is_super_admin
    )

    # 管理员必须设置密码
    if is_admin or is_super_admin:
        if not password:
            raise ValueError('管理员必须设置密码')
        user.set_password(password)
    else:
        # 普通用户设置空密码（使用TOTP验证）
        user.set_password('')
    
    db.session.add(user)
    db.session.commit()
    return True

def update_user(username_or_id, **user_data):
    """更新用户信息"""
    if isinstance(username_or_id, int):
        user = User.query.filter_by(id=username_or_id).first()
    else:
        user = User.query.filter_by(username=username_or_id).first()

    if not user:
        return False
    
    # 更新字段
    if 'name' in user_data:
        user.name = user_data['name']
    if 'totp_secret' in user_data:
        user.totp_secret = user_data['totp_secret']
    if 'is_admin' in user_data:
        user.is_admin = user_data['is_admin']
    if 'is_super_admin' in user_data:
        user.is_super_admin = user_data['is_super_admin']
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
            'id': user.id,
            'username': user.username,
            'name': user.name,
            'totp_secret': user.totp_secret,
            'is_admin': user.is_admin,
            'is_super_admin': user.is_super_admin
        }
    return result
