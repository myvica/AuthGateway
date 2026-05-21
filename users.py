from models import db, User

def get_user(username=None, user_id=None):
    """获取用户信息"""
    if user_id is not None:
        return db.session.get(User, user_id)
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

def add_user(username, password='', totp_secret=None, name='', is_admin=False, is_super_admin=False):
    """添加新用户"""
    user = User(
        username=username,
        name=name,
        totp_secret=totp_secret,
        is_admin=is_admin,
        is_super_admin=is_super_admin
    )
    
    if is_admin or is_super_admin:
        if not password:
            raise ValueError('管理员必须设置密码')
        user.set_password(password)
    else:
        user.set_password('')
    
    db.session.add(user)
    db.session.commit()
    return True

def update_user(identifier, password=None, totp_secret=None, name=None, is_admin=None, is_super_admin=None):
    """更新用户信息"""
    user = None
    if isinstance(identifier, int):
        user = db.session.get(User, identifier)
    else:
        user = User.query.filter_by(username=identifier).first()
    
    if not user:
        return False
    
    if password is not None:
        user.set_password(password)
    if totp_secret is not None:
        user.totp_secret = totp_secret
    if name is not None:
        user.name = name
    if is_admin is not None:
        user.is_admin = is_admin
    if is_super_admin is not None:
        user.is_super_admin = is_super_admin
    
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

def get_all_users(include_super_admin=True):
    """获取所有用户"""
    query = User.query
    if not include_super_admin:
        query = query.filter_by(is_super_admin=False)
    users = query.all()
    result = {}
    for user in users:
        result[user.username] = {
            'username': user.username,
            'name': user.name,
            'totp_secret': user.totp_secret,
            'is_admin': user.is_admin,
            'is_super_admin': user.is_super_admin,
            'last_login_at': user.last_login_at.isoformat() if user.last_login_at else None
        }
    return result
