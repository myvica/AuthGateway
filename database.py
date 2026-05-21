import os
from flask import Flask
from sqlalchemy import inspect, text
from models import db, User
from config import Config


def _ensure_user_columns():
    """为现有 users 表补齐新增列。"""
    inspector = inspect(db.engine)
    if 'users' not in inspector.get_table_names():
        return

    existing_columns = {column['name'] for column in inspector.get_columns('users')}
    if 'last_login_at' in existing_columns:
        return

    db.session.execute(text('ALTER TABLE users ADD COLUMN last_login_at DATETIME NULL'))
    db.session.commit()

def init_db(app):
    """初始化数据库"""
    db.init_app(app)
    
    with app.app_context():
        # 创建数据目录（如果是SQLite）
        if 'sqlite' in Config.SQLALCHEMY_DATABASE_URI:
            # 从 URI 中提取路径
            db_path = Config.SQLALCHEMY_DATABASE_URI.replace('sqlite:///', '')
            # 确保目录存在
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # 创建所有表
        db.create_all()
        _ensure_user_columns()
        
        # 检查是否需要创建默认管理员
        if User.query.filter_by(username='admin').first() is None:
            admin = User(
                username='admin',
                name='内置管理员',
                is_admin=True,
                is_super_admin=True
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("已创建默认管理员账户: admin/admin123")

def get_db():
    """获取数据库实例"""
    return db
