import os
from flask import Flask
from models import db, User
from config import Config

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
