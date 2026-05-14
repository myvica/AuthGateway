import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-change-this-in-production'
    
    CMS_BASE_URL = 'http://cms.xxx.ht'
    
    SESSION_TIMEOUT = 3600
    
    DEBUG = False
    
    # 数据库配置
    # 默认使用 SQLite，可通过环境变量切换到 MariaDB/MySQL
    # 环境变量 DATABASE_URL 格式：
    #   SQLite: sqlite:///data/auth.db
    #   MariaDB/MySQL: mysql+pymysql://user:password@localhost/dbname
    DATABASE_URL = os.environ.get('DATABASE_URL') or 'sqlite:///data/auth.db'
    
    # SQLAlchemy 配置
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # 确保 SQLite 路径是绝对路径
    if DATABASE_URL.startswith('sqlite:///') and not DATABASE_URL.startswith('sqlite:////'):
        # 将相对路径转换为基于项目目录的绝对路径
        db_path = DATABASE_URL.replace('sqlite:///', '')
        project_dir = os.path.dirname(os.path.abspath(__file__))
        abs_db_path = os.path.join(project_dir, db_path)
        SQLALCHEMY_DATABASE_URI = f'sqlite:///{abs_db_path}'
    
    # 数据库引擎选项：连接池配置、字符集等
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,          # 每次使用连接前检查是否存活，防止连接过期
        'pool_recycle': 3600,           # 一小时后回收连接，避免MySQL wait_timeout问题
    }
    
    # 如果是 MySQL/MariaDB，指定字符集为 utf8mb4
    if 'mysql' in DATABASE_URL or 'mariadb' in DATABASE_URL:
        SQLALCHEMY_ENGINE_OPTIONS['connect_args'] = {
            'charset': 'utf8mb4',
            'use_unicode': True,
        }
