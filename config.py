import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-change-this-in-production'
    GATEWAY_NAME = os.environ.get('GATEWAY_NAME') or 'AuthGateway'
    TOTP_ISSUER_NAME = os.environ.get('TOTP_ISSUER_NAME') or GATEWAY_NAME

    # 多系统配置
    SYSTEMS = [
        {
            "prefix": "cms",
            "base_url": "http://htims.xxx.ht",
            "name": "CMS系统",
            "attachment_hosts": [
                "attch.xxx.ss",
                "xxx.ss"
            ]
        }
    ]
    
    SESSION_TIMEOUT = 3600
    
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes')
    
    # 日志配置
    LOG_ENABLED = True
    LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
    LOG_FILE = os.path.join(LOG_DIR, 'app.log')
    ERROR_LOG_FILE = os.path.join(LOG_DIR, 'error.log')
    LOGIN_LOG_FILE = os.path.join(LOG_DIR, 'login.log')
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()
    
    # 服务配置
    HOST = '0.0.0.0'
    PORT = 5000
    # 前置可信代理层数（如 nginx 为 1），用于 ProxyFix 解析真实客户端 IP/协议/主机名
    PROXY_COUNT = int(os.environ.get('PROXY_COUNT', '1'))
    
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
    
    # 登录通知配置
    NOTIFICATION_ENABLED = os.environ.get('NOTIFICATION_ENABLED', 'False').lower() in ('true', '1', 'yes')
    # 企业微信 Webhook 地址
    WECHAT_WEBHOOK_URL = os.environ.get('WECHAT_WEBHOOK_URL', '')
