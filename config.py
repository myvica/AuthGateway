import os
import ipaddress
import secrets
import time
from datetime import timedelta


def _parse_trusted_proxies(raw):
    """解析 TRUSTED_PROXIES（逗号分隔，支持单 IP 与 CIDR），无效条目告警忽略"""
    networks = []
    for item in raw.split(','):
        item = item.strip()
        if not item:
            continue
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            print(f'警告: TRUSTED_PROXIES 中的无效条目已忽略: {item}')
    return networks


def _load_or_create_secret_key(key_file=None):
    """优先读 SECRET_KEY 环境变量；未设置时自动生成随机密钥并持久化到 data/secret_key。

    持久化保证 gunicorn 多 worker 与服务重启后密钥一致。文件不存在或为空
    （如写入中途崩溃的残留）时，通过锁文件保证同一时刻只有一个进程重建，
    其余进程等待读取；锁残留超过 30 秒视为写者已死，可抢占重试。
    密钥文件不应提交进仓库。
    """
    env_key = os.environ.get('SECRET_KEY')
    if env_key:
        return env_key

    if key_file is None:
        key_file = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'data', 'secret_key'
        )
    lock_file = key_file + '.lock'

    def _read():
        with open(key_file, 'r', encoding='utf-8') as f:
            return f.read().strip()

    def _wait_for_key(seconds=5.0):
        # 其他进程持锁重建中，等待其完成
        for _ in range(int(seconds / 0.05)):
            time.sleep(0.05)
            try:
                existing = _read()
                if existing:
                    return existing
            except OSError:
                pass
        return None

    try:
        if os.path.exists(key_file):
            existing = _read()
            if existing:
                return existing

        os.makedirs(os.path.dirname(key_file), exist_ok=True)

        lock_fd = None
        for _ in range(2):
            try:
                lock_fd = os.open(lock_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                break
            except FileExistsError:
                try:
                    stale = time.time() - os.path.getmtime(lock_file) > 30
                except OSError:
                    stale = False
                if stale:
                    try:
                        os.remove(lock_file)
                    except OSError:
                        pass
                    continue
                existing = _wait_for_key()
                if existing:
                    return existing
                raise RuntimeError(f'等待其他进程重建密钥文件超时: {key_file}')

        if lock_fd is None:
            raise RuntimeError(f'获取密钥文件锁失败: {lock_file}')

        with os.fdopen(lock_fd, 'w', encoding='utf-8') as f:
            f.write(str(os.getpid()))
        try:
            # 拿到锁后二次检查：可能其他进程刚重建完成
            if os.path.exists(key_file):
                existing = _read()
                if existing:
                    return existing

            new_key = secrets.token_hex(32)
            tmp_file = f'{key_file}.tmp.{os.getpid()}'
            fd = os.open(tmp_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(new_key)
            os.replace(tmp_file, key_file)
            print(f'警告: 未设置 SECRET_KEY 环境变量，已自动生成随机密钥并保存到 {key_file}，'
                  f'生产环境建议通过环境变量显式配置')
            return new_key
        finally:
            try:
                os.remove(lock_file)
            except OSError:
                pass
    except OSError as e:
        raise RuntimeError(
            f'无法读取或创建 {key_file}，请显式设置 SECRET_KEY 环境变量，'
            f'或删除损坏的密钥文件后重启: {e}'
        )


class Config:
    SECRET_KEY = _load_or_create_secret_key()
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
    # 会话过期时间（滑动过期：每次请求刷新），登录成功后设置 session.permanent 生效
    PERMANENT_SESSION_LIFETIME = timedelta(seconds=SESSION_TIMEOUT)
    SESSION_COOKIE_SAMESITE = 'Lax'

    # 登录限流：窗口期内失败次数达到阈值后锁定（按用户名与 IP 分别计数）
    LOGIN_MAX_ATTEMPTS = int(os.environ.get('LOGIN_MAX_ATTEMPTS', '5'))
    LOGIN_LOCKOUT_SECONDS = int(os.environ.get('LOGIN_LOCKOUT_SECONDS', '900'))
    
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
    # 可信反向代理地址：仅当直连对端命中该列表时才采信 X-Forwarded-* 头，
    # 其余来源的转发头一律剥离，防止直连客户端伪造来源 IP 绕过限流
    TRUSTED_PROXIES = _parse_trusted_proxies(os.environ.get('TRUSTED_PROXIES', '127.0.0.1,::1'))
    
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
