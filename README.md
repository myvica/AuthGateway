# AuthGateway 认证网关

这是一个基于 Flask 的认证网关，为内网系统提供 TOTP 双因素认证保护。

## 项目结构

```
AuthGateway/
├── app.py                 # 主应用文件
├── config.py              # 配置文件（含数据库配置）
├── database.py            # 数据库初始化
├── models.py              # SQLAlchemy 数据模型
├── users.py               # 用户管理接口
├── captcha.py             # 图形验证码生成
├── generate_totp.py       # TOTP 密钥生成工具
├── notification.py        # 登录通知（企业微信 Webhook）
├── requirements.txt       # Python 依赖
├── authgateway.service    # systemd 服务文件（生产环境）
├── data/
│   └── auth.db            # SQLite 数据库文件（自动创建）
├── logs/
│   ├── app.log            # 应用日志
│   ├── error.log          # 错误日志
│   └── login.log          # 登录日志
├── templates/
│   ├── login.html         # 普通用户登录页面
│   ├── admin_login.html   # 管理员登录页面
│   └── admin.html         # 用户管理后台
└── README.md             # 使用说明
```

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 配置数据库

项目支持 SQLite（默认）和 MariaDB/MySQL。

**默认配置（SQLite）**：
- 数据库文件自动创建在 `data/auth.db`
- 默认管理员账户：`admin` / `admin123`

**使用 MariaDB/MySQL**：

设置环境变量 `DATABASE_URL`：

```bash
# Linux/macOS
export DATABASE_URL="mysql+pymysql://username:password@localhost/dbname"

# Windows (PowerShell)
$env:DATABASE_URL="mysql+pymysql://username:password@localhost/dbname"
```

### 3. 配置网关名称与系统地址

编辑 `config.py`，设置网关名称、2FA 发行者名称，以及后端系统地址：

```python
GATEWAY_NAME = 'AuthGateway'
TOTP_ISSUER_NAME = 'AuthGateway'

SYSTEMS = [
    {
        "prefix": "cms",
        "base_url": "http://cms.xxx.ht",
        "name": "CMS系统"
    }
]
```

- `GATEWAY_NAME`：网关在登录页、管理页等界面展示的名称
- `TOTP_ISSUER_NAME`：2FA 令牌在验证器应用中显示的发行者名称

### 3.1 配置登录通知（可选）

支持通过企业微信 Webhook 推送登录成功通知：

```python
# config.py 或环境变量
NOTIFICATION_ENABLED = True
WECHAT_WEBHOOK_URL = 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=YOUR_KEY'
```

### 4. 运行应用

```bash
python app.py
```

应用将在 `http://0.0.0.0:5000` 启动。

首次启动时会自动创建数据库和默认管理员账户。

## 用户管理

### 管理员登录

访问 `http://your-server:5000/admin_login`

默认管理员账户：
- 用户名：`admin`
- 密码：`admin123`
- 验证码：页面显示的图形验证码

### 管理功能

在管理后台可以：
- 查看所有用户列表
- 添加新用户（自动生成 TOTP 密钥和二维码）
- 重置用户 TOTP 密钥
- 删除用户

### 普通用户登录

访问 `http://your-server:5000/`

普通用户需完成两步验证：
1. 输入用户名、密码和验证码
2. 输入 TOTP 动态码（通过 Google Authenticator 等应用获取）

## 部署建议

### 生产环境完整部署流程

#### 1. 服务器准备
```bash
# 更新系统
sudo apt update && sudo apt upgrade -y

# 安装 Python 和 pip
sudo apt install python3 python3-pip python3-venv -y

# 创建项目目录
sudo mkdir -p /opt/AuthGateway
sudo chown $USER:$USER /opt/AuthGateway
```

#### 2. 部署应用
```bash
# 克隆或复制项目文件到 /opt/AuthGateway
cd /opt/AuthGateway

# 创建虚拟环境
python3 -m venv venv

# 激活虚拟环境并安装依赖
source venv/bin/activate
pip install -r requirements.txt
pip install gunicorn

# 配置应用（可选：设置 MariaDB 连接）
# export DATABASE_URL="mysql+pymysql://user:password@localhost/dbname"
```

#### 3. 配置 systemd 服务
```bash
# 复制服务文件
sudo cp authgateway.service /etc/systemd/system/

# 编辑服务文件中的路径（如果需要）
sudo nano /etc/systemd/system/authgateway.service

# 重新加载 systemd
sudo systemctl daemon-reload

# 启用开机自启
sudo systemctl enable authgateway

# 启动服务
sudo systemctl start authgateway
```

#### 4. 验证部署
```bash
# 检查服务状态
sudo systemctl status authgateway
sudo systemctl status nginx

# 查看应用日志
sudo journalctl -u authgateway -f --no-pager

# 测试访问
curl -I https://your-domain.com
```

### Nginx 配置示例

```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 安全增强计划（已实现/待实现）

- [x] 用户管理后台
- [x] 密码加密存储（bcrypt）
- [x] 数据库存储（SQLite/MariaDB）
- [x] 图形验证码（管理员登录）
- [ ] IP 白名单限制
- [ ] 登录速率限制（防止暴力破解）
- [ ] 会话超时自动登出
- [x] 登录日志记录
- [x] 登录通知（2FA登录成功后推送通知）
- [ ] 登录失败告警

## 使用流程

### 普通用户
1. 访问网关地址 `http://your-server:5000/`
2. 输入用户名、密码和验证码
3. 输入 TOTP 动态码完成二次验证
4. 验证通过后，选择并跳转到目标系统

### 管理员
1. 访问管理地址 `http://your-server:5000/admin_login`
2. 输入用户名和密码
3. 验证通过后，进入用户管理后台

## 注意事项

- 请确保网关服务器能够访问内网目标系统
- 定期更换管理员密码
- 建议为每个用户单独配置 TOTP 密钥
- 生产环境务必使用 HTTPS
- 默认管理员密码 `admin123` 应在首次登录后立即修改
