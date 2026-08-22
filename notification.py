import requests
import json
from config import Config
from datetime import datetime


def send_wechat_notification(username, client_ip, user_agent, message='2FA 登录成功'):
    """
    发送企业微信通知
    
    Args:
        username: 用户名
        client_ip: 客户端IP地址
        user_agent: User-Agent信息
        message: 通知消息
    """
    if not Config.NOTIFICATION_ENABLED or not Config.WECHAT_WEBHOOK_URL:
        return False, '通知功能未启用或Webhook地址未配置'
    
    try:
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        data = {
            "msgtype": "markdown",
            "markdown": {
                "content": f"""### 🔐 {Config.GATEWAY_NAME} 登录通知

**时间**: {current_time}
**用户**: {username}
**IP地址**: {client_ip}
**设备信息**: {user_agent}
**状态**: {message}"""
            }
        }
        
        response = requests.post(
            Config.WECHAT_WEBHOOK_URL,
            data=json.dumps(data),
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        
        result = response.json()
        if result.get('errcode') == 0:
            return True, '通知发送成功'
        else:
            return False, f'企业微信API错误: {result.get("errmsg", "未知错误")}'
            
    except requests.exceptions.RequestException as e:
        return False, f'网络请求失败: {str(e)}'
    except Exception as e:
        return False, f'通知发送异常: {str(e)}'


def send_login_notification(username, request, success=True, message=''):
    """
    发送登录通知（包含完整的登录信息）
    
    Args:
        username: 用户名
        request: Flask request对象
        success: 登录是否成功
        message: 附加消息
    """
    if not Config.NOTIFICATION_ENABLED or not success:
        return
    
    client_ip = 'unknown'
    user_agent = 'unknown'

    if request:
        client_ip = request.remote_addr or 'unknown'
        user_agent = request.headers.get('User-Agent', 'unknown')
        if len(user_agent) > 200:
            user_agent = user_agent[:200] + '...'
    
    # 发送企业微信通知
    result, msg = send_wechat_notification(username, client_ip, user_agent, message or '2FA 验证成功')
    
    # 记录日志
    from app import logger, sanitize_log_field
    if logger:
        username = sanitize_log_field(username, 100)
        if result:
            logger.info(f"[{username}] {msg}")
        else:
            logger.warning(f"[{username}] {msg}")
