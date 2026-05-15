import pyotp
import qrcode
from io import BytesIO
import base64

from config import Config

def generate_totp_secret():
    return pyotp.random_base32()

def generate_qr_code(username, secret, issuer=None):
    issuer = issuer or Config.TOTP_ISSUER_NAME
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=username,
        issuer_name=issuer
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return img_str, provisioning_uri

def generate_user_setup(username):
    secret = generate_totp_secret()
    qr_base64, uri = generate_qr_code(username, secret)
    
    print(f"\n{'='*60}")
    print(f"用户: {username}")
    print(f"TOTP 密钥: {secret}")
    print(f"{'='*60}")
    print(f"\n请使用以下方式配置身份验证器:")
    print(f"1. 手动输入密钥: {secret}")
    print(f"2. 或使用二维码扫描")
    print(f"\n二维码 Base64 (可用于HTML显示):")
    print(f"data:image/png;base64,{qr_base64[:100]}...")
    print(f"\n完整 URI: {uri}")
    print(f"{'='*60}\n")
    
    return secret

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        username = sys.argv[1]
    else:
        username = input("请输入用户名: ")
    
    generate_user_setup(username)
