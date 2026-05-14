import random
import string
from PIL import Image, ImageDraw, ImageFont
from io import BytesIO
import base64

def generate_captcha_text(length=4):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def generate_captcha_image(text):
    width, height = 120, 40
    image = Image.new('RGB', (width, height), color=(255, 255, 255))
    draw = ImageDraw.Draw(image)
    
    try:
        font = ImageFont.truetype("arial.ttf", 24)
    except:
        font = ImageFont.load_default()
    
    for i, char in enumerate(text):
        x = 20 + i * 25
        y = random.randint(5, 10)
        color = (random.randint(0, 100), random.randint(0, 100), random.randint(150, 255))
        draw.text((x, y), char, fill=color, font=font)
    
    for _ in range(30):
        x = random.randint(0, width)
        y = random.randint(0, height)
        color = (random.randint(150, 200), random.randint(150, 200), random.randint(150, 200))
        draw.point((x, y), fill=color)
    
    for _ in range(3):
        x1 = random.randint(0, width)
        y1 = random.randint(0, height)
        x2 = random.randint(0, width)
        y2 = random.randint(0, height)
        color = (random.randint(150, 200), random.randint(150, 200), random.randint(150, 200))
        draw.line([(x1, y1), (x2, y2)], fill=color, width=1)
    
    buffered = BytesIO()
    image.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return img_str
