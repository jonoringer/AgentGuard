from PIL import Image, ImageDraw, ImageFont

W, H = 1280, 640
img = Image.new('RGB', (W, H), '#0b1220')
d = ImageDraw.Draw(img)

for y in range(H):
    t = y / (H - 1)
    r = int(11 + (15 - 11) * t)
    g = int(18 + (118 - 18) * t)
    b = int(32 + (110 - 32) * t)
    d.line([(0, y), (W, y)], fill=(r, g, b))

for i in range(18):
    x0 = 70 * i - 120
    y0 = 40 + (i % 5) * 95
    x1 = x0 + 260
    y1 = y0 + 260
    d.ellipse((x0, y0, x1, y1), outline=(80, 220, 240, 35), width=2)

panel = (70, 70, 1210, 570)
d.rounded_rectangle(panel, radius=36, fill=(8, 17, 35), outline=(95, 230, 245), width=2)

cx, cy = 220, 320
shield_w, shield_h = 190, 220
sx0, sy0 = cx - shield_w // 2, cy - shield_h // 2
sx1, sy1 = cx + shield_w // 2, cy + shield_h // 2
shield = [
    (cx, sy0),
    (sx1, sy0 + 48),
    (sx1, sy0 + 120),
    (cx, sy1),
    (sx0, sy0 + 120),
    (sx0, sy0 + 48),
]
d.polygon(shield, fill=(203, 248, 252), outline=(15, 23, 42), width=5)

d.rounded_rectangle((184, 305, 256, 380), radius=14, fill=(34, 211, 238))
d.arc((190, 255, 250, 325), 180, 360, fill=(34, 211, 238), width=10)
d.line((204, 345, 220, 361), fill=(8, 17, 35), width=6)
d.line((220, 361, 242, 333), fill=(8, 17, 35), width=6)

font_paths = [
    '/System/Library/Fonts/Supplemental/Arial Bold.ttf',
    '/System/Library/Fonts/SFNS.ttf',
]

def load_font(size):
    for p in font_paths:
        try:
            return ImageFont.truetype(p, size=size)
        except Exception:
            pass
    return ImageFont.load_default()

h1 = load_font(84)
h2 = load_font(56)
body = load_font(28)
cta = load_font(46)

text_x = 360
d.text((text_x, 170), 'AgentGuard', font=h1, fill=(224, 251, 255))
d.text((text_x, 275), 'AI Agent Security Platform', font=h2, fill=(126, 241, 255))
d.text((text_x, 352), 'Policy firewall for autonomous agents', font=body, fill=(182, 237, 247))
d.text((text_x, 397), 'Real-time decisions, scoped permissions, audit trails', font=body, fill=(182, 237, 247))

cta_text = 'Secure Agent Actions Before They Execute'
left = text_x
y0 = 455
bbox = d.textbbox((0, 0), cta_text, font=cta)
text_w = bbox[2] - bbox[0]
text_h = bbox[3] - bbox[1]
pad_x = 28
pad_y = 14
pill = (left, y0, left + text_w + pad_x * 2, y0 + text_h + pad_y * 2)
d.rounded_rectangle(pill, radius=16, fill=(13, 148, 136))
d.text((left + pad_x, y0 + pad_y - 2), cta_text, font=cta, fill=(235, 255, 255))

out = 'assets/agentguard-social-preview.png'
img.save(out, 'PNG', optimize=True)
print(out)
