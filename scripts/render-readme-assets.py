#!/usr/bin/env python3
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont, ImageFilter

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "assets" / "brand" / "raster"
OUT.mkdir(parents=True, exist_ok=True)

FONT_REG = "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"
FONT_BOLD = "/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc"
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONO_B = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"

BG1 = (4, 12, 24)
BG2 = (5, 28, 44)
CYAN = (34, 211, 238)
BLUE = (52, 147, 255)
GREEN = (55, 231, 154)
WHITE = (240, 248, 255)
MUTED = (155, 184, 207)
PANEL = (8, 25, 40)
BORDER = (28, 78, 112)
WARN = (255, 202, 93)

def font(size, bold=False):
    return ImageFont.truetype(FONT_BOLD if bold else FONT_REG, size)

def mono(size, bold=False):
    return ImageFont.truetype(MONO_B if bold else MONO, size)

def gradient_bg(w, h):
    im = Image.new("RGB", (w, h))
    px = im.load()
    for y in range(h):
        ty = y / max(1, h - 1)
        for x in range(w):
            tx = x / max(1, w - 1)
            t = 0.55 * tx + 0.45 * ty
            px[x, y] = tuple(int(BG1[i] * (1 - t) + BG2[i] * t) for i in range(3))
    glow = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    for r, alpha in ((420, 18), (300, 24), (190, 34)):
        gd.ellipse((w // 2 - r, h // 2 - r, w // 2 + r, h // 2 + r), fill=(0, 180, 220, alpha))
    glow = glow.filter(ImageFilter.GaussianBlur(55))
    return Image.alpha_composite(im.convert("RGBA"), glow)

def rr(draw, box, radius=22, fill=PANEL, outline=BORDER, width=2):
    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=width)

def text(draw, xy, value, ft, fill=WHITE, anchor=None):
    draw.text(xy, value, font=ft, fill=fill, anchor=anchor)

def glow_line(im, points, color=CYAN, width=4):
    layer = Image.new("RGBA", im.size, (0, 0, 0, 0))
    ld = ImageDraw.Draw(layer)
    ld.line(points, fill=(*color, 90), width=width + 10, joint="curve")
    layer = layer.filter(ImageFilter.GaussianBlur(8))
    im.alpha_composite(layer)
    ImageDraw.Draw(im).line(points, fill=(*color, 230), width=width, joint="curve")

def save(im, name, quality=82):
    im.convert("RGB").save(OUT / name, "WEBP", quality=quality, method=6)

def render_logo():
    w, h = 1200, 360
    im = gradient_bg(w, h)
    d = ImageDraw.Draw(im)
    d.ellipse((60, 70, 280, 290), outline=CYAN, width=6)
    d.line((105, 115, 105, 235, 165, 235), fill=BLUE, width=24)
    d.line((174, 235, 174, 118, 220, 178, 264, 118, 264, 238), fill=GREEN, width=24, joint="curve")
    for x, y, c in ((170, 58, CYAN), (292, 180, GREEN), (170, 302, CYAN), (48, 180, GREEN)):
        d.ellipse((x - 10, y - 10, x + 10, y + 10), fill=c)
    text(d, (355, 120), "Linux-macctl", font(82, True))
    d.rounded_rectangle((358, 225, 850, 234), 4, fill=CYAN)
    text(d, (360, 250), "Connect · Automate · Control", font(28, True), GREEN)
    text(d, (360, 295), "Linux → macOS · Browser · Workstation · Fleet", font(23), MUTED)
    save(im, "logo.webp", 86)

def render_hero():
    w, h = 1920, 840
    im = gradient_bg(w, h)
    d = ImageDraw.Draw(im)
    for x in range(0, w, 80):
        d.line((x, 0, x, h), fill=(18, 52, 73, 80), width=1)
    for y in range(0, h, 80):
        d.line((0, y, w, y), fill=(18, 52, 73, 80), width=1)
    text(d, (w // 2, 74), "Control Macs like infrastructure. Automate them like software.", font(56, True), WHITE, "mm")
    text(d, (w // 2, 132), "从 Linux 出发，把 macOS、浏览器、工作站与服务器纳入同一套可验证控制平面。", font(30, True), MUTED, "mm")
    rr(d, (700, 260, 1220, 620), 40, (7, 29, 47), (35, 137, 175), 3)
    text(d, (960, 340), "Linux-macctl", font(68, True), WHITE, "mm")
    text(d, (960, 405), "CONTROL PLANE", font(29, True), CYAN, "mm")
    text(d, (960, 465), "POLICY  ·  TRANSACTION  ·  AUDIT  ·  RECOVERY", font(22, True), GREEN, "mm")
    cards = [
        (100, 260, 520, 365, "Browser Automation", "CDP · AX · Vision", CYAN),
        (100, 410, 520, 515, "Workstation Control", "Build · Test · GUI", BLUE),
        (100, 560, 520, 665, "Remote Linux Fleet", "SSH · systemd · Root Ops", GREEN),
        (1400, 260, 1820, 365, "macOS Control", "OpenSSH · Helper · TCC", CYAN),
        (1400, 410, 1820, 515, "Delegated Messaging", "Bounded · Deduped · Audited", BLUE),
        (1400, 560, 1820, 665, "Artifacts & Evidence", "Exact bytes · SHA-256", GREEN),
    ]
    for x1, y1, x2, y2, title, sub, c in cards:
        rr(d, (x1, y1, x2, y2), 24, (7, 24, 39), BORDER, 2)
        d.ellipse((x1 + 26, y1 + 26, x1 + 46, y1 + 46), fill=c)
        text(d, (x1 + 66, y1 + 30), title, font(27, True))
        text(d, (x1 + 66, y1 + 65), sub, font(20), MUTED)
    for y1, y2 in ((312, 335), (462, 440), (612, 545)):
        glow_line(im, [(520, y1), (650, y1), (700, y2)], CYAN, 4)
    for y1, y2 in ((335, 312), (440, 462), (545, 612)):
        glow_line(im, [(1220, y1), (1270, y1), (1400, y2)], GREEN, 4)
    d = ImageDraw.Draw(im)
    text(d, (960, 735), "One gateway. Multiple execution domains. One policy-aware control plane.", font(25, True), MUTED, "mm")
    save(im, "hero.webp", 82)

def base(title, subtitle):
    im = gradient_bg(1600, 900)
    d = ImageDraw.Draw(im)
    text(d, (70, 72), title, font(48, True))
    text(d, (70, 122), subtitle, font(24), MUTED)
    return im, d

def render_terminal():
    im, d = base("Terminal / Control Plane", "Public CLI surface · deterministic execution · evidence-first")
    rr(d, (70, 165, 1530, 820), 28, (3, 15, 25), (30, 93, 128), 3)
    for i, c in enumerate(((255, 107, 107), (255, 209, 102), (85, 236, 168))):
        d.ellipse((105 + i * 34, 200, 123 + i * 34, 218), fill=c)
    text(d, (235, 198), "linux-gateway — linux-macctl", font(23), MUTED)
    lines = [
        ("$ curl -fsSL https://raw.githubusercontent.com/udianlaio/linux-macctl/main/install.sh | sudo bash", WHITE),
        ("linux-macctl-0.6.2.tar.gz: OK", GREEN),
        ("Linux-macctl 0.6.2 installed", GREEN),
        ("", WHITE),
        ("$ sudo macctl version", WHITE),
        ('{"macctl":"0.6.2","transport":"openssh","auth":"publickey"}', CYAN),
        ("", WHITE),
        ("$ sudo macctl doctor", WHITE),
        ("SSH_AUTHENTICATED=true   POLICY_READY=true   AUDIT_READY=true", GREEN),
        ("FULL_READY=true", GREEN),
        ("", WHITE),
        ("$ macctl browser --help", WHITE),
        ("navigate query extract analyze wait click type upload download ...", MUTED),
        ("", WHITE),
        ("$ macctl policy status", WHITE),
        ("unknown operation → FAIL CLOSED", GREEN),
        ("high-impact mutation → explicit gate", GREEN),
    ]
    y = 265
    for line, c in lines:
        if line:
            text(d, (115, y), line, mono(21), c)
        y += 34
    save(im, "terminal-demo.webp", 82)

def render_browser():
    im, d = base("Browser Automation", "Bounded browser control without surrendering authority")
    rr(d, (70, 170, 1040, 800), 28, (5, 18, 29), (35, 95, 130), 3)
    rr(d, (95, 195, 1015, 255), 18, (13, 40, 58), (13, 40, 58), 1)
    for i, c in enumerate(((255, 107, 107), (255, 209, 102), (85, 236, 168))):
        d.ellipse((125 + i * 34, 214, 143 + i * 34, 232), fill=c)
    rr(d, (260, 210, 930, 242), 14, (4, 16, 25), (35, 82, 106), 1)
    text(d, (286, 212), "https://example.com/docs   EXACT HOST ✓", mono(18), MUTED)
    text(d, (135, 310), "Product Documentation", font(34, True))
    text(d, (135, 360), "Getting Started", font(24), MUTED)
    rr(d, (135, 410, 970, 520), 16, (9, 29, 45), (22, 72, 99), 1)
    text(d, (165, 440), "$ macctl browser session-navigate …", mono(21))
    text(d, (165, 476), "✓ authority verified · query/fragment redacted", mono(18), GREEN)
    rr(d, (135, 550, 970, 735), 16, (3, 15, 24), (18, 58, 82), 1)
    commands = [
        ("session-query", "h1 → Getting Started"),
        ("session-extract", "visible text → bounded result"),
        ("session-wait", "expected text → PASS"),
        ("session-download", "exact bytes → SHA-256 PASS"),
    ]
    y = 585
    for a, b in commands:
        text(d, (165, y), a, mono(18, True), CYAN)
        text(d, (390, y), b, mono(18))
        y += 38
    rr(d, (1090, 170, 1530, 800), 28, (7, 25, 40), (35, 95, 130), 3)
    text(d, (1130, 220), "Control Boundaries", font(32, True))
    items = [
        ("✓ Exact-host allowlist", GREEN),
        ("✓ CDP isolated session", GREEN),
        ("✓ AX semantic fallback", GREEN),
        ("✓ Vision fallback", GREEN),
        ("✓ Secret-value redaction", GREEN),
        ("✓ Action lock + recovery", GREEN),
        ("✓ Exact-byte download", GREEN),
        ("Publish / payment / account", WARN),
        ("security → separately gated", WARN),
    ]
    y = 300
    for label, c in items:
        text(d, (1130, y), label, font(22, c == WARN), c)
        y += 48
    save(im, "browser-demo.webp", 82)

def render_gui():
    im, d = base("GUI / Vision / Helper", "See it. Resolve it. Act on it. Verify the postcondition.")
    rr(d, (70, 170, 1040, 800), 28, (12, 24, 38), (44, 94, 130), 3)
    rr(d, (70, 170, 1040, 225), 28, (27, 38, 55), (27, 38, 55), 1)
    for i, c in enumerate(((255, 107, 107), (255, 209, 102), (85, 236, 168))):
        d.ellipse((105 + i * 34, 190, 123 + i * 34, 208), fill=c)
    text(d, (235, 188), "Automation Workspace", font(21))
    rr(d, (110, 270, 410, 730), 18, (8, 18, 29), (24, 58, 78), 1)
    for i, label in enumerate(("All Items", "Today", "Pinned", "Recent")):
        text(d, (145, 325 + i * 62), label, font(22, i == 1), WHITE if i == 1 else MUTED)
    rr(d, (455, 270, 990, 730), 18, (238, 244, 248), (238, 244, 248), 1)
    text(d, (500, 330), "Automation Ideas", font(30, True), (25, 50, 74))
    for i, label in enumerate(("Make repetitive work disappear", "Verify every action", "Keep an audit trail")):
        y = 410 + i * 72
        d.rounded_rectangle((500, y, 528, y + 28), 6, fill=CYAN if i == 0 else (255, 255, 255), outline=(150, 175, 192), width=2)
        text(d, (548, y - 2), label, font(21), (25, 50, 74))
    d.rounded_rectangle((485, 390, 940, 458), 14, outline=GREEN, width=4)
    text(d, (712, 375), "semantic-find → exact candidate", mono(16), GREEN, "mm")
    rr(d, (1090, 170, 1530, 800), 28, (6, 23, 36), (44, 94, 130), 3)
    text(d, (1130, 220), "Real GUI Surface", font(32, True))
    commands = ("semantic-find", "semantic-press", "screenshot / inspect", "type-text / key-press", "mouse-move / click", "helper-screen-ocr", "accessibility-inventory", "event-observe / wait")
    y = 295
    for label in commands:
        text(d, (1130, y), label, mono(18), CYAN)
        y += 42
    text(d, (1130, 675), "✓ Accessibility / AX", font(21), GREEN)
    text(d, (1130, 715), "✓ ScreenCaptureKit / Vision", font(21), GREEN)
    text(d, (1130, 755), "TCC requires human approval", font(19, True), WARN)
    save(im, "gui-demo.webp", 82)

def render_showcase():
    w, h = 1920, 1080
    im = gradient_bg(w, h)
    d = ImageDraw.Draw(im)
    text(d, (70, 70), "Linux-macctl Capability Map", font(48, True))
    text(d, (70, 118), "One control plane across macOS, browsers, workstations, servers, messaging and artifacts", font(25), MUTED)
    cards = [
        (55, 160, 610, 770, "macOS / Terminal", [
            ("Pinned OpenSSH", "Target identity"),
            ("Files / Process / Logs", "Bounded execution"),
            ("Doctor / Workstation", "Live qualification"),
            ("Lifecycle / Recovery", "Reboot · Sleep · Login"),
        ]),
        (683, 160, 1238, 770, "Browser Automation", [
            ("Navigate / Query / Extract", "High-level primitives"),
            ("CDP / AX / Vision", "Scenario-aware routing"),
            ("Upload / Download", "Artifact integrity"),
            ("Action locks", "Recovery + reconcile"),
        ]),
        (1311, 160, 1865, 770, "GUI / Application", [
            ("Accessibility / AX", "Semantic targeting"),
            ("ScreenCaptureKit", "Visual evidence"),
            ("Apple Vision OCR", "Fallback perception"),
            ("Mouse / Keyboard", "Postcondition verified"),
        ]),
    ]
    for x1, y1, x2, y2, title, items in cards:
        rr(d, (x1, y1, x2, y2), 28, (8, 25, 40), (27, 85, 120), 3)
        text(d, (x1 + 36, y1 + 40), title, font(32, True))
        y = y1 + 120
        for a, b in items:
            rr(d, (x1 + 30, y, x2 - 30, y + 92), 16, (7, 32, 50), (24, 72, 100), 1)
            text(d, (x1 + 52, y + 18), a, font(22, True), CYAN)
            text(d, (x1 + 52, y + 52), b, font(18), MUTED)
            y += 110
    bottom = [
        (55, 825, 475, 1000, "Workstation", "Build · Test · GUI"),
        (495, 825, 915, 1000, "Linux Fleet", "systemd · Logs · Root Ops"),
        (935, 825, 1355, 1000, "Messaging", "Allowlist · Dedupe · Rate limit"),
        (1375, 825, 1865, 1000, "Policy / Audit / Recovery", "Fail-closed · Evidence · Reconcile"),
    ]
    for x1, y1, x2, y2, title, sub in bottom:
        rr(d, (x1, y1, x2, y2), 22, (10, 34, 53), (30, 95, 125), 2)
        text(d, (x1 + 28, y1 + 34), title, font(25, True))
        text(d, (x1 + 28, y1 + 85), sub, font(18), GREEN)
    save(im, "capability-showcase.webp", 82)

if __name__ == "__main__":
    render_logo()
    render_hero()
    render_showcase()
    render_terminal()
    render_browser()
    render_gui()
    print("README_RASTER_ASSETS_PASS")
