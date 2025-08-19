# server/app.py
import os
import re
import datetime
import sqlite3
import jwt

from flask import Flask, request, jsonify, g
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

APP_SECRET = os.environ.get("APP_SECRET", "change_this_now")  # set this in prod!
ALLOWED_ORIGINS = os.environ.get("CORS_ORIGINS", "*")

app = Flask(__name__)
if ALLOWED_ORIGINS == "*":
    CORS(app)
else:
    CORS(app, origins=[o.strip() for o in ALLOWED_ORIGINS.split(",")], supports_credentials=True)

# ---------- DB ----------
DB_PATH = os.environ.get(
    "DB_PATH",
    os.path.join(os.path.dirname(__file__), "users.db")
)

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
        try:
            g.db.execute("PRAGMA journal_mode=WAL")
            g.db.execute("PRAGMA synchronous=NORMAL")
        except Exception:
            pass
    return g.db

@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db:
        db.close()

def init_db():
    db = get_db()
    db.execute("""
      CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
      )
    """)
    db.commit()

with app.app_context():
    init_db()

# ---------- Auth helpers ----------
def make_token(user_id, email):
    payload = {
        "sub": user_id,
        "email": email,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7)
    }
    return jwt.encode(payload, APP_SECRET, algorithm="HS256")

def auth_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        hdr = request.headers.get("Authorization", "")
        if not hdr.startswith("Bearer "):
            return jsonify({"error": "missing_token"}), 401
        token = hdr.split(" ", 1)[1]
        try:
            data = jwt.decode(token, APP_SECRET, algorithms=["HS256"])
            request.user_id = data["sub"]
            request.user_email = data["email"]
        except Exception:
            return jsonify({"error": "invalid_token"}), 401
        return fn(*args, **kwargs)
    return wrapper

# ---------- AUTH ----------
@app.post("/auth/register")
def register():
    body = request.json or {}
    name = body.get("name", "").strip()
    email = body.get("email", "").strip().lower()
    password = body.get("password", "")

    if not (name and email and password):
        return jsonify({"error": "missing_fields"}), 400

    db = get_db()
    cur = db.execute("SELECT id FROM users WHERE email=?", (email,))
    if cur.fetchone():
        return jsonify({"error": "email_in_use"}), 409

    pwd = generate_password_hash(password)
    now = datetime.datetime.utcnow().isoformat()
    db.execute(
        "INSERT INTO users(name,email,password_hash,created_at) VALUES(?,?,?,?)",
        (name, email, pwd, now)
    )
    db.commit()
    uid = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()["id"]
    token = make_token(uid, email)
    return jsonify({"token": token, "user": {"id": uid, "name": name, "email": email}})

@app.post("/auth/login")
def login():
    body = request.json or {}
    email = body.get("email", "").strip().lower()
    password = body.get("password", "")
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not row or not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "invalid_credentials"}), 401
    token = make_token(row["id"], row["email"])
    return jsonify({"token": token, "user": {"id": row["id"], "name": row["name"], "email": row["email"]}})

@app.get("/auth/me")
@auth_required
def me():
    db = get_db()
    row = db.execute("SELECT id,name,email FROM users WHERE id=?", (request.user_id,)).fetchone()
    return jsonify(dict(row))

# ---------- Classifier ----------
_url_re = re.compile(r'https?://[^\s]+', re.I)

def classify_text_advanced(text: str):
    t = text.lower()
    findings, score = [], 0.0

    if any(k in t for k in ['urgent','immediate action required','account suspended','act now','limited time']):
        findings.append("Creates a false sense of urgency."); score += 0.3
    if any(k in t for k in ['unauthorized access','suspicious activity','security alert','problem with your account']):
        findings.append("Uses threats or warnings to scare you."); score += 0.3
    if any(k in t for k in ['password','social security','ssn','credit card','login details','verify your account']):
        findings.append("Asks for sensitive personal information."); score += 0.4
    if _url_re.findall(t):
        findings.append("Contains URL(s). Be careful where you click."); score += 0.2
    if any(k in t for k in ['dear customer','dear user','valued member']):
        findings.append("Uses a generic greeting instead of your name."); score += 0.1
    if any(k in t for k in ['you have won','congratulations you won','claim your prize','lottery']):
        findings.append("Promises an unexpected prize or reward."); score += 0.3

    final = min(1.0, score)
    label = "phish" if final >= 0.4 else "safe"
    explanation = (
        "No common red flags were found. However, always remain cautious."
        if not findings else
        "Potential red flags identified:\n- " + "\n- ".join(findings)
    )
    return label, final, explanation

history = []  # demo-only, in-memory

@app.post("/classify")
@auth_required
def classify_endpoint():
    body = request.json or {}
    text = body.get("text", "")
    if not text.strip():
        return jsonify({"error": "text_is_empty"}), 400
    label, score, explanation = classify_text_advanced(text)
    rec = {
        "user_id": request.user_id,
        "scenario": "text",
        "text": text,
        "label": label,
        "score": score,
        "explanation": explanation,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
    }
    history.append(rec)
    return jsonify(rec)

@app.get("/history")
@auth_required
def get_history():
    scn = request.args.get("scenario")
    user_hist = [r for r in history if r.get("user_id") == request.user_id]
    return jsonify([r for r in user_hist if not scn or r["scenario"] == scn])

@app.get("/auth/health")
def health_auth():
    return jsonify({"ok": True, "time": datetime.datetime.utcnow().isoformat() + "Z"})

@app.get("/healthz")
def healthz():
    return "ok"

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    debug = os.environ.get("DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
