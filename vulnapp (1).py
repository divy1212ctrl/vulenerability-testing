"""
VulnScan Pro - VulnApp (Deliberately Vulnerable Target)
========================================================
WARNING: This app is INTENTIONALLY VULNERABLE.
Run ONLY in isolated/local environment. Never deploy publicly.

OWASP Top 10 Covered:
  - A01: Broken Access Control (IDOR)
  - A02: Cryptographic Failures (Weak hashing, JWT tampering)
  - A03: Injection (SQLi — Classic, UNION, Blind)
  - A07: Identification & Authentication Failures
  - A03: XSS (Reflected + Stored)
  - A01: CSRF (no token validation)

Run:
    pip install flask pyjwt
    python vulnapp.py

FIXES APPLIED (vs original):
  - FIX1: init_db() ka logic robust kiya — already-seeded DB ko re-wipe nahi karega
  - FIX2: /api/orders/<id> pe integer validation added (negative IDs block)
  - FIX3: JWT decode pe options={'verify_exp': False} explicitly set (PyJWT v2 compat)
  - FIX4: /api/xss/comment pe empty user bhi block kiya
  - FIX5: /api/health pe DB connectivity check added
  - FIX6: Port env variable se configurable kiya
"""

import sqlite3
import hashlib
import os
import jwt                          # pip install PyJWT
from flask import (
    Flask, request, jsonify, g,
    render_template_string, session, make_response
)

app = Flask(__name__)
app.secret_key = "supersecretkey123"   # ❌ VULN: Hardcoded weak secret (intentional)
JWT_SECRET     = "jwt_secret_123"      # ❌ VULN: Weak JWT secret (intentional)

DATABASE = os.environ.get("VULNAPP_DB", "vulnapp.db")
PORT     = int(os.environ.get("VULNAPP_PORT", 5000))

# ──────────────────────────────────────────────
# DB HELPERS
# ──────────────────────────────────────────────

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db(force=False):
    """
    Create tables and seed data.
    FIX1: force=False means existing DB is not wiped on restart.
    Pass force=True (or set VULNAPP_RESET=1 env var) to reset.
    """
    reset = force or os.environ.get("VULNAPP_RESET", "0") == "1"
    with app.app_context():
        db = get_db()

        # Check if already seeded
        try:
            count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            if count > 0 and not reset:
                print("[*] Database already seeded. Skipping init (use VULNAPP_RESET=1 to force).")
                return
        except sqlite3.OperationalError:
            pass  # Table doesn't exist yet — proceed with init

        db.executescript("""
            DROP TABLE IF EXISTS users;
            DROP TABLE IF EXISTS products;
            DROP TABLE IF EXISTS orders;
            DROP TABLE IF EXISTS comments;

            CREATE TABLE users (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                username    TEXT UNIQUE NOT NULL,
                password    TEXT NOT NULL,
                role        TEXT DEFAULT 'user',
                email       TEXT,
                credit_card TEXT
            );

            CREATE TABLE products (
                id    INTEGER PRIMARY KEY AUTOINCREMENT,
                name  TEXT NOT NULL,
                price REAL NOT NULL,
                stock INTEGER DEFAULT 100
            );

            CREATE TABLE orders (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER,
                product_id INTEGER,
                quantity   INTEGER,
                total      REAL
            );

            CREATE TABLE comments (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                user    TEXT,
                content TEXT
            );

            INSERT INTO users (username, password, role, email, credit_card) VALUES
                ('admin','21232f297a57a5a743894a0e4a801fc3','admin','admin@vulnapp.local','4111-1111-1111-1111'),
                ('alice','482c811da5d5b4bc6d497ffa98491e38','user', 'alice@example.com',  '4222-2222-2222-2222'),
                ('bob',  '81dc9bdb52d04dc20036dbd8313ed055','user', 'bob@example.com',    '4333-3333-3333-3333');

            INSERT INTO products (name, price, stock) VALUES
                ('Laptop',     999.99,  50),
                ('Headphones', 149.99, 200),
                ('USB Hub',     29.99, 500);

            INSERT INTO orders (user_id, product_id, quantity, total) VALUES
                (2, 1, 1, 999.99),
                (3, 2, 2, 299.98);

            INSERT INTO comments (user, content) VALUES
                ('alice', 'Great product!'),
                ('bob',   'Loved the USB Hub.');
        """)
        db.commit()
    print("[*] Database initialized with seed data.")


# ──────────────────────────────────────────────
# INDEX
# ──────────────────────────────────────────────

INDEX_HTML = """
<!DOCTYPE html><html>
<head>
  <title>VulnApp — VulnScan Pro Target</title>
  <style>
    body { font-family: monospace; background: #0d1117; color: #58a6ff; padding: 2rem; }
    h1   { color: #f85149; }
    h2   { color: #e3b341; margin-top: 2rem; }
    a    { color: #58a6ff; }
    .warn { color: #f85149; border: 1px solid #f85149; padding:.5rem 1rem; display:inline-block; margin-bottom:1rem; }
    ul   { line-height: 2; }
    .badge { background:#238636; color:#fff; font-size:11px; padding:2px 6px; border-radius:4px; margin-left:6px; }
  </style>
</head>
<body>
  <h1>⚠ VulnApp — Intentionally Vulnerable Target</h1>
  <p class="warn">DO NOT deploy on a public server. For local/lab use only.</p>
  <h2>🔴 Vulnerable Endpoints</h2>
  <ul>
    <li><b>POST /api/login</b>                        — SQLi Login Bypass (Classic)</li>
    <li><b>GET  /api/products/search?q=</b>           — UNION-Based SQLi</li>
    <li><b>GET  /api/user/exists?username=</b>        — Boolean-Blind SQLi</li>
    <li><b>GET  /api/orders/&lt;id&gt;</b>            — IDOR (no auth check)</li>
    <li><b>GET  /api/xss/reflect?name=</b>            — Reflected XSS</li>
    <li><b>POST /api/xss/comment</b>                  — Stored XSS (submit)</li>
    <li><b>GET  /api/xss/comments</b>                 — Stored XSS (view)</li>
    <li><b>POST /api/csrf/transfer</b>                — CSRF (no token)</li>
    <li><b>GET  /api/jwt/forge?role=</b>              — JWT Role Tampering</li>
    <li><b>GET  /api/jwt/admin</b>                    — JWT Admin Gate</li>
  </ul>
  <h2>🟢 Secure Comparison</h2>
  <ul>
    <li><b>POST /api/secure/login</b> — Parameterized query + bcrypt-style check</li>
  </ul>
  <h2>ℹ️ Other</h2>
  <ul>
    <li><a href="/api/health">/api/health</a> — Health check</li>
  </ul>
</body></html>
"""


@app.route("/")
def index():
    return render_template_string(INDEX_HTML)


# ──────────────────────────────────────────────
# VULN 1 — Classic SQLi: Login Bypass
# ──────────────────────────────────────────────

@app.route("/api/login", methods=["POST"])
def login():
    data     = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    db    = get_db()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"  # ❌ VULN

    try:
        user = db.execute(query).fetchone()
    except Exception as e:
        return jsonify({"error": str(e), "query": query}), 400

    if user:
        session["user_id"] = user["id"]
        session["role"]    = user["role"]
        token = jwt.encode(
            {"user_id": user["id"], "role": user["role"]},
            JWT_SECRET,
            algorithm="HS256"
        )
        if isinstance(token, bytes):
            token = token.decode("utf-8")
        return jsonify({
            "success":     True,
            "message":     f"Welcome, {user['username']}!",
            "role":        user["role"],
            "token":       token,
            "debug_query": query
        })

    return jsonify({
        "success":     False,
        "message":     "Invalid credentials",
        "debug_query": query
    }), 401


# ──────────────────────────────────────────────
# VULN 2 — UNION-Based SQLi
# ──────────────────────────────────────────────

@app.route("/api/products/search")
def search_products():
    q     = request.args.get("q", "")
    db    = get_db()
    query = f"SELECT id, name, price, stock FROM products WHERE name LIKE '%{q}%'"  # ❌ VULN

    try:
        results = db.execute(query).fetchall()
    except Exception as e:
        return jsonify({"error": str(e), "query": query}), 400

    return jsonify({
        "results":     [dict(r) for r in results],
        "count":       len(results),
        "debug_query": query
    })


# ──────────────────────────────────────────────
# VULN 3 — Boolean-Blind SQLi
# ──────────────────────────────────────────────

@app.route("/api/user/exists")
def user_exists():
    username = request.args.get("username", "")
    db       = get_db()
    query    = f"SELECT id FROM users WHERE username='{username}'"  # ❌ VULN

    try:
        result = db.execute(query).fetchone()
        return jsonify({"exists": bool(result), "debug_query": query})
    except Exception as e:
        return jsonify({"error": str(e), "query": query}), 400


# ──────────────────────────────────────────────
# VULN 4 — IDOR
# ──────────────────────────────────────────────

@app.route("/api/orders/<int:order_id>")
def get_order(order_id):
    if order_id < 1:
        return jsonify({"error": "Invalid order ID"}), 400

    db    = get_db()
    order = db.execute(
        "SELECT o.*, u.username, u.email, u.credit_card, p.name AS product "
        "FROM orders o "
        "JOIN users u ON o.user_id = u.id "
        "JOIN products p ON o.product_id = p.id "
        "WHERE o.id = ?",
        (order_id,)
    ).fetchone()

    if order:
        return jsonify(dict(order))  # ❌ Exposes credit_card with no auth
    return jsonify({"error": "Order not found"}), 404


# ──────────────────────────────────────────────
# VULN 5 — Reflected XSS
# ──────────────────────────────────────────────

@app.route("/api/xss/reflect")
def xss_reflect():
    name = request.args.get("name", "World")
    html = f"""<!DOCTYPE html><html><body>
      <h2>Hello, {name}!</h2>
      <p>Try: <code>?name=&lt;script&gt;alert(1)&lt;/script&gt;</code></p>
    </body></html>"""
    return make_response(html, 200, {"Content-Type": "text/html"})


# ──────────────────────────────────────────────
# VULN 6 — Stored XSS
# ──────────────────────────────────────────────

@app.route("/api/xss/comment", methods=["POST"])
def xss_store_comment():
    data    = request.get_json(silent=True) or {}
    user    = data.get("user", "anonymous") or "anonymous"
    content = data.get("content", "").strip()

    if not content:
        return jsonify({"error": "content required"}), 400

    if len(content) > 2000:
        return jsonify({"error": "content too long (max 2000 chars)"}), 400

    db = get_db()
    db.execute("INSERT INTO comments (user, content) VALUES (?, ?)", (user, content))
    db.commit()
    return jsonify({"success": True, "message": "Comment saved."})


@app.route("/api/xss/comments")
def xss_view_comments():
    db       = get_db()
    comments = db.execute("SELECT user, content FROM comments ORDER BY id DESC").fetchall()

    rows = "".join(
        f"<tr><td><b>{c['user']}</b></td><td>{c['content']}</td></tr>"
        for c in comments
    )
    html = f"""<!DOCTYPE html><html><body>
      <h2>Comments</h2>
      <table border='1'><tr><th>User</th><th>Comment</th></tr>
      {rows if rows else '<tr><td colspan="2">No comments yet.</td></tr>'}
      </table>
      <br><a href='/api/xss/comments'>Refresh</a>
    </body></html>"""
    return make_response(html, 200, {"Content-Type": "text/html"})


# ──────────────────────────────────────────────
# VULN 7 — CSRF
# ──────────────────────────────────────────────

@app.route("/api/csrf/transfer", methods=["POST"])
def csrf_transfer():
    data   = request.get_json(silent=True) or request.form
    to     = data.get("to",     "unknown")
    amount = data.get("amount", "0")

    return jsonify({
        "success": True,
        "message": f"Transferred ${amount} to '{to}'.",
        "warning": "No CSRF token validated — this request could be forged!"
    })


# ──────────────────────────────────────────────
# VULN 8 — JWT Role Tampering
# ──────────────────────────────────────────────

@app.route("/api/jwt/forge")
def jwt_forge():
    role   = request.args.get("role", "user")
    forged = jwt.encode(
        {"user_id": 999, "role": role, "forged": True},
        JWT_SECRET,
        algorithm="HS256"
    )
    if isinstance(forged, bytes):
        forged = forged.decode("utf-8")

    return jsonify({
        "forged_token": forged,
        "decoded":      {"user_id": 999, "role": role, "forged": True},
        "hint":         f"Secret used: '{JWT_SECRET}' — trivially brute-forced with hashcat/john"
    })


@app.route("/api/jwt/admin")
def jwt_admin():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "No token provided. Use: Authorization: Bearer <token>"}), 401

    token = auth.split(" ", 1)[1]
    try:
        payload = jwt.decode(
            token, JWT_SECRET, algorithms=["HS256"],
            options={"verify_exp": False}
        )
    except jwt.InvalidTokenError as e:
        return jsonify({"error": f"Invalid token: {e}"}), 401

    if payload.get("role") != "admin":
        return jsonify({"error": "Admin only"}), 403

    return jsonify({
        "success": True,
        "message": "Welcome, forged admin! You accessed a protected resource.",
        "payload": payload
    })


# ──────────────────────────────────────────────
# SECURE COMPARISON
# ──────────────────────────────────────────────

@app.route("/api/secure/login", methods=["POST"])
def secure_login():
    data     = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    db   = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()

    if user and hashlib.md5(password.encode()).hexdigest() == user["password"]:
        session["user_id"] = user["id"]
        session["role"]    = user["role"]
        return jsonify({
            "success": True,
            "message": f"Secure login OK for '{username}'.",
            "note":    "Parameterized query used — SQLi impossible here."
        })

    return jsonify({"success": False, "message": "Invalid credentials"}), 401


# ──────────────────────────────────────────────
# HEALTH CHECK
# ──────────────────────────────────────────────

@app.route("/api/health")
def health():
    db_ok = False
    try:
        get_db().execute("SELECT 1")
        db_ok = True
    except Exception:
        pass

    return jsonify({
        "status":   "running" if db_ok else "degraded",
        "db":       "ok" if db_ok else "error",
        "app":      "VulnApp",
        "version":  "1.3.0",
        "warning":  "Intentionally vulnerable — local use only!"
    })


# ──────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    print("\n[*] VulnApp v1.3 running at http://localhost:5000")
    print("[!] WARNING: Never expose this to the internet!\n")
    app.run(debug=True, host="0.0.0.0", port=PORT, use_reloader=False)
