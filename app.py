import hashlib
import hmac
import os
import sqlite3
import time
from functools import wraps
from flask import Flask, jsonify, request, send_from_directory

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "nero_market.db")
ADMIN_PASSWORD = os.environ.get("NERO_ADMIN_PASS", "nero2026")
SECRET_KEY = os.environ.get("NERO_SECRET_KEY", "nero-market-secret-key-2026")
TOKEN_TTL_SECONDS = 60 * 60 * 12


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                store TEXT NOT NULL,
                price REAL NOT NULL,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()


def create_admin_token() -> str:
    exp = int(time.time()) + TOKEN_TTL_SECONDS
    payload = f"admin:{exp}".encode("utf-8")
    sig = hmac.new(SECRET_KEY.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return f"{exp}.{sig}"


def verify_admin_token(token: str) -> bool:
    if not token or "." not in token:
        return False
    parts = token.split(".", 1)
    try:
        exp = int(parts[0])
    except ValueError:
        return False
    if int(time.time()) > exp:
        return False
    expected_sig = hmac.new(
        SECRET_KEY.encode("utf-8"),
        f"admin:{exp}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(parts[1], expected_sig)


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        token = auth_header.replace("Bearer ", "").strip() if auth_header.startswith("Bearer ") else ""
        if not verify_admin_token(token):
            return jsonify({"error": "صلاحية الإدارة مطلوبة لتنفيذ هذا الإجراء"}), 401
        return f(*args, **kwargs)

    return decorated


@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/api/admin/status", methods=["GET"])
def admin_status():
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "").strip() if auth_header.startswith("Bearer ") else ""
    return jsonify({"authenticated": verify_admin_token(token)})


@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json(silent=True) or {}
    password = str(data.get("password", ""))
    if not hmac.compare_digest(password, ADMIN_PASSWORD):
        return jsonify({"error": "كلمة مرور الإدارة غير صحيحة"}), 401
    return jsonify({"token": create_admin_token(), "expires_in": TOKEN_TTL_SECONDS})


@app.route("/api/products", methods=["GET"])
def get_products():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, name, store, price, updated_at FROM products ORDER BY id DESC"
        ).fetchall()
    return jsonify([dict(row) for row in rows])


@app.route("/api/products", methods=["POST"])
def add_product():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    store = str(data.get("store", "")).strip()
    try:
        price = float(data.get("price"))
    except (TypeError, ValueError):
        return jsonify({"error": "السعر غير صالح"}), 400

    if not name or not store or price <= 0:
        return jsonify({"error": "يرجى إدخال اسم المنتج والمتجر وسعر أكبر من صفر"}), 400

    with get_db() as conn:
        cursor = conn.execute(
            "INSERT INTO products (name, store, price, updated_at) VALUES (?, ?, ?, datetime('now'))",
            (name, store, price),
        )
        conn.commit()
        new_id = cursor.lastrowid
        row = conn.execute(
            "SELECT id, name, store, price, updated_at FROM products WHERE id = ?",
            (new_id,),
        ).fetchone()
    return jsonify(dict(row)), 201


@app.route("/api/products/<int:product_id>", methods=["PUT"])
@admin_required
def update_product(product_id: int):
    data = request.get_json(silent=True) or {}
    try:
        price = float(data.get("price"))
    except (TypeError, ValueError):
        return jsonify({"error": "السعر غير صالح"}), 400

    if price <= 0:
        return jsonify({"error": "يجب أن يكون السعر أكبر من صفر"}), 400

    with get_db() as conn:
        cur = conn.execute(
            "UPDATE products SET price = ?, updated_at = datetime('now') WHERE id = ?",
            (price, product_id),
        )
        conn.commit()
        if cur.rowcount == 0:
            return jsonify({"error": "المنتج غير موجود"}), 404
        row = conn.execute(
            "SELECT id, name, store, price, updated_at FROM products WHERE id = ?",
            (product_id,),
        ).fetchone()
    return jsonify(dict(row))


@app.route("/api/products/<int:product_id>", methods=["DELETE"])
@admin_required
def delete_product(product_id: int):
    with get_db() as conn:
        cur = conn.execute("DELETE FROM products WHERE id = ?", (product_id,))
        conn.commit()
        if cur.rowcount == 0:
            return jsonify({"error": "المنتج غير موجود"}), 404
    return jsonify({"deleted": True, "id": product_id})


init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_DEBUG", "1") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug_mode)