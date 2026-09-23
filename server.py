from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "site.db"
SESSION_TTL = timedelta(hours=8)
COOKIE_NAME = "mh_admin_session"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 210_000)
    return f"pbkdf2_sha256$210000${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, rounds, salt_hex, digest_hex = stored.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds))
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db() -> None:
    with connect() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                price_bdt INTEGER NOT NULL DEFAULT 0,
                price_usd TEXT NOT NULL DEFAULT '',
                delivery TEXT NOT NULL DEFAULT '',
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_id INTEGER,
                customer_name TEXT NOT NULL,
                customer_contact TEXT NOT NULL,
                notes TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE SET NULL
            );
            CREATE TABLE IF NOT EXISTS reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_name TEXT NOT NULL,
                rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
                message TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'new',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                admin_id INTEGER NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY(admin_id) REFERENCES admins(id) ON DELETE CASCADE
            );
            """
        )
        if db.execute("SELECT 1 FROM admins LIMIT 1").fetchone() is None:
            db.execute(
                "INSERT INTO admins(username, password_hash, created_at) VALUES (?, ?, ?)",
                ("admin", hash_password(os.environ.get("MH_ADMIN_PASSWORD", "ChangeMe-2008!")), utc_now()),
            )
        if db.execute("SELECT 1 FROM services LIMIT 1").fetchone() is None:
            db.executemany(
                "INSERT INTO services(name, description, price_bdt, price_usd, delivery, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                [
                    ("Suspended Back", "Restore suspended or locked Facebook accounts.", 1000, "8", "4-5 Hours", utc_now()),
                    ("2FA Bypass", "Resolve authentication-code and lost-SIM issues.", 750, "6", "2-3 Hours", utc_now()),
                    ("Hacked ID Recovery", "Recover an account after unauthorized access.", 2000, "17", "1-3 Days", utc_now()),
                    ("Lock Id Unlock", "Unlock an account with identity information.", 1500, "12.5", "1-3 Days", utc_now()),
                    ("FB ACCOUNT PAGE REMOVE", "Submit an account or page removal request.", 4000, "33", "1-3 Days", utc_now()),
                    ("Page Remove", "Review and manage a page removal request.", 5000, "37", "1-3 Days", utc_now()),
                    ("Fake Copyright Report", "Submit a copyright dispute request.", 7500, "55", "1-5 Days", utc_now()),
                    ("Fake Copyright Restore", "Submit a copyright restoration request.", 2500, "22", "1-3 Days", utc_now()),
                    ("Instagram Account Remove", "Submit an Instagram account removal request.", 2500, "22", "1-3 Days", utc_now()),
                    ("Disabled Account Recover", "Submit a disabled account recovery request.", 8000, "65", "1-3 Days", utc_now()),
                ],
            )


def row_dict(row: sqlite3.Row | None) -> dict | None:
    return dict(row) if row else None


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "MHSocial/1.0"

    def log_message(self, format: str, *args: object) -> None:
        return

    def send_json(self, payload: dict, status: int = HTTPStatus.OK, cookies: list[str] | None = None) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        origin = self.headers.get("Origin")
        if origin in {"null", "http://127.0.0.1:8000", "http://localhost:8000"}:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        for cookie in cookies or []:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self) -> None:
        origin = self.headers.get("Origin")
        if origin not in {"null", "http://127.0.0.1:8000", "http://localhost:8000"}:
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 1_000_000:
            raise ValueError("Request is too large")
        return json.loads(self.rfile.read(length) or b"{}")

    def cookie(self, name: str) -> str | None:
        raw = self.headers.get("Cookie", "")
        for item in raw.split(";"):
            key, _, value = item.strip().partition("=")
            if key == name:
                return value
        return None

    def admin_id(self) -> int | None:
        token = self.cookie(COOKIE_NAME)
        if not token:
            return None
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with connect() as db:
            row = db.execute(
                "SELECT admin_id FROM sessions WHERE token_hash = ? AND expires_at > ?",
                (token_hash, utc_now()),
            ).fetchone()
        return int(row["admin_id"]) if row else None

    def require_admin(self) -> bool:
        if self.admin_id() is None:
            self.send_json({"error": "Authentication required"}, HTTPStatus.UNAUTHORIZED)
            return False
        return True

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/public":
            with connect() as db:
                services = [row_dict(row) for row in db.execute("SELECT * FROM services WHERE active = 1 ORDER BY id")]
                reviews = [row_dict(row) for row in db.execute("SELECT id, customer_name, rating, message, created_at FROM reviews WHERE status = 'approved' ORDER BY id DESC")]
                count = db.execute("SELECT COUNT(*) FROM reviews WHERE status != 'rejected'").fetchone()[0]
            self.send_json({"services": services, "reviews": reviews, "total_reviews": count})
            return
        if path == "/api/admin/dashboard":
            if not self.require_admin():
                return
            with connect() as db:
                counts = {key: db.execute(query).fetchone()[0] for key, query in {
                    "total_orders": "SELECT COUNT(*) FROM orders",
                    "pending_orders": "SELECT COUNT(*) FROM orders WHERE status = 'pending'",
                    "processing_orders": "SELECT COUNT(*) FROM orders WHERE status = 'processing'",
                    "completed_orders": "SELECT COUNT(*) FROM orders WHERE status = 'completed'",
                    "cancelled_orders": "SELECT COUNT(*) FROM orders WHERE status = 'cancelled'",
                    "total_reviews": "SELECT COUNT(*) FROM reviews WHERE status != 'rejected'",
                    "new_reviews": "SELECT COUNT(*) FROM reviews WHERE status = 'new'",
                    "total_services": "SELECT COUNT(*) FROM services WHERE active = 1",
                }.items()}
                orders = [row_dict(row) for row in db.execute("SELECT orders.*, services.name AS service_name FROM orders LEFT JOIN services ON services.id = orders.service_id ORDER BY orders.id DESC")]
                reviews = [row_dict(row) for row in db.execute("SELECT * FROM reviews ORDER BY id DESC")]
                services = [row_dict(row) for row in db.execute("SELECT * FROM services ORDER BY id")]
            self.send_json({"counts": counts, "orders": orders, "reviews": reviews, "services": services})
            return
        self.serve_file(path)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try:
            body = self.read_json()
        except (ValueError, json.JSONDecodeError):
            self.send_json({"error": "Invalid JSON"}, HTTPStatus.BAD_REQUEST)
            return
        if path == "/api/login":
            with connect() as db:
                admin = db.execute("SELECT * FROM admins WHERE username = ?", (str(body.get("username", "")),)).fetchone()
            if not admin or not verify_password(str(body.get("password", "")), admin["password_hash"]):
                self.send_json({"error": "Invalid credentials"}, HTTPStatus.UNAUTHORIZED)
                return
            token = secrets.token_urlsafe(32)
            expires = datetime.now(timezone.utc) + SESSION_TTL
            with connect() as db:
                db.execute("INSERT INTO sessions(token_hash, admin_id, expires_at) VALUES (?, ?, ?)", (hashlib.sha256(token.encode()).hexdigest(), admin["id"], expires.isoformat()))
            cookie = f"{COOKIE_NAME}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={int(SESSION_TTL.total_seconds())}"
            self.send_json({"ok": True}, cookies=[cookie])
            return
        if path == "/api/logout":
            token = self.cookie(COOKIE_NAME)
            if token:
                with connect() as db:
                    db.execute("DELETE FROM sessions WHERE token_hash = ?", (hashlib.sha256(token.encode()).hexdigest(),))
            self.send_json({"ok": True}, cookies=[f"{COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"])
            return
        if path == "/api/reviews":
            name, message = str(body.get("name", "")).strip(), str(body.get("message", "")).strip()
            rating = int(body.get("rating", 0))
            if not name or not message or rating not in range(1, 6) or len(name) > 80 or len(message) > 1000:
                self.send_json({"error": "Please provide a valid name, rating, and review."}, HTTPStatus.BAD_REQUEST)
                return
            with connect() as db:
                db.execute("INSERT INTO reviews(customer_name, rating, message, created_at) VALUES (?, ?, ?, ?)", (name, rating, message, utc_now()))
            self.send_json({"ok": True, "message": "Review submitted for approval."}, HTTPStatus.CREATED)
            return
        if path == "/api/orders":
            name, contact = str(body.get("name", "")).strip(), str(body.get("contact", "")).strip()
            service_id = body.get("service_id")
            if not name or not contact or len(name) > 80 or len(contact) > 120:
                self.send_json({"error": "Name and contact are required."}, HTTPStatus.BAD_REQUEST)
                return
            with connect() as db:
                service = db.execute("SELECT id FROM services WHERE id = ? AND active = 1", (service_id,)).fetchone()
                if not service:
                    self.send_json({"error": "Select an available service."}, HTTPStatus.BAD_REQUEST)
                    return
                db.execute("INSERT INTO orders(service_id, customer_name, customer_contact, notes, created_at) VALUES (?, ?, ?, ?, ?)", (service_id, name, contact, str(body.get("notes", ""))[:1000], utc_now()))
            self.send_json({"ok": True, "message": "Order received."}, HTTPStatus.CREATED)
            return
        if path.startswith("/api/admin/") and self.require_admin():
            self.admin_action(path, body)
            return
        self.send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)

    def do_PATCH(self) -> None:
        path = urlparse(self.path).path
        if not self.require_admin():
            return
        try:
            body = self.read_json()
        except (ValueError, json.JSONDecodeError):
            self.send_json({"error": "Invalid JSON"}, HTTPStatus.BAD_REQUEST)
            return
        with connect() as db:
            if path.startswith("/api/admin/orders/"):
                order_id = path.rsplit("/", 1)[-1]
                if body.get("status") not in {"pending", "processing", "completed", "cancelled"}:
                    self.send_json({"error": "Invalid order status"}, HTTPStatus.BAD_REQUEST)
                    return
                db.execute("UPDATE orders SET status = ? WHERE id = ?", (body["status"], order_id))
            elif path.startswith("/api/admin/reviews/"):
                review_id = path.rsplit("/", 1)[-1]
                if body.get("status") not in {"new", "approved", "rejected"}:
                    self.send_json({"error": "Invalid review status"}, HTTPStatus.BAD_REQUEST)
                    return
                db.execute("UPDATE reviews SET status = ? WHERE id = ?", (body["status"], review_id))
            else:
                self.send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
                return
        self.send_json({"ok": True})

    def admin_action(self, path: str, body: dict) -> None:
        with connect() as db:
            if path == "/api/admin/services":
                name = str(body.get("name", "")).strip()
                if not name:
                    self.send_json({"error": "Service name is required"}, HTTPStatus.BAD_REQUEST)
                    return
                db.execute("INSERT INTO services(name, description, price_bdt, price_usd, delivery, created_at) VALUES (?, ?, ?, ?, ?, ?)", (name, str(body.get("description", "")), max(0, int(body.get("price_bdt", 0))), str(body.get("price_usd", "")), str(body.get("delivery", "")), utc_now()))
                self.send_json({"ok": True}, HTTPStatus.CREATED)
                return
        self.send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)

    def serve_file(self, path: str) -> None:
        relative = "v2.html" if path in {"/", ""} else path.lstrip("/")
        file_path = (ROOT / relative).resolve()
        if ROOT not in file_path.parents or not file_path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        content_type = "text/html; charset=utf-8" if file_path.suffix == ".html" else "text/plain; charset=utf-8"
        data = file_path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    init_db()
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    print(f"MH Social running at http://{host}:{port}")
    ThreadingHTTPServer((host, port), ApiHandler).serve_forever()
