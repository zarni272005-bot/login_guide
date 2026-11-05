import hmac
import os
import re
import secrets
import sqlite3
from datetime import timedelta
from pathlib import Path

from flask import Flask, g, jsonify, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
DUMMY_PASSWORD_HASH = generate_password_hash(secrets.token_urlsafe(32))
SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY,
    full_name TEXT NOT NULL,
    contact_type TEXT NOT NULL CHECK (contact_type IN ('email', 'phone')),
    contact_value TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (contact_type, contact_value)
)
"""


def _secret_key(instance_path):
    configured_key = os.environ.get("SECRET_KEY")
    if configured_key:
        return configured_key

    key_path = Path(instance_path) / "flask_secret.key"
    try:
        with key_path.open("x", encoding="utf-8") as key_file:
            key_file.write(secrets.token_hex(32))
    except FileExistsError:
        pass
    return key_path.read_text(encoding="utf-8").strip()


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    app.config.from_mapping(
        SECRET_KEY=_secret_key(app.instance_path),
        DATABASE=str(Path(app.instance_path) / "accounts.sqlite3"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(days=7),
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    if test_config:
        app.config.update(test_config)

    def connect_db():
        connection = sqlite3.connect(app.config["DATABASE"], timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def init_db():
        database_path = Path(app.config["DATABASE"])
        database_path.parent.mkdir(parents=True, exist_ok=True)
        connection = connect_db()
        try:
            connection.execute(SCHEMA)
            connection.commit()
        finally:
            connection.close()

    def get_db():
        if "db" not in g:
            g.db = connect_db()
        return g.db

    @app.teardown_appcontext
    def close_db(_error=None):
        connection = g.pop("db", None)
        if connection is not None:
            connection.close()

    def json_error(message, status):
        return jsonify(error=message), status

    def csrf_is_valid():
        saved_token = session.get("csrf_token")
        submitted_token = request.headers.get("X-CSRF-Token", "")
        return bool(
            saved_token
            and submitted_token
            and hmac.compare_digest(saved_token, submitted_token)
        )

    def require_csrf():
        if not csrf_is_valid():
            return json_error("Your session expired. Refresh the page and try again.", 400)
        return None

    def normalize_contact(contact_type, value):
        if not isinstance(value, str):
            raise ValueError("Enter a valid email address or phone number.")
        value = value.strip()
        if contact_type == "email":
            value = value.lower()
            if len(value) > 254 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
                raise ValueError("Enter a valid email address.")
            return value
        if contact_type == "phone":
            value = re.sub(r"[\s().-]", "", value)
            if not re.fullmatch(r"\+?[1-9]\d{6,14}", value):
                raise ValueError("Enter a phone number with 7 to 15 digits.")
            return value
        raise ValueError("Choose email or phone.")

    def payload():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            raise ValueError("Submit the form data and try again.")
        return data

    def account_json(row):
        return {
            "id": row["id"],
            "name": row["full_name"],
            "contactType": row["contact_type"],
            "contact": row["contact_value"],
        }

    def sign_in(row):
        session.clear()
        session.permanent = True
        session["user_id"] = row["id"]
        session["csrf_token"] = secrets.token_urlsafe(32)
        return jsonify(account=account_json(row), csrfToken=session["csrf_token"])

    @app.after_request
    def set_api_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "img-src 'self' data:; "
            "style-src 'self' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "script-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'"
        )
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/")
    def index():
        return send_from_directory(BASE_DIR, "index.html")

    @app.get("/api/csrf")
    def csrf_token():
        token = session.setdefault("csrf_token", secrets.token_urlsafe(32))
        return jsonify(csrfToken=token)

    @app.get("/api/me")
    def current_account():
        account_id = session.get("user_id")
        if account_id is None:
            return jsonify(authenticated=False)
        row = get_db().execute(
            "SELECT id, full_name, contact_type, contact_value "
            "FROM accounts WHERE id = ?",
            (account_id,),
        ).fetchone()
        if row is None:
            session.clear()
            return jsonify(authenticated=False)
        return jsonify(authenticated=True, account=account_json(row))

    @app.post("/api/register")
    def register():
        csrf_error = require_csrf()
        if csrf_error:
            return csrf_error
        try:
            data = payload()
            full_name = data.get("name")
            if not isinstance(full_name, str) or not 2 <= len(full_name.strip()) <= 80:
                return json_error("Enter your name (2 to 80 characters).", 400)
            full_name = full_name.strip()
            contact_type = data.get("contactType")
            contact_value = normalize_contact(contact_type, data.get("identifier"))
            password = data.get("password")
            if not isinstance(password, str) or not 10 <= len(password) <= 128:
                return json_error("Use a password between 10 and 128 characters.", 400)

            password_hash = generate_password_hash(password)
            connection = get_db()
            cursor = connection.execute(
                "INSERT INTO accounts "
                "(full_name, contact_type, contact_value, password_hash) "
                "VALUES (?, ?, ?, ?)",
                (full_name, contact_type, contact_value, password_hash),
            )
            connection.commit()
        except ValueError as error:
            return json_error(str(error), 400)
        except sqlite3.IntegrityError:
            return json_error("An account already uses that email or phone number.", 409)

        row = connection.execute(
            "SELECT id, full_name, contact_type, contact_value "
            "FROM accounts WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
        return sign_in(row), 201

    @app.post("/api/login")
    def login():
        csrf_error = require_csrf()
        if csrf_error:
            return csrf_error
        try:
            data = payload()
            contact_type = data.get("contactType")
            contact_value = normalize_contact(contact_type, data.get("identifier"))
        except ValueError as error:
            return json_error(str(error), 400)

        password = data.get("password")
        if not isinstance(password, str) or not password or len(password) > 128:
            return json_error("The email/phone or password is incorrect.", 401)

        row = get_db().execute(
            "SELECT id, full_name, contact_type, contact_value, password_hash "
            "FROM accounts WHERE contact_type = ? AND contact_value = ?",
            (contact_type, contact_value),
        ).fetchone()
        stored_hash = row["password_hash"] if row is not None else DUMMY_PASSWORD_HASH
        password_matches = check_password_hash(stored_hash, password)
        if row is None or not password_matches:
            return json_error("The email/phone or password is incorrect.", 401)
        return sign_in(row)

    @app.post("/api/logout")
    def logout():
        csrf_error = require_csrf()
        if csrf_error:
            return csrf_error
        session.clear()
        return jsonify(authenticated=False)

    @app.errorhandler(413)
    def request_too_large(_error):
        return json_error("The request is too large.", 413)

    init_db()
    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
