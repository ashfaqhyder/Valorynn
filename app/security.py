"""Password, signed-session, and CSRF helpers.

Passwords are deliberately never reversible or logged. Session values are signed and
short-lived; the actual account identifier remains private to the browser session.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time

from app.config import settings

PASSWORD_COST = 2**14
PASSWORD_MEMORY = 8
PASSWORD_PARALLELISM = 1
SESSION_MAX_AGE = 60 * 60 * 12


def hash_password(password: str) -> str:
    if len(password) < 10:
        raise ValueError("Use a password of at least 10 characters.")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=PASSWORD_COST, r=PASSWORD_MEMORY, p=PASSWORD_PARALLELISM
    )
    return "scrypt$%s$%s" % (
        base64.urlsafe_b64encode(salt).decode("ascii"),
        base64.urlsafe_b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, encoded_salt, encoded_digest = stored.split("$", 2)
        if algorithm != "scrypt":
            return False
        calculated = hashlib.scrypt(
            password.encode("utf-8"),
            salt=base64.urlsafe_b64decode(encoded_salt),
            n=PASSWORD_COST,
            r=PASSWORD_MEMORY,
            p=PASSWORD_PARALLELISM,
        )
        return hmac.compare_digest(calculated, base64.urlsafe_b64decode(encoded_digest))
    except (ValueError, TypeError):
        return False


def _sign(value: str) -> str:
    return hmac.new(settings.secret_key.encode(), value.encode(), hashlib.sha256).hexdigest()


def create_session(user_id: int) -> str:
    payload = f"{user_id}:{int(time.time())}:{secrets.token_urlsafe(12)}"
    return f"{payload}.{_sign(payload)}"


def read_session(value: str | None) -> int | None:
    if not value or "." not in value:
        return None
    payload, signature = value.rsplit(".", 1)
    if not hmac.compare_digest(signature, _sign(payload)):
        return None
    try:
        user_id, issued_at, _nonce = payload.split(":", 2)
        if int(time.time()) - int(issued_at) > SESSION_MAX_AGE:
            return None
        return int(user_id)
    except ValueError:
        return None


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def valid_csrf(submitted: str | None, expected: str | None) -> bool:
    return bool(submitted and expected and hmac.compare_digest(submitted, expected))
