"""Password hashing (PBKDF2-SHA256) and session token serialization."""
import hashlib
import secrets

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

PBKDF2_ITERATIONS = 310_000


def hash_password(password: str, salt: str | None = None) -> dict:
    """Return {"hash": hex, "salt": hex}."""
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ITERATIONS
    )
    return {"hash": dk.hex(), "salt": salt}


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ITERATIONS
    )
    return secrets.compare_digest(dk.hex(), expected_hash)


def make_token(secret_key: str, payload: dict) -> str:
    s = URLSafeTimedSerializer(secret_key, salt="titan-session")
    return s.dumps(payload)


def read_token(secret_key: str, token: str, max_age: int) -> dict | None:
    s = URLSafeTimedSerializer(secret_key, salt="titan-session")
    try:
        return s.loads(token, max_age=max_age)
    except (BadSignature, SignatureExpired):
        return None
