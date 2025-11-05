import secrets
import string
from datetime import datetime, timezone


def generate_secret_value(
    length: int = 64,
    alphabet: str = string.ascii_letters + string.digits,
) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(length))


def utc_now() -> datetime:
    return datetime.now(tz=timezone.utc)
