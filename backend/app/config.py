"""Settings from the environment, with the repo's .env as a fallback.

Values already in the environment win. Nothing here is ever printed.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from urllib.parse import unquote, urlsplit

ENV_FILE = Path(__file__).resolve().parents[2] / ".env"


def load_env(path: Path = ENV_FILE) -> None:
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def setting(name: str, default: str | None = None) -> str | None:
    load_env()
    value = os.environ.get(name)
    return value if value else default


REPO_ROOT = ENV_FILE.parent
SECRET_SETTINGS = ("GHOSTOPS_HMAC_SECRET", "GHOSTOPS_SIGNING_KEY", "GROQ_API_KEY", "GHOSTOPS_API_KEY",
                   "GHOSTOPS_DATABASE_URL")
LOCAL_ORIGINS = ("http://localhost:3000", "http://127.0.0.1:3000")


class ConfigError(RuntimeError):
    """A required setting is missing or invalid. The message never contains values."""


def check_required() -> None:
    """Refuse to start without what the backend cannot work without."""
    problems = []
    signing_key = setting("GHOSTOPS_SIGNING_KEY")
    if signing_key:
        from app.keys import SigningKeyError, load_private_key
        try:
            load_private_key(signing_key)
        except SigningKeyError as exc:
            problems.append(f"{exc} (generate one: python -m app.keys generate)")
    secret = setting("GHOSTOPS_HMAC_SECRET")
    if not secret and not signing_key:
        problems.append("GHOSTOPS_HMAC_SECRET is not set and neither is GHOSTOPS_SIGNING_KEY "
                        "(one of them signs every Risk Certificate; Ed25519 via python -m app.keys generate "
                        "is preferred).")
    elif secret and len(secret) < 32:
        problems.append("GHOSTOPS_HMAC_SECRET is shorter than 32 characters.")
    if hosted():
        key = setting("GHOSTOPS_API_KEY")
        if not key:
            problems.append("GHOSTOPS_API_KEY is not set (GHOSTOPS_HOSTED=1 requires it for every POST/PUT/DELETE).")
        elif len(key) < 24:
            problems.append("GHOSTOPS_API_KEY is shorter than 24 characters.")
    database_url = setting("GHOSTOPS_DATABASE_URL")
    if database_url and not database_url.startswith(("postgres://", "postgresql://")):
        problems.append("GHOSTOPS_DATABASE_URL must be a postgresql:// URL (leave it empty to use SQLite).")
    if problems:
        raise ConfigError(
            "GhostOps cannot start:\n  - " + "\n  - ".join(problems) + "\n"
            f"Add it to {ENV_FILE} (template: .env.example). Generate one with:\n"
            "  python -m app.keys generate   (GHOSTOPS_SIGNING_KEY, Ed25519)\n"
            '  python -c "import secrets; print(secrets.token_hex(32))"   (GHOSTOPS_HMAC_SECRET)'
        )


def hosted() -> bool:
    """GHOSTOPS_HOSTED=1: running on a public host (Render). Turns on the API key
    check and turns off everything that reads server paths named by the caller."""
    return (setting("GHOSTOPS_HOSTED") or "").strip().lower() in ("1", "true", "yes")


def cors_origins() -> list[str]:
    """The local dashboard plus GHOSTOPS_CORS_ORIGINS (comma-separated, e.g. a Vercel URL).

    Only explicit http(s) origins are accepted; "*" and anything else is ignored.
    """
    extra = [o.strip().rstrip("/") for o in (setting("GHOSTOPS_CORS_ORIGINS") or "").split(",")]
    origins = list(LOCAL_ORIGINS)
    for origin in extra:
        if origin.startswith(("https://", "http://")) and "*" not in origin and origin not in origins:
            origins.append(origin)
    return origins


def db_path() -> Path:
    """The SQLite file; not used when GHOSTOPS_DATABASE_URL selects Postgres (see app/store.py)."""
    return Path(setting("GHOSTOPS_DB_PATH") or REPO_ROOT / "data" / "ghostops.db")


def secret_values() -> list[str]:
    """Values that must never reach a log: secret settings and the database password."""
    values = [v for v in (setting(n) for n in SECRET_SETTINGS) if v]
    try:
        password = urlsplit(setting("GHOSTOPS_DATABASE_URL") or "").password
    except ValueError:
        password = None
    if password:
        values += [password, unquote(password)]
    return [v for v in values if len(v) >= 8]


def redact(text: str) -> str:
    for value in sorted(secret_values(), key=len, reverse=True):  # whole URL before its password
        text = text.replace(value, "[redacted]")
    return text


class SecretRedactingFilter(logging.Filter):
    """Replace the values of secret settings in any log record (defence in depth)."""

    def filter(self, record: logging.LogRecord) -> bool:
        if secret_values():
            message = record.getMessage()
            redacted = redact(message)
            if redacted != message:
                record.msg, record.args = redacted, None
        return True


def install_secret_filter(logger_names: tuple[str, ...] = ("", "uvicorn", "uvicorn.error", "uvicorn.access")) -> None:
    flt = SecretRedactingFilter()
    for name in logger_names:
        logger = logging.getLogger(name)
        for handler in logger.handlers:
            if not any(isinstance(f, SecretRedactingFilter) for f in handler.filters):
                handler.addFilter(flt)
        if not any(isinstance(f, SecretRedactingFilter) for f in logger.filters):
            logger.addFilter(flt)
