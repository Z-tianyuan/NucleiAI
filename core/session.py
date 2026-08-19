"""Session management — cookies, headers, and Bearer tokens for authenticated scanning."""

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class Session:
    name: str
    headers: dict[str, str]
    created: str = field(default_factory=lambda: datetime.now().isoformat())
    cookie: str = ""


def _sessions_dir() -> Path:
    from core.config import get_config
    cfg = get_config()
    raw = cfg.get("sessions_dir", "./sessions")
    path = Path(raw)
    if not path.is_absolute():
        base = Path(__file__).resolve().parent.parent
        path = base / raw
    return path


def parse_cookie_string(cookie_str: str) -> dict[str, str]:
    """Convert 'key1=val1; key2=val2' into {'Cookie': 'key1=val1; key2=val2'}."""
    cookie_str = cookie_str.strip()
    if not cookie_str:
        return {}
    return {"Cookie": cookie_str}


def parse_basic_auth(username: str, password: str) -> dict[str, str]:
    """Return {'Authorization': 'Basic <b64>'} header."""
    import base64
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def parse_bearer_token(token: str) -> dict[str, str]:
    """Return {'Authorization': 'Bearer <token>'} header."""
    return {"Authorization": f"Bearer {token}"}


def save_session(session: Session) -> None:
    d = _sessions_dir()
    d.mkdir(parents=True, exist_ok=True)
    data = {
        "name": session.name,
        "headers": session.headers,
        "created": session.created,
        "cookie": session.cookie,
    }
    filepath = d / f"{session.name}.json"
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def load_session(name: str) -> Session | None:
    filepath = _sessions_dir() / f"{name}.json"
    if not filepath.exists():
        return None
    with open(filepath, encoding="utf-8") as f:
        data = json.load(f)
    return Session(
        name=data["name"],
        headers=data.get("headers", {}),
        created=data.get("created", ""),
        cookie=data.get("cookie", ""),
    )


def list_sessions() -> list[str]:
    d = _sessions_dir()
    if not d.is_dir():
        return []
    return sorted(p.stem for p in d.glob("*.json") if p.is_file())


def delete_session(name: str) -> bool:
    filepath = _sessions_dir() / f"{name}.json"
    if filepath.exists():
        filepath.unlink()
        return True
    return False


def build_headers_from_form(cookie: str = "",
                             custom_headers: list[tuple[str, str]] | None = None,
                             bearer: str = "",
                             session_name: str = "") -> dict[str, str]:
    """Combine all auth sources into a single headers dict.

    Priority (lowest to highest): saved session < cookie < bearer < custom headers.
    """
    headers: dict[str, str] = {}

    if session_name:
        session = load_session(session_name)
        if session:
            headers.update(session.headers)

    if cookie:
        headers.update(parse_cookie_string(cookie))

    if bearer:
        headers.update(parse_bearer_token(bearer))

    if custom_headers:
        for key, value in custom_headers:
            key = key.strip()
            if key:
                headers[key] = value.strip()

    return headers
