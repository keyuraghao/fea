"""Image registry and settings: ~/.fea/images.toml (override the folder with FEA_HOME)."""
from __future__ import annotations

import os
import tomllib
from pathlib import Path
from zoneinfo import ZoneInfo

import tomli_w

HOME = Path(os.environ.get("FEA_HOME", Path.home() / ".fea"))
CONF = HOME / "images.toml"
CACHE = HOME / "cache"
DEFAULT_TZ = "UTC"
_NAME_OK = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.")


def load() -> dict:
    d: dict = {}
    if CONF.exists():
        with open(CONF, "rb") as f:
            d = tomllib.load(f)
    d.setdefault("settings", {}).setdefault("timezone", DEFAULT_TZ)
    d.setdefault("images", {})
    return d


def save(d: dict) -> None:
    HOME.mkdir(parents=True, exist_ok=True)
    tmp = CONF.with_suffix(".tmp")
    with open(tmp, "wb") as f:
        tomli_w.dump(d, f)
    os.replace(tmp, CONF)


def timezone() -> str:
    return os.environ.get("FEA_TZ") or load()["settings"]["timezone"]


def validate_tz(tz: str) -> str:
    ZoneInfo(tz)  # raises for unknown zones
    return tz


def set_timezone(tz: str) -> None:
    d = load(); d["settings"]["timezone"] = validate_tz(tz); save(d)


def set_setting(key: str, value) -> None:
    d = load(); d["settings"][key] = value; save(d)


def add_image(name: str, path: str, label: str = "", tz: str | None = None) -> dict:
    if not name or set(name) - _NAME_OK:
        raise ValueError("image name may contain only letters, digits, '_', '-' and '.'")
    p = Path(path).expanduser().resolve()
    if not p.is_file():
        raise FileNotFoundError(str(p))
    d = load()
    d["images"][name] = {"path": str(p), "label": label, "timezone": validate_tz(tz) if tz else d["settings"]["timezone"]}
    save(d)
    try:  # drop any cached handle for a re-registered name
        from .images import handle
        handle.cache_clear()
    except Exception:
        pass
    return d["images"][name]


def remove_image(name: str) -> bool:
    d = load()
    ok = d["images"].pop(name, None) is not None
    save(d)
    return ok


def get_image(name: str) -> dict:
    d = load()
    if name in d["images"]:
        return {"name": name, **d["images"][name]}
    from .paths import check_image_path
    p = check_image_path(name)  # direct path: only when the access policy allows it
    return {"name": p.name, "path": str(p), "label": "", "timezone": d["settings"]["timezone"]}


def cache_dir(image_name: str) -> Path:
    from .paths import safe_name
    c = CACHE / safe_name(image_name, "image")
    c.mkdir(parents=True, exist_ok=True)
    return c
