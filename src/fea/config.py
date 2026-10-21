"""Image registry and settings: ~/.fea/images.toml (override with FEA_HOME)."""
from __future__ import annotations

import os
import tomllib
from pathlib import Path

import tomli_w

HOME = Path(os.environ.get("FEA_HOME", Path.home() / ".fea"))
CONF = HOME / "images.toml"
CACHE = HOME / "cache"
DEFAULT_TZ = "America/New_York"


def load() -> dict:
    if CONF.exists():
        with open(CONF, "rb") as f:
            d = tomllib.load(f)
    else:
        d = {}
    d.setdefault("settings", {}).setdefault("timezone", DEFAULT_TZ)
    d.setdefault("images", {})
    return d


def save(d: dict) -> None:
    HOME.mkdir(parents=True, exist_ok=True)
    with open(CONF, "wb") as f:
        tomli_w.dump(d, f)


def timezone() -> str:
    return os.environ.get("FEA_TZ") or load()["settings"]["timezone"]


def set_timezone(tz: str) -> None:
    d = load(); d["settings"]["timezone"] = tz; save(d)


def add_image(name: str, path: str, label: str = "", tz: str | None = None) -> dict:
    p = Path(path).expanduser().resolve()
    if not p.exists():
        raise FileNotFoundError(str(p))
    d = load()
    d["images"][name] = {"path": str(p), "label": label, "timezone": tz or d["settings"]["timezone"]}
    save(d)
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
    p = Path(name).expanduser()
    if p.exists():  # allow a direct path as the image name
        return {"name": p.name, "path": str(p.resolve()), "label": "", "timezone": d["settings"]["timezone"]}
    raise KeyError(f"unknown image '{name}'; registered: {', '.join(d['images']) or '(none)'}")


def cache_dir(image_name: str) -> Path:
    c = CACHE / image_name.replace("/", "_")
    c.mkdir(parents=True, exist_ok=True)
    return c
