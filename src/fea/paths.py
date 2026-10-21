"""Access policy for host paths.

The MCP server is driven by an agent that reads untrusted evidence; a planted instruction inside an image must not be able to
turn FEA into a way of reading or writing arbitrary files on the examiner's machine. Policy:

- Images may only be opened from the registry, or from paths under `allowed_roots` (settings) / FEA_ALLOWED_ROOTS.
- `local_path` arguments may only point inside the cache, the output root or `allowed_roots`.
- `out_dir` arguments (extract, recover_deleted) must be inside the output root (`~/.fea/out` by default, `output_root` setting / FEA_OUTPUT_ROOT).
- Names derived from image content are sanitised before they touch the host file system.

Set FEA_UNRESTRICTED=1 to disable the policy for interactive CLI use on a trusted machine.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from . import config

_BAD = re.compile(r'[<>:"|?*\x00-\x1f]')


class AccessDenied(PermissionError):
    pass


def unrestricted() -> bool:
    return os.environ.get("FEA_UNRESTRICTED") == "1"


def output_root() -> Path:
    s = os.environ.get("FEA_OUTPUT_ROOT") or config.load()["settings"].get("output_root") or str(config.HOME / "out")
    p = Path(s).expanduser()
    p.mkdir(parents=True, exist_ok=True)
    return p.resolve()


def allowed_roots() -> list[Path]:
    roots = list(config.load()["settings"].get("allowed_roots", []))
    env = os.environ.get("FEA_ALLOWED_ROOTS", "")
    roots += [x for x in env.split(os.pathsep) if x]
    return [Path(r).expanduser().resolve() for r in roots]


def _under(p: Path, root: Path) -> bool:
    try:
        p.resolve().relative_to(root)
        return True
    except ValueError:
        return False


def check_image_path(path: str) -> Path:
    """A path given directly as an image (not via the registry)."""
    p = Path(path).expanduser()
    if unrestricted():
        return p.resolve()
    if any(_under(p, r) for r in allowed_roots()):
        return p.resolve()
    raise AccessDenied(f"'{path}' is not a registered image and lies outside allowed_roots; register it with `fea images add` on the host")


def check_local_read(path: str) -> Path:
    p = Path(path).expanduser()
    if unrestricted():
        return p.resolve()
    roots = allowed_roots() + [config.CACHE.resolve(), output_root()]
    if any(_under(p, r) for r in roots):
        return p.resolve()
    raise AccessDenied(f"local_path '{path}' is outside the cache, the output root and allowed_roots")


def check_out_dir(path: str) -> Path:
    p = Path(path).expanduser()
    if unrestricted():
        p.mkdir(parents=True, exist_ok=True)
        return p.resolve()
    root = output_root()
    cand = p if p.is_absolute() else root / p
    if _under(cand, root) or cand.resolve() == root:
        cand.mkdir(parents=True, exist_ok=True)
        return cand.resolve()
    raise AccessDenied(f"out_dir '{path}' must be inside the output root {root} (set FEA_OUTPUT_ROOT or settings.output_root to change it)")


def safe_name(name: str, fallback: str = "item") -> str:
    """One path component derived from image content: no separators, no traversal, no Windows-invalid characters."""
    n = _BAD.sub("_", name.replace("\\", "/").split("/")[-1]).strip(" .")
    if n in ("", ".", ".."):
        n = fallback
    return n[:200]


def safe_relpath(path: str) -> Path:
    """A relative path built from image-side components, each sanitised, traversal removed."""
    parts = [safe_name(x) for x in path.replace("\\", "/").split("/") if x not in ("", ".", "..")]
    return Path(*parts) if parts else Path("item")


def policy_report() -> dict:
    return {"unrestricted": unrestricted(), "output_root": str(output_root()), "allowed_roots": [str(r) for r in allowed_roots()], "cache": str(config.CACHE)}
