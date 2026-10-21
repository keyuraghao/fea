"""Platform helpers: locate optional native tools, pure-Python strings and file typing."""
from __future__ import annotations
import os, re, shutil, sys
from pathlib import Path
from . import config

# Optional accelerators. Everything works without them; when present they are used for speed or extra detail.
OPTIONAL = {"fls": "sleuthkit", "istat": "sleuthkit", "blkls": "sleuthkit", "blkcalc": "sleuthkit", "tsk_recover": "sleuthkit", "exiftool": "exiftool"}
_WIN_DEFAULT_DIRS = [r"C:\Program Files\sleuthkit\bin", r"C:\Program Files (x86)\sleuthkit\bin", r"C:\Tools\sleuthkit\bin", r"C:\Program Files\exiftool"]
_MAC_DEFAULT_DIRS = ["/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin"]


def tool_dirs() -> list[str]:
    d = config.load().get("settings", {}).get("tool_dirs", [])
    env = os.environ.get("FEA_TOOL_DIRS", "")
    dirs = list(d) + [x for x in env.split(os.pathsep) if x]
    if sys.platform.startswith("win"):
        dirs += _WIN_DEFAULT_DIRS
    elif sys.platform == "darwin":
        dirs += _MAC_DEFAULT_DIRS
    return dirs


def find_tool(name: str) -> str | None:
    """Full path of a native tool or None. Searches PATH, configured tool_dirs and common install dirs; handles .exe on Windows.
    Set FEA_NO_NATIVE=1 to force the pure-Python code paths (useful for testing portability)."""
    if os.environ.get("FEA_NO_NATIVE"):
        return None
    cands = [name] + ([name + ".exe"] if sys.platform.startswith("win") else [])
    for c in cands:
        p = shutil.which(c)
        if p:
            return p
    for d in tool_dirs():
        for c in cands:
            p = Path(d) / c
            if p.exists():
                return str(p)
    return None


def tool_report() -> dict:
    import platform
    return {"platform": f"{platform.system()} {platform.release()} ({platform.machine()})", "python": sys.version.split()[0],
            "pure_python_forced": bool(os.environ.get("FEA_NO_NATIVE")),
            "optional_tools": {t: {"found": find_tool(t), "package": pkg} for t, pkg in OPTIONAL.items()},
            "note": "all tools work without the optional binaries; sleuthkit speeds up directory walks and unallocated scans, exiftool adds full metadata"}


# ---- strings (pure Python) --------------------------------------------------------------------------------
_ASCII = re.compile(rb"[\x20-\x7e\t]{%d,}")
_UTF16 = re.compile(rb"(?:[\x20-\x7e\t]\x00){%d,}")


def iter_strings(data: bytes, min_len: int = 6, encodings: tuple[str, ...] = ("ascii", "utf16le")):
    """Yield (offset, encoding, text) like GNU strings -t d (ASCII) and -e l (UTF-16LE)."""
    if "ascii" in encodings:
        rx = re.compile(_ASCII.pattern % min_len)
        for m in rx.finditer(data):
            yield m.start(), "ascii", m.group().decode("ascii")
    if "utf16le" in encodings:
        rx = re.compile(_UTF16.pattern % min_len)
        for m in rx.finditer(data):
            yield m.start(), "utf16le", m.group().decode("utf-16-le", errors="replace")


# ---- file typing ---------------------------------------------------------------------------------------------
def file_type(p: Path, data: bytes | None = None) -> str:
    exe = find_tool("file")
    if exe and not sys.platform.startswith("win"):
        import subprocess
        try:
            r = subprocess.run([exe, "-b", str(p)], capture_output=True, timeout=60)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.decode(errors="replace").strip()
        except Exception:
            pass
    try:
        import puremagic
        res = puremagic.magic_file(str(p))
        if res:
            best = res[0]
            return f"{best.name or best.mime_type} ({best.mime_type}, {best.extension}, confidence {best.confidence:.2f}) [puremagic]"
    except Exception:
        pass
    head = (data or p.read_bytes()[:16])[:16]
    return f"unknown (first bytes {head.hex()})"
