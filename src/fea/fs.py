"""File-system level operations: ls, stat, read, extract, find, timeline, recover.
Pure Python (pytsk3) throughout; the native sleuthkit binaries are used only as optional accelerators when installed."""
from __future__ import annotations

import re
import subprocess
from datetime import datetime
from pathlib import Path

import pytsk3

from . import config
from .images import ImageHandle, handle, meta_dict, ntfs_filename_times, run
from .tools import find_tool

BODY_FIELDS = ["md5", "name", "inode", "mode", "uid", "gid", "size", "atime", "mtime", "ctime", "crtime"]
_INODE = re.compile(r"^(inode:)?\d+$")


def ls(image: str, part: int | None, path: str = "/", show_deleted: bool = True, limit: int = 500) -> dict:
    h = handle(image)
    fs = h.fs(part)
    p = path if path.startswith("/") else "/" + path
    d = fs.open_dir(path=p) if not _INODE.match(path) else fs.open_dir(inode=int(path.split(":")[-1]))
    rows, n = [], 0
    for e in d:
        name = e.info.name.name
        if name in (b".", b".."):
            continue
        row = meta_dict(h, e, name)
        if not show_deleted and (row.get("name_deleted") or (row.get("inode") is not None and not row.get("allocated", True))):
            continue
        streams = [a.info.name.decode(errors="replace") for a in h.data_attrs(e) if a.info.name] if row.get("inode") else []
        if streams:
            row["ads"] = streams
        n += 1
        if n <= limit:
            rows.append(row)
    return {"path": p, "entries": rows, "total": n, "truncated": n > limit, "evidence": h.evidence(part, source=p)}


def stat(image: str, part: int | None, ref: str) -> dict:
    h = handle(image)
    f = h.open(part, ref)
    d = meta_dict(h, f)
    attrs = []
    try:
        for a in f:
            attrs.append({"type": str(a.info.type).replace("TSK_FS_ATTR_TYPE_", ""), "id": a.info.id,
                          "name": (a.info.name or b"").decode(errors="replace"), "size": a.info.size,
                          "resident": bool(int(a.info.flags) & int(pytsk3.TSK_FS_ATTR_RES))})
    except OSError:
        pass
    d["attributes"] = attrs
    fn = ntfs_filename_times(h, f)
    if fn:
        d["filename_attr_times"] = fn
        if fn.get("crtime") and d.get("crtime") and fn["crtime"]["utc"] > d["crtime"]["utc"]:
            d["timestomp_indicator"] = "$STANDARD_INFORMATION creation time is EARLIER than $FILE_NAME creation time"
    inode = d.get("inode")
    if inode is not None and find_tool("istat"):
        r = run(["istat", "-z", "UTC", "-o", str(h.part_offset_sectors(part)), h.path, str(inode)], timeout=60)
        if r.returncode == 0:
            d["istat"] = r.stdout.decode(errors="replace")[:6000]
    return {"data": d, "evidence": h.evidence(part, source=ref, inode=inode, tool="pytsk3" + ("+istat" if "istat" in d else ""))}


def read(image: str, part: int | None, ref: str, offset: int = 0, length: int = 4096, stream: str | None = None, as_text: bool = True) -> dict:
    h = handle(image)
    f = h.open(part, ref)
    attr = None
    if stream:
        attr = next((a for a in h.data_attrs(f) if (a.info.name or b"").decode(errors="replace") == stream), None)
        if attr is None:
            raise FileNotFoundError(f"stream '{stream}' not found")
    length = min(length, 4 << 20)
    data = h.read_attr(f, attr, offset, length)
    total = attr.info.size if attr is not None else (f.info.meta.size if f.info.meta else 0)
    out = {"offset": offset, "returned": len(data), "total_size": total}
    if as_text:
        txt = data.decode("utf-8", errors="replace")
        if "\x00" in txt and len(data) > 2:
            alt = data.decode("utf-16-le", errors="replace")
            if alt.count("�") < txt.count("�"):
                txt = alt; out["decoded_as"] = "utf-16-le"
        out["text"] = txt
    else:
        out["hex"] = data.hex()
    return {"data": out, "evidence": h.evidence(part, source=ref, inode=f.info.meta.addr if f.info.meta else None, stream=stream)}


def extract(image: str, part: int | None, ref: str, out_dir: str, stream: str | None = None, name: str | None = None) -> dict:
    h = handle(image)
    f = h.open(part, ref)
    base = name or (Path(ref).name if ref.startswith("/") else f"inode{f.info.meta.addr if f.info.meta else 0}")
    if stream:
        base += "~" + stream
    dest = Path(out_dir).expanduser() / base
    r = h.extract(part, ref, dest, stream)
    return {"data": r, "evidence": h.evidence(part, source=ref, inode=f.info.meta.addr if f.info.meta else None, stream=stream, tool="pytsk3 read_random")}


# ---- body file (fls -m format) cache: basis for find and timeline --------------------------------------
def _walk_body(h: ImageHandle, part: int | None, out) -> int:
    """Pure-Python recursive walk producing fls -m style lines (allocated and deleted names)."""
    fs = h.fs(part)
    seen, n = set(), 0
    stack = [("/", fs.open_dir(path="/"))]
    while stack:
        prefix, d = stack.pop()
        for e in d:
            nm = e.info.name
            if nm is None or nm.name in (b".", b".."):
                continue
            name = nm.name.decode(errors="replace")
            full = (prefix + name) if prefix.endswith("/") else prefix + "/" + name
            m = e.info.meta
            deleted = bool(int(nm.flags) & int(pytsk3.TSK_FS_NAME_FLAG_UNALLOC))
            if m is None and nm.meta_addr:
                try:
                    m = fs.open_meta(inode=nm.meta_addr).info.meta
                except OSError:
                    m = None
            if m is None:
                out.write(f"0|{full}{' (deleted)' if deleted else ''}|0|0|0|0|0|0|0|0|0\n"); n += 1
                continue
            if not deleted and not (int(m.flags) & int(pytsk3.TSK_FS_META_FLAG_ALLOC)):
                deleted = True
            is_dir = int(m.type) == int(pytsk3.TSK_FS_META_TYPE_DIR)
            inode = f"{m.addr}"
            if is_dir and not deleted and m.addr in seen:
                continue
            out.write(f"0|{full}{'/' if is_dir else ''}{' (deleted)' if deleted else ''}|{inode}|{'d' if is_dir else 'r'}/{'d' if is_dir else 'r'}rwxrwxrwx|{m.uid}|{m.gid}|{m.size}|{m.atime or 0}|{m.mtime or 0}|{m.ctime or 0}|{m.crtime or 0}\n")
            n += 1
            if is_dir and not deleted and m.addr not in seen and name not in ("$OrphanFiles",):
                seen.add(m.addr)
                try:
                    stack.append((full, fs.open_dir(inode=m.addr)))
                except OSError:
                    pass
    # orphan files (deleted entries without a parent) if the file system exposes them
    try:
        od = fs.open_dir(path="/$OrphanFiles")
        for e in od:
            m = e.info.meta
            if m is None or e.info.name.name in (b".", b".."):
                continue
            out.write(f"0|/$OrphanFiles/{e.info.name.name.decode(errors='replace')} (deleted)|{m.addr}|r/rrwxrwxrwx|{m.uid}|{m.gid}|{m.size}|{m.atime or 0}|{m.mtime or 0}|{m.ctime or 0}|{m.crtime or 0}\n"); n += 1
    except OSError:
        pass
    return n


def body_path(h: ImageHandle, part: int | None) -> Path:
    part = part if part is not None else h.default_part()
    p = config.cache_dir(h.name) / f"p{part}.body"
    if not p.exists() or p.stat().st_size == 0:
        fls = find_tool("fls")
        if fls:
            with open(p, "wb") as out:
                subprocess.run([fls, "-r", "-m", "/", "-o", str(h.part_offset_sectors(part)), h.path], stdout=out, stderr=subprocess.DEVNULL, timeout=3600)
        if not fls or p.stat().st_size == 0:
            with open(p, "w", encoding="utf-8", errors="replace") as out:
                _walk_body(h, part, out)
    return p


def iter_body(h: ImageHandle, part: int | None):
    with open(body_path(h, part), "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.rstrip("\n").split("|")
            if len(parts) < 11:
                continue
            d = dict(zip(BODY_FIELDS, parts))
            name = d["name"]
            d["deleted"] = name.endswith("(deleted)") or name.endswith("(deleted-realloc)")
            d["name"] = re.sub(r" \(deleted(-realloc)?\)$", "", name).rstrip("/") or "/"
            for k in ("size", "atime", "mtime", "ctime", "crtime"):
                try:
                    d[k] = int(d[k])
                except ValueError:
                    d[k] = 0
            yield d


def _parse_time(s: str | None, h: ImageHandle) -> int | None:
    if not s:
        return None
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=h.tz)
    return int(dt.timestamp())


def find(image: str, part: int | None, pattern: str, regex: bool = False, deleted: str = "any", min_size: int = 0, max_size: int | None = None,
         mtime_from: str | None = None, mtime_to: str | None = None, limit: int = 500, include_filename_attr: bool = False) -> dict:
    """pattern matches the full path (case-insensitive); glob by default (* ? allowed)."""
    h = handle(image)
    if regex:
        rx = re.compile(pattern, re.I)
    elif "*" in pattern or "?" in pattern:
        rx = re.compile("^" + re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".") + "$", re.I)
    else:
        rx = re.compile(re.escape(pattern), re.I)
    t0, t1 = _parse_time(mtime_from, h), _parse_time(mtime_to, h)
    rows, n = [], 0
    for d in iter_body(h, part):
        if not include_filename_attr and d["name"].endswith("($FILE_NAME)"):
            continue
        if not rx.search(d["name"]):
            continue
        if deleted == "only" and not d["deleted"]:
            continue
        if deleted == "no" and d["deleted"]:
            continue
        if d["size"] < min_size or (max_size is not None and d["size"] > max_size):
            continue
        if t0 and d["mtime"] < t0 or t1 and d["mtime"] > t1:
            continue
        n += 1
        if n <= limit:
            rows.append({"path": d["name"], "inode": d["inode"], "size": d["size"], "deleted": d["deleted"],
                         "mtime": h.ts(d["mtime"]), "crtime": h.ts(d["crtime"])})
    return {"matches": rows, "total": n, "truncated": n > limit, "evidence": h.evidence(part, tool="file-system walk (cached body file)"),
            "limitations": ["name-based search over the file-system tree (allocated + deleted names); content is not searched, use grep"]}


def timeline(image: str, part: int | None, start: str | None = None, end: str | None = None, path_regex: str | None = None,
             kinds: str = "mcb", include_deleted: bool = True, limit: int = 1000) -> dict:
    """kinds: letters from m (modified) a (accessed) c (changed/MFT) b (born/created)."""
    h = handle(image)
    t0, t1 = _parse_time(start, h), _parse_time(end, h)
    rx = re.compile(path_regex, re.I) if path_regex else None
    events = []
    for d in iter_body(h, part):
        if d["name"].endswith("($FILE_NAME)") or (rx and not rx.search(d["name"])):
            continue
        if not include_deleted and d["deleted"]:
            continue
        for k, key in (("m", "mtime"), ("a", "atime"), ("c", "ctime"), ("b", "crtime")):
            if k not in kinds:
                continue
            t = d[key]
            if not t or (t0 and t < t0) or (t1 and t > t1):
                continue
            events.append((t, k, d))
    events.sort(key=lambda e: e[0])
    out = [{"time": h.ts(t), "kind": k, "path": d["name"], "inode": d["inode"], "size": d["size"], "deleted": d["deleted"]} for t, k, d in events[:limit]]
    return {"events": out, "total": len(events), "truncated": len(events) > limit, "evidence": h.evidence(part, tool="file-system walk (body file)"),
            "limitations": ["$STANDARD_INFORMATION times only (NTFS $FILE_NAME times via stat); body-file times are second precision"]}


def recover_deleted(image: str, part: int | None, out_dir: str, path_regex: str | None = None, progress=None) -> dict:
    """Recover deleted files (names still present in the tree or orphaned) into out_dir. Uses tsk_recover when installed, else pure Python."""
    h = handle(image)
    dest = Path(out_dir).expanduser(); dest.mkdir(parents=True, exist_ok=True)
    rx = re.compile(path_regex, re.I) if path_regex else None
    if find_tool("tsk_recover"):
        r = run(["tsk_recover", "-e", "-o", str(h.part_offset_sectors(part)), h.path, str(dest)], timeout=7200)
        kept, removed = 0, 0
        for p in list(dest.rglob("*")):
            if p.is_file():
                if rx and not rx.search(str(p.relative_to(dest))):
                    p.unlink(); removed += 1
                else:
                    kept += 1
        return {"data": {"out_dir": str(dest), "files": kept, "filtered_out": removed, "tool_output": r.stdout.decode(errors="replace")[-500:]},
                "evidence": h.evidence(part, tool="tsk_recover -e")}
    fs = h.fs(part); kept, errors, seen = 0, 0, set()
    for d in iter_body(h, part):
        if not d["deleted"] or d["size"] <= 0 or d["name"].endswith("($FILE_NAME)") or (rx and not rx.search(d["name"])):
            continue
        inode = int(d["inode"].split("-")[0])
        if inode in seen or inode == 0:
            continue
        seen.add(inode)
        try:
            f = fs.open_meta(inode=inode)
            if f.info.meta is None or int(f.info.meta.type) == int(pytsk3.TSK_FS_META_TYPE_DIR):
                continue
            rel = d["name"].lstrip("/").replace(":", "_")
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, "wb") as out:
                off, total = 0, f.info.meta.size
                while off < total:
                    chunk = h.read_attr(f, None, off, min(8 << 20, total - off))
                    if not chunk:
                        break
                    out.write(chunk); off += len(chunk)
            kept += 1
            if progress and kept % 100 == 0:
                progress(f"{kept} files recovered")
        except Exception:
            errors += 1
    return {"data": {"out_dir": str(dest), "files": kept, "errors": errors}, "evidence": h.evidence(part, tool="pytsk3 deleted-entry walk"),
            "limitations": ["deleted files whose clusters were reused come back with foreign content; verify by type/hash", "only entries that still have a name (incl. orphans) are recovered; carve unallocated space for the rest"]}
