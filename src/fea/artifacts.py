"""Artefact parsers: registry, event logs, SQLite, LNK, Prefetch, ESE databases, EXIF, hashes, file type, YARA."""
from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from . import config
from .images import handle, run, sha1_file
from .paths import check_local_read

MAX_REG_DEPTH = 4
MAX_REG_NODES = 3000
MAX_ESE_SCAN = 200000
MAX_OFFICE_PART = 32 << 20
MAX_FILEINFO_BYTES = 64 << 20


def _source(image: str | None, part: int | None, ref: str | None, local_path: str | None) -> tuple[Path, dict, ZoneInfo]:
    """Return a host path for the artefact, extracting from the image into the cache when needed."""
    if local_path:
        p = check_local_read(local_path)
        if not p.is_file():
            raise FileNotFoundError(local_path)
        tz = ZoneInfo(handle(image).meta.get("timezone") if image else config.timezone())
        return p, {"local_path": str(p), "sha1": sha1_file(p)}, tz
    if not (image and ref):
        raise ValueError("give image+ref (path or inode in the image) or local_path")
    h = handle(image)
    p, info = h.cached_copy(part, ref)
    return p, h.evidence(part, source=ref, sha1=info["sha1"], local_copy=str(p)), h.tz


def _ts(dt, tz: ZoneInfo):
    if dt is None:
        return None
    if isinstance(dt, (int, float)):
        dt = datetime.fromtimestamp(dt, tz=timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return {"utc": dt.isoformat(), "local": dt.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S.%f %Z")}


def _iso_bound(s: str | None, tz: ZoneInfo):
    if not s:
        return None
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=tz)


# ---- Windows registry -------------------------------------------------------------------
def registry_key(image: str | None, part: int | None, ref: str | None, key: str = "", depth: int = 1, local_path: str | None = None, max_values: int = 200) -> dict:
    from regipy.registry import RegistryHive
    from regipy.utils import convert_wintime
    p, ev, tz = _source(image, part, ref, local_path)
    hive = RegistryHive(str(p))
    key = key.strip("\\")
    try:
        nk = hive.get_key("\\" + key) if key else hive.root
    except Exception as e:
        return {"error": f"key not found: {key} ({type(e).__name__})", "evidence": ev}
    depth = max(0, min(depth, MAX_REG_DEPTH))
    budget = {"nodes": 0}

    def dump(k, d):
        budget["nodes"] += 1
        vals = []
        for v in list(k.iter_values(as_json=True))[:max_values]:
            vals.append({"name": v.name, "type": v.value_type, "value": v.value if not isinstance(v.value, bytes) else v.value.hex()[:400]})
        try:
            lw = _ts(convert_wintime(k.header.last_modified, as_json=False), tz)
        except Exception:
            lw = None
        out = {"name": k.name, "last_write": lw, "values": vals, "subkeys": []}
        subs = list(k.iter_subkeys())
        if d > 0 and budget["nodes"] < MAX_REG_NODES:
            out["subkeys"] = [dump(sk, d - 1) for sk in subs]
        else:
            out["subkeys"] = [sk.name for sk in subs]
        return out
    data = dump(nk, depth)
    lim = ["transaction logs (.LOG1/.LOG2) are not replayed; a dirty hive may lack the newest writes"]
    if budget["nodes"] >= MAX_REG_NODES:
        lim.append(f"output capped at {MAX_REG_NODES} keys; narrow the key or reduce depth")
    return {"data": data, "evidence": {**ev, "tool": "regipy"}, "limitations": lim}


def registry_plugins(image: str | None, part: int | None, ref: str | None, plugins: list[str] | None = None, local_path: str | None = None) -> dict:
    """Run regipy plugins (e.g. user_assist, shellbags_ntuser, word_wheel_query, typed_paths, usbstor_plugin, services, computer_name, timezone_data, ...)."""
    from regipy.plugins.utils import run_relevant_plugins
    from regipy.registry import RegistryHive
    p, ev, tz = _source(image, part, ref, local_path)
    hive = RegistryHive(str(p))
    res = run_relevant_plugins(hive, as_json=True, plugins=plugins) if plugins else run_relevant_plugins(hive, as_json=True)
    return {"data": res, "evidence": {**ev, "tool": "regipy plugins"}, "limitations": ["plugin output times are UTC ISO strings"]}


# ---- Windows event logs -------------------------------------------------------------------
def evtx(image: str | None, part: int | None, ref: str | None, event_ids: list[int] | None = None, start: str | None = None, end: str | None = None,
         contains: str | None = None, provider: str | None = None, limit: int = 300, local_path: str | None = None) -> dict:
    from evtx import PyEvtxParser
    p, ev, tz = _source(image, part, ref, local_path)
    t0, t1 = _iso_bound(start, tz), _iso_bound(end, tz)
    rx = re.compile(contains, re.I) if contains else None
    ids = set(event_ids or [])
    out, total, first, last, errors = [], 0, None, None, 0
    for r in PyEvtxParser(str(p)).records_json():
        total += 1
        try:
            j = json.loads(r["data"])["Event"]
            s = j.get("System", {})
            rid = s.get("EventRecordID"); first = rid if first is None else first; last = rid
            eid = s.get("EventID"); eid = eid.get("#text") if isinstance(eid, dict) else eid
            if ids and eid not in ids:
                continue
            prov = (s.get("Provider") or {}).get("#attributes", {}).get("Name", "")
            if provider and provider.lower() not in prov.lower():
                continue
            ts = datetime.fromisoformat(s["TimeCreated"]["#attributes"]["SystemTime"].replace("Z", "+00:00"))
        except Exception:
            errors += 1; continue
        if (t0 and ts < t0) or (t1 and ts > t1):
            continue
        data = j.get("EventData") or j.get("UserData") or {}
        if isinstance(data, dict) and len(data) == 1 and isinstance(next(iter(data.values())), dict):
            data = next(iter(data.values()))  # UserData wrappers such as LogFileCleared
        flat = {k: v for k, v in (data.items() if isinstance(data, dict) else []) if v not in (None, "") and not str(k).startswith("#")}
        if rx and not rx.search(json.dumps(flat, default=str) + prov):
            continue
        if len(out) < limit:
            out.append({"record_id": rid, "event_id": eid, "provider": prov, "time": _ts(ts, tz), "computer": s.get("Computer"),
                        "user_sid": (s.get("Security") or {}).get("#attributes", {}).get("UserID"), "data": flat})
    return {"events": out, "records_in_file": total, "record_id_range": [first, last], "parse_errors": errors, "truncated": len(out) >= limit,
            "evidence": {**ev, "tool": "evtx (rust parser)"}}


# ---- SQLite ---------------------------------------------------------------------------------
def _sqlite_source(image, part, ref, local_path):
    """Extract the DB and, when present in the image, its -wal / -journal siblings so pending pages are visible."""
    p, ev, tz = _source(image, part, ref, local_path)
    sidecars = []
    if not local_path and ref and not re.match(r"^(inode:)?\d+", ref):
        h = handle(image)
        for suffix in ("-wal", "-journal"):
            try:
                sp, info = h.cached_copy(part, ref + suffix)
                target = p.with_name(p.name + suffix)
                if sp != target:
                    target.write_bytes(sp.read_bytes())
                sidecars.append(suffix)
            except Exception:
                pass
    ev["sidecars_applied"] = sidecars
    return p, ev, tz


def _sqlite_open(p: Path) -> sqlite3.Connection:
    if p.with_name(p.name + "-wal").exists():
        return sqlite3.connect(f"file:{p}?mode=ro", uri=True)
    return sqlite3.connect(f"file:{p}?mode=ro&immutable=1", uri=True)


def sqlite_tables(image: str | None, part: int | None, ref: str | None, local_path: str | None = None) -> dict:
    p, ev, _ = _sqlite_source(image, part, ref, local_path)
    con = _sqlite_open(p)
    try:
        tables = []
        for (name, _sql) in con.execute("select name, sql from sqlite_master where type='table'"):
            try:
                n = con.execute(f'select count(*) from "{name}"').fetchone()[0]
            except Exception:
                n = None
            cols = [c[1] for c in con.execute(f'pragma table_info("{name}")')]
            tables.append({"name": name, "rows": n, "columns": cols})
        fl = con.execute("pragma freelist_count").fetchone()[0]
    finally:
        con.close()
    wal = p.with_name(p.name + "-wal")
    return {"data": {"tables": tables, "freelist_pages": fl, "wal_present": wal.exists()}, "evidence": {**ev, "tool": "sqlite3 (read-only, immutable)"},
            "limitations": ["WAL/journal files are applied only when they exist next to the DB in the image; freelist pages may hold deleted rows (use strings)"]}


def sqlite_query(image: str | None, part: int | None, ref: str | None, sql: str, limit: int = 200, local_path: str | None = None) -> dict:
    if not re.match(r"^\s*(select|with|pragma|explain)\b", sql, re.I):
        raise ValueError("read-only: only SELECT / WITH / PRAGMA / EXPLAIN are allowed")
    if re.search(r"\b(attach|detach|vacuum|load_extension|writefile|readfile)\b", sql, re.I):
        raise ValueError("read-only: that statement is not allowed")
    p, ev, _ = _sqlite_source(image, part, ref, local_path)
    con = _sqlite_open(p)
    try:
        con.execute("pragma query_only = 1")
        cur = con.execute(sql)
        cols = [c[0] for c in cur.description] if cur.description else []
        rows = []
        for r in cur:
            rows.append([v.hex()[:400] if isinstance(v, bytes) else v for v in r])
            if len(rows) >= limit:
                break
    finally:
        con.close()
    return {"data": {"columns": cols, "rows": rows, "truncated": len(rows) >= limit}, "evidence": {**ev, "tool": "sqlite3", "sql": sql}}


# ---- LNK / Prefetch -----------------------------------------------------------------------------
def lnk(image: str | None, part: int | None, ref: str | None, local_path: str | None = None) -> dict:
    import pylnk
    p, ev, tz = _source(image, part, ref, local_path)
    f = pylnk.file(); f.open(str(p))
    try:
        d = {"local_path": f.get_local_path(), "network_path": f.get_network_path(), "relative_path": f.get_relative_path(), "working_directory": f.get_working_directory(),
             "arguments": f.get_command_line_arguments(), "description": f.get_description(), "volume_label": f.get_volume_label(),
             "drive_serial": f"{f.get_drive_serial_number():08X}" if f.get_drive_serial_number() is not None else None, "drive_type": f.get_drive_type(),
             "machine_identifier": f.get_machine_identifier(), "target_size": f.get_file_size(),
             "target_created": _ts(f.get_file_creation_time(), tz), "target_modified": _ts(f.get_file_modification_time(), tz), "target_accessed": _ts(f.get_file_access_time(), tz),
             "droid_volume_id": str(f.get_droid_volume_identifier()) if f.get_droid_volume_identifier() else None,
             "droid_file_id": str(f.get_droid_file_identifier()) if f.get_droid_file_identifier() else None}
    finally:
        f.close()
    return {"data": d, "evidence": {**ev, "tool": "liblnk"}}


def prefetch(image: str | None, part: int | None, ref: str | None, local_path: str | None = None) -> dict:
    import pyscca
    p, ev, tz = _source(image, part, ref, local_path)
    f = pyscca.file(); f.open(str(p))
    try:
        runs = []
        for i in range(8):
            try:
                t = f.get_last_run_time(i)
                if t and t.year > 1601:
                    runs.append(_ts(t, tz))
            except Exception:
                break
        d = {"executable": f.executable_filename, "format_version": f.format_version, "run_count": f.run_count, "prefetch_hash": f"{f.prefetch_hash:08X}",
             "last_runs": runs, "volumes": [{"device_path": v.device_path, "serial": f"{v.serial_number:08X}", "created": _ts(v.creation_time, tz)} for v in f.volumes],
             "files": [f.get_filename(i) for i in range(f.number_of_filenames)]}
    finally:
        f.close()
    return {"data": d, "evidence": {**ev, "tool": "libscca"}, "limitations": ["Windows 10 prefetch is MAM-compressed; libscca handles it", "last_runs holds up to 8 most recent runs"]}


# ---- ESE databases (SRUM, Windows Search, WebCache, NTDS) ------------------------------------------
def esedb_tables(image: str | None, part: int | None, ref: str | None, local_path: str | None = None) -> dict:
    from dissect.esedb import EseDB
    p, ev, _ = _source(image, part, ref, local_path)
    with open(p, "rb") as fh:
        db = EseDB(fh)
        tables = [{"name": t.name, "columns": [c.name for c in t.columns][:80], "column_count": len(t.columns)} for t in db.tables()]
    return {"data": {"tables": tables}, "evidence": {**ev, "tool": "dissect.esedb"}}


def esedb_dump(image: str | None, part: int | None, ref: str | None, table: str, columns: list[str] | None = None, limit: int = 200, contains: str | None = None, local_path: str | None = None) -> dict:
    from dissect.esedb import EseDB
    p, ev, tz = _source(image, part, ref, local_path)
    rx = re.compile(contains, re.I) if contains else None
    rows, total = [], 0
    with open(p, "rb") as fh:
        db = EseDB(fh)
        t = db.table(table)
        cols = columns or [c.name for c in t.columns]
        for rec in t.records():
            total += 1
            if total > MAX_ESE_SCAN:
                break
            row = {}
            for c in cols:
                try:
                    v = rec.get(c)
                except Exception:
                    v = None
                if isinstance(v, bytes):
                    v = v.hex()[:200]
                elif isinstance(v, datetime):
                    v = _ts(v, tz)
                row[c] = v
            if rx and not rx.search(json.dumps(row, default=str)):
                continue
            if len(rows) < limit:
                rows.append(row)
            elif not rx:
                break
    lim = [] if total <= MAX_ESE_SCAN else [f"scan stopped after {MAX_ESE_SCAN} records"]
    return {"data": {"table": table, "rows": rows, "records_scanned": total, "truncated": len(rows) >= limit}, "evidence": {**ev, "tool": "dissect.esedb"}, "limitations": lim}


# ---- Generic file helpers --------------------------------------------------------------------------
def exif(image: str | None, part: int | None, ref: str | None, local_path: str | None = None) -> dict:
    from .tools import find_tool
    p, ev, _ = _source(image, part, ref, local_path)
    if find_tool("exiftool"):
        r = run(["exiftool", "-j", "-a", "-G1", "-struct", str(p)], timeout=120)
        try:
            data = json.loads(r.stdout.decode(errors="replace"))[0]
        except Exception:
            data = {"raw": r.stdout.decode(errors="replace")[:4000], "stderr": r.stderr.decode(errors="replace")[:500]}
        for k in ("SourceFile", "System:FileName", "System:Directory", "System:FilePermissions", "System:FileModifyDate", "System:FileAccessDate", "System:FileInodeChangeDate"):
            data.pop(k, None)
        return {"data": data, "evidence": {**ev, "tool": "exiftool"}, "limitations": ["host file-system fields of the extracted copy were removed; use stat for image times"]}
    data, lim = _exif_pure(p)
    return {"data": data, "evidence": {**ev, "tool": "Pillow/zipfile (exiftool not installed)"}, "limitations": lim}


def _exif_pure(p: Path):
    """Fallback metadata without exiftool: image EXIF via Pillow, OOXML core/app properties via zipfile."""
    lim = ["exiftool not installed: only EXIF/PNG text (Pillow) and OOXML properties are read"]
    try:
        from PIL import ExifTags, Image
        with Image.open(p) as im:
            d = {"Format": im.format, "ImageSize": f"{im.width}x{im.height}", "Mode": im.mode}
            ex = im.getexif()
            for tag, val in ex.items():
                d[ExifTags.TAGS.get(tag, str(tag))] = val if not isinstance(val, bytes) else val[:64].hex()
            try:
                for ifd in (ExifTags.IFD.Exif, ExifTags.IFD.GPSInfo):
                    for tag, val in ex.get_ifd(ifd).items():
                        name = ExifTags.TAGS.get(tag) or ExifTags.GPSTAGS.get(tag) or str(tag)
                        d[name] = val if not isinstance(val, bytes) else val[:64].hex()
            except Exception:
                pass
            for k, v in (getattr(im, "info", {}) or {}).items():
                if isinstance(v, (str, int, float)) and k not in d:
                    d[f"info:{k}"] = v
            return d, lim
    except Exception:
        pass
    if zipfile.is_zipfile(p):
        d = {}
        with zipfile.ZipFile(p) as z:
            for name in ("docProps/core.xml", "docProps/app.xml"):
                if name in z.namelist():
                    xml = z.read(name).decode("utf-8", errors="replace")
                    for m in re.finditer(r"<(?:\w+:)?(\w+)[^>]*>([^<]{1,300})</", xml):
                        d[m.group(1)] = m.group(2)
        return d, lim
    return {"note": "no parser for this file type without exiftool"}, lim


def file_info(image: str | None, part: int | None, ref: str | None, local_path: str | None = None, trailing_check: bool = True) -> dict:
    """Type (libmagic/puremagic), SHA1/MD5/SHA256 (streamed), entropy of the first 8 MiB, and a trailing-data check for JPEG/PNG/PDF."""
    from .tools import file_type
    p, ev, _ = _source(image, part, ref, local_path)
    size = p.stat().st_size
    h1, h5, h256 = hashlib.sha1(), hashlib.md5(), hashlib.sha256()
    head, tail_buf = b"", b""
    counts = [0] * 256
    with open(p, "rb") as fh:
        n_ent = 0
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h1.update(chunk); h5.update(chunk); h256.update(chunk)
            if len(head) < 16:
                head += chunk[:16 - len(head)]
            if n_ent < 8 << 20:
                for b in chunk[: (8 << 20) - n_ent]:
                    counts[b] += 1
                n_ent += min(len(chunk), (8 << 20) - n_ent)
            tail_buf = (tail_buf + chunk)[-(1 << 16):]
    d = {"size": size, "type": file_type(p, head), "sha1": h1.hexdigest(), "md5": h5.hexdigest(), "sha256": h256.hexdigest()}
    if n_ent:
        d["entropy"] = round(-sum(c / n_ent * math.log2(c / n_ent) for c in counts if c), 3)
    if trailing_check and head:
        ends = {b"\xff\xd8": (b"\xff\xd9", "JPEG"), b"\x89PNG": (b"IEND\xaeB`\x82", "PNG"), b"%PDF": (b"%%EOF", "PDF")}
        for magic, (eof, kind) in ends.items():
            if head.startswith(magic):
                idx = tail_buf.rfind(eof)
                d["container"] = kind
                d["bytes_after_eof"] = None if idx < 0 else max(0, len(tail_buf) - (idx + len(eof)) - (1 if kind == "PDF" and tail_buf.endswith(b"\n") else 0))
                if idx < 0:
                    d.setdefault("notes", []).append(f"no {kind} end marker in the last 64 KiB")
        if head.startswith(b"PK\x03\x04"):
            d["container"] = "ZIP/OOXML"
    return {"data": d, "evidence": {**ev, "tool": "puremagic/file + hashlib"}}


def yara_scan(image: str | None, part: int | None, ref: str | None, rules: str, local_path: str | None = None) -> dict:
    """rules = YARA rule text or a path (inside allowed roots) to a .yar file."""
    import yara
    p, ev, _ = _source(image, part, ref, local_path)
    rp = Path(rules).expanduser()
    if rules.strip().endswith((".yar", ".yara")) and rp.exists():
        comp = yara.compile(filepath=str(check_local_read(str(rp))))
    else:
        comp = yara.compile(source=rules)
    matches = []
    for m in comp.match(str(p), timeout=120):
        matches.append({"rule": m.rule, "tags": m.tags, "strings": [{"offset": s.instances[0].offset, "id": s.identifier, "data": s.instances[0].matched_data[:64].hex()} for s in m.strings][:50]})
    return {"data": {"matches": matches}, "evidence": {**ev, "tool": "yara-python"}}


def office_parts(image: str | None, part: int | None, ref: str | None, local_path: str | None = None, max_chars: int = 20000) -> dict:
    """List the parts of an OOXML/ZIP file and return document text, comments, core/app properties and custom XML (hidden text and revisions flagged)."""
    p, ev, _ = _source(image, part, ref, local_path)
    out = {"parts": [], "texts": {}}
    lim = []
    with zipfile.ZipFile(p) as z:
        for i in z.infolist():
            out["parts"].append({"name": i.filename, "size": i.file_size, "compressed": i.compress_size, "date": list(i.date_time)})
            if re.search(r"(document|comments|core|app|custom|sharedStrings|sheet\d+|slide\d+|notesSlide\d+|footnotes|endnotes|header\d*|footer\d*)\.xml$", i.filename):
                if i.file_size > MAX_OFFICE_PART:
                    lim.append(f"{i.filename} skipped ({i.file_size} bytes > cap)"); continue
                xml = z.read(i.filename).decode("utf-8", errors="replace")
                flags = []
                if "w:vanish" in xml:
                    flags.append("hidden text (w:vanish)")
                if "<w:del " in xml or "<w:ins " in xml:
                    flags.append("tracked changes")
                txt = re.sub(r"<[^>]+>", " ", xml)
                txt = re.sub(r"\s+", " ", txt).strip()
                out["texts"][i.filename] = {"flags": flags, "text": txt[:max_chars], "truncated": len(txt) > max_chars}
    return {"data": out, "evidence": {**ev, "tool": "zipfile"}, "limitations": lim}
