"""Artefact parsers: registry, event logs, SQLite, LNK, Prefetch, ESE databases, EXIF, hashes, file type, YARA."""
from __future__ import annotations
import json, re, sqlite3, subprocess
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo
from . import config
from .images import handle, sha1_file, run


def _source(image: str | None, part: int | None, ref: str | None, local_path: str | None) -> tuple[Path, dict, ZoneInfo]:
    """Return a host path for the artefact, extracting from the image into the cache when needed."""
    if local_path:
        p = Path(local_path).expanduser()
        if not p.exists():
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


# ---- Windows registry -------------------------------------------------------------------
def registry_key(image: str | None, part: int | None, ref: str | None, key: str = "", depth: int = 1, local_path: str | None = None, max_values: int = 200) -> dict:
    from regipy.registry import RegistryHive
    p, ev, tz = _source(image, part, ref, local_path)
    hive = RegistryHive(str(p))
    key = key.strip("\\")
    try:
        nk = hive.get_key("\\" + key) if key else hive.root
    except Exception as e:
        return {"error": f"key not found: {key} ({e})", "evidence": ev}

    def dump(k, d):
        vals = []
        for v in list(k.iter_values(as_json=True))[:max_values]:
            vals.append({"name": v.name, "type": v.value_type, "value": v.value if not isinstance(v.value, bytes) else v.value.hex()[:400]})
        out = {"name": k.name, "last_write": _ts(datetime.fromisoformat(k.header.last_modified.isoformat()) if hasattr(k.header.last_modified, "isoformat") else None, tz) if hasattr(k.header, "last_modified") else None,
               "values": vals, "subkeys": []}
        try:
            from regipy.utils import convert_wintime
            out["last_write"] = _ts(convert_wintime(k.header.last_modified, as_json=False), tz)
        except Exception:
            pass
        if d > 0:
            for sk in k.iter_subkeys():
                out["subkeys"].append(dump(sk, d - 1))
        else:
            out["subkeys"] = [sk.name for sk in k.iter_subkeys()]
        return out
    return {"data": dump(nk, depth), "evidence": {**ev, "tool": "regipy"}, "limitations": ["transaction logs (.LOG1/.LOG2) are not replayed; a dirty hive may lack the newest writes"]}


def registry_plugins(image: str | None, part: int | None, ref: str | None, plugins: list[str] | None = None, local_path: str | None = None) -> dict:
    """Run regipy plugins (e.g. user_assist, shellbags_ntuser, word_wheel_query, typed_paths, usbstor_plugin, services, computer_name, timezone_data, ...)."""
    from regipy.registry import RegistryHive
    from regipy.plugins.utils import run_relevant_plugins
    p, ev, tz = _source(image, part, ref, local_path)
    hive = RegistryHive(str(p))
    res = run_relevant_plugins(hive, as_json=True, plugins=plugins) if plugins else run_relevant_plugins(hive, as_json=True)
    return {"data": res, "evidence": {**ev, "tool": "regipy plugins"}, "limitations": ["plugin output times are UTC ISO strings"]}


# ---- Windows event logs -------------------------------------------------------------------
def evtx(image: str | None, part: int | None, ref: str | None, event_ids: list[int] | None = None, start: str | None = None, end: str | None = None,
         contains: str | None = None, provider: str | None = None, limit: int = 300, local_path: str | None = None) -> dict:
    from evtx import PyEvtxParser
    p, ev, tz = _source(image, part, ref, local_path)
    t0 = datetime.fromisoformat(start).replace(tzinfo=tz) if start and datetime.fromisoformat(start).tzinfo is None else (datetime.fromisoformat(start) if start else None)
    t1 = datetime.fromisoformat(end).replace(tzinfo=tz) if end and datetime.fromisoformat(end).tzinfo is None else (datetime.fromisoformat(end) if end else None)
    rx = re.compile(contains, re.I) if contains else None
    ids = set(event_ids or [])
    out, total, first, last, errors = [], 0, None, None, 0
    for r in PyEvtxParser(str(p)).records_json():
        total += 1
        try:
            j = json.loads(r["data"])["Event"]
        except Exception:
            errors += 1; continue
        s = j.get("System", {})
        rid = s.get("EventRecordID"); first = rid if first is None else first; last = rid
        eid = s.get("EventID"); eid = eid.get("#text") if isinstance(eid, dict) else eid
        if ids and eid not in ids:
            continue
        prov = (s.get("Provider") or {}).get("#attributes", {}).get("Name", "")
        if provider and provider.lower() not in prov.lower():
            continue
        ts = datetime.fromisoformat(s["TimeCreated"]["#attributes"]["SystemTime"].replace("Z", "+00:00"))
        if (t0 and ts < t0) or (t1 and ts > t1):
            continue
        data = j.get("EventData") or j.get("UserData") or {}
        if isinstance(data, dict) and len(data) == 1 and isinstance(next(iter(data.values())), dict):
            data = next(iter(data.values()))  # UserData wrappers such as LogFileCleared
        flat = {k: v for k, v in (data.items() if isinstance(data, dict) else []) if v not in (None, "") and not str(k).startswith("#")}
        if rx and not rx.search(json.dumps(flat) + prov):
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
    tables = []
    for (name, sql) in con.execute("select name, sql from sqlite_master where type='table'"):
        try:
            n = con.execute(f'select count(*) from "{name}"').fetchone()[0]
        except Exception:
            n = None
        cols = [c[1] for c in con.execute(f'pragma table_info("{name}")')]
        tables.append({"name": name, "rows": n, "columns": cols})
    fl = con.execute("pragma freelist_count").fetchone()[0]
    con.close()
    wal = p.with_name(p.name + "-wal")
    return {"data": {"tables": tables, "freelist_pages": fl, "wal_present": wal.exists()}, "evidence": {**ev, "tool": "sqlite3 (read-only, immutable)"},
            "limitations": ["WAL/journal files are not applied unless extracted next to the DB; freelist pages may hold deleted rows (use strings)"]}


def sqlite_query(image: str | None, part: int | None, ref: str | None, sql: str, limit: int = 200, local_path: str | None = None) -> dict:
    if not re.match(r"^\s*(select|with|pragma|explain)\b", sql, re.I):
        raise ValueError("read-only: only SELECT / WITH / PRAGMA / EXPLAIN are allowed")
    p, ev, _ = _sqlite_source(image, part, ref, local_path)
    con = _sqlite_open(p)
    cur = con.execute(sql)
    cols = [c[0] for c in cur.description] if cur.description else []
    rows = []
    for r in cur:
        rows.append([v.hex()[:400] if isinstance(v, bytes) else v for v in r])
        if len(rows) >= limit:
            break
    con.close()
    return {"data": {"columns": cols, "rows": rows, "truncated": len(rows) >= limit}, "evidence": {**ev, "tool": "sqlite3", "sql": sql}}


# ---- LNK / Prefetch -----------------------------------------------------------------------------
def lnk(image: str | None, part: int | None, ref: str | None, local_path: str | None = None) -> dict:
    import pylnk
    p, ev, tz = _source(image, part, ref, local_path)
    f = pylnk.file(); f.open(str(p))
    g = lambda n: (getattr(f, n, None) if not callable(getattr(f, n, None)) else None)
    d = {"local_path": f.get_local_path(), "network_path": f.get_network_path(), "relative_path": f.get_relative_path(), "working_directory": f.get_working_directory(),
         "arguments": f.get_command_line_arguments(), "description": f.get_description(), "volume_label": f.get_volume_label(),
         "drive_serial": f"{f.get_drive_serial_number():08X}" if f.get_drive_serial_number() is not None else None, "drive_type": f.get_drive_type(),
         "machine_identifier": f.get_machine_identifier(), "target_size": f.get_file_size(),
         "target_created": _ts(f.get_file_creation_time(), tz), "target_modified": _ts(f.get_file_modification_time(), tz), "target_accessed": _ts(f.get_file_access_time(), tz),
         "droid_volume_id": str(f.get_droid_volume_identifier()) if f.get_droid_volume_identifier() else None, "droid_file_id": str(f.get_droid_file_identifier()) if f.get_droid_file_identifier() else None}
    f.close()
    return {"data": d, "evidence": {**ev, "tool": "liblnk"}}


def prefetch(image: str | None, part: int | None, ref: str | None, local_path: str | None = None) -> dict:
    import pyscca
    p, ev, tz = _source(image, part, ref, local_path)
    f = pyscca.file(); f.open(str(p))
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
    f.close()
    return {"data": d, "evidence": {**ev, "tool": "libscca"}, "limitations": ["Windows 10 prefetch is MAM-compressed; libscca handles it", "last_runs holds up to 8 most recent runs"]}


# ---- ESE databases (SRUM, Windows Search, Exchange-related, NTDS) ----------------------------------
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
    return {"data": {"table": table, "rows": rows, "records_in_table": total, "truncated": len(rows) >= limit}, "evidence": {**ev, "tool": "dissect.esedb"}}


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
        data.pop("SourceFile", None)
        return {"data": data, "evidence": {**ev, "tool": "exiftool"}, "limitations": ["file-system times shown by exiftool are those of the extracted copy, not the image"]}
    data, lim = _exif_pure(p)
    return {"data": data, "evidence": {**ev, "tool": "Pillow/zipfile (exiftool not installed)"}, "limitations": lim}


def _exif_pure(p: Path):
    """Fallback metadata without exiftool: image EXIF via Pillow, OOXML core/app properties via zipfile."""
    import zipfile
    lim = ["exiftool not installed: only EXIF/PNG text (Pillow) and OOXML properties are read"]
    try:
        from PIL import Image, ExifTags
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
    """Type (libmagic), hashes, size, entropy, and a trailing-data check for JPEG/PNG/ZIP/PDF."""
    import math
    p, ev, _ = _source(image, part, ref, local_path)
    from .tools import file_type
    data = p.read_bytes()
    import hashlib
    d = {"size": len(data), "type": file_type(p, data), "sha1": hashlib.sha1(data).hexdigest(), "md5": hashlib.md5(data).hexdigest(),
         "sha256": hashlib.sha256(data).hexdigest()}
    if data:
        counts = [0] * 256
        for b in data[: 8 << 20]:
            counts[b] += 1
        n = min(len(data), 8 << 20)
        d["entropy"] = round(-sum(c / n * math.log2(c / n) for c in counts if c), 3)
    if trailing_check and data:
        ends = {b"\xff\xd8": (b"\xff\xd9", "JPEG"), b"\x89PNG": (b"IEND\xaeB`\x82", "PNG"), b"%PDF": (b"%%EOF", "PDF")}
        for magic, (eof, kind) in ends.items():
            if data.startswith(magic):
                idx = data.rfind(eof)
                tail = len(data) - (idx + len(eof)) if idx >= 0 else None
                d["container"] = kind; d["bytes_after_eof"] = tail if tail is None else max(0, tail - (1 if kind == "PDF" and data.endswith(b"\n") else 0))
        if data.startswith(b"PK\x03\x04"):
            d["container"] = "ZIP/OOXML"
    return {"data": d, "evidence": {**ev, "tool": "file + hashlib"}}


def yara_scan(image: str | None, part: int | None, ref: str | None, rules: str, local_path: str | None = None) -> dict:
    """rules = YARA rule text or a path to a .yar file."""
    import yara
    p, ev, _ = _source(image, part, ref, local_path)
    rp = Path(rules).expanduser()
    comp = yara.compile(filepath=str(rp)) if rp.exists() else yara.compile(source=rules)
    matches = []
    for m in comp.match(str(p)):
        matches.append({"rule": m.rule, "tags": m.tags, "strings": [{"offset": s.instances[0].offset, "id": s.identifier, "data": s.instances[0].matched_data[:64].hex()} for s in m.strings][:50]})
    return {"data": {"matches": matches}, "evidence": {**ev, "tool": "yara-python"}}


def office_parts(image: str | None, part: int | None, ref: str | None, local_path: str | None = None, max_chars: int = 20000) -> dict:
    """List the parts of an OOXML/ZIP file and return document text, comments, core/app properties and custom XML (hidden text and revisions included)."""
    import zipfile
    p, ev, _ = _source(image, part, ref, local_path)
    out = {"parts": [], "texts": {}}
    with zipfile.ZipFile(p) as z:
        for i in z.infolist():
            out["parts"].append({"name": i.filename, "size": i.file_size, "compressed": i.compress_size, "date": list(i.date_time)})
            if re.search(r"(document|comments|core|app|custom|sharedStrings|sheet\d+|slide\d+|notesSlide\d+|footnotes|endnotes|header\d*|footer\d*)\.xml$", i.filename):
                xml = z.read(i.filename).decode("utf-8", errors="replace")
                flags = []
                if "w:vanish" in xml:
                    flags.append("hidden text (w:vanish)")
                if "<w:del " in xml or "<w:ins " in xml:
                    flags.append("tracked changes")
                txt = re.sub(r"<[^>]+>", " ", xml)
                txt = re.sub(r"\s+", " ", txt).strip()
                out["texts"][i.filename] = {"flags": flags, "text": txt[:max_chars]}
    return {"data": out, "evidence": {**ev, "tool": "zipfile"}}
