"""Content search: allocated files, unallocated space, single files, raw disk ranges. Pure Python with optional blkls acceleration."""
from __future__ import annotations

import mmap
import re
import subprocess

import pytsk3

from .fs import iter_body
from .images import handle, private_handle, run
from .paths import check_local_read
from .tools import find_tool, iter_strings

ENC = {"utf8": lambda s: s.encode("utf-8"), "utf16le": lambda s: s.encode("utf-16-le"), "latin1": lambda s: s.encode("latin-1", errors="ignore")}
OVERLAP = 4096          # bytes kept between scan windows so a match on a boundary is still found once
IN_IMAGE_CAP = 512 << 20  # grep_file reads at most this much of an in-image file; extract and use local_path for more


def _patterns(terms: list[str], regex: bool, encodings: list[str] | None, ignore_case: bool):
    if not terms:
        raise ValueError("terms must not be empty")
    pats, flags = [], (re.I if ignore_case else 0)
    for t in terms:
        for e in encodings or ["utf8", "utf16le"]:
            if e not in ENC:
                raise ValueError(f"unknown encoding {e}; use utf8, utf16le, latin1")
            if regex:
                if e == "utf16le":
                    lit = "".join(ch + "\x00" if ch.isalnum() or ch in " @._-" else ch for ch in t)
                    pats.append((t, e, re.compile(lit.encode("latin-1", errors="ignore"), flags)))
                else:
                    pats.append((t, e, re.compile(t.encode("utf-8"), flags)))
            else:
                pats.append((t, e, re.compile(re.escape(ENC[e](t)), flags)))
    return pats


def _context(buf: bytes, m, enc: str, width: int = 80) -> str:
    a, b = max(0, m.start() - width), min(len(buf), m.end() + width)
    frag = buf[a:b]
    if enc == "utf16le":
        if a % 2:
            frag = buf[a + 1:b]
        txt = frag.decode("utf-16-le", errors="replace")
    else:
        txt = frag.decode("utf-8", errors="replace")
    return re.sub(r"[\x00-\x08\x0b-\x1f]", ".", txt)


def _scan_windows(reader, pats, on_hit, max_hits: int, context: int, max_bytes: int | None, progress, window: int = 8 << 20):
    """Generic windowed scan with overlap and de-duplication. reader(window) returns bytes (empty at end)."""
    pos, tail, hits = 0, b"", 0
    while True:
        buf = reader(window)
        if not buf:
            break
        data = tail + buf
        base = pos - len(tail)
        for term, enc, p in pats:
            for m in p.finditer(data):
                if m.end() <= len(tail):  # entirely inside the previous window: already reported
                    continue
                on_hit(term, enc, base + m.start(), _context(data, m, enc, context))
                hits += 1
                if hits >= max_hits:
                    return pos + len(buf), True
        pos += len(buf)
        tail = data[-OVERLAP:]
        if progress and (pos // window) % 32 == 0:
            progress(f"{pos >> 20} MiB scanned, {hits} hits")
        if max_bytes and pos >= max_bytes:
            break
    return pos, False


def grep_files(image: str, part: int | None, terms: list[str], path_regex: str = ".", regex: bool = False, encodings: list[str] | None = None,
               ignore_case: bool = True, max_file_mb: int = 64, max_files: int = 20000, max_hits: int = 300, include_deleted: bool = False, progress=None) -> dict:
    """Search file CONTENT of allocated (and optionally deleted) files whose path matches path_regex."""
    h = private_handle(image)
    pats = _patterns(terms, regex, encodings, ignore_case)
    rx = re.compile(path_regex, re.I)
    hits, scanned, skipped_big, errors = [], 0, 0, 0
    for d in iter_body(h, part):
        if len(hits) >= max_hits or scanned >= max_files:
            break
        if d["size"] == 0 or d["name"].endswith("($FILE_NAME)") or not rx.search(d["name"]) or (d["deleted"] and not include_deleted):
            continue
        if d["size"] > max_file_mb << 20:
            skipped_big += 1; continue
        try:
            f = h.fs(part).open_meta(inode=int(d["inode"].split("-")[0]))
            data = h.read_attr(f, None, 0, d["size"])
        except Exception:
            errors += 1; continue
        scanned += 1
        if progress and scanned % 500 == 0:
            progress(f"scanned {scanned} files, {len(hits)} hits")
        for term, enc, p in pats:
            for m in p.finditer(data):
                hits.append({"path": d["name"], "inode": d["inode"], "deleted": d["deleted"], "term": term, "encoding": enc, "offset": m.start(), "context": _context(data, m, enc)})
                if len(hits) >= max_hits:
                    break
            if len(hits) >= max_hits:
                break
    return {"hits": hits, "files_scanned": scanned, "skipped_over_size": skipped_big, "read_errors": errors, "truncated": len(hits) >= max_hits,
            "evidence": h.evidence(part, tool="pytsk3 content scan"), "limitations": ["compressed/encrypted containers are not opened; only raw file bytes are matched"]}


# ---- unallocated space -------------------------------------------------------------------------------------
def _ntfs_unalloc_runs(h, part):
    """Yield (first_block, count) runs of unallocated clusters from the NTFS $Bitmap."""
    fs = h.fs(part)
    bm = fs.open("/$Bitmap")
    data = h.read_attr(bm, None, 0, bm.info.meta.size)
    total = fs.info.block_count
    start, run_len = None, 0
    for byte_i in range((total + 7) // 8):
        byte = data[byte_i] if byte_i < len(data) else 0xFF
        if byte == 0xFF:  # fully allocated byte: close any open run
            if start is not None:
                yield start, run_len; start, run_len = None, 0
            continue
        if byte == 0x00 and byte_i * 8 + 8 <= total:  # fully free byte
            if start is None:
                start = byte_i * 8
            run_len += 8
            continue
        for bit in range(8):
            blk = byte_i * 8 + bit
            if blk >= total:
                break
            if not (byte >> bit) & 1:
                if start is None:
                    start = blk
                run_len += 1
            elif start is not None:
                yield start, run_len; start, run_len = None, 0
    if start is not None:
        yield start, run_len


def _unalloc_reader(h, part, chunk_blocks: int = 2048):
    """Return (reader, mode, block_of_stream_offset) over unallocated space. NTFS via $Bitmap; other file systems: whole volume (flagged)."""
    fs = h.fs(part)
    bs = fs.info.block_size
    base_off = h.part_offset_sectors(part) * 512
    if int(fs.info.ftype) == int(pytsk3.TSK_FS_TYPE_NTFS) or "NTFS" in str(fs.info.ftype):
        runs, mode = list(_ntfs_unalloc_runs(h, part)), "ntfs-bitmap"
    else:
        runs, mode = [(0, fs.info.block_count)], "whole-volume"
    segments = []  # (stream_offset, first_block, count)
    pos = 0
    for start, count in runs:
        segments.append((pos, start, count)); pos += count * bs
    state = {"i": 0, "off": 0}

    def reader(n_bytes: int) -> bytes:
        while state["i"] < len(segments):
            _, start, count = segments[state["i"]]
            if state["off"] >= count:
                state["i"] += 1; state["off"] = 0; continue
            n = min(chunk_blocks, count - state["off"], max(1, n_bytes // bs))
            try:
                data = h.img.read(base_off + (start + state["off"]) * bs, n * bs)
            except OSError:
                data = b"\x00" * (n * bs)
            state["off"] += n
            return data
        return b""

    def block_of(stream_offset: int) -> tuple[int, int]:
        for s_off, start, count in segments:
            if s_off <= stream_offset < s_off + count * bs:
                rel = stream_offset - s_off
                return start + rel // bs, rel % bs
        return -1, 0
    return reader, mode, block_of, bs


def grep_unallocated(image: str, part: int | None, terms: list[str], regex: bool = False, encodings: list[str] | None = None, ignore_case: bool = True,
                     max_hits: int = 300, context: int = 80, progress=None, max_bytes: int | None = None) -> dict:
    """Match terms in unallocated space. Hits carry real file-system block numbers in both modes (blkls stream offsets are mapped back)."""
    h = private_handle(image)
    pats = _patterns(terms, regex, encodings, ignore_case)
    hits = []
    fs = h.fs(part); bs = fs.info.block_size
    blkls = find_tool("blkls")
    if blkls:
        proc = subprocess.Popen([blkls, "-o", str(h.part_offset_sectors(part)), h.path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)

        def on_hit(term, enc, off, ctx):
            hits.append({"term": term, "encoding": enc, "blkls_offset": off, "blkls_unit": off // bs, "in_block_offset": off % bs, "context": ctx})
        try:
            scanned, truncated = _scan_windows(proc.stdout.read, pats, on_hit, max_hits, context, max_bytes, progress)
        finally:
            proc.kill()
        return {"hits": hits, "bytes_scanned": scanned, "truncated": truncated, "evidence": h.evidence(part, tool="blkls stream scan"),
                "limitations": ["blkls_offset is a position in the stream of unallocated blocks: map blkls_unit to a real block with blkcalc before quoting it"]}
    reader, mode, block_of, bs = _unalloc_reader(h, part)

    def on_hit2(term, enc, off, ctx):
        blk, inb = block_of(off)
        hits.append({"term": term, "encoding": enc, "fs_block": blk, "in_block_offset": inb, "volume_byte_offset": blk * bs + inb, "context": ctx})
    scanned, truncated = _scan_windows(reader, pats, on_hit2, max_hits, context, max_bytes, progress)
    lim = ["pure-Python scan: hits carry real file-system block numbers (use block_read)"]
    if mode == "whole-volume":
        lim.insert(0, "no allocation bitmap parser for this file system: the WHOLE volume (allocated + unallocated) was scanned")
    return {"hits": hits, "bytes_scanned": scanned, "truncated": truncated, "evidence": h.evidence(part, tool=f"pytsk3 block scan ({mode})"), "limitations": lim}


def _local_bytes(local_path: str):
    p = check_local_read(local_path)
    fh = open(p, "rb")
    try:
        mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
    except ValueError:  # empty file
        fh.close()
        return b"", {"local_path": str(p)}
    return mm, {"local_path": str(p), "_fh": fh}


def grep_file(image: str, part: int | None, ref: str, terms: list[str], regex: bool = False, encodings: list[str] | None = None, ignore_case: bool = True,
              max_hits: int = 200, local_path: str | None = None, context: int = 100) -> dict:
    """Search one file (in-image ref or a local file such as pagefile.sys you already extracted)."""
    pats = _patterns(terms, regex, encodings, ignore_case)
    lim = []
    if local_path:
        data, ev = _local_bytes(local_path)
    else:
        h = handle(image); f = h.open(part, ref)
        size = f.info.meta.size if f.info.meta else 0
        data = h.read_attr(f, None, 0, min(size, IN_IMAGE_CAP)); ev = h.evidence(part, source=ref, inode=f.info.meta.addr if f.info.meta else None)
        if size > IN_IMAGE_CAP:
            lim.append(f"only the first {IN_IMAGE_CAP >> 20} MiB of the file were searched; extract it and use local_path for a full scan")
    hits = []
    try:
        for term, enc, p in pats:
            for m in p.finditer(data):
                hits.append({"term": term, "encoding": enc, "offset": m.start(), "context": _context(data, m, enc, context)})
                if len(hits) >= max_hits:
                    break
            if len(hits) >= max_hits:
                break
        size = len(data)
    finally:
        fh = ev.pop("_fh", None)
        if fh:
            data.close(); fh.close()
    return {"hits": hits, "size": size, "truncated": len(hits) >= max_hits, "evidence": ev, "limitations": lim}


def strings(image: str, part: int | None, ref: str, min_len: int = 6, encoding: str = "both", pattern: str | None = None, limit: int = 500, local_path: str | None = None) -> dict:
    """Printable strings (ASCII and/or UTF-16LE) from a file with offsets, optionally filtered by a regex. Pure Python, memory-mapped."""
    if local_path:
        p = check_local_read(local_path); ev = {"local_path": str(p)}
    else:
        h = handle(image); p, info = h.cached_copy(part, ref); ev = h.evidence(part, source=ref, sha1=info["sha1"])
    rx = re.compile(pattern, re.I) if pattern else None
    encs = ("ascii", "utf16le") if encoding == "both" else (("utf16le",) if encoding == "utf16" else ("ascii",))
    out, total = [], 0
    with open(p, "rb") as fh:
        try:
            data = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        except ValueError:
            data = b""
        try:
            for off, enc, s in iter_strings(data, max(2, min_len), encs):
                if rx and not rx.search(s):
                    continue
                total += 1
                if len(out) < limit:
                    out.append({"offset": off, "encoding": enc, "string": s[:2000]})
        finally:
            if data:
                data.close()
    return {"strings": out, "total": total, "truncated": total > limit, "evidence": {**ev, "tool": "pure-python strings (mmap)"}}


def disk_read(image: str, offset: int, length: int = 512, as_text: bool = False) -> dict:
    """Raw bytes from the image at an absolute byte offset (hex dump by default)."""
    h = handle(image)
    length = max(0, min(length, 1 << 20))
    data = h.img.read(max(0, offset), length)
    out = {"offset": offset, "returned": len(data)}
    if as_text:
        out["text"] = re.sub(r"[\x00-\x08\x0b-\x1f]", ".", data.decode("utf-8", errors="replace"))
    else:
        out["hexdump"] = hexdump(data, offset)
    return {"data": out, "evidence": h.evidence()}


def block_read(image: str, part: int | None, block: int, count: int = 1, as_text: bool = False) -> dict:
    """Read file-system blocks (clusters) by number, e.g. to follow up a grep_unallocated hit."""
    h = handle(image)
    fs = h.fs(part)
    bs = fs.info.block_size
    count = max(1, min(count, (1 << 20) // bs))
    data = h.img.read(h.part_offset_sectors(part) * 512 + block * bs, count * bs)
    out = {"block": block, "count": count, "block_size": bs}
    if as_text:
        out["text"] = re.sub(r"[\x00-\x08\x0b-\x1f]", ".", data.decode("utf-8", errors="replace"))
    else:
        out["hexdump"] = hexdump(data[:65536], block * bs)
    return {"data": out, "evidence": h.evidence(part, tool="image read at block offset")}


def blkcalc(image: str, part: int | None, blkls_offset: int) -> dict:
    """Map a blkls stream byte offset to the real file-system block number."""
    h = handle(image)
    fs = h.fs(part)
    bs = fs.info.block_size
    unit = blkls_offset // bs
    if find_tool("blkcalc"):
        r = run(["blkcalc", "-u", str(unit), "-o", str(h.part_offset_sectors(part)), h.path], timeout=600)
        txt = r.stdout.decode(errors="replace").strip()
        try:
            blk = int(txt.split()[0])
        except Exception:
            blk = None
        return {"data": {"blkls_unit": unit, "fs_block": blk, "block_size": bs, "in_block_offset": blkls_offset % bs, "raw": txt or r.stderr.decode(errors="replace")}, "evidence": h.evidence(part, tool="blkcalc -u")}
    seen = 0
    for start, count in _ntfs_unalloc_runs(h, part) if int(fs.info.ftype) == int(pytsk3.TSK_FS_TYPE_NTFS) else []:
        if seen + count > unit:
            return {"data": {"blkls_unit": unit, "fs_block": start + (unit - seen), "block_size": bs, "in_block_offset": blkls_offset % bs, "method": "NTFS bitmap walk"}, "evidence": h.evidence(part)}
        seen += count
    return {"error": "blkcalc not installed and no bitmap parser for this file system; pure-mode grep_unallocated hits already carry fs_block"}


def hexdump(data: bytes, base: int = 0, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + i:010x}  {hx:<{width * 3}} |{asc}|")
    return "\n".join(lines)
