"""Content search: allocated files, unallocated space, single files, raw disk ranges. Pure Python with optional blkls acceleration."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytsk3

from .fs import iter_body
from .images import handle, run
from .tools import find_tool, iter_strings

ENC = {"utf8": lambda s: s.encode("utf-8"), "utf16le": lambda s: s.encode("utf-16-le"), "latin1": lambda s: s.encode("latin-1", errors="ignore")}


def _patterns(terms: list[str], regex: bool, encodings: list[str], ignore_case: bool):
    pats = []
    flags = re.I if ignore_case else 0
    for t in terms:
        for e in encodings:
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


def grep_files(image: str, part: int | None, terms: list[str], path_regex: str = ".", regex: bool = False, encodings: list[str] | None = None,
               ignore_case: bool = True, max_file_mb: int = 64, max_files: int = 20000, max_hits: int = 300, include_deleted: bool = False, progress=None) -> dict:
    """Search file CONTENT of allocated (and optionally deleted) files whose path matches path_regex."""
    h = handle(image)
    pats = _patterns(terms, regex, encodings or ["utf8", "utf16le"], ignore_case)
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
    for blk in range(total):
        byte = data[blk >> 3] if (blk >> 3) < len(data) else 0xFF
        free = not (byte >> (blk & 7)) & 1
        if free:
            if start is None:
                start = blk
            run_len += 1
        elif start is not None:
            yield start, run_len; start, run_len = None, 0
    if start is not None:
        yield start, run_len


def _iter_unalloc_pure(h, part, chunk_blocks: int = 2048):
    """Yield (fs_block, bytes) chunks of unallocated space. NTFS via $Bitmap; other file systems: whole volume (flagged)."""
    fs = h.fs(part)
    bs = fs.info.block_size
    base_off = h.part_offset_sectors(part) * 512
    ftype = str(fs.info.ftype)
    if "NTFS" in ftype or int(fs.info.ftype) == int(pytsk3.TSK_FS_TYPE_NTFS):
        runs = _ntfs_unalloc_runs(h, part); mode = "ntfs-bitmap"
    else:
        runs = [(0, fs.info.block_count)]; mode = "whole-volume"
    for start, count in runs:
        off = 0
        while off < count:
            n = min(chunk_blocks, count - off)
            try:
                data = h.img.read(base_off + (start + off) * bs, n * bs)
            except OSError:
                off += n; continue
            yield start + off, data, mode
            off += n


def grep_unallocated(image: str, part: int | None, terms: list[str], regex: bool = False, encodings: list[str] | None = None, ignore_case: bool = True,
                     max_hits: int = 300, context: int = 80, progress=None, max_bytes: int | None = None) -> dict:
    """Match terms in unallocated space. With sleuthkit's blkls installed the stream is used (hits carry blkls offsets);
    otherwise a pure-Python walk of the allocation bitmap is used and hits carry real file-system block numbers."""
    h = handle(image)
    pats = _patterns(terms, regex, encodings or ["utf8", "utf16le"], ignore_case)
    hits, pos, overlap = [], 0, 512
    blkls = find_tool("blkls")
    fs = h.fs(part); bs = fs.info.block_size
    if blkls:
        proc = subprocess.Popen([blkls, "-o", str(h.part_offset_sectors(part)), h.path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
        tail, chunk = b"", 8 << 20
        try:
            while True:
                buf = proc.stdout.read(chunk)
                if not buf:
                    break
                data = tail + buf; base = pos - len(tail)
                for term, enc, p in pats:
                    for m in p.finditer(data):
                        if m.start() < len(tail) - overlap:
                            continue
                        hits.append({"term": term, "encoding": enc, "blkls_offset": base + m.start(), "context": _context(data, m, enc, context)})
                        if len(hits) >= max_hits:
                            break
                    if len(hits) >= max_hits:
                        break
                pos += len(buf); tail = data[-overlap:]
                if progress and (pos // chunk) % 64 == 0:
                    progress(f"{pos >> 20} MiB scanned, {len(hits)} hits")
                if len(hits) >= max_hits or (max_bytes and pos >= max_bytes):
                    break
        finally:
            proc.kill()
        return {"hits": hits, "bytes_scanned": pos, "truncated": len(hits) >= max_hits, "evidence": h.evidence(part, tool="blkls stream scan"),
                "limitations": ["offsets are positions in the blkls stream of unallocated blocks (map with blkcalc)", "a match may straddle a block boundary"]}
    mode = None
    for blk, data, mode in _iter_unalloc_pure(h, part):
        for term, enc, p in pats:
            for m in p.finditer(data):
                hits.append({"term": term, "encoding": enc, "fs_block": blk + m.start() // bs, "in_block_offset": m.start() % bs,
                             "volume_byte_offset": (blk * bs) + m.start(), "context": _context(data, m, enc, context)})
                if len(hits) >= max_hits:
                    break
            if len(hits) >= max_hits:
                break
        pos += len(data)
        if progress and (pos >> 20) % 256 == 0:
            progress(f"{pos >> 20} MiB scanned, {len(hits)} hits")
        if len(hits) >= max_hits or (max_bytes and pos >= max_bytes):
            break
    lim = ["pure-Python scan: hits carry real file-system block numbers (use block_read)", "matches straddling a chunk boundary can be missed"]
    if mode == "whole-volume":
        lim.insert(0, "no allocation bitmap parser for this file system: the WHOLE volume (allocated + unallocated) was scanned")
    return {"hits": hits, "bytes_scanned": pos, "truncated": len(hits) >= max_hits, "evidence": h.evidence(part, tool=f"pytsk3 block scan ({mode})"), "limitations": lim}


def grep_file(image: str, part: int | None, ref: str, terms: list[str], regex: bool = False, encodings: list[str] | None = None, ignore_case: bool = True,
              max_hits: int = 200, local_path: str | None = None, context: int = 100) -> dict:
    """Search one file (in-image ref or a local file such as pagefile.sys you already extracted)."""
    if local_path:
        data = Path(local_path).expanduser().read_bytes(); ev = {"local_path": local_path}
    else:
        h = handle(image); f = h.open(part, ref)
        data = h.read_attr(f, None, 0, min(f.info.meta.size, 2 << 30)); ev = h.evidence(part, source=ref, inode=f.info.meta.addr)
    pats = _patterns(terms, regex, encodings or ["utf8", "utf16le"], ignore_case)
    hits = []
    for term, enc, p in pats:
        for m in p.finditer(data):
            hits.append({"term": term, "encoding": enc, "offset": m.start(), "context": _context(data, m, enc, context)})
            if len(hits) >= max_hits:
                break
        if len(hits) >= max_hits:
            break
    return {"hits": hits, "size": len(data), "truncated": len(hits) >= max_hits, "evidence": ev}


def strings(image: str, part: int | None, ref: str, min_len: int = 6, encoding: str = "both", pattern: str | None = None, limit: int = 500, local_path: str | None = None) -> dict:
    """Printable strings (ASCII and/or UTF-16LE) from a file with offsets, optionally filtered by a regex. Pure Python."""
    if local_path:
        p = Path(local_path).expanduser(); ev = {"local_path": local_path}
    else:
        h = handle(image); p, info = h.cached_copy(part, ref); ev = h.evidence(part, source=ref, sha1=info["sha1"])
    rx = re.compile(pattern, re.I) if pattern else None
    encs = ("ascii", "utf16le") if encoding == "both" else (("utf16le",) if encoding == "utf16" else ("ascii",))
    out, total = [], 0
    with open(p, "rb") as fh:
        data = fh.read(1 << 30)  # 1 GiB cap
    for off, enc, s in iter_strings(data, min_len, encs):
        if rx and not rx.search(s):
            continue
        total += 1
        if len(out) < limit:
            out.append({"offset": off, "encoding": enc, "string": s})
    return {"strings": out, "total": total, "truncated": total > limit, "evidence": {**ev, "tool": "pure-python strings", "bytes_examined": len(data)}}


def disk_read(image: str, offset: int, length: int = 512, as_text: bool = False) -> dict:
    """Raw bytes from the image at an absolute byte offset (hex dump by default)."""
    h = handle(image)
    length = min(length, 1 << 20)
    data = h.img.read(offset, length)
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
    data = h.img.read(h.part_offset_sectors(part) * 512 + block * bs, count * bs)
    out = {"block": block, "count": count, "block_size": bs}
    if as_text:
        out["text"] = re.sub(r"[\x00-\x08\x0b-\x1f]", ".", data.decode("utf-8", errors="replace"))
    else:
        out["hexdump"] = hexdump(data[:65536], block * bs)
    return {"data": out, "evidence": h.evidence(part, tool="pytsk3 read_block")}


def blkcalc(image: str, part: int | None, blkls_offset: int) -> dict:
    """Map a blkls stream byte offset to the real file-system block number (needs sleuthkit; pure-mode hits already carry fs_block)."""
    h = handle(image)
    fs = h.fs(part)
    bs = fs.info.block_size
    unit = blkls_offset // bs
    if not find_tool("blkcalc"):
        # pure fallback: walk the unallocated runs and count units
        try:
            from .search import _ntfs_unalloc_runs  # noqa
            seen = 0
            for start, count in _ntfs_unalloc_runs(h, part):
                if seen + count > unit:
                    return {"data": {"blkls_unit": unit, "fs_block": start + (unit - seen), "block_size": bs, "in_block_offset": blkls_offset % bs, "method": "pure NTFS bitmap walk"}, "evidence": h.evidence(part)}
                seen += count
        except Exception as e:
            return {"error": f"blkcalc not installed and no bitmap parser for this file system ({e})"}
    r = run(["blkcalc", "-u", str(unit), "-o", str(h.part_offset_sectors(part)), h.path], timeout=600)
    txt = r.stdout.decode(errors="replace").strip()
    try:
        blk = int(txt.split()[0])
    except Exception:
        blk = None
    return {"data": {"blkls_unit": unit, "fs_block": blk, "block_size": bs, "in_block_offset": blkls_offset % bs, "raw": txt or r.stderr.decode(errors="replace")}, "evidence": h.evidence(part, tool="blkcalc -u")}


def hexdump(data: bytes, base: int = 0, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + i:010x}  {hx:<{width * 3}} |{asc}|")
    return "\n".join(lines)
