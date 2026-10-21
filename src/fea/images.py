"""Open images and file systems with The Sleuth Kit (pytsk3); resolve paths and inodes; time helpers."""
from __future__ import annotations

import hashlib
import re
import subprocess
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from zoneinfo import ZoneInfo

import pytsk3

from . import config

SECTOR = 512
META_TYPES = {0: "undef", 1: "file", 2: "dir", 3: "fifo", 4: "chr", 5: "blk", 6: "lnk", 7: "shad", 8: "sock", 9: "wht", 10: "virt", 11: "virt_dir"}
_INODE_RE = re.compile(r"^(?:inode:)?(\d+)(?:-(\d+)(?:-(\d+))?)?$")


class ImageHandle:
    def __init__(self, name: str):
        self.meta = config.get_image(name)
        self.name = self.meta["name"]
        self.path = self.meta["path"]
        self.tz = ZoneInfo(self.meta.get("timezone") or config.timezone())
        self.img = pytsk3.Img_Info(self.path)
        self.size = self.img.get_size()
        self._fs: dict[int, pytsk3.FS_Info] = {}

    # ---- partitions -------------------------------------------------------
    def partitions(self) -> list[dict]:
        out = []
        try:
            vol = pytsk3.Volume_Info(self.img)
            for p in vol:
                out.append({"addr": p.addr, "start_sector": p.start, "length_sectors": p.len,
                            "desc": p.desc.decode(errors="replace"),
                            "is_fs_candidate": not (p.flags & pytsk3.TSK_VS_PART_FLAG_META) and not (p.flags & pytsk3.TSK_VS_PART_FLAG_UNALLOC)})
        except OSError:
            out.append({"addr": 0, "start_sector": 0, "length_sectors": self.size // SECTOR, "desc": "whole image (no partition table)", "is_fs_candidate": True})
        for p in out:  # probe each candidate for a file system
            if p["is_fs_candidate"]:
                try:
                    fs = pytsk3.FS_Info(self.img, offset=p["start_sector"] * SECTOR)
                    p["fs_type"] = str(fs.info.ftype).replace("TSK_FS_TYPE_", "")
                    p["block_size"] = fs.info.block_size
                    p["block_count"] = fs.info.block_count
                except OSError as e:
                    p["fs_type"] = None; p["fs_error"] = str(e).splitlines()[0]
        return out

    def default_part(self) -> int:
        best = None
        for p in self.partitions():
            if p.get("fs_type") and (best is None or p["length_sectors"] > best["length_sectors"]):
                best = p
        if best is None:
            raise ValueError("no partition with a recognised file system; pass part explicitly or use disk_read")
        return best["addr"]

    def part_offset_sectors(self, part: int | None) -> int:
        if part is None:
            part = self.default_part()
        for p in self.partitions():
            if p["addr"] == part:
                return p["start_sector"]
        raise ValueError(f"no partition with addr {part}")

    def fs(self, part: int | None) -> pytsk3.FS_Info:
        if part is None:
            part = self.default_part()
        if part not in self._fs:
            self._fs[part] = pytsk3.FS_Info(self.img, offset=self.part_offset_sectors(part) * SECTOR)
        return self._fs[part]

    # ---- files ------------------------------------------------------------
    def open(self, part: int | None, ref: str) -> pytsk3.File:
        """ref = '/path/in/image' or 'inode:123' or '123-128-3'."""
        fs = self.fs(part)
        m = _INODE_RE.match(ref.strip())
        if m:
            return fs.open_meta(inode=int(m.group(1)))
        p = ref if ref.startswith("/") else "/" + ref
        return fs.open(p)

    def read_attr(self, f: pytsk3.File, attr=None, offset: int = 0, size: int | None = None) -> bytes:
        total = attr.info.size if attr is not None else (f.info.meta.size if f.info.meta else 0)
        if size is None or offset + size > total:
            size = max(0, total - offset)
        if size == 0:
            return b""
        if attr is not None:
            return f.read_random(offset, size, attr.info.type, attr.info.id)
        return f.read_random(offset, size)

    def data_attrs(self, f: pytsk3.File) -> list:
        """All $DATA-like attributes (NTFS main stream + ADS); for other FS the default stream."""
        out = []
        try:
            for a in f:
                t = int(a.info.type)
                if t in (int(pytsk3.TSK_FS_ATTR_TYPE_NTFS_DATA), int(pytsk3.TSK_FS_ATTR_TYPE_DEFAULT)):
                    out.append(a)
        except OSError:
            pass
        return out

    def extract(self, part: int | None, ref: str, dest: Path, stream: str | None = None) -> dict:
        f = self.open(part, ref)
        attr = None
        if stream:
            for a in self.data_attrs(f):
                if (a.info.name or b"").decode(errors="replace") == stream:
                    attr = a
            if attr is None:
                raise FileNotFoundError(f"stream '{stream}' not found")
        dest.parent.mkdir(parents=True, exist_ok=True)
        h1, h5 = hashlib.sha1(), hashlib.md5()
        total = attr.info.size if attr is not None else (f.info.meta.size if f.info.meta else 0)
        with open(dest, "wb") as out:
            off = 0
            while off < total:
                chunk = self.read_attr(f, attr, off, min(8 << 20, total - off))
                if not chunk:
                    break
                out.write(chunk); h1.update(chunk); h5.update(chunk); off += len(chunk)
        return {"local_path": str(dest), "size": off, "sha1": h1.hexdigest(), "md5": h5.hexdigest()}

    def cached_copy(self, part: int | None, ref: str, stream: str | None = None) -> tuple[Path, dict]:
        """Extract once into the cache (keyed by inode) and reuse."""
        f = self.open(part, ref)
        inode = f.info.meta.addr if f.info.meta else 0
        base = Path(ref).name if not _INODE_RE.match(ref) else f"inode{inode}"
        dest = config.cache_dir(self.name) / f"p{part if part is not None else self.default_part()}" / f"{inode}_{base}{('~' + stream) if stream else ''}"
        if dest.exists():
            return dest, {"local_path": str(dest), "size": dest.stat().st_size, "sha1": sha1_file(dest), "cached": True}
        return dest, self.extract(part, ref, dest, stream)

    # ---- time ---------------------------------------------------------------
    def ts(self, epoch: int | None, nano: int = 0) -> dict | None:
        if not epoch:
            return None
        dt = datetime.fromtimestamp(epoch, tz=timezone.utc).replace(microsecond=min(nano // 1000, 999999))
        return {"utc": dt.isoformat(), "local": dt.astimezone(self.tz).strftime("%Y-%m-%d %H:%M:%S.%f %Z")}

    def evidence(self, part: int | None = None, **extra) -> dict:
        ev = {"image": self.name, "image_path": self.path}
        if part is not None or extra:
            try:
                ev["partition"] = part if part is not None else self.default_part()
                ev["fs_offset_sectors"] = self.part_offset_sectors(ev["partition"])
            except Exception:
                pass
        ev.update(extra)
        return ev


@lru_cache(maxsize=16)
def handle(name: str) -> ImageHandle:
    return ImageHandle(name)


def sha1_file(p: Path) -> str:
    h = hashlib.sha1()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def meta_dict(h: ImageHandle, f: pytsk3.File, name: bytes | None = None) -> dict:
    m = f.info.meta
    n = f.info.name
    d = {"name": (name or (n.name if n else b"")).decode(errors="replace")}
    if n is not None:
        d["name_deleted"] = bool(int(n.flags) & int(pytsk3.TSK_FS_NAME_FLAG_UNALLOC))
    if m is None:
        d["inode"] = None; d["note"] = "no metadata (name-only entry)"
        return d
    d.update({"inode": m.addr, "type": META_TYPES.get(int(m.type), str(int(m.type))), "size": m.size,
              "allocated": bool(int(m.flags) & int(pytsk3.TSK_FS_META_FLAG_ALLOC)),
              "mtime": h.ts(m.mtime, getattr(m, "mtime_nano", 0)), "atime": h.ts(m.atime, getattr(m, "atime_nano", 0)),
              "ctime": h.ts(m.ctime, getattr(m, "ctime_nano", 0)), "crtime": h.ts(m.crtime, getattr(m, "crtime_nano", 0)),
              "uid": m.uid, "gid": m.gid, "nlink": m.nlink})
    return d


def run(cmd: list[str], timeout: int = 600) -> subprocess.CompletedProcess:
    """Run an optional external tool; cmd[0] is resolved through tools.find_tool (returns a failed result if absent)."""
    from .tools import find_tool
    exe = find_tool(cmd[0])
    if not exe:
        return subprocess.CompletedProcess(cmd, 127, b"", f"{cmd[0]} not installed".encode())
    return subprocess.run([exe] + cmd[1:], capture_output=True, timeout=timeout)


FILETIME_EPOCH = 116444736000000000


def filetime(v: int):
    if not v:
        return None
    return (v - FILETIME_EPOCH) // 10_000_000, ((v - FILETIME_EPOCH) % 10_000_000) * 100


def ntfs_filename_times(h: "ImageHandle", f: pytsk3.File) -> dict | None:
    """$FILE_NAME attribute times (NTFS), parsed from the raw attribute: harder to timestomp than $STANDARD_INFORMATION."""
    try:
        for a in f:
            if int(a.info.type) == 48 and a.info.size >= 40:  # TSK_FS_ATTR_TYPE_NTFS_FNAME
                raw = f.read_random(0, 40, a.info.type, a.info.id)
                cr, mo, mf, ac = (int.from_bytes(raw[i:i + 8], "little") for i in (8, 16, 24, 32))
                out = {}
                for k, v in (("crtime", cr), ("mtime", mo), ("ctime", mf), ("atime", ac)):
                    ft = filetime(v)
                    out[k] = h.ts(ft[0], ft[1]) if ft else None
                return out
    except Exception:
        return None
    return None
