"""FEA MCP server: one MCP for disk-image forensics (sleuthkit, registry, event logs, SQLite, artefact parsers).
Every tool returns a dict with the data, an `evidence` block (image, partition, path/inode, tool, hashes) and, where relevant, `limitations`."""
from __future__ import annotations
from typing import Any
from mcp.server.mcpserver import MCPServer
from . import config, fs, search, artifacts, jobs
from .images import handle

INSTRUCTIONS = """FEA exposes forensic disk images to you read-only. Workflow:
1. images_list -> pick an image; partitions -> pick the file-system partition (or omit `part` for the largest one).
2. ls / find / timeline to locate files; stat for metadata (NTFS $FN times, ADS); read / extract to get content.
3. Artefact tools (registry_key, registry_plugins, evtx, sqlite_*, lnk, prefetch, esedb_*, exif, office_parts, file_info, yara_scan) accept an in-image path or inode (`ref`) or a `local_path`.
4. grep_files / grep_unallocated / recover_deleted run as background jobs: poll job_result(job_id, wait_s=20).
5. Times are given in UTC and in the image's configured timezone; quote both. Cite the `evidence` block (image, partition, path, inode, sha1) with every conclusion and keep `limitations` in mind.
Never claim more than the artefact shows; distinguish observed from inferred."""

mcp = MCPServer("fea", instructions=INSTRUCTIONS)


def wrap(fn, *a, **kw) -> dict[str, Any]:
    try:
        r = fn(*a, **kw)
        if isinstance(r, dict) and "ok" not in r:
            r = {"ok": "error" not in r, **r}
        return r
    except Exception as e:  # noqa
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


# ---- images -----------------------------------------------------------------------------
@mcp.tool()
def images_list() -> dict:
    """List registered disk images (name, path, label, timezone) and the default timezone."""
    d = config.load()
    return {"ok": True, "timezone": d["settings"]["timezone"], "images": [{"name": k, **v} for k, v in d["images"].items()]}


@mcp.tool()
def images_add(name: str, path: str, label: str = "", timezone: str | None = None) -> dict:
    """Register a disk image (raw, split raw .001, E01) under a short name. `path` is the first segment."""
    return wrap(lambda: {"image": config.add_image(name, path, label, timezone)})


@mcp.tool()
def tools_status() -> dict:
    """Platform, Python version and which optional native tools (sleuthkit, exiftool) are available; FEA works without them."""
    from .tools import tool_report
    return {"ok": True, **tool_report()}


@mcp.tool()
def partitions(image: str) -> dict:
    """Partition table (mmls-style) with file-system type probing for each partition."""
    return wrap(lambda: {"size_bytes": handle(image).size, "partitions": handle(image).partitions(), "evidence": handle(image).evidence()})


# ---- file system ------------------------------------------------------------------------------
@mcp.tool()
def ls(image: str, path: str = "/", part: int | None = None, show_deleted: bool = True, limit: int = 500) -> dict:
    """List a directory (path or 'inode:N'): names, inodes, sizes, MAC times, deleted flags, alternate data streams."""
    return wrap(fs.ls, image, part, path, show_deleted, limit)


@mcp.tool()
def stat(image: str, ref: str, part: int | None = None) -> dict:
    """Full metadata for a file/dir by path or inode ('inode:N' or 'N-128-3'): times, attributes/ADS, istat output ($FILE_NAME times on NTFS)."""
    return wrap(fs.stat, image, part, ref)


@mcp.tool()
def read(image: str, ref: str, part: int | None = None, offset: int = 0, length: int = 4096, stream: str | None = None, as_text: bool = True) -> dict:
    """Read up to 4 MiB of a file (or an ADS via `stream`) as text (auto UTF-16 detection) or hex."""
    return wrap(fs.read, image, part, ref, offset, length, stream, as_text)


@mcp.tool()
def extract(image: str, ref: str, out_dir: str, part: int | None = None, stream: str | None = None, name: str | None = None) -> dict:
    """Copy a file (or ADS) out of the image into out_dir; returns size, SHA1, MD5."""
    return wrap(fs.extract, image, part, ref, out_dir, stream, name)


@mcp.tool()
def find(image: str, pattern: str, part: int | None = None, regex: bool = False, deleted: str = "any", min_size: int = 0, max_size: int | None = None,
         mtime_from: str | None = None, mtime_to: str | None = None, limit: int = 500) -> dict:
    """Find files by path name (glob with * ? or regex), including deleted names. deleted = any|only|no. Times ISO in image timezone."""
    return wrap(fs.find, image, part, pattern, regex, deleted, min_size, max_size, mtime_from, mtime_to, limit)


@mcp.tool()
def timeline(image: str, part: int | None = None, start: str | None = None, end: str | None = None, path_regex: str | None = None, kinds: str = "mcb",
             include_deleted: bool = True, limit: int = 1000) -> dict:
    """File-system timeline (fls body) between start/end (ISO, image timezone), optionally filtered by path regex. kinds: m a c b."""
    return wrap(fs.timeline, image, part, start, end, path_regex, kinds, include_deleted, limit)


@mcp.tool()
def recover_deleted(image: str, out_dir: str, part: int | None = None, path_regex: str | None = None) -> dict:
    """Background job: tsk_recover deleted/unallocated files into out_dir (optionally keep only paths matching regex). Poll job_result."""
    return wrap(jobs.start, "recover_deleted", lambda progress, **kw: fs.recover_deleted(**kw), image=image, part=part, out_dir=out_dir, path_regex=path_regex)


# ---- search ------------------------------------------------------------------------------------
@mcp.tool()
def grep_files(image: str, terms: list[str], part: int | None = None, path_regex: str = ".", regex: bool = False, encodings: list[str] | None = None,
               ignore_case: bool = True, max_file_mb: int = 64, max_files: int = 20000, max_hits: int = 300, include_deleted: bool = False) -> dict:
    """Background job: search file CONTENT (UTF-8 and UTF-16LE) of files whose path matches path_regex. Poll job_result."""
    return wrap(jobs.start, "grep_files", search.grep_files, image=image, part=part, terms=terms, path_regex=path_regex, regex=regex, encodings=encodings,
                ignore_case=ignore_case, max_file_mb=max_file_mb, max_files=max_files, max_hits=max_hits, include_deleted=include_deleted)


@mcp.tool()
def grep_unallocated(image: str, terms: list[str], part: int | None = None, regex: bool = False, encodings: list[str] | None = None, ignore_case: bool = True,
                     max_hits: int = 300, context: int = 80, max_mb: int | None = None) -> dict:
    """Background job: stream unallocated blocks (blkls) and match terms; hits carry blkls offsets (map with blkcalc). Poll job_result."""
    return wrap(jobs.start, "grep_unallocated", search.grep_unallocated, image=image, part=part, terms=terms, regex=regex, encodings=encodings,
                ignore_case=ignore_case, max_hits=max_hits, context=context, max_bytes=(max_mb << 20) if max_mb else None)


@mcp.tool()
def grep_file(image: str | None = None, ref: str | None = None, part: int | None = None, terms: list[str] | None = None, regex: bool = False,
              encodings: list[str] | None = None, ignore_case: bool = True, max_hits: int = 200, local_path: str | None = None, context: int = 100) -> dict:
    """Search one file (in-image ref, or local_path e.g. an extracted pagefile) for terms; returns offsets and context."""
    return wrap(search.grep_file, image, part, ref, terms or [], regex, encodings, ignore_case, max_hits, local_path, context)


@mcp.tool()
def strings(image: str | None = None, ref: str | None = None, part: int | None = None, min_len: int = 6, encoding: str = "both", pattern: str | None = None,
            limit: int = 500, local_path: str | None = None) -> dict:
    """Printable strings (ASCII and UTF-16LE) from a file with offsets, optionally filtered by regex."""
    return wrap(search.strings, image, part, ref, min_len, encoding, pattern, limit, local_path)


@mcp.tool()
def disk_read(image: str, offset: int, length: int = 512, as_text: bool = False) -> dict:
    """Raw bytes at an absolute byte offset in the image (hex dump or text)."""
    return wrap(search.disk_read, image, offset, length, as_text)


@mcp.tool()
def block_read(image: str, block: int, part: int | None = None, count: int = 1, as_text: bool = False) -> dict:
    """Read file-system blocks by number (follow up grep_unallocated hits after blkcalc)."""
    return wrap(search.block_read, image, part, block, count, as_text)


@mcp.tool()
def blkcalc(image: str, blkls_offset: int, part: int | None = None) -> dict:
    """Map a blkls stream byte offset (from grep_unallocated) to the real file-system block."""
    return wrap(search.blkcalc, image, part, blkls_offset)


# ---- artefacts ---------------------------------------------------------------------------------
@mcp.tool()
def registry_key(image: str | None = None, ref: str | None = None, part: int | None = None, key: str = "", depth: int = 1, local_path: str | None = None, max_values: int = 200) -> dict:
    """Read a Windows registry hive (SYSTEM, SOFTWARE, SAM, NTUSER.DAT, UsrClass.dat, Amcache.hve): a key's values, last-write time and subkeys to `depth`."""
    return wrap(artifacts.registry_key, image, part, ref, key, depth, local_path, max_values)


@mcp.tool()
def registry_plugins(image: str | None = None, ref: str | None = None, part: int | None = None, plugins: list[str] | None = None, local_path: str | None = None) -> dict:
    """Run regipy artefact plugins on a hive (UserAssist, ShellBags, WordWheelQuery, TypedPaths, USBSTOR, services, ComputerName, timezone, ...)."""
    return wrap(artifacts.registry_plugins, image, part, ref, plugins, local_path)


@mcp.tool()
def evtx(image: str | None = None, ref: str | None = None, part: int | None = None, event_ids: list[int] | None = None, start: str | None = None, end: str | None = None,
         contains: str | None = None, provider: str | None = None, limit: int = 300, local_path: str | None = None) -> dict:
    """Query a Windows .evtx log: filter by event IDs, time range (ISO, image timezone), provider, or text; returns flattened event data."""
    return wrap(artifacts.evtx, image, part, ref, event_ids, start, end, contains, provider, limit, local_path)


@mcp.tool()
def sqlite_tables(image: str | None = None, ref: str | None = None, part: int | None = None, local_path: str | None = None) -> dict:
    """Tables, row counts, columns and freelist size of a SQLite database (browser history, chat apps, Android apps)."""
    return wrap(artifacts.sqlite_tables, image, part, ref, local_path)


@mcp.tool()
def sqlite_query(image: str | None = None, ref: str | None = None, part: int | None = None, sql: str = "", limit: int = 200, local_path: str | None = None) -> dict:
    """Run a read-only SELECT against a SQLite database inside the image."""
    return wrap(artifacts.sqlite_query, image, part, ref, sql, limit, local_path)


@mcp.tool()
def lnk(image: str | None = None, ref: str | None = None, part: int | None = None, local_path: str | None = None) -> dict:
    """Parse a Windows shortcut (.lnk / Jump List entry): target path, volume serial, machine id, target times."""
    return wrap(artifacts.lnk, image, part, ref, local_path)


@mcp.tool()
def prefetch(image: str | None = None, ref: str | None = None, part: int | None = None, local_path: str | None = None) -> dict:
    """Parse a Windows Prefetch (.pf) file: executable, run count, last 8 run times, volumes, referenced files."""
    return wrap(artifacts.prefetch, image, part, ref, local_path)


@mcp.tool()
def esedb_tables(image: str | None = None, ref: str | None = None, part: int | None = None, local_path: str | None = None) -> dict:
    """List tables of an ESE database (SRUDB.dat, Windows.edb, WebCacheV01.dat, ntds.dit)."""
    return wrap(artifacts.esedb_tables, image, part, ref, local_path)


@mcp.tool()
def esedb_dump(image: str | None = None, ref: str | None = None, part: int | None = None, table: str = "", columns: list[str] | None = None, limit: int = 200,
               contains: str | None = None, local_path: str | None = None) -> dict:
    """Dump rows of an ESE database table (optionally selected columns, filtered by text)."""
    return wrap(artifacts.esedb_dump, image, part, ref, table, columns, limit, contains, local_path)


@mcp.tool()
def exif(image: str | None = None, ref: str | None = None, part: int | None = None, local_path: str | None = None) -> dict:
    """All metadata of a media/document file via exiftool (EXIF, XMP, IPTC, office properties)."""
    return wrap(artifacts.exif, image, part, ref, local_path)


@mcp.tool()
def file_info(image: str | None = None, ref: str | None = None, part: int | None = None, local_path: str | None = None) -> dict:
    """File type (libmagic), SHA1/MD5/SHA256, entropy, and bytes after the JPEG/PNG/PDF end marker (hidden appended data)."""
    return wrap(artifacts.file_info, image, part, ref, local_path)


@mcp.tool()
def office_parts(image: str | None = None, ref: str | None = None, part: int | None = None, local_path: str | None = None, max_chars: int = 20000) -> dict:
    """Open an OOXML document (docx/xlsx/pptx): list parts, extract text, comments, properties; flag hidden text and tracked changes."""
    return wrap(artifacts.office_parts, image, part, ref, local_path, max_chars)


@mcp.tool()
def yara_scan(image: str | None = None, ref: str | None = None, part: int | None = None, rules: str = "", local_path: str | None = None) -> dict:
    """Scan a file with YARA rules (rule text or path to a .yar file)."""
    return wrap(artifacts.yara_scan, image, part, ref, rules, local_path)


# ---- jobs -------------------------------------------------------------------------------------
@mcp.tool()
def job_status(job_id: str) -> dict:
    """Status and progress of a background job."""
    return {"ok": True, **jobs.status(job_id)}


@mcp.tool()
def job_result(job_id: str, wait_s: int = 20) -> dict:
    """Wait up to wait_s seconds for a background job and return its result when done."""
    return {"ok": True, **jobs.result(job_id, wait_s)}


@mcp.tool()
def jobs_list() -> dict:
    """List background jobs started in this session."""
    return {"ok": True, "jobs": jobs.list_jobs()}


def serve(transport: str = "stdio") -> None:
    mcp.run(transport=transport)
