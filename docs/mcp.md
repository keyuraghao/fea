# MCP contract

Generated from the server (`uv run python scripts/gen_mcp_docs.py`). Every tool returns a JSON object with `ok`, the payload, an `evidence` block and, where relevant, `limitations` (see [evidence.md](evidence.md)).

Conventions:

- `image`: a name registered with `images_add` (or a path to the image file).
- `part`: partition address from `partitions`; omit for the largest partition with a file system.
- `ref`: in-image path starting with `/`, or `inode:N`. Artefact tools accept `local_path` instead for a file already on disk.
- ISO times without a zone are interpreted in the image's timezone.
- Long scans return `{job_id}`; poll `job_result(job_id, wait_s)`.

## Images

### `images_list`

List registered disk images (name, path, label, timezone) and the default timezone.

### `images_add`

Register a disk image (raw, split raw .001, E01) under a short name. Allowed only for paths under the configured allowed_roots (or with FEA_UNRESTRICTED=1); otherwise register on the host with `fea images add`.

| Parameter | Type | Required | Default |
|---|---|---|---|
| `name` | string | yes |  |
| `path` | string | yes |  |
| `label` | string |  |  |
| `timezone` | string | null |  |  |

### `partitions`

Partition table (mmls-style) with file-system type probing for each partition.

| Parameter | Type | Required | Default |
|---|---|---|---|
| `image` | string | yes |  |

### `tools_status`

Platform, Python version, optional native tools (sleuthkit, exiftool) and the host access policy in force.

## File system

### `ls`

List a directory (path or 'inode:N'): names, inodes, sizes, MAC times, deleted flags, alternate data streams.

| Parameter | Type | Required | Default |
|---|---|---|---|
| `image` | string | yes |  |
| `path` | string |  | `/` |
| `part` | integer | null |  |  |
| `show_deleted` | boolean |  | `True` |
| `limit` | integer |  | `500` |

### `stat`

Full metadata for a file/dir by path or inode ('inode:N' or 'N-128-3'): times, attributes/ADS, NTFS $FILE_NAME times with a timestomp indicator, istat text when sleuthkit is installed.

| Parameter | Type | Required | Default |
|---|---|---|---|
| `image` | string | yes |  |
| `ref` | string | yes |  |
| `part` | integer | null |  |  |

### `read`

Read up to 4 MiB of a file (or an ADS via `stream`) as text (auto UTF-16 detection) or hex.

| Parameter | Type | Required | Default |
|---|---|---|---|
| `image` | string | yes |  |
| `ref` | string | yes |  |
| `part` | integer | null |  |  |
| `offset` | integer |  | `0` |
| `length` | integer |  | `4096` |
| `stream` | string | null |  |  |
| `as_text` | boolean |  | `True` |

### `extract`

Copy a file (or ADS) out of the image into out_dir (relative to, or inside, the output root); returns size, SHA1, MD5.

| Parameter | Type | Required | Default |
|---|---|---|---|
| `image` | string | yes |  |
| `ref` | string | yes |  |
| `out_dir` | string |  | `extracted` |
| `part` | integer | null |  |  |
| `stream` | string | null |  |  |
| `name` | string | null |  |  |

### `find`

Find files by path name (glob with * ? or regex), including deleted names. deleted = any|only|no. Times ISO in image timezone.

| Parameter | Type | Required | Default |
|---|---|---|---|
| `image` | string | yes |  |
| `pattern` | string | yes |  |
| `part` | integer | null |  |  |
| `regex` | boolean |  | `False` |
| `deleted` | string |  | `any` |
| `min_size` | integer |  | `0` |
| `max_size` | integer | null |  |  |
| `mtime_from` | string | null |  |  |
| `mtime_to` | string | null |  |  |
| `limit` | integer |  | `500` |

### `timeline`

File-system timeline (directory walk) between start/end (ISO, image timezone), optionally filtered by path regex. kinds: m a c b.

| Parameter | Type | Required | Default |
|---|---|---|---|
| `image` | string | yes |  |
| `part` | integer | null |  |  |
| `start` | string | null |  |  |
| `end` | string | null |  |  |
| `path_regex` | string | null |  |  |
| `kinds` | string |  | `mcb` |
| `include_deleted` | boolean |  | `True` |
| `limit` | integer |  | `1000` |

### `recover_deleted`

Background job: recover deleted/orphaned files into out_dir (inside the output root), optionally only paths matching regex. Poll job_result.

| Parameter | Type | Required | Default |
|---|---|---|---|
| `image` | string | yes |  |
| `out_dir` | string |  | `recovered` |
| `part` | integer | null |  |  |
| `path_regex` | string | null |  |  |
| `max_files` | integer |  | `20000` |

## Search

### `grep_files`

Background job: search file CONTENT (UTF-8 and UTF-16LE) of files whose path matches path_regex. Poll job_result.

| Parameter | Type | Required | Default |
|---|---|---|---|
| `image` | string | yes |  |
| `terms` | list[string] | yes |  |
| `part` | integer | null |  |  |
| `path_regex` | string |  | `.` |
| `regex` | boolean |  | `False` |
| `encodings` | list[string] | null |  |  |
| `ignore_case` | boolean |  | `True` |
| `max_file_mb` | integer |  | `64` |
| `max_files` | integer |  | `20000` |
| `max_hits` | integer |  | `300` |
| `include_deleted` | boolean |  | `False` |

### `grep_unallocated`

Background job: scan unallocated space for terms; hits carry file-system block numbers (or blkls offsets when sleuthkit is used). Poll job_result.

| Parameter | Type | Required | Default |
|---|---|---|---|
| `image` | string | yes |  |
| `terms` | list[string] | yes |  |
| `part` | integer | null |  |  |
| `regex` | boolean |  | `False` |
| `encodings` | list[string] | null |  |  |
| `ignore_case` | boolean |  | `True` |
| `max_hits` | integer |  | `300` |
| `context` | integer |  | `80` |
| `max_mb` | integer | null |  |  |

### `grep_file`

Search one file (in-image ref, or local_path to an extracted file such as pagefile.sys) for terms; returns offsets and context.

| Parameter | Type | Required | Default |
|---|---|---|---|
| `image` | string | null |  |  |
| `ref` | string | null |  |  |
| `part` | integer | null |  |  |
| `terms` | list[string] | null |  |  |
| `regex` | boolean |  | `False` |
| `encodings` | list[string] | null |  |  |
| `ignore_case` | boolean |  | `True` |
| `max_hits` | integer |  | `200` |
| `local_path` | string | null |  |  |
| `context` | integer |  | `100` |

### `strings`

Printable strings (ASCII and UTF-16LE) from a file with offsets, optionally filtered by regex.

| Parameter | Type | Required | Default |
|---|---|---|---|
| `image` | string | null |  |  |
| `ref` | string | null |  |  |
| `part` | integer | null |  |  |
| `min_len` | integer |  | `6` |
| `encoding` | string |  | `both` |
| `pattern` | string | null |  |  |
| `limit` | integer |  | `500` |
| `local_path` | string | null |  |  |

### `disk_read`

Raw bytes at an absolute byte offset in the image (hex dump or text).

| Parameter | Type | Required | Default |
|---|---|---|---|
| `image` | string | yes |  |
| `offset` | integer | yes |  |
| `length` | integer |  | `512` |
| `as_text` | boolean |  | `False` |

### `block_read`

Read file-system blocks by number (follow up grep_unallocated hits).

| Parameter | Type | Required | Default |
|---|---|---|---|
| `image` | string | yes |  |
| `block` | integer | yes |  |
| `part` | integer | null |  |  |
| `count` | integer |  | `1` |
| `as_text` | boolean |  | `False` |

### `blkcalc`

Map a blkls stream byte offset (from a sleuthkit-mode grep_unallocated hit) to the real file-system block.

| Parameter | Type | Required | Default |
|---|---|---|---|
| `image` | string | yes |  |
| `blkls_offset` | integer | yes |  |
| `part` | integer | null |  |  |

## Windows artefacts

### `registry_key`

Read a Windows registry hive (SYSTEM, SOFTWARE, SAM, NTUSER.DAT, UsrClass.dat, Amcache.hve): a key's values, last-write time and subkeys to `depth` (max 4).

| Parameter | Type | Required | Default |
|---|---|---|---|
| `image` | string | null |  |  |
| `ref` | string | null |  |  |
| `part` | integer | null |  |  |
| `key` | string |  |  |
| `depth` | integer |  | `1` |
| `local_path` | string | null |  |  |
| `max_values` | integer |  | `200` |

### `registry_plugins`

Run regipy artefact plugins on a hive (UserAssist, ShellBags, WordWheelQuery, TypedPaths, USBSTOR, services, ComputerName, timezone, ...).

| Parameter | Type | Required | Default |
|---|---|---|---|
| `image` | string | null |  |  |
| `ref` | string | null |  |  |
| `part` | integer | null |  |  |
| `plugins` | list[string] | null |  |  |
| `local_path` | string | null |  |  |

### `evtx`

Query a Windows .evtx log: filter by event IDs, time range (ISO, image timezone), provider, or text; returns flattened event data.

| Parameter | Type | Required | Default |
|---|---|---|---|
| `image` | string | null |  |  |
| `ref` | string | null |  |  |
| `part` | integer | null |  |  |
| `event_ids` | list[integer] | null |  |  |
| `start` | string | null |  |  |
| `end` | string | null |  |  |
| `contains` | string | null |  |  |
| `provider` | string | null |  |  |
| `limit` | integer |  | `300` |
| `local_path` | string | null |  |  |

### `prefetch`

Parse a Windows Prefetch (.pf) file: executable, run count, last 8 run times, volumes, referenced files.

| Parameter | Type | Required | Default |
|---|---|---|---|
| `image` | string | null |  |  |
| `ref` | string | null |  |  |
| `part` | integer | null |  |  |
| `local_path` | string | null |  |  |

### `lnk`

Parse a Windows shortcut (.lnk / Jump List entry): target path, volume serial, machine id, target times.

| Parameter | Type | Required | Default |
|---|---|---|---|
| `image` | string | null |  |  |
| `ref` | string | null |  |  |
| `part` | integer | null |  |  |
| `local_path` | string | null |  |  |

### `esedb_tables`

List tables of an ESE database (SRUDB.dat, Windows.edb, WebCacheV01.dat, ntds.dit).

| Parameter | Type | Required | Default |
|---|---|---|---|
| `image` | string | null |  |  |
| `ref` | string | null |  |  |
| `part` | integer | null |  |  |
| `local_path` | string | null |  |  |

### `esedb_dump`

Dump rows of an ESE database table (optionally selected columns, filtered by text).

| Parameter | Type | Required | Default |
|---|---|---|---|
| `image` | string | null |  |  |
| `ref` | string | null |  |  |
| `part` | integer | null |  |  |
| `table` | string |  |  |
| `columns` | list[string] | null |  |  |
| `limit` | integer |  | `200` |
| `contains` | string | null |  |  |
| `local_path` | string | null |  |  |

## Any file

### `sqlite_tables`

Tables, row counts, columns and freelist size of a SQLite database (browser history, chat apps, Android apps). WAL applied when present.

| Parameter | Type | Required | Default |
|---|---|---|---|
| `image` | string | null |  |  |
| `ref` | string | null |  |  |
| `part` | integer | null |  |  |
| `local_path` | string | null |  |  |

### `sqlite_query`

Run a read-only SELECT against a SQLite database inside the image.

| Parameter | Type | Required | Default |
|---|---|---|---|
| `image` | string | null |  |  |
| `ref` | string | null |  |  |
| `part` | integer | null |  |  |
| `sql` | string |  |  |
| `limit` | integer |  | `200` |
| `local_path` | string | null |  |  |

### `exif`

Metadata of a media/document file (exiftool when installed, else Pillow EXIF and OOXML properties).

| Parameter | Type | Required | Default |
|---|---|---|---|
| `image` | string | null |  |  |
| `ref` | string | null |  |  |
| `part` | integer | null |  |  |
| `local_path` | string | null |  |  |

### `file_info`

File type, SHA1/MD5/SHA256, entropy, and bytes after the JPEG/PNG/PDF end marker (hidden appended data).

| Parameter | Type | Required | Default |
|---|---|---|---|
| `image` | string | null |  |  |
| `ref` | string | null |  |  |
| `part` | integer | null |  |  |
| `local_path` | string | null |  |  |

### `office_parts`

Open an OOXML document (docx/xlsx/pptx): list parts, extract text, comments, properties; flag hidden text and tracked changes.

| Parameter | Type | Required | Default |
|---|---|---|---|
| `image` | string | null |  |  |
| `ref` | string | null |  |  |
| `part` | integer | null |  |  |
| `local_path` | string | null |  |  |
| `max_chars` | integer |  | `20000` |

### `yara_scan`

Scan a file with YARA rules (rule text, or a .yar path inside the allowed roots).

| Parameter | Type | Required | Default |
|---|---|---|---|
| `image` | string | null |  |  |
| `ref` | string | null |  |  |
| `part` | integer | null |  |  |
| `rules` | string |  |  |
| `local_path` | string | null |  |  |

## Jobs

### `job_status`

Status and progress of a background job.

| Parameter | Type | Required | Default |
|---|---|---|---|
| `job_id` | string | yes |  |

### `job_result`

Wait up to wait_s seconds (max 300) for a background job and return its result when done.

| Parameter | Type | Required | Default |
|---|---|---|---|
| `job_id` | string | yes |  |
| `wait_s` | integer |  | `20` |

### `jobs_list`

List background jobs started in this session.

## Other

- `job_cancel`: Ask a running background job to stop at its next progress checkpoint.
