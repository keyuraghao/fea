# FEA - Forensic Evidence Agent

One MCP server (and CLI) for disk-image forensics, in the spirit of [REA](https://github.com/morluto/rea) for reverse engineering: it lets an AI agent such as Claude Code open forensic disk images read-only and answer questions about them with evidence attached to every result.

Runs on **Windows, macOS and Linux** with nothing but Python 3.12+ (every dependency ships binary wheels for all three). The native sleuthkit and exiftool binaries are optional accelerators, never requirements.

Targets: raw and split-raw images (`.001`, `.002`, ...) and E01 (via The Sleuth Kit library), with NTFS, FAT, exFAT, ext2/3/4, HFS+, APFS, UFS, ISO9660 and YAFFS2 file systems. Windows, Linux and Android artefacts are parsed in place; nothing is mounted and nothing from the image is ever executed.

## Install

With [uv](https://docs.astral.sh/uv/) (recommended, any OS):

```bash
git clone https://github.com/<you>/fea && cd fea
uv sync
uv run fea setup        # registers the MCP server with Claude Code (user scope) and installs the /fea skill
uv run fea doctor       # shows platform, Python and which optional native tools were found
```

With plain pip (any OS):

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e .
python -m fea setup
```

Optional accelerators, picked up automatically when on PATH (or in `tool_dirs` of `~/.fea/images.toml`, or `FEA_TOOL_DIRS`): `sleuthkit` (fls, istat, blkls, blkcalc, tsk_recover), `exiftool`. On Windows the default install folders under `C:\Program Files` are searched too. Set `FEA_NO_NATIVE=1` to force the pure-Python paths.

Register images once (paths are stored in `~/.fea/images.toml`, `%USERPROFILE%\.fea` on Windows):

```bash
uv run fea images add E4 /cases/ambrosia/jeanhassan.001 --label "Jeanette Hassan desktop"
uv run fea images tz America/New_York     # default reporting timezone (UTC is always given too)
```

## MCP tools (34)

| Area | Tools |
|---|---|
| Images | `images_list`, `images_add`, `partitions`, `tools_status` |
| File system | `ls`, `stat` (NTFS $FILE_NAME times with a timestomp indicator, ADS), `read`, `extract`, `find` (names incl. deleted), `timeline`, `recover_deleted` |
| Search | `grep_files` (content, UTF-8 + UTF-16LE), `grep_unallocated` (NTFS bitmap walk or blkls), `grep_file`, `strings`, `disk_read`, `block_read`, `blkcalc` |
| Windows | `registry_key`, `registry_plugins` (UserAssist, ShellBags, WordWheelQuery, TypedPaths, USBSTOR, services...), `evtx`, `prefetch`, `lnk`, `esedb_tables`, `esedb_dump` (SRUM, Windows.edb, WebCache, ntds.dit) |
| Any file | `sqlite_tables`, `sqlite_query` (read-only; WAL applied), `exif`, `file_info` (hashes, entropy, trailing data after JPEG/PNG/PDF end), `office_parts` (hidden text, tracked changes, comments), `yara_scan` |
| Jobs | `job_status`, `job_result`, `jobs_list` for the long scans |

Every result carries an `evidence` block (image, partition, path, inode, SHA1 of the extracted copy, tool) and, where it matters, `limitations`. Times are returned in UTC and in the image's configured timezone.

## CLI

The same operations from the shell, with `--json` for machine output:

```bash
fea parts E4
fea ls E4 /Users/jean.AMBROSIA/Downloads
fea stat E4 inode:237
fea find E4 '*.lnk' --deleted only --since 2021-02-01
fea timeline E4 --start 2021-02-03T12:30 --end 2021-02-03T12:40 --path Prefetch
fea cat E4 /Windows/System32/drivers/etc/hosts
fea extract E4 /Windows/System32/config/SYSTEM ./out
fea reg E4 /Windows/System32/config/SYSTEM --key 'ControlSet001\Control\ComputerName\ComputerName'
fea regplugins E4 /Users/jean.AMBROSIA/NTUSER.DAT --plugin user_assist
fea evtx E4 /Windows/System32/winevt/Logs/Security.evtx --ids 1102,4624 --start 2021-02-03
fea prefetch E4 /Windows/Prefetch/UPDATE2.EXE-7783C67A.pf
fea sqlite E4 '/Users/jean.AMBROSIA/.../plum.sqlite' --sql 'select Text from Note'
fea grep E4 192.168.2.42 FROGMAN --path 'Users/.*'       # file content
fea grep E4 FROGMAN --unallocated                         # deleted / unallocated space
fea strings E4 /pagefile.sys --pattern 'trillian|mattermost'
```

(`uv run fea ...` when using uv without activating the environment; `python -m fea ...` works everywhere.)

## How an agent uses it

1. `images_list` -> `partitions` (omit `part` to use the largest file system).
2. `find` / `ls` / `timeline` to locate; `stat` / `read` / `extract` to inspect.
3. Artefact tools take an in-image `ref` (path or `inode:N`) or a `local_path` for something already extracted.
4. Long scans return a `job_id`; call `job_result(job_id, wait_s=30)` until `status` is `done`.
5. Cite the `evidence` block with every conclusion and keep the `limitations`.

## Portability notes

| Capability | Pure Python (default everywhere) | With native tool present |
|---|---|---|
| Directory walk for find/timeline | pytsk3 recursive walk (deleted names and orphans included) | `fls -r -m` (faster, adds $FILE_NAME rows) |
| NTFS $FILE_NAME times | parsed from the raw attribute | plus `istat` text |
| Unallocated search | NTFS `$Bitmap` walk, real block numbers in hits; other file systems scan the whole volume (flagged) | `blkls` stream + `blkcalc` |
| Deleted-file recovery | deleted-entry walk | `tsk_recover -e` |
| strings | regex over bytes (ASCII + UTF-16LE) | - |
| File typing | puremagic | `file` |
| Metadata | Pillow EXIF + OOXML properties | `exiftool` (everything) |

## Layout

```
src/fea/config.py     image registry (~/.fea/images.toml), cache dir
src/fea/images.py     pytsk3 image/partition/file access, time conversion, $FILE_NAME parsing, evidence blocks
src/fea/tools.py      optional native tool lookup, pure-Python strings and file typing
src/fea/fs.py         ls, stat, read, extract, find, timeline, recover_deleted
src/fea/search.py     grep over files / unallocated / single file, strings, raw and block reads, blkcalc
src/fea/artifacts.py  registry, evtx, sqlite, lnk, prefetch, esedb, exif, file_info, office, yara
src/fea/jobs.py       background jobs
src/fea/server.py     MCP server (mcp.server.mcpserver.MCPServer, stdio by default)
src/fea/cli.py        click CLI
src/fea/setup.py      claude mcp add + skill install (Windows/macOS/Linux)
```

## Limits

- The Sleuth Kit does not parse HPFS or some exotic file systems; use `disk_read` / `strings` on those.
- Volume shadow copies, BitLocker and encrypted containers are not opened.
- Registry transaction logs are not replayed.
- In pure-Python mode `grep_unallocated` on non-NTFS volumes scans allocated blocks as well; the result says so.

## License

MIT.
