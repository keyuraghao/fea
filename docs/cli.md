# CLI reference

All commands take an image name (as registered with `fea images add`) or a direct path to an image file. `-p/--part N` selects a partition address from `fea parts`; omitted, the largest partition with a recognised file system is used. `--json` prints the full result including the `evidence` block.

Paths inside an image start with `/` regardless of the host OS. A file can also be addressed as `inode:N` (or `N-128-3` on NTFS).

## Setup and registry

| Command | Purpose |
|---|---|
| `fea setup [--scope user\|project\|local] [--no-skill]` | register the MCP server with Claude Code and install the skill |
| `fea doctor` | platform, Python, optional tool detection |
| `fea images list` | registered images and default timezone |
| `fea images add NAME PATH [--label L] [--tz ZONE]` | register an image (first segment of a split image) |
| `fea images remove NAME` | forget an image |
| `fea images tz ZONE` | set the default reporting timezone |
| `fea mcp [--transport stdio\|sse\|streamable-http]` | run the MCP server (under the host access policy) |
| `fea images settings [--allowed-root DIR ...] [--output-root DIR] [--show]` | host access policy for the MCP server |
| `fea version` | print the version |

## File system

| Command | Purpose |
|---|---|
| `fea parts IMAGE` | partition table with file-system probing |
| `fea ls IMAGE [PATH] [--no-deleted] [--limit N]` | directory listing: inode, type, size, mtime, deleted flag, ADS |
| `fea stat IMAGE REF` | metadata, attributes, NTFS `$FILE_NAME` times, timestomp indicator, istat text when available |
| `fea cat IMAGE REF [--offset O] [--length L] [--stream ADS] [--hex]` | print content (UTF-16 auto-detected) |
| `fea extract IMAGE REF OUT_DIR [--stream ADS]` | copy out with SHA1/MD5 |
| `fea find IMAGE PATTERN [--regex] [--deleted any\|only\|no] [--since ISO] [--until ISO] [--limit N]` | find by path name; glob `*` `?` or regex |
| `fea timeline IMAGE [--start ISO] [--end ISO] [--path REGEX] [--kinds mcab] [--limit N]` | file-system timeline |

## Search

| Command | Purpose |
|---|---|
| `fea grep IMAGE TERM... [--path REGEX] [--regex] [--max-hits N]` | content search in files (UTF-8 + UTF-16LE) |
| `fea grep IMAGE TERM... --unallocated` | search unallocated space |
| `fea strings IMAGE REF [--pattern REGEX] [--min-len N] [--limit N]` | strings with offsets |

## Artefacts

Each takes `IMAGE REF` or `--local FILE` for a file already on disk.

| Command | Purpose |
|---|---|
| `fea reg IMAGE HIVE --key 'Path\To\Key' [--depth N]` | registry key dump |
| `fea regplugins IMAGE HIVE [--plugin NAME ...]` | regipy plugins (`user_assist`, `shellbags_ntuser`, `word_wheel_query`, `typed_paths`, `usbstor_plugin`, `services`, `computer_name`, `timezone_data`, ...) |
| `fea evtx IMAGE LOG [--ids 1102,4624] [--start ISO] [--end ISO] [--contains TEXT] [--limit N]` | event log query |
| `fea prefetch IMAGE FILE.pf` | prefetch details |
| `fea lnk IMAGE FILE.lnk` | shortcut details |
| `fea sqlite IMAGE DB [--sql 'select ...'] [--limit N]` | tables or a read-only query (WAL applied when present) |
| `fea esedb IMAGE DB` | ESE tables (SRUDB.dat, Windows.edb, WebCacheV01.dat, ntds.dit) |
| `fea exif IMAGE FILE` | metadata (exiftool or Pillow/OOXML fallback) |
| `fea fileinfo IMAGE FILE` | type, hashes, entropy, trailing bytes after EOF marker |
| `fea office IMAGE FILE.docx` | OOXML parts, text, hidden text and tracked-change flags |

## Examples

```bash
fea find WS1 '*.evtx'
fea evtx WS1 /Windows/System32/winevt/Logs/Security.evtx --ids 4624,4625 --start 2021-02-03 --contains consent
fea reg WS1 /Windows/System32/config/SOFTWARE --key 'Microsoft\Windows NT\CurrentVersion' --depth 0
fea regplugins WS1 /Users/<user>/NTUSER.DAT --plugin user_assist --plugin word_wheel_query
fea grep WS1 'drop point' CODEWORD --unallocated --max-hits 20
fea strings WS1 /pagefile.sys --pattern 'https?://' --limit 100
fea sqlite WS2 '/Users/<user>/AppData/Local/Microsoft/Edge/User Data/Default/History' --sql 'select url,title,last_visit_time from urls order by last_visit_time desc'
```
