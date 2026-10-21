# Evidence contract

FEA is meant to produce findings that can be re-derived by another examiner from the same image. Every tool result therefore follows one shape.

```json
{
  "ok": true,
  "data": { "...": "tool specific" },
  "evidence": {
    "image": "E4",
    "image_path": "/cases/x/jeanhassan.001",
    "partition": 3,
    "fs_offset_sectors": 104448,
    "source": "/Users/jean.AMBROSIA/Downloads/securityupdate.zip",
    "inode": 237,
    "sha1": "98fbe3f954070c287efe92b781a9675c75586552",
    "local_copy": "~/.fea/cache/E4/p3/237_securityupdate.zip",
    "tool": "pytsk3"
  },
  "limitations": ["..."]
}
```

## Fields

| Field | Meaning |
|---|---|
| `image`, `image_path` | registered name and the first segment on disk |
| `partition`, `fs_offset_sectors` | partition address (as in `partitions`) and its start in 512-byte sectors; enough to reproduce with `fls -o <offset>` |
| `source` | the in-image path or inode reference that was asked for |
| `inode` | metadata address (MFT entry on NTFS) |
| `stream` | alternate data stream name when one was read |
| `sha1`, `local_copy` | hash and location of the extracted copy used by a parser |
| `tool` | library or binary that produced the data, including its mode (`blkls stream scan` vs `pytsk3 block scan (ntfs-bitmap)`) |
| `sql` | the query executed (SQLite tools) |

Search hits add their own locators: `offset` within a file, `blkls_offset` within the unallocated stream (sleuthkit mode) or `fs_block` + `in_block_offset` + `volume_byte_offset` (pure mode).

## Times

Every timestamp is an object `{ "utc": "...", "local": "..." }`. `local` uses the image's configured timezone and carries the zone abbreviation. File-system times from the directory walk are second precision; `stat` returns nanosecond precision from the metadata. NTFS `$FILE_NAME` times are reported separately in `filename_attr_times`; when the `$STANDARD_INFORMATION` creation time precedes the `$FILE_NAME` creation time, `timestomp_indicator` is set.

## Limitations

`limitations` is a list of plain sentences about what the result cannot show. Typical entries:

- name-based search does not look at content;
- registry transaction logs are not replayed;
- WAL files are only applied when they were extracted next to the database;
- a match may straddle a block boundary;
- the whole volume (allocated and unallocated) was scanned because no bitmap parser exists for this file system.

Agents are instructed (through the server instructions and the installed skill) to quote the evidence block and the limitations with each conclusion and to distinguish observed facts from inference.

## Read-only guarantee

Images are opened through The Sleuth Kit library in read-only mode; FEA never mounts them and never writes to them. Extracted files go to the cache or to the `out_dir` the caller names. Executables found in images are copied as data and never run.
