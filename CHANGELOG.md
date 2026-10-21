# Changelog

All notable changes to FEA are recorded here. The format follows Keep a Changelog; versions follow semantic versioning.

## [0.1.0] - 2026-10-21

### Security
- Host access policy for the MCP server: images only from the registry or `allowed_roots`; `local_path` only inside cache/output/allowed roots; `extract` and `recover_deleted` write only under the output root; names from image content sanitised (no traversal, no Windows-invalid characters). `tools_status` reports the policy.
- `sqlite_query` rejects ATTACH/load_extension and runs with `query_only`; YARA rule files must be inside allowed roots.
- Server instructions tell agents to treat image content as evidence, never as instructions.

### Fixed
- Duplicate and missed hits at scan-window boundaries in unallocated-space search (4 KiB overlap with de-duplication); pure-mode hits map back to real block numbers through the bitmap runs.
- Background jobs now use private pytsk3 handles (pytsk3 is not thread-safe); jobs can be cancelled and old jobs are pruned.
- Partition probing is cached per image (was repeated on every call); directory listing no longer enumerates attributes for entries beyond the limit.
- Hashing, entropy and strings stream or memory-map files instead of reading them whole; registry depth, ESE scans and OOXML parts are capped.
- exiftool output no longer reports host file-system fields of the extracted copy.

### Added
- MCP server (`fea mcp`) with 34 tools: image registry and partitions, file-system listing/stat/read/extract/find/timeline/recover, content and unallocated-space search, registry, event logs, prefetch, LNK, ESE, SQLite, EXIF, file typing and hashes, OOXML inspection, YARA, background jobs.
- `fea` CLI mirroring the tools, with `--json` output.
- `fea setup` to register with Claude Code and install the `/fea` skill; `fea doctor` for platform and tool detection.
- Cross-platform pure-Python core (Windows, macOS, Linux) with optional sleuthkit and exiftool acceleration.
- NTFS `$FILE_NAME` parsing with a timestomp indicator; SQLite WAL application; trailing-data checks for JPEG/PNG/PDF.
- Documentation: installation, CLI, MCP contract, targets, evidence contract.
