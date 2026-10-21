# Changelog

All notable changes to FEA are recorded here. The format follows Keep a Changelog; versions follow semantic versioning.

## [0.1.0] - 2026-10-21

### Added
- MCP server (`fea mcp`) with 34 tools: image registry and partitions, file-system listing/stat/read/extract/find/timeline/recover, content and unallocated-space search, registry, event logs, prefetch, LNK, ESE, SQLite, EXIF, file typing and hashes, OOXML inspection, YARA, background jobs.
- `fea` CLI mirroring the tools, with `--json` output.
- `fea setup` to register with Claude Code and install the `/fea` skill; `fea doctor` for platform and tool detection.
- Cross-platform pure-Python core (Windows, macOS, Linux) with optional sleuthkit and exiftool acceleration.
- NTFS `$FILE_NAME` parsing with a timestomp indicator; SQLite WAL application; trailing-data checks for JPEG/PNG/PDF.
- Documentation: installation, CLI, MCP contract, targets, evidence contract.
