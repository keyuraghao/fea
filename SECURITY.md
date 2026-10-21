# Security and evidence handling

## Reporting a vulnerability

Open a private security advisory on GitHub (Security tab, "Report a vulnerability") or email the maintainer listed in `pyproject.toml`. Please include the FEA version, platform, and a minimal reproduction. You will get an acknowledgement within a week.

## What FEA does and does not do

- Opens images **read-only** through The Sleuth Kit library. It never mounts them, never writes to them and never changes their timestamps.
- Never executes content from an image. Executables are copied as data when extracted; the installed skill tells agents the same.
- Writes only to `~/.fea` (registry and cache) and to directories the caller names in `extract` / `recover_deleted`.
- Runs locally. No network access of any kind.
- `sqlite_query` accepts `SELECT`, `WITH`, `PRAGMA` and `EXPLAIN` only, on an immutable copy or a read-only connection.

## Handling case data

- The cache under `~/.fea/cache` contains extracted files from your images, including possible malware samples and credentials. Treat that folder as evidence: encrypt the disk, restrict permissions, and delete it when the case closes.
- Keep images on storage with write protection where possible; FEA cannot protect an image from other software on the host.
- Do not commit `~/.fea`, body files or extracted artefacts to version control. The repository `.gitignore` excludes them.

## Threat model notes

- Parsers (registry, evtx, SQLite, ESE, LNK, prefetch, images) process untrusted input. They are third-party libraries with their own track records; run FEA on an analysis machine, not on a production host.
- YARA rules are compiled from text or files you provide; do not pass rules from untrusted sources without review.
