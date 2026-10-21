# Security and evidence handling

## Reporting a vulnerability

Open a private security advisory on GitHub (Security tab, "Report a vulnerability") or email the maintainer listed in `pyproject.toml`. Include the FEA version, platform and a minimal reproduction. You will get an acknowledgement within a week.

## Threat model

FEA is driven by an AI agent that reads untrusted evidence. Text inside an image (a document, a log line, a chat message) may be crafted to instruct the agent. The design goal is that even a fully compromised agent cannot use FEA to read or write anything on the examiner's machine beyond the images and the output area.

### Host access policy (`fea.paths`)

| Operation | Allowed targets |
|---|---|
| Open an image | names in the registry (`fea images add` on the host), or paths under `allowed_roots` |
| `local_path` arguments | files under the cache (`~/.fea/cache`), the output root, or `allowed_roots` |
| `out_dir` for `extract` / `recover_deleted` | inside the output root (`~/.fea/out` by default) |
| YARA rule files | under `allowed_roots` (rule text is always allowed) |

Configure in `~/.fea/images.toml`:

```toml
[settings]
timezone = "UTC"
allowed_roots = ["/cases"]
output_root = "/cases/out"
```

or with `FEA_ALLOWED_ROOTS` (path-separator delimited) and `FEA_OUTPUT_ROOT`. `FEA_UNRESTRICTED=1` disables the policy; the CLI sets it for interactive use on the host, the MCP server never does. `tools_status` reports the policy in force.

Names taken from image content (file names, stream names, recovered paths) are sanitised before they touch the host file system: no path separators, no `..`, no characters that are invalid on Windows.

### Other guarantees

- Images are opened **read-only** through The Sleuth Kit library; FEA never mounts them, never writes to them and never changes their timestamps.
- Nothing from an image is executed. Executables are copied as data when extracted; the server instructions and the skill tell agents the same.
- `sqlite_query` accepts `SELECT`, `WITH`, `PRAGMA` and `EXPLAIN` only, on a read-only or immutable connection with `query_only` set, and rejects `ATTACH`, `load_extension` and friends.
- Output sizes are capped (`limit`, `max_hits`, byte caps, registry depth and node caps, ESE scan cap, OOXML part cap) so a single call cannot flood an agent or exhaust memory.
- No network access of any kind.
- Evidence blocks include host paths (`image_path`, `local_copy`) because reproducibility needs them. If transcripts leave the analysis machine, redact them.

## Handling case data

- `~/.fea/cache` and the output root contain extracted files from your images, including possible malware samples and credentials. Treat them as evidence: encrypt the disk, restrict permissions, delete them when the case closes.
- Keep images on write-protected storage where possible; FEA cannot protect an image from other software on the host.
- Do not commit `~/.fea`, body files or extracted artefacts to version control; the repository `.gitignore` excludes them.
- Parsers (registry, evtx, SQLite, ESE, LNK, prefetch, images) process untrusted input through third-party libraries. Run FEA on an analysis machine, not on a production host.
