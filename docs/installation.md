# Installation

FEA needs Python 3.12 or newer. Every dependency ships binary wheels for Windows (x86-64), macOS (Intel and Apple silicon) and Linux, so no compiler is required.

## With uv (recommended)

```bash
git clone https://github.com/keyuraghao/fea && cd fea
uv sync
uv run fea doctor
```

`uv run fea ...` runs the CLI inside the project environment. `uv run fea mcp` starts the MCP server.

## With pip

```bash
git clone https://github.com/keyuraghao/fea && cd fea
python -m venv .venv
. .venv/bin/activate            # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -e .
fea doctor                      # or: python -m fea doctor
```

## Register with Claude Code

```bash
uv run fea setup                # user scope; add --scope project for a per-repository registration
```

This runs `claude mcp add fea -- <server command>` and writes `~/.claude/skills/fea/SKILL.md`. Restart Claude Code or run `/mcp` to see the `fea` server. The server command is `uv --directory <repo> run fea mcp` when uv is installed, otherwise `<python> -m fea mcp`.

If the `claude` CLI is not on PATH, `fea setup` prints the exact `claude mcp add` line to run yourself.

### Other MCP clients

Any client that launches stdio servers works. Example configuration block:

```json
{
  "mcpServers": {
    "fea": { "command": "uv", "args": ["--directory", "/path/to/fea", "run", "fea", "mcp"] }
  }
}
```

HTTP transports: `fea mcp --transport streamable-http` or `--transport sse`.

## Optional native tools

FEA works without them. When present they are used automatically for speed or extra detail:

| Tool | Package | Used for |
|---|---|---|
| `fls`, `istat`, `blkls`, `blkcalc`, `tsk_recover` | sleuthkit | faster directory walks with `$FILE_NAME` rows, istat text, streamed unallocated scans, recovery |
| `exiftool` | exiftool | complete metadata for any file type |
| `file` | libmagic | file typing on macOS/Linux (puremagic is the fallback everywhere) |

Lookup order: `PATH`, the `tool_dirs` list in `~/.fea/images.toml`, the `FEA_TOOL_DIRS` environment variable (path-separator delimited), then common install folders (`C:\Program Files\sleuthkit\bin`, `/opt/homebrew/bin`, ...). `FEA_NO_NATIVE=1` forces the pure-Python code paths.

Windows: install sleuthkit from the release zip and add its `bin` folder to `tool_dirs`; exiftool as `exiftool.exe` on PATH.

## Image registry and cache

- Registry: `~/.fea/images.toml` (`%USERPROFILE%\.fea` on Windows), or the folder given by `FEA_HOME`.
- Cache: `~/.fea/cache/<image>/` holds the body file (directory walk) and files extracted for parsing, named by inode. Delete it freely; it is rebuilt on demand.
- Default timezone: `fea images tz <IANA name>`; per image with `--tz` on `fea images add`. `FEA_TZ` overrides at run time.

## Host access policy

The MCP server only opens registered images (or paths under `allowed_roots`), only reads `local_path` files inside the cache/output area, and only writes under the output root. Configure once:

```bash
uv run fea images settings --allowed-root /cases --output-root /cases/out --show
```

The CLI itself runs without the policy (it is the examiner at the keyboard). See SECURITY.md.

## Verify

```bash
FEA_TEST_IMAGE=E4 uv run pytest tests      # smoke tests against a registered image
uv run fea parts E4
```
