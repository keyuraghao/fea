# Contributing

Thanks for helping. FEA is small on purpose: one module per concern, every tool returning the same result shape, no mounting, no execution of evidence.

## Set up

```bash
git clone https://github.com/keyuraghao/fea && cd fea
uv sync --group dev
uv run ruff check src tests
FEA_TEST_IMAGE=<registered image> uv run pytest tests
```

Smoke tests need a registered image; they skip otherwise. CI runs the lint, the import and the CLI on Windows, macOS and Linux without images.

## Adding a tool

1. Implement the function in the right module (`fs.py`, `search.py`, `artifacts.py`). Accept `image, part, ref` and/or `local_path`, return a dict with `data` (or a top-level payload), `evidence` and, where honest, `limitations`. Use `images.handle(...).evidence(...)` to build the evidence block and `h.ts(...)` for every timestamp.
2. Expose it in `server.py` with `@mcp.tool()` and a one-line docstring that says what an agent gets from it; wrap the call with `wrap(...)` so errors come back as `{"ok": false, "error": ...}`.
3. Add a CLI command in `cli.py` if it is useful from the shell.
4. Regenerate `docs/mcp.md`: `uv run python scripts/gen_mcp_docs.py`.
5. Add a line to `CHANGELOG.md`.

Rules of thumb:

- Pure Python first. A native binary may accelerate a path but the tool must work without it (`FEA_NO_NATIVE=1`).
- Never write into an image, never mount, never execute extracted content.
- Times are UTC plus the image timezone, always both.
- Cap output sizes (`limit`, `max_hits`, byte caps) so a tool call cannot flood an agent's context.
- Long scans go through `jobs.start`.

## Style

`ruff` with the configuration in `pyproject.toml` (line length 180). Keep functions short and names plain. No em dashes in docs.

## Reporting problems

Open an issue with the image type (file system, OS), the tool call and its arguments, the full error text, and `fea doctor` output. Do not attach case data.
