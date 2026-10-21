## What this changes

## How it was tested
- [ ] `uv run ruff check src tests scripts`
- [ ] `FEA_TEST_IMAGE=<image> uv run pytest tests`
- [ ] Works with `FEA_NO_NATIVE=1` (pure Python)

## Checklist
- [ ] Result carries `evidence` and, where honest, `limitations`
- [ ] Times are UTC plus image timezone
- [ ] `docs/mcp.md` regenerated if tools changed (`uv run python scripts/gen_mcp_docs.py`)
- [ ] `CHANGELOG.md` updated
