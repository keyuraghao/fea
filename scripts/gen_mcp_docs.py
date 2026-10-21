#!/usr/bin/env python3
"""Generate docs/mcp.md from the live MCP server: tool names, descriptions and parameters."""
import asyncio
from pathlib import Path

from fea.server import mcp

OUT = Path(__file__).resolve().parents[1] / "docs/mcp.md"

GROUPS = [
    ("Images", ["images_list", "images_add", "partitions", "tools_status"]),
    ("File system", ["ls", "stat", "read", "extract", "find", "timeline", "recover_deleted"]),
    ("Search", ["grep_files", "grep_unallocated", "grep_file", "strings", "disk_read", "block_read", "blkcalc"]),
    ("Windows artefacts", ["registry_key", "registry_plugins", "evtx", "prefetch", "lnk", "esedb_tables", "esedb_dump"]),
    ("Any file", ["sqlite_tables", "sqlite_query", "exif", "file_info", "office_parts", "yara_scan"]),
    ("Jobs", ["job_status", "job_result", "jobs_list"]),
]


def fmt_type(prop: dict) -> str:
    if "anyOf" in prop:
        return " | ".join(fmt_type(p) for p in prop["anyOf"])
    t = prop.get("type", "any")
    if t == "array":
        return f"list[{fmt_type(prop.get('items', {}))}]"
    return t


async def main() -> None:
    tools = {t.name: t for t in await mcp.list_tools()}
    lines = ["# MCP contract", "",
             "Generated from the server (`uv run python scripts/gen_mcp_docs.py`). Every tool returns a JSON object with `ok`, the payload, an `evidence` block and, where relevant, `limitations` (see [evidence.md](evidence.md)).",
             "", "Conventions:", "",
             "- `image`: a name registered with `images_add` (or a path to the image file).",
             "- `part`: partition address from `partitions`; omit for the largest partition with a file system.",
             "- `ref`: in-image path starting with `/`, or `inode:N`. Artefact tools accept `local_path` instead for a file already on disk.",
             "- ISO times without a zone are interpreted in the image's timezone.",
             "- Long scans return `{job_id}`; poll `job_result(job_id, wait_s)`.", ""]
    seen = set()
    for group, names in GROUPS:
        lines += [f"## {group}", ""]
        for n in names:
            t = tools.get(n)
            if not t:
                continue
            seen.add(n)
            schema = getattr(t, "input_schema", None) or getattr(t, "inputSchema", None) or {}
            props = schema.get("properties", {})
            req = set(schema.get("required", []))
            lines += [f"### `{n}`", "", (t.description or "").strip(), ""]
            if props:
                lines += ["| Parameter | Type | Required | Default |", "|---|---|---|---|"]
                for pn, p in props.items():
                    d = p.get("default", "")
                    lines.append(f"| `{pn}` | {fmt_type(p)} | {'yes' if pn in req else ''} | {'' if d in ('', None) else f'`{d}`'} |")
                lines.append("")
    rest = [n for n in tools if n not in seen]
    if rest:
        lines += ["## Other", ""] + [f"- `{n}`: {(tools[n].description or '').strip()}" for n in rest]
    OUT.write_text("\n".join(lines) + "\n")
    print(f"wrote {OUT} ({len(tools)} tools)")


asyncio.run(main())
