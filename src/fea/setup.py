"""Register the FEA MCP server with Claude Code and install a workflow skill."""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SKILL = """---
name: fea
description: Forensic disk-image analysis through the FEA MCP server (sleuthkit, registry, event logs, SQLite, prefetch, LNK, ESE, EXIF, YARA, unallocated-space search). Use when asked to examine a disk image, find or recover files, build a timeline, or prove what happened on a machine.
---
# FEA workflow
1. `images_list` then `partitions(image)`; omit `part` to use the largest file system.
2. Locate: `find` (names, incl. deleted), `ls`, `timeline(start,end,path_regex)`. Inspect: `stat` (NTFS $FILE_NAME times, ADS), `read`, `extract`.
3. Parse artefacts in place: `registry_key` / `registry_plugins` (SYSTEM, SOFTWARE, SAM, NTUSER.DAT, UsrClass.dat, Amcache.hve), `evtx` (Security 4624/4625/4720/1102, System 7045/104), `prefetch`, `lnk`, `sqlite_tables`/`sqlite_query` (browser, chat, Android), `esedb_*` (SRUDB.dat, Windows.edb, WebCacheV01.dat), `exif`, `office_parts`, `file_info` (hashes, entropy, trailing data), `yara_scan`.
4. Content: `grep_file` for one file (pagefile.sys, hiberfil.sys), `grep_files` for a subtree, `grep_unallocated` for deleted data; both are jobs: `job_result(job_id, wait_s=30)` until status is done. Map unallocated hits with `blkcalc` then `block_read`.
5. Report every finding with its evidence block (image, partition, path, inode, sha1) and both UTC and local times; state limitations; never execute extracted binaries.
"""


def server_command() -> list[str]:
    """Command that starts the MCP server on this machine: uv if available, otherwise the current interpreter."""
    uv = shutil.which("uv") or next((str(c) for c in (Path.home() / ".local/bin/uv", Path.home() / ".cargo/bin/uv", Path.home() / ".local/bin/uv.exe") if c.exists()), None)
    if uv:
        return [uv, "--directory", str(ROOT), "run", "fea", "mcp"]
    return [sys.executable, "-m", "fea", "mcp"]


def register(scope: str = "user", skill: bool = True):
    cmd = server_command()
    claude = shutil.which("claude") or shutil.which("claude.cmd") or shutil.which("claude.exe")
    yield f"project: {ROOT} ({platform.system()})"
    yield "server command: " + " ".join(cmd)
    if not claude:
        yield "claude CLI not found on PATH; add manually:  claude mcp add -s user fea -- " + " ".join(cmd)
    else:
        subprocess.run([claude, "mcp", "remove", "-s", scope, "fea"], capture_output=True, shell=os.name == "nt")
        r = subprocess.run([claude, "mcp", "add", "-s", scope, "fea", "--"] + cmd, capture_output=True, text=True, shell=os.name == "nt")
        yield (r.stdout or r.stderr).strip() or "registered MCP server 'fea'"
    if skill:
        d = Path.home() / ".claude/skills/fea"
        d.mkdir(parents=True, exist_ok=True)
        (d / "SKILL.md").write_text(SKILL)
        yield f"skill installed: {d / 'SKILL.md'}"
    yield "restart Claude Code (or run /mcp) to load the 'fea' server"
