"""fea command line: the same operations as the MCP tools, printed as text or --json."""
from __future__ import annotations
import json, sys
import click
from . import config, fs, search, artifacts, setup as setup_mod
from .images import handle


def out(d, as_json: bool):
    if as_json:
        click.echo(json.dumps(d, indent=2, default=str)); return
    if isinstance(d, dict) and "entries" in d:
        for e in d["entries"]:
            t = (e.get("mtime") or {}).get("local", "-")
            flag = "D" if (e.get("name_deleted") or (e.get("inode") is not None and not e.get("allocated", True))) else " "
            click.echo(f"{flag} {str(e.get('inode')):>10} {e.get('type', '-'):>4} {e.get('size', 0):>12} {t:<36} {e['name']}{(' [ADS: ' + ','.join(e['ads']) + ']') if e.get('ads') else ''}")
        click.echo(f"-- {d['total']} entries{' (truncated)' if d.get('truncated') else ''}")
    elif isinstance(d, dict) and "events" in d and d["events"] and "kind" in d["events"][0]:
        for e in d["events"]:
            click.echo(f"{e['time']['local']}  {e['kind']}  {e['size']:>10}  {'(del) ' if e['deleted'] else ''}{e['path']}")
        click.echo(f"-- {d['total']} events{' (truncated)' if d.get('truncated') else ''}")
    elif isinstance(d, dict) and "matches" in d:
        for m in d["matches"]:
            click.echo(f"{(m.get('mtime') or {}).get('local', '-'):<36} {m['inode']:>12} {m['size']:>10} {'(del) ' if m['deleted'] else ''}{m['path']}")
        click.echo(f"-- {d['total']} matches{' (truncated)' if d.get('truncated') else ''}")
    elif isinstance(d, dict) and "hits" in d:
        for h in d["hits"]:
            where = h.get("path") or h.get("blkls_offset") or h.get("offset")
            click.echo(f"[{h.get('encoding')}] {h['term']} @ {where}: {h['context']}")
        click.echo(f"-- {len(d['hits'])} hits{' (truncated)' if d.get('truncated') else ''}")
    else:
        click.echo(json.dumps(d, indent=2, default=str))


@click.group()
def cli():
    """FEA - forensic evidence agent: query disk images from the shell or via MCP."""


@cli.command()
@click.option("--transport", default="stdio", type=click.Choice(["stdio", "sse", "streamable-http"]))
def mcp(transport):
    """Run the MCP server (used by Claude Code and other agents)."""
    from .server import serve
    serve(transport)


@cli.command()
@click.option("--scope", default="user", type=click.Choice(["user", "project", "local"]))
@click.option("--skill/--no-skill", default=True, help="also install the Claude Code skill file")
def setup(scope, skill):
    """Register FEA with Claude Code (claude mcp add) and install the workflow skill."""
    for line in setup_mod.register(scope, skill):
        click.echo(line)


@cli.command()
def doctor():
    """Show platform, Python and optional native tool availability."""
    from .tools import tool_report
    click.echo(json.dumps(tool_report(), indent=2))


@cli.group()
def images():
    """Manage the image registry (~/.fea/images.toml)."""


@images.command("list")
@click.option("--json", "as_json", is_flag=True)
def images_list(as_json):
    d = config.load()
    if as_json:
        out(d, True); return
    click.echo(f"timezone: {d['settings']['timezone']}")
    for k, v in d["images"].items():
        click.echo(f"{k:<8} {v['path']}  {v.get('label', '')}")


@images.command("add")
@click.argument("name")
@click.argument("path")
@click.option("--label", default="")
@click.option("--tz", default=None)
def images_add(name, path, label, tz):
    click.echo(json.dumps(config.add_image(name, path, label, tz)))


@images.command("remove")
@click.argument("name")
def images_remove(name):
    click.echo("removed" if config.remove_image(name) else "not found")


@images.command("tz")
@click.argument("timezone")
def images_tz(timezone):
    config.set_timezone(timezone); click.echo(f"default timezone set to {timezone}")


@cli.command()
@click.argument("image")
@click.option("--json", "as_json", is_flag=True)
def parts(image, as_json):
    """Partition table with file-system probing."""
    h = handle(image)
    d = {"size_bytes": h.size, "partitions": h.partitions()}
    if as_json:
        out(d, True); return
    for p in d["partitions"]:
        click.echo(f"{p['addr']:>3} start {p['start_sector']:>12} len {p['length_sectors']:>12}  {p['desc']:<28} {p.get('fs_type') or ''}")


@cli.command()
@click.argument("image")
@click.argument("path", default="/")
@click.option("-p", "--part", type=int, default=None)
@click.option("--no-deleted", is_flag=True)
@click.option("--limit", default=500)
@click.option("--json", "as_json", is_flag=True)
def ls(image, path, part, no_deleted, limit, as_json):
    """List a directory."""
    out(fs.ls(image, part, path, not no_deleted, limit), as_json)


@cli.command()
@click.argument("image")
@click.argument("ref")
@click.option("-p", "--part", type=int, default=None)
@click.option("--json", "as_json", is_flag=True)
def stat(image, ref, part, as_json):
    """Metadata for a path or inode."""
    d = fs.stat(image, part, ref)
    if as_json:
        out(d, True); return
    for k, v in d["data"].items():
        if k != "istat":
            click.echo(f"{k}: {v}")
    click.echo(d["data"].get("istat", ""))


@cli.command()
@click.argument("image")
@click.argument("ref")
@click.option("-p", "--part", type=int, default=None)
@click.option("--offset", default=0)
@click.option("--length", default=4096)
@click.option("--stream", default=None, help="alternate data stream name")
@click.option("--hex", "as_hex", is_flag=True)
def cat(image, ref, part, offset, length, stream, as_hex):
    """Print file content (text or --hex)."""
    d = fs.read(image, part, ref, offset, length, stream, not as_hex)["data"]
    click.echo(d.get("text") if not as_hex else search.hexdump(bytes.fromhex(d["hex"]), offset))


@cli.command()
@click.argument("image")
@click.argument("ref")
@click.argument("out_dir")
@click.option("-p", "--part", type=int, default=None)
@click.option("--stream", default=None)
def extract(image, ref, out_dir, part, stream):
    """Copy a file out of the image (prints hashes)."""
    click.echo(json.dumps(fs.extract(image, part, ref, out_dir, stream)["data"], indent=2))


@cli.command()
@click.argument("image")
@click.argument("pattern")
@click.option("-p", "--part", type=int, default=None)
@click.option("--regex", is_flag=True)
@click.option("--deleted", default="any", type=click.Choice(["any", "only", "no"]))
@click.option("--since", default=None, help="mtime from (ISO, image tz)")
@click.option("--until", default=None)
@click.option("--limit", default=500)
@click.option("--json", "as_json", is_flag=True)
def find(image, pattern, part, regex, deleted, since, until, limit, as_json):
    """Find files by name/path (glob or --regex), incl. deleted names."""
    out(fs.find(image, part, pattern, regex, deleted, 0, None, since, until, limit), as_json)


@cli.command()
@click.argument("image")
@click.option("-p", "--part", type=int, default=None)
@click.option("--start", default=None)
@click.option("--end", default=None)
@click.option("--path", "path_regex", default=None, help="path regex")
@click.option("--kinds", default="mcb")
@click.option("--limit", default=1000)
@click.option("--json", "as_json", is_flag=True)
def timeline(image, part, start, end, path_regex, kinds, limit, as_json):
    """File-system timeline between two times."""
    out(fs.timeline(image, part, start, end, path_regex, kinds, True, limit), as_json)


@cli.command()
@click.argument("image")
@click.argument("terms", nargs=-1, required=True)
@click.option("-p", "--part", type=int, default=None)
@click.option("--unallocated", is_flag=True, help="search unallocated space instead of files")
@click.option("--path", "path_regex", default=".", help="path regex (files mode)")
@click.option("--regex", is_flag=True)
@click.option("--max-hits", default=300)
@click.option("--json", "as_json", is_flag=True)
def grep(image, terms, part, unallocated, path_regex, regex, max_hits, as_json):
    """Search content of files or unallocated space (UTF-8 + UTF-16LE)."""
    prog = lambda m: click.echo(m, err=True)
    if unallocated:
        out(search.grep_unallocated(image, part, list(terms), regex, None, True, max_hits, 80, prog), as_json)
    else:
        out(search.grep_files(image, part, list(terms), path_regex, regex, None, True, 64, 20000, max_hits, False, prog), as_json)


@cli.command()
@click.argument("image")
@click.argument("ref")
@click.option("-p", "--part", type=int, default=None)
@click.option("--pattern", default=None)
@click.option("--min-len", default=6)
@click.option("--limit", default=500)
@click.option("--json", "as_json", is_flag=True)
def strings(image, ref, part, pattern, min_len, limit, as_json):
    """Strings (ASCII + UTF-16LE) from a file."""
    d = search.strings(image, part, ref, min_len, "both", pattern, limit)
    if as_json:
        out(d, True); return
    for s in d["strings"]:
        click.echo(f"{s['offset']:>12} {s['encoding']:<8} {s['string']}")


def _art(fn, image, ref, part, local, as_json, **kw):
    out(fn(image, part, ref, local_path=local, **kw) if not local else fn(image, part, None, local_path=local, **kw), True)


@cli.command()
@click.argument("image", required=False)
@click.argument("ref", required=False)
@click.option("-p", "--part", type=int, default=None)
@click.option("--local", default=None, help="use a local file instead of an in-image ref")
@click.option("--key", default="")
@click.option("--depth", default=1)
def reg(image, ref, part, local, key, depth):
    """Registry key dump from a hive."""
    out(artifacts.registry_key(image, part, ref, key, depth, local), True)


@cli.command()
@click.argument("image", required=False)
@click.argument("ref", required=False)
@click.option("-p", "--part", type=int, default=None)
@click.option("--local", default=None)
@click.option("--plugin", "plugins", multiple=True)
def regplugins(image, ref, part, local, plugins):
    """Run regipy plugins on a hive."""
    out(artifacts.registry_plugins(image, part, ref, list(plugins) or None, local), True)


@cli.command()
@click.argument("image", required=False)
@click.argument("ref", required=False)
@click.option("-p", "--part", type=int, default=None)
@click.option("--local", default=None)
@click.option("--ids", default=None, help="comma-separated event ids")
@click.option("--start", default=None)
@click.option("--end", default=None)
@click.option("--contains", default=None)
@click.option("--limit", default=300)
def evtx(image, ref, part, local, ids, start, end, contains, limit):
    """Query a Windows event log."""
    eids = [int(x) for x in ids.split(",")] if ids else None
    d = artifacts.evtx(image, part, ref, eids, start, end, contains, None, limit, local)
    for e in d["events"]:
        click.echo(f"{e['time']['local']}  EventID {e['event_id']}  rec {e['record_id']}  {e['provider']}")
        for k, v in e["data"].items():
            click.echo(f"    {k}: {v}")
    click.echo(f"-- {d['records_in_file']} records in file, ids {d['record_id_range']}")


@cli.command()
@click.argument("image", required=False)
@click.argument("ref", required=False)
@click.option("-p", "--part", type=int, default=None)
@click.option("--local", default=None)
@click.option("--sql", default=None)
@click.option("--limit", default=200)
def sqlite(image, ref, part, local, sql, limit):
    """SQLite: tables (default) or --sql query."""
    out(artifacts.sqlite_query(image, part, ref, sql, limit, local) if sql else artifacts.sqlite_tables(image, part, ref, local), True)


for _name, _fn, _help in (("lnk", artifacts.lnk, "Parse a .lnk shortcut."), ("prefetch", artifacts.prefetch, "Parse a Prefetch file."),
                          ("exif", artifacts.exif, "exiftool metadata."), ("fileinfo", artifacts.file_info, "Type, hashes, entropy, trailing data."),
                          ("office", artifacts.office_parts, "OOXML parts and text."), ("esedb", artifacts.esedb_tables, "ESE database tables.")):
    def _make(fn):
        @click.argument("image", required=False)
        @click.argument("ref", required=False)
        @click.option("-p", "--part", type=int, default=None)
        @click.option("--local", default=None)
        def _cmd(image, ref, part, local):
            out(fn(image, part, ref, local_path=local), True)
        return _cmd
    cli.command(name=_name, help=_help)(_make(_fn))


def main():
    cli()
