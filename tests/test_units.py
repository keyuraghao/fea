"""Unit tests that need no disk image."""
import os
import re
import sqlite3
from pathlib import Path

import pytest


@pytest.fixture()
def fea_home(tmp_path, monkeypatch):
    monkeypatch.setenv("FEA_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("FEA_UNRESTRICTED", raising=False)
    import importlib

    from fea import config, paths
    importlib.reload(config); importlib.reload(paths)
    return tmp_path


def test_iter_strings_ascii_and_utf16():
    from fea.tools import iter_strings
    data = b"\x00\x01hello world\x00\xff\xfe" + "secret".encode("utf-16-le") + b"\x00\x00"
    found = list(iter_strings(data, 5))
    assert ("hello world", "ascii") in [(s, e) for _, e, s in found]
    assert ("secret", "utf16le") in [(s, e) for _, e, s in found]


def test_hexdump_shape():
    from fea.search import hexdump
    out = hexdump(bytes(range(20)), base=0x1000)
    lines = out.splitlines()
    assert len(lines) == 2 and lines[0].startswith("0000001000") and "|" in lines[0]


def test_patterns_and_context():
    from fea.search import _context, _patterns
    pats = _patterns(["abc"], False, None, True)
    assert {e for _, e, _ in pats} == {"utf8", "utf16le"}
    buf = b"xxxxABCxxxx" + "abc".encode("utf-16-le")
    hits = [(e, m.start()) for t, e, p in pats for m in p.finditer(buf)]
    assert ("utf8", 4) in hits and ("utf16le", 11) in hits
    m = next(pats[0][2].finditer(buf))
    assert "ABC" in _context(buf, m, "utf8", 2)
    with pytest.raises(ValueError):
        _patterns([], False, None, True)
    with pytest.raises(ValueError):
        _patterns(["a"], False, ["ebcdic"], True)


def test_scan_windows_dedup_and_boundary():
    from fea.search import OVERLAP, _patterns, _scan_windows
    needle = b"NEEDLE-ON-BOUNDARY"
    blob = b"a" * (100 - 9) + needle + b"b" * 200 + needle + b"c" * 50
    chunks = [blob[i:i + 100] for i in range(0, len(blob), 100)]
    it = iter(chunks)
    hits = []
    _scan_windows(lambda n: next(it, b""), _patterns(["NEEDLE-ON-BOUNDARY"], False, ["utf8"], True), lambda t, e, off, ctx: hits.append(off), 100, 10, None, None, window=100)
    assert sorted(hits) == [91, 91 + len(needle) + 200]
    assert OVERLAP >= len(needle)


def test_filetime_conversion():
    from fea.images import FILETIME_EPOCH, filetime
    assert filetime(0) is None
    assert filetime(FILETIME_EPOCH) == (0, 0)
    sec, nano = filetime(FILETIME_EPOCH + 10_000_000 * 3 + 5)
    assert sec == 3 and nano == 500


def test_body_parsing(tmp_path, monkeypatch):
    from fea import fs
    body = tmp_path / "p0.body"
    body.write_text("0|/Users/a/x.txt|12-128-1|r/rrwxrwxrwx|0|0|100|1612000000|1612000001|1612000002|1612000003\n"
                    "0|/Users/a/gone.txt (deleted)|13-128-1|r/rrwxrwxrwx|0|0|5|0|1612000010|0|0\n"
                    "0|/Users/a/dir/|14-144-1|d/drwxrwxrwx|0|0|0|1|2|3|4\n")
    monkeypatch.setattr(fs, "body_path", lambda h, part: body)
    rows = list(fs.iter_body(None, None))
    assert rows[0]["name"] == "/Users/a/x.txt" and rows[0]["mtime"] == 1612000001 and not rows[0]["deleted"]
    assert rows[1]["deleted"] and rows[1]["name"] == "/Users/a/gone.txt"
    assert rows[2]["name"] == "/Users/a/dir"


def test_name_regex():
    from fea.fs import _name_regex
    assert _name_regex("*.lnk", False).search("/Users/x/Recent/a.LNK")
    assert not _name_regex("*.lnk", False).search("/Users/x/a.lnk.bak")
    assert _name_regex("secur", False).search("/a/securityupdate.zip")
    assert _name_regex(r"^/Users/.*\.pf$", True).search("/Users/a/b.pf")


def test_safe_names():
    from fea.paths import safe_name, safe_relpath
    assert safe_name("../../etc/passwd") == "passwd"
    assert safe_name("..") == "item"
    assert safe_name('a<b>:"c|d?e*f') == "a_b___c_d_e_f"
    assert safe_relpath("/Users/../../x/..\\y/z.txt") == Path("Users") / "x" / "y" / "z.txt"


def test_access_policy(fea_home, monkeypatch):
    from fea import paths
    root = paths.output_root()
    assert paths.check_out_dir("sub").is_relative_to(root)
    with pytest.raises(paths.AccessDenied):
        paths.check_out_dir(str(fea_home / "elsewhere"))
    with pytest.raises(paths.AccessDenied):
        paths.check_local_read(str(fea_home / "secret.txt"))
    with pytest.raises(paths.AccessDenied):
        paths.check_image_path(str(fea_home / "any.001"))
    monkeypatch.setenv("FEA_ALLOWED_ROOTS", str(fea_home / "cases"))
    (fea_home / "cases").mkdir()
    (fea_home / "cases" / "img.001").write_bytes(b"\x00" * 512)
    assert paths.check_image_path(str(fea_home / "cases" / "img.001")).exists()
    monkeypatch.setenv("FEA_UNRESTRICTED", "1")
    assert paths.check_local_read(str(fea_home / "secret.txt"))


def test_registry_roundtrip(fea_home):
    from fea import config
    img = fea_home / "disk.001"; img.write_bytes(b"\x00" * 1024)
    with pytest.raises(ValueError):
        config.add_image("bad name!", str(img))
    with pytest.raises(Exception):
        config.add_image("x", str(img), tz="Mars/Olympus")
    config.add_image("x", str(img), label="test", tz="UTC")
    assert config.get_image("x")["path"] == str(img.resolve())
    assert config.remove_image("x") and not config.remove_image("x")
    with pytest.raises(Exception):
        config.get_image(str(img))  # direct path denied under the default policy


def test_sqlite_guard(fea_home, monkeypatch):
    from fea import artifacts
    monkeypatch.setenv("FEA_UNRESTRICTED", "1")
    db = fea_home / "t.sqlite"
    con = sqlite3.connect(db); con.execute("create table t(a)"); con.execute("insert into t values (1)"); con.commit(); con.close()
    r = artifacts.sqlite_query(None, None, None, "select a from t", local_path=str(db))
    assert r["data"]["rows"] == [[1]]
    for bad in ("delete from t", "attach database 'x' as y", "select load_extension('x')"):
        with pytest.raises(ValueError):
            artifacts.sqlite_query(None, None, None, bad, local_path=str(db))
    t = artifacts.sqlite_tables(None, None, None, local_path=str(db))
    assert t["data"]["tables"][0]["name"] == "t"


def test_file_info_trailing(fea_home, monkeypatch):
    from fea import artifacts
    monkeypatch.setenv("FEA_UNRESTRICTED", "1")
    jpg = fea_home / "x.jpg"
    jpg.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 50 + b"\xff\xd9" + b"HIDDEN PAYLOAD")
    r = artifacts.file_info(None, None, None, local_path=str(jpg))["data"]
    assert r["container"] == "JPEG" and r["bytes_after_eof"] == 14 and len(r["sha1"]) == 40


def test_jobs_lifecycle():
    import time

    from fea import jobs

    def work(progress, n):
        progress("half"); time.sleep(0.05); return {"n": n}
    j = jobs.start("t", work, n=3)
    r = jobs.result(j["job_id"], wait_s=5)
    assert r["status"] == "done" and r["result"] == {"n": 3}

    def boom(progress):
        raise RuntimeError("x")
    j2 = jobs.start("t", boom)
    r2 = jobs.result(j2["job_id"], wait_s=5)
    assert r2["status"] == "failed" and "RuntimeError" in r2["error"]
    assert jobs.status("nope")["error"]


def test_find_tool_respects_no_native(monkeypatch):
    from fea import tools
    monkeypatch.setenv("FEA_NO_NATIVE", "1")
    assert tools.find_tool("python") is None
    monkeypatch.delenv("FEA_NO_NATIVE")
    assert tools.file_type(Path(__file__)).strip() != ""


def test_server_tool_count_and_shape():
    import asyncio

    from fea.server import mcp, wrap
    tools = asyncio.run(mcp.list_tools())
    names = {t.name for t in tools}
    assert {"ls", "stat", "grep_unallocated", "registry_key", "evtx", "sqlite_query", "job_cancel", "tools_status"} <= names
    assert len(tools) >= 35
    assert wrap(lambda: (_ for _ in ()).throw(ValueError("bad")))["ok"] is False
    assert re.match(r"ValueError", wrap(lambda: (_ for _ in ()).throw(ValueError("bad")))["error"])
    os.environ.pop("FEA_HOME", None)
