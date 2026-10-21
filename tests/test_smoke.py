"""Smoke tests that run against a registered image when one is available (skip otherwise)."""
import os, pytest
from fea import config, fs, search

IMG = os.environ.get("FEA_TEST_IMAGE")
pytestmark = pytest.mark.skipif(not IMG or IMG not in config.load()["images"], reason="set FEA_TEST_IMAGE to a registered image name")


def test_partitions():
    from fea.images import handle
    parts = handle(IMG).partitions()
    assert any(p.get("fs_type") for p in parts)


def test_ls_root():
    r = fs.ls(IMG, None, "/")
    assert r["total"] > 0 and r["evidence"]["image"] == IMG


def test_find_and_stat():
    r = fs.find(IMG, None, "*", limit=5)
    assert r["matches"]
    m = r["matches"][0]
    s = fs.stat(IMG, None, "inode:" + m["inode"].split("-")[0])
    assert "inode" in s["data"]


def test_disk_read():
    r = search.disk_read(IMG, 0, 64)
    assert r["data"]["returned"] == 64
