"""The cached font manifest is created once and never replaced or read back (no browser).

Windows e2e of 13/11 and 20/11 (oss-invisible/playwright runs 43373058301 and 44689898222): two sessions start together on a
cold cache and both see the file missing. The first one's browser opens bundle-fonts-<hash>.list; on Windows the second one's
os.replace is then refused (WinError 5) and so is a read of the file. The file is addressed by the hash of its own bytes, so
the one there is the same: it is created exclusively (os.link of a unique temporary file), an existing one is accepted by its
size without reading it, and a file of another size is an error. Known-bad: the old function raises PermissionError.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from invisible_core import launch

pytestmark = pytest.mark.unit

MANIFEST = "f|Arial.ttf|0\n"
RAW = MANIFEST.encode("ascii")


@pytest.fixture
def cache(tmp_path, monkeypatch):
    monkeypatch.setenv("INVISIBLE_PLAYWRIGHT_CACHE_DIR", str(tmp_path / "state"))
    return tmp_path


def _another_session_wins(monkeypatch, content: bytes):
    """The other session creates the file between our size check and our write, and its browser holds it as on Windows."""
    real_write = Path.write_bytes
    real_read = Path.read_bytes
    created = []

    def write_bytes(self, data):
        if self.name.endswith(".tmp") and not created:
            out = self.parent / self.name.split(".list")[0]
            out = out.with_name(out.name + ".list")
            real_write(out, content)
            created.append(out)
        return real_write(self, data)

    def read_bytes(self):
        if self.suffix == ".list":
            raise PermissionError(13, "Permission denied", str(self))
        return real_read(self)

    def replace(src, dst):
        raise PermissionError(13, "Access is denied", str(src), 5, str(dst))

    monkeypatch.setattr(Path, "write_bytes", write_bytes)
    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    monkeypatch.setattr(launch.os, "replace", replace)
    return created


def test_a_file_created_by_another_session_is_kept_and_not_read(cache, monkeypatch):
    created = _another_session_wins(monkeypatch, RAW)
    out = launch.cached_font_manifest_path(MANIFEST)
    assert created == [out]
    assert out.stat().st_size == len(RAW)
    assert not list(out.parent.glob("*.tmp")), "the temporary file is left behind"


def test_a_file_of_another_size_is_an_error(cache, monkeypatch):
    _another_session_wins(monkeypatch, b"something else\n")
    d = launch.state_dir("fonts")
    with pytest.raises(OSError, match="expected"):
        launch.cached_font_manifest_path(MANIFEST)
    assert not list(d.glob("*.tmp")), "the temporary file is left behind"


def test_a_cold_cache_creates_the_file_whole_and_leaves_no_temporary(cache):
    out = launch.cached_font_manifest_path(MANIFEST)
    assert out.read_bytes() == RAW
    assert not list(out.parent.glob("*.tmp"))


def test_without_hard_links_it_falls_back_to_a_rename(cache, monkeypatch):
    def no_link(src, dst):
        raise OSError(1, "Operation not permitted")
    monkeypatch.setattr(launch.os, "link", no_link)
    out = launch.cached_font_manifest_path(MANIFEST)
    assert out.read_bytes() == RAW
    assert not list(out.parent.glob("*.tmp"))
