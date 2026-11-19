"""The GeoIP database is a resource of the MACHINE: it is checked and downloaded once, however many launches ask for it at the same time.

⛔ THE KNOWN-BAD, measured on GitHub runners with the published 64.73.0: on the first launch of a machine, four browsers launched together in one process
each downloaded the database (`_download_geoip_tag` ran four times in parallel, 2.7-3.0 s each) and asked GitHub for the latest tag four times, so the first
round's `prepare_session_geo` took 3.8 s. The check and the download are now one flight inside a process and one file lock across processes, and whoever
waited re-reads what the other left. These tests count the downloads and the HEADs at the layer under the helpers (the file download and `requests.head`),
with the real lock, the real reader and a real database, in threads and in separate processes. Nothing reaches the network.
"""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import threading
import time
import zipfile
from pathlib import Path

import pytest

import invisible_core._geoip_db as dl
from _tiny_mmdb import tiny_mmdb

pytestmark = pytest.mark.unit
TAG = "2026.11.11"
OLD = "2026.11.04"
LAUNCHES = 4
#: Long enough for every launch to be inside the call while the first one downloads, on a loaded runner too.
SLOW_S = 1.0


@pytest.fixture
def cache(tmp_path, monkeypatch):
    monkeypatch.setenv("INVISIBLE_PLAYWRIGHT_CACHE_DIR", str(tmp_path))
    monkeypatch.delenv("STEALTHFOX_GEOIP_MMDB", raising=False)
    monkeypatch.setattr(dl, "_CHECKED_THIS_PROCESS", False)
    monkeypatch.setattr(dl, "release_asset_urls", lambda owner, repo, tag, name, direct: [direct])
    return tmp_path


class _Head:
    def __init__(self, tag):
        self.headers = {"Location": "https://github.com/x/y/releases/download/%s/geoip-aio-all.mmdb.gz" % tag}


class _World:
    """The two things the module asks of the network, counted and slow: the HEAD for the latest tag and the download of the archive."""

    def __init__(self, monkeypatch, delay=0.3, fail_downloads=0):
        self.heads = 0
        self.downloads = 0
        self.delay = delay
        self.fail_downloads = fail_downloads
        self._lock = threading.Lock()
        monkeypatch.setattr(dl.requests, "head", self._head)
        monkeypatch.setattr(dl, "_download_file", self._download)

    def _head(self, *a, **k):
        with self._lock:
            self.heads += 1
        time.sleep(self.delay)
        return _Head(TAG)

    def _download(self, url, dst, *a, **k):
        with self._lock:
            self.downloads += 1
            n = self.downloads
        time.sleep(self.delay)
        if n <= self.fail_downloads:
            raise OSError("download %d failed" % n)
        with zipfile.ZipFile(dst, "w") as z:
            z.writestr(dl.GEOIP_MMDB_NAME, tiny_mmdb())


def _in_threads(n, call):
    """`n` launches at the same moment: (kind, result or error) for each, in the order of the threads."""
    out = [None] * n
    start = threading.Barrier(n)

    def run(i):
        start.wait()
        try:
            out[i] = ("ok", call())
        except BaseException as exc:  # noqa: BLE001 - the test reports what each launch got
            out[i] = ("err", exc)

    threads = [threading.Thread(target=run, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(120)
    assert not any(t.is_alive() for t in threads), "a launch is stuck"
    return out


def _cached(root, tag):
    d = root / "geoip" / tag
    d.mkdir(parents=True, exist_ok=True)
    (d / dl.GEOIP_MMDB_NAME).write_bytes(tiny_mmdb())
    return d / dl.GEOIP_MMDB_NAME


def test_four_launches_at_once_on_a_cold_cache_download_once(cache, monkeypatch):
    world = _World(monkeypatch)
    got = _in_threads(LAUNCHES, dl.ensure_geoip_mmdb)
    assert [k for k, _ in got] == ["ok"] * LAUNCHES, got
    assert len({v for _, v in got}) == 1, "the launches did not get the same database: %s" % got
    assert got[0][1].is_file() and got[0][1].parent.name == TAG
    assert world.downloads == 1, "%d downloads for %d launches" % (world.downloads, LAUNCHES)
    assert world.heads == 1, "%d questions about the latest tag" % world.heads


def test_a_failed_download_is_not_kept_every_waiter_gets_its_error_and_the_next_call_tries_again(cache, monkeypatch):
    world = _World(monkeypatch, fail_downloads=1)
    monkeypatch.setattr(dl, "DOWNLOAD_ATTEMPTS", 1)
    monkeypatch.setattr(dl, "_latest_geoip_tag_api", lambda: TAG)
    got = _in_threads(LAUNCHES, dl.ensure_geoip_mmdb)
    assert [k for k, _ in got] == ["err"] * LAUNCHES, got
    assert len({id(e) for _, e in got}) == 1, "the waiters did not get the error of the one download: %s" % got
    assert "download 1 failed" in str(got[0][1])
    assert world.downloads == 1, "%d downloads for one failed flight" % world.downloads
    assert dl._cached_geoip_mmdb() is None
    # Nothing was kept: the next call is a flight of its own, and it lands the database.
    path = dl.ensure_geoip_mmdb()
    assert path.is_file() and path.parent.name == TAG
    assert world.downloads == 2


def test_the_lock_is_released_when_the_flight_raises(cache, monkeypatch):
    def boom():
        raise RuntimeError("no")

    monkeypatch.setattr(dl, "_resolve_latest_geoip_tag", boom)
    with pytest.raises(RuntimeError, match="no"):
        dl.ensure_geoip_mmdb()
    assert dl._flight is None
    # The lock file is taken again at once: it was released, not left behind. (A bounded wait, so a bug fails here and does not hang.)
    monkeypatch.setattr(dl, "_LOCK_WAIT_S", 5.0)
    t0 = time.monotonic()
    with dl._machine_lock():
        pass
    assert time.monotonic() - t0 < 2.0, "the lock was still held after the error"


def test_a_caller_with_a_database_does_not_wait_for_a_refresh_in_flight(cache, monkeypatch):
    f = _cached(cache, OLD)
    world = _World(monkeypatch, delay=1.0)
    first = threading.Thread(target=dl.ensure_geoip_mmdb)
    first.start()
    try:
        deadline = time.monotonic() + 60
        while world.heads == 0 and time.monotonic() < deadline:
            time.sleep(0.01)
        t0 = time.monotonic()
        assert dl.ensure_geoip_mmdb() == f
        assert time.monotonic() - t0 < 0.5, "a launch with a cached database waited for the refresh"
    finally:
        first.join(120)


def test_sequential_launches_inside_the_interval_ask_for_the_latest_tag_once(cache, monkeypatch):
    world = _World(monkeypatch, delay=0.0)
    for _ in range(3):
        monkeypatch.setattr(dl, "_CHECKED_THIS_PROCESS", False)  # a new process each time
        dl.ensure_geoip_mmdb()
    assert world.heads == 1 and world.downloads == 1


# --- separate processes: the file lock ---------------------------------------------------------------------------------------------------------------

_CHILD = textwrap.dedent("""
    import sys, time, zipfile
    from pathlib import Path
    sys.path[:0] = [sys.argv[1], sys.argv[2]]
    import invisible_core._geoip_db as dl
    from _tiny_mmdb import tiny_mmdb

    log, go, tag, delay = Path(sys.argv[3]), Path(sys.argv[4]), sys.argv[5], float(sys.argv[6])

    class Head:
        headers = {"Location": "https://github.com/x/y/releases/download/%s/geoip-aio-all.mmdb.gz" % tag}

    def head(*a, **k):
        with open(log, "a") as f:
            f.write("head\\n")
        time.sleep(delay)
        return Head()

    def download(url, dst, *a, **k):
        with open(log, "a") as f:
            f.write("download\\n")
        time.sleep(delay)
        with zipfile.ZipFile(dst, "w") as z:
            z.writestr(dl.GEOIP_MMDB_NAME, tiny_mmdb())

    dl.requests.head = head
    dl._download_file = download
    dl.release_asset_urls = lambda owner, repo, t, name, direct: [direct]
    deadline = time.monotonic() + 120
    while not go.exists() and time.monotonic() < deadline:
        time.sleep(0.005)
    print(dl.ensure_geoip_mmdb())
""")


def _processes(tmp_path, tag, delay=SLOW_S):
    """`LAUNCHES` processes released at the same moment against the cache of `tmp_path`: (paths they printed, lines of the log)."""
    scratch = tmp_path.parent / (tmp_path.name + "-procs")
    scratch.mkdir()
    script, log, go = scratch / "child.py", scratch / "log.txt", scratch / "go"
    script.write_text(_CHILD, encoding="utf-8")
    log.write_text("", encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k != "STEALTHFOX_GEOIP_MMDB"}
    env["INVISIBLE_PLAYWRIGHT_CACHE_DIR"] = str(tmp_path)
    src = str(Path(dl.__file__).resolve().parents[1])
    tests = str(Path(__file__).resolve().parent)
    procs = [subprocess.Popen([sys.executable, str(script), src, tests, str(log), str(go), tag, str(delay)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
             for _ in range(LAUNCHES)]
    try:
        time.sleep(2.0)  # let every interpreter reach the start line before the release, on a slow runner too
        go.write_text("go", encoding="utf-8")
        results = [p.communicate(timeout=240) + (p.returncode,) for p in procs]
        for out, err, code in results:
            assert code == 0, err
        lines = log.read_text(encoding="utf-8").split()
    finally:
        for p in procs:
            if p.poll() is None:
                p.kill()
                p.wait()
        import shutil
        shutil.rmtree(scratch, ignore_errors=True)
    return [Path(out.strip()) for out, _, _ in results], lines


def test_four_processes_on_a_cold_cache_download_once_and_the_others_reuse_the_file(cache):
    paths, lines = _processes(cache, TAG)
    assert lines.count("download") == 1, "%d downloads for %d processes" % (lines.count("download"), LAUNCHES)
    assert lines.count("head") == 1, "%d questions about the latest tag" % lines.count("head")
    assert len(set(paths)) == 1 and paths[0].is_file() and paths[0].parent.name == TAG, paths
    assert sorted(p.name for p in cache.iterdir()) == ["geoip"], "something was left beside the geoip root"


def test_four_processes_with_a_database_ask_for_the_latest_tag_once_per_interval(cache):
    f = _cached(cache, TAG)
    paths, lines = _processes(cache, TAG)
    assert lines == ["head"], "the latest tag was asked %d times for %d processes at once" % (lines.count("head"), LAUNCHES)
    assert set(paths) == {f}
    # And the next launches, inside the interval, ask nothing at all.
    paths, lines = _processes(cache, TAG, delay=0.0)
    assert lines == [] and set(paths) == {f}
