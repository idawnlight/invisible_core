"""The preloaded intermediate certificates are declared by the core, from a list it downloaded and checked; a launch never waits for Mozilla and starts no thread
for it, and the one who looks for a newer list is `update_intermediates` (the `fetch` command).

A retail Firefox has the intermediates of the public web in cert_storage from its first second (Mozilla's Remote Settings collection `security-state/intermediates`).
The engine does not sync that collection any more: the core downloads the list (from the user's Python), verifies it, caches it, and the launch declares the file
to the engine with the pref `zoom.stealth.intermediates.file`. Nothing here reaches Mozilla: the transport (`_intermediates._get`, the module's one network seam) is a
fake that serves a synthetic collection built from certificates made in this file. No test measures a time: the asserts are on what happened and in which order.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import threading
import zipfile
from pathlib import Path

import pytest
import requests

from invisible_core import _cached_asset as asset
from invisible_core import _intermediates as im
from invisible_core import download
from invisible_core.constants import (
    INTERMEDIATES_BUNDLE_PATH,
    INTERMEDIATES_FILE_NAME,
    INTERMEDIATES_LATEST_URL,
    INTERMEDIATES_PREF,
    INTERMEDIATES_SERVER_INFO_URL,
)
from invisible_core.juggler import connection
from invisible_core.launch import write_user_js
from test_a_launch_has_one_deadline import _Browser

pytestmark = pytest.mark.unit

#: The function the launch calls, as it is in the package: the conftest of the suite stubs it for every test that is not about it.
REAL_ENSURE = im.ensure_intermediates

BASE = "https://attachments.invalid/"
CHANGESET = "https://firefox.settings.services.mozilla.com/v2/buckets/security-state/collections/intermediates/changeset?"


# --- certificates made here (DER by hand: the core reads only the subject, and the test must not need a library either) ------------------------------------

def _tlv(tag: int, body: bytes) -> bytes:
    n = len(body)
    if n < 0x80:
        head = bytes([tag, n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        head = bytes([tag, 0x80 | len(raw)]) + raw
    return head + body


def _name(cn: str) -> bytes:
    atv = _tlv(0x30, _tlv(0x06, b"\x55\x04\x03") + _tlv(0x0C, cn.encode()))
    return _tlv(0x30, _tlv(0x31, atv))


def make_cert(cn: str) -> bytes:
    algorithm = _tlv(0x30, _tlv(0x06, b"\x2a\x03\x04"))
    validity = _tlv(0x30, _tlv(0x17, b"260101000000Z") + _tlv(0x17, b"360101000000Z"))
    tbs = _tlv(0x30, _tlv(0xA0, _tlv(0x02, b"\x02")) + _tlv(0x02, b"\x01") + algorithm + _name("an issuer") + validity
               + _name(cn) + _tlv(0x30, b""))
    return _tlv(0x30, tbs + algorithm + _tlv(0x03, b"\x00\x01"))


def to_pem(der: bytes) -> bytes:
    b64 = base64.b64encode(der).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return ("-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n").encode()


class Mozilla:
    """The collection and its server, as the transport answers them. `calls` is every URL asked, in order."""

    def __init__(self, timestamp: int, names=("Alpha CA", "Bravo CA", "Charlie CA")):
        self.timestamp = timestamp
        self.calls: list = []
        self.records: list = []
        self.attachments: dict = {}
        self.missing_from_bundle: set = set()
        self.forbidden = False
        self.offline = False
        for i, name in enumerate(names):
            self.add(name, "rec-%d" % i)

    def add(self, name: str, rid: str) -> dict:
        der = make_cert(name)
        pem = to_pem(der)
        record = {
            "id": rid,
            "derHash": base64.b64encode(hashlib.sha256(der).digest()).decode(),
            "subjectDN": base64.b64encode(_name(name)).decode(),
            "attachment": {"hash": hashlib.sha256(pem).hexdigest(), "size": len(pem), "location": "sec/%s.pem" % rid},
        }
        self.records.append(record)
        self.attachments[rid] = pem
        return record

    def bundle(self) -> bytes:
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w") as z:
            for r in self.records:
                if r["id"] in self.missing_from_bundle:
                    continue
                z.writestr(r["id"] + ".meta.json", json.dumps(r))
                z.writestr(r["id"], self.attachments[r["id"]])
        return out.getvalue()

    def __call__(self, url: str) -> bytes:
        self.calls.append(url)
        if self.forbidden:
            raise AssertionError("the network was asked: %s" % url)
        if self.offline:
            raise requests.ConnectionError("no route to host")
        if url == INTERMEDIATES_LATEST_URL:
            return json.dumps({"timestamp": 1, "changes": [{"bucket": "security-state", "collection": "intermediates",
                                                           "last_modified": self.timestamp}]}).encode()
        if url.startswith(CHANGESET):
            return json.dumps({"timestamp": self.timestamp, "metadata": {}, "changes": self.records}).encode()
        if url == INTERMEDIATES_SERVER_INFO_URL:
            return json.dumps({"capabilities": {"attachments": {"base_url": BASE}}}).encode()
        if url == BASE + INTERMEDIATES_BUNDLE_PATH:
            return self.bundle()
        if url.startswith(BASE + "sec/"):
            return self.attachments[url[len(BASE + "sec/"):-len(".pem")]]
        raise AssertionError("an address nobody serves: %s" % url)


@pytest.fixture
def cache(tmp_path, monkeypatch):
    monkeypatch.setenv("INVISIBLE_PLAYWRIGHT_CACHE_DIR", str(tmp_path))
    monkeypatch.delenv("STEALTHFOX_INTERMEDIATES", raising=False)
    monkeypatch.setattr(im, "ensure_intermediates", REAL_ENSURE)
    monkeypatch.setattr(im, "_WARNED", False)
    monkeypatch.setattr(download, "_SLEEP", lambda seconds: None)   # the retries ask again at once
    monkeypatch.setattr(download, "_note", lambda message: None)
    return tmp_path


@pytest.fixture
def mozilla(monkeypatch):
    m = Mozilla(timestamp=2000)
    monkeypatch.setattr(im, "_get", m)
    return m


def _root(cache: Path) -> Path:
    return cache / "intermediates"


def _put_version(cache: Path, timestamp: int, body: bytes = b'{"format":1}') -> Path:
    d = _root(cache) / str(timestamp)
    d.mkdir(parents=True, exist_ok=True)
    (d / INTERMEDIATES_FILE_NAME).write_bytes(body)
    return d / INTERMEDIATES_FILE_NAME


def _versions(cache: Path) -> list:
    root = _root(cache)
    return sorted(p.name for p in root.iterdir() if p.is_dir()) if root.exists() else []


def _beside_the_root(cache: Path) -> list:
    return sorted(p.name for p in cache.iterdir() if p.name.startswith(".tmp-intermediates"))


# --- a. a list in the cache is the answer, and nobody is asked -------------------------------------------------------------------------------------------

def test_a_cached_list_is_returned_and_the_network_is_not_asked(cache, mozilla):
    """The known-bad is a launch that asks Mozilla whether the list changed: a copy, however old, is the answer and the transport RAISES if it is called at
    all. A check state a month old (what the old weekly model read as "due") is on disk to prove that no clock decides anything here."""
    path = _put_version(cache, 1000)
    asset.check_state_path(_root(cache)).write_text(json.dumps({"checked_at": 1.0}), encoding="utf-8")
    mozilla.forbidden = True
    assert im.ensure_intermediates() == path
    assert mozilla.calls == []


# --- b. a launch starts no thread and asks nobody -----------------------------------------------------------------------------------------------------

def _launch(monkeypatch, profile: Path, log: list, prefs=None):
    """What a client does, over the fake browser: `write_user_js` (the one writer of the pref) and then `connection.launch`, with a log of who was called in
    which order."""
    browser = _Browser()
    seen = {}

    def spawn(executable, argv, env):
        log.append("spawn")
        seen["user_js_at_spawn"] = (profile / "user.js").read_text(encoding="utf-8") if (profile / "user.js").is_file() else ""
        return browser.spawn(executable, argv, env)

    def ensure(*a, **k):
        log.append("ensure")
        return REAL_ENSURE(*a, **k)

    monkeypatch.setattr(connection, "_spawn_windows", spawn)
    monkeypatch.setattr(connection, "_spawn_posix", spawn)
    monkeypatch.setattr(im, "ensure_intermediates", ensure)
    write_user_js(profile, {"a": 1} if prefs is None else prefs)
    conn = connection.launch("firefox", str(profile), ready_timeout=30.0)
    return conn, seen


def _pref_value(user_js_text: str) -> str:
    """The value of the intermediates pref in a user.js (one line, a JSON string)."""
    (line,) = [ln for ln in user_js_text.splitlines() if INTERMEDIATES_PREF in ln]
    head = 'user_pref("%s", ' % INTERMEDIATES_PREF
    assert line.startswith(head) and line.endswith(");"), line
    return json.loads(line[len(head):-2])


def test_a_launch_with_a_cached_list_starts_no_thread_for_it_and_asks_nobody(cache, mozilla, monkeypatch, tmp_path):
    """The known-bad is the check made after the spawn, in a daemon thread (`invisible-intermediates`): the launch started a thread of the core and, once a
    week, a request to Mozilla from the user's process. Here the cache has a list, the state file says the old weekly check is long overdue, and the
    transport raises if touched. Two spies: every `Thread.start` of the launch is recorded with its target's module, and the threads alive after the launch are
    compared with those before it. None of them is the core's intermediates thread, and the transport was not called."""
    _put_version(cache, 1000)
    asset.check_state_path(_root(cache)).write_text(json.dumps({"checked_at": 1.0}), encoding="utf-8")
    mozilla.forbidden = True
    started = []
    real_start = threading.Thread.start

    def spy(self):
        started.append((self.name, getattr(getattr(self, "_target", None), "__module__", None)))
        return real_start(self)

    monkeypatch.setattr(threading.Thread, "start", spy)
    before = set(threading.enumerate())
    profile = tmp_path / "profile"
    profile.mkdir()
    log: list = []
    conn, seen = _launch(monkeypatch, profile, log)
    try:
        new = [t.name for t in threading.enumerate() if t not in before]
        assert log == ["ensure", "spawn"]
        assert not [n for n in started if "intermediates" in n[0] or n[1] == im.__name__], started
        assert "invisible-intermediates" not in new, new
        assert mozilla.calls == []
        assert _pref_value(seen["user_js_at_spawn"]) == str(_root(cache) / "1000" / INTERMEDIATES_FILE_NAME)
    finally:
        conn.close()


# --- c. a record that does not add up refuses the whole download ------------------------------------------------------------------------------------

def _corrupt_hash(m):
    m.records[1]["attachment"]["hash"] = "0" * 64


def _corrupt_der_hash(m):
    m.records[1]["derHash"] = base64.b64encode(b"x" * 32).decode()


def _corrupt_subject(m):
    m.records[1]["subjectDN"] = base64.b64encode(_name("Somebody Else")).decode()


def _corrupt_size(m):
    m.records[1]["attachment"]["size"] += 1


def _swapped_bytes(m):
    """The bytes of one attachment are another certificate's, and the record was left as it was."""
    m.attachments["rec-1"] = m.attachments["rec-0"]


@pytest.mark.parametrize("corrupt", [_corrupt_hash, _corrupt_der_hash, _corrupt_subject, _corrupt_size, _swapped_bytes])
def test_a_certificate_that_does_not_add_up_leaves_the_cache_as_it_was(cache, mozilla, corrupt, capsys):
    """The known-bad: a list kept although one record's sha256, derHash or subject disagrees with its certificate. A refusal is total: the cached version is
    intact, no other directory, finished or half, is left in the root or beside it, and the user is told on stderr instead of getting an exception."""
    kept = _put_version(cache, 1000, b'{"format":1,"kept":true}')
    corrupt(mozilla)
    assert im.update_intermediates() == (kept, False)
    assert _versions(cache) == ["1000"]
    assert kept.read_bytes() == b'{"format":1,"kept":true}'
    assert _beside_the_root(cache) == []
    assert "could not look for a newer list" in capsys.readouterr().err


# --- d. a process that dies in the middle of the writing leaves nothing broken -----------------------------------------------------------------------------

def test_an_update_that_dies_while_writing_leaves_the_cache_and_the_root_as_they_were(cache, mozilla, monkeypatch):
    """The known-bad is the version written in place: an exception between the two files left a directory with a listing and no sources, taken by the next launch
    for the newest list. The version is built beside the root and renamed in one step, so the root never shows it half."""
    kept = _put_version(cache, 1000, b'{"format":1,"kept":true}')

    def dies_after_the_first_file(directory, listing_bytes, sources_bytes):
        (directory / INTERMEDIATES_FILE_NAME).write_bytes(listing_bytes)
        raise OSError("the disk went away")

    monkeypatch.setattr(im, "_write_files", dies_after_the_first_file)
    assert im.update_intermediates() == (kept, False)
    assert _versions(cache) == ["1000"]
    assert kept.read_bytes() == b'{"format":1,"kept":true}'
    assert _beside_the_root(cache) == [], "the half-built directory was left beside the root"
    assert im.ensure_intermediates() == kept


# --- e. a cold cache with no network: no list, a warning, no pref -----------------------------------------------------------------------------------

def test_a_cold_cache_with_no_network_gives_none_a_warning_and_no_pref(cache, mozilla, monkeypatch, tmp_path, capsys):
    """The known-bad is a launch that fails (or hangs) because Mozilla cannot be reached: the browser starts without the list instead, says so once, and the
    profile carries no pref that would point the engine at a file that is not there."""
    mozilla.offline = True
    profile = tmp_path / "profile"
    profile.mkdir()
    conn, seen = _launch(monkeypatch, profile, [])
    try:
        err = capsys.readouterr().err
        assert err.count("intermediate certificates could not be downloaded") == 1
        assert INTERMEDIATES_PREF not in seen["user_js_at_spawn"]
        assert INTERMEDIATES_PREF not in (profile / "user.js").read_text(encoding="utf-8")
        assert im.ensure_intermediates() is None
        assert capsys.readouterr().err == "", "the warning is once per process"
        assert _versions(cache) == [] and _beside_the_root(cache) == []
    finally:
        conn.close()


# --- f. the pref is the path of the file, and it is declared once ----------------------------------------------------------------------------------

def test_the_pref_is_the_path_of_the_cached_file_and_is_declared_once(cache, mozilla, monkeypatch, tmp_path):
    """The known-bad is a launch with the file in the cache and no pref (the engine never reads it), or one that appends the line again on every launch of
    the same profile. The line is in `user.js` BEFORE the process starts, equals the file's absolute path, and a second launch of the profile adds nothing."""
    path = _put_version(cache, 1000)
    mozilla.forbidden = True
    profile = tmp_path / "profile"
    profile.mkdir()
    for _ in range(2):
        conn, seen = _launch(monkeypatch, profile, [])
        conn.close()
        text = (profile / "user.js").read_text(encoding="utf-8")
        assert text.count(INTERMEDIATES_PREF) == 1, text
        assert _pref_value(text) == str(path)
        assert Path(_pref_value(text)).is_absolute()
        assert seen["user_js_at_spawn"].count(INTERMEDIATES_PREF) == 1, "the line was not there when the process started"
        assert 'user_pref("a", 1);' in text, "the caller's own lines are kept"


# --- g. every road of the core's launch writes the pref once, from the one writer; the caller's pref wins; no list, no pref -----------------------------------

def _plan_user_js(monkeypatch, tmp_path: Path) -> str:
    """`build_launch_plan`, hermetic like tests/test_launch.py, and the `user.js` it wrote."""
    import invisible_core._fpforge as _fp
    import invisible_core._geo as _geo
    import invisible_core._proxy as _proxy
    import invisible_core.download as _dl
    import invisible_core.prefs as _prefs
    from invisible_core._geo import SessionGeo
    from invisible_core._locale import decide_session_locale
    from invisible_core.launch import build_launch_plan

    monkeypatch.setattr(_dl, "ensure_binary", lambda ver=None: "/fake/firefox")
    monkeypatch.setattr(_geo, "prepare_session_geo",
                        lambda tz, proxy, locale="auto", **_kw: SessionGeo("America/New_York", "198.51.100.4", locale=decide_session_locale("en-US")))
    monkeypatch.setattr(_fp, "generate_profile", lambda seed, pin=None: object())
    monkeypatch.setattr(_prefs, "translate_profile_to_prefs", lambda fp, **kw: {"zoom.stealth.screen.dpr": 1.25})
    monkeypatch.setattr(_proxy, "configure_proxy", lambda proxy, prefs: None)
    pdir = tmp_path / "plan_profile"
    build_launch_plan(42, profile_dir=pdir, timezone="auto", locale="auto")
    return (pdir / "user.js").read_text(encoding="utf-8")


class _Stop(Exception):
    pass


def _instance_user_js(monkeypatch, tmp_path: Path, prefs=None) -> str:
    """`instance.launch` (the core's own client): the `user.js` as it is when `connection.launch` is called, which then stops the launch."""
    from invisible_core.juggler import instance

    seen = {}

    def stop(executable, profile_dir, **kw):
        seen["text"] = (Path(profile_dir) / "user.js").read_text(encoding="utf-8")
        raise _Stop()

    monkeypatch.setattr(connection, "launch", stop)
    with pytest.raises(_Stop):
        instance.launch("firefox", prefs=prefs or {"a": 1}, profile_dir=str(tmp_path / "instance_profile"))
    return seen["text"]


ROADS = {"build_launch_plan": _plan_user_js, "instance.launch": _instance_user_js}


@pytest.mark.parametrize("road", sorted(ROADS))
def test_every_road_of_the_core_s_launch_writes_the_pref_once(cache, mozilla, monkeypatch, tmp_path, road):
    """The known-bad is a declaration made in `connection.launch` only: `build_launch_plan` writes its `user.js` and the caller spawns the browser itself, so
    that road never carried the pref. Both roads end in `write_user_js`, the one writer, and each has the line exactly once, equal to the cached file."""
    path = _put_version(cache, 1000)
    mozilla.forbidden = True
    text = ROADS[road](monkeypatch, tmp_path)
    assert text.count(INTERMEDIATES_PREF) == 1, text
    assert _pref_value(text) == str(path)
    assert mozilla.calls == []


@pytest.mark.parametrize("road", ["write_user_js", "instance.launch"])
def test_a_pref_the_caller_gave_wins_and_nothing_is_fetched(cache, mozilla, monkeypatch, tmp_path, road):
    """The known-bad is the core overwriting, or adding beside, what the caller declared: the caller's path is the only line, and with a COLD cache the
    network is not asked (a fetch for a value nobody will use)."""
    mozilla.forbidden = True
    mine = str(tmp_path / "mine.json")
    prefs = {"a": 1, INTERMEDIATES_PREF: mine}
    if road == "write_user_js":
        text = write_user_js(tmp_path / "p", prefs).read_text(encoding="utf-8")
    else:
        text = _instance_user_js(monkeypatch, tmp_path, prefs)
    assert text.count(INTERMEDIATES_PREF) == 1, text
    assert _pref_value(text) == mine
    assert mozilla.calls == [] and _versions(cache) == []


def test_the_writer_does_not_touch_the_prefs_it_was_given(cache, mozilla, tmp_path):
    """The dict of the caller is read, not changed: a second launch from the same dict must decide again (the cache may have changed)."""
    _put_version(cache, 1000)
    prefs = {"a": 1}
    write_user_js(tmp_path / "p", prefs)
    assert prefs == {"a": 1}


@pytest.mark.parametrize("road", sorted(ROADS))
def test_with_no_list_and_no_network_no_road_writes_the_pref(cache, mozilla, monkeypatch, tmp_path, road):
    """The known-bad is a pref that names a file that is not there. Cold cache, Mozilla unreachable: the profile carries no line, on either road."""
    mozilla.offline = True
    text = ROADS[road](monkeypatch, tmp_path)
    assert INTERMEDIATES_PREF not in text
    assert _versions(cache) == []


def test_the_pref_name_is_written_in_one_place_of_the_package():
    """One declaration of the name: the constant. Every other module takes it from there."""
    src = Path(im.__file__).parent
    places = [p.relative_to(src).as_posix() for p in src.rglob("*.py")
              if INTERMEDIATES_PREF in p.read_text(encoding="utf-8")]
    assert places == ["constants.py"], places


# --- the rest of the contract: what the file is, and the road for what the bundle lacks ---------------------------------------------------------------

def test_a_cold_cache_downloads_in_line_and_the_file_has_the_declared_format(cache, mozilla):
    path = im.ensure_intermediates()
    assert path == _root(cache) / "2000" / INTERMEDIATES_FILE_NAME
    raw = path.read_bytes()
    assert b"\r" not in raw and b"\n" not in raw, "compact, LF"
    listing = json.loads(raw)
    assert list(listing) == ["format", "collection", "collection_timestamp", "fetched_utc", "count", "set_sha256", "certs"]
    assert listing["format"] == 1 and listing["collection"] == "security-state/intermediates"
    hashes = [c["derHash"] for c in listing["certs"]]
    assert hashes == sorted(hashes) and listing["count"] == len(hashes) == 3
    assert listing["set_sha256"] == hashlib.sha256("\n".join(hashes).encode()).hexdigest()
    cert = listing["certs"][0]
    assert list(cert) == ["derHash", "cert", "subject"]
    der = base64.b64decode(cert["cert"])
    assert base64.b64encode(hashlib.sha256(der).digest()).decode() == cert["derHash"]
    assert base64.b64decode(cert["subject"]) == im.subject_der(der)
    sources = json.loads((path.parent / "SOURCES.json").read_text(encoding="utf-8"))
    assert sources["collection_timestamp"] == 2000 and sources["count"] == 3 and sources["set_sha256"] == listing["set_sha256"]
    assert sources["server"].startswith("https://firefox.settings.services.mozilla.com/")
    assert not (_root(cache) / asset.CHECK_STATE_NAME).exists(), "there is no schedule, so no state of one"


def test_a_record_the_bundle_lacks_is_fetched_by_its_own_location(cache, mozilla):
    mozilla.missing_from_bundle = {"rec-2"}
    path = im.ensure_intermediates()
    assert json.loads(path.read_bytes())["count"] == 3
    assert BASE + "sec/rec-2.pem" in mozilla.calls
    assert BASE + "sec/rec-0.pem" not in mozilla.calls


# --- the `fetch` command: is there a newer list? (`update_intermediates`) --------------------------------------------------------------------------------

def test_fetch_puts_a_newer_list_in_place_and_prunes_the_old_one(cache, mozilla):
    """The known-bad is a `fetch` that leaves the list as it is: the cache holds version 1000, the feed says 2000, and afterwards the cache holds 2000 whole
    (both files, nothing left beside the root) and the 1000 is pruned."""
    _put_version(cache, 1000)
    path, changed = im.update_intermediates()
    assert changed is True
    assert path == _root(cache) / "2000" / INTERMEDIATES_FILE_NAME
    assert _versions(cache) == ["2000"]
    assert sorted(p.name for p in path.parent.iterdir()) == ["SOURCES.json", INTERMEDIATES_FILE_NAME]
    assert json.loads(path.read_bytes())["collection_timestamp"] == 2000
    assert _beside_the_root(cache) == []
    assert im.intermediates_path() == path


@pytest.mark.parametrize("cached", [2000, 3000])
def test_fetch_downloads_nothing_when_the_feed_is_not_newer(cache, mozilla, cached):
    """The feed says 2000: a cache at 2000 (same) or 3000 (ahead) is kept and the only request is the feed's own, a few hundred bytes. No changeset, no bundle."""
    kept = _put_version(cache, cached)
    assert im.update_intermediates() == (kept, False)
    assert mozilla.calls == [INTERMEDIATES_LATEST_URL]
    assert _versions(cache) == [str(cached)]


def test_fetch_asks_the_feed_every_time_it_is_run(cache, mozilla):
    """No schedule: two runs in a row are two questions (the second one finds the list current and downloads nothing)."""
    _put_version(cache, 1000)
    assert im.update_intermediates()[1] is True
    assert im.update_intermediates()[1] is False
    assert mozilla.calls.count(INTERMEDIATES_LATEST_URL) == 2
    assert len([u for u in mozilla.calls if u.startswith(CHANGESET)]) == 1


def test_fetch_with_a_cold_cache_downloads(cache, mozilla):
    path, changed = im.update_intermediates()
    assert changed is True and path == _root(cache) / "2000" / INTERMEDIATES_FILE_NAME and path.is_file()


def test_fetch_with_no_network_keeps_the_cache_and_warns_without_raising(cache, mozilla, capsys):
    """The known-bad is a `fetch` that fails because Mozilla cannot be reached: the cached list is untouched, the answer is that list and `changed` is False, and
    one line on stderr says so."""
    kept = _put_version(cache, 1000, b'{"format":1,"kept":true}')
    mozilla.offline = True
    assert im.update_intermediates() == (kept, False)
    assert kept.read_bytes() == b'{"format":1,"kept":true}'
    assert _versions(cache) == ["1000"] and _beside_the_root(cache) == []
    err = capsys.readouterr().err
    assert err.count("could not look for a newer list") == 1 and "stays" in err


def test_fetch_with_no_network_and_a_cold_cache_gives_none_and_a_warning(cache, mozilla, capsys):
    mozilla.offline = True
    assert im.update_intermediates() == (None, False)
    assert "starts without it" in capsys.readouterr().err
    assert _versions(cache) == []


def test_fetch_with_the_variable_set_does_nothing(cache, mozilla, monkeypatch, tmp_path):
    """STEALTHFOX_INTERMEDIATES is the user's file: no request at all (the transport raises if touched), the cache is not changed."""
    kept = _put_version(cache, 1000)
    mozilla.forbidden = True
    mine = tmp_path / "mine.json"
    mine.write_bytes(b"{}")
    monkeypatch.setenv("STEALTHFOX_INTERMEDIATES", str(mine))
    assert im.update_intermediates() == (mine, False)
    assert mozilla.calls == [] and _versions(cache) == ["1000"] and kept.is_file()


def test_the_override_is_the_file_and_asks_nothing(cache, mozilla, monkeypatch, tmp_path):
    mozilla.forbidden = True
    mine = tmp_path / "mine.json"
    mine.write_bytes(b"{}")
    monkeypatch.setenv("STEALTHFOX_INTERMEDIATES", str(mine))
    assert im.ensure_intermediates() == mine
    monkeypatch.setenv("STEALTHFOX_INTERMEDIATES", str(tmp_path / "missing.json"))
    with pytest.raises(RuntimeError, match="missing file"):
        im.ensure_intermediates()
    assert mozilla.calls == []


def test_with_the_variable_set_nothing_is_downloaded_and_no_thread_is_started(cache, mozilla, monkeypatch, tmp_path):
    """STEALTHFOX_INTERMEDIATES is the user's file: the core neither downloads nor checks. The transport raises if it is touched, and a thread spy proves no
    thread of the intermediates was created. The launch (writer + `connection.launch`) declares the user's file."""
    _put_version(cache, 1000)
    mozilla.forbidden = True
    mine = tmp_path / "mine.json"
    mine.write_bytes(b"{}")
    monkeypatch.setenv("STEALTHFOX_INTERMEDIATES", str(mine))
    started = []
    real_start = threading.Thread.start
    monkeypatch.setattr(threading.Thread, "start", lambda self: (started.append(self.name), real_start(self))[1])
    profile = tmp_path / "profile"
    profile.mkdir()
    conn, seen = _launch(monkeypatch, profile, [])
    try:
        assert "invisible-intermediates" not in started, started
        assert _pref_value(seen["user_js_at_spawn"]) == str(mine)
        assert mozilla.calls == []
    finally:
        conn.close()


#: A real intermediate of Mozilla's collection (record 515b5465-..., SZAFIR Trusted CA6): the DER reader meets a certificate it did not make.
REAL_CERT_B64 = (
    "MIIFmTCCBIGgAwIBAgIUFobWbkmXQcNY82H+JTMWCRDxtXQwDQYJKoZIhvcNAQELBQAwUTELMAkGA1UEBhMCUEwxKDAmBgNVBAoM"
    "H0tyYWpvd2EgSXpiYSBSb3psaWN6ZW5pb3dhIFMuQS4xGDAWBgNVBAMMD1NaQUZJUiBST09UIENBMjAeFw0yNDEwMjEwODAwNTZa"
    "Fw0zNDEwMjEwODAwNTZaMFQxCzAJBgNVBAYTAlBMMSgwJgYDVQQKDB9LcmFqb3dhIEl6YmEgUm96bGljemVuaW93YSBTLkEuMRsw"
    "GQYDVQQDDBJTWkFGSVIgVHJ1c3RlZCBDQTYwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC4J0tw3SWSeKcGCcXOVZ2V"
    "c3rcFo77SF7APLLWXtjcRkL8jq9SmZSYVoo9NdiytmHaQfOVI5jZBKt4ER5OS8+e+/BUZPz1TeGc7p5fhSAuXC3CizHQD93txK2r"
    "aiuIwqZqLpAb22Je1MdFyQh1ICRgombZ7LRyVx/j6RfJkvQe3sJzMzBHRRyucD66MCi8oUH6w5j2k2y1X14ONpHtTFs9nCGiEY3U"
    "XjvlPfSt1b4PljfwZj5l7rDRl4SyMhsQhef+rxgtkqp3nyT4OLIfi+ynEiiMmFoZWveudEZQHZ+IK6UDASSCwq1zn4ISC2VT62yD"
    "GqMPBbCyJTfFs6VuJeUn28ydp80ZOlfSUp5/+pxKbrboDDJxQi3LuI0x/ocysSMucPwpp7HSesYYmFnI0Jp9YBGM19keFCHYjjCi"
    "c3J4grKX04Al/UDNit7IA41gDxmAjRiQahSx3o6yItW241PyTGpeVHbJ0171BRcJqjnaUiAl6QgkQ8nnY8G8Q2aW4wwRahEPTIql"
    "BOFMD+j2d5xIdWh2vpfX0+/4hivtJgHwUh2x4koCwcMZb3BIAT7aSem23d1nLwYNyu0Om6KD0ye0KX/YM9kidd+HRkU3rkrqrCgN"
    "0lMfiuD6FCpViq9ctVIrE2KjAxvtLHhhuTRZP8VYGdNx88zahRtp73nFjca27QIDAQABo4IBZDCCAWAwDwYDVR0TAQH/BAUwAwEB"
    "/zB6BggrBgEFBQcBAQRuMGwwLgYIKwYBBQUHMAGGImh0dHA6Ly9vY3NwLmVsZWt0cm9uaWN6bnlwb2RwaXMucGwwOgYIKwYBBQUH"
    "MAKGLmh0dHA6Ly9jZHAuZWxla3Ryb25pY3pueXBvZHBpcy5wbC9yb290X2NhMi5jcnQwIQYDVR0gBBowGDAIBgZngQwBAgIwDAYK"
    "KoRoAYb3IwECBjAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB8GA1UdIwQYMBaAFC4WqUoY"
    "tcvM9W9Q8yNf+F3nrPDIMD8GA1UdHwQ4MDYwNKAyoDCGLmh0dHA6Ly9jZHAuZWxla3Ryb25pY3pueXBvZHBpcy5wbC9yb290X2Nh"
    "Mi5jcmwwHQYDVR0OBBYEFAQC5AVJAffed7/r+4W/H0TMPvG0MA0GCSqGSIb3DQEBCwUAA4IBAQBPl2jU755j+FBvSsgTR5GyREO7"
    "WuRBflAqk7TURuGbjBkL6pB93QWVFTpW36+yu6C3J1ippS+fuDR7psHc618/W2mznczu6TJkqgINI+6VYftJZU33Dm5SLFeFkPHp"
    "+V1hXAlntZPPT++h4IOexpCLfXmW3hRbZoVdXHIFHLB35liPW2942BHy94DpvMHaS3e8UneNpKsoCgMUsyMVoxG7O8TUPtoD3te1"
    "RS3CdTspIJGKQ2zNTcAcIJxKWQotT8DgQLIfIlRoguVQH2c9UhYrwKbPM2KV60wQvea2pxPT5vGMH3aBePk4W6gJOWigSPXsL0PO"
    "AtsJlF4by9GjJQpQ"
)
REAL_SUBJECT_B64 = (
    "MFQxCzAJBgNVBAYTAlBMMSgwJgYDVQQKDB9LcmFqb3dhIEl6YmEgUm96bGljemVuaW93YSBTLkEuMRswGQYDVQQDDBJTWkFGSVIg"
    "VHJ1c3RlZCBDQTY="
)


def test_the_subject_of_a_real_certificate_is_read_as_mozilla_declares_it():
    assert im.subject_der(base64.b64decode(REAL_CERT_B64)) == base64.b64decode(REAL_SUBJECT_B64)


@pytest.mark.parametrize("cut", [0, 1, 2, 10, 40])
def test_a_truncated_certificate_is_refused_by_the_reader(cut):
    der = make_cert("Alpha CA")
    with pytest.raises(im.IntermediatesError):
        im.subject_der(der[:cut] if cut < 5 else der[:len(der) - cut])
