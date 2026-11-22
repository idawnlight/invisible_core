"""The security state of a profile is ONE road: downloaded and verified by `fetch`, generated once by the engine, kept in the cache, and COPIED into every profile.

A retail Firefox has the intermediates of the public web, OneCRL and the CRLite filters in `cert_storage` from its first second. The core downloads the three collections of
Mozilla's bucket `security-state` only when the changes feed says something is newer, has the engine's generate mode import them once, and every launch copies what the
engine wrote into its profile: no pref, no network on a warm cache, no thread. Nothing here reaches Mozilla or the real engine: the transport (`_intermediates._get`, the one
network seam of the core) is a fake service that serves the feed, the three collections and the attachments and records every URL it was asked, and the engine is the stand-in
of `_fake_security_state_engine.py` (which refuses whatever the generate contract forbids), reached through the one seam of the module (`_security_state._engine_for`).

No test measures a time and none reads a clock: the time of a fetch and the "now" of every decision (the age warning, the copy without the CRLite files, the refusal to generate
from stale data) are passed as data, and a launch that is given none reads `ss._now`, which the `cache` fixture fixes at `T0`. Every refusal is judged by the TREE of the cache,
which must be exactly what it was.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import requests

from invisible_core import _cached_asset as asset
from invisible_core import _intermediates as im
from invisible_core import _security_state as ss
from invisible_core import _security_state_generate as gen
from invisible_core import download
from invisible_core.constants import (
    CRLITE_PREF,
    INTERMEDIATES_BUNDLE_PATH,
    INTERMEDIATES_PREF,
    INTERMEDIATES_SERVER_INFO_URL,
    ONECRL_PREF,
    SECURITY_STATE_CHANGESET_URL_TEMPLATE,
    SECURITY_STATE_DIR_NAME,
    SECURITY_STATE_GENERATE_PREF,
    SECURITY_STATE_LATEST_URL,
    SECURITY_STATE_RESULT_NAME,
)
from invisible_core.juggler import connection
from invisible_core.launch import write_user_js
from test_revocations_are_built_as_firefox_reads_them import BASE, crlite as crlite_record, payload
from test_the_intermediates_are_declared import Mozilla as Intermediates

FAKE = Path(__file__).with_name("_fake_security_state_engine.py")
#: The function the launch calls, as it is in the package: the conftest of the suite stubs it for every test that is not about it.
REAL_ENSURE = ss.ensure_security_state
REAL_ENGINE_FOR = ss._engine_for

T0 = datetime(2026, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
T0_UTC = "2026-11-20T10:00:00Z"
BUILD_A = "20261119174916"
BUILD_B = "20270101000000"
PREFS_OF_THE_SECURITY_STATE = (SECURITY_STATE_GENERATE_PREF, INTERMEDIATES_PREF, ONECRL_PREF, CRLITE_PREF)


def changeset_url(collection: str, expected: int) -> str:
    return SECURITY_STATE_CHANGESET_URL_TEMPLATE.format(collection=collection, expected=expected)


class Service:
    """Mozilla's Remote Settings, as the transport answers it: the feed, the three collections, the server's info, the bundle and the attachments. `calls` is every URL asked."""

    def __init__(self):
        self.calls: list = []
        self.offline = False
        self.hidden: set = set()                 # collections the feed does not list
        self.corrupt_attachments = False         # the CRLite files come with other bytes than the record's hash
        self.inter = Intermediates(timestamp=1000)
        self.onecrl_ts = 1100
        self.onecrl = [{"id": "o1", "enabled": False, "issuerName": "TUZZeA==", "serialNumber": "AMvc+g1kEScJzxS35IWCUA=="}]
        self.crlite_ts = 1200
        self.crlite = [crlite_record("f", 1, incremental=False), crlite_record("d1", 2, incremental=True)]

    def add_delta(self, rid: str, n: int) -> dict:
        record = crlite_record(rid, n, incremental=True)
        self.crlite.append(record)
        return record

    def stamps(self) -> dict:
        return {"intermediates": self.inter.timestamp, "onecrl": self.onecrl_ts, "cert-revocations": self.crlite_ts}

    def feed(self) -> bytes:
        changes = [{"bucket": "main", "collection": "some-other", "last_modified": 5}]
        changes += [{"bucket": "security-state", "collection": c, "last_modified": t} for c, t in self.stamps().items() if c not in self.hidden]
        return json.dumps({"timestamp": 9, "changes": changes}).encode()

    def attachment_urls(self) -> list:
        return [BASE + r["attachment"]["location"] for r in self.crlite]

    def __call__(self, url: str) -> bytes:
        self.calls.append(url)
        if self.offline:
            raise requests.ConnectionError("no route to host")
        if url == SECURITY_STATE_LATEST_URL:
            return self.feed()
        if url == changeset_url("onecrl", self.onecrl_ts):
            return json.dumps({"timestamp": self.onecrl_ts, "metadata": {}, "changes": self.onecrl}).encode()
        if url == changeset_url("cert-revocations", self.crlite_ts):
            return json.dumps({"timestamp": self.crlite_ts, "metadata": {}, "changes": self.crlite}).encode()
        for record in self.crlite:
            if url == BASE + record["attachment"]["location"]:
                n = int(record["attachment"]["location"].split("/")[-1].split(".")[0])
                data = payload(n)
                return data[:-1] + b"?" if self.corrupt_attachments else data
        return self.inter(url)


class Engine:
    """The stand-in for the engine, behind the module's seam. `runs` is the build id of every generation it was asked for; `args` is what the callers gave as `engine=`."""

    def __init__(self):
        self.build_id = BUILD_A
        self.mode = "ok"
        self.runs: list = []
        self.args: list = []
        self.argvs: list = []   # what the callers gave as `engine_argv=`


@pytest.fixture
def cache(tmp_path, monkeypatch) -> Path:
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    monkeypatch.setenv("INVISIBLE_PLAYWRIGHT_CACHE_DIR", str(cache_dir))
    monkeypatch.delenv("STEALTHFOX_SECURITY_STATE", raising=False)
    monkeypatch.setattr(ss, "ensure_security_state", REAL_ENSURE)
    monkeypatch.setattr(ss, "_WARNED", False)
    monkeypatch.setattr(ss, "_AGE_WARNED", False)
    monkeypatch.setattr(ss, "_now", lambda: T0)   # the one clock of the module: a launch with no `now` is at T0
    monkeypatch.setattr(ss, "_SLOT", asset.FlightSlot())
    monkeypatch.setattr(download, "_SLEEP", lambda seconds: None)   # the retries ask again at once
    monkeypatch.setattr(download, "_note", lambda message: None)
    return cache_dir


@pytest.fixture
def service(cache, monkeypatch) -> Service:
    s = Service()
    monkeypatch.setattr(im, "_get", s)
    return s


@pytest.fixture
def engine(cache, monkeypatch) -> Engine:
    e = Engine()

    def seam(given, engine_argv=None):
        e.args.append(given)
        e.argvs.append(engine_argv)
        argv = list(engine_argv) if engine_argv is not None else [sys.executable, "-I", str(FAKE), "-headless", "-no-remote"]
        return argv, gen.EngineId(version="159.0", build_id=e.build_id)

    real_generate = ss.generate

    def counting(command, inputs, eid, out_dir, **kw):
        e.runs.append(eid.build_id)
        monkeypatch.setenv("FAKE_ENGINE_MODE", e.mode)
        monkeypatch.setenv("FAKE_ENGINE_VERSION", "159.0")
        monkeypatch.setenv("FAKE_ENGINE_BUILD_ID", e.build_id)
        return real_generate(command, inputs, eid, out_dir, **kw)

    monkeypatch.setattr(ss, "_engine_for", seam)
    monkeypatch.setattr(ss, "generate", counting)
    return e


def root_of(cache: Path) -> Path:
    return cache / "security-state"


def versions_of(cache: Path) -> list:
    root = root_of(cache)
    return sorted(p.name for p in root.iterdir() if p.is_dir()) if root.exists() else []


def snapshot(base: Path) -> dict:
    """Every path under `base` with the sha256 of its bytes (None for a directory): what 'the cache is exactly as it was' means."""
    out = {}
    for p in sorted(base.rglob("*")):
        out[p.relative_to(base).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
    return out


def state_files(directory: Path) -> dict:
    """The `security_state/` directory of a ready or a profile: name -> bytes."""
    return {p.name: p.read_bytes() for p in sorted((directory / SECURITY_STATE_DIR_NAME).iterdir())}


def user_js_of(profile: Path) -> str:
    return (profile / "user.js").read_text(encoding="utf-8")


def ready_of(cache: Path, version: str, build_id: str = BUILD_A) -> Path:
    return root_of(cache) / version / ("generated-" + build_id)


def filter_names(service: Service) -> list:
    return sorted(r["attachment"]["filename"] for r in service.crlite)


# --- a cold `fetch`: the three collections, one generation, the version in place -----------------------------------------------------------------------

@pytest.mark.integration
def test_a_cold_fetch_downloads_the_three_collections_generates_once_and_puts_the_version_in_place(cache, service, engine):
    path, changed = ss.update_security_state(now=T0)
    assert changed is True
    assert path == ready_of(cache, "1000-1100-1200")
    assert engine.runs == [BUILD_A]
    version = root_of(cache) / "1000-1100-1200"
    assert sorted(p.name for p in version.iterdir()) == sorted(
        ["intermediates.json", "onecrl.json", "crlite.json", "manifest.json", "generated-" + BUILD_A] + filter_names(service))
    assert json.loads((version / "manifest.json").read_text()) == {
        "format": 1, "version": "1000-1100-1200", "updated_utc": T0_UTC,
        "collections": {"intermediates": 1000, "onecrl": 1100, "cert-revocations": 1200}}
    assert sorted(p.name for p in path.iterdir()) == sorted([SECURITY_STATE_RESULT_NAME, SECURITY_STATE_DIR_NAME])
    state = state_files(path)
    assert sorted(state) == sorted(["data.safe.bin", "crlite.filter", "20261112-0-default.filter.delta"])
    assert json.loads((path / SECURITY_STATE_RESULT_NAME).read_text())["engine"]["build_id"] == BUILD_A
    # the three collections were each asked once, through the one feed
    asked = service.calls
    assert asked[0] == SECURITY_STATE_LATEST_URL
    assert changeset_url("intermediates", 1000) in asked and changeset_url("onecrl", 1100) in asked and changeset_url("cert-revocations", 1200) in asked
    assert sorted(p.name for p in cache.iterdir()) == ["security-state"], "nothing is left beside the root"


@pytest.mark.integration
def test_a_second_fetch_with_the_same_feed_asks_only_the_feed_and_generates_nothing(cache, service, engine):
    first, _ = ss.update_security_state(now=T0)
    service.calls.clear()
    before = snapshot(cache)
    path, changed = ss.update_security_state(now=T0 + timedelta(days=3))
    assert (path, changed) == (first, False)
    assert service.calls == [SECURITY_STATE_LATEST_URL], "the user's command asks the feed every time, and nothing else"
    assert engine.runs == [BUILD_A]
    assert snapshot(cache) == before


@pytest.mark.integration
def test_a_newer_crlite_downloads_only_its_new_delta_and_copies_the_other_two_collections(cache, service, engine):
    """The known-bad is a fetch that downloads the three collections again when one moved (or one that reuses nothing of the filters it already holds): here only the
    changeset of `cert-revocations`, the server's info and the NEW delta are asked, intermediates.json and onecrl.json are copies (never links), and the engine runs once more."""
    ss.update_security_state(now=T0)
    service.add_delta("d2", 3)
    service.crlite_ts = 1300
    service.calls.clear()
    later = T0 + timedelta(days=2)
    path, changed = ss.update_security_state(now=later)
    assert changed is True and path == ready_of(cache, "1000-1100-1300")
    assert service.calls == [SECURITY_STATE_LATEST_URL, changeset_url("cert-revocations", 1300), INTERMEDIATES_SERVER_INFO_URL, service.attachment_urls()[2]]
    assert engine.runs == [BUILD_A, BUILD_A]
    new, old = root_of(cache) / "1000-1100-1300", root_of(cache) / "1000-1100-1200"
    assert json.loads((new / "manifest.json").read_text())["updated_utc"] == "2026-11-22T10:00:00Z"
    assert json.loads((new / "manifest.json").read_text())["collections"] == {"intermediates": 1000, "onecrl": 1100, "cert-revocations": 1300}
    for name in ("intermediates.json", "onecrl.json"):
        assert (new / name).read_bytes() == (old / name).read_bytes()
        assert os.stat(new / name).st_nlink == 1 and os.stat(old / name).st_nlink == 1, "a copy, never a link"
    assert sorted(state_files(path)) == sorted(["data.safe.bin", "crlite.filter", "20261112-0-default.filter.delta", "20261113-0-default.filter.delta"])
    assert versions_of(cache) == ["1000-1100-1200", "1000-1100-1300"], "the previous version stays beside the newest"


@pytest.mark.integration
def test_a_newer_intermediates_alone_downloads_only_the_intermediates(cache, service, engine):
    ss.update_security_state(now=T0)
    service.inter.timestamp = 1050
    service.calls.clear()
    path, changed = ss.update_security_state(now=T0)
    assert changed is True and path == ready_of(cache, "1050-1100-1200")
    assert service.calls == [SECURITY_STATE_LATEST_URL, changeset_url("intermediates", 1050), INTERMEDIATES_SERVER_INFO_URL, BASE + INTERMEDIATES_BUNDLE_PATH]
    new, old = root_of(cache) / "1050-1100-1200", root_of(cache) / "1000-1100-1200"
    for name in ["onecrl.json", "crlite.json"] + filter_names(service):
        assert (new / name).read_bytes() == (old / name).read_bytes()


@pytest.mark.integration
def test_only_the_two_newest_versions_are_kept(cache, service, engine):
    for i in range(3):
        service.onecrl_ts = 1100 + i
        ss.update_security_state(now=T0)
    assert versions_of(cache) == ["1000-1101-1200", "1000-1102-1200"]
    assert ss._newest(root_of(cache)).stamps == (1000, 1102, 1200)


# --- the engine changed: a new generation from the cached data, with no network --------------------------------------------------------------------------

@pytest.mark.integration
def test_an_engine_that_changed_generates_again_from_the_cached_data_and_asks_nobody(cache, service, engine):
    """The known-bad is a cache that hands the cert_storage of one engine build to another, or one that downloads again to regenerate: the new build id gets its own
    `generated-<build>` from the version's own files, the transport is not touched, and the generation of the old build is still there."""
    first, _ = ss.update_security_state(now=T0)
    engine.build_id = BUILD_B
    service.calls.clear()
    ready = REAL_ENSURE(now=T0)
    assert ready is not None and ready.path == ready_of(cache, "1000-1100-1200", BUILD_B)
    assert service.calls == []
    assert engine.runs == [BUILD_A, BUILD_B]
    assert first.is_dir() and (first / SECURITY_STATE_DIR_NAME).is_dir(), "the old generation stays"
    assert ready.updated_utc == T0_UTC
    assert REAL_ENSURE(now=T0).path == ready.path and engine.runs == [BUILD_A, BUILD_B], "once generated, it is a lookup"
    assert json.loads((ready.path / SECURITY_STATE_RESULT_NAME).read_text())["engine"]["build_id"] == BUILD_B


@pytest.mark.integration
def test_a_fetch_after_an_engine_change_with_nothing_newer_asks_the_feed_and_generates(cache, service, engine):
    ss.update_security_state(now=T0)
    engine.build_id = BUILD_B
    service.calls.clear()
    path, changed = ss.update_security_state(now=T0)
    assert (path, changed) == (ready_of(cache, "1000-1100-1200", BUILD_B), False)
    assert service.calls == [SECURITY_STATE_LATEST_URL]
    assert engine.runs == [BUILD_A, BUILD_B]


@pytest.mark.integration
def test_a_regeneration_that_fails_leaves_the_version_as_it_was_and_the_launch_warns(cache, service, engine, capsys):
    ss.update_security_state(now=T0)
    engine.build_id = BUILD_B
    engine.mode = "exit1"
    before = snapshot(cache)
    assert REAL_ENSURE(now=T0) is None
    assert snapshot(cache) == before
    assert capsys.readouterr().err.count("could not be made") == 1


# --- every launch copies ---------------------------------------------------------------------------------------------------------------------------

@pytest.mark.integration
def test_every_launch_copies_the_generated_directory_into_its_profile_and_writes_no_pref(cache, service, engine, tmp_path):
    """The known-bad is a launch that does not copy (the profile starts with an empty cert_storage), one that links (a session would write into the cache and into every other
    profile), or one that writes a pref for it. Two launches, two profiles: each has `security_state/` equal to the cache's, every file a real copy, and no line of the
    four prefs of the security state in `user.js`; the transport was not touched."""
    ready, _ = ss.update_security_state(now=T0)
    service.calls.clear()
    runs = list(engine.runs)
    cached = state_files(ready)
    for name in ("p1", "p2"):
        profile = tmp_path / name
        user_js = write_user_js(profile, {"a": 1, "b": "x"})
        assert state_files(profile) == cached
        for f in (profile / SECURITY_STATE_DIR_NAME).iterdir():
            assert os.stat(f).st_nlink == 1 and not f.is_symlink(), "a copy, never a link: %s" % f
        text = user_js.read_text(encoding="utf-8")
        assert text == 'user_pref("a", 1);\nuser_pref("b", "x");\n'
        assert not [p for p in PREFS_OF_THE_SECURITY_STATE if p in text]
    assert service.calls == [] and engine.runs == runs
    (tmp_path / "p1" / SECURITY_STATE_DIR_NAME / "crlite.filter").write_bytes(b"a session rewrote its own copy")
    assert state_files(ready) == cached and state_files(tmp_path / "p2") == cached, "no session writes into the cache or into another profile"
    write_user_js(tmp_path / "p1", {"a": 1})
    assert state_files(tmp_path / "p1") == cached, "a launch of the same profile puts the state back, whole"


def _plan_user_js(monkeypatch, tmp_path: Path, **launch_kw) -> Path:
    """`build_launch_plan`, hermetic like tests/test_launch.py; the profile it wrote."""
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
    build_launch_plan(42, profile_dir=pdir, timezone="auto", locale="auto", **launch_kw)
    return pdir


class _Stop(Exception):
    pass


def _instance_profile(monkeypatch, tmp_path: Path, **launch_kw) -> Path:
    """`instance.launch` (the core's own client): the profile as it is when `connection.launch` is called, which then stops the launch."""
    from invisible_core.juggler import instance

    seen = {}

    def stop(executable, profile_dir, **kw):
        seen["profile"] = Path(profile_dir)
        raise _Stop()

    monkeypatch.setattr(connection, "launch", stop)
    with pytest.raises(_Stop):
        instance.launch("my-firefox", prefs={"a": 1}, profile_dir=str(tmp_path / "instance_profile"), **launch_kw)
    return seen["profile"]


ROADS = {"build_launch_plan": (_plan_user_js, "/fake/firefox"), "instance.launch": (_instance_profile, "my-firefox")}


@pytest.mark.integration
@pytest.mark.parametrize("road", sorted(ROADS))
def test_every_road_of_the_core_s_launch_places_the_state_once_with_the_engine_it_runs(cache, service, engine, monkeypatch, tmp_path, road):
    """The known-bad is a copy made in `connection.launch` only, or with no word of which engine the launch runs: `build_launch_plan` writes its profile and the caller
    spawns the browser itself. Both roads end in `write_user_js`, the one writer, which passes the binary it was given."""
    ready, _ = ss.update_security_state(now=T0)
    service.calls.clear()
    engine.args.clear()
    build, binary = ROADS[road]
    profile = build(monkeypatch, tmp_path)
    assert state_files(profile) == state_files(ready)
    assert not [p for p in PREFS_OF_THE_SECURITY_STATE if p in user_js_of(profile)]
    assert engine.args == [binary]
    assert service.calls == []


@pytest.mark.unit
def test_the_four_prefs_are_written_in_one_place_of_the_package_and_the_launch_writes_none():
    """One declaration of each name (the constants); the generate mode writes them on its own work profile, and `launch.py` names none."""
    src = Path(ss.__file__).parent
    for pref in PREFS_OF_THE_SECURITY_STATE:
        places = sorted(p.relative_to(src).as_posix() for p in src.rglob("*.py") if pref in p.read_text(encoding="utf-8"))
        assert places == ["constants.py"], (pref, places)
    assert "_PREF" not in (src / "launch.py").read_text(encoding="utf-8")


# --- the warning at ten days ------------------------------------------------------------------------------------------------------------------------

TEN_DAYS = timedelta(days=10)
ONE_SECOND = timedelta(seconds=1)


@pytest.mark.integration
def test_data_ten_days_old_or_more_is_a_warning_on_stderr_once_and_just_under_ten_days_is_not(cache, service, engine, tmp_path, capsys):
    ss.update_security_state(now=T0)
    capsys.readouterr()
    assert ss.place_security_state(tmp_path / "a", now=T0 + TEN_DAYS - ONE_SECOND) is True
    assert capsys.readouterr().err == "", "ten days less a second is fresh"
    assert ss.place_security_state(tmp_path / "b", now=T0 + TEN_DAYS) is True
    err = capsys.readouterr().err
    assert err.count("revocation data is 10 days old") == 1 and "left out" in err and "invisible-playwright fetch" in err, "exactly ten days is stale"
    assert ss.place_security_state(tmp_path / "c", now=T0 + timedelta(days=30)) is True
    assert capsys.readouterr().err == "", "once per process"
    assert sorted(state_files(tmp_path / "c")) == ["data.safe.bin"] and sorted(state_files(tmp_path / "a")) == sorted(state_files(ready_of(cache, "1000-1100-1200")))


@pytest.mark.integration
@pytest.mark.parametrize("age", [TEN_DAYS, TEN_DAYS + ONE_SECOND, timedelta(days=45)])
def test_a_launch_with_stale_data_copies_only_the_data_without_the_crlite_filter_and_the_deltas(cache, service, engine, tmp_path, capsys, age):
    """(b) The known-bad is a stale profile that still carries `crlite.filter` and the deltas: cert_storage would take them for fresh, because their time is the time of OUR
    generation. With data ten days old (exactly: it is stale) the profile has `security_state/data.safe.bin` and nothing of the filters; the cache keeps them whole."""
    ready, _ = ss.update_security_state(now=T0)
    cached = state_files(ready)
    assert "crlite.filter" in cached and any(n.endswith(".delta") for n in cached)
    service.calls.clear()
    capsys.readouterr()
    before = snapshot(cache)
    assert ss.place_security_state(tmp_path / "p", now=T0 + age) is True
    state = state_files(tmp_path / "p")
    assert sorted(state) == ["data.safe.bin"] and state["data.safe.bin"] == cached["data.safe.bin"]
    assert not [n for n in state if n == "crlite.filter" or n.endswith(".delta")]
    err = capsys.readouterr().err
    assert "CRLite filters are left out" in err and "invisible-playwright fetch" in err and "%d days old" % age.days in err
    assert snapshot(cache) == before and service.calls == [], "the cache is as it was and nothing was asked"


@pytest.mark.integration
def test_a_launch_with_data_ten_days_less_a_second_old_copies_everything_and_says_nothing(cache, service, engine, tmp_path, capsys):
    ready, _ = ss.update_security_state(now=T0)
    capsys.readouterr()
    assert ss.place_security_state(tmp_path / "p", now=T0 + TEN_DAYS - ONE_SECOND) is True
    assert state_files(tmp_path / "p") == state_files(ready)
    assert capsys.readouterr().err == ""


@pytest.mark.integration
@pytest.mark.parametrize("age", [TEN_DAYS, TEN_DAYS + ONE_SECOND])
def test_an_engine_that_changed_is_not_generated_for_when_the_cached_data_is_stale(cache, service, engine, tmp_path, capsys, age):
    """(a) The known-bad is a generation made at launch from old data: cert_storage would date it at the moment of the generation and the old filters would look fresh, which a
    retail Firefox never does. Ten days exactly, and ten days and a second: the engine is not run, nothing is asked, the cache is as it was, the launch copies nothing and the
    warning says to run fetch."""
    ss.update_security_state(now=T0)
    engine.build_id = BUILD_B
    service.calls.clear()
    capsys.readouterr()
    before = snapshot(cache)
    assert REAL_ENSURE(now=T0 + age) is None
    assert ss.place_security_state(tmp_path / "p", now=T0 + age) is False
    assert not (tmp_path / "p" / SECURITY_STATE_DIR_NAME).exists()
    assert engine.runs == [BUILD_A], "no generation was run"
    assert service.calls == [] and snapshot(cache) == before
    err = capsys.readouterr().err
    assert err.count("could not be made") == 1 and "invisible-playwright fetch" in err, "one warning per process, and it names fetch"


@pytest.mark.integration
def test_an_engine_that_changed_is_generated_for_when_the_cached_data_is_ten_days_less_a_second_old(cache, service, engine, tmp_path, capsys):
    ss.update_security_state(now=T0)
    engine.build_id = BUILD_B
    service.calls.clear()
    capsys.readouterr()
    ready = REAL_ENSURE(now=T0 + TEN_DAYS - ONE_SECOND)
    assert ready is not None and ready.path == ready_of(cache, "1000-1100-1200", BUILD_B)
    assert engine.runs == [BUILD_A, BUILD_B], "one generation"
    assert service.calls == []
    assert ss.place_security_state(tmp_path / "p", now=T0 + TEN_DAYS - ONE_SECOND) is True
    assert state_files(tmp_path / "p") == state_files(ready.path)
    assert capsys.readouterr().err == ""


@pytest.mark.integration
@pytest.mark.parametrize("age", [TEN_DAYS, TEN_DAYS + ONE_SECOND])
def test_a_fetch_with_nothing_newer_after_an_engine_change_does_not_generate_from_stale_data(cache, service, engine, capsys, age):
    """(a) `update_security_state` too: the feed has nothing newer, the engine changed, the data is stale: no generation, `(None, False)`, the cache exactly as it was."""
    ss.update_security_state(now=T0)
    engine.build_id = BUILD_B
    service.calls.clear()
    capsys.readouterr()
    before = snapshot(cache)
    assert ss.update_security_state(now=T0 + age) == (None, False)
    assert engine.runs == [BUILD_A]
    assert service.calls == [SECURITY_STATE_LATEST_URL], "only the feed was asked"
    assert snapshot(cache) == before
    assert "could not update the security state" in capsys.readouterr().err


@pytest.mark.integration
def test_a_fetch_with_nothing_newer_ten_days_less_a_second_after_an_engine_change_generates(cache, service, engine):
    ss.update_security_state(now=T0)
    engine.build_id = BUILD_B
    assert ss.update_security_state(now=T0 + TEN_DAYS - ONE_SECOND) == (ready_of(cache, "1000-1100-1200", BUILD_B), False)
    assert engine.runs == [BUILD_A, BUILD_B]


@pytest.mark.integration
def test_a_fetch_that_builds_a_new_version_after_a_long_time_generates_from_its_own_fresh_data(cache, service, engine):
    """The data of a fetch has `updated_utc` = the fetch's own `now`, so it is fresh whatever the age of the previous version."""
    ss.update_security_state(now=T0)
    service.onecrl_ts += 1
    path, changed = ss.update_security_state(now=T0 + timedelta(days=60))
    assert changed is True and path == ready_of(cache, "1000-1101-1200")
    assert engine.runs == [BUILD_A, BUILD_A]


@pytest.mark.unit
def test_a_state_the_user_gave_has_no_age_and_no_warning(cache, service, tmp_path, monkeypatch, capsys):
    given = tmp_path / "given"
    (given / SECURITY_STATE_DIR_NAME).mkdir(parents=True)
    (given / SECURITY_STATE_DIR_NAME / "data.safe.bin").write_bytes(b"mine")
    (given / SECURITY_STATE_DIR_NAME / "crlite.filter").write_bytes(b"filter")
    (given / SECURITY_STATE_DIR_NAME / "1.filter.delta").write_bytes(b"delta")
    (given / SECURITY_STATE_RESULT_NAME).write_text("{}")
    monkeypatch.setenv("STEALTHFOX_SECURITY_STATE", str(given))
    assert ss.place_security_state(tmp_path / "p", now=T0 + timedelta(days=3650)) is True
    assert capsys.readouterr().err == ""
    assert state_files(tmp_path / "p") == {"data.safe.bin": b"mine", "crlite.filter": b"filter", "1.filter.delta": b"delta"}, "a directory the user gave is copied whole, whatever the date"


# --- nothing that fails changes the cache --------------------------------------------------------------------------------------------------------

def _a_crlite_file_with_other_bytes(service, engine):
    service.corrupt_attachments = True


def _a_onecrl_record_that_is_not_base64(service, engine):
    service.onecrl[0]["issuerName"] = "!!not base64!!"


def _a_generation_that_fails(service, engine):
    engine.mode = "exit1"


def _a_feed_without_a_collection(service, engine):
    service.hidden.add("cert-revocations")


@pytest.mark.integration
@pytest.mark.parametrize("fail", [_a_crlite_file_with_other_bytes, _a_onecrl_record_that_is_not_base64, _a_generation_that_fails, _a_feed_without_a_collection])
def test_a_fetch_that_does_not_add_up_leaves_the_cache_exactly_as_it_was(cache, service, engine, fail, capsys):
    """The known-bad is a version kept (or half kept) although one check failed: the tree of the cache, the root AND beside it, is byte for byte what it was, no staging
    directory is left, the call does not raise, says it in one line on stderr and returns the generation that was ready and `False`."""
    ready, _ = ss.update_security_state(now=T0)
    service.onecrl_ts += 1
    service.add_delta("d2", 3)
    service.crlite_ts += 1
    fail(service, engine)
    before = snapshot(cache)
    capsys.readouterr()
    assert ss.update_security_state(now=T0 + timedelta(days=1)) == (ready, False)
    assert snapshot(cache) == before
    assert [p.name for p in cache.iterdir() if p.name.startswith(".tmp")] == []
    err = capsys.readouterr().err
    assert err.count("could not update the security state") == 1 and len(err.splitlines()) == 1


@pytest.mark.integration
def test_a_cold_fetch_that_fails_leaves_no_version_and_no_staging(cache, service, engine, capsys):
    engine.mode = "exit1"
    assert ss.update_security_state(now=T0) == (None, False)
    assert versions_of(cache) == [] and [p.name for p in cache.iterdir() if p.name.startswith(".tmp")] == []
    assert "there is none in the cache" in capsys.readouterr().err


@pytest.mark.unit
def test_a_fetch_with_no_network_keeps_the_cache_and_says_so_without_raising(cache, service, engine, capsys):
    ready, _ = ss.update_security_state(now=T0)
    service.offline = True
    before = snapshot(cache)
    capsys.readouterr()
    assert ss.update_security_state(now=T0) == (ready, False)
    assert snapshot(cache) == before
    assert capsys.readouterr().err.count("the one in the cache stays") == 1


# --- the launch with a cold cache -----------------------------------------------------------------------------------------------------------------

@pytest.mark.unit
def test_a_cold_launch_with_no_network_starts_without_the_state_and_says_so_once(cache, service, engine, tmp_path, capsys):
    """The known-bad is a launch that fails (or hangs) because Mozilla cannot be reached: the browser starts like a retail one with a new profile, `user.js` is written, there is
    no `security_state/`, the warning is said once per process, and nothing is left in the cache."""
    service.offline = True
    profile = tmp_path / "profile"
    user_js = write_user_js(profile, {"a": 1})
    assert user_js.read_text(encoding="utf-8") == 'user_pref("a", 1);\n'
    assert not (profile / SECURITY_STATE_DIR_NAME).exists()
    assert capsys.readouterr().err.count("could not be made") == 1
    assert REAL_ENSURE() is None
    assert capsys.readouterr().err == "", "the warning is once per process"
    assert versions_of(cache) == [] and [p.name for p in cache.iterdir() if p.name.startswith(".tmp")] == []
    assert engine.runs == []


@pytest.mark.integration
def test_a_cold_launch_downloads_and_generates_once_in_line_and_the_next_one_only_copies(cache, service, engine, tmp_path):
    write_user_js(tmp_path / "p1", {"a": 1})
    assert versions_of(cache) == ["1000-1100-1200"] and engine.runs == [BUILD_A]
    asked = len(service.calls)
    write_user_js(tmp_path / "p2", {"a": 1})
    assert len(service.calls) == asked and engine.runs == [BUILD_A]
    assert state_files(tmp_path / "p1") == state_files(tmp_path / "p2")
    assert json.loads((root_of(cache) / "1000-1100-1200" / "manifest.json").read_text())["updated_utc"].endswith("Z")


@pytest.mark.integration
def test_the_callers_of_a_cold_cache_in_one_process_share_one_generation(cache, service, engine):
    results: list = []
    errors: list = []

    def call():
        try:
            results.append(REAL_ENSURE())
        except BaseException as exc:   # the thread must report, not die quietly
            errors.append(exc)

    threads = [threading.Thread(target=call) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert engine.runs == [BUILD_A], "one generation for four callers"
    assert len({r.path for r in results}) == 1 and len(results) == 4


# --- the user's own state (STEALTHFOX_SECURITY_STATE) ------------------------------------------------------------------------------------------------

@pytest.mark.unit
def test_a_state_the_user_gave_is_copied_as_it_is_and_nothing_is_asked(cache, service, engine, tmp_path, monkeypatch):
    given = tmp_path / "given"
    (given / SECURITY_STATE_DIR_NAME).mkdir(parents=True)
    (given / SECURITY_STATE_DIR_NAME / "data.safe.bin").write_bytes(b"mine")
    (given / SECURITY_STATE_DIR_NAME / "crlite.filter").write_bytes(b"filter")
    (given / SECURITY_STATE_RESULT_NAME).write_text("{}")
    monkeypatch.setenv("STEALTHFOX_SECURITY_STATE", str(given))
    ready = REAL_ENSURE()
    assert ready is not None and ready.path == given and ready.updated_utc is None
    write_user_js(tmp_path / "p", {"a": 1})
    assert state_files(tmp_path / "p") == {"data.safe.bin": b"mine", "crlite.filter": b"filter"}
    assert ss.update_security_state(now=T0) == (given, False)
    assert service.calls == [] and engine.runs == [] and not root_of(cache).exists()


@pytest.mark.unit
def test_a_state_the_user_gave_with_no_data_copies_nothing(cache, service, engine, tmp_path, monkeypatch):
    """The state of CI (`ci/security-state`): a result and no `security_state/`; a launch copies nothing and does not fail."""
    given = tmp_path / "given"
    given.mkdir()
    (given / SECURITY_STATE_RESULT_NAME).write_text("{}")
    monkeypatch.setenv("STEALTHFOX_SECURITY_STATE", str(given))
    assert ss.place_security_state(tmp_path / "p") is False
    assert not (tmp_path / "p" / SECURITY_STATE_DIR_NAME).exists()


@pytest.mark.unit
def test_a_state_the_user_gave_that_is_not_there_is_an_error(cache, service, engine, tmp_path, monkeypatch):
    monkeypatch.setenv("STEALTHFOX_SECURITY_STATE", str(tmp_path / "missing"))
    with pytest.raises(RuntimeError, match="securitystate-result.json"):
        REAL_ENSURE()
    with pytest.raises(RuntimeError, match="securitystate-result.json"):
        write_user_js(tmp_path / "p", {"a": 1})
    (tmp_path / "empty").mkdir()
    monkeypatch.setenv("STEALTHFOX_SECURITY_STATE", str(tmp_path / "empty"))
    with pytest.raises(RuntimeError, match="securitystate-result.json"):
        REAL_ENSURE()
    assert service.calls == []


# --- what the cache calls complete, and the order of its versions ------------------------------------------------------------------------------------

def _make_version(cache: Path, stamps, build_id=BUILD_A, *, manifest=True, generated=True, name=None) -> Path:
    version = root_of(cache) / (name or "-".join(str(s) for s in stamps))
    version.mkdir(parents=True)
    if manifest:
        (version / "manifest.json").write_text(json.dumps({
            "format": 1, "version": "-".join(str(s) for s in stamps), "updated_utc": T0_UTC,
            "collections": dict(zip(["intermediates", "onecrl", "cert-revocations"], stamps))}))
    if generated:
        (version / ("generated-" + build_id)).mkdir()
        (version / ("generated-" + build_id) / SECURITY_STATE_RESULT_NAME).write_text("{}")
    return version


@pytest.mark.unit
def test_the_newest_version_is_the_highest_tuple_of_three_numbers_not_the_last_name(cache):
    for stamps in [(999, 5, 5), (1000, 1, 1), (1000, 1, 20), (1000, 1, 3)]:
        _make_version(cache, stamps)
    assert [v.stamps for v in ss._versions(root_of(cache))] == [(999, 5, 5), (1000, 1, 1), (1000, 1, 3), (1000, 1, 20)]
    assert ss._newest(root_of(cache)).stamps == (1000, 1, 20)


@pytest.mark.unit
@pytest.mark.parametrize("how", ["no manifest", "no generation", "a generation with no result", "a manifest that names another version", "a name that is not a version"])
def test_a_directory_is_a_version_only_when_it_is_complete(cache, how):
    stamps = (1000, 1100, 1200)
    if how == "no manifest":
        _make_version(cache, stamps, manifest=False)
    elif how == "no generation":
        _make_version(cache, stamps, generated=False)
    elif how == "a generation with no result":
        v = _make_version(cache, stamps, generated=False)
        (v / ("generated-" + BUILD_A)).mkdir()
    elif how == "a manifest that names another version":
        v = _make_version(cache, stamps)
        (v / "manifest.json").write_text(json.dumps({"format": 1, "version": "1-2-3", "updated_utc": T0_UTC,
                                                     "collections": {"intermediates": 1, "onecrl": 2, "cert-revocations": 3}}))
    else:
        _make_version(cache, stamps, name="latest")
    assert ss._versions(root_of(cache)) == []


@pytest.mark.unit
def test_a_launch_finds_nothing_in_an_incomplete_version_and_takes_the_newest_complete_one(cache):
    _make_version(cache, (1000, 1, 1), BUILD_A)
    _make_version(cache, (2000, 1, 1), BUILD_B, generated=False)
    eng = ss._Engine(None, gen.EngineId("159.0", BUILD_A))
    ready = ss._lookup(root_of(cache), eng)
    assert ready == ss.Ready(root_of(cache) / "1000-1-1" / ("generated-" + BUILD_A), T0_UTC)
    assert ss._lookup(root_of(cache), ss._Engine(None, gen.EngineId("159.0", BUILD_B))) is None


@pytest.mark.unit
def test_the_newest_version_decides_even_when_an_older_one_has_the_engine(cache):
    """A launch reads the newest version: the generation of another engine in an older one is not used with newer data."""
    _make_version(cache, (1000, 1, 1), BUILD_B)
    _make_version(cache, (2000, 1, 1), BUILD_A)
    assert ss._lookup(root_of(cache), ss._Engine(None, gen.EngineId("159.0", BUILD_B))) is None


@pytest.mark.unit
def test_the_names_of_the_old_road_are_gone_and_the_new_ones_are_exported():
    import invisible_core

    assert not hasattr(invisible_core, "ensure_intermediates")
    assert invisible_core.ensure_security_state is REAL_ENSURE
    assert invisible_core.update_security_state is ss.update_security_state
    assert invisible_core.update_intermediates is ss.update_security_state, "the name the wrapper's CLI imports today"
    assert "security-state" in download.STATE_DIRS and "intermediates" not in download.STATE_DIRS


# --- the launch line is the caller's -----------------------------------------------------------------------------------------------------------------

def _minapp_line(tmp_path: Path, monkeypatch) -> list:
    """A caller's launch line of another layout than the invisible one, and the fake told to expect exactly it (plus `-profile <dir>`)."""
    tail = ["-app", str(tmp_path / "minapp"), "-headless", "-no-remote"]
    monkeypatch.setenv("FAKE_ENGINE_EXPECT_ARGS", json.dumps(tail))
    return [sys.executable, "-I", str(FAKE)] + tail


@pytest.mark.unit
def test_the_seam_takes_the_identity_from_the_engine_when_given_else_from_the_first_word_of_the_line(cache, monkeypatch):
    read = []

    def identity(binary):
        read.append(str(binary))
        return gen.EngineId(version="159.0", build_id=BUILD_A)

    monkeypatch.setattr(ss, "engine_id_of", identity)
    line = ["/x/engine/firefox", "-app", "/x/engine/minapp", "-headless", "-no-remote"]
    assert REAL_ENGINE_FOR(None, line) == (line, gen.EngineId("159.0", BUILD_A))
    assert read == ["/x/engine/firefox"]
    read.clear()
    assert REAL_ENGINE_FOR("/y/bin/firefox", line) == (line, gen.EngineId("159.0", BUILD_A))
    assert read == ["/y/bin/firefox"]
    read.clear()
    assert REAL_ENGINE_FOR("/y/bin/firefox") == (["/y/bin/firefox", "-headless", "-no-remote"], gen.EngineId("159.0", BUILD_A))
    assert read == ["/y/bin/firefox"]


@pytest.mark.integration
def test_a_fetch_generates_with_the_callers_launch_line(cache, service, engine, monkeypatch, tmp_path):
    line = _minapp_line(tmp_path, monkeypatch)
    path, changed = ss.update_security_state(engine_argv=line, now=T0)
    assert changed is True and path == ready_of(cache, "1000-1100-1200")
    assert engine.argvs == [line] and engine.runs == [BUILD_A]


@pytest.mark.integration
def test_a_launch_generates_in_line_with_the_callers_launch_line(cache, service, engine, monkeypatch, tmp_path):
    line = _minapp_line(tmp_path, monkeypatch)
    ready = ss.ensure_security_state(engine_argv=line, now=T0)
    assert ready is not None and ready.path == ready_of(cache, "1000-1100-1200")
    assert engine.argvs == [line] and engine.runs == [BUILD_A]


@pytest.mark.integration
def test_write_user_js_passes_the_launch_line_to_the_generation(cache, service, engine, monkeypatch, tmp_path):
    line = _minapp_line(tmp_path, monkeypatch)
    profile = tmp_path / "p"
    write_user_js(profile, {"a": 1}, engine_argv=line)
    assert engine.argvs == [line] and engine.runs == [BUILD_A]
    assert sorted(state_files(profile)) == sorted(["data.safe.bin", "crlite.filter", "20261112-0-default.filter.delta"])


@pytest.mark.integration
def test_write_user_js_with_no_launch_line_gives_none_to_the_seam(cache, service, engine, tmp_path):
    write_user_js(tmp_path / "p", {"a": 1}, engine="/y/bin/firefox")
    assert engine.args == ["/y/bin/firefox"] and engine.argvs == [None]


def _fresh_data_for_an_engine_that_changed(engine, service) -> None:
    """Fresh cached data with a generation for the old build only; the launch under test runs the new one. The transport and the recording start clean."""
    ss.update_security_state(now=T0)
    engine.build_id = BUILD_B
    service.calls.clear()
    engine.runs.clear()
    engine.args.clear()
    engine.argvs.clear()


@pytest.mark.integration
@pytest.mark.parametrize("road", sorted(ROADS))
def test_a_launch_of_a_changed_engine_generates_once_with_the_callers_launch_line_and_asks_nobody(cache, service, engine, monkeypatch, tmp_path, road):
    """The known-bad is a public launch that does not carry `engine_argv`: with fresh data and no generation for the engine it runs, the core generates with the default line
    `[binary, -headless, -no-remote]` instead of the caller's (the fake engine refuses any other line than the expected one)."""
    _fresh_data_for_an_engine_that_changed(engine, service)   # first: the fake is told to expect the caller's line only after the old build was generated
    line = _minapp_line(tmp_path, monkeypatch)
    build, binary = ROADS[road]
    profile = build(monkeypatch, tmp_path, engine_argv=line)
    assert engine.argvs == [line] and engine.runs == [BUILD_B]
    assert engine.args == [binary]
    assert state_files(profile), "the generated state is in the profile"
    assert service.calls == []


@pytest.mark.integration
@pytest.mark.parametrize("road", sorted(ROADS))
def test_a_launch_with_no_launch_line_gives_none_to_the_generation(cache, service, engine, monkeypatch, tmp_path, road):
    """The guard: without `engine_argv` the core's own line (`default_argv` of the engine) is what the generation uses; the seam is told None."""
    _fresh_data_for_an_engine_that_changed(engine, service)
    build, binary = ROADS[road]
    build(monkeypatch, tmp_path)
    assert engine.argvs == [None] and engine.runs == [BUILD_B] and engine.args == [binary]
    assert service.calls == []
