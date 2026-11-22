"""The security state of a profile, ONE road: what a retail Firefox has in `cert_storage` (the intermediates, OneCRL, the CRLite filters) from its first second.

The core downloads the three collections of Mozilla's bucket `security-state` (`_intermediates.py`, `_revocations.py`), has the engine import them ONCE in its generate
mode (`_security_state_generate.py`), keeps what the engine wrote, and every launch COPIES it into its profile. A launch writes NO pref of the security state, asks nobody
on a warm cache and starts no thread.

THE CACHE, `download.state_dir("security-state")`:

    <root>/<intermediates_ts>-<onecrl_ts>-<crlite_ts>/        one DATA version: the three collection timestamps
        intermediates.json  onecrl.json  crlite.json + the CRLite filter files the manifest names   (the inputs of the generate mode)
        manifest.json       {"format":1,"version":..,"updated_utc":"YYYY-MM-DDTHH:MM:SSZ","collections":{"intermediates":ts,"onecrl":ts,"cert-revocations":ts}}
        generated-<build_id>/                               one per engine build: `security_state/` + `securitystate-result.json`, as `generate` wrote them

A version is COMPLETE with `manifest.json` AND at least one `generated-*`. It is built in a staging directory beside the root, its generation for the current engine
INCLUDED, and renamed into the root in one step: a reader sees a whole version or none, and a download, a verification or a generation that fails deletes the staging
directory and leaves the cache exactly as it was. A `generated-<build_id>` for another engine is built the same way (a staging directory, one rename) and is immutable once in
place. The newest two versions are kept (a launch may be copying from the previous one); the newest is the highest tuple of the three timestamps. `updated_utc` is the clock
of the fetch that built the version, and it is what the ten-day rule reads.

THE TEN-DAY RULE (`_security_state_generate.is_stale`; cert_storage's own, security/manager/ssl/cert_storage/src/lib.rs:464-483: filters are fresh while `now < last_crlite_update
+ 10 days`, and `last_crlite_update` is the time of OUR generation, which cert_storage cannot be told otherwise). Data is STALE from exactly ten days after `updated_utc`.
  * The core NEVER generates from stale data: not for a new engine at a launch, not in `update_security_state` with nothing newer, nowhere (`_ensure_generated`). A generation made
    now from old data would look fresh, which a retail Firefox never does. Without a generation for this engine the launch starts as with no directory, and says to run
    `invisible-playwright fetch`. A version a fetch has just built has `updated_utc` = now, so it is fresh and is generated as ever.
  * A launch whose data is stale copies `security_state/` WITHOUT `crlite.filter` and the `*.delta` files (only `data.safe.bin`: intermediates and OneCRL) and says so. A ready
    directory the user gave has no age and is copied whole.

THE ROADS:
  * `update_security_state` is what `invisible-playwright fetch` calls, because the user asked: it reads the changes feed (one request, a few hundred bytes) EVERY time, and
    only when a collection is newer than the newest version does it download, and only that collection (an unchanged one is copied from the newest version, never linked;
    the CRLite files already held are not downloaded again). There is no schedule and no state file.
  * `ensure_security_state` / `place_security_state` is what a launch calls BEFORE the browser starts (`launch.write_user_js`, the one writer). A warm cache with a generation for
    the engine in use is answered with NO request, whatever its age (an old one is copied without the CRLite files); a FRESH version with no generation for this engine is
    generated from the cached data, in line, with no network (a stale one is not: see the rule); a cold cache downloads and generates once, in line. Any failure is one warning per process and the browser starts like a retail one with a new profile.
  * `STEALTHFOX_SECURITY_STATE` names a ready directory (`securitystate-result.json` and, when it has data, `security_state/`): it is copied as it is and nothing is asked,
    downloaded or generated.
"""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import sys
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, NamedTuple, Optional, Sequence, Tuple

from . import _cached_asset as _asset
from . import _intermediates as _im
from . import _revocations as _rv
from . import download, environment
from ._security_state_generate import (
    EngineId,
    GenerationError,
    Inputs,
    age_warning,
    default_argv,
    engine_id_of,
    generate,
    is_stale,
    place_in_profile,
)
from .constants import (
    CRLITE_COLLECTION_ID,
    CRLITE_FILE_NAME,
    INTERMEDIATES_COLLECTION_ID,
    INTERMEDIATES_FILE_NAME,
    ONECRL_COLLECTION_ID,
    ONECRL_FILE_NAME,
    SECURITY_STATE_BUCKET,
    SECURITY_STATE_DIR_NAME,
    SECURITY_STATE_LATEST_URL,
    SECURITY_STATE_RESULT_NAME,
)
from .seal import active_seal

__all__ = ["Ready", "SecurityStateError", "ensure_security_state", "place_security_state", "update_security_state"]

#: The directory of the cache, a name of `download.STATE_DIRS`.
ROOT_NAME = "security-state"
MANIFEST_NAME = "manifest.json"
GENERATED_PREFIX = "generated-"
#: The staging directories live BESIDE the root (`_cached_asset.new_staging`), with this prefix.
STAGING_PREFIX = ".tmp-security-state-"
#: How many data versions stay: the newest, and the one a launch may still be copying from.
KEEP_VERSIONS = 2
#: The three collections, in the order of the version's name.
COLLECTIONS = (INTERMEDIATES_COLLECTION_ID, ONECRL_COLLECTION_ID, CRLITE_COLLECTION_ID)

_VERSION = re.compile(r"(\d+)-(\d+)-(\d+)")
_BUILD_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")

#: The one cold generation in flight in this process: the callers of a cold or regenerating cache share it.
_SLOT = _asset.FlightSlot()
#: Each warning is printed once per process.
_WARNED = False
_AGE_WARNED = False


class SecurityStateError(RuntimeError):
    """The feed or the cache says something the core cannot use. The caller's cache stays as it was."""


class StaleSecurityState(SecurityStateError):
    """The cached data is stale (`is_stale`) and has no generation for this engine: it is not generated, because a generation made now would look fresh to cert_storage."""


@dataclass(frozen=True)
class Ready:
    """A generated security state ready to be copied: the `generated-<build_id>` directory and the `updated_utc` of its data (None for a ready directory the user gave)."""

    path: Path
    updated_utc: Optional[str]


class _Version(NamedTuple):
    stamps: Tuple[int, int, int]
    path: Path


@dataclass
class _Engine:
    """The engine a generation is tied to. `argv` is its launch line without the profile, None until a generation needs it: the sealed engine is only resolved (downloaded, if need be) then."""

    argv: Optional[List[str]]
    id: EngineId

    def resolved(self) -> Tuple[List[str], EngineId]:
        if self.argv is not None:
            return self.argv, self.id
        binary = download.ensure_binary()
        real = engine_id_of(binary)
        if real.build_id != self.id.build_id:
            raise GenerationError("the sealed engine's build id is %r, the engine at %s says %r" % (self.id.build_id, binary, real.build_id))
        self.argv, self.id = default_argv(binary), real
        return self.argv, real


def _engine_for(engine: "Optional[str | os.PathLike[str]]", engine_argv: Optional[Sequence[str]] = None) -> Tuple[Optional[List[str]], EngineId]:
    """THE SEAM to the engine: `(argv, id)`, the launch line without the profile and the identity a generation is tied to.
    `engine_argv` given -> that line as it is (the core appends `-profile <work profile>` and nothing else), the identity read (`application.ini`) from `engine` when given, else
    from `engine_argv[0]`. Only `engine` given -> its identity and `default_argv(engine)`. Neither -> the sealed engine: its build id is the seal's for this platform (no file is
    read, no download made) and the argv is None until a generation needs the binary (`default_argv`). A test replaces this function."""
    if engine_argv is not None:
        argv = [str(a) for a in engine_argv]
        if not argv:
            raise GenerationError("the engine's launch line is empty")
        return argv, engine_id_of(engine if engine is not None else argv[0])
    if engine is not None:
        return default_argv(engine), engine_id_of(engine)
    seal = active_seal()
    asset = seal.asset_for(sys.platform, platform.machine())
    if not asset.build_id:
        raise GenerationError("the seal names no build id for this platform")
    return None, EngineId(version=seal.upstream_version, build_id=asset.build_id)


def _the_engine(engine, engine_argv: Optional[Sequence[str]] = None) -> _Engine:
    argv, eid = _engine_for(engine, engine_argv)
    return _Engine(argv, eid)


def _generated_name(eid: EngineId) -> str:
    if _BUILD_ID.fullmatch(eid.build_id or "") is None:
        raise GenerationError("the engine's build id is not a plain name: %r" % (eid.build_id,))
    return GENERATED_PREFIX + eid.build_id


def _warn_once(message: str) -> None:
    global _WARNED
    if _WARNED:
        return
    _WARNED = True
    print("invisible_core: " + message, file=sys.stderr, flush=True)


def _now() -> datetime:
    """THE ONE READ OF THE CLOCK of this module, for the public entry points called with no `now`; everything below them is given the moment as data. A test replaces it."""
    return datetime.now(timezone.utc)


def _utc(now: datetime) -> str:
    moment = now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _root() -> Path:
    return download.state_dir(ROOT_NAME)


# --- the cache -----------------------------------------------------------------------------------------------------------------------------------------

def _version_name(stamps: Sequence[int]) -> str:
    return "-".join(str(n) for n in stamps)


def _read_manifest(directory: Path) -> Optional[dict]:
    """The manifest of a version directory, or None when it is not one that says what its name says."""
    m = _VERSION.fullmatch(directory.name)
    if m is None:
        return None
    try:
        data = json.loads((directory / MANIFEST_NAME).read_bytes().decode("utf-8"))
    except (OSError, ValueError):
        return None
    stamps = tuple(int(g) for g in m.groups())
    collections = data.get("collections") if isinstance(data, dict) else None
    if (not isinstance(data, dict) or data.get("format") != 1 or data.get("version") != directory.name
            or not isinstance(collections, dict) or tuple(collections.get(c) for c in COLLECTIONS) != stamps):
        return None
    return data


def _generated_ok(directory: Path) -> bool:
    return directory.is_dir() and (directory / SECURITY_STATE_RESULT_NAME).is_file()


def _is_complete(directory: Path) -> bool:
    """A version is whole with its manifest and at least one generation."""
    if _read_manifest(directory) is None:
        return False
    return any(_generated_ok(g) for g in directory.glob(GENERATED_PREFIX + "*"))


def _versions(root: Path) -> List[_Version]:
    """The complete versions of the cache, the oldest first (the order is the tuple of the three timestamps)."""
    found: List[_Version] = []
    if not root.is_dir():
        return found
    for d in root.iterdir():
        m = _VERSION.fullmatch(d.name)
        if m is not None and d.is_dir() and _is_complete(d):
            found.append(_Version(tuple(int(g) for g in m.groups()), d))
    return sorted(found, key=lambda v: v.stamps)


def _newest(root: Path) -> Optional[_Version]:
    versions = _versions(root)
    return versions[-1] if versions else None


def _lookup(root: Path, eng: _Engine) -> Optional[Ready]:
    """What a launch finds on a warm cache: the newest version's generation for this engine. No request, no file but the directory's own."""
    newest = _newest(root)
    if newest is None:
        return None
    generated = newest.path / _generated_name(eng.id)
    if not _generated_ok(generated):
        return None
    manifest = _read_manifest(newest.path) or {}
    return Ready(generated, manifest.get("updated_utc"))


def _prune(root: Path) -> None:
    for old in _versions(root)[:-KEEP_VERSIONS]:
        shutil.rmtree(old.path, ignore_errors=True)


# --- the feed -------------------------------------------------------------------------------------------------------------------------------------------

def _latest(attempts: int) -> Dict[str, int]:
    """The timestamps of the three collections, from the changes feed (one request). A collection the feed does not list is an error: the version would be a guess."""
    feed = _im._get_json(SECURITY_STATE_LATEST_URL, attempts)
    found: Dict[str, int] = {}
    for entry in feed.get("changes", []) if isinstance(feed, dict) else []:
        if not isinstance(entry, dict) or entry.get("bucket") != SECURITY_STATE_BUCKET or entry.get("collection") not in COLLECTIONS:
            continue
        stamp = entry.get("last_modified")
        if isinstance(stamp, int) and not isinstance(stamp, bool) and stamp > 0:
            found[entry["collection"]] = stamp
    missing = [c for c in COLLECTIONS if c not in found]
    if missing:
        raise SecurityStateError("the changes feed does not list the collection(s) %s" % ", ".join(missing))
    return found


# --- building a version ---------------------------------------------------------------------------------------------------------------------------------

def _stamp_of(path: Path) -> int:
    value = json.loads(path.read_bytes().decode("utf-8")).get("collection_timestamp")
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise SecurityStateError("%s has no collection_timestamp" % path.name)
    return value


def _held_filters(previous: Optional[_Version]) -> Dict[str, Path]:
    """sha256 -> file, for the CRLite filters the newest version already holds: what `fetch_crlite` is allowed to copy instead of downloading."""
    held: Dict[str, Path] = {}
    if previous is None:
        return held
    try:
        manifest = json.loads((previous.path / CRLITE_FILE_NAME).read_bytes().decode("utf-8"))
        for part in [manifest.get("full")] + list(manifest.get("deltas") or []):
            held[part["sha256"].lower()] = previous.path / part["file"]
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return {}
    return held


def _copy_crlite(previous: _Version, staging: Path) -> None:
    """An unchanged `cert-revocations` is COPIED from the newest version: the manifest and every file it names, each checked again against the manifest."""
    manifest = json.loads((previous.path / CRLITE_FILE_NAME).read_bytes().decode("utf-8"))
    for part in [manifest["full"]] + list(manifest.get("deltas") or []):
        raw = (previous.path / part["file"]).read_bytes()
        if len(raw) != part["size"] or hashlib.sha256(raw).hexdigest() != part["sha256"]:
            raise SecurityStateError("the cached CRLite file %s is not what the manifest says" % part["file"])
        (staging / part["file"]).write_bytes(raw)
    shutil.copyfile(previous.path / CRLITE_FILE_NAME, staging / CRLITE_FILE_NAME)


def _inputs_in(directory: Path) -> Inputs:
    return Inputs(directory / INTERMEDIATES_FILE_NAME, directory / ONECRL_FILE_NAME, directory / CRLITE_FILE_NAME)


def _generate_into(out_dir: Path, data_dir: Path, eng: _Engine) -> None:
    argv, eid = eng.resolved()
    generate(argv, _inputs_in(data_dir), eid, out_dir)


def _ensure_generated(version: Path, eng: _Engine, now: datetime) -> Path:
    """The `generated-<build_id>` of a version for this engine, made from the version's own files when it is not there (no network). It is built in a staging directory and
    renamed in: immutable once in place. STALE data (`is_stale` at `now`; the manifest's `updated_utc`) is never generated from: `StaleSecurityState`, nothing written."""
    destination = version / _generated_name(eng.id)
    if _generated_ok(destination):
        return destination
    updated = (_read_manifest(version) or {}).get("updated_utc")
    if is_stale(updated, now):
        raise StaleSecurityState("the cached data (updated_utc=%r) is stale, ten days old or more, and has no generation for this engine; a generation made now would look "
                                 "fresh to cert_storage, so none is made" % (updated,))
    staging = _asset.new_staging(_root(), STAGING_PREFIX)
    try:
        _generate_into(staging, version, eng)
        _asset.put_in_place(staging, destination, _generated_ok)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    if not _generated_ok(destination):
        raise SecurityStateError("the generation is not in %s after it was put in place" % destination)
    return destination


def _build_version(root: Path, previous: Optional[_Version], feed: Dict[str, int], now: datetime, eng: _Engine, attempts: int) -> Path:
    """Download what is newer than `previous`, copy what is not, verify, generate for `eng`, and put the version in place; the version's directory. Raises on anything that
    does not add up, with the cache as it was and the staging directory gone."""
    utc = _utc(now)
    staging = _asset.new_staging(root, STAGING_PREFIX)
    try:
        def unchanged(collection: str) -> bool:
            return previous is not None and feed[collection] <= previous.stamps[COLLECTIONS.index(collection)]

        if unchanged(INTERMEDIATES_COLLECTION_ID):
            shutil.copyfile(previous.path / INTERMEDIATES_FILE_NAME, staging / INTERMEDIATES_FILE_NAME)
        else:
            _im.fetch_intermediates(staging, feed[INTERMEDIATES_COLLECTION_ID], attempts)
        if unchanged(ONECRL_COLLECTION_ID):
            shutil.copyfile(previous.path / ONECRL_FILE_NAME, staging / ONECRL_FILE_NAME)
        else:
            changeset = _rv.fetch_changeset(ONECRL_COLLECTION_ID, feed[ONECRL_COLLECTION_ID], attempts)
            _rv.write_onecrl(staging, _rv.build_onecrl(changeset, updated_utc=utc))
        if unchanged(CRLITE_COLLECTION_ID):
            _copy_crlite(previous, staging)
        else:
            changeset = _rv.fetch_changeset(CRLITE_COLLECTION_ID, feed[CRLITE_COLLECTION_ID], attempts)
            base = _im._attachments_base(attempts)
            _rv.fetch_crlite(staging, changeset, base, reuse=_held_filters(previous).get, attempts=attempts, updated_utc=utc)

        stamps = tuple(_stamp_of(staging / name) for name in (INTERMEDIATES_FILE_NAME, ONECRL_FILE_NAME, CRLITE_FILE_NAME))
        name = _version_name(stamps)
        destination = root / name
        if _is_complete(destination):
            # The data is a version the cache already holds (the feed was ahead of the collection's own timestamp): nothing new, only perhaps this engine's generation.
            _ensure_generated(destination, eng, now)
            return destination
        _generate_into(staging / _generated_name(eng.id), staging, eng)
        collections = dict(zip(COLLECTIONS, stamps))
        (staging / MANIFEST_NAME).write_bytes(_im._compact({"format": 1, "version": name, "updated_utc": utc, "collections": collections}))
        _asset.put_in_place(staging, destination, _is_complete)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    if not _is_complete(destination):
        raise SecurityStateError("the security state is not in %s after it was put in place" % destination)
    _prune(root)
    return destination


# --- the user's `fetch` ---------------------------------------------------------------------------------------------------------------------------------

def update_security_state(*, engine: "Optional[str | os.PathLike[str]]" = None, engine_argv: Optional[Sequence[str]] = None,
                          now: Optional[datetime] = None) -> Tuple[Optional[Path], bool]:
    """Ask whether the bucket has anything newer than the cache's newest version and, if so, download it, verify it, generate it for the engine and put the version in place.
    `(path, changed)`: the ready `generated-<build_id>` directory (None when there is none) and whether this call put a new DATA version in the cache.

    `engine_argv` is the caller's launch line of the engine without the profile (the core appends `-profile <work profile>`); None is `default_argv` of `engine` or of the sealed
    engine. The identity a generation is tied to is read from `engine` when given, else from `engine_argv[0]`.

    Called by `invisible-playwright fetch`, so it asks the changes feed EVERY time and downloads only what is newer; with nothing newer it only generates for the engine when
    the newest version has no generation for it (no network). One process of the machine at a time. `STEALTHFOX_SECURITY_STATE` set -> nothing is asked: `(that directory,
    False)`. `now` is the clock of the fetch (what the version's `updated_utc` says); None is the real clock, and only here. Never raises: no network, or anything that does
    not add up, leaves the cache as it was, says so in one line on stderr and returns what is ready."""
    override = os.environ.get(environment.SECURITY_STATE)
    if override:
        return Path(override), False
    root = _root()
    eng: Optional[_Engine] = None
    try:
        eng = _the_engine(engine, engine_argv)
        moment = _now() if now is None else now
        with _asset.machine_lock(root, _asset.LOCK_WAIT_S):
            feed = _latest(download.DOWNLOAD_ATTEMPTS)
            newest = _newest(root)
            if newest is not None and all(feed[c] <= newest.stamps[i] for i, c in enumerate(COLLECTIONS)):
                return _ensure_generated(newest.path, eng, moment), False
            built = _build_version(root, newest, feed, moment, eng, download.DOWNLOAD_ATTEMPTS)
            return built / _generated_name(eng.id), built != getattr(newest, "path", None)
    except Exception as exc:
        kept = None
        try:
            ready = _lookup(root, eng) if eng is not None else None
            kept = ready.path if ready is not None else None
        except Exception:
            kept = None
        print("invisible_core: could not update the security state (%s); %s" % (
            exc, "the one in the cache stays" if kept is not None else "there is none in the cache for this engine, and the browser starts without it"),
            file=sys.stderr, flush=True)
        return kept, False


# --- the launch -----------------------------------------------------------------------------------------------------------------------------------------

def _override_ready(override: str) -> Ready:
    p = Path(override)
    if not (p / SECURITY_STATE_RESULT_NAME).is_file():
        raise RuntimeError(f"{environment.SECURITY_STATE} points to a directory with no {SECURITY_STATE_RESULT_NAME}: {p}")
    return Ready(p, None)


def _make_ready(root: Path, eng: _Engine, now: datetime) -> Ready:
    """The generation for this engine, made in line, one process of the machine at a time. Whoever gets the lock after another finished uses what that one left."""
    with _asset.machine_lock(root, _asset.LOCK_WAIT_S):
        have = _lookup(root, eng)
        if have is not None:
            return have
        newest = _newest(root)
        if newest is None:
            _build_version(root, None, _latest(download.DOWNLOAD_ATTEMPTS), now, eng, download.DOWNLOAD_ATTEMPTS)
        else:
            _ensure_generated(newest.path, eng, now)
        made = _lookup(root, eng)
    if made is None:
        raise SecurityStateError("no generation for the engine is in the cache after it was made")
    return made


def _ensure(engine, engine_argv, now: datetime) -> Optional[Ready]:
    override = os.environ.get(environment.SECURITY_STATE)
    if override:
        return _override_ready(override)
    try:
        eng = _the_engine(engine, engine_argv)
        root = _root()
        return _asset.ensure_once(
            _SLOT,
            cached=lambda: _lookup(root, eng),
            check_due=lambda: False,   # a generation for this engine is the answer: with one there is nothing to ask
            mark_checked=lambda: None,
            fetch=lambda: _make_ready(root, eng, now),
        )
    except StaleSecurityState as exc:
        _warn_once("the security state (intermediates, OneCRL, CRLite) could not be made (%s); the browser starts like a retail one with a new profile. "
                   "Run `invisible-playwright fetch` to download newer data." % (exc,))
        return None
    except Exception as exc:
        _warn_once("the security state (intermediates, OneCRL, CRLite) could not be made (%s); the browser starts like a retail one with a new profile. "
                   "Connect once to download it, or set %s to a ready directory." % (exc, environment.SECURITY_STATE))
        return None


def ensure_security_state(*, engine: "Optional[str | os.PathLike[str]]" = None, engine_argv: Optional[Sequence[str]] = None,
                          now: Optional[datetime] = None) -> Optional[Ready]:
    """The ready security state of this engine, or None. `engine_argv` is the caller's launch line without the profile (see `update_security_state`). `now` is the moment the ten-day rule is judged at; None is the real clock, and only here.

    Resolution order:
      1. ``STEALTHFOX_SECURITY_STATE`` -> that directory (user-supplied / CI), as `Ready(dir, None)`; one that does not hold `securitystate-result.json` is an error.
      2. The newest version in the cache has a generation for this engine -> it, with NO request, however old it is: newer data is looked for only by `update_security_state`.
      3. A FRESH version with no generation for this engine (the engine changed) -> generated in line from the cached data, with no network. A STALE one (`is_stale`) is
         never generated from: a warning that says to run `invisible-playwright fetch`, and None.
      4. A cold cache -> downloaded and generated once, in line (the callers of one process share it, other processes wait for the machine lock and read what it left).
      5. Anything that fails -> a warning on stderr once per process, and None."""
    return _ensure(engine, engine_argv, _now() if now is None else now)


def _age_warn_once(ready: Ready, now: datetime) -> None:
    global _AGE_WARNED
    if ready.updated_utc is None or _AGE_WARNED:
        return
    text = age_warning(ready.updated_utc, now)
    if text is None:
        return
    _AGE_WARNED = True
    print(text, file=sys.stderr, flush=True)


def place_security_state(profile_dir: "str | os.PathLike[str]", *, engine: "Optional[str | os.PathLike[str]]" = None, engine_argv: Optional[Sequence[str]] = None,
                         now: Optional[datetime] = None) -> bool:
    """What a launch calls: puts a COPY of the ready `security_state/` in `profile_dir`; True when something was copied.

    `engine_argv` is the caller's launch line of the engine without the profile (None: the invisible launch).

    `ensure_security_state` (looked up in this module's globals, so a test that stubs it stubs the launch) and `place_in_profile` (a copy, never a link: the engine rewrites the
    files in place). When the data is STALE (`is_stale` at `now`: ten days or more, or an `updated_utc` nobody can read) the copy leaves out `crlite.filter` and the `*.delta` files
    and the warning of `age_warning` is printed once per process: a retail Firefox does not use filters that old. A ready directory the user gave has no age: copied whole, no
    warning. With nothing ready, or nothing to copy (a ready directory with no data), the profile is not touched. A copy that fails is removed whole and said once: half a
    `cert_storage` is worse than none. `now` is the clock of the decision; None is the real clock, and only here."""
    moment = _now() if now is None else now
    ready = ensure_security_state(engine=engine, engine_argv=engine_argv, now=moment)
    if ready is None:
        return False
    stale = ready.updated_utc is not None and is_stale(ready.updated_utc, moment)
    try:
        copied = place_in_profile(ready.path, Path(profile_dir), without_crlite=stale)
    except Exception as exc:
        shutil.rmtree(Path(profile_dir) / SECURITY_STATE_DIR_NAME, ignore_errors=True)
        _warn_once("the security state could not be copied into the profile (%s); the browser starts like a retail one with a new profile" % (exc,))
        return False
    _age_warn_once(ready, moment)
    return copied
