"""The mechanics of a downloaded asset the core keeps in the machine's cache: GeoIP's database and Mozilla's intermediates list.

SPLIT OUT OF `_geoip_db.py`. That file held, next to the GeoIP specifics (which release is the latest, what the archive holds), everything that is true of ANY
asset fetched once and kept: a root in the state directory with one directory per version, the newest one wins, a `.last-check.json` that says when the source was
last asked, a process that asks at most once, one process of the machine at a time on the download, a version that appears complete or not at all, and the old
ones pruned. A second asset (`_intermediates.py`) needed the same, so it is here once; each user keeps only what is its own.

Nothing here knows an asset's name, its source or its format. What differs is passed in as a callable or a value, and the users pass THEIR module's globals
through small wrappers, so a test that patches a name of the user's module still reaches the code that reads it.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Optional

#: Where the time of the last good check is kept: a file of the asset's root, not inside a version directory (nothing that lists the versions sees it).
CHECK_STATE_NAME = ".last-check.json"

#: The file that serialises the check and the download across the processes of the machine: in the asset's root, beside the state file, where the glob of the
#: versions and the prune (directories only) do not see it. An OS lock, so a process that dies releases it and nothing is left that blocks.
LOCK_NAME = ".download.lock"

#: The longest a process waits for another one to finish the check or the download. Past it the process goes on without the lock: a downloader that hangs
#: must not hang every launch behind it, and the worst case of going on is the download this lock exists to avoid, never a wrong asset.
LOCK_WAIT_S = 300.0


class Flight:
    """What the callers of one process wait for: the result of the check or download the first of them runs, or the error it ended with."""

    def __init__(self):
        self.done = threading.Event()
        self.result = None
        self.error = None

    def wait(self):
        self.done.wait()
        if self.error is not None:
            raise self.error
        return self.result


class FlightSlot:
    """The one check/download in flight in this process for one asset, or None. `lock` guards `current`."""

    def __init__(self):
        self.lock = threading.Lock()
        self.current: Optional[Flight] = None


def ensure_once(slot: FlightSlot, *, cached: Callable, check_due: Callable, mark_checked: Callable, fetch: Callable):
    """The newest cached copy, or the one flight of this process that fetches it.

    A copy is cached and no check is due -> it is returned and nothing is asked. A flight is in progress and there is a copy to use meanwhile -> nobody waits
    for it. A cold cache -> the callers share the one fetch, and its error (which is not kept: the flight ends and the next call starts its own).
    `mark_checked` is called by the one that starts a flight, before it starts: a process asks at most once, good or not.
    """
    with slot.lock:
        have = cached()
        if slot.current is not None:
            if have:
                return have
            flight, leader = slot.current, False
        else:
            if have and not check_due():
                return have
            mark_checked()
            flight = slot.current = Flight()
            leader = True
    if not leader:
        return flight.wait()
    try:
        flight.result = fetch()
        return flight.result
    except BaseException as exc:
        flight.error = exc
        raise
    finally:
        with slot.lock:
            slot.current = None
        flight.done.set()


def check_and_fetch(lock, *, cached: Callable, state_due: Callable, fetch_locked: Callable):
    """The check and the download, one process of the machine at a time: whoever got the lock after another one finished re-reads what that one left (the
    copy, the time of its check) before deciding that anything is to be asked or fetched. `lock` is the context manager of `machine_lock`."""
    with lock:
        have = cached()
        if have and not state_due():
            return have  # another process checked (and fetched) while this one waited
        return fetch_locked(have)


def check_state_path(root: Path) -> Path:
    return root / CHECK_STATE_NAME


def state_is_due(root: Path, interval_s: float) -> bool:
    """The state file alone: the last good check of ANY process of the machine is older than the interval (or unreadable, or from the future)."""
    try:
        stamp = json.loads(check_state_path(root).read_text(encoding="utf-8"))["checked_at"]
        if isinstance(stamp, bool):
            return True  # JSON true is not a time
        checked_at = float(stamp)  # an integer too large for a float raises OverflowError
    except (OSError, ValueError, KeyError, TypeError, OverflowError, RecursionError):
        return True
    age = time.time() - checked_at
    return not (0 <= age < interval_s)


def record_check(root: Path) -> None:
    """The time of a check that reached the source. Best effort: a root that cannot be written only means the next process asks again."""
    path = check_state_path(root)
    tmp = path.with_name(path.name + ".%d.tmp" % os.getpid())
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps({"checked_at": time.time()}), encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass


@contextmanager
def machine_lock(root: Path, wait_s: float):
    """Held while the source is asked and the asset downloaded: one process at a time, the others wait and then read what it left. Best effort by design - a
    root that cannot be written, or a holder that does not let go within `wait_s`, means going on without it, not failing the launch."""
    handle = None
    try:
        root.mkdir(parents=True, exist_ok=True)
        handle = open(root / LOCK_NAME, "a+b")
    except OSError:
        handle = None
    locked = False
    if handle is not None:
        deadline = time.monotonic() + wait_s
        while True:
            try:
                if os.name == "nt":
                    import msvcrt
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except OSError:
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.05)
    try:
        yield
    finally:
        if handle is not None:
            try:
                if locked:
                    if os.name == "nt":
                        import msvcrt
                        handle.seek(0)
                        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            finally:
                handle.close()


def newest_file(root: Path, pattern: str, key: Callable = None) -> Optional[Path]:
    """The newest file matching `pattern` under `root` (one version per directory), or None. The default order is the path's (a lexical sort, chronological
    for dates written year first); `key` orders by something else (a number a name does not sort as)."""
    if not root.exists():
        return None
    cands = sorted(root.glob(pattern), key=key)
    return cands[-1] if cands else None


def new_staging(root: Path, prefix: str) -> Path:
    """A directory to build a version in: BESIDE the root, on the same filesystem so the rename into it is atomic, and outside it so nothing that lists the
    versions can see it."""
    root.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=prefix, dir=root.parent))


def put_in_place(staging: Path, dst: Path, complete: Callable[[Path], bool]) -> None:
    """Rename `staging` to `dst` in one step: a version directory appears complete or not at all. `complete(dir)` says whether a directory holds a whole
    version; one that does not (left by the code before this) is removed, and a process that loses the rename uses the winner's copy."""
    if dst.exists() and not complete(dst):
        shutil.rmtree(dst, ignore_errors=True)
    try:
        os.replace(staging, dst)
    except OSError:
        if not complete(dst):
            raise
        # Another process landed the same version first; its copy is complete.


def prune_dirs(root: Path, keep: str) -> None:
    """Drop every version directory of `root` except `keep`, to bound disk usage."""
    if not root.exists():
        return
    for d in root.iterdir():
        if d.is_dir() and d.name != keep:
            shutil.rmtree(d, ignore_errors=True)
