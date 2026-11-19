"""`close()` waits for the browser's real exit, and a browser that is exiting is never ended.

Measured on the hosted runners (GitHub hunts, 4 browsers closing together on Windows): `Connection.close(timeout=5.0)` ended the
engine at 5.0 s while it was still exiting in 26 closes of 64. With the deadlines raised to 60 s every one of them exited by itself,
with code 0 (p50 5.83 s, max 6.85 s; retail Firefox on the same runner 3.66 s, up to 9 s on other runs). The close is a pipe closed
and a shutdown that takes what it takes: the deadline is not a measure of it.

Now:

* `Connection.close()` returns when the browser has exited, however long that takes, and never ends it while it is alive. Its limit
  is `process.BROWSER_EXIT_LIMIT`, after the moment Firefox brings down a shutdown that does not finish
  (`toolkit.asyncshutdown.crash_timeout` 60 s + `crash_timeout_additional_wait` 10 s): the net for a browser that is stuck. It is
  the limit of the wait for the exit only: a browser that was ended is not exiting, and the launch's `Reaper` keeps its own 5 s;
* a caller that passes its own `timeout` keeps it.

No test here waits for a real time (a machine under load would turn it red with no defect). The browser is a stand-in process
object that exits only when the clock the close reads says it is time: the close reads `time` through its module, and the test
gives it a virtual clock that advances by what the close sleeps, so a close that waits 5.8 s costs a few milliseconds and what is
claimed is a fact of the order of events (the stand-in was ended while it was alive, or it was not), never of the machine.
"""
from __future__ import annotations

import inspect
import os
import threading
import time

import pytest

from invisible_core import process as P
from invisible_core.juggler import connection as C

NUL = b"\x00"

#: When the stand-in exits by itself (virtual seconds after the pipe closed): later than the 5.0 s the old close waited, which is
#: where the hosted runners' browsers were (5.8 s at the median), and well below the limit.
EXITS_AT = 6.0

#: A safety net for the threads of a test, never a measure.
NET = 60


class _VirtualTime:
    """What the close sees as `time`: a monotonic that moves by what is slept, so no test waits for a real second."""

    def __init__(self) -> None:
        self.now = 0.0
        self._lock = threading.Lock()

    def monotonic(self) -> float:
        with self._lock:
            return self.now

    def sleep(self, seconds: float) -> None:
        with self._lock:
            self.now += seconds
        time.sleep(0)             # let the other threads of the test run

    def __getattr__(self, name):
        return getattr(time, name)


class _Browser:
    """The stand-in for the engine's process. Alive until `exits_at` (virtual seconds), or until something ends it. Records every
    end, with the virtual time and whether it was alive: `ended_while_alive` is the defect."""

    def __init__(self, clock: _VirtualTime, exits_at) -> None:
        self.clock = clock
        self.exits_at = exits_at
        self.ended: list = []
        self._dead = False
        self.pid = 1
        self.tree = None

    def poll(self):
        if self._dead:
            return 0
        if self.exits_at is not None and self.clock.monotonic() >= self.exits_at:
            self._dead = True
            return 0
        return None

    def terminate(self) -> None:
        self.ended.append((self.clock.monotonic(), self.poll() is None))
        self._dead = True

    kill = terminate


class _Tree:
    """The launch's tree as the close and the reaper see it: it records how the reaper ends it (`grace`, `timeout`)."""

    def __init__(self) -> None:
        self.ends: list = []

    def remember(self) -> None:
        pass

    def wait_browser_gone(self, deadline: float) -> bool:
        return True

    def end(self, *, grace: float = 0.0, timeout: float = 5.0) -> int:
        self.ends.append((grace, timeout))
        return 0

    def release(self) -> None:
        pass


class _Peer:
    """The engine's side of the Juggler pipe: answers what it is sent and closes its ends when ours closes."""

    def __init__(self, process) -> None:
        to_r, to_w = os.pipe()
        from_r, from_w = os.pipe()
        self.connection = C.Connection(to_w, from_r, process)
        self._ends = (to_r, from_w)
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self) -> None:
        to_r, from_w = self._ends
        try:
            while os.read(to_r, 65536):
                pass
        finally:
            os.close(to_r)
            os.close(from_w)


@pytest.fixture
def clock(monkeypatch):
    virtual = _VirtualTime()
    monkeypatch.setattr(C, "time", virtual)
    return virtual


def _close(connection, *args, **kwargs):
    done = threading.Event()
    result: list = []

    def run() -> None:
        try:
            connection.close(*args, **kwargs)
        except BaseException as exc:             # pragma: no cover - reported by the assertion below
            result.append(exc)
        done.set()

    threading.Thread(target=run, daemon=True).start()
    assert done.wait(NET), "the close did not return"
    assert not result, result
    reaper = connection.reaper
    if reaper is not None:
        reaper.join(NET)


def test_the_limit_is_after_the_moment_firefox_crashes_its_own_stuck_shutdown():
    """The net is a constant with its reason: Firefox's AsyncShutdown crashes a stuck shutdown at
    `toolkit.asyncshutdown.crash_timeout` (60 s) plus `toolkit.asyncshutdown.crash_timeout_additional_wait` (10 s), so 70 s is the
    moment it brings itself down. A limit on that boundary or below it ends a browser that Firefox is still allowing to finish."""
    assert P.BROWSER_EXIT_LIMIT > 60.0 + 10.0


def test_a_browser_that_is_exiting_is_not_ended(clock):
    """The browser exits by itself 6 s after its pipe closed (the hosted runners' median is 5.8 s). The close waits for it and ends
    nothing. On the old code it was ended at 5.0 s, while it was alive."""
    process = _Browser(clock, EXITS_AT)
    peer = _Peer(process)
    _close(peer.connection)
    assert not process.ended, "terminated while exiting: it was ended at %.2f s, alive, and it would have exited at %.1f s" % (
        process.ended[0][0], EXITS_AT)
    assert process.poll() == 0
    assert clock.monotonic() >= EXITS_AT, "the close returned before the browser had exited"


def test_a_browser_that_is_stuck_is_ended_at_the_limit(clock, monkeypatch):
    """Beyond the net the browser is stuck, not exiting: it is ended, once, and not before the net."""
    monkeypatch.setattr(P, "BROWSER_EXIT_LIMIT", 20.0)
    process = _Browser(clock, None)
    peer = _Peer(process)
    _close(peer.connection)
    assert len(process.ended) == 1, process.ended
    when, alive = process.ended[0]
    assert alive
    assert when >= 20.0, "ended at %.2f s, before the net" % when


def test_with_the_net_at_zero_the_last_resort_is_taken_at_once(clock, monkeypatch):
    """The last-resort branch exists and is reached without waiting: the test brings the net to zero."""
    monkeypatch.setattr(P, "BROWSER_EXIT_LIMIT", 0.0)
    process = _Browser(clock, EXITS_AT)
    peer = _Peer(process)
    _close(peer.connection)
    assert len(process.ended) == 1, process.ended
    assert process.ended[0][1], "it was not alive when it was ended"


def test_the_reaper_of_a_browser_that_was_ended_does_not_wait_beyond_its_own_default(clock, monkeypatch):
    """The limit is for the wait for the EXIT, inside `close`. A browser that was ended is not exiting: what the reaper gives it to
    leave before it is killed is the reaper's own default, never the limit. The limit is a sentinel here, so a reaper that was
    built with it shows."""
    monkeypatch.setattr(P, "BROWSER_EXIT_LIMIT", 7.5)
    process = _Browser(clock, None)
    process.tree = _Tree()
    peer = _Peer(process)
    _close(peer.connection)
    assert process.ended and process.ended[0][0] >= 7.5, process.ended
    default = inspect.signature(P.Reaper).parameters["timeout"].default
    assert process.tree.ends == [(0.0, default)], (
        "the reaper waits %r (grace, timeout) after the termination, its default is %r: a browser that was ended is not exiting, "
        "the limit is not its wait" % (process.tree.ends, default))


def test_the_reaper_of_a_browser_that_exited_keeps_its_leftover_deadline(clock):
    """What stays after a browser that DID exit is the leftovers', whose deadlines are their own (`SENDER_GRACE`, the 5 s of
    `EngineTree.end`)."""
    process = _Browser(clock, EXITS_AT)
    peer = _Peer(process)
    _close(peer.connection)
    reaper = peer.connection.reaper
    assert reaper is not None
    assert reaper.timeout == 5.0
    assert reaper.grace > 0


def test_a_timeout_given_by_the_caller_is_kept(clock):
    """A caller that passes its own `timeout` has it: a browser that has not exited by then is ended at that time."""
    process = _Browser(clock, None)
    peer = _Peer(process)
    _close(peer.connection, timeout=2.0)
    assert len(process.ended) == 1, process.ended
    when, alive = process.ended[0]
    assert alive and 2.0 <= when < P.BROWSER_EXIT_LIMIT, process.ended


def test_the_default_of_close_and_aclose_is_the_limit_not_a_number():
    """`timeout=None` means the limit, read when the close runs: no second copy of the number in a signature."""
    assert C.Connection.close.__defaults__ == (None,)
    assert C.Connection.aclose.__defaults__ == (None,)


def test_an_engine_that_never_answered_is_not_waited_for_as_one_that_exits():
    """The launch-failure path of an engine that did not answer its first command keeps a short, named deadline: it never finished
    starting, so it is not exiting. The engines that answered (a refusal) and the ones whose launch failed after they were ready
    leave by their pipe and are waited for."""
    assert C.STARTUP_CLOSE_WAIT < P.BROWSER_EXIT_LIMIT
