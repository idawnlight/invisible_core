"""A step handed to the reaper never runs on the thread that hands it over.

Found in a hunt on Windows (4 browsers of one process closed together): `Reaper.then(step)` called after the reaper had finished ran
the step "at once by the caller". The step was the removal of the session's profile (`SessionFiles.remove`), 0.4 to 2.5 s with four
profile directories deleted together, and the caller was the wrapper's `juggler-shutdown` thread, which the user's `__aexit__`
waits for: 12 of 24 closes returned more than 0.5 s after the browser had exited (closed one after another: 0 of 24).

Now a step handed to a reaper that has finished goes to a continuation of it: a thread that is not a daemon, covered by `join()`,
`finished`, `wait_reaped` and the end of the interpreter. The caller runs it only where no thread can be made.

No test here waits for a time or measures one. Every step is held on an Event the test releases, and what is claimed is a fact of
the order of events (the caller has returned while the step is held; the reaper is not finished while it is held), never a duration.
"""
from __future__ import annotations

import subprocess
import sys
import textwrap
import threading
import types

import pytest

from invisible_core import process as P
from invisible_core.juggler.instance import Browser

#: A safety net for the waits of a test (a step that never runs would hang it), never a measure.
NET = 60


def _finished_reaper() -> P.Reaper:
    reaper = P.Reaper(None)
    reaper.start()
    reaper.join(NET)
    assert reaper.finished
    return reaper


class _Step:
    """A step that says which thread ran it, and ends only when the test releases it."""

    def __init__(self, hold: bool = True, name: str = "", log=None) -> None:
        self.name = name
        self.log = log
        self.started = threading.Event()
        self.release = threading.Event()
        self.done = threading.Event()
        self.thread = None
        self._hold = hold

    def __call__(self) -> None:
        self.thread = threading.current_thread()
        self.started.set()
        if self._hold:
            assert self.release.wait(NET)
        if self.log is not None:
            self.log.append(self.name)
        self.done.set()


def _hand_over(reaper: P.Reaper, step: _Step) -> threading.Event:
    """Hands `step` over from a thread of the test (the caller) and returns an Event set when `then` has returned. It waits
    for the step to start and fails at once if the caller is the thread running it: on the old code `then` does not return
    while the step is held, and a test that handed it over from its own thread would hang instead of failing."""
    returned = threading.Event()

    def hand() -> None:
        reaper.then(step)
        returned.set()

    caller = threading.Thread(target=hand, name="the-caller", daemon=True)
    caller.start()
    assert step.started.wait(NET), "the step never started"
    assert step.thread is not caller, "the step ran on the thread that handed it over, which cannot return while it is held"
    return returned


@pytest.fixture
def held():
    steps = []
    yield steps
    for step in steps:                  # a failed assertion must not leave a thread of the test waiting
        step.release.set()


def test_a_step_handed_to_a_finished_reaper_does_not_run_on_the_caller(held):
    reaper = _finished_reaper()
    step = _Step(hold=False)
    held.append(step)
    reaper.then(step)
    assert step.done.wait(NET), "the step never ran"
    assert step.thread is not threading.current_thread(), "the step ran on the thread that handed it over"
    reaper.join(NET)


def test_then_returns_while_the_step_is_held(held):
    reaper = _finished_reaper()
    step = _Step()
    held.append(step)
    returned = _hand_over(reaper, step)
    assert returned.wait(NET), "then() did not return"
    assert not step.done.is_set(), "then() returned only after the step had ended"
    step.release.set()
    reaper.join(NET)
    assert step.done.is_set()


def test_join_and_finished_cover_the_step_handed_after_the_end(held):
    reaper = _finished_reaper()
    step = _Step()
    held.append(step)
    _hand_over(reaper, step)
    reaper.join(0)
    assert not reaper.finished, "finished said done while a step was still running"
    waited = threading.Event()

    def wait_for_all() -> None:
        reaper.join()
        waited.set()

    waiter = threading.Thread(target=wait_for_all, daemon=True)
    waiter.start()
    waiter.join(0)
    assert not waited.is_set(), "join() returned while the step was held"
    step.release.set()
    assert waited.wait(NET)
    assert reaper.finished and step.done.is_set()


def test_wait_reaped_covers_the_step_handed_after_the_end(held):
    reaper = _finished_reaper()
    step = _Step()
    held.append(step)
    _hand_over(reaper, step)
    stand_in = types.SimpleNamespace(conn=types.SimpleNamespace(reaper=reaper))
    assert Browser.wait_reaped(stand_in, 0) is False, "wait_reaped said done while the step was held"
    step.release.set()
    assert Browser.wait_reaped(stand_in, NET) is True
    assert step.done.is_set()


def test_the_continuation_is_not_a_daemon(held):
    reaper = _finished_reaper()
    step = _Step()
    held.append(step)
    _hand_over(reaper, step)
    assert step.thread.daemon is False, "a daemon thread is dropped in the middle of a removal at the end of the interpreter"
    step.release.set()
    reaper.join(NET)


def test_steps_handed_after_the_end_run_in_the_order_of_the_hand_over(held):
    reaper = _finished_reaper()
    ran = []
    first = _Step(name="first", log=ran)
    second, third = _Step(hold=False, name="second", log=ran), _Step(hold=False, name="third", log=ran)
    held.extend([first, second, third])
    _hand_over(reaper, first)
    reaper.then(second)                # handed while the first is running: it waits for it
    reaper.then(third)
    assert not second.started.is_set() and not third.started.is_set(), "a step started before the one handed before it ended"
    first.release.set()
    reaper.join(NET)
    assert ran == ["first", "second", "third"]
    assert reaper.finished


def test_a_new_continuation_serves_a_step_handed_after_the_last_one_ended(held):
    reaper = _finished_reaper()
    one, two = _Step(hold=False), _Step(hold=False)
    held.extend([one, two])
    reaper.then(one)
    reaper.join(NET)
    reaper.then(two)
    reaper.join(NET)
    assert one.done.is_set() and two.done.is_set()
    assert one.thread is not threading.current_thread() and two.thread is not threading.current_thread()


def test_a_step_that_raises_does_not_stop_the_ones_after_it(held):
    reaper = _finished_reaper()
    after = _Step(hold=False)
    held.append(after)

    def boom() -> None:
        raise RuntimeError("a step that fails")

    reaper.then(boom)
    reaper.then(after)
    reaper.join(NET)
    assert after.done.is_set()


def test_a_step_handed_before_the_end_runs_on_the_reaper_not_on_the_caller(held):
    reaper = P.Reaper(None)
    step = _Step(hold=False)
    held.append(step)
    reaper.then(step)                   # not started yet: queued
    reaper.start()
    reaper.join(NET)
    assert step.done.is_set()
    assert step.thread is reaper


def test_where_no_thread_can_be_made_the_caller_runs_the_step(monkeypatch):
    reaper = _finished_reaper()
    real_start = threading.Thread.start

    def start(self):
        if self.name == "invisible-reaper-then":
            raise RuntimeError("can't create new thread at interpreter shutdown")
        return real_start(self)

    monkeypatch.setattr(threading.Thread, "start", start)
    step = _Step(hold=False)
    reaper.then(step)
    assert step.done.is_set(), "the step was lost where no thread could be made"
    assert step.thread is threading.current_thread()
    assert reaper.finished               # the failed continuation left nothing registered
    monkeypatch.undo()
    later = _Step(hold=False)
    reaper.then(later)                   # and a later step goes to a thread again
    reaper.join(NET)
    assert later.done.is_set() and later.thread is not threading.current_thread()


def test_the_end_of_the_interpreter_waits_for_a_step_handed_after_the_end(tmp_path):
    marker = tmp_path / "done"
    flag = tmp_path / "flag"
    script = textwrap.dedent("""
        import os, sys, threading, time
        from invisible_core import process as P
        marker, flag = sys.argv[1:3]
        reaper = P.Reaper(None)
        reaper.start()
        reaper.join()

        def step():
            if threading.current_thread() is threading.main_thread():     # the caller would wait for a flag only it can set
                open(marker, "w").write("ran on the caller")
                return
            while not os.path.exists(flag):      # ends only when the program has already reached its end
                time.sleep(0.01)
            open(marker, "w").write("removed")

        reaper.then(step)
        open(flag, "w").close()
    """)
    done = subprocess.run([sys.executable, "-c", script, str(marker), str(flag)], timeout=NET)
    assert done.returncode == 0
    assert marker.read_text() == "removed"
