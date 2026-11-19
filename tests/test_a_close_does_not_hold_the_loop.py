"""Closing a browser waits, and the wait is not the event loop's.

The teardown of a browser waits for its processes to exit, ends the survivors of its tree and removes its profile: seconds of
waiting (`close()` returns when the browser has exited, and the launch's reaper does the rest: `wait_reaped`). What was wrong is WHO
waited. With four browsers in one Python process py-spy put about a fifth of the main thread in the wait for the exit
(`psutil.wait_procs`) and the removal of the profile (`rmtree`) when one of them closed, all on the event loop that serves the other
three, plus a scan of every process of the machine, its environment read, to find the tree to end.

Now:

* the tree of a launch is known from the launch, never searched for: its job on Windows, its engine's descendants on POSIX
  (`process.EngineTree`); `find_processes` and `reap_session` of a token a launch registered read nothing of the machine;
* the close has a form an event loop can await (`Browser.aclose`, `Connection.aclose`, `SessionFiles.aremove`), which runs the same
  close in a thread of its own: the contract (it returns when the processes are gone and the profile is removed) is the same, only
  the thread that waits is not the loop's.

The tests stand a Python process in for the engine (what is measured is the teardown, not the browser): it answers the Juggler
pipe and has two children of its own. They run in a client program of their own, as the spawn tests of this suite do: the real
spawn of the platform (`_spawn_windows`, `_spawn_posix`), the real `instance.launch` and `Browser`, on Linux and on Windows.

No test here compares anything with a time (a machine under load would turn it red with no defect). The stand-in is the one that
makes the close wait: when its pipe closes it ends its children, starts a stand-in for the sender (which outlives the browser, as
the pingsender does) and then WAITS FOR THE TEST, in three steps, each a file the test writes:

1. the engine stays alive after its pipe is closed: the close is waiting for it;
2. the engine starts one more child, born in the last instant of its life (after any listing a close could have made while the
   engine was alive: only a tree that holds it by construction waits for it) and exits: the close is waiting for that child;
3. the close has returned, the sender is still held: the reaper is waiting for it.

In each step, while the close is waiting for something the test holds, the event loop of the client is asked to serve: a heartbeat
task on it counts its ticks, and the claim is that the count grows (`TICKS` of them) before the test lets go of anything. A close
made on the loop's own thread would leave the count at zero: no tick can happen while the thread that would run it is inside the
wait. The control makes that close inline and shows the instrument sees it. A clock is only the safety net (`NET`) that lets a
hanging test give up.
"""
from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import textwrap
import threading
import time

import pytest

from invisible_core import process as P

WINDOWS = sys.platform == "win32"

#: A safety net, never a measure: how long a test waits for something that is certain to happen before it gives up (and lets
#: everything it holds go, so that nothing hangs). Nothing is compared with a time.
NET = 60

#: How many ticks of the heartbeat on the client's loop show that the loop is serving while a close waits.
TICKS = 20

#: The stand-in for the sender of the shutdown pings: its command line carries `-backgroundtask pingsender`. It says it has started,
#: finishes only when the test has released it (a file), and writes `done` when it has: that is only written by a run that was
#: not ended.
_SENDER = textwrap.dedent("""
    import os, sys, time
    started, release, marker = sys.argv[1:4]
    open(started, "w").close()
    while not os.path.exists(release):
        time.sleep(0.01)
    open(marker, "w").write("done")
""")

#: A process of the browser that is NOT a sender (nothing on its command line says so): it too finishes only when the test says, and
#: writes `done` when it has: that is only written by a run that was let go, not by one that was ended.
_HELD = textwrap.dedent("""
    import os, sys, time
    started, release, marker = sys.argv[1:4]
    open(started, "w").close()
    while not os.path.exists(release):
        time.sleep(0.01)
    open(marker, "w").write("done")
""")

#: What stands for the engine. It answers every command on the Juggler pipe (fds 3 and 4 on POSIX, the handles named by
#: PW_PIPE_READ/PW_PIPE_WRITE on Windows), starts two children, and says so. When the pipe closes it ends them, starts the sender
#: and waits for `exit_engine`; then it starts a child that lives until `release_late`, is sure it runs, and exits.
_ENGINE = r'''
import json, os, subprocess, sys, time
if os.name == "nt":
    import msvcrt
    r = msvcrt.open_osfhandle(int(os.environ["PW_PIPE_READ"]), os.O_RDONLY)
    w = msvcrt.open_osfhandle(int(os.environ["PW_PIPE_WRITE"]), 0)
else:
    r, w = 3, 4
DIR = @@DIR@@


def path(name):
    return os.path.join(DIR, name)


def wait_for(name):
    while not os.path.exists(path(name)):
        time.sleep(0.01)


kids = [subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"]) for _ in range(2)]
print("PIDS", os.getpid(), *[k.pid for k in kids], flush=True)
print("Juggler listening to the pipe", flush=True)
buffer = b""
while True:
    data = os.read(r, 65536)
    if not data:
        break
    buffer += data
    while b"\0" in buffer:
        raw, buffer = buffer.split(b"\0", 1)
        if raw:
            message = json.loads(raw)
            os.write(w, json.dumps({"id": message["id"], "result": {}}).encode() + b"\0")
for k in kids:
    k.kill()
sender = subprocess.Popen([sys.executable, "-c", @@SENDER@@, path("sender_started"), path("release_sender"),
                           path("sender_marker"), "-backgroundtask", "pingsender"])
print("PIDS", sender.pid, flush=True)
wait_for("sender_started")
wait_for("exit_engine")
late = subprocess.Popen([sys.executable, "-c", @@HELD@@, path("late_started"), path("release_late"),
                        path("late_marker")])
print("PIDS", late.pid, flush=True)
wait_for("late_started")
print("BYE", flush=True)
'''

#: The client: two browsers made by the real `instance.launch` (only the executable is the stand-in). The first one closes while
#: a heartbeat runs on the loop and a thread of its own (not the loop's) looks at the world at each step and says what it sees:
#: the test answers each look by releasing what holds the close. The second browser is the bystander: its stand-in is
#: pre-released, and it closes at the end. `sys.argv[1]`: `aclose` (the close an event loop awaits) or `inline` (the control:
#: the same close made on the loop itself).
_CLIENT = r'''
import asyncio, json, os, sys, threading, time
import psutil
from invisible_core.juggler import _profile, connection, instance
from invisible_core import process as _process
from invisible_core.process import SessionToken, find_processes

ROOT = os.environ["MARKER_DIR"]
NET, TICKS = @@NET@@, @@TICKS@@
INLINE = sys.argv[1] == "inline"
STUCK = sys.argv[2:] == ["stuck"]
ENGINE = @@ENGINE@@
real = {"nt": connection._spawn_windows, "posix": connection._spawn_posix}
spawn = real["nt" if os.name == "nt" else "posix"]
NEXT = [None]


def stand_in(executable, argv, env):
    return spawn(sys.executable, ["-c", ENGINE.replace("@@DIR@@", repr(os.path.join(ROOT, NEXT[0])))], env)


connection._spawn_windows = connection._spawn_posix = stand_in
# Nothing here is let to wait out a bound of the product: the sender finishes when the test says, the browser's exit is waited for
# as long as the test holds it, and `SENDER_GRACE` is longer than any safety net, so that a reaper that waited for it would hang.
_profile.SENDER_GRACE = 3600.0
# The limit for the browser's exit (`BROWSER_EXIT_LIMIT`, ONE constant that `close` and its reaper read): the other runs wait as
# long as the test holds the browser; the stuck run is the one whose child never leaves, so it ends at a short limit of its own
# instead of the product's 70 s (the safety net of a browser that is stuck, not a measure of anything the test claims).
_process.BROWSER_EXIT_LIMIT = 2.0 if STUCK else float(NET)
if sys.argv[2:] == ["subreaper"]:
    # A client that is the init of its orphans and does not reap them: the PID 1 of a container without one. What the engine
    # leaves behind becomes this process's child and, when it ends, a zombie nobody collects.
    import ctypes
    assert ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0      # PR_SET_CHILD_SUBREAPER

_real_sleep = time.sleep
_out = threading.Lock()


def say(tag, payload):
    with _out:
        sys.stdout.write("%s %s\n" % (tag, json.dumps(payload)))
        sys.stdout.flush()


def wait_for(condition, net=NET):
    end = time.monotonic() + net
    while not condition():
        if time.monotonic() >= end:
            return False
        _real_sleep(0.01)
    return True


def pids_of(browser):
    out, bye = [], False
    for line in browser.conn.output.tail(200):
        if line.startswith("PIDS"):
            out += [int(x) for x in line.split()[1:]]
        if line.startswith("BYE"):
            bye = True
    return out, bye


def status_of(pid):
    try:
        return psutil.Process(pid).status()
    except psutil.NoSuchProcess:          # gone between the question and the answer
        return None


def alive(pids):
    return [p for p in pids if status_of(p) not in (None, psutil.STATUS_ZOMBIE)]


def launch(name):
    folder = os.path.join(ROOT, name)
    os.makedirs(folder, exist_ok=True)
    if name == "b" or STUCK:              # the bystander's stand-in holds nothing; the stuck run's holds only its late child
        for held in ("exit_engine", "release_late", "release_sender"):
            if not (STUCK and held == "release_late"):
                open(os.path.join(folder, held), "w").close()
    NEXT[0] = name
    token = SessionToken.mint()
    browser = instance.launch("engine", prefs={"a": True}, env=token.stamp(dict(os.environ)), ready_timeout=NET)
    wait_for(lambda: len(pids_of(browser)[0]) >= 3)           # the engine and its two children are running
    return token, browser


async def main():
    (ta, a), (tb, b) = launch("a"), launch("b")
    pa, pb = pids_of(a)[0], pids_of(b)[0]
    files_a = (a._files.profile, a._files.tmp)
    leader = None if os.name == "nt" else (os.getpgid(pa[0]) == pa[0] != os.getpgrp())
    main_id = threading.get_ident()

    def here(name):
        return os.path.exists(os.path.join(ROOT, "a", name))

    # What the test is shown: the close ran on the loop's own thread, which the stack of that thread says.
    def blocked_in_a_close():
        frame = sys._current_frames().get(main_id)
        while frame is not None:
            code = frame.f_code
            if code.co_name in ("close", "wait_reaped") and code.co_filename.endswith(("connection.py", "instance.py", "process.py")):
                return True
            frame = frame.f_back
        return False

    ticks, state = [0], {"closed": False, "reaped": False, "watch": False}

    async def heartbeat():
        while True:
            ticks[0] += 1
            await asyncio.sleep(0.001)

    def look(name, ready):
        wait_for(ready)
        base = ticks[0]
        # The loop serves (TICKS ticks happen while the close waits for what the test holds), or the thread that should have run
        # them is inside the close (no tick can happen, and the stack says why).
        while ticks[0] - base < TICKS and not blocked_in_a_close():
            _real_sleep(0.005)
        pids, bye = pids_of(a)
        say("PENDING", {
            "name": name, "ticks": ticks[0] - base, "blocked": blocked_in_a_close(),
            "closed": state["closed"], "reaped": state["reaped"], "pids": pids, "alive": alive(pids), "bye": bye,
            "sender_released": here("release_sender"), "late_released": here("release_late"),
            "marker": here("sender_marker"), "dirs": [d for d in files_a if os.path.exists(d)]})

    def monitor():
        look("engine", lambda: here("sender_started") and len(pids_of(a)[0]) >= 4)
        look("late", lambda: here("late_started") and pids_of(a)[1] and len(pids_of(a)[0]) >= 5
             and pids_of(a)[0][0] not in alive(pids_of(a)[0]))
        look("reaper", lambda: state["closed"])

    # What the loop's own thread runs while the close is awaited: every blocking step a close makes, by the thread that made it.
    import shutil
    on_the_loop, replaced = [], {}

    def watched(owner, name):
        replaced[(owner, name)] = original = getattr(owner, name)

        def call(*x, **k):
            if threading.get_ident() == main_id and state["watch"]:
                on_the_loop.append(name)
            return original(*x, **k)
        setattr(owner, name, call)

    watched(time, "sleep")
    watched(os, "close")
    watched(shutil, "rmtree")
    watched(psutil, "wait_procs")
    scans = []
    real_iter, real_environ = psutil.process_iter, psutil.Process.environ
    psutil.process_iter = lambda *x, **k: (scans.append("process_iter"), real_iter(*x, **k))[1]
    psutil.Process.environ = lambda self: (scans.append("environ"), real_environ(self))[1]

    beat = asyncio.create_task(heartbeat())
    while ticks[0] < TICKS:               # the heartbeat itself works on a free loop: the counts below start from there
        await asyncio.sleep(0)
    if not STUCK:
        threading.Thread(target=monitor, daemon=True, name="the-monitor").start()
    state["watch"] = True
    if INLINE:
        a.close()                         # the control: the same close, made on the loop itself
        state["closed"] = True
        reaped = a.wait_reaped(NET)
    else:
        await a.aclose()
        state["closed"] = True
        reaped = await a.await_reaped(NET)
    state["watch"] = False
    state["reaped"] = True
    beat.cancel()
    for (owner, name), original in replaced.items():
        setattr(owner, name, original)
    psutil.process_iter, psutil.Process.environ = real_iter, real_environ

    wait_for(lambda: pids_of(a)[1])
    pa = pids_of(a)[0]
    report = {
        "reaped": reaped, "scans": scans, "leader": leader, "on_the_loop": on_the_loop,
        "a_pids": len(pa), "a_alive": alive(pa),
        "a_dirs": [d for d in files_a if os.path.exists(d)],
        "marker_text": open(os.path.join(ROOT, "a", "sender_marker")).read() if here("sender_marker") else None,
        "late_done": here("late_marker"), "late_released": here("release_late"),
        "zombies": [p for p in pa if status_of(p) == psutil.STATUS_ZOMBIE],
        "b_pids": len(pb), "b_alive": alive(pb),
        "b_dirs": [d for d in (b._files.profile, b._files.tmp) if os.path.exists(d)],
        "token_a_listed": len(find_processes(ta)),
    }
    if INLINE:
        b.close()
        b.wait_reaped(NET)
    else:
        await b.aclose()
        await b.await_reaped(NET)
    wait_for(lambda: pids_of(b)[1])
    report["b_closed_alive"] = alive(pids_of(b)[0])
    report["b_closed_dirs"] = [d for d in (b._files.profile, b._files.tmp) if os.path.exists(d)]
    say("REPORT", report)


asyncio.run(main())
'''


class _Run:
    """One run of the client program, driven line by line: the client says what it sees at each step of the close and the test
    answers by releasing what holds it (a file the stand-ins wait for)."""

    #: What the test lets go of when the client reports each step.
    STEPS = (("engine", "exit_engine"), ("late", "release_late"), ("reaper", "release_sender"))

    def __init__(self, tmp_path, how, *more):
        engine = (_ENGINE.replace("@@SENDER@@", repr(_SENDER)).replace("@@HELD@@", repr(_HELD)))
        script = tmp_path / "client.py"
        script.write_text(_CLIENT.replace("@@ENGINE@@", repr(engine)).replace("@@NET@@", str(NET))
                          .replace("@@TICKS@@", str(TICKS)), encoding="utf-8")
        self.dir = tmp_path / "markers"
        (self.dir / "a").mkdir(parents=True, exist_ok=True)
        self.proc = subprocess.Popen([sys.executable, str(script), how, *more], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True, env=dict(os.environ, MARKER_DIR=str(self.dir)))
        self.lines, self.stdout, self.stderr = queue.Queue(), [], []
        threading.Thread(target=self._read_out, daemon=True).start()
        threading.Thread(target=lambda: self.stderr.extend(self.proc.stderr), daemon=True).start()
        self.pending, self.final, self.returncode = {}, None, None

    def _read_out(self):
        for line in self.proc.stdout:
            self.stdout.append(line)
            self.lines.put(line)
        self.lines.put(None)

    def expect(self, tag, net=NET):
        """The payload of the next `tag` line, or None when the client ended (or said nothing within the safety net)."""
        while True:
            try:
                line = self.lines.get(timeout=net)
            except queue.Empty:
                return None
            if line is None:
                self.lines.put(None)
                return None
            if line.startswith(tag + " "):
                return json.loads(line[len(tag) + 1:])

    def let_go(self, name):
        (self.dir / "a" / name).write_text("go")

    def why(self):
        return "the client said:\n%s\n%s" % ("".join(self.stdout)[-2000:], "".join(self.stderr)[-4000:])

    def end(self):
        for _, name in self.STEPS:
            self.let_go(name)                       # nothing is left held, whatever happened
        try:
            self.proc.wait(timeout=NET)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        return self.proc.returncode


def _drive(tmp_path, how, *more):
    run = _Run(tmp_path, how, *more)
    try:
        for name, release in run.STEPS:
            said = run.expect("PENDING")
            run.pending[name] = said
            run.let_go(release)                      # only now does what the client is waiting for go away
            if said is None:
                break
        run.final = run.expect("REPORT")
    finally:
        run.returncode = run.end()
    return run


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    """One run of the client closing with `aclose`: what it saw at each step is asserted one claim at a time below."""
    return _drive(tmp_path_factory.mktemp("teardown"), "aclose")


@pytest.fixture(scope="module")
def control(tmp_path_factory):
    """The same run with the close made inline on the loop."""
    return _drive(tmp_path_factory.mktemp("control"), "inline")


@pytest.fixture(scope="module")
def subreaped(tmp_path_factory):
    """One run of the client as the parent of its orphans that never reaps them."""
    return _drive(tmp_path_factory.mktemp("subreaper"), "aclose", "subreaper")


def _drive_stuck(tmp_path):
    """One run in which a child of the browser (not a sender) is never let go: nothing is held but that child."""
    run = _Run(tmp_path, "aclose", "stuck")
    try:
        run.final = run.expect("REPORT")
    finally:
        run.returncode = run.end()
    return run


@pytest.fixture
def report(run):
    assert run.final, run.why()
    return run.final


pytestmark = pytest.mark.integration


def _seen(run, name):
    said = run.pending.get(name)
    assert said, "the client never said what it saw at the step %r: %s" % (name, run.why())
    return said


def test_the_instrument_sees_a_loop_that_is_held(control):
    """The control: closed inline, the thread that would run the heartbeat is inside the close at each step and not one tick
    happens. Without this, a heartbeat that could not tell a held loop from a free one would pass the test below for nothing."""
    for name, _ in _Run.STEPS:
        said = _seen(control, name)
        assert said["blocked"] is True and said["ticks"] == 0, (
            "closing on the loop itself, the step %r was not seen as a held loop: %r" % (name, said))
    assert control.final, control.why()
    assert control.final["on_the_loop"], "no blocking step of the close was seen on the loop's thread, closing it there"


def test_the_loop_serves_its_tasks_while_a_close_waits(run):
    """While the close waits for what the test holds (the engine, the child it leaves in its last instant, the sender the reaper
    waits for) a task on the client's loop runs: `TICKS` ticks of its heartbeat happen before the test lets go of anything, and
    the thread that waits is not the loop's. A close made on the loop leaves the count at zero (the control above)."""
    for name, _ in _Run.STEPS:
        said = _seen(run, name)
        assert said["blocked"] is False and said["ticks"] >= TICKS, (
            "the loop was held while the close waited at the step %r: %d ticks, the loop's thread was %sinside a close"
            % (name, said["ticks"], "" if said["blocked"] else "not "))


def test_the_close_waits_for_the_engine_then_for_the_child_it_leaves_and_returns_before_the_sender(run):
    """The order of the contract, proved by what the test holds: the close had not returned while the engine was alive, nor while
    the child born in its last instant was; it had returned (and the reaper had not finished) while the sender was held."""
    pids = _seen(run, "engine")["pids"]
    engine, sender = pids[0], pids[3]
    first, second, third = _seen(run, "engine"), _seen(run, "late"), _seen(run, "reaper")
    assert first["closed"] is False and engine in first["alive"] and sender in first["alive"] and len(first["pids"]) == 4, (
        "the close was not waiting for the engine: %r" % first)
    late = second["pids"][4]
    assert second["closed"] is False and late in second["alive"] and engine not in second["alive"] and second["late_released"] is False, (
        "the close was not waiting for the child the engine left in its last instant: %r" % second)
    assert third["closed"] is True and third["reaped"] is False and third["late_released"] is True, (
        "the close had not returned by the time the late child was gone: %r" % third)
    assert third["sender_released"] is False and sender in third["alive"] and not set(second["pids"][:3] + [late]) & set(third["alive"]), (
        "close() returned with a process of the browser alive, or ended the sender: %r" % third)
    assert third["marker"] is False and len(third["dirs"]) == 2, (
        "the reaper removed the directories (or the sender had finished) before the sender was let go: %r" % third)


def test_no_blocking_step_of_the_close_runs_on_the_loop_s_thread(report):
    """The cause, asked directly: `time.sleep`, `os.close`, `rmtree` and `psutil.wait_procs` are what a close does while it waits
    and removes, and none of them may be called by the thread that runs the loop. Red on a close made inline."""
    assert report["on_the_loop"] == [], "the loop's own thread made these calls while it awaited the close: %s" % report["on_the_loop"]


def test_closing_a_browser_reads_no_process_of_the_machine_and_no_environment(report):
    """Red on the token search: `find_processes` asks `psutil.process_iter` for every process and reads the environment of each."""
    assert report["scans"] == [], "the close scanned the machine: %d calls (%s)" % (
        len(report["scans"]), sorted(set(report["scans"])))


def test_after_close_no_process_of_the_tree_is_alive_and_the_profile_is_gone(report):
    """The contract of `close()` does not change: it returns when the processes have exited. The sender (the pingsender: it
    outlives the browser and is the process that kept a profile from being removed) is let finish, not ended, and a child born in
    the last instant of the engine is in the tree of the launch: a tree LISTED while the engine was alive cannot hold it; one the
    launch is born as the leader of (a process group, a job) does."""
    assert report["a_pids"] == 5, "the engine, its two children, the sender and the last child were not all counted: %r" % report
    assert report["reaped"] is True, "the reaper had not finished when it was waited for (the safety net)"
    assert report["a_alive"] == [], "processes of the closed browser are alive: %s" % report["a_alive"]
    assert report["a_dirs"] == [], "the closed browser left its directories: %s" % report["a_dirs"]
    assert report["marker_text"] == "done", "the sender was ended instead of being let finish: %r" % report
    assert report["token_a_listed"] == 0, "the session's token still lists processes after the close"


def test_the_reaper_ends_a_process_of_the_tree_that_never_leaves_by_itself(tmp_path):
    """A child of the browser that is not a sender and that nothing lets go: the close returns at the limit for the
    browser's exit (it does not wait for ever; the client shortens the product's limit), and the reaper ends the child. Proved by condition, not by time: `await_reaped`
    returns True (a reaper that waited for the child to leave, or for the sender's grace, would hang until the safety net), and the
    child is gone without having written the `done` that only a child that was let go writes. The deadline is the product's; the
    test compares nothing with it."""
    run = _drive_stuck(tmp_path)
    assert run.final, run.why()
    final = run.final
    assert final["late_released"] is False, "the setup is not the one under test: the child was let go: %r" % final
    assert final["a_pids"] == 5, "the child was not born: %r" % final
    assert final["reaped"] is True, "the reaper did not finish while a child of the browser stayed (the safety net)"
    assert final["a_alive"] == [], "a process of the browser that never left was not ended: %s" % final["a_alive"]
    assert final["late_done"] is False, "the child finished by itself: it was not ended, so nothing was proved: %r" % final
    assert final["a_dirs"] == [], "the closed browser left its directories: %s" % final["a_dirs"]


def test_closing_one_browser_does_not_touch_the_other(report):
    """Two browsers in one process: the first one's close ends its own tree and nothing of the second's, and then the second closes
    the same way."""
    assert report["b_pids"] == 3
    assert len(report["b_alive"]) == 3, "closing the first browser ended a process of the second: %r" % report
    assert report["b_dirs"] != [] and len(report["b_dirs"]) == 2, "the second browser's directories went with the first's"
    assert report["b_closed_alive"] == [], "the second browser's tree is not gone after its own close: %s" % report["b_closed_alive"]
    assert report["b_closed_dirs"] == []


# ── the pieces, without a launch ────────────────────────────────────────────

class _NoSearch:
    """`psutil` that records a search of the machine and answers nothing, for the calls that must not make one."""

    def __init__(self, monkeypatch):
        import psutil

        self.calls = []
        monkeypatch.setattr(psutil, "process_iter",
                            lambda *a, **k: (self.calls.append("process_iter"), iter(()))[1])
        monkeypatch.setattr(psutil.Process, "environ",
                            lambda proc: (self.calls.append("environ"), {})[1])


#: A process that says its own pid and stays. The processes of a test are counted by the pids they report, never by how many the
#: tree holds: where the interpreter is a venv's launcher (Windows), `sys.executable` is a process that starts the real interpreter as
#: its child, so the tree of a `Popen` of it holds two processes, and both are the test's own.
_SAY_MY_PID = "import os, time; print(os.getpid(), flush=True); time.sleep(60)"


def _spawn_saying_its_pid():
    """(the Popen, the pids of the processes this started: the Popen's own and the one that said its pid)."""
    child = subprocess.Popen([sys.executable, "-c", _SAY_MY_PID], stdout=subprocess.PIPE, text=True)
    return child, {child.pid, int(child.stdout.readline())}


@pytest.mark.unit
def test_a_registered_token_is_listed_and_ended_from_its_tree_not_searched(monkeypatch):
    import psutil

    searched = _NoSearch(monkeypatch)
    token = P.SessionToken.mint()
    child, ours = _spawn_saying_its_pid()
    try:
        tree = P.EngineTree(child.pid)
        P.register_tree(token, tree)
        assert {p.pid for p in P.find_processes(token)} == ours
        assert P.reap_session(token, timeout=5) == len(ours)
        child.wait(timeout=10)
        assert P.find_processes(token) == []
        assert not psutil.pid_exists(child.pid) or child.poll() is not None
        assert searched.calls == [], "a registered token was searched for: %s" % searched.calls
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
        child.stdout.close()


@pytest.mark.unit
def test_a_token_no_launch_registered_is_still_searched_for(monkeypatch):
    """What `find_processes` is still for: a tree that was not launched by this core (the search reads the token from each environment)."""
    seen = []
    import psutil

    monkeypatch.setattr(psutil, "process_iter", lambda *a, **k: (seen.append(1), iter(()))[1])
    assert P.find_processes(P.SessionToken.mint()) == []
    assert seen == [1]


_GRANDCHILD = ("import os, subprocess, sys, time; "
               "k = subprocess.Popen([sys.executable, '-c', %r], stdout=subprocess.PIPE, text=True); "
               "print(os.getpid(), k.pid, k.stdout.readline().strip(), flush=True); time.sleep(60)" % _SAY_MY_PID)


@pytest.mark.unit
def test_the_tree_of_an_engine_is_its_descendants_listed_in_one_pass():
    import psutil

    engine = subprocess.Popen([sys.executable, "-c", _GRANDCHILD], stdout=subprocess.PIPE, text=True)
    try:
        engine_said, grandchild_launched, grandchild_said = (int(n) for n in engine.stdout.readline().split())
        engines = {engine.pid, engine_said}
        grandchildren = {grandchild_launched, grandchild_said}
        tree = P.EngineTree(engine.pid)
        assert {p.pid for p in tree.members()} == engines | grandchildren
        tree.remember()
        # The engine is gone (the process that said its pid, whose launcher ends with it) and its child is reparented: it is still the
        # tree's, because it was listed while its parent lived.
        psutil.Process(engine_said).kill()
        engine.wait()
        assert {p.pid for p in tree.members()} == grandchildren
        assert tree.end(timeout=5) == len(grandchildren)
        assert tree.members() == []
        assert not any(psutil.pid_exists(pid) and psutil.Process(pid).is_running() for pid in grandchildren)
    finally:
        engine.kill()
        engine.stdout.close()


@pytest.mark.unit
def test_an_engine_that_has_been_reaped_does_not_name_a_process_that_reuses_its_pid():
    """The tree holds process objects with their creation time, so a pid the system reused is not the one that was listed."""
    engine = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    tree = P.EngineTree(engine.pid)
    engine.kill()
    engine.wait()
    assert tree.members() == []


@pytest.mark.unit
@pytest.mark.skipif(not WINDOWS, reason="the job object is Windows")
def test_a_job_lists_and_ends_its_own_tree_and_only_it():
    """`EngineJob.pids` lists what is in the job by its own account (the job of another launch holds its own), `terminate` ends all of it."""
    import ctypes
    from ctypes import wintypes

    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    k.AssignProcessToJobObject.restype = wintypes.BOOL
    a, b = P.EngineJob.create(), P.EngineJob.create()
    procs = []
    try:
        for job in (a, b):
            proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], creationflags=0x4)
            procs.append(proc)
            assert k.AssignProcessToJobObject(job.handle, int(proc._handle))
            import psutil
            psutil.Process(proc.pid).resume()
        assert a.pids() == [procs[0].pid] and b.pids() == [procs[1].pid]
        a.terminate()
        assert a.wait_empty(time.monotonic() + 10) is True
        assert procs[0].wait(timeout=10) is not None
        assert procs[1].poll() is None, "ending one job ended the other's process"
        assert b.pids() == [procs[1].pid]
    finally:
        for job in (a, b):
            job.close()
        for proc in procs:
            if proc.poll() is None:
                proc.kill()
                proc.wait()


@pytest.mark.skipif(WINDOWS, reason="process groups are POSIX")
def test_the_engine_is_born_the_leader_of_a_process_group_of_its_own(report):
    """The tree is the group: the engine's pid is its group's, and not the client's (Playwright's launcher: `detached: true`)."""
    assert report["leader"] is True


@pytest.mark.unit
@pytest.mark.skipif(WINDOWS, reason="process groups are POSIX")
def test_a_group_is_waited_for_and_ended_whole_with_nothing_listed(monkeypatch):
    """The leader exits and leaves a child behind: the group still holds it (`killpg(pgid, 0)`), and `end` ends it, listing
    and scanning nothing."""
    searched = _NoSearch(monkeypatch)
    leader = subprocess.Popen(
        [sys.executable, "-c",
         "import subprocess, sys; "
         "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); print('up', flush=True)"],
        process_group=0, stdout=subprocess.PIPE, text=True)
    try:
        assert leader.stdout.readline().strip() == "up"
        leader.wait(timeout=10)
        tree = P.EngineTree(leader.pid, group=True, poll=leader.poll)
        assert tree._group_alive(), "the child the leader left behind is not in its group"
        assert tree.end(timeout=5) == 1
        assert not tree._group_alive()
        assert searched.calls == [], "ending a group read the machine: %s" % searched.calls
    finally:
        try:
            os.killpg(leader.pid, 9)
        except OSError:
            pass


@pytest.mark.unit
@pytest.mark.skipif(WINDOWS, reason="process groups are POSIX")
def test_a_group_that_has_been_seen_empty_is_never_signalled_again(monkeypatch):
    """Its number may belong to an unrelated process group by then."""
    leader = subprocess.Popen([sys.executable, "-c", "pass"], process_group=0)
    leader.wait(timeout=10)
    tree = P.EngineTree(leader.pid, group=True, poll=leader.poll)
    assert tree.end(timeout=1) == 0 and tree._gone
    sent = []
    monkeypatch.setattr(os, "killpg", lambda *a: sent.append(a))
    assert tree.end(timeout=1) == 0
    assert sent == [], "a group that was empty was signalled: %s" % sent




@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="a client that is its orphans' init, and /proc: Linux")
def test_a_group_of_zombies_is_empty_so_a_close_does_not_wait_for_nobody(subreaped):
    """Red when the group is waited for with `killpg(pgid, 0)` alone, which answers for a zombie too: in a container whose PID 1 is
    the user's script, the sender that outlived the engine stays a zombie nobody reaps, the group looks alive, and the reaper waits
    the grace a sender is given (here an hour, far past the safety net) and then the SIGTERM. The client here is the init of its
    orphans and reaps none. It is done when the tree is: the test lets the sender go and waits for the reaper on a condition."""
    assert subreaped.final, subreaped.why()
    assert subreaped.final["zombies"], "the setup is not the one under test: nothing was left a zombie: %r" % subreaped.final
    assert subreaped.final["reaped"] is True, "the reaper kept waiting for a group of zombies (the safety net)"
    for name, _ in _Run.STEPS:
        said = _seen(subreaped, name)
        assert said["blocked"] is False and said["ticks"] >= TICKS, "the loop was held at the step %r: %r" % (name, said)
    assert subreaped.final["a_dirs"] == [], "the closed browser left its directories: %s" % subreaped.final["a_dirs"]
