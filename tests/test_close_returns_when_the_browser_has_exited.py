"""`close()` returns when the BROWSER has exited, and the launch's reaper does the rest.

Measured on the hosted runners (64.73.0): a browser close took 1.3-2.0 s on Linux and 1.7-3.3 s on Windows (stock Playwright:
0.4-1.1 s). Between the last instant the Firefox parent was seen alive and `close()` returning, 0.2-1.0 s on Linux and 0.8-1.2 s on
Windows went on waiting for the tree to leave by itself (`SessionFiles.remove`, `EngineTree.end(grace=SENDER_GRACE)`) and on our own
tail (the job empty, its release, the removal of the directories).

Now:

* `Connection.close` returns when the parent AND the processes that belong to it (content, GPU, socket, rdd, utility, forkserver) are
  gone, told from the launch's job (Windows) or process group (POSIX). The only processes allowed to be left are the ones Firefox
  starts to outlive itself, known by their COMMAND LINE (`process.outlives_the_browser`: an executable named `pingsender`, or the
  `-backgroundtask` argument), never as "whoever is left";
* the sender is not waited for by `close()` and not ended before it has finished. The launch's reaper (`process.Reaper`, a thread
  that is not a daemon) waits for the tree to be empty (`SENDER_GRACE`), ends what is left, releases the launch and removes the
  session's directories. `Browser.wait_reaped()` / `await_reaped()` wait for all of it; the end of the interpreter does too;
* nothing in the reaper waits a fixed time: a tree that is already empty costs a few milliseconds.

The tests stand a Python process in for the engine (what is measured is the teardown, not the browser), in a client program of
its own with the real spawn of the platform (`_spawn_windows`, `_spawn_posix`: the job and the process group) and the real
`instance.launch` and `Browser`. When its pipe closes the engine starts a stand-in for the sender, a child whose command line carries
`-backgroundtask pingsender` and that holds a file in the session's temporary directory until the TEST lets it go, and exits.

No test here compares anything with a time (a machine under load would turn it red with no defect). The processes that outlive the
browser are held alive by the test itself, so every claim is made while they are alive: `close()` has returned and the sender is
still there, a process that is not a sender is still keeping `close()` waiting; then the test releases them and waits, on a condition
(with a long safety net), for the reaper.
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

pytestmark = pytest.mark.integration

#: A safety net, never a measure: how long a test waits for something that is certain to happen before it gives up (and, where a
#: process is being held, lets it go so that nothing hangs). Nothing is compared with a time: every claim below is made while a
#: process the test itself holds alive is alive, and the test is the one that releases it.
NET = 60

#: The stand-in for the sender of the shutdown pings: its command line carries `-backgroundtask pingsender`. It holds a file of the
#: session, says it has started, and finishes only when the test has released it (a file in the test's directory), saying so.
_SENDER = textwrap.dedent("""
    import os, sys, time
    started, release, marker = sys.argv[1:4]
    f = open(os.path.join(os.environ["TMP"], "ping"), "wb")
    open(started, "w").close()
    while not os.path.exists(release):
        time.sleep(0.01)
    f.close()
    open(marker, "w").write("done")
""")

#: A process of the browser that is NOT a sender (nothing on its command line says so): it too finishes only when the test says.
_CONTENT = textwrap.dedent("""
    import os, sys, time
    started, release = sys.argv[1:3]
    open(started, "w").close()
    while not os.path.exists(release):
        time.sleep(0.01)
""")

_ENGINE = r'''
import json, os, subprocess, sys, time
if os.name == "nt":
    import msvcrt
    r = msvcrt.open_osfhandle(int(os.environ["PW_PIPE_READ"]), os.O_RDONLY)
    w = msvcrt.open_osfhandle(int(os.environ["PW_PIPE_WRITE"]), 0)
else:
    r, w = 3, 4
DIR, SENDER, CONTENT = @@DIR@@, @@SENDER@@, @@CONTENT@@
RELEASE, MARKER = os.path.join(DIR, "release"), os.path.join(DIR, "sender")
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
spawned = []
if SENDER:
    started = os.path.join(DIR, "sender_started")
    spawned.append((started, subprocess.Popen([sys.executable, "-c", @@SENDER_CODE@@, started, RELEASE, MARKER,
                                                 "-backgroundtask", "pingsender"])))
if CONTENT:
    # A process of the browser that is NOT a sender: the close has to wait for it.
    started = os.path.join(DIR, "content_started")
    spawned.append((started, subprocess.Popen([sys.executable, "-c", @@CONTENT_CODE@@, started, RELEASE])))
if spawned:
    print("PIDS", *[p.pid for _, p in spawned], flush=True)
    for started, p in spawned:           # every one of them is running before the engine is gone
        while not os.path.exists(started) and p.poll() is None:
            time.sleep(0.01)
print("BYE", flush=True)
'''

_CLIENT = r'''
import asyncio, json, os, sys, threading, time
import psutil
from invisible_core import process as _process
from invisible_core.juggler import _profile, connection, instance
from invisible_core.process import SessionToken

DIR = os.environ["MARKER_DIR"]
RELEASE, MARKER = os.path.join(DIR, "release"), os.path.join(DIR, "sender")
# The engine's environment is born filtered, so the stand-in processes are told where to write by their command lines.
ENGINE = @@ENGINE@@.replace("@@DIR@@", repr(DIR))
real = {"nt": connection._spawn_windows, "posix": connection._spawn_posix}
spawn = real["nt" if os.name == "nt" else "posix"]


def stand_in(executable, argv, env):
    return spawn(sys.executable, ["-c", ENGINE], env)


connection._spawn_windows = connection._spawn_posix = stand_in
MODE = sys.argv[1]
# What the sender is let to finish is a bound in the product; here it is never the one that ends it (the test releases it).
_profile.SENDER_GRACE = 120.0

# How many times each process's command line is read (the one seam it is read through).
READS = {}
if hasattr(_process, "_command_line_of"):
    _real_command_line = _process._command_line_of

    def _counted(pid):
        READS[pid] = READS.get(pid, 0) + 1
        return _real_command_line(pid)

    _process._command_line_of = _counted

# What the reaper's thread asks to sleep (a fixed wait would be one call of its own).
SLEPT = []
_real_sleep = time.sleep


def _recording_sleep(seconds):
    if threading.current_thread().name == "invisible-reaper":
        SLEPT.append(seconds)
    return _real_sleep(seconds)


time.sleep = _recording_sleep


def say(tag, payload=None):
    print(tag, json.dumps(payload or {}), flush=True)


def wait_for(condition, net=60):
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


def alive(pids):
    return [p for p in pids if psutil.pid_exists(p) and psutil.Process(p).status() != psutil.STATUS_ZOMBIE]


def launch():
    token = SessionToken.mint()
    browser = instance.launch("engine", prefs={"a": True}, env=token.stamp(dict(os.environ)), ready_timeout=60)
    dirs = [browser._files.profile, browser._files.tmp]
    wait_for(lambda: len(pids_of(browser)[0]) >= 3)           # the engine and its two children are running
    return browser, dirs


def snapshot(browser, dirs):
    wait_for(lambda: pids_of(browser)[1])                      # the engine's last word has been read
    pids, bye = pids_of(browser)
    return {"pids": pids, "bye": bye, "alive": alive(pids), "marker": os.path.exists(MARKER),
            "dirs": [d for d in dirs if os.path.exists(d)]}


def closed(browser, dirs, released_at_return):
    # `released_at_return` is taken at the instant `close()` returned: False when nothing had let the held processes go.
    say("CLOSED", dict(snapshot(browser, dirs), released_at_return=released_at_return))


def finish(browser, dirs, reaped):
    say("REPORT", {"reaped": reaped, "after": snapshot(browser, dirs),
                   "marker_text": open(MARKER).read() if os.path.exists(MARKER) else None,
                   "reads": {str(k): v for k, v in READS.items()}, "reaper_sleeps": SLEPT})


def held(browser, dirs):
    """`close()` in a thread while a process of the browser that is not a sender is held alive by the test: it must still be
    running after the engine is gone and after the tree has been asked about that process (and told it stays) several times."""
    asked, outcome = {}, {}
    if hasattr(_process.EngineTree, "_survives"):
        real_survives = _process.EngineTree._survives

        def counted(self, pid):
            answer = real_survives(self, pid)
            asked.setdefault(pid, []).append(answer)
            return answer

        _process.EngineTree._survives = counted

    def closer():
        browser.close()
        outcome["released_at_return"] = os.path.exists(RELEASE)

    thread = threading.Thread(target=closer, name="the-closer")
    thread.start()
    wait_for(lambda: len(pids_of(browser)[0]) >= 4 or not thread.is_alive())
    content = pids_of(browser)[0][-1]
    wait_for(lambda: len(asked.get(content, [])) >= 5 or not thread.is_alive())
    pids, _ = pids_of(browser)
    say("HELD", {"closing": thread.is_alive(), "pids": pids, "alive": alive(pids), "answers": asked.get(content, [])})
    thread.join(120)
    closed(browser, dirs, outcome.get("released_at_return"))
    finish(browser, dirs, browser.wait_reaped(60))


def smain():
    browser, dirs = launch()
    say("CLOSING")
    if MODE == "held":
        return held(browser, dirs)
    browser.close()
    released = os.path.exists(RELEASE)
    closed(browser, dirs, released)
    if MODE == "exit":
        return                           # nothing is waited for: the interpreter ends with the reaper still at work
    finish(browser, dirs, browser.wait_reaped(60))


async def amain():
    browser, dirs = launch()
    say("CLOSING")
    await browser.aclose()
    released = os.path.exists(RELEASE)
    closed(browser, dirs, released)
    finish(browser, dirs, await browser.await_reaped(60))


if MODE == "async":
    asyncio.run(amain())
else:
    smain()
'''


class _Run:
    """One run of the client program, driven line by line: the test reads what the client says and is the one that releases the
    processes it holds (a file the stand-ins wait for)."""

    def __init__(self, tmp_path, how, sender, content):
        engine = (_ENGINE.replace("@@SENDER@@", repr(int(sender))).replace("@@CONTENT@@", repr(int(content)))
                  .replace("@@SENDER_CODE@@", repr(_SENDER)).replace("@@CONTENT_CODE@@", repr(_CONTENT)))
        script = tmp_path / "client.py"
        script.write_text(_CLIENT.replace("@@ENGINE@@", repr(engine)), encoding="utf-8")
        self.dir = tmp_path / "markers"
        self.dir.mkdir(exist_ok=True)
        self.proc = subprocess.Popen([sys.executable, str(script), how], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                     env=dict(os.environ, MARKER_DIR=str(self.dir)))
        self.lines, self.stdout, self.stderr = queue.Queue(), [], []
        threading.Thread(target=self._read_out, daemon=True).start()
        threading.Thread(target=lambda: self.stderr.extend(self.proc.stderr), daemon=True).start()
        self.closed = self.final = self.held = self.running_at_close = self.returncode = None

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

    def release(self):
        (self.dir / "release").write_text("go")

    def closed_or_release(self):
        """`close()` returns by itself while the held processes live. A close that waits for them would never return: after the safety
        net they are let go, so that nothing hangs, and the payload says it (`released_at_return`)."""
        self.expect("CLOSING", 120)
        self.closed = self.expect("CLOSED")
        if self.closed is None:
            self.release()
            self.closed = self.expect("CLOSED")
        return self.closed

    def why(self):
        return "the client said:\n%s\n%s" % ("".join(self.stdout)[-2000:], "".join(self.stderr)[-4000:])

    def end(self):
        self.release()
        try:
            self.proc.wait(timeout=NET)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        return self.proc.returncode


def _drive(tmp_path, how, *, sender=True, content=False):
    run = _Run(tmp_path, how, sender, content)
    try:
        if content:
            run.expect("CLOSING", 120)
            run.held = run.expect("HELD")
            run.release()                                     # the test lets the held process go: only now may `close()` return
            run.closed = run.expect("CLOSED")
        elif how == "exit":
            run.closed_or_release()
            # The interpreter cannot end while the sender lives: the reaper is not a daemon.
            run.running_at_close = run.proc.poll() is None
        else:
            run.closed_or_release()
            run.release()                                     # the sender is let finish only after `close()` has returned
        if how != "exit":
            run.final = run.expect("REPORT")
    finally:
        run.returncode = run.end()
    return run


@pytest.fixture(scope="module", params=["sync", "async"])
def report(request, tmp_path_factory):
    """One run of the client per path (the sync `close` and the async `aclose`), a sender that lives until the test lets it go."""
    return _drive(tmp_path_factory.mktemp("exited_" + request.param), request.param)


@pytest.fixture(scope="module")
def held_run(tmp_path_factory):
    """One run with a process of the browser that is not a sender, held alive by the test across the close."""
    return _drive(tmp_path_factory.mktemp("held"), "held", sender=False, content=True)


def test_close_returns_when_the_browser_has_exited_not_when_the_sender_has(report):
    """Red on the close that waits for the whole tree: the sender is held until the test releases it, and a close that waits for it
    returns only after that (`released_at_return`), with the sender done."""
    closed = report.closed
    assert closed, report.why()
    assert closed["bye"] is True, "the stand-in engine never said it was leaving: %r" % closed
    assert closed["released_at_return"] is False, "close() returned only after the sender had been let go: it waited for it"
    assert closed["marker"] is False, "close() waited for the sender: it had finished when it returned"
    engine, sender = closed["pids"][:3], closed["pids"][3]
    assert sender in closed["alive"], "the sender was gone when close() returned (it was ended, or waited for)"
    # What belongs to the browser is gone: the engine and its two children.
    assert not set(engine) & set(closed["alive"]), "a process of the browser was alive when close() returned: %r" % closed


def test_the_sender_is_not_killed_it_finishes_with_its_own_result(report):
    """It holds a file of the session and says so when it has finished: that is only written by a run that was not ended."""
    assert report.final, report.why()
    assert report.final["marker_text"] == "done", "the sender was ended before it finished: %r" % report.final
    assert report.final["after"]["marker"] is True


def test_after_the_reaper_no_process_of_the_tree_remains_and_the_directories_are_gone(report):
    assert report.final, report.why()
    assert report.final["reaped"] is True, "the reaper had not finished when it was waited for (the safety net)"
    assert report.final["after"]["alive"] == [], "processes of the closed browser are alive: %s" % report.final["after"]["alive"]
    assert report.final["after"]["dirs"] == [], "the closed browser left its directories: %s" % report.final["after"]["dirs"]


def test_waiting_for_the_reaper_of_an_empty_tree_costs_no_fixed_wait(tmp_path):
    """Nothing outlives the browser, and nothing is held or released: the reaper finishes by itself. `SENDER_GRACE` is a bound, not a
    sleep: the reaper's thread asked to sleep for no fixed time (a poll is a few milliseconds, a grace would be a call of its own)."""
    run = _drive(tmp_path, "sync", sender=False)
    assert run.final, run.why()
    assert run.final["reaped"] is True, "the reaper of an empty tree had not finished (the safety net)"
    assert run.final["after"]["alive"] == [] and run.final["after"]["dirs"] == []
    assert [s for s in run.final["reaper_sleeps"] if s >= 0.1] == [], "the reaper slept: %r" % run.final["reaper_sleeps"]


def test_a_process_of_the_browser_that_is_not_a_sender_is_waited_for(held_run):
    """Recognised by what it is, never as whoever is left: a child the engine leaves with no `pingsender` and no `-backgroundtask`
    on its command line is part of the browser. While the test holds it alive, after the engine is gone and after the tree has been
    asked about it again and again, `close()` is still running, and it returns only after the test has let the process go."""
    held = held_run.held
    assert held, held_run.why()
    engine, content = held["pids"][0], held["pids"][-1]
    assert engine not in held["alive"] and content in held["alive"], "the engine is not gone, or the held process is: %r" % held
    assert len(held["answers"]) >= 5 and not any(held["answers"]), "the held process was taken for a sender: %r" % held["answers"]
    assert held["closing"] is True, "close() returned with a process of the browser still alive: %r" % held
    closed = held_run.closed
    assert closed["released_at_return"] is True, "close() returned before the held process was let go"
    assert closed["alive"] == [], "a process of the browser was alive when close() returned: %r" % closed


@pytest.mark.skipif(sys.platform != "win32", reason="a Windows process has its final command line from its creation")
def test_on_windows_a_command_line_is_read_once_per_process_during_a_close(held_run):
    """The loop that waits for the browser to be gone looks again and again: a process that is not a sender stays in it for as long as
    it is held (here, until at least five looks have been made at it), and its command line (a read of the process's PEB, under the
    GIL) was read on every look. Counted, not timed."""
    assert held_run.final, held_run.why()
    reads = held_run.final["reads"]
    assert reads, "no command line was read: the seam is not the one the tree reads through"
    assert max(reads.values()) <= 1, "a command line was read more than once: %r" % reads


def test_the_end_of_the_interpreter_waits_for_the_reaper_and_leaves_nothing(tmp_path):
    """A program that closes its browser and ends, without waiting for anything: the reaper is not a daemon, so the interpreter
    does not end under it. While the sender is held the program is still running after `close()` has returned; once the test lets the
    sender go the program ends, no process of the tree is alive, the session's directories are gone, and the sender had finished (it
    was the end of the interpreter that waited, not a kill)."""
    import psutil

    run = _drive(tmp_path, "exit")
    closed = run.closed
    assert closed, run.why()
    assert closed["released_at_return"] is False and closed["marker"] is False, (
        "the close waited for the sender, so this proves nothing about the end of the interpreter: %r" % closed)
    assert run.running_at_close is True, "the interpreter had ended with the sender still alive: nothing waited for the reaper"
    assert run.returncode == 0, run.why()
    left = [p for p in closed["pids"] if psutil.pid_exists(p) and psutil.Process(p).status() != psutil.STATUS_ZOMBIE]
    assert left == [], "processes of the tree outlived the interpreter: %s" % left
    assert [d for d in closed["dirs"] if os.path.exists(d)] == [], "the session's directories outlived the interpreter"
    assert (run.dir / "sender").read_text() == "done", "the sender was ended instead of being let finish"


# ── the pieces ──────────────────────────────────────────────────────────────

#: The sender's command line on Windows, as seen 67 times in one GitHub run (the directories and the uuid tail made up): the executable is the
#: browser's own, and the task is `--backgroundtask pingsender`.
WINDOWS_SENDER = [
    r"D:\cache\invisible-playwright\Cache\firefox-64_159.0_20261114003728\firefox.exe",
    "--backgroundtask", "pingsender",
    "https://incoming.telemetry.mozilla.org/submit/telemetry/de30146e-596a-4c1b-9d27-5e8f0a1b2c3d/event/Firefox/159.0/"
    "release/20261114003728?v=4",
]
WINDOWS_PARENT = [WINDOWS_SENDER[0], "-no-remote", "-profile", r"D:\temp\invisible_profile_1_ab",
                  "-juggler-pipe"]
WINDOWS_CONTENT = [WINDOWS_SENDER[0], "-contentproc", "--channel=1234.0.1234", "-childID", "1", "-isForBrowser", "-prefsHandle", "800",
                   "-prefMapHandle", "804", "-jsInitHandle", "808", "-parentBuildID", "20261114003728", "tab"]


@pytest.mark.unit
@pytest.mark.parametrize("command", [
    WINDOWS_SENDER,
    # Linux: no real line has been captured yet (a hunt will); both forms Firefox can be started in are accepted until then:
    # the `pingsender` binary as argv[0], and the browser itself with the background task.
    ["pingsender", "https://example.invalid/", "ping.json"],
    ["C:\\Program Files\\Mozilla Firefox\\pingsender.exe", "https://example.invalid/", "ping.json"],
    ["/opt/firefox/pingsender", "x"],
    ["/opt/firefox/PingSender.EXE"],
    ["firefox", "-backgroundtask", "pingsender"],
    ["/opt/firefox/firefox", "--backgroundtask", "pingsender", "https://incoming.telemetry.mozilla.org/submit/x"],
    ["C:\\fx\\firefox.exe", "--backgroundtask", "pingsender"],
    ["firefox.exe", "/BackgroundTask", "x"],
])
def test_a_sender_and_a_background_task_are_known_by_their_command_line(command):
    assert P.outlives_the_browser(command) is True


@pytest.mark.unit
@pytest.mark.parametrize("command", [
    WINDOWS_PARENT,
    WINDOWS_CONTENT,
    [],
    None,
    ["firefox", "-contentproc", "-childID", "1", "tab"],
    ["firefox", "-no-remote", "-profile", "C:\\invisible_profile_1"],
    ["/opt/firefox/firefox", "-profile", "/tmp/pingsender"],       # the name of a directory is not the name of a program
    ["firefox", "-backgroundtasks"],
    ["firefox", "backgroundtask"],
    ["pingsender-not-really", "x"],
])
def test_a_process_of_the_browser_is_not_taken_for_a_sender(command):
    assert P.outlives_the_browser(command) is False


@pytest.mark.unit
@pytest.mark.parametrize("final, reads", [(True, 1), (False, 25)])
def test_a_command_line_is_read_once_where_it_is_final_and_asked_again_where_it_is_not(monkeypatch, final, reads):
    """Windows (a process has its final command line from birth): one read per pid, yes or no. POSIX (fork, then exec): a no is
    asked again, because a child not yet executed still reads as its parent, and a yes is kept."""
    seen = []
    monkeypatch.setattr(P, "_command_line_is_final", lambda: final)
    monkeypatch.setattr(P, "_command_line_of", lambda pid: (seen.append(pid), WINDOWS_CONTENT)[1])
    tree = P.EngineTree(os.getpid())
    answers = [tree._survives(1234) for _ in range(25)]
    assert answers == [False] * 25
    assert len(seen) == reads, "%d reads for a process looked at 25 times" % len(seen)
    seen.clear()
    monkeypatch.setattr(P, "_command_line_of", lambda pid: (seen.append(pid), WINDOWS_SENDER)[1])
    assert [tree._survives(99) for _ in range(25)] == [True] * 25
    assert len(seen) == 1, "a sender is known once it is read"


@pytest.mark.unit
def test_a_command_line_that_cannot_be_read_is_asked_again_on_every_platform(monkeypatch):
    seen = []

    def denied(pid):
        seen.append(pid)
        raise PermissionError("not ours")

    monkeypatch.setattr(P, "_command_line_of", denied)
    tree = P.EngineTree(os.getpid())
    assert [tree._survives(7) for _ in range(3)] == [False] * 3
    assert len(seen) == 3


#: The leader of a group: a sender (argv[0] `pingsender`, held for ever) and a process that is not one (held until `release`), both
#: running before it says `up` and exits.
_LEADER = textwrap.dedent("""
    import os, subprocess, sys, time
    release, never, a, b = sys.argv[1:5]
    HOLD = ("import os, sys, time\\n"
            "open(sys.argv[1], 'w').close()\\n"
            "while not os.path.exists(sys.argv[2]):\\n"
            "    time.sleep(0.01)\\n")
    subprocess.Popen(['pingsender', '-c', HOLD, a, never], executable=sys.executable)
    subprocess.Popen([sys.executable, '-c', HOLD, b, release])
    while not (os.path.exists(a) and os.path.exists(b)):
        time.sleep(0.01)
    print('up', flush=True)
""")


@pytest.mark.unit
@pytest.mark.skipif(sys.platform == "win32", reason="argv[0] by `executable=` is POSIX")
def test_a_group_is_gone_when_only_a_sender_is_left_in_it(tmp_path):
    """The group's own answer, with no engine and no connection: the leader has exited, a child that is not a sender is in the group
    (not gone), and then one that is (gone, and not ended)."""
    release, never = tmp_path / "release", tmp_path / "never"
    started = [tmp_path / "sender_started", tmp_path / "other_started"]
    leader = subprocess.Popen(
        [sys.executable, "-c", _LEADER, str(release), str(never), *map(str, started)],
        process_group=0, stdout=subprocess.PIPE, text=True)
    try:
        assert leader.stdout.readline().strip() == "up"
        leader.wait(timeout=NET)
        tree = P.EngineTree(leader.pid, group=True, poll=leader.poll)
        # One look (a deadline that is already past): the process that is not a sender is in the group, held by the test.
        assert tree.wait_browser_gone(time.monotonic() - 1) is False, "a process that is not a sender was let be"
        release.write_text("go")
        assert tree.wait_browser_gone(time.monotonic() + NET) is True       # the net: it returns when that process has gone
        assert tree._group_alive(), "the sender was ended"
    finally:
        try:
            os.killpg(leader.pid, 9)
        except OSError:
            pass
