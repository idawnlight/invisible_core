"""The engine is created INSIDE a job object of its own, so its tree dies with the launch or with the process, and nothing searches the machine for it.

Until now the engine was started outside any job and the wrapper adopted it afterwards: `JobObjectGuard.bind` scanned EVERY process
of the machine (`find_processes`, the environment of each read under the GIL), slept a quarter of a second, and scanned again until
a second passed with nothing new, up to ten. py-spy on a Windows runner put that loop at 12-29% of the launching thread and most
of the GIL samples, synchronously on the caller's event loop. Adopting afterwards was also the weaker guarantee: Firefox puts its
content processes in sandbox jobs of their own, and `AssignProcessToJobObject` refuses those (ERROR_ACCESS_DENIED).

Now `juggler.connection._spawn_windows` makes one `EngineJob` per launch (kill-on-close, nothing that lets a child leave), creates
the engine suspended, assigns it while it is alone and resumes it, and the kernel creates every later process of the tree (the
launcher's browser, content, GPU, socket, the pingsender at shutdown) inside the same job. `Connection.close` waits for the job to
empty, then closes its handle: what is left of THAT launch ends, and no other browser's process is touched. A client that dies
takes the handle with it, and the kernel ends every engine it launched.

Two halves, by what each needs:

* the first part is the default selection (core CI, Linux and Windows): the policy of `adopt_and_resume` on a fake kernel32 (the
  order, and that a failure never leaves the engine suspended) and, on Windows, the real job (a new one each time, its limit
  flags kill-on-close and nothing that lets a child leave);
* the second part is e2e and Windows only (`engine-born-in-the-job` job of ci.yml, and any run of `-m e2e` on Windows): the real
  `_spawn_windows`, with a Python process standing for the engine because the property is the spawn's, not the browser's, then
  the same with the real engine when `INVPW_BINARY_PATH` names one.
"""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import threading
import time

import pytest

from invisible_core import process as P

WINDOWS = sys.platform == "win32"


# ── default selection: the policy, on any platform ──────────────────────────

class _Kernel32:
    """The three calls `adopt_and_resume` makes, recording their order."""

    def __init__(self, assign=True, resume=1, assign_error=0, resume_error=0):
        self.calls = []
        self._assign, self._resume = assign, resume
        self._assign_error, self._resume_error = assign_error, resume_error
        self.last_error = 0   # the thread's last error, as the real calls leave it (ctypes.set_last_error is Windows-only)

        class _Fn:
            def __init__(self, fn):
                self._fn = fn
                self.argtypes = self.restype = None

            def __call__(self, *a):
                return self._fn(*a)

        self.AssignProcessToJobObject = _Fn(self._do_assign)
        self.ResumeThread = _Fn(self._do_resume)

    def _do_assign(self, job, process):
        self.calls.append(("assign", job, process))
        self.last_error = self._assign_error
        return self._assign

    def _do_resume(self, thread):
        self.calls.append(("resume", thread))
        self.last_error = self._resume_error
        return self._resume


@pytest.mark.unit
def test_the_process_is_assigned_to_the_job_before_it_runs():
    k = _Kernel32()
    job = P.EngineJob(handle=11, kernel32=k, last_error=lambda: k.last_error)
    assert job.adopt_and_resume(22, 33) == (True, 0)
    assert [c[0] for c in k.calls] == ["assign", "resume"], (
        "the thread ran before the process was in the job: whatever it created "
        "in between is outside it")
    assert k.calls[0][1:] == (11, 22) and k.calls[1][1:] == (33,)


@pytest.mark.unit
def test_a_refused_assignment_still_resumes_the_engine_and_says_so():
    """A launch that works without the guarantee beats a launch that hangs."""
    k = _Kernel32(assign=False)
    job = P.EngineJob(handle=11, kernel32=k, last_error=lambda: k.last_error)
    with pytest.warns(RuntimeWarning):
        assert job.adopt_and_resume(22, 33)[0] is False
    assert [c[0] for c in k.calls] == ["assign", "resume"]


@pytest.mark.unit
def test_the_warning_names_the_error_of_the_assignment_not_of_the_resume():
    """The assignment fails with 5 (ERROR_ACCESS_DENIED) and ResumeThread then
    leaves another last error: the code reported is the assignment's."""
    k = _Kernel32(assign=False, assign_error=5, resume_error=1816)
    job = P.EngineJob(handle=11, kernel32=k, last_error=lambda: k.last_error)
    with pytest.warns(RuntimeWarning, match=r"\(error 5\)") as seen:
        assigned, error = job.adopt_and_resume(22, 33)
    assert (assigned, error) == (False, 5)
    assert k.last_error == 1816, "the resume did not leave its own error: the test proves nothing"
    assert "1816" not in str(seen[0].message)


@pytest.mark.unit
def test_an_engine_that_cannot_be_resumed_is_an_error_not_a_silent_hang():
    k = _Kernel32(resume=0xFFFFFFFF)
    job = P.EngineJob(handle=11, kernel32=k, last_error=lambda: k.last_error)
    with pytest.raises(OSError):
        job.adopt_and_resume(22, 33)


@pytest.mark.unit
def test_where_there_is_no_job_the_spawn_asks_for_none():
    assert P.EngineJob.create(platform="posix") is None


@pytest.mark.unit
@pytest.mark.skipif(not WINDOWS, reason="the job object is Windows")
def test_every_launch_has_a_job_of_its_own_that_only_kills_on_close():
    """One job per launch: closing one browser's can never reach another's.
    And no flag that lets a child leave it."""
    import ctypes
    from ctypes import wintypes

    a, b = P.EngineJob.create(), P.EngineJob.create()
    try:
        assert a is not None and b is not None and a.handle != b.handle

        info = P._ExtendedLimitInformation()
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.QueryInformationJobObject.argtypes = [
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
            ctypes.c_void_p]
        assert k.QueryInformationJobObject(
            a.handle, P.EngineJob._EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(info), ctypes.sizeof(info), None)
        flags = info.BasicLimitInformation.LimitFlags
        breakaway_ok, silent_breakaway_ok = 0x0800, 0x1000
        assert flags & P.EngineJob._KILL_ON_JOB_CLOSE
        assert not flags & breakaway_ok, "a child could ask to leave the job"
        assert not flags & silent_breakaway_ok, "every child could leave the job"
        assert flags == P.EngineJob._KILL_ON_JOB_CLOSE
        assert a.active() == 0
        assert a.wait_empty(time.monotonic() + 1) is True
    finally:
        for job in (a, b):
            if job is not None:
                job.close()
                job.close()          # idempotent


# ── e2e, Windows: the real spawn ────────────────────────────────────────────

#: What stands for the engine. ``stays`` keeps running, as the browser does;
#: ``stub`` starts its child and EXITS, as `firefox.exe` the launcher does, so
#: the child's parent is gone and only the job can still say whose it is. Each
#: starts a child at once and one more 1.5 s later (the late children: content,
#: GPU, socket, the pingsender), and prints every pid it made.
_ENGINE = textwrap.dedent("""
    import os, subprocess, sys, time
    SLEEP = [sys.executable, "-c", "import time; time.sleep(120)"]
    def child():
        k = subprocess.Popen(SLEEP)
        print("PID", k.pid, flush=True)
    print("PID", os.getpid(), flush=True)
    child()
    time.sleep(1.5)
    child()
    print("READY", flush=True)
    if sys.argv[1:] != ["stub"]:
        time.sleep(120)
""")


def _read_until_ready(stream, timeout=60.0):
    """The pids the engine printed, up to READY, or a failure naming what was read."""
    pids, lines = [], []

    def read():
        for raw in iter(stream.readline, b""):
            text = raw.decode("ascii", "replace").strip()
            lines.append(text)
            if text.startswith("PID "):
                pids.append(int(text.split()[1]))
            if text == "READY":
                return

    t = threading.Thread(target=read, daemon=True)
    t.start()
    t.join(timeout)
    assert "READY" in lines, "the stand-in engine never said READY: %r" % lines
    return pids


def _in_job(pid, job):
    import ctypes
    from ctypes import wintypes

    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.OpenProcess.restype = wintypes.HANDLE
    k.IsProcessInJob.argtypes = [wintypes.HANDLE, wintypes.HANDLE,
                                 ctypes.POINTER(wintypes.BOOL)]
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    h = k.OpenProcess(0x1000, False, pid)        # PROCESS_QUERY_LIMITED_INFORMATION
    assert h, "pid %d is not there to ask about" % pid
    try:
        flag = wintypes.BOOL(0)
        assert k.IsProcessInJob(h, job, ctypes.byref(flag))
        return bool(flag.value)
    finally:
        k.CloseHandle(h)


def _wait_all_gone(procs, timeout):
    import psutil

    _, alive = psutil.wait_procs(procs, timeout=timeout)
    return alive


def _release(spawned):
    """The pipe ends and the handle of a stand-in, closed; and the process ended."""
    to_browser, from_browser, p = spawned
    p.terminate()
    for fd in (to_browser, from_browser):
        try:
            os.close(fd)
        except OSError:
            pass
    try:
        p.stdout.close()
    except Exception:
        pass


@pytest.mark.e2e
@pytest.mark.skipif(not WINDOWS, reason="the job object is Windows")
@pytest.mark.parametrize("shape", ["stays", "stub"])
def test_the_engine_and_every_late_child_are_born_in_its_launchs_job(shape, monkeypatch):
    """Red on the old spawn, which created the engine outside every job.

    Also the other claim of this change, asserted on the CALLS: the spawn
    reads no process of the machine and no environment of one."""
    import psutil
    from invisible_core.juggler import connection

    scans = []
    real_iter, real_environ = psutil.process_iter, psutil.Process.environ
    monkeypatch.setattr(psutil, "process_iter",
                        lambda *a, **k: (scans.append("process_iter"),
                                         real_iter(*a, **k))[1])
    monkeypatch.setattr(psutil.Process, "environ",
                        lambda self: (scans.append("environ"),
                                      real_environ(self))[1])

    spawned = connection._spawn_windows(
        sys.executable, ["-c", _ENGINE, shape], dict(os.environ))
    procs = []
    try:
        assert spawned[2].in_job is True
        pids = _read_until_ready(spawned[2].stdout)
        procs = [psutil.Process(p) for p in pids if psutil.pid_exists(p)]
        job = spawned[2].job.handle
        outside = [pid for pid in pids
                   if psutil.pid_exists(pid) and not _in_job(pid, job)]
        assert len(pids) == 3, pids      # the engine and its two children
        assert not outside, (
            "created outside the job: %s (a child of a job member joins it "
            "unless the job lets it leave)" % outside)
        assert not scans, (
            "the spawn read the machine's processes: %d calls" % len(scans))
    finally:
        _release(spawned)
        P.terminate(procs)


def _pids_of(spawned):
    return _read_until_ready(spawned[2].stdout)


@pytest.mark.e2e
@pytest.mark.skipif(not WINDOWS, reason="the job object is Windows")
def test_closing_one_launch_leaves_the_other_s_tree_alive():
    """Two launches in one Python process, each in a job of its own. Closing
    the first (`Connection.close`, which waits for its job to empty and then
    closes it) ends all of ITS tree, the late children included, and none of
    the second's; the second is then closed the same way. The first is a
    stand-in that stays, the second one whose launcher stub has already exited
    (so only its job still says whose its children are)."""
    import psutil
    from invisible_core.juggler import connection

    first = connection._spawn_windows(sys.executable, ["-c", _ENGINE, "stays"],
                                      dict(os.environ))
    second = connection._spawn_windows(sys.executable, ["-c", _ENGINE, "stub"],
                                       dict(os.environ))
    mine, theirs = [], []
    conns = []
    try:
        assert first[2].job.handle != second[2].job.handle
        a, b = _pids_of(first), _pids_of(second)
        mine = [psutil.Process(p) for p in a if psutil.pid_exists(p)]
        # b[0] is the stub itself, which exits on its own: only its children are asked about.
        theirs = [psutil.Process(p) for p in b[1:] if psutil.pid_exists(p)]
        assert len(theirs) == 2, b
        job_a, job_b = first[2].job.handle, second[2].job.handle
        assert not any(psutil.pid_exists(p) and _in_job(p, job_b) for p in a), (
            "a process of the first launch is in the second launch's job")
        assert not any(psutil.pid_exists(p) and _in_job(p, job_a) for p in b), (
            "a process of the second launch is in the first launch's job")

        conns = [connection.Connection(first[0], first[1], first[2]),
                 connection.Connection(second[0], second[1], second[2])]
        conns[0].close(timeout=1)
        assert not _wait_all_gone(mine, timeout=20), "the first launch's tree survived its close()"
        assert all(p.is_running() for p in theirs), (
            "closing the first launch ended a process of the second: %s"
            % [p.pid for p in theirs if not p.is_running()])

        conns[1].close(timeout=1)
        assert not _wait_all_gone(theirs, timeout=20), (
            "the second launch's late children survived its close()")
    finally:
        for c in conns:
            c.close(timeout=1)
        for s in (first, second):
            _release(s)
        P.terminate([p for p in mine + theirs if p.is_running()])


_CLIENT = textwrap.dedent("""
    import os, sys, time
    from invisible_core.juggler import connection
    engine = {engine!r}
    spawned = connection._spawn_windows(sys.executable, ["-c", engine], dict(os.environ))
    for raw in iter(spawned[2].stdout.readline, b""):
        text = raw.decode("ascii", "replace").strip()
        print(text, flush=True)
        if text == "READY":
            break
    print("INJOB", spawned[2].in_job, flush=True)
    print("CLIENT", os.getpid(), flush=True)
    time.sleep(120)
""")


@pytest.mark.e2e
@pytest.mark.skipif(not WINDOWS, reason="the job object is Windows")
def test_when_the_client_is_killed_every_engine_process_is_gone(tmp_path):
    """The killed-runner path, where no teardown runs: a client that launches
    and is ended with TerminateProcess leaves nothing. Red on the old spawn
    (nothing but the wrapper's later adoption held the tree)."""
    import psutil

    script = tmp_path / "client.py"
    script.write_text(_CLIENT.format(engine=_ENGINE), encoding="utf-8")
    client = subprocess.Popen([sys.executable, str(script)],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    procs = []
    try:
        lines = []

        def read():
            for raw in iter(client.stdout.readline, b""):
                lines.append(raw.decode("ascii", "replace").strip())
                if lines[-1].startswith("CLIENT"):
                    return

        t = threading.Thread(target=read, daemon=True)
        t.start()
        t.join(90)
        pids = [int(x.split()[1]) for x in lines if x.startswith("PID ")]
        assert any(x.startswith("CLIENT") for x in lines) and len(pids) == 3, lines
        procs = [psutil.Process(p) for p in pids] + [psutil.Process(client.pid)]

        client.kill()                        # TerminateProcess: no teardown runs
        alive = _wait_all_gone(procs, timeout=20)
        assert not alive, (
            "the client was killed and these are still running: %s"
            % [(p.pid, p.name()) for p in alive])
    finally:
        client.kill()
        P.terminate([p for p in procs if p.is_running()])


# ── e2e, Windows: a client that is ALREADY inside a job ─────────────────────
#
# GitHub's runners and Windows services run their children in a job. Windows 8 and later nest jobs, so a process already in
# one can be assigned to a new one with no breakaway flag; these tests start the client inside an outer job that has NO flag at
# all (it does not even kill on close, so only the launch's own job can end the tree) and ask for the same three things.

def _outer_job():
    """A job with no limit at all, and its handle (held by the test, never closed before the end)."""
    import ctypes

    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateJobObjectW.restype = ctypes.c_void_p
    handle = k.CreateJobObjectW(None, None)
    assert handle
    return handle


def _client_in(outer, script, *args):
    """A Python process created suspended, put in `outer`, then resumed."""
    import ctypes
    import psutil
    from ctypes import wintypes

    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    k.AssignProcessToJobObject.restype = wintypes.BOOL
    proc = subprocess.Popen([sys.executable, str(script), *args],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            creationflags=0x4)            # CREATE_SUSPENDED
    assert k.AssignProcessToJobObject(outer, int(proc._handle)), (
        "the test could not put its client in the outer job: %d" % ctypes.get_last_error())
    psutil.Process(proc.pid).resume()
    return proc


def _lines_until(proc, marker, timeout=90):
    lines = []

    def read():
        for raw in iter(proc.stdout.readline, b""):
            lines.append(raw.decode("ascii", "replace").strip())
            if lines[-1].startswith(marker):
                return

    t = threading.Thread(target=read, daemon=True)
    t.start()
    t.join(timeout)
    assert any(x.startswith(marker) for x in lines), lines
    return lines


def _end_outer(outer):
    import ctypes

    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.TerminateJobObject.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    k.CloseHandle.argtypes = [ctypes.c_void_p]
    k.TerminateJobObject(outer, 1)
    k.CloseHandle(outer)


@pytest.fixture
def nested_client(tmp_path):
    """(client, outer job handle) of `_CLIENT` started inside the outer job; ended afterwards."""
    script = tmp_path / "client.py"
    script.write_text(_CLIENT.format(engine=_ENGINE), encoding="utf-8")
    outer = _outer_job()
    client = _client_in(outer, script)
    try:
        yield client, outer
    finally:
        client.kill()
        _end_outer(outer)


@pytest.mark.e2e
@pytest.mark.skipif(not WINDOWS, reason="the job object is Windows")
def test_a_client_already_in_a_job_gets_its_engine_in_the_launch_s_job_nested(nested_client):
    """The assignment into the launch's job succeeds under an outer job, no breakaway flag: the spawn says
    so (`in_job`), and every process of the tree is below the outer job too, which is what nesting is."""
    import psutil

    client, outer = nested_client
    lines = _lines_until(client, "CLIENT")
    assert "INJOB True" in lines, (
        "the engine was not put in the launch's job under an outer job: %r" % lines)
    pids = [int(x.split()[1]) for x in lines if x.startswith("PID ")]
    assert len(pids) == 3, pids
    outside = [p for p in pids if psutil.pid_exists(p) and not _in_job(p, outer)]
    assert not outside, "outside the outer job: %s" % outside


@pytest.mark.e2e
@pytest.mark.skipif(not WINDOWS, reason="the job object is Windows")
def test_killing_a_client_that_is_inside_a_job_ends_the_engine_tree(nested_client):
    """The outer job has no kill-on-close, so what ends the tree is the launch's own job, nested in it."""
    import psutil

    client, outer = nested_client
    lines = _lines_until(client, "CLIENT")
    pids = [int(x.split()[1]) for x in lines if x.startswith("PID ")]
    procs = [psutil.Process(p) for p in pids] + [psutil.Process(client.pid)]
    try:
        client.kill()
        alive = _wait_all_gone(procs, timeout=20)
        assert not alive, "survivors of the killed client: %s" % [
            (p.pid, p.name()) for p in alive]
    finally:
        P.terminate([p for p in procs if p.is_running()])


_TWO = textwrap.dedent("""
    import os, sys, time
    import psutil
    from invisible_core.juggler import connection
    engine = {engine!r}
    def launch():
        s = connection._spawn_windows(sys.executable, ["-c", engine], dict(os.environ))
        pids = []
        for raw in iter(s[2].stdout.readline, b""):
            text = raw.decode("ascii", "replace").strip()
            if text.startswith("PID "):
                pids.append(int(text.split()[1]))
            if text == "READY":
                break
        return s, pids
    (a, pa), (b, pb) = launch(), launch()
    print("INJOB", a[2].in_job, b[2].in_job, flush=True)
    ca = connection.Connection(a[0], a[1], a[2])
    cb = connection.Connection(b[0], b[1], b[2])
    procs_a = [psutil.Process(p) for p in pa]
    ca.close(timeout=1)
    gone, alive_a = psutil.wait_procs(procs_a, timeout=20)
    b_alive = all(psutil.pid_exists(p) for p in pb)
    print("RESULT", len(alive_a) == 0, b_alive, flush=True)
    cb.close(timeout=1)
    time.sleep(1)
""")


@pytest.mark.e2e
@pytest.mark.skipif(not WINDOWS, reason="the job object is Windows")
def test_closing_one_launch_leaves_the_other_s_tree_alive_under_an_outer_job(tmp_path):
    """Two launches in one process that is itself inside a job: each in its own nested job; closing the
    first ends all of its tree and none of the second's."""
    script = tmp_path / "two.py"
    script.write_text(_TWO.replace("{engine!r}", repr(_ENGINE)), encoding="utf-8")
    outer = _outer_job()
    client = _client_in(outer, script)
    try:
        lines = _lines_until(client, "RESULT", timeout=120)
        assert "INJOB True True" in lines, lines
        assert "RESULT True True" in lines, (
            "closing the first launch: its tree gone, the second's alive = True True; got %r" % lines)
    finally:
        client.kill()
        _end_outer(outer)


# ── e2e, Windows, the real engine ───────────────────────────────────────────

def _binary():
    path = os.environ.get("INVPW_BINARY_PATH", "")
    if not path or not os.path.isfile(path):
        pytest.skip("INVPW_BINARY_PATH names no firefox binary")
    return path


_ENGINE_CLIENT = textwrap.dedent("""
    import os, sys, time
    from invisible_core import build_launch_env
    from invisible_core._fpforge import generate_profile
    from invisible_core.juggler.instance import launch
    from invisible_core.prefs import compose_session_prefs
    from invisible_core.process import SessionToken

    binary, profile_dir, keep = sys.argv[1:4]
    token = SessionToken.mint()
    profile = generate_profile(seed=20261114)
    prefs = dict(compose_session_prefs(
        profile, locale="en-US", timezone="America/New_York").prefs)
    browser = launch(binary, prefs=prefs, profile_dir=profile_dir,
                     env=token.stamp(build_launch_env(prefs)), headless=True,
                     ready_timeout=120)
    page = browser.new_context().new_page()
    page.lifecycle.goto("data:text/html,<p>born in the job</p>", until="load")
    print("TOKEN", token.value, flush=True)
    if keep == "close":
        browser.close()
        print("CLOSED", flush=True)
    time.sleep(120)
""")


def _run_engine_client(tmp_path, keep):
    binary = _binary()
    script = tmp_path / "engine_client.py"
    script.write_text(_ENGINE_CLIENT, encoding="utf-8")
    client = subprocess.Popen(
        [sys.executable, str(script), binary, str(tmp_path / "profile"), keep],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        # A session of its own on POSIX: its process group is the client's alone, which is what a terminal's Ctrl+C reaches.
        start_new_session=not WINDOWS)
    lines = []
    marker = "CLOSED" if keep == "close" else "TOKEN"

    def read():
        for raw in iter(client.stdout.readline, b""):
            lines.append(raw.decode("utf-8", "replace").strip())
            if lines[-1].startswith(marker):
                return

    t = threading.Thread(target=read, daemon=True)
    t.start()
    t.join(180)
    token = next((x.split()[1] for x in lines if x.startswith("TOKEN ")), "")
    assert token and any(x.startswith(marker) for x in lines), lines
    return client, P.SessionToken(token)


@pytest.mark.e2e
def test_a_killed_client_leaves_no_engine_process(tmp_path):
    """Item 3 with the real engine: a Python process that launches the browser,
    opens a page (so content processes exist) and is killed (TerminateProcess on
    Windows, SIGKILL elsewhere: no teardown runs); every process that carries the
    session's token goes. On Windows the job ends the tree; on POSIX the engine,
    in a process group of its own, ends by itself when the client's end of the
    Juggler pipe closes (`nsRemoteDebuggingPipe`: end of input is `Browser.close`)."""
    client, token = _run_engine_client(tmp_path, keep="open")
    try:
        tree = P.find_processes(token)
        assert len(tree) >= 2, "the engine's tree was not there to be killed"
        client.kill()
        alive = _wait_all_gone(tree, timeout=30)
        assert not alive, "survivors of the killed client: %s" % [
            (p.pid, p.name()) for p in alive]
    finally:
        client.kill()
        P.terminate(P.find_processes(token))


@pytest.mark.e2e
@pytest.mark.skipif(WINDOWS, reason="a terminal's Ctrl+C reaches a process group: POSIX")
def test_an_interrupted_client_leaves_no_engine_process(tmp_path):
    """What the engine's own process group costs: a Ctrl+C at the terminal reaches the client's group and no longer the engine's.
    SIGINT to the client's group, as the terminal sends it; the client ends (nothing handles it: KeyboardInterrupt out of the
    script) and every process that carries the session's token goes, because the pipe closes with the client."""
    import signal

    client, token = _run_engine_client(tmp_path, keep="open")
    try:
        tree = P.find_processes(token)
        assert len(tree) >= 2, "the engine's tree was not there to be ended"
        assert os.getpgid(client.pid) == client.pid, "the client is not the leader of the group the test interrupts"
        assert all(os.getpgid(p.pid) != client.pid for p in tree), (
            "a process of the engine's tree is in the client's group: Ctrl+C would reach it")
        os.killpg(client.pid, signal.SIGINT)
        client.wait(timeout=60)
        alive = _wait_all_gone(tree, timeout=60)
        assert not alive, "survivors of the interrupted client: %s" % [
            (p.pid, p.name()) for p in alive]
    finally:
        if client.poll() is None:
            client.kill()
        P.terminate(P.find_processes(token))


@pytest.mark.e2e
def test_after_close_no_process_of_the_session_is_left(tmp_path):
    """Item 2 with the real engine: `Browser.close()` ends the whole tree,
    the late children (the pingsender that outlives the browser) included."""
    client, token = _run_engine_client(tmp_path, keep="close")
    try:
        assert P.wait_until_gone(token, timeout=30), (
            "processes of the session are left after close(): %s" % [
                (p.pid, p.name()) for p in P.find_processes(token)])
    finally:
        client.kill()
        P.terminate(P.find_processes(token))
