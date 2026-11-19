"""Make a browser tree die when the process that launched it does.

SHARED BY EVERY PRODUCT THAT LAUNCHES A BROWSER, which is why it lives here -
written when there were two: each of them launched the patched Firefox and
each of them had the same problem; the automation wrapper solved it in
2026-07-26 and the profile manager did not, so on 2026-07-27 the manager still
leaked its ENTIRE tree every single time it was killed - measured at eight
surviving processes, three runs out of three, 100%. Two copies of this would
have been two chances to fix it once. The manager was deleted 2026-08-18; the
module is unchanged by that, because it was never written FOR a fixed count of
consumers.

THE BUG IT EXISTS FOR
---------------------
Twelve runs of one test left eleven browsers alive. The first diagnosis blamed
"any path where teardown does not run cleanly", lumping three situations
together; measured separately, only one of them leaks. An exception out of the
``with`` block does NOT leak - teardown runs, the driver cleans up, zero
survivors over an interleaved A/B. The leak is the KILLED-RUNNER path, where
teardown never executes at all: launch, kill, count - eight survivors, then
twelve. For the manager the equivalent is the user closing the app, the OS
ending it, or a crash: all the same case, and none of them reaches anything the
app could have written.

Nothing written inside a teardown method can reach that, so the guarantee has to
come from the operating system. On Windows a job object with KILL_ON_JOB_CLOSE
does exactly it: the launching process holds the only handle, and when it ends by
any means the kernel terminates the job's members. Processes created inside a job
join it automatically, so content processes spawned later need no tracking.

THE DESIGN
----------
Four pieces with one responsibility each, so the Win32 layer is not tangled with
the policy and neither is tangled with any launcher:

    SessionToken   identity. Mints itself, stamps an environment, and answers
                   whether a given process is ours.
    find_processes the search.
    terminate      immediate cleanup, returning a COUNT.
    LifetimeGuard  the strategy. ``JobObjectGuard`` on Windows, ``NullGuard``
                   everywhere else and whenever the mechanism is unavailable.

``os.name`` is tested in exactly one place - ``guard_for()`` - so no caller
branches on the platform. NullGuard is a Null Object in the strict sense: it
satisfies the interface and REPORTS that it guarantees nothing (``bound == 0``,
``guaranteed is False``) rather than quietly doing nothing and looking
successful.

WHY A TOKEN AND NOT A SEARCH
----------------------------
The manager used to find its browser by matching the ``-profile`` directory,
which works because it owns that path - but the wrapper cannot, because
Playwright creates the profile and never says where. Everything else available -
"a firefox that appeared after we started", "a firefox running our binary" - is
a heuristic, and it invites the one failure a reaper must never have: on a fleet,
several sessions start on the same binary within the same second, and a wrong
guess kills a healthy browser belonging to someone else.

So each session mints a random token and puts it in the browser's environment.
Children inherit it, so every process in the tree carries it, and a process
either has this session's token or it does not. Verified on Windows, where the
launcher stub made this necessary: ``psutil.Process.environ()`` reads a
same-user process's block and children show the inherited value.

A LAUNCH OF THIS CORE IS NOT SEARCHED FOR AT ALL, neither at launch nor when it
closes. The spawn makes the launch's tree a thing the launch holds (``EngineTree``:
its job on Windows, its engine's descendants on POSIX) and registers the token
as meaning that tree, so ``find_processes`` and ``reap`` of that token list and
end it from itself. The search by environment stays for a token no launch of ours
registered. Closing a browser used to scan every process of the machine, read
each one's environment, and wait for the exit on the thread that serves the other
browsers of the process (``Browser.aclose`` and ``Connection.aclose`` now wait in
a thread of their own).

The rule throughout: act on POSITIVE identification only. A process whose
environment cannot be read is left alone. Leaking a browser is a bug; killing
someone else's is an incident, and only one of the two is recoverable.
"""
from __future__ import annotations

import os
import secrets
import signal
import struct
import threading
import time
from abc import ABC, abstractmethod
from collections import OrderedDict
from typing import Any, Dict, Iterable, List, Mapping, Optional

from . import environment

# Named in the environment of every process in the tree, read back through
# psutil. The browser itself never looks at it.
#
# The INVPW_ prefix is LEGACY and deliberate. This started in the automation
# wrapper, and the published wrapper reads exactly this name; renaming it would
# make an already-shipped client and a newer core disagree about which processes
# belong to a session - which is the one disagreement a reaper must not have.
TOKEN_VAR = environment.SESSION_TOKEN

try:  # psutil is a declared dependency; guarded so that an import problem in a
    # user's environment degrades to a Null guard rather than breaking launch.
    import psutil
except Exception:  # pragma: no cover - exercised by the tests' monkeypatching
    psutil = None  # type: ignore[assignment]


# ── identity ──────────────────────────────────────────────────────────────

class SessionToken:
    """What makes a process ours, and the only thing that does.

    A value object: two tokens are equal when their values are, and an EMPTY
    token is falsy and matches nothing. That last part is load-bearing rather
    than defensive tidiness - without it, a session that failed before minting
    one would sweep every process whose variable happens to be empty.
    """

    __slots__ = ("value",)

    def __init__(self, value: str = "") -> None:
        self.value = value

    @classmethod
    def mint(cls) -> "SessionToken":
        return cls(secrets.token_hex(16))

    def __bool__(self) -> bool:
        return bool(self.value)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, SessionToken) and other.value == self.value

    def __hash__(self) -> int:
        return hash(self.value)

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return f"SessionToken({self.value[:8]}...)" if self else "SessionToken(empty)"

    def stamp(self, env: Mapping[str, str]) -> dict:
        """A copy of ``env`` the browser will pass on to its children."""
        out = dict(env)
        out[TOKEN_VAR] = self.value
        return out

    def matches(self, proc: Any) -> bool:
        """True only when the environment can be READ and holds this token.

        Every failure answers False. A process we cannot inspect is a process
        we do not touch.
        """
        if not self:
            return False
        try:
            return proc.environ().get(TOKEN_VAR) == self.value
        except Exception:
            return False


# ── the search: the only place psutil is used ─────────────────────────────

def find_processes(token: SessionToken) -> List[Any]:
    """Every live process carrying ``token``, deepest child first.

    Deepest-first so that terminating in order reaches the content processes
    before the parent that would otherwise orphan or restart them.
    """
    if psutil is None or not token:
        return []
    # ⛔ A LAUNCH OF THIS CORE IS LISTED FROM ITSELF, never searched for: its job
    # on Windows, the descendants of its engine on POSIX (`EngineTree`). The
    # search below is for a token no launch of ours registered.
    members = registered_members(token)
    if members is not None:
        return members
    # NO `ppid` in the attrs, and this is not a micro-optimisation. On Windows
    # psutil answers ppid out of `ppid_map()`, which enumerates EVERY process on
    # the machine, and `process_iter(["pid", "ppid"])` asks once per process:
    # 354 processes x 26ms = 9.2 seconds per pass, measured with cProfile on
    # 2026-08-01. `LifetimeGuard.bind` runs this in a loop bounded by wait=10.0
    # and its own docstring says the loop "costs about a second on launch" - it
    # cost ten, on every launch, and the scan never converged because a single
    # pass outlasted the settle window it was being measured against.
    #
    # The parent is only needed for the handful that MATCHED, so it is read
    # there: a browser tree is tens of processes, not hundreds.
    found = [p for p in psutil.process_iter(["pid"]) if token.matches(p)]
    pids = {p.pid for p in found}

    def _parent(proc: Any) -> Any:
        try:
            return proc.ppid()
        except Exception:      # gone between the scan and here
            return None

    # The token already delimits the tree exactly, so "deeper" is just "my
    # parent is also in the set" - no tree walk needed.
    found.sort(key=lambda p: _parent(p) in pids, reverse=True)
    return found


def terminate(procs: Iterable[Any], *, timeout: float = 5.0,
              grace: float = 0.0) -> int:
    """Graceful terminate, then kill the survivors. Returns how many were sent.

    A count rather than nothing, so a caller can tell "nothing was leaked" from
    "the reaper did not run" - two outcomes that look identical from outside.

    ``grace`` is how long the processes get to exit ON THEIR OWN before they
    are asked to; the ones that do are not counted, because nothing was sent
    to them.
    """
    procs = list(procs)
    if procs and grace > 0:
        try:
            _, procs = psutil.wait_procs(procs, timeout=grace)
        except Exception:
            pass
    if not procs:
        return 0
    for proc in procs:
        try:
            proc.terminate()
        except Exception:
            pass
    alive = procs
    try:
        _, alive = psutil.wait_procs(procs, timeout=timeout)
    except Exception:
        pass
    for proc in alive:
        try:
            proc.kill()
        except Exception:
            pass
    if alive:
        try:
            psutil.wait_procs(alive, timeout=1.0)
        except Exception:
            pass
    return len(procs)


def alive(proc: Any) -> bool:
    """Cross-OS liveness for one process. False when gone OR a zombie.

    A zombie answers ``is_running()`` True on POSIX, and reading that as alive
    is how a UI shows a profile RUNNING forever after its browser has died.
    Came from the manager, which is where that was learned.
    """
    if proc is None or psutil is None:
        return False
    try:
        return proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE
    except Exception:
        return False


def wait_until_gone(token: SessionToken, timeout: float = 10.0) -> bool:
    """True once nothing carries ``token`` any more, False on timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not find_processes(token):
            return True
        time.sleep(0.2)
    return not find_processes(token)


def reap_session(token: SessionToken, *, grace: float = 0.0,
                 timeout: float = 5.0) -> int:
    """End what is left of a session's tree: wait ``grace`` for it to leave by
    itself, then end it. Returns how many were sent something.

    A launch of this core ends from its own tree (`EngineTree.end`: its job on
    Windows, its engine's descendants on POSIX). Only a token no launch of ours
    registered is searched for, by `find_processes`, as before.
    """
    if psutil is None or not token:
        return 0
    ends = registered_trees(token)
    if ends is None:
        return terminate(find_processes(token), grace=grace, timeout=timeout)
    return sum(tree.end(grace=grace, timeout=timeout) for tree in ends)


# ── the strategy ──────────────────────────────────────────────────────────

class LifetimeGuard(ABC):
    """Tie a session's process tree to this process's lifetime."""

    #: False on any implementation that cannot actually promise it.
    guaranteed: bool = False

    @abstractmethod
    def bind(self, token: SessionToken, *, wait: float = 10.0) -> int:
        """Adopt the tree carrying ``token``. Returns how many were adopted."""

    def reap(self, token: SessionToken, *, timeout: float = 5.0) -> int:
        """Terminate the tree now, for teardowns that DO get to run.

        Kept even where ``bind`` guarantees the kill, because a browser that
        refuses ``close()`` should not wait for this process to exit.
        """
        return reap_session(token, timeout=timeout)


class NullGuard(LifetimeGuard):
    """No OS-level guarantee here, and it says so instead of implying one.

    The honest answer on platforms without the mechanism and on any failure to
    obtain it. ``reap`` still works: it is inherited, because immediate cleanup
    is not the part that needs a kernel.
    """

    guaranteed = False

    def bind(self, token: SessionToken, *, wait: float = 10.0,
             settle: float = 1.0) -> int:
        return 0

    def spawn_into(self, argv, *, env=None, **popen_kwargs):
        """An ordinary spawn, and it says so by being a NullGuard.

        Same signature as the real one so no caller branches on the platform -
        that is the whole point of the Null implementation.
        """
        import subprocess

        return subprocess.Popen(argv, env=env, **popen_kwargs)


class JobObjectGuard(LifetimeGuard):
    """Windows. The kernel empties the job when our last handle closes.

    The handle is held for the life of the guard and never closed explicitly:
    closing it is precisely the event that kills the job, so the process
    exiting - by any route, including being killed - is what triggers it.
    """

    guaranteed = True

    _KILL_ON_JOB_CLOSE = 0x2000
    _EXTENDED_LIMIT_INFORMATION = 9
    _PROCESS_SET_QUOTA = 0x0100
    _PROCESS_TERMINATE = 0x0001

    def __init__(self, handle: Any, kernel32: Any) -> None:
        self._handle = handle
        self._kernel32 = kernel32
        self._adopted: set = set()

    @classmethod
    def create(cls) -> "LifetimeGuard":
        """A guard, or a NullGuard if the mechanism is not available."""
        try:
            import ctypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            handle = kernel32.CreateJobObjectW(None, None)
            if not handle:
                return NullGuard()
            info = _ExtendedLimitInformation()
            info.BasicLimitInformation.LimitFlags = cls._KILL_ON_JOB_CLOSE
            ok = kernel32.SetInformationJobObject(
                handle, cls._EXTENDED_LIMIT_INFORMATION,
                ctypes.byref(info), ctypes.sizeof(info),
            )
            if not ok:
                kernel32.CloseHandle(handle)
                return NullGuard()
            return cls(handle, kernel32)
        except Exception:
            return NullGuard()

    def bind(self, token: SessionToken, *, wait: float = 10.0,
             settle: float = 1.0) -> int:
        """Wait for the tree to appear, then adopt ALL of it.

        NOT HOW THE CORE'S OWN LAUNCH GUARDS THE ENGINE ANY MORE. The spawn
        creates the engine inside a job of its own (`EngineJob`), so a caller of
        the core's `launch` has nothing to adopt, and this loop (every process of
        the machine scanned, its environment read, until a second passes with
        nothing new) is pure cost there. It remains for a caller that starts a
        process by other means and wants it adopted by token.

        The wait exists because the driver spawns the browser asynchronously.
        The token makes it exact rather than a guess about how long that takes.

        WHY IT KEEPS SCANNING AFTER THE FIRST SUCCESS. Until 2026-07-27 this
        loop did `if bound: break`, so it adopted whatever existed at the first
        instant anything existed, and returned. Processes appearing a moment
        later escaped unless Windows added them automatically - which it only
        does for CHILDREN of a job member, and on Windows `firefox.exe` is a
        launcher stub that exits, re-parenting the real browser away from
        anything that was adopted.

        Measured by killing the runner mid-session and counting survivors:
        four runs gave sync 0/0/0/0 and async 2/0/0/2. Intermittent, ~50% on
        the async path, 0% on the sync one - not because the two APIs differ
        here, but because their timing does, which is exactly the shape that
        makes a race look like a working feature.

        So it now scans until a full pass adds nothing for `settle` seconds,
        bounded by `wait`. The cost is about a second on launch; the thing it
        buys is that "the kernel is holding this tree" stops being a coin flip.
        """
        if not token:
            return 0
        deadline = time.monotonic() + wait
        bound = 0
        quiet_since: Optional[float] = None
        while time.monotonic() < deadline:
            added = 0
            for proc in find_processes(token):
                if proc.pid in self._adopted:
                    continue
                # ONLY a success is recorded. It used to add the pid either way,
                # so `_adopted` meant "tried" while reading as "held": a process
                # whose assignment failed was never retried, and the returned
                # count was a number of attempts. Measured on the profile
                # manager, that reported 8 adopted out of 8 while 8 survived the
                # kill - the guard was reporting a guarantee it did not have.
                if self._adopt(proc.pid):
                    self._adopted.add(proc.pid)
                    added += 1
            bound += added
            now = time.monotonic()
            if added:
                quiet_since = None
            elif bound:
                if quiet_since is None:
                    quiet_since = now
                elif now - quiet_since >= settle:
                    break
            time.sleep(0.25)
        return bound

    def spawn_into(self, argv, *, env=None, **popen_kwargs):
        """Start a process ALREADY INSIDE the job, so its whole tree is born in it.

        This exists because adopting afterwards does not work for this browser,
        and the measurement is unambiguous. On the profile manager's launch path,
        `AssignProcessToJobObject` returns **ERROR_ACCESS_DENIED (5)** for six of
        the eight processes and ERROR_NOT_ENOUGH_QUOTA (1816) for a seventh:
        Firefox puts its own content processes into its own sandbox jobs, and a
        process already in a job that does not permit nesting cannot be added to
        another one. Only the top process could be adopted, and the tree survived
        the kill 8 out of 8, three runs of three.

        Creating the process suspended, assigning it, and only then resuming it
        inverts that: everything it spawns is created inside our job from the
        start, which is the case Windows does support. `psutil` does the resume
        because `subprocess.Popen` does not expose the thread handle needed for
        `ResumeThread`.

        Falls back to an ordinary spawn if anything here fails - a launch that
        works without a guarantee beats a guarantee that refuses to launch.
        """
        import subprocess

        _CREATE_SUSPENDED = 0x00000004
        flags = popen_kwargs.pop("creationflags", 0) | _CREATE_SUSPENDED
        try:
            proc = subprocess.Popen(argv, env=env, creationflags=flags,
                                    **popen_kwargs)
        except Exception:
            return subprocess.Popen(argv, env=env, **popen_kwargs)
        try:
            if not self._adopt(proc.pid):
                raise OSError("the process could not be assigned to the job")
            self._adopted.add(proc.pid)
        except Exception:
            # Resume it anyway: a suspended browser that nobody resumes is a
            # worse outcome than an unguarded one.
            self._resume(proc.pid)
            return proc
        self._resume(proc.pid)
        return proc

    @staticmethod
    def _resume(pid: int) -> None:
        try:
            import psutil as _ps

            _ps.Process(pid).resume()
        except Exception:
            pass

    def _adopt(self, pid: int) -> bool:
        handle = self._kernel32.OpenProcess(
            self._PROCESS_SET_QUOTA | self._PROCESS_TERMINATE, False, pid
        )
        if not handle:
            return False
        try:
            return bool(
                self._kernel32.AssignProcessToJobObject(self._handle, handle)
            )
        finally:
            self._kernel32.CloseHandle(handle)


def _define_job_structures():
    """The Win32 layout, built once and only when ctypes is importable."""
    import ctypes
    from ctypes import wintypes

    class IoCounters(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in
                    ("ReadOperationCount", "WriteOperationCount",
                     "OtherOperationCount", "ReadTransferCount",
                     "WriteTransferCount", "OtherTransferCount")]

    class BasicLimit(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.POINTER(ctypes.c_ulong)),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class ExtendedLimit(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BasicLimit),
            ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    return ExtendedLimit


try:
    _ExtendedLimitInformation = _define_job_structures()
except Exception:  # pragma: no cover - non-Windows, or no ctypes
    _ExtendedLimitInformation = None  # type: ignore[assignment]


class EngineJob:
    """The job of ONE launch: the engine is born in it, and closing it ends the tree.

    Made by the spawn (`juggler.connection._spawn_windows`), one per engine, and
    held by the process object the spawn returns. Two things follow from it
    being one per launch and not one per Python process: closing one browser
    can never touch another browser's processes, and the tree of one browser
    is a thing that can be listed and ended by itself, without looking at the
    rest of the machine.

    ⛔ THE LIMIT FLAGS ARE `KILL_ON_JOB_CLOSE` AND NOTHING ELSE. `BREAKAWAY_OK`
    would let a child ask to leave the job, and `SILENT_BREAKAWAY_OK` would let
    every child of the engine leave it without asking: the tree would be in the
    job only as long as nobody wanted out. Neither is set, so a process created
    inside it stays in it, and a `CREATE_BREAKAWAY_FROM_JOB` request is refused.

    The handle is closed by `close()` (the kernel then ends whatever is left of
    the tree) and, if nothing ever closes it, by the end of this process by any
    route, which is the crash guarantee `JobObjectGuard` gives.
    """

    _KILL_ON_JOB_CLOSE = JobObjectGuard._KILL_ON_JOB_CLOSE
    _EXTENDED_LIMIT_INFORMATION = JobObjectGuard._EXTENDED_LIMIT_INFORMATION
    _BASIC_ACCOUNTING_INFORMATION = 1
    _BASIC_PROCESS_ID_LIST = 3

    def __init__(self, handle: Any, kernel32: Any, last_error: Any = None) -> None:
        self.handle = handle
        self._kernel32 = kernel32
        # The thread's last Win32 error, read right after the call that set it. `ctypes.get_last_error` exists on
        # Windows only; a stand-in kernel32 (the unit tests, on every system) brings its own.
        self._last_error = last_error
        self._lock = threading.Lock()

    @classmethod
    def create(cls, platform: str | None = None) -> Optional["EngineJob"]:
        """A new job, or None where there is none (not Windows, or it could not be made).

        None is an ordinary launch: a launch that works without the guarantee
        beats a guarantee that refuses to launch.
        """
        name = os.name if platform is None else platform
        if name != "nt" or _ExtendedLimitInformation is None:
            return None
        try:
            import ctypes

            k = ctypes.WinDLL("kernel32", use_last_error=True)
            k.CreateJobObjectW.restype = ctypes.c_void_p
            handle = k.CreateJobObjectW(None, None)
            if not handle:
                return None
            info = _ExtendedLimitInformation()
            info.BasicLimitInformation.LimitFlags = cls._KILL_ON_JOB_CLOSE
            ok = k.SetInformationJobObject(
                ctypes.c_void_p(handle), cls._EXTENDED_LIMIT_INFORMATION,
                ctypes.byref(info), ctypes.sizeof(info))
            if not ok:
                k.CloseHandle(ctypes.c_void_p(handle))
                return None
            return cls(handle, k)
        except Exception:
            return None

    def adopt_and_resume(self, process_handle: Any, thread_handle: Any) -> tuple:
        """Put a process created SUSPENDED into the job, then let it run.

        `CreateProcessW` with `CREATE_SUSPENDED` gives the two handles; the
        process is alone and has run no instruction, and ASSIGNING IT NOW is the
        case Windows supports (see `JobObjectGuard.spawn_into`): every process it
        creates (the launcher's browser, content, GPU and socket processes, the
        pingsender at shutdown) is created inside the job by the kernel, with
        nothing to find and nothing to adopt afterwards. No scan of the machine.

        Returns `(assigned, error)`: whether the process is in the job, and the
        Windows error of the assignment (0 when it worked), read RIGHT AFTER
        `AssignProcessToJobObject`, before `ResumeThread` can overwrite it. A
        refusal also raises a `RuntimeWarning` naming that error: the engine
        runs, but it will not die with this process.

        ⛔ THE THREAD IS RESUMED EITHER WAY: a suspended engine that nobody
        resumes is a hung launch, a worse outcome than an unguarded one. A
        resume that fails raises, and the caller ends the process.
        """
        import ctypes
        import warnings
        from ctypes import wintypes

        k = self._kernel32
        k.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        k.AssignProcessToJobObject.restype = wintypes.BOOL
        k.ResumeThread.argtypes = [wintypes.HANDLE]
        k.ResumeThread.restype = wintypes.DWORD
        assigned = bool(k.AssignProcessToJobObject(self.handle, process_handle))
        if assigned:
            error = 0
        elif self._last_error is not None:
            error = self._last_error()
        else:
            import ctypes
            error = ctypes.get_last_error()
        if k.ResumeThread(thread_handle) == 0xFFFFFFFF:
            raise OSError("the suspended process could not be resumed")
        if not assigned:
            warnings.warn(
                "the engine could not be put in the job object (error %d): it "
                "runs, but it will not die with this process" % error,
                RuntimeWarning, stacklevel=3)
        return assigned, error

    def active(self) -> int:
        """How many processes of the tree are alive right now (the job's own count)."""
        import ctypes
        from ctypes import wintypes

        class Accounting(ctypes.Structure):
            _fields_ = [("TotalUserTime", ctypes.c_longlong),
                        ("TotalKernelTime", ctypes.c_longlong),
                        ("ThisPeriodTotalUserTime", ctypes.c_longlong),
                        ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
                        ("TotalPageFaultCount", wintypes.DWORD),
                        ("TotalProcesses", wintypes.DWORD),
                        ("ActiveProcesses", wintypes.DWORD),
                        ("TotalTerminatedProcesses", wintypes.DWORD)]

        k = self._kernel32
        k.QueryInformationJobObject.argtypes = [
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
            ctypes.c_void_p]
        with self._lock:
            if not self.handle:
                return 0
            info = Accounting()
            if not k.QueryInformationJobObject(
                    self.handle, self._BASIC_ACCOUNTING_INFORMATION,
                    ctypes.byref(info), ctypes.sizeof(info), None):
                return 0
            return int(info.ActiveProcesses)

    def wait_empty(self, deadline: float) -> bool:
        """True once no process of the tree is alive, False at `deadline` (a `time.monotonic()` value)."""
        while self.active():
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.02)
        return True

    def pids(self) -> List[int]:
        """The pids of the tree, from the job itself: nothing of the machine is read.

        `JobObjectBasicProcessIdList`: a count, then that many pointer-sized ids.
        A tree larger than the buffer is asked again with the size the job
        reported.
        """
        import ctypes
        from ctypes import wintypes

        k = self._kernel32
        k.QueryInformationJobObject.argtypes = [
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
            ctypes.c_void_p]
        slots = 64
        with self._lock:
            if not self.handle:
                return []
            while True:
                size = 8 + slots * ctypes.sizeof(ctypes.c_size_t)
                buffer = ctypes.create_string_buffer(size)
                ok = k.QueryInformationJobObject(
                    self.handle, self._BASIC_PROCESS_ID_LIST, buffer, size, None)
                assigned, listed = struct.unpack_from("II", buffer, 0)
                if ok:
                    return list(struct.unpack_from("@%dN" % listed, buffer, 8))
                if assigned > slots:
                    slots = assigned + 16
                    continue
                return []

    def terminate(self) -> None:
        """Ends every process of the tree at once; the job stays open until `close`."""
        import ctypes

        k = self._kernel32
        k.TerminateJobObject.argtypes = [ctypes.c_void_p, ctypes.c_uint]
        with self._lock:
            if self.handle:
                k.TerminateJobObject(self.handle, 1)

    def close(self) -> None:
        """Close the handle, once: the kernel ends whatever is left of the tree."""
        with self._lock:
            handle, self.handle = self.handle, None
            if handle:
                from ctypes import c_void_p
                self._kernel32.CloseHandle(c_void_p(handle))


# ── the tree of one launch, listed from the launch ─────────────────────────

#: Seconds `EngineTree.release` lets the kernel finish ending a terminated job.
JOB_END_WAIT = 2.0

#: Seconds a browser that is EXITING is waited for before it is ended: `Connection.close` waits for its real exit, and this is
#: the one limit of that wait. ⛔ ONE DEFINITION, and it is not a measure of a close: a close
#: takes 3-7 s on a hosted runner (4 browsers together on Windows: p50 5.83 s, max 6.85 s, all with exit code 0 when the limit was
#: raised; with 5.0 s, 26 closes of 64 were ended while they were still exiting), and a browser that is exiting is never ended.
#: This is the net for one that is stuck, and it sits AFTER the moment Firefox brings itself down for a shutdown that does not
#: finish, not on it: AsyncShutdown crashes the process at `toolkit.asyncshutdown.crash_timeout` (60 s in
#: `modules/libpref/init/all.js`, on a release build) plus `crash_timeout_additional_wait` (10 s, the terminator's wait on top of
#: it), so 60 + 10 = 70 s, and 80 s leaves 10 s past it. A browser still alive past this is not exiting, and ending it is
#: correct. It is the limit of the wait for the exit only: what ends a browser that was ended (`Reaper`) is not a wait for an
#: exit, and keeps its own 5 s. Every wait on it is on a condition (the exit), so it costs nothing when it exits.
BROWSER_EXIT_LIMIT = 80.0

#: Seconds between two listings of the tree while an engine on POSIX is
#: closing (`Connection.close`): a child it makes while it shuts down is in
#: the next one, and each is one pass over the parents of the processes.
TREE_REFRESH = 0.1

#: Closed launches whose tree stays answerable by token, so that a late
#: `reap(token)` (every client's last step) finds nothing without a search.
CLOSED_KEPT = 64


def _pids_in_group(pgid: int) -> Optional[List[int]]:
    """The pids of the living members of group `pgid` (a zombie is not one), from one pass over `/proc/*/stat`
    (`pid (comm) state ppid pgrp ...`: state and group only). None where it cannot be told."""
    try:
        names = os.listdir("/proc")
    except OSError:
        return _pids_in_group_by_psutil(pgid)
    found: List[int] = []
    for name in names:
        if not name.isdigit():
            continue
        try:
            with open("/proc/%s/stat" % name, "rb") as stat:
                tail = stat.read().rpartition(b")")[2].split()
            if int(tail[2]) == pgid and tail[0] not in (b"Z", b"X"):
                found.append(int(name))
        except (OSError, ValueError, IndexError):     # gone since the listing
            continue
    return found


def _pids_in_group_by_psutil(pgid: int) -> Optional[List[int]]:
    """The same without `/proc` (macOS): psutil reads the state, `getpgid` the group."""
    if psutil is None:
        return None
    found: List[int] = []
    for proc in psutil.process_iter(["pid", "status"]):
        try:
            if proc.info["status"] != psutil.STATUS_ZOMBIE and os.getpgid(proc.pid) == pgid:
                found.append(proc.pid)
        except Exception:
            continue
    return found


def _living_in_group(pgid: int) -> Optional[bool]:
    """Whether a process of group `pgid` is alive and not a zombie. None where it cannot be told."""
    pids = _pids_in_group(pgid)
    return None if pids is None else bool(pids)


def _command_line_of(pid: int) -> List[str]:
    """The command line of a process (the one place it is read, which is what a test counts)."""
    if psutil is None:
        raise RuntimeError("psutil is not available")
    return psutil.Process(pid).cmdline()


def _command_line_is_final() -> bool:
    """Whether a process has its final command line from its creation (Windows: `CreateProcess` writes it into the
    process before its first instruction), so that what was read once is what it is. POSIX forks first and executes
    after, and a child can be read as its parent for a moment."""
    return os.name == "nt"


#: The flag Firefox's background tasks are started with (`firefox -backgroundtask <name>`); it is accepted with one dash,
#: two, or a slash.
BACKGROUND_TASK_FLAGS = ("-backgroundtask", "--backgroundtask", "/backgroundtask")


def outlives_the_browser(command: Optional[Iterable[str]]) -> bool:
    """Whether a process, by its COMMAND LINE, is one the browser starts to outlive it: the shutdown-ping sender
    (an executable named `pingsender`) or its background task (a `-backgroundtask` argument).

    ⛔ BY WHAT THE PROCESS IS, never by being the one that is left: a content process the browser did not end is
    left as well, and it is not allowed to survive. A command line that could not be read is not one of them."""
    args = [str(a) for a in command or ()]
    if not args:
        return False
    name = args[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
    if name.endswith(".exe"):
        name = name[:-4]
    if name == "pingsender":
        return True
    return any(a.lower() in BACKGROUND_TASK_FLAGS for a in args[1:])


def _running(proc: Any) -> bool:
    """`alive`, without the status call where there is no zombie to tell apart:
    on Windows psutil answers a status by listing every process of the machine."""
    if os.name == "nt":
        try:
            return proc.is_running()
        except Exception:
            return False
    return alive(proc)


class EngineTree:
    """The processes of ONE launch, known from the launch and never searched for.

    ⛔ NOTHING OF THE MACHINE IS SCANNED, and no process's environment is read.
    The search this replaces (`find_processes`: every process, its environment
    read for the token) is what ended a browser, on the closing thread: with
    four browsers in one Python process py-spy put the wait for the exit and
    the removal of the profile at about a fifth of the main thread, all of it
    on the event loop that serves the other three.

    * Windows: the tree is the launch's job (`EngineJob`). It is listed by the
      job (`pids`), waited for by the job's own count and ended by the job
      (`terminate`): the launcher stub that exits while its browser runs, and
      the pingsender that outlives the browser, are in it by construction.
    * POSIX: the tree is the engine's PROCESS GROUP. The spawn makes the engine
      the leader of a group of its own (`posix_spawn` with `setpgroup=0`, what
      Playwright's launcher does with `detached: true`, and ends with
      `kill(-pid)`), so whatever the engine creates after that, however late,
      is in the group by construction, and whatever it leaves behind when it
      exits stays in it: the tree is waited for with `killpg(pgid, 0)` (ESRCH
      is empty) and ended with `killpg`, with nothing listed, nothing scanned
      and nothing refreshed. No process of the engine's makes itself leader of
      another group or session (`setsid` and `setpgid` are called in the
      engine's tree by the crash helper alone, which the core's environment
      keeps from starting).
    * No job and no group (a tree built from a pid alone): the engine's
      descendants, in ONE pass (`psutil.Process.children(recursive=True)`),
      listed while the engine is alive, because what a dead engine left is
      reparented and nobody can say whose it is: `remember()` runs when a close
      begins and while it waits.

    ⛔ A GROUP IS SIGNALLED ONLY WHILE IT IS KNOWN TO HAVE MEMBERS. Once
    `killpg(pgid, 0)` has said that nobody is left, the number could be given to
    an unrelated process group, and a late `reap(token)` would kill it: the tree
    is then `_gone` for good. A group whose members are all zombies still counts
    as alive until their parent (or init) reaps them; the leader, which is our
    child, is reaped here (`poll`).

    What is remembered is `psutil.Process` objects, which carry the creation
    time: a pid that was reused is not the process that was listed.
    """

    def __init__(self, pid: int, job: Optional["EngineJob"] = None, *,
                 group: bool = False, poll: Any = None) -> None:
        self.pid = pid
        self.job = job
        #: The engine is the leader of a process group of its own (POSIX spawn): its pid is the group's.
        self.group = group
        #: Reaps the leader (our child) when it has exited, or None: a zombie leader keeps its group "alive".
        self._poll = poll
        #: `killpg(pid, 0)` said nobody is left: the number is never signalled again.
        self._gone = False
        #: When the members of the group were last looked at (`_living_member`).
        self._looked = 0.0
        #: Set by `release`: the launch is over, what is left is only waited for and ended.
        self.closed = False
        self._lock = threading.Lock()
        self._seen: Dict[int, Any] = {}
        #: pid -> whether its command line says it outlives the browser (`wait_browser_gone`, `_survives`).
        self._kind: Dict[int, bool] = {}
        self._root: Any = None
        if psutil is not None:
            try:
                self._root = psutil.Process(pid)
                self._seen[pid] = self._root
            except Exception:
                pass

    # ── listing ─────────────────────────────────────────────────────────────
    def _list(self) -> None:
        """Adds what the launch has right now to what is remembered. Under `_lock`."""
        if psutil is None or self.group:
            return
        job = self.job
        found: List[Any] = []
        if job is not None and job.handle:
            for pid in job.pids():
                try:
                    found.append(psutil.Process(pid))
                except Exception:        # gone between the job's answer and here
                    pass
        elif job is None and self._root is not None:
            try:
                if self._root.is_running():
                    found = self._root.children(recursive=True)
            except Exception:
                found = []
        for proc in found:
            if self._seen.get(proc.pid) != proc:
                self._seen[proc.pid] = proc

    def members(self) -> List[Any]:
        """The live processes of the launch, the later ones first (a child is
        learnt after its parent, so ending in this order reaches the content
        processes before the process that would restart them).

        For a group this is the one place a process of the machine is looked
        at, one pass reading each process's group and nothing of its
        environment, and it is for a caller that wants to SEE the tree
        (`find_processes`, a test): ending and waiting never list."""
        if self.group:
            return self._group_members()
        with self._lock:
            self._list()
            live = {pid: proc for pid, proc in self._seen.items() if _running(proc)}
            self._seen = live
            procs = list(live.values())
        procs.reverse()
        return procs

    def remember(self) -> None:
        """List the tree now, so that it is known when the engine is gone.

        Only a tree with neither a job nor a group needs it: a job is asked at
        the end (`release`), a group by its number, and what is in either then
        is everything there is."""
        if self.job is None and not self.group:
            self.members()

    # ── the group ───────────────────────────────────────────────────────────
    def _group_alive(self) -> bool:
        """Whether the process group has a member (`killpg(pgid, 0)`: ESRCH is empty)."""
        if self._gone:
            return False
        leader = None
        if self._poll is not None:
            try:
                leader = self._poll()
            except Exception:
                pass
        try:
            os.killpg(self.pid, 0)
        except ProcessLookupError:
            self._gone = True
            return False
        except OSError:                    # EPERM: it has members, and they are not ours to signal
            return True
        if leader is None:                 # the leader runs, or there is none to ask: the group is alive
            return True
        return self._living_member()

    #: Seconds between two looks at the members of a group whose leader is gone.
    LOOK_EVERY = 0.25

    def _living_member(self) -> bool:
        """`killpg(pgid, 0)` answers for a ZOMBIE too, and the leader is gone: is anything in the group alive?

        ⛔ A ZOMBIE IS NOT A MEMBER. A process nobody reaps stays a zombie: the pingsender that outlives the engine, in a container
        whose PID 1 is the user's own script (no init), never leaves the group, and a close that waited for the group to be empty
        would wait for ever. So, ONLY when the leader has been reaped and the group still answers, the group is looked at once:
        one pass over `/proc/*/stat`, reading each process's state and group and nothing else (its environment never), and
        again at most every `LOOK_EVERY` seconds while something lives. A group of zombies is empty."""
        now = time.monotonic()
        if now - self._looked < self.LOOK_EVERY and self._looked:
            return True
        self._looked = now
        living = _living_in_group(self.pid)
        if living is False:
            self._gone = True
            return False
        return True

    def _signal_group(self, number: int) -> None:
        if not self._group_alive():
            return
        try:
            os.killpg(self.pid, number)
        except OSError:
            pass

    def _wait_group(self, timeout: float) -> bool:
        """True once the group is empty, False after `timeout` seconds."""
        deadline = time.monotonic() + timeout
        while self._group_alive():
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.02)
        return True

    def _group_members(self) -> List[Any]:
        if psutil is None or not self._group_alive():
            return []
        found = []
        for proc in psutil.process_iter(["pid"]):
            try:
                if os.getpgid(proc.pid) == self.pid and alive(proc):
                    found.append(proc)
            except Exception:              # gone, or not ours to ask about
                pass
        return found

    # ── waiting and ending ──────────────────────────────────────────────────
    def wait_browser_gone(self, deadline: float) -> bool:
        """Waits until the BROWSER has exited: the engine and every process that belongs to it (content, GPU, socket,
        rdd, utility, forkserver) are gone, or `deadline` (a monotonic time). True when they are, False at the deadline.

        The only processes allowed to be left are the ones Firefox starts to outlive itself, known by their command
        line (`outlives_the_browser`): the shutdown-ping sender and its background task. They are not waited for and
        not ended here (the launch's reaper lets them finish).

        Windows asks the job, which holds the launcher stub's browser and every later process by construction; a
        launch with a group asks the group (one pass over `/proc`, states and groups, then the command line of a
        process not seen before); a tree of neither lists its descendants. The engine itself is the caller's to have
        seen exit: a group whose leader is still running is not gone."""
        job = self.job
        while True:
            if self.group:
                if self._poll is not None and self._poll() is None:
                    pids: Optional[List[int]] = [self.pid]
                else:
                    pids = self._group_pids()
            elif job is not None and job.handle:
                pids = job.pids()
            else:
                pids = [proc.pid for proc in self.members()]
            if pids is None or all(self._survives(pid) for pid in pids):
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)

    def _group_pids(self) -> Optional[List[int]]:
        """The living members of the group, once `killpg(pgid, 0)` says there are any; a group seen empty is gone for good."""
        if self._gone:
            return []
        try:
            os.killpg(self.pid, 0)
        except ProcessLookupError:
            self._gone = True
            return []
        except OSError:
            pass
        pids = _pids_in_group(self.pid)
        if pids is not None and not pids:        # only zombies: nobody is left to wait for
            self._gone = True
        return pids

    def _survives(self, pid: int) -> bool:
        """Whether the process is one that outlives the browser, by its command line. A process that has gone since
        the listing is not left, so it is not a reason to wait: True.

        ⛔ WINDOWS READS A COMMAND LINE ONCE PER PROCESS, YES OR NO: a process has its final command line from the
        moment it is created, and reading it is a read of the process's PEB (under the GIL) that, repeated at the
        pace of this loop, would be made about a hundred times a second for every process of the browser until it
        exits. POSIX remembers only a yes: a process the browser has forked and not yet executed still has the
        browser's own command line, and asking again a moment later (a read of `/proc`, which is cheap) is what tells
        a sender from the content process it was made out of."""
        known = self._kind.get(pid)
        if known is not None:
            return known
        try:
            command = _command_line_of(pid)
        except Exception as failure:
            if psutil is not None and isinstance(failure, psutil.NoSuchProcess):
                return True
            return False                         # not readable: not ours to call a survivor, and asked again
        verdict = outlives_the_browser(command)
        if verdict or _command_line_is_final():
            self._kind[pid] = verdict
        return verdict

    def _wait(self, procs: List[Any], timeout: float) -> List[Any]:
        """The ones of `procs` still alive after up to `timeout` seconds."""
        job = self.job
        if job is not None and job.handle:
            job.wait_empty(time.monotonic() + timeout)
            return self.members()
        try:
            _, left = psutil.wait_procs(procs, timeout=timeout)
        except Exception:
            return procs
        return left

    def end(self, *, grace: float = 0.0, timeout: float = 5.0) -> int:
        """Waits ``grace`` for the tree to leave by itself, then ends it.
        Returns how many were sent something (what left by itself is not counted).

        Windows ends the whole job in one call; a group is sent SIGTERM as a
        whole, waited for ``timeout`` and sent SIGKILL (a group is one count: 1
        is "it was signalled"); without either, each process is asked to
        terminate, waited for ``timeout`` and killed if it stayed."""
        if self.group:
            if not self._group_alive():
                return 0
            if grace > 0 and self._wait_group(grace):
                return 0
            self._signal_group(signal.SIGTERM)
            if not self._wait_group(timeout):
                self._signal_group(signal.SIGKILL)
                self._wait_group(1.0)
            return 1
        procs = self.members()
        if procs and grace > 0:
            procs = self._wait(procs, grace)
        if not procs:
            return 0
        sent = len(procs)
        job = self.job
        if job is not None and job.handle:
            job.terminate()
        else:
            for proc in procs:
                try:
                    proc.terminate()
                except Exception:
                    pass
        procs = self._wait(procs, timeout)
        for proc in procs:
            try:
                proc.kill()
            except Exception:
                pass
        if procs:
            self._wait(procs, 1.0)
        return sent

    def release(self) -> None:
        """The launch is over. What is left of the tree is ended (the job, on
        Windows, in one call, and its count is waited for) and the job's handle
        is closed: the kernel has nothing left to end, and no other launch's
        process was ever in it."""
        job = self.job
        if job is not None and job.handle:
            with self._lock:
                self._list()                # what survives is known by its pid afterwards
            if job.active():
                job.terminate()
                job.wait_empty(time.monotonic() + JOB_END_WAIT)
            job.close()
        self.closed = True


class Reaper(threading.Thread):
    """What follows the exit of the browser, for ONE launch: it keeps the tree until nothing of it is left, ends what
    stays past the grace, releases the launch (the job) and runs the steps handed to `then` (the removal of the
    session's directories).

    ⛔ THE CLOSE OF A BROWSER RETURNS WHEN THE BROWSER HAS EXITED (`EngineTree.wait_browser_gone`), NOT WHEN THE LAST
    PROCESS OF ITS TREE HAS. What stays after it is the sender of the shutdown pings (`outlives_the_browser`), measured
    at 0.6 s on Linux and 1.0 s on Windows, and nobody who closed a browser is waiting for it: this thread is. It
    ends it only after `grace`, and never before it has finished.

    A thread that is NOT a daemon: the interpreter's exit waits for it, so a program that closes its browser and
    ends leaves neither a process of the tree nor a profile (a daemon would be dropped in the middle of the
    removal). `join()` is the way to wait for all of it, for a caller who wants the guarantee at a point of its
    own; it costs nothing when nothing was left, because every wait here is on a condition (the job empty, the
    group empty), never on a time.
    """

    def __init__(self, tree: Optional[EngineTree], *, grace: float = 0.0, timeout: float = 5.0) -> None:
        # `timeout` is what a process that was told to end is given to leave before it is killed: 5.0, for a stray child and
        # for a browser that `Connection.close` ended at `BROWSER_EXIT_LIMIT` too. Once ended, a browser is not exiting, and
        # the limit is only for the wait for the exit.
        super().__init__(name="invisible-reaper", daemon=False)
        self.tree = tree
        self.grace = grace
        self.timeout = timeout
        self._lock = threading.Lock()
        self._steps: List[Any] = []
        self._finished = False
        # The steps handed over after the reaping was over: they run on a thread of their own (a continuation), never on
        # the thread of whoever hands them over. `_tail` is their queue, `_cont` the thread that is running them (None
        # when there is none).
        self._tail: List[Any] = []
        self._cont: Optional[threading.Thread] = None

    @property
    def finished(self) -> bool:
        """Whether the tree is ended and every step has run, those handed over after the reaping was over included."""
        with self._lock:
            return self._finished and self._cont is None

    def then(self, step: Any) -> None:
        """Run `step()` once the tree is gone, ALWAYS on a thread of this reaper and never on the caller's: by the
        reaper's own thread while it is still working, by a continuation of it (a thread that is not a daemon, one at
        a time, in the order of the hand-over) when it has finished. `join()`, `finished` and the end of the
        interpreter cover the continuation too. Never raises.

        The only case where the caller runs the step is a thread that cannot be created any more (the end of the
        interpreter: `RuntimeError` from `Thread.start`): there is no other thread to give it to, and the step is run
        rather than lost."""
        with self._lock:
            if not self._finished:
                self._steps.append(step)
                return
            self._tail.append(step)
            if self._cont is not None:        # a continuation is running: it takes this step after the earlier ones
                return
            cont = threading.Thread(target=self._continue, name="invisible-reaper-then", daemon=False)
            self._cont = cont
            try:
                cont.start()
                return
            except RuntimeError:              # no thread can be made: the step is the caller's
                self._cont = None
                self._tail.remove(step)
        try:
            step()
        except Exception:
            pass

    def _continue(self) -> None:
        """The continuation: takes the steps handed over after the end, in order, until there are none."""
        while True:
            with self._lock:
                steps, self._tail = self._tail, []
                if not steps:
                    self._cont = None
                    return
            for step in steps:
                try:
                    step()
                except Exception:
                    pass

    def run(self) -> None:
        tree = self.tree
        if tree is not None:
            try:
                tree.end(grace=self.grace, timeout=self.timeout)
            except Exception:
                pass
            try:
                tree.release()
            except Exception:
                pass
        while True:
            with self._lock:
                steps, self._steps = self._steps, []
                if not steps:
                    self._finished = True
                    return
            for step in steps:
                try:
                    step()
                except Exception:
                    pass

    def start(self) -> None:
        """Starts the thread; at the end of the interpreter, where a thread can no longer be made, the reaping is
        done by the caller instead (the same work, on its thread)."""
        try:
            super().start()
        except RuntimeError:
            self.run()

    def join(self, timeout: Optional[float] = None) -> None:
        """Waits for the reaping and for every step handed over, the ones after its end too. At `timeout` it returns
        with the rest still running (`finished` says so)."""
        deadline = None if timeout is None else time.monotonic() + timeout
        try:
            super().join(timeout)
        except RuntimeError:               # it was never started: `start` ran it
            pass
        while True:
            with self._lock:
                cont = self._cont
            if cont is None:
                return
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                return
            try:
                cont.join(remaining)
            except RuntimeError:           # a step waiting for its own thread
                return


_registry_lock = threading.Lock()
_registry: "OrderedDict[str, List[EngineTree]]" = OrderedDict()


def register_tree(token: SessionToken, tree: EngineTree) -> None:
    """Make ``token`` mean ``tree``: `find_processes` and `reap_session` list
    and end a registered token from the tree, with no search. Called by the
    launch, which stamped the token into the engine's environment. A token may
    hold more than one tree (two launches of one session)."""
    if not token:
        return
    with _registry_lock:
        _registry.setdefault(token.value, []).append(tree)
        _registry.move_to_end(token.value)
        done = [k for k, trees in _registry.items() if all(t.closed for t in trees)]
        for key in done[:max(0, len(done) - CLOSED_KEPT)]:
            del _registry[key]


def registered_trees(token: SessionToken) -> Optional[List[EngineTree]]:
    """The trees registered for ``token``, or None for a token no launch of ours made."""
    if not token:
        return None
    with _registry_lock:
        trees = _registry.get(token.value)
        return list(trees) if trees else None


def registered_members(token: SessionToken) -> Optional[List[Any]]:
    """The live processes of the trees registered for ``token``, or None."""
    trees = registered_trees(token)
    if trees is None:
        return None
    found: List[Any] = []
    for tree in trees:
        found.extend(tree.members())
    return found


def guard_for(platform: str | None = None) -> LifetimeGuard:
    """The only place the platform is tested.

    Every caller gets a LifetimeGuard and never asks which one it is: the Null
    implementation satisfies the same interface, so no launcher code branches
    on Windows.
    """
    name = os.name if platform is None else platform
    if name != "nt" or psutil is None or _ExtendedLimitInformation is None:
        return NullGuard()
    return JobObjectGuard.create()
