"""A stroke: the commands of one gesture, each sent at its own planned instant on the CLIENT's clock.

⛔ WHY THIS IS ITS OWN MODULE. A gesture (one `type()`, one mouse path, one click, one wheel notch) has a plan: the instants, from its
start, at which each command should reach the page. The clients used to send a command, wait for its reply, and sleep the planned gap
AFTER the reply. The engine holds the reply of an input event for its `latency` and a loaded host answers later still, so the schedule
was the engine's: measured on GitHub runners, the first key of a text was received by the page at once and answered 1.7 s later; the
second key, planned 276 ms after the first, was only sent when that reply came, and every key after it slipped by as much. The page saw
a pause the plan does not have.

So a stroke owns the clock. It is started once (`t0`, `time.monotonic()`), and each command leaves at `t0 + at` whatever the engine
has answered, without waiting for the reply of the command before it. The replies are collected when the stroke ends: the error of any
one command is still the error of the call, raised after the stroke, the first one in order, and no command is lost to it.

Every tagged command carries two optional fields of the protocol, `stroke` (this stroke's id, unique in the process and so in the
session) and `at` (its instant, in ms, FROM THE STROKE'S OWN START). The client and the engine share no clock: only offsets travel.

The keyboard, the pointer and the wheel all send through here; a second copy of the schedule is the defect this replaced.
"""
from __future__ import annotations

import contextlib
import itertools
import time
from typing import Any, Callable, Optional

#: One counter for the process: two strokes never share an id, in any session of it.
_IDS = itertools.count(1)


class Stroke:
    """The commands of one gesture, and their replies, collected at the end.

    `now` and `wait` are the owner's clock (seconds): the keyboard and the pointer pass their own, so a test drives a whole gesture
    without waiting for it."""

    def __init__(self, connection, session: Optional[str], *, now: Callable[[], float] = time.monotonic,
                 wait: Callable[[float], None] = time.sleep) -> None:
        self.id = "s%d" % next(_IDS)
        self._c = connection
        self._session = session
        self._now = now
        self._wait = wait
        self.t0 = now()
        #: One entry per command, in the order sent: (handle or None, the failure it already has, what to do with its result).
        self._sent: list = []

    def elapsed_ms(self) -> float:
        """How long this stroke has run on the client's clock."""
        return (self._now() - self.t0) * 1000.0

    def hold_until(self, at_ms: float) -> None:
        """Wait, on the client's clock, until `at_ms` of the stroke (a click's last gap); nothing if it has passed."""
        left = self.t0 + at_ms / 1000.0 - self._now()
        if left > 0.0:
            self._wait(left)

    def send(self, method: str, params: dict, at_ms: float, *, tagged: bool = True, paced: bool = False,
             on_result: Optional[Callable[[Any], None]] = None) -> None:
        """Send `method` at `at_ms` from the start of the stroke and return without its reply.

        `tagged` False leaves the command as it is: a command whose schema does not declare `stroke` and `at` (the closed world of the
        protocol rejects an undeclared field) still goes at its instant. `paced` True means the caller already waited for the instant
        (the pointer's `Pacer` owns its clock and may drop or delay an event on purpose), and none is waited for here. `on_result`
        receives the reply when the stroke ends."""
        if not paced:
            self.hold_until(at_ms)
        if tagged:
            params["stroke"] = self.id
            params["at"] = float(at_ms)
        send_async = getattr(self._c, "send_async", None)
        try:
            if send_async is not None:
                self._sent.append((send_async(method, params, self._session), None, on_result))
            else:
                # A stand-in that has only `send` (a test's fake) answers at once: its reply is already here.
                self._sent.append((None, (self._c.send(method, params, session=self._session, timeout=None),), on_result))
        except Exception as failure:  # noqa: BLE001 - raised by `finish`, after the stroke, like a reply's
            self._sent.append((None, failure, None))

    def finish(self, until_ms: Optional[float] = None, *, raising: bool = True) -> None:
        """Collect every reply, in the order sent, and raise the first failure once all are in.

        `until_ms` first lets the stroke run to its planned end (a click's last gap). With `raising` False the failures are taken and
        dropped: the caller is already unwinding from another exception, and a second one would hide it."""
        if until_ms is not None:
            self.hold_until(until_ms)
        first: Optional[BaseException] = None
        for handle, held, on_result in self._sent:
            try:
                if isinstance(held, BaseException):
                    raise held
                result = held[0] if handle is None else handle.wait(None)[0]
                if on_result is not None:
                    on_result(result)
            except Exception as failure:  # noqa: BLE001 - the first, in order, is the call's
                if first is None:
                    first = failure
        self._sent = []
        if first is not None and raising:
            raise first

    @classmethod
    @contextlib.contextmanager
    def within(cls, owner, connection, session: Optional[str], *, now: Callable[[], float] = time.monotonic,
               wait: Callable[[float], None] = time.sleep):
        """The stroke of `owner` (its `_stroke` attribute): the one already running, or a new one that ends with the block.

        A gesture made of gestures (a typed text made of key presses) is one stroke: the inner block joins the outer one."""
        if owner._stroke is not None:
            yield owner._stroke
            return
        stroke = owner._stroke = cls(connection, session, now=now, wait=wait)
        try:
            yield stroke
        except BaseException:
            owner._stroke = None
            stroke.finish(raising=False)
            raise
        owner._stroke = None
        stroke.finish()
