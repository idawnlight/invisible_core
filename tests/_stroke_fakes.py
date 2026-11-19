"""The fakes of the stroke tests: a clock that only moves when something sleeps or a reply is waited for, and an engine that answers late.

`Clock` stands in for `time` (the keyboard's, the pointer's and the pacer's: `monotonic`, `perf_counter`, `sleep`). `Engine` is a
connection that answers a command after `latency` (the event's own hold) plus `rtt_ms`, and `late[i]` more for the i-th command it
receives; `fail[i]` makes its reply an error. It records every command, when it went out, and when a reply was waited for (`log`), and it
refuses what the engine's `checkScheme` would (`_closed_world.check_command`). It answers `send` as well as `send_async`: the same test
runs on the code that blocked on each reply and on the code that does not.
"""
from __future__ import annotations

from _closed_world import check_command


class Clock:
    """`time` over a number the test owns."""

    def __init__(self) -> None:
        self.t = 1000.0

    def monotonic(self) -> float:
        return self.t

    perf_counter = monotonic

    def sleep(self, seconds: float) -> None:
        assert seconds >= 0.0, "a negative sleep"
        self.t += seconds


class Reply:
    def __init__(self, engine, ready_at, error, result) -> None:
        self.engine, self.ready_at, self.error, self.result = engine, ready_at, error, result

    def wait(self, timeout=None):
        self.engine.log.append(("wait", self.engine.clock.t))
        self.engine.clock.t = max(self.engine.clock.t, self.ready_at)
        if self.error is not None:
            raise self.error
        return self.result, 0


class Engine:
    def __init__(self, clock: Clock, rtt_ms: float = 5.0, late=None, fail=None, answer=None) -> None:
        self.clock = clock
        self.rtt_ms = rtt_ms
        self.late = late or {}      # index of the command -> extra ms before its reply
        self.fail = fail or {}      # index of the command -> the error its reply is
        self.answer = answer        # (method, params) -> the result of the reply
        self.sent = []              # (seconds, method, params): what went out, when
        self.log = []               # ("send", t) and ("wait", t), in order

    def send_async(self, method, params, session=None):
        check_command(method, params)
        index = len(self.sent)
        self.sent.append((self.clock.t, method, dict(params)))
        self.log.append(("send", self.clock.t))
        delay = (params.get("latency", 0.0) + self.late.get(index, 0.0) + self.rtt_ms) / 1000.0
        result = self.answer(method, params) if self.answer is not None else {}
        return Reply(self, self.clock.t + delay, self.fail.get(index), result)

    def send(self, method, params, session=None, timeout=None):
        return self.send_async(method, params, session).wait(timeout)[0]

    def params(self):
        return [p for _t, _m, p in self.sent]

    def offsets_ms(self, start):
        return [(t - start) * 1000.0 for t, _m, _p in self.sent]
