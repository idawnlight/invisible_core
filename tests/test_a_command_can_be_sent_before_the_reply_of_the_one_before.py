"""`Connection.send_async` writes a command and returns at once; the reply is waited on later, with the handle.

The clients that schedule on their own clock (`_stroke.Stroke`) cannot wait for the reply of a command before they send the next one.
`send` is `send_async` and the wait, and it keeps what it did: the same result, the same errors.

No browser starts here: the two pipes are `os.pipe()` pairs whose browser ends the test holds.
"""
from __future__ import annotations

import json
import os
import threading
import time

import pytest

from invisible_core.juggler.connection import Connection, ProtocolError, ReplyTimeout

pytestmark = pytest.mark.unit


class _Browser:
    def __init__(self) -> None:
        self.to_r, to_w = os.pipe()
        from_r, self.from_w = os.pipe()
        self.connection = Connection(to_w, from_r, None)
        self._buffer = b""

    def received(self, n: int) -> list:
        """The next `n` commands the client wrote."""
        out, deadline = [], time.monotonic() + 5
        while len(out) < n and time.monotonic() < deadline:
            while b"\0" not in self._buffer:
                self._buffer += os.read(self.to_r, 65536)
            raw, self._buffer = self._buffer.split(b"\0", 1)
            out.append(json.loads(raw))
        assert len(out) == n, "the commands never went out"
        return out

    def answers(self, message: dict) -> None:
        os.write(self.from_w, json.dumps(message).encode() + b"\0")

    def release(self) -> None:
        os.close(self.to_r)
        os.close(self.from_w)
        self.connection._reader.join(5)
        self.connection.close(timeout=5)


def test_two_commands_are_written_before_the_first_is_answered_and_each_reply_finds_its_handle():
    b = _Browser()
    first = b.connection.send_async("Page.dispatchKeyEvent", {"type": "keydown"}, "S")
    second = b.connection.send_async("Page.dispatchKeyEvent", {"type": "keyup"}, "S")
    sent = b.received(2)
    assert [m["params"]["type"] for m in sent] == ["keydown", "keyup"]
    assert all(m["sessionId"] == "S" for m in sent)
    b.answers({"id": sent[1]["id"], "result": {"n": 2}})      # answered out of order, the second first
    b.answers({"id": sent[0]["id"], "result": {"n": 1}})
    assert second.wait(5)[0] == {"n": 2}
    assert first.wait(5)[0] == {"n": 1}
    b.release()


def test_an_error_reply_is_raised_by_the_wait_and_not_by_the_send():
    b = _Browser()
    handle = b.connection.send_async("Page.dispatchKeyEvent", {"type": "keydown"})
    (sent,) = b.received(1)
    b.answers({"id": sent["id"], "error": {"message": "no such key"}})
    with pytest.raises(ProtocolError, match="no such key"):
        handle.wait(5)
    b.release()


def test_a_reply_that_does_not_come_is_the_waits_timeout():
    b = _Browser()
    handle = b.connection.send_async("Page.dispatchKeyEvent", {"type": "keydown"})
    b.received(1)
    with pytest.raises(ReplyTimeout):
        handle.wait(0.05)
    b.release()


def test_send_still_waits_for_its_own_reply():
    b = _Browser()
    got = []
    t = threading.Thread(target=lambda: got.append(b.connection.send("Browser.getInfo", timeout=5)))
    t.start()
    (sent,) = b.received(1)
    assert t.is_alive(), "send returned before its reply"
    b.answers({"id": sent["id"], "result": {"ok": True}})
    t.join(5)
    assert got == [{"ok": True}]
    b.release()
