"""A key is sent at its planned instant from the start of the text, on the client's own clock, and no reply is waited for until the text ends.

THE KNOWN-BAD, measured on GitHub runners: the engine held the reply of a key event for its `latency` (PageAgent `_dispatchKeyEvent`:
`await setTimeout(latency)`) and a loaded host answered later still. The core slept the plan AFTER each reply, so the schedule was the
engine's: the first key reached the page at once and was answered 1.7 s later; the second, planned 276 ms after the first, was only
sent when that reply came (columns planned / sent / reply / page timeStamp, ms from the first send: 1st 0 / 0 / 1728 / -10; 2nd 276 /
1753 / 1756 / 1740), and every key after it slipped. The page saw a pause the plan does not have.

A text is one stroke (`_stroke.Stroke`): each command leaves at `t0 + at` and carries its stroke's id and its `at` (ms, from the stroke's
start; no clock is shared with the engine), the replies are collected when the text has been typed, and the error of any one command is
the error of the call, raised then.

No browser starts here: the real `Keyboard`, the real plan, a clock that only moves when something sleeps or a reply is waited for, and
a connection whose replies take the event's own `latency` plus a round trip the test picks. The fake answers `send` (what the code did
before) as well as `send_async`, so the same test runs on both and the old code fails it.
"""
from __future__ import annotations

import pytest

from _stroke_fakes import Clock, Engine
from invisible_core.juggler import keyboard as kb
from invisible_core.juggler._behaviour import InputLatency, PageActs, TypingPersona, plan_shift, plan_typing
from invisible_core.juggler.connection import ProtocolError

pytestmark = pytest.mark.unit

TEXT = "someone@example.com"
SEED = 2
RTTS = [0.0, 5.0, 60.0]


def _type(monkeypatch, text=TEXT, rtt_ms=5.0, late=None, fail=None, delay_ms=0.0, persona=True):
    clock = Clock()
    monkeypatch.setattr(kb, "time", clock)
    engine = Engine(clock, rtt_ms, late, fail)
    board = kb.Keyboard(engine, "s", TypingPersona.from_seed(SEED) if persona else None, acts=PageActs(0),
                        latency=InputLatency.from_seed(SEED) if persona else None)
    start = clock.t
    if delay_ms:
        board.type(text, delay_ms=delay_ms)
    else:
        board.type(text)
    return engine, start


def _expected(text):
    """(type, key, at ms) of every command the plan asks for, worked out here from the plan alone: a Shift run's Shift goes down `lead`
    before its first key and up `lag` after its last keyup; the plan starts when the first Shift goes down."""
    persona = TypingPersona.from_seed(SEED)
    plan = plan_typing(text, persona, nonce=PageActs(0).next("typing"))
    closure = kb.closure_for("us")
    shifted = [bool(closure[ch].get("needs_shift")) for ch in text]
    starts = [s and (i == 0 or not shifted[i - 1]) for i, s in enumerate(shifted)]
    ends = [s and (i == len(text) - 1 or not shifted[i + 1]) for i, s in enumerate(shifted)]
    timing = iter(plan_shift(persona, sum(starts), nonce=PageActs(0).next("typing-shift")))
    lead_at, lag_at = {}, {}
    for i in range(len(text)):
        if starts[i]:
            lead_at[i], lag = next(timing)
        if ends[i]:
            lag_at[i] = lag
    base = lead_at[0] if starts[0] else 0.0
    out, start = [], 0.0
    for i, ch in enumerate(text):
        dwell, gap = plan[i]
        if starts[i]:
            out.append(("keydown", "Shift", base + start - lead_at[i]))
        out.append(("keydown", closure[ch]["key"], base + start))
        out.append(("keyup", closure[ch]["key"], base + start + dwell))
        if ends[i]:
            out.append(("keyup", "Shift", base + start + dwell + lag_at[i]))
        start += dwell + gap
    floor, fixed = 0.0, []
    for typ, key, at in out:       # an instant behind the event before it goes right after it, as the stroke does
        floor = max(floor, at)
        fixed.append((typ, key, floor))
    return fixed


def _commands(engine):
    return [(p["type"], p["key"], p["at"]) for p in engine.params()]


STALLS = {"no stall": None, "a reply 1.5 s late": {4: 1500.0}, "a keyup reply 1.5 s late": {7: 1500.0}, "the first reply 1.7 s late": {0: 1700.0}}


@pytest.mark.parametrize("stall", list(STALLS))
@pytest.mark.parametrize("rtt_ms", RTTS)
def test_every_command_leaves_at_its_planned_instant_whatever_the_replies_cost(monkeypatch, rtt_ms, stall):
    engine, start = _type(monkeypatch, rtt_ms=rtt_ms, late=STALLS[stall])
    expected = _expected(TEXT)
    assert len(engine.sent) == len(expected)
    for (t, _m, _params), (typ, key, at) in zip(engine.sent, expected):
        assert (t - start) * 1000.0 == pytest.approx(at, abs=0.5), "%s %s sent %.1f ms from the start, planned %.1f" % (typ, key, (t - start) * 1000.0, at)


def test_a_first_keydown_answered_1_7_s_late_does_not_move_the_second_command(monkeypatch):
    """The measured case: the engine answers the first keydown after 1.7 s. The second command (that key's keyup) leaves at its planned
    instant, one dwell after the first; sent behind that reply it went out at 1.75 s."""
    engine, start = _type(monkeypatch, rtt_ms=5.0, late={0: 1700.0})
    planned = _expected(TEXT)[1][2]
    second = (engine.sent[1][0] - start) * 1000.0
    assert second == pytest.approx(planned, abs=50.0), "the second command left at %.0f ms, planned %.0f" % (second, planned)
    assert second < 500.0


def test_every_command_of_a_text_carries_the_one_stroke_and_the_plan_s_offsets(monkeypatch):
    engine, _start = _type(monkeypatch)
    expected = _expected(TEXT)
    got = _commands(engine)
    assert [(a, b) for a, b, _ in got] == [(a, b) for a, b, _ in expected]
    assert [at for _, _, at in got] == pytest.approx([at for _, _, at in expected])
    assert any(key == "Shift" for _, key, _ in got), "no Shift run in the text: the test is not testing"
    ats = [at for _, _, at in got]
    assert ats == sorted(ats) and ats[0] == 0.0
    assert len({p["stroke"] for p in engine.params()}) == 1
    assert all(isinstance(p["stroke"], str) and p["stroke"] for p in engine.params())


def test_a_text_that_starts_under_shift_starts_its_plan_at_the_shift(monkeypatch):
    engine, _start = _type(monkeypatch, text="Ab")
    expected = _expected("Ab")
    got = _commands(engine)
    assert [(a, b) for a, b, _ in got] == [("keydown", "Shift"), ("keydown", "A"), ("keyup", "A"), ("keyup", "Shift"),
                                           ("keydown", "b"), ("keyup", "b")]
    assert [at for _, _, at in got] == pytest.approx([at for _, _, at in expected])
    assert got[0][2] == 0.0 and got[1][2] > 0.0, "the first Shift is the start of the stroke, its key a lead later"


def test_two_texts_are_two_strokes(monkeypatch):
    clock = Clock()
    monkeypatch.setattr(kb, "time", clock)
    engine = Engine(clock, 5.0)
    board = kb.Keyboard(engine, "s", TypingPersona.from_seed(SEED), acts=PageActs(0))
    board.type("ab")
    n = len(engine.sent)
    board.type("cd")
    first = {p["stroke"] for _t, _m, p in engine.sent[:n]}
    second = {p["stroke"] for _t, _m, p in engine.sent[n:]}
    assert len(first) == len(second) == 1 and first != second
    assert engine.sent[n][2]["at"] == 0.0, "the second text counts its offsets from its own start"


def test_no_reply_is_waited_for_until_the_text_has_been_typed(monkeypatch):
    engine, _start = _type(monkeypatch)
    kinds = [k for k, _t in engine.log]
    assert kinds == ["send"] * len(engine.sent) + ["wait"] * len(engine.sent), "a reply was waited for in the middle of the text"


def test_the_reply_of_a_middle_key_that_fails_is_raised_after_the_text_is_typed(monkeypatch):
    with pytest.raises(ProtocolError, match="no such key"):
        _type(monkeypatch, fail={5: ProtocolError("Page.dispatchKeyEvent: no such key")})


def test_a_failure_in_the_middle_loses_no_command_and_leaves_no_reply_unread(monkeypatch):
    clock = Clock()
    monkeypatch.setattr(kb, "time", clock)
    engine = Engine(clock, 5.0, fail={5: ProtocolError("boom")})
    board = kb.Keyboard(engine, "s", TypingPersona.from_seed(SEED), acts=PageActs(0))
    with pytest.raises(ProtocolError):
        board.type(TEXT)
    assert [(a, b) for a, b, _ in _commands(engine)] == [(a, b) for a, b, _ in _expected(TEXT)], "a command was lost to the failure"
    assert [k for k, _t in engine.log].count("wait") == len(engine.sent), "a reply was left unread"


def test_the_first_of_two_failures_in_order_is_the_one_raised(monkeypatch):
    with pytest.raises(ProtocolError, match="first"):
        _type(monkeypatch, fail={9: ProtocolError("second"), 3: ProtocolError("first")})


def test_the_same_seed_is_sent_at_the_same_times_twice(monkeypatch):
    first = _type(monkeypatch, rtt_ms=5.0)
    second = _type(monkeypatch, rtt_ms=5.0)
    a = [(round((t - first[1]) * 1000.0, 6), p["type"], p["key"], p["at"]) for t, _m, p in first[0].sent]
    b = [(round((t - second[1]) * 1000.0, 6), p["type"], p["key"], p["at"]) for t, _m, p in second[0].sent]
    assert a == b


def test_humanize_off_with_a_delay_is_on_the_callers_delay_whatever_a_reply_costs(monkeypatch):
    """`type("abcd", delay=150)` with no persona: a keydown every 150 ms from the start, on the client's clock, one reply 300 ms late."""
    engine, start = _type(monkeypatch, text="abcd", rtt_ms=5.0, late={2: 300.0}, delay_ms=150.0, persona=False)
    downs = [(t - start) * 1000.0 for t, _m, p in engine.sent if p["type"] == "keydown"]
    assert downs == pytest.approx([0.0, 150.0, 300.0, 450.0], abs=0.5)
