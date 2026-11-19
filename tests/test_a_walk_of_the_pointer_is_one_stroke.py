"""`Actions.walk`: a timeline of the pointer (a path, a wheel burst) is ONE stroke, whoever drew it.

THE KNOWN-BAD, measured on a GitHub runner (hunt 43794672372): the Playwright wrapper's cursor asked the `Pacer` for the instant of each
point, but sent each one as a lone command and waited for its reply before asking for the next. A slow reply of the engine stopped the
path (the page saw a 2.6 s pause) and the points after it were then crowded together. The keys had the same defect before the stroke.

`walk` takes the events of a plan (`_pacing.Ev`, with their `t_ms`) and sends each one at its instant, carrying `stroke` and `at`, without
waiting for any reply; the replies are collected at the end, the first failure in order is the call's and no point is lost to it. An
explicit `move`, of one step or many, and `mouse_down` / `mouse_up` stay single commands that wait for their own reply, as in stock
Playwright: they are the caller's explicit calls, not a human path.

No browser starts here: the real `Actions` over the clock and the engine of `_stroke_fakes.py`. Nothing asserts on time: a reply is held
(`late`) and what is asserted is what had gone out when it was waited for.
"""
from __future__ import annotations

import pytest

from _stroke_fakes import Clock, Engine
from invisible_core.juggler import _pacing
from invisible_core.juggler import actions as actions_module
from invisible_core.juggler._behaviour import PageActs
from invisible_core.juggler._pacing import Ev
from invisible_core.juggler.actions import Actions
from invisible_core.juggler.connection import ProtocolError

pytestmark = pytest.mark.unit

#: A path of six points, 20 ms apart: the instants the pacer was asked for.
PATH = [Ev(20.0 * (i + 1), 100.0 + 10.0 * i, 50.0) for i in range(6)]


def _actions(monkeypatch, **engine_kw):
    clock = Clock()
    monkeypatch.setattr(actions_module, "time", clock)
    monkeypatch.setattr(_pacing, "time", clock)
    engine = Engine(clock, **engine_kw)
    return Actions(engine, "S", None, None, acts=PageActs(1), session_seed=7), engine, clock


def _mouse(engine):
    return [p for _t, m, p in engine.sent if m == "Page.dispatchMouseEvent"]


def _walked(a):
    a.position = (90.0, 50.0)
    return a.walk(PATH)


def test_a_point_is_sent_while_the_reply_of_the_one_before_is_held(monkeypatch):
    a, engine, clock = _actions(monkeypatch, late={1: 2600.0})
    assert _walked(a) == len(PATH)
    assert [k for k, _t in engine.log] == ["send"] * len(PATH) + ["wait"] * len(PATH), "a point waited for a reply"


def test_every_point_carries_its_stroke_and_its_instant(monkeypatch):
    a, engine, clock = _actions(monkeypatch, late={1: 2600.0})
    _walked(a)
    moves = _mouse(engine)
    assert [p["type"] for p in moves] == ["mousemove"] * len(PATH)
    assert [(p["x"], p["y"]) for p in moves] == [(e.x, e.y) for e in PATH]
    assert [p["at"] for p in moves] == [e.t_ms for e in PATH]
    assert len({p["stroke"] for p in moves}) == 1
    assert a.position == (PATH[-1].x, PATH[-1].y)


def test_a_failed_reply_is_raised_at_the_end_and_no_point_is_lost(monkeypatch):
    a, engine, clock = _actions(monkeypatch, fail={1: ProtocolError("Page.dispatchMouseEvent: first"),
                                                   3: ProtocolError("Page.dispatchMouseEvent: second")})
    with pytest.raises(ProtocolError, match="first"):
        _walked(a)
    assert len(_mouse(engine)) == len(PATH), "the path stopped at the failure"
    assert [k for k, _t in engine.log] == ["send"] * len(PATH) + ["wait"] * len(PATH)


def test_a_wheel_notch_of_the_walk_is_in_the_stroke_at_its_instant(monkeypatch):
    plan = [Ev(20.0, 100.0, 50.0), Ev(40.0, 100.0, 50.0, "wheel", 0.0, 100.0), Ev(60.0, 110.0, 50.0),
            Ev(80.0, 110.0, 50.0, "wheel", 0.0, 120.0)]
    a, engine, clock = _actions(monkeypatch, late={1: 2600.0})
    a.position = (90.0, 50.0)
    assert a.walk(plan) == 4
    sent = [(m, p) for _t, m, p in engine.sent]
    assert [m for m, _p in sent] == ["Page.dispatchMouseEvent", "Page.dispatchWheelEvent",
                                     "Page.dispatchMouseEvent", "Page.dispatchWheelEvent"]
    assert [p["at"] for _m, p in sent] == [20.0, 40.0, 60.0, 80.0]
    assert len({p["stroke"] for _m, p in sent}) == 1
    assert [p["deltaY"] for m, p in sent if m == "Page.dispatchWheelEvent"] == [100.0, 120.0]
    assert [k for k, _t in engine.log] == ["send"] * 4 + ["wait"] * 4


def test_the_last_event_is_left_to_the_caller_when_asked(monkeypatch):
    a, engine, clock = _actions(monkeypatch)
    a.position = (90.0, 50.0)
    assert a.walk(PATH, emit_last=False) == len(PATH) - 1
    assert len(_mouse(engine)) == len(PATH) - 1


def test_an_explicit_multi_step_move_stays_as_it_was_one_command_per_step(monkeypatch):
    a, engine, clock = _actions(monkeypatch, late={1: 2600.0})
    a.position = (0.0, 0.0)
    a.move(50.0, 0.0, steps=5)
    assert [k for k, _t in engine.log] == ["send", "wait"] * 5, "an explicit move left as a burst"
    moves = _mouse(engine)
    assert [p["x"] for p in moves] == [10.0, 20.0, 30.0, 40.0, 50.0]
    assert all("stroke" not in p and "at" not in p for p in moves)


def test_a_one_step_move_and_a_press_and_a_release_each_wait_for_their_own_reply(monkeypatch):
    a, engine, clock = _actions(monkeypatch)
    a.move(10.0, 10.0)
    a.mouse_down()
    a.mouse_up()
    assert [k for k, _t in engine.log] == ["send", "wait"] * 3
    assert all("stroke" not in p and "at" not in p for p in _mouse(engine))
