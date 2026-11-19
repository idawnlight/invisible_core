"""A mouse path, a click and a wheel notch are strokes: each command leaves at its planned instant, whatever the engine answers late.

THE KNOWN-BAD, the pointer's side of the defect the keyboard had (`test_typing_is_on_the_plan_not_on_the_replies.py`): every mouse event
was sent and its reply waited for before the next one, and the plan's dwell and gap slept after that reply. The engine holds the reply
of an input event for its `latency` and answers late under load, so the press-to-release time and every point of a path slipped with it:
the page saw a click held, and a path drawn, that the plan does not have.

A path, a click (and a double click) and a wheel notch each carry one `stroke` and, per command, its `at` (ms from the start of the
gesture). The replies are collected when the gesture ends: the landing an event reports (`landsOn`) is kept then, before the commit that
sent it returns, and the error of any command is the call's, raised then.

No browser starts here: the real `Actions` and the real plans, over the clock and the engine of `_stroke_fakes.py`.
"""
from __future__ import annotations

import pytest

from _stroke_fakes import Clock, Engine
from invisible_core.juggler import _pacing
from invisible_core.juggler import actions as actions_module
from invisible_core.juggler._behaviour import PageActs, PointerPersona, plan_click
from invisible_core.juggler.actions import Actions
from invisible_core.juggler.connection import ProtocolError

pytestmark = pytest.mark.unit

POINT = (120.0, 80.0)


def _actions(monkeypatch, **engine_kw):
    clock = Clock()
    monkeypatch.setattr(actions_module, "time", clock)
    monkeypatch.setattr(_pacing, "time", clock)
    engine = Engine(clock, **engine_kw)
    return Actions(engine, "S", None, None, acts=PageActs(1), session_seed=7), engine, clock


def _mouse(engine):
    return [(t, p) for t, m, p in engine.sent if m == "Page.dispatchMouseEvent"]


def _plan(clicks):
    """The click's plan as `_click_plan` draws it on a fresh page: the first draw of the `click` act."""
    return plan_click(PointerPersona.from_seed(7), clicks, nonce=PageActs(1).next("click"))


def _click_offsets(plan):
    at, out = 0.0, []
    for dwell, gap in plan:
        out += [("mousedown", at), ("mouseup", at + dwell)]
        at += dwell + gap
    return out


def test_a_click_leaves_each_press_and_release_at_its_planned_instant(monkeypatch):
    a, engine, clock = _actions(monkeypatch)
    start = clock.t
    a._click_at_point(POINT, clicks=2)
    got = [(p["type"], p["at"]) for _t, p in _mouse(engine)]
    want = _click_offsets(_plan(2))
    assert [k for k, _ in got] == [k for k, _ in want] == ["mousedown", "mouseup", "mousedown", "mouseup"]
    assert [at for _, at in got] == pytest.approx([at for _, at in want])
    assert len({p["stroke"] for _t, p in _mouse(engine)}) == 1
    assert [t * 1000.0 for t in (t - start for t, _p in _mouse(engine))] == pytest.approx([at for _, at in want], abs=0.5)


def test_a_press_answered_1_7_s_late_does_not_move_the_release(monkeypatch):
    """The release is the press plus the dwell on the client's clock; it was sent behind the press's reply, 1.7 s later."""
    a, engine, clock = _actions(monkeypatch, late={0: 1700.0})
    start = clock.t
    a._click_at_point(POINT)
    release = (_mouse(engine)[1][0] - start) * 1000.0
    assert release == pytest.approx(_plan(1)[0][0], abs=50.0)
    assert release < 500.0


def test_the_landing_of_each_event_is_kept_before_the_click_returns(monkeypatch):
    def answer(method, params):
        return {"landing": {"type": params["type"], "landed": True, "seen": 1, "on": ""}}
    a, engine, clock = _actions(monkeypatch, answer=answer)
    a._landing_target, a._landings = ("frame", "element"), {}
    a._click_at_point(POINT)
    assert sorted(a._landings) == ["mousedown", "mouseup"]
    assert all(v["landed"] for v in a._landings.values())
    assert all(p["landsOn"] == {"frameId": "frame", "objectId": "element"} for _t, p in _mouse(engine))


def test_an_error_reply_to_the_press_is_raised_after_the_release_has_gone(monkeypatch):
    a, engine, clock = _actions(monkeypatch, fail={0: ProtocolError("Page.dispatchMouseEvent: refused")})
    with pytest.raises(ProtocolError, match="refused"):
        a._click_at_point(POINT)
    assert [p["type"] for _t, p in _mouse(engine)] == ["mousedown", "mouseup"], "the release was lost to the failure"
    assert [k for k, _t in engine.log] == ["send", "send", "wait", "wait"]


def test_two_clicks_are_two_strokes(monkeypatch):
    a, engine, clock = _actions(monkeypatch)
    a._click_at_point(POINT)
    a._click_at_point(POINT)
    ids = [p["stroke"] for _t, p in _mouse(engine)]
    assert ids[0] == ids[1] and ids[2] == ids[3] and ids[0] != ids[2]
    assert [p["at"] for _t, p in _mouse(engine)][2] == 0.0


def test_a_path_leaves_each_point_at_its_planned_instant_whatever_the_replies_cost(monkeypatch):
    a, engine, clock = _actions(monkeypatch, late={0: 1700.0, 3: 900.0})
    start = clock.t
    a.glide_to(420.0, 300.0)
    moves = _mouse(engine)
    assert len(moves) > 3, "a path of one point is not a path"
    assert {p["type"] for _t, p in moves} == {"mousemove"}
    assert len({p["stroke"] for _t, p in moves}) == 1
    ats = [p["at"] for _t, p in moves]
    assert ats == sorted(ats) and len(set(ats)) == len(ats), "the instants of a path increase"
    for t, p in moves:
        assert (t - start) * 1000.0 == pytest.approx(p["at"], abs=1.0), "a point left %.0f ms behind its instant" % ((t - start) * 1000.0 - p["at"])
    assert [k for k, _t in engine.log] == ["send"] * len(moves) + ["wait"] * len(moves)
    assert a.position == (420.0, 300.0)


def test_an_error_reply_to_a_middle_point_is_raised_after_the_path_is_drawn(monkeypatch):
    a, engine, clock = _actions(monkeypatch, fail={2: ProtocolError("Page.dispatchMouseEvent: refused")})
    with pytest.raises(ProtocolError, match="refused"):
        a.glide_to(420.0, 300.0)
    moves = _mouse(engine)
    assert len(moves) > 3 and (moves[-1][1]["x"], moves[-1][1]["y"]) == (420.0, 300.0), "the path stopped at the failure"


def test_a_wheel_notch_is_a_stroke_of_its_own(monkeypatch):
    a, engine, clock = _actions(monkeypatch)
    a.wheel(0, 120)
    a.wheel(0, -120)
    wheels = [p for _t, m, p in engine.sent if m == "Page.dispatchWheelEvent"]
    assert [p["deltaY"] for p in wheels] == [120, -120]
    assert [p["at"] for p in wheels] == [0.0, 0.0]
    assert wheels[0]["stroke"] != wheels[1]["stroke"]


def test_an_error_reply_to_a_wheel_notch_is_the_calls(monkeypatch):
    a, engine, clock = _actions(monkeypatch, fail={0: ProtocolError("Page.dispatchWheelEvent: refused")})
    with pytest.raises(ProtocolError, match="refused"):
        a.wheel(0, 120)
