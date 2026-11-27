"""A selector that resolves to nothing is already `hidden` and already `detached`: the wait returns at once.

Stock Playwright's `Frame.waitForSelector` says it in one place: when the selector resolves to no
element and the state is `hidden` or `detached` it returns null without another turn
(`if (!resolved) { if (state === "hidden" || state === "detached") return null; return continuePolling; }`),
and `hidden` or `detached` never hands back a handle, because the element it was waiting for is not
there to be handed back. `Actions.wait_for_selector` kept polling until the timeout when nothing
matched `hidden` (a script waiting for a spinner that was already gone stalled for its whole timeout and
then raised), and returned the element for a present element that is not visible.

The fakes are those of `test_no_limit_is_none.py` (the clock that jumps 100 s on every reading, so a wait
that did not return in its first turn is the one that raises) and a `sleep` that fails the test, since a
turn that sleeps is a second turn. A wait that must keep waiting runs on a clock that moves 10 s a reading,
so it makes several turns before its 30 s are over.
"""
from __future__ import annotations

import itertools

import pytest

from invisible_core.juggler import PageActs, deadline as deadline_module
from invisible_core.juggler.actions import Actions, ElementNotActionable

from test_no_limit_is_none import _Clock


class _SlowClock:
    """`time.monotonic` that moves 10 s on every reading: a 30 s wait makes a few turns, then expires."""

    def __init__(self):
        self._ticks = itertools.count(0, 10.0)

    def monotonic(self):
        return next(self._ticks)


class _Injected:
    """A frame with at most one element that is, or is not, visible."""

    def __init__(self, element=None, visible=True):
        self.element = element
        self.visible = visible
        self.queries = 0
        self.disposed = []

    def query_selector(self, frame, selector, strict=False):
        self.queries += 1
        return self.element

    def element_state(self, frame, element, state):
        return self.visible if state == "visible" else not self.visible

    def dispose(self, frame, element):
        self.disposed.append(element)


class _Lifecycle:
    main_frame = "frame-1"


def _actions(injected):
    return Actions(object(), "s", _Lifecycle(), injected, acts=PageActs(1))


@pytest.fixture
def one_turn(monkeypatch):
    """A clock that expires any finite wait after a few readings, and a sleep that is a failure."""
    clock = _Clock()
    monkeypatch.setattr(deadline_module.time, "monotonic", clock.monotonic)

    def no_second_turn(seconds):
        raise AssertionError("the wait went round again: a second turn sleeps first")

    monkeypatch.setattr("invisible_core.juggler.actions.time.sleep", no_second_turn)


@pytest.fixture
def jumping_clock(monkeypatch):
    clock = _SlowClock()
    monkeypatch.setattr(deadline_module.time, "monotonic", clock.monotonic)
    monkeypatch.setattr("invisible_core.juggler.actions.time.sleep", lambda s: None)


@pytest.mark.unit
def test_hidden_with_no_element_returns_none_in_the_first_turn(one_turn):
    injected = _Injected(element=None)
    assert _actions(injected).wait_for_selector("#gone", state="hidden", timeout=30.0) is None
    assert injected.queries == 1


@pytest.mark.unit
def test_hidden_with_no_element_returns_none_without_a_limit(one_turn):
    injected = _Injected(element=None)
    assert _actions(injected).wait_for_selector("#gone", state="hidden", timeout=None) is None
    assert injected.queries == 1


@pytest.mark.unit
def test_detached_with_no_element_returns_none_in_the_first_turn(one_turn):
    injected = _Injected(element=None)
    assert _actions(injected).wait_for_selector("#gone", state="detached", timeout=30.0) is None
    assert injected.queries == 1


@pytest.mark.unit
def test_hidden_on_a_present_invisible_element_returns_none_and_lets_the_handle_go(one_turn):
    injected = _Injected(element="node", visible=False)
    assert _actions(injected).wait_for_selector("#x", state="hidden", timeout=30.0) is None
    assert injected.queries == 1
    assert injected.disposed == ["node"]


@pytest.mark.unit
def test_hidden_on_a_present_visible_element_keeps_waiting(jumping_clock):
    injected = _Injected(element="node", visible=True)
    with pytest.raises(ElementNotActionable):
        _actions(injected).wait_for_selector("#x", state="hidden", timeout=30.0)
    assert injected.queries > 1


@pytest.mark.unit
def test_detached_on_a_present_element_keeps_waiting(jumping_clock):
    injected = _Injected(element="node", visible=False)
    with pytest.raises(ElementNotActionable):
        _actions(injected).wait_for_selector("#x", state="detached", timeout=30.0)
    assert injected.queries > 1


@pytest.mark.unit
def test_the_default_visible_still_waits_for_a_selector_that_matches_nothing(jumping_clock):
    injected = _Injected(element=None)
    with pytest.raises(ElementNotActionable):
        _actions(injected).wait_for_selector("#gone", timeout=30.0)
    assert injected.queries > 1


@pytest.mark.unit
def test_the_default_visible_still_returns_the_visible_element(one_turn):
    injected = _Injected(element="node", visible=True)
    assert _actions(injected).wait_for_selector("#x", timeout=30.0) == "node"
    assert injected.disposed == []


@pytest.mark.unit
def test_attached_with_no_element_still_waits(jumping_clock):
    with pytest.raises(ElementNotActionable):
        _actions(_Injected(element=None)).wait_for_selector("#gone", state="attached", timeout=30.0)
