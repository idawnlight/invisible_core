"""Every session declares the counter URL, whose fork default is empty.

An explicit session URL or enabled setting continues to override the default.
"""
from __future__ import annotations

from invisible_core._fpforge import generate_profile
from invisible_core.prefs import USAGE_PING_URL, compose_session_prefs

KEY = "invisible_firefox.usage_ping.url"


def test_every_session_declares_where_to_report_a_launch():
    profile = generate_profile(seed=4242)
    for virtual_display in (False, True):
        prefs = compose_session_prefs(profile,
                                      virtual_display=virtual_display, timezone="America/New_York").prefs
        assert prefs[KEY] == USAGE_PING_URL, (
            "a session with virtual_display=%r would let the engine fall back "
            "to the address compiled into it" % virtual_display)


def test_the_default_address_matches_the_fork_engine():
    assert USAGE_PING_URL == ""


def test_a_caller_can_still_point_it_elsewhere_or_turn_it_off():
    """setdefault, so an explicit override wins: the pref exists to be movable,
    and the enabled switch is the documented way to opt out."""
    profile = generate_profile(seed=7)
    moved = compose_session_prefs(profile, extra_prefs={KEY: "https://example.invalid/x"}, timezone="America/New_York").prefs
    assert moved[KEY] == "https://example.invalid/x"
    off = compose_session_prefs(
        profile, extra_prefs={"invisible_firefox.usage_ping.enabled": False}, timezone="America/New_York").prefs
    assert off["invisible_firefox.usage_ping.enabled"] is False
