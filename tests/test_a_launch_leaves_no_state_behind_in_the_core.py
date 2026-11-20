"""A normal launch changes nothing that the core keeps in its modules.

⛔ THE DYNAMIC HALF of ``test_the_core_keeps_no_memory_cache.py`` (which reads the source): this one RUNS the launch and
compares the modules of the core before and after. The source can hide a memo in a shape the scan does not know; a
launch that fills one cannot hide it from a snapshot of every module-level container, every rebound global, every
``lru_cache`` and every class-level container of the core.

The launch is the wrapper's, end to end and hermetic: the seal, the engine's own identity read from a tree on disk,
``prepare_session_geo`` (direct, and behind a SOCKS5 proxy with a UDP relay on loopback), the fingerprint, the prefs,
``write_user_js``, the keyboard, ``instance.launch`` against a fake browser on OS pipes, and a context given a proxy.
What may change is what ``EXCEPTIONS`` of the static test names, and nothing else.
"""
from __future__ import annotations

import collections
import importlib
import pkgutil
import sys
import types

import pytest

from _udp_gateway import FakeStun, UdpGateway
from test_a_launch_has_one_deadline import _Browser
from test_the_core_keeps_no_memory_cache import EXCEPTIONS

import invisible_core
from invisible_core import _geo, _udp_exit

pytestmark = pytest.mark.unit

EXIT = "203.0.113.7"
_CONTAINERS = (dict, list, set, collections.deque, bytearray)


def _import_every_module():
    for info in pkgutil.walk_packages(invisible_core.__path__, "invisible_core."):
        try:
            importlib.import_module(info.name)
        except Exception:  # noqa: BLE001 - a module that cannot be imported here (a platform's) has no state to compare
            pass


def _excused():
    """The (module, name) the static test excuses, in the form the snapshot uses."""
    return {("invisible_core." + key.split(":")[0], key.split(":")[1]) for key in EXCEPTIONS}


def _state_of(value):
    """What to compare of a value: its identity, and its size when it holds things; a cache's fill for a cached function."""
    info = getattr(value, "cache_info", None)
    if callable(info):
        try:
            return (id(value), info().currsize)
        except Exception:  # noqa: BLE001
            pass
    if isinstance(value, _CONTAINERS):
        return (id(value), len(value))
    return (id(value), None)


def _snapshot():
    """{(module, name): state} for every module-level name that is not a module, a class, a function or a dunder, and
    for every class-level container of a class the core defines."""
    out = {}
    for module_name, module in sorted(sys.modules.items()):
        if module_name != "invisible_core" and not module_name.startswith("invisible_core."):
            continue
        if module is None:
            continue
        for name, value in list(vars(module).items()):
            if name.startswith("__") and name.endswith("__"):
                continue
            if isinstance(value, types.ModuleType):
                continue
            if isinstance(value, type):
                if getattr(value, "__module__", None) == module_name:
                    for attr, item in list(vars(value).items()):
                        if attr.startswith("__") and attr.endswith("__"):
                            continue
                        if isinstance(item, _CONTAINERS):
                            out[(module_name, "%s.%s" % (name, attr))] = _state_of(item)
                continue
            if isinstance(value, (types.FunctionType, types.BuiltinFunctionType)) and not hasattr(value, "cache_info"):
                continue
            out[(module_name, name)] = _state_of(value)
    return out


@pytest.fixture
def engine_tree(tmp_path):
    """A tree on disk that `seal.read_engine_identity` reads: the executable, application.ini and platform.ini."""
    root = tmp_path / "engine"
    root.mkdir()
    (root / "firefox").write_bytes(b"\x7fELF-not-run")
    (root / "application.ini").write_text("[App]\nVersion=159.0\nBuildID=20260101000000\n", encoding="utf-8")
    (root / "platform.ini").write_text("[Build]\nMilestone=159.0\nBuildID=20260101000000\n", encoding="utf-8")
    return root / "firefox"


class _Echo:
    text = EXIT + "\n"

    def raise_for_status(self):
        pass


def _a_normal_launch(spawn_to, tmp_path, engine_tree, servers, proxy):
    """The path of the wrapper's launch, as `measure/m_counts.py` measured it."""
    from invisible_core import _fpforge, prefs, seal
    from invisible_core.juggler import instance
    from invisible_core.juggler.keyboard import Keyboard
    from invisible_core.launch import write_user_js  # noqa: F401 - the launch writes through instance.launch

    seal.read_engine_identity(engine_tree)
    seal.active_seal()
    geo = _geo.prepare_session_geo("Asia/Tokyo", proxy, "auto", seed=1561645783, udp_stun_servers=servers)
    fp = _fpforge.generate_profile(seed=1561645783)
    composed = prefs.compose_session_prefs(fp, locale=geo.locale, timezone=geo.timezone, proxy=proxy,
                                           survive_hard_kill=True)
    fake = spawn_to[0] = _Browser()
    browser = instance.launch("firefox", prefs=dict(composed.prefs), profile_dir=str(tmp_path / "profile"),
                              proxy=proxy, headless=True, ready_timeout=10.0, udp_stun_servers=servers,
                              udp_exit=geo.udp_exit)
    try:
        Keyboard(types.SimpleNamespace(), "S", None, layout="00000410")
    except Exception:  # noqa: BLE001 - the keyboard needs a client to type; building it is what matters
        pass
    if proxy:
        sent = []
        fake_browser = types.SimpleNamespace(
            ENGINE_OPTIONS=instance.Browser.ENGINE_OPTIONS, udp_stun_servers=servers,
            context_send=lambda method, params, **kw: sent.append((method, params)))
        instance.Browser.apply_context_options(fake_browser, "ctx-1", {"proxy": proxy})
    browser.close()
    return fake


def test_a_normal_launch_changes_nothing_the_core_keeps(monkeypatch, tmp_path, engine_tree):
    from invisible_core.juggler import connection
    monkeypatch.setattr(_geo, "_http_get", lambda *a, **kw: _Echo())
    # The seams of the spawn are put in place BEFORE the first snapshot: they are the test's, not the core's.
    spawn_to = [None]
    monkeypatch.setattr(connection, "_spawn_windows", lambda *a: spawn_to[0].spawn(*a))
    monkeypatch.setattr(connection, "_spawn_posix", lambda *a: spawn_to[0].spawn(*a))
    stuns = [FakeStun(EXIT), FakeStun(EXIT)]
    servers = ["%s:%d" % s.address for s in stuns]
    try:
        with UdpGateway() as gw:
            _import_every_module()
            before = _snapshot()
            _a_normal_launch(spawn_to, tmp_path / "direct", engine_tree, servers, None)
            _a_normal_launch(spawn_to, tmp_path / "proxied", engine_tree, servers, gw.proxy)
            after = _snapshot()
    finally:
        for s in stuns:
            s.close()

    excused = _excused()
    changed = sorted("%s.%s  (%r -> %r)" % (module, name, before.get((module, name)), after.get((module, name)))
                     for (module, name) in set(before) | set(after)
                     if before.get((module, name)) != after.get((module, name))
                     and (module, name) not in excused)
    assert not changed, (
        "a launch changed what the core keeps in a module (a cache filled, a global rebound): compute it on every call "
        "instead, or name it in EXCEPTIONS with why it is not a memo:\n  " + "\n  ".join(changed))


def test_two_launches_without_a_proxy_ask_for_the_exit_twice(monkeypatch, tmp_path):
    asked = []

    def echo(url, proxies=None, timeout=None, family=None):
        asked.append(url)
        return _Echo()

    monkeypatch.setattr(_geo, "_http_get", echo)
    _geo.prepare_session_geo("Asia/Tokyo", None, "auto", seed=1)
    _geo.prepare_session_geo("Asia/Tokyo", None, "auto", seed=1)
    assert len(asked) == 2, "the second launch did not ask: the exit was kept between two launches: %r" % asked
