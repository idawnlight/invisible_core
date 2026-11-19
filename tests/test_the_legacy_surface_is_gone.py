"""What 66.76.0 removed from the core stays removed.

Nothing here is switched off: the aliases, the deprecated parameter, the shortcut scripts, the macOS
leftovers and the dead code are gone from the source. A name that comes back, in a module, a signature, a
workflow or a message, fails this file; so does a change of the names the engine driver and an outside
user import.
"""
from __future__ import annotations

import importlib
import importlib.util
import inspect
import pathlib

import pytest

pytestmark = pytest.mark.unit

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src" / "invisible_core"

#: (module, name) pairs that no longer exist.
#: Note: the fork retains `resolve_session_timezone` in `invisible_core._geo`
#: and `invisible_core` for backward compatibility with `invisible_chromium`.
_GONE_NAMES = (
    ("invisible_core", "tz_env"),
    ("invisible_core.launch", "tz_env"),
    ("invisible_core.launch", "write_font_manifest"),
    ("invisible_core.constants", "BROKEN_VERSIONS"),
    ("invisible_core.constants", "BINARY_ENTRY_REL"),
    ("invisible_core.download", "cache_dir_for_version"),
    ("invisible_core.download", "ensure_geoip_mmdb"),
    ("invisible_core.download", "geoip_mmdb_path"),
    ("invisible_core.download", "_parse_checksums"),
    ("invisible_core._geo", "_SOCKS_SCHEMES"),
    ("invisible_core.release", "SCRIPT_DIR"),
    ("invisible_core.environment", "LOCALE_SET_BY_THE_CORE"),
    ("invisible_core.juggler._behaviour", "_fitts_ms"),
    ("invisible_core.juggler.keyboard", "_klid_of_tag"),
    ("invisible_core.juggler.keylayout", "BY_SHIFTED_KEY"),
    ("invisible_core.juggler._pacing", "_motion_mod"),
)

#: Words no file of the package may spell again.
_GONE_WORDS = (
    "tz_env", "BROKEN_VERSIONS", "BINARY_ENTRY_REL", "cache_dir_for_version", "write_font_manifest",
    "_fitts_ms", "_klid_of_tag", "BY_SHIFTED_KEY", "_SOCKS_SCHEMES", "LOCALE_SET_BY_THE_CORE",
    "_parse_checksums", "_motion_mod",
    "Contents/MacOS", "darwin", "invisible_core._pin", "invisible_core/_pin", "._pin import",
    "install_hooks", "version_gate",
)

#: The names the engine driver and an outside user import. They must stay.
_KEPT = ("SessionGeo", "SessionLocale", "build_launch_plan", "compose_session_prefs", "generate_profile",
         "prepare_session_geo", "resolve_session_timezone", "resolve_session_seed", "_udp_exit")


@pytest.mark.parametrize("module,name", _GONE_NAMES, ids=[f"{m}.{n}" for m, n in _GONE_NAMES])
def test_the_name_is_gone(module, name):
    assert not hasattr(importlib.import_module(module), name), f"{module}.{name} is back"


def test_the_package_does_not_export_what_went():
    import invisible_core

    assert "tz_env" not in invisible_core.__all__
    assert "resolve_session_timezone" in invisible_core.__all__
    assert "ensure_geoip_mmdb" in invisible_core.__all__  # the public one stays, from its own module
    assert invisible_core.ensure_geoip_mmdb.__module__ == "invisible_core._geoip_db"


def test_the_alias_module_is_gone():
    assert importlib.util.find_spec("invisible_core._pin") is None
    assert not (_SRC / "_pin.py").exists()
    from invisible_core import pin  # the module it stood for

    assert hasattr(pin, "pin_report")


def test_the_shortcut_scripts_are_gone():
    for name in ("install_hooks.py", "version_gate.py"):
        assert not (_ROOT / "scripts" / name).exists(), name


def test_the_installer_of_the_hooks_is_a_module_command():
    from invisible_core import hooks

    assert hooks.INSTALL_COMMAND == "python -m invisible_core.hooks install"


def test_build_launch_env_takes_no_timezone():
    from invisible_core.launch import build_launch_env, build_launch_plan

    assert "timezone" not in inspect.signature(build_launch_env).parameters
    with pytest.raises(TypeError):
        build_launch_env({}, timezone="Europe/Rome", base_env={})
    assert "timezone" in inspect.signature(build_launch_plan).parameters  # another thing, and it stays


def test_the_pin_report_has_no_ok_key():
    from invisible_core import pin

    assert "ok" not in pin.pin_report("this-distribution-does-not-exist")


def test_there_is_one_cache_layout():
    from invisible_core import download

    assert download._tree_belongs_to_tag("firefox-18_151.0_2026", "firefox-18")
    assert not download._tree_belongs_to_tag("firefox-18", "firefox-18")  # the flat name is no layout of ours
    assert not download._tree_belongs_to_tag("firefox-180_151.0_2026", "firefox-18")


def test_no_macos_entry_remains(tmp_path):
    from invisible_core import seal

    assert set(seal.DEFAULT_ENTRY_REL) == {"win32", "linux"}
    # An app-bundle shaped tree is no special layout: the resources are beside the executable.
    entry = tmp_path / "Firefox.app" / "Contents" / "MacOS" / "firefox"
    (tmp_path / "Firefox.app" / "Contents" / "Resources").mkdir(parents=True)
    assert seal.resource_root(entry) == entry.parent
    assert seal._platform_key_for_entry(entry) != "darwin"


def test_the_motion_floor_is_the_path_generators():
    from invisible_core.juggler import _motion, _pacing

    assert _pacing.MIN_EVENT_INTERVAL_MS == float(_motion.SAMPLE_FLOOR_MS)


def test_no_file_spells_what_went():
    files = sorted(_SRC.rglob("*.py")) + sorted((_ROOT / ".github" / "workflows").glob("*.yml"))
    hook = _ROOT / ".githooks" / "pre-push"
    if hook.exists():
        files.append(hook)
    found = [(p.relative_to(_ROOT).as_posix(), word)
             for p in files
             for word in _GONE_WORDS if word in p.read_text(encoding="utf-8")]
    assert not found, found


@pytest.mark.parametrize("name", _KEPT)
def test_what_the_driver_and_the_outside_user_import_still_imports(name):
    import invisible_core

    assert hasattr(invisible_core, name), name
