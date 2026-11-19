"""A Windows ARM64 host gets the x86_64 engine, by declaration.

The runtime half, that the engine really starts under emulation, is the
`arm64-host` job of ci.yml on a `windows-11-arm` runner. This half pins what
the declaration does and does not do, on every runner.
"""
from __future__ import annotations

from dataclasses import replace

import pytest

from invisible_core import environment
from invisible_core.seal import (
    EMULATED_LEGS,
    RETIRED_LEGS,
    SUPPORTED_LEGS,
    Asset,
    active_seal,
)


def _seal_with(*legs, tag="firefox-56"):
    """A seal with exactly these (platform, arch) assets, the rest of it the packaged one's."""
    assets = {
        f"firefox-x-{p}-{a}": Asset(name=f"firefox-x-{p}-{a}", platform=p, arch=a, sha256="0" * 64,
                                    size=1, entry_rel="firefox", omni_sha256="", build_id="20261029033851")
        for p, a in legs}
    return replace(active_seal(), tag=tag, assets=assets)


def test_a_windows_arm64_host_gets_the_x86_64_asset():
    """Refused with NotImplementedError until 2026-09-25, with no remedy."""
    seal = _seal_with(("win32", "x86_64"), ("linux", "x86_64"), ("linux", "arm64"))
    asset = seal.asset_for("win32", "ARM64")
    assert (asset.platform, asset.arch) == ("win32", "x86_64"), asset


def test_a_native_asset_wins_over_the_emulated_one():
    """The declaration is for hosts WITHOUT an asset, not a preference for x86_64:
    a native one, if a seal carries it, wins."""
    seal = _seal_with(("win32", "x86_64"), ("win32", "arm64"))
    asset = seal.asset_for("win32", "ARM64")
    assert (asset.platform, asset.arch) == ("win32", "arm64"), asset


def test_an_old_seal_with_a_linux_arm64_asset_still_gives_it():
    """linux-arm64 left on 2026-11-04 (firefox-56): the seals up to firefox-55 carry
    it, and a host that runs one of them keeps getting it."""
    seal = _seal_with(("linux", "x86_64"), ("linux", "arm64"), ("win32", "x86_64"))
    asset = seal.asset_for("linux", "aarch64")
    assert (asset.platform, asset.arch) == ("linux", "arm64"), asset


def test_fork_seal_never_points_linux_arm64_to_pypi_invisible_core_56():
    """When oss-invisible is not used, remedies must never point users to PyPI
    invisible-core<56 or firefox-55."""
    assert SUPPORTED_LEGS == (("linux", "x86_64"), ("win32", "x86_64"))
    assert RETIRED_LEGS == {("linux", "arm64"): "firefox-55"}
    for seal in (active_seal(), _seal_with(("linux", "x86_64"), ("win32", "x86_64"))):
        with pytest.raises(NotImplementedError) as info:
            seal.asset_for("linux", "aarch64")
        said = str(info.value)
        assert "invisible-core<56" not in said, said
        assert "firefox-55" not in said, said


def test_a_linux_arm64_host_on_an_upstream_seal_is_told_where_to_stay(monkeypatch):
    """When configured for oss-invisible, a numbered seal names the last
    upstream release with linux-arm64."""
    monkeypatch.setenv(
        environment.ENGINE_REPOSITORY, "oss-invisible/firefox_antidetect_patch"
    )
    seal = _seal_with(("linux", "x86_64"), ("win32", "x86_64"))
    with pytest.raises(NotImplementedError) as info:
        seal.asset_for("linux", "aarch64")
    said = str(info.value)
    assert "firefox-55" in said and "invisible-core<56" in said, said


def test_the_declaration_does_not_invent_a_leg_nobody_measured():
    assert EMULATED_LEGS == {("win32", "arm64"): "x86_64"}
    with pytest.raises(NotImplementedError):
        active_seal().asset_for("darwin", "arm64")
