"""A Windows ARM64 host gets the x86_64 engine, by declaration.

The runtime half, that the engine really starts under emulation, is the
`arm64-host` job of ci.yml on a `windows-11-arm` runner. This half pins what
the declaration does and does not do, on every runner.
"""
from __future__ import annotations

import pytest
from dataclasses import replace

from invisible_core.seal import Asset, EMULATED_LEGS, active_seal


@pytest.fixture
def seal_with_supported_legs():
    assets = {}
    for platform, arch in (("win32", "x86_64"), ("linux", "x86_64"), ("linux", "arm64")):
        name = f"{platform}-{arch}.zip"
        assets[name] = Asset(name, platform, arch, "0" * 64, 1, "firefox", "", "20261029033851")
    return replace(active_seal(), assets=assets)


def test_a_windows_arm64_host_gets_the_x86_64_asset(seal_with_supported_legs):
    """Refused with NotImplementedError until 2026-09-25, with no remedy."""
    seal = seal_with_supported_legs
    asset = seal.asset_for("win32", "ARM64")
    assert (asset.platform, asset.arch) == ("win32", "x86_64"), asset


def test_a_native_asset_wins_over_the_emulated_one(seal_with_supported_legs):
    """Linux ARM64 has its own asset and must keep getting it: the declaration
    is for hosts WITHOUT one, not a preference for x86_64."""
    seal = seal_with_supported_legs
    asset = seal.asset_for("linux", "aarch64")
    assert (asset.platform, asset.arch) == ("linux", "arm64"), asset


def test_the_declaration_does_not_invent_a_leg_nobody_measured():
    assert EMULATED_LEGS == {("win32", "arm64"): "x86_64"}
    with pytest.raises(NotImplementedError):
        active_seal().asset_for("darwin", "arm64")
