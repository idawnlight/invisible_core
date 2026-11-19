"""Software compositing for every persona, declared by the core, the same on every machine.

Owner's decision 2026-11-15. The decision is the one official Firefox 159 takes on a
Windows machine with no GPU, measured on GitHub windows-2022 (adapter Microsoft Hyper-V
Video 0x000b, nsIGfxInfo.getFeatureStatusStr per feature): Direct3D11 compositing and
WebRender are blocklisted with FEATURE_FAILURE_VM_VENDOR, the GPU process stays up (WebGL
needs it). The core declares exactly that for the compositing features of every device and
leaves WebGL, WebGPU, media and every other feature as the device's own entry; on Windows it
also declares gfx.webrender.software true and gfx.webrender.software.d3d11 false, once.
Linux declares no pref: its compositor is already software.
"""
from __future__ import annotations

import dataclasses
import json
import re
import sys
from pathlib import Path

import pytest

from invisible_core import _webgl_personas as W
from invisible_core import prefs as P
from invisible_core._fpforge import generate_profile
from invisible_core.prefs import translate_profile_to_prefs

from test_gfx_device_is_declared import contract_violations

pytestmark = pytest.mark.unit

_VM = "FEATURE_FAILURE_VM_VENDOR"
# stock Firefox 159 on the VM runner, status and failure id per compositing feature
_VM_DECISION = {
    "DIRECT3D_9_LAYERS": "4|" + _VM,
    "DIRECT3D_10_LAYERS": "4|" + _VM,
    "DIRECT3D_10_1_LAYERS": "4|" + _VM,
    "DIRECT3D_11_LAYERS": "4|" + _VM,
    "GPU_PROCESS": "1",
    "WEBRENDER": "4|" + _VM,
    "WEBRENDER_COMPOSITOR": "4|" + _VM,
    "WEBRENDER_SCISSORED_CACHE_CLEARS": "4|" + _VM,
    "WEBRENDER_OPTIMIZED_SHADERS": "4|" + _VM,
    "WEBRENDER_SHADER_CACHE": "4|" + _VM,
    "WEBRENDER_PARTIAL_PRESENT": "4|" + _VM,
    "WEBRENDER_DCOMP": "4|" + _VM,
    "WEBRENDER_ANGLE_METAL": "1",
    "WEBRENDER_ANGLE_GL": "1",
    "D3D11_KEYED_MUTEX": "4|" + _VM,
    "DX_INTEROP2": "4|" + _VM,
    "CANVAS2D_ACCELERATION": "4|" + _VM,
    "ACCELERATED_CANVAS2D": "4|" + _VM,
}
_UNTOUCHED = ("WEBGL", "WEBGL2", "WEBGL_ANGLE", "WEBGL_USE_HARDWARE", "DIRECT3D_11_ANGLE", "WEBGPU",
              "HARDWARE_VIDEO_DECODING", "H264_HW_DECODE", "VP9_HW_DECODE", "HW_DECODED_VIDEO_ZERO_COPY")
_DEVICES = json.loads(W._DEVICES_PATH.read_text(encoding="utf-8"))["by_renderer"]
_POOL = json.loads(W._POOL_PATH.read_text(encoding="utf-8"))["win"]
_ALL = [(r, d) for r, devs in sorted(_DEVICES.items()) for d in devs]
_PREFS = ("gfx.webrender.software", "gfx.webrender.software.d3d11")


def expected_declaration(device_table):
    """A device's measured table with ONLY the compositing features at the VM decision."""
    return ",".join("%s|%s" % (e.split("|", 1)[0], _VM_DECISION[e.split("|", 1)[0]])
                    if e.split("|", 1)[0] in _VM_DECISION else e for e in device_table.split(","))


def _table(text):
    return {e.split("|", 1)[0]: e.split("|", 1)[1] for e in text.split(",")}


def _prefs_for(renderer, device, platform, monkeypatch, seed=12):
    monkeypatch.setattr(sys, "platform", platform)
    prof = generate_profile(seed=seed)
    vendor = next(e["prefs"]["zoom.stealth.webgl.vendor"] for e in _POOL
                  if e["prefs"]["zoom.stealth.webgl.renderer"] == renderer)
    prof = dataclasses.replace(prof, gpu=dataclasses.replace(prof.gpu, renderer=renderer, vendor=vendor,
                                                             device=device["label"]))
    return translate_profile_to_prefs(prof, timezone="America/New_York")


@pytest.mark.parametrize("platform", ["win32", "linux"])
@pytest.mark.parametrize("renderer,device", _ALL, ids=[d["label"] for _, d in _ALL])
def test_compositing_features_carry_the_vm_decision_and_the_rest_the_devices_own(monkeypatch, platform, renderer, device):
    declared = _prefs_for(renderer, device, platform, monkeypatch)["zoom.stealth.gfx.feature_status"]
    got, original = _table(declared), _table(device["feature_status"])
    assert list(got) == list(original)
    for name, value in got.items():
        if name in _VM_DECISION:
            assert value == _VM_DECISION[name], (device["label"], name)
        else:
            assert value == original[name], (device["label"], name)
    assert set(_VM_DECISION) <= set(got)
    assert contract_violations(declared) == [], device["label"]


@pytest.mark.parametrize("renderer,device", _ALL, ids=[d["label"] for _, d in _ALL])
def test_webgl_webgpu_and_media_keep_the_device_s_entry(monkeypatch, renderer, device):
    got = _table(_prefs_for(renderer, device, "win32", monkeypatch)["zoom.stealth.gfx.feature_status"])
    original = _table(device["feature_status"])
    for name in _UNTOUCHED:
        assert got[name] == original[name], name
    for name in ("WEBGL", "WEBGL2", "WEBGL_ANGLE", "DIRECT3D_11_ANGLE", "WEBGPU", "GPU_PROCESS"):
        assert got[name] == "1", name


@pytest.mark.parametrize("seed", range(1, 300, 11))
def test_windows_declares_the_two_prefs_once(monkeypatch, seed):
    monkeypatch.setattr(sys, "platform", "win32")
    for virtual_display in (False, True):
        prefs = translate_profile_to_prefs(generate_profile(seed=seed), timezone="America/New_York",
                                           virtual_display=virtual_display)
        assert prefs["gfx.webrender.software"] is True
        assert prefs["gfx.webrender.software.d3d11"] is False
        assert [k for k in prefs if k in _PREFS] == list(_PREFS)


@pytest.mark.parametrize("seed", [1, 12, 29])
def test_linux_declares_no_compositing_pref(monkeypatch, seed):
    # llvmpipe is sent to software WebRender by gfx.webrender.reject-software-driver (true on GTK)
    monkeypatch.setattr(sys, "platform", "linux")
    prefs = translate_profile_to_prefs(generate_profile(seed=seed), timezone="America/New_York")
    for name in _PREFS:
        assert name not in prefs


def test_each_pref_is_declared_once_in_the_source_and_nowhere_else_in_the_package():
    root = Path(P.__file__).parent
    for name in _PREFS:
        hits = []
        for f in root.rglob("*"):
            if f.suffix in (".py", ".json", ".js", ".txt", ".cfg"):
                text = f.read_text(encoding="utf-8", errors="replace")
                hits += [(f.name, m) for m in re.findall(r'"%s"\s*:' % re.escape(name), text)]
        assert [h[0] for h in hits] == ["prefs.py"], (name, hits)
        assert len(hits) == 1, (name, hits)


def test_the_declaration_carries_its_reason_on_the_line():
    source = Path(P.__file__).read_text(encoding="utf-8")
    for name in _PREFS:
        line = next(l for l in source.splitlines() if re.search(r'"%s"\s*:' % re.escape(name), l))
        assert "STEALTH-HOOK" in line and "2026-11-15" in line, line
