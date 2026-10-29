"""Install the declared core Git tag without importing the checkout into pytest.

Run from the user-install workflow's stdlib/pytest/packaging-only environment,
with conftests, source pythonpath and the world plugin disabled.
"""
from __future__ import annotations

import ast
import importlib.metadata
import json
import os
import platform
import re
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.e2e
REPOSITORY = "https://github.com/idawnlight/invisible_core.git"
ROOT = Path(__file__).resolve().parents[1]
_LEAKS = ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV",
          "INVISIBLE_PLAYWRIGHT_ENGINE_DIR", "INVISIBLE_FIREFOX_RELEASE_REPOSITORY",
          "INVISIBLE_PLAYWRIGHT_CACHE_DIR",
          "INVISIBLE_DOWNLOAD_DEADLINE", "STEALTHFOX_GITHUB_TOKEN", "GITHUB_TOKEN",
          "INVISIBLE_SEAL_FILE", "INVISIBLE_CORE_PIN", "INVISIBLE_CORE_AUTOFIX",
          "INVISIBLE_CORE_AUTOFIX_TIMEOUT", "UV", "STEALTHFOX_GEOIP_MMDB",
          "STEALTHFOX_FONT_MANIFEST", "STEALTHFOX_WEBRTC_PUBLIC_IP",
          "INVPW_CURSOR_TIMER", "INVISIBLE_CORE_AUTOFIX_ATTEMPTED",
          "INVPW_SESSION_TOKEN", "INVPW_DESKTOP", "STEALTHFOX_WEBRTC_DISABLE_IPV6")


def _version() -> str:
    tree = ast.parse((ROOT / "src/invisible_core/_version.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == "__version__"
                for target in node.targets):
            value = ast.literal_eval(node.value)
            assert re.fullmatch(r"\d+\.\d+\.\d+", value), value
            return value
    raise AssertionError("the core has no explicit package version")


def _run(command, *, cache: Path | None = None, timeout=600):
    env = dict(os.environ)
    for key in _LEAKS:
        env.pop(key, None)
    env.update(PYTHONNOUSERSITE="1", PIP_NO_CACHE_DIR="1", PIP_DISABLE_PIP_VERSION_CHECK="1")
    if cache is not None:
        env["INVISIBLE_PLAYWRIGHT_CACHE_DIR"] = str(cache)
    result = subprocess.run([str(value) for value in command], env=env,
                            capture_output=True, text=True, timeout=timeout)
    assert result.returncode == 0, (
        f"{command!r} exited {result.returncode}\n{result.stdout[-3000:]}\n"
        f"{result.stderr[-3000:]}")
    return result


def _json(python: Path, script: str, *, cache: Path | None = None, timeout=60):
    result = _run([python, "-I", "-c", script], cache=cache, timeout=timeout)
    return json.loads(result.stdout.strip().splitlines()[-1])


@pytest.fixture(scope="module")
def installed(tmp_path_factory, record_testsuite_property):
    if sys.platform != "linux" or platform.machine().lower() not in ("x86_64", "amd64"):
        pytest.skip("this release provides a Linux x86_64 engine")
    assert not any(name == "invisible_core" or name.startswith("invisible_core.")
                   for name in sys.modules), "pytest imported the source checkout"
    for name in ("invisible-core", "invisible-playwright"):
        with pytest.raises(importlib.metadata.PackageNotFoundError):
            importlib.metadata.distribution(name)
    version = _version()
    tag = "v" + version
    refs = _run(["git", "ls-remote", REPOSITORY,
                 f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}"], timeout=90)
    remote = dict(line.split()[::-1] for line in refs.stdout.splitlines())
    commit = remote.get(f"refs/tags/{tag}^{{}}") or remote.get(f"refs/tags/{tag}")
    assert commit, f"{REPOSITORY} has no Git tag {tag}"
    directory = tmp_path_factory.mktemp("github-core-install")
    venv = directory / ".venv"
    _run([sys.executable, "-m", "venv", venv])
    python = venv / "bin/python"
    _run([python, "-m", "pip", "install", "--no-cache-dir",
          f"invisible-core @ git+{REPOSITORY}@{tag}"], timeout=1800)
    metadata = _json(python, """
import importlib.metadata, invisible_core, json
from pathlib import Path
module = Path(invisible_core.__file__)
dist = importlib.metadata.distribution("invisible-core")
print(json.dumps({"path": str(module), "version": dist.version,
    "code_version": invisible_core.__version__,
    "direct_url": json.loads(dist.read_text("direct_url.json")),
    "seal": json.loads(module.with_name("seal.json").read_text())}))
""")
    _run([python, "-m", "pip", "check"])
    record_testsuite_property("core_git_tag", tag)
    record_testsuite_property("core_git_commit", commit)
    return {"directory": directory, "venv": venv, "python": python,
            "version": version, "tag": tag, "commit": commit, "metadata": metadata}


def test_git_tag_installs_a_noneditable_package(installed):
    metadata = installed["metadata"]
    assert metadata["version"] == metadata["code_version"] == installed["version"]
    assert Path(metadata["path"]).is_relative_to(installed["venv"] / "lib")
    assert "site-packages" in Path(metadata["path"]).parts
    direct = metadata["direct_url"]
    assert direct["url"] == REPOSITORY
    assert direct["vcs_info"]["requested_revision"] == installed["tag"]
    assert direct["vcs_info"]["commit_id"] == installed["commit"]
    assert not direct.get("dir_info", {}).get("editable", False)


@pytest.fixture(scope="module")
def engine(installed, record_testsuite_property):
    cache = installed["directory"] / "engine-cache"
    assert not cache.exists(), "the download cache was already populated"
    result = _json(installed["python"], """
import configparser, hashlib, json, requests
from pathlib import Path
from invisible_core import ensure_binary
from invisible_core.seal import active_seal
urls = []
original = requests.sessions.Session.request
def observe(self, method, url, *args, **kwargs):
    urls.append(url)
    return original(self, method, url, *args, **kwargs)
requests.sessions.Session.request = observe
entry = ensure_binary()
seal = active_seal()
asset = seal.asset_for("linux", "x86_64")
root = entry.parent
identity = {}
for filename, section in [("application.ini", "App"), ("platform.ini", "Build")]:
    ini = configparser.ConfigParser(interpolation=None)
    ini.read(root / filename)
    identity[filename] = dict(ini[section])
print(json.dumps({"path": str(entry), "tag": seal.tag,
    "source_commit": seal.source_commit, "build_id": asset.build_id,
    "version": seal.upstream_version, "identity": identity,
    "omni_sha256": hashlib.sha256((root / "omni.ja").read_bytes()).hexdigest(),
    "expected_omni_sha256": asset.omni_sha256, "requested_urls": urls}))
""", cache=cache, timeout=1800)
    path = Path(result["path"])
    assert path.is_file() and path.is_relative_to(cache), path
    seal = installed["metadata"]["seal"]
    assert result["tag"] == seal["tag"] and result["source_commit"] == seal["source_commit"]
    expected_prefix = ("https://github.com/idawnlight/firefox_antidetect_patch/"
                       f"releases/download/{seal['tag']}/")
    assert any(url.startswith(expected_prefix) for url in result["requested_urls"]), result
    for filename, identity in result["identity"].items():
        assert identity["sourcestamp"] == seal["source_commit"], (filename, identity)
        assert identity["buildid"] == result["build_id"], (filename, identity)
        assert identity["sourcerepository"] == "https://github.com/idawnlight/firefox_antidetect_patch"
    assert result["omni_sha256"] == result["expected_omni_sha256"]
    record_testsuite_property("engine_release", result["tag"])
    record_testsuite_property("engine_source_commit", result["source_commit"])
    record_testsuite_property("engine_build_id", result["build_id"])
    return {"cache": cache, "result": result}


def test_default_release_downloads_into_an_empty_cache(engine):
    assert engine["result"]["requested_urls"]


def test_second_lookup_reuses_the_cache_without_network(installed, engine):
    result = _json(installed["python"], """
import json, requests, socket
from invisible_core import ensure_binary
attempts = []
def blocked(*args, **kwargs):
    attempts.append(str(args[:2]))
    raise AssertionError("cached ensure_binary attempted a network operation")
requests.sessions.Session.request = blocked
socket.create_connection = blocked
socket.getaddrinfo = blocked
socket.socket.connect = blocked
socket.socket.connect_ex = blocked
entry = ensure_binary()
print(json.dumps({"path": str(entry), "network_attempts": attempts}))
""", cache=engine["cache"], timeout=60)
    assert result["path"] == engine["result"]["path"]
    assert result["network_attempts"] == []


def test_downloaded_firefox_reports_the_sealed_version(installed, engine):
    result = _run([engine["result"]["path"], "--version"], cache=engine["cache"], timeout=30)
    assert f"Firefox {engine['result']['version']}" in result.stdout + result.stderr
