import hashlib
import io
import json
from pathlib import Path
import tarfile
import zipfile

import pytest

from invisible_core.github_release import build_release, project_identity

pytestmark = pytest.mark.unit


def project(tmp_path, *, dynamic=False):
    root = tmp_path / "project"
    root.mkdir()
    body = '[project]\nname="example_pkg"\n'
    if dynamic:
        (root / "version.py").write_text('__version__="1.2.3"\n')
        body += ('dynamic=["version"]\n[tool.hatch.version]\n'
                 'source="code"\npath="version.py"\nexpression="__version__"\n')
    else:
        body += 'version="1.2.3"\n'
    (root / "pyproject.toml").write_text(body)
    return root


def artifacts(root, outdir, *, wheel_name="example-pkg", wheel_version="1.2.3",
              sdist_name="example-pkg", sdist_version="1.2.3", seal=None, sdist_seal=None):
    def metadata(name, version):
        return f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n".encode()

    wheel_prefix = wheel_name.replace("-", "_") + "-" + wheel_version
    with zipfile.ZipFile(outdir / f"{wheel_prefix}-py3-none-any.whl", "w") as wheel:
        wheel.writestr(f"{wheel_prefix}.dist-info/METADATA", metadata(wheel_name, wheel_version))
        if seal is not None:
            wheel.writestr("invisible_core/seal.json", json.dumps(seal))
    blob = metadata(sdist_name, sdist_version)
    sdist_prefix = sdist_name.replace("-", "_") + "-" + sdist_version
    with tarfile.open(outdir / f"{sdist_prefix}.tar.gz", "w:gz") as sdist:
        entry = tarfile.TarInfo(f"{sdist_prefix}/PKG-INFO")
        entry.size = len(blob)
        sdist.addfile(entry, io.BytesIO(blob))
        if seal is not None:
            seal_blob = json.dumps(sdist_seal if sdist_seal is not None else seal).encode()
            entry = tarfile.TarInfo(f"{sdist_prefix}/src/invisible_core/seal.json")
            entry.size = len(seal_blob)
            sdist.addfile(entry, io.BytesIO(seal_blob))


@pytest.mark.parametrize("dynamic", [False, True])
def test_release_build_checks_both_artifacts_and_writes_checksums(tmp_path, dynamic):
    root = project(tmp_path, dynamic=dynamic)
    assert project_identity(root) == ("example_pkg", "1.2.3")
    files = build_release(root, "v1.2.3", Path("dist"), builder=artifacts)
    assert {path.suffix for path in files} == {".whl", ".gz"}
    expected = "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in files)
    assert (root / "dist/SHA256SUMS").read_text() == expected


def test_tag_mismatch_stops_before_building(tmp_path):
    root = project(tmp_path)
    with pytest.raises(ValueError, match="does not match"):
        build_release(root, "v1.2.2", root / "dist", builder=lambda *args: pytest.fail("build ran"))
    assert not (root / "dist").exists()


def test_a_previous_or_mixed_output_directory_is_not_reused(tmp_path):
    root = project(tmp_path)
    outdir = root / "dist"
    outdir.mkdir()
    (outdir / "old.whl").write_bytes(b"old")
    with pytest.raises(ValueError, match="must be empty"):
        build_release(root, "v1.2.3", outdir, builder=lambda *args: pytest.fail("build ran"))
    assert (outdir / "old.whl").read_bytes() == b"old"


@pytest.mark.parametrize("field,value", [
    ("wheel_name", "other-package"), ("sdist_name", "other-package"),
    ("wheel_version", "1.2.2"), ("sdist_version", "1.2.2"),
])
def test_artifact_metadata_must_match_the_project_and_tag(tmp_path, field, value):
    root = project(tmp_path)
    with pytest.raises(ValueError, match="metadata does not match"):
        build_release(root, "v1.2.3", root / "dist",
                      builder=lambda *args: artifacts(*args, **{field: value}))
    assert not (root / "dist/SHA256SUMS").exists()


def test_an_extra_build_artifact_is_rejected(tmp_path):
    root = project(tmp_path)

    def mixed(root, outdir):
        artifacts(root, outdir)
        (outdir / "unexpected.whl").write_bytes(b"extra")

    with pytest.raises(ValueError, match="exactly one wheel and one sdist"):
        build_release(root, "v1.2.3", root / "dist", builder=mixed)


def release_seal():
    return {
        "schema": 2, "tag": "firefox-159.0-r1", "upstream_version": "159.0",
        "source_commit": "a" * 40, "playwright": {"min": "1.55.0", "max": "1.61.0"},
        "assets": {"engine.tar.gz": {
            "platform": "linux", "arch": "x86_64", "sha256": "b" * 64,
            "build_id": "20261029033851", "size": 1234,
            "entry_rel": "firefox", "omni_sha256": "",
        }},
    }


def core_project(tmp_path, seal):
    root = project(tmp_path)
    pyproject = root / "pyproject.toml"
    pyproject.write_text(pyproject.read_text().replace("example_pkg", "invisible_core"))
    path = root / "src/invisible_core/seal.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(seal))
    return root


@pytest.mark.parametrize("problem", [None, "local", "source_commit", "tag", "upstream_version",
    "playwright", "sha256", "build_id", "platform", "arch", "entry_rel", "size"])
def test_a_core_release_bundles_a_complete_downloadable_seal(tmp_path, problem):
    seal = release_seal()
    if problem == "local":
        seal["assets"] = {}
    elif problem in {"source_commit", "tag", "upstream_version", "playwright"}:
        seal.pop(problem)
    elif problem:
        seal["assets"]["engine.tar.gz"].pop(problem)
    root = core_project(tmp_path, seal)
    builder = lambda *args: artifacts(*args, wheel_name="invisible-core", sdist_name="invisible-core", seal=seal)
    if problem is None:
        build_release(root, "v1.2.3", root / "dist", builder=builder)
        assert (root / "dist/SHA256SUMS").exists()
    else:
        with pytest.raises(ValueError, match="release seal"):
            build_release(root, "v1.2.3", root / "dist", builder=builder)
        assert not (root / "dist/SHA256SUMS").exists()


@pytest.mark.parametrize("field,value", [
    ("tag", "firefox-159"), ("upstream_version", "160.0"),
    ("source_commit", "short"), ("playwright", {"min": "1.61.0", "max": "1.55.0"}),
])
def test_a_release_seal_declares_a_consistent_engine_identity(tmp_path, field, value):
    seal = release_seal()
    seal[field] = value
    root = core_project(tmp_path, seal)
    with pytest.raises(ValueError, match="release seal"):
        build_release(root, "v1.2.3", root / "dist", builder=lambda *args: artifacts(
            *args, wheel_name="invisible-core", sdist_name="invisible-core", seal=seal))


@pytest.mark.parametrize("artifact", ["wheel", "sdist"])
def test_each_artifacts_seal_must_match_the_actual_source(tmp_path, artifact):
    seal = release_seal()
    root = core_project(tmp_path, seal)
    changed = json.loads(json.dumps(seal))
    changed["assets"]["engine.tar.gz"]["build_id"] = "20261029033852"
    with pytest.raises(ValueError, match="does not match the source"):
        build_release(root, "v1.2.3", root / "dist", builder=lambda *args: artifacts(
            *args, wheel_name="invisible-core", sdist_name="invisible-core",
            seal=changed if artifact == "wheel" else seal,
            sdist_seal=changed if artifact == "sdist" else seal))
    assert not (root / "dist/SHA256SUMS").exists()


@pytest.mark.parametrize("problem", ["missing", "invalid-json"])
def test_a_damaged_sdist_seal_is_rejected_even_with_valid_package_metadata(tmp_path, problem):
    seal = release_seal()
    root = core_project(tmp_path, seal)

    def damaged_sdist(root, outdir):
        artifacts(root, outdir, wheel_name="invisible-core", sdist_name="invisible-core", seal=seal)
        path = next(outdir.glob("*.tar.gz"))
        with tarfile.open(path, "r:gz") as archive:
            contents = [(member.name, archive.extractfile(member).read()) for member in archive.getmembers()]
        with tarfile.open(path, "w:gz") as archive:
            for name, blob in contents:
                if name.endswith("/seal.json"):
                    if problem == "missing":
                        continue
                    blob = b"{"
                member = tarfile.TarInfo(name)
                member.size = len(blob)
                archive.addfile(member, io.BytesIO(blob))

    with pytest.raises(ValueError, match="release seal"):
        build_release(root, "v1.2.3", root / "dist", builder=damaged_sdist)
    assert not (root / "dist/SHA256SUMS").exists()
