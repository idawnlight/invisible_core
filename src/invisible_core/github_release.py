"""Build and check Python artifacts for a versioned GitHub Release."""
from __future__ import annotations

import argparse
from email.parser import BytesParser
import hashlib
import json
from pathlib import Path
import re
import runpy
import subprocess
import sys
import tarfile
import tomllib
import zipfile


def _name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def project_identity(root: Path) -> tuple[str, str]:
    data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    project = data["project"]
    version = project.get("version")
    if version is None:
        version_config = data.get("tool", {}).get("hatch", {}).get("version", {})
        if version_config.get("source") != "code" or version_config.get("expression", "__version__") != "__version__":
            raise ValueError("dynamic version must declare a Hatch code source with __version__")
        version_path = (root / version_config["path"]).resolve()
        if not version_path.is_relative_to(root):
            raise ValueError("version source must be inside the project")
        version = runpy.run_path(str(version_path))["__version__"]
    return str(project["name"]), str(version)


def _metadata(artifact: Path) -> bytes:
    if artifact.suffix == ".whl":
        with zipfile.ZipFile(artifact) as wheel:
            entries = [name for name in wheel.namelist() if name.endswith(".dist-info/METADATA")]
            if len(entries) != 1:
                raise ValueError(f"{artifact.name} must contain one wheel METADATA")
            return wheel.read(entries[0])
    with tarfile.open(artifact, "r:gz") as sdist:
        entries = [item for item in sdist.getmembers()
                   if len(Path(item.name).parts) == 2 and Path(item.name).name == "PKG-INFO"]
        if len(entries) != 1 or not entries[0].isfile():
            raise ValueError(f"{artifact.name} must contain one top-level PKG-INFO")
        stream = sdist.extractfile(entries[0])
        assert stream is not None
        return stream.read()


def _build(root: Path, outdir: Path) -> None:
    subprocess.run([sys.executable, "-m", "build", "--no-isolation", "--wheel", "--sdist",
                    "--outdir", str(outdir)], cwd=root, check=True)


def _artifact_core_seal(artifact: Path) -> bytes:
    if artifact.suffix == ".whl":
        with zipfile.ZipFile(artifact) as archive:
            return archive.read("invisible_core/seal.json")
    with tarfile.open(artifact, "r:gz") as archive:
        entries = [item for item in archive.getmembers()
                   if len(Path(item.name).parts) == 4 and
                   Path(item.name).parts[1:] == ("src", "invisible_core", "seal.json")]
        if len(entries) != 1 or not entries[0].isfile():
            raise ValueError(f"{artifact.name} must contain one bundled release seal")
        stream = archive.extractfile(entries[0])
        assert stream is not None
        return stream.read()


def _check_core_seals(root: Path, artifacts: list[Path]) -> None:
    from .seal import SealError, SUPPORTED_LEGS, load_seal, seal_digest
    from pathlib import PurePosixPath
    import tempfile

    def seal_data(payload: bytes, origin: str) -> dict:
        try:
            data = json.loads(payload)
        except ValueError as error:
            raise ValueError(f"{origin}: release seal is not valid JSON") from error
        if not isinstance(data, dict):
            raise ValueError(f"{origin}: release seal must be a JSON object")
        return data

    source_path = root / "src/invisible_core/seal.json"
    source_data = seal_data(source_path.read_bytes(), str(source_path))
    expected_digest = seal_digest(source_data)
    payloads = [(str(source_path), source_path.read_bytes())]
    payloads.extend((artifact.name, _artifact_core_seal(artifact)) for artifact in artifacts)
    with tempfile.TemporaryDirectory(prefix="invisible-release-seal-") as temporary:
        for index, (origin, payload) in enumerate(payloads):
            data = seal_data(payload, origin)
            if seal_digest(data) != expected_digest:
                raise ValueError(f"{origin} release seal does not match the source bundled seal")
            if (any(not isinstance(data.get(field), str) for field in
                    ("tag", "upstream_version", "source_commit")) or
                    not isinstance(data.get("playwright"), dict) or
                    not isinstance(data.get("assets"), dict) or
                    any(not isinstance(asset, dict) for asset in data["assets"].values())):
                raise ValueError(f"{origin}: release seal has missing or invalid fields")
            path = Path(temporary) / f"seal-{index}.json"
            path.write_bytes(payload)
            try:
                seal = load_seal(path)
            except (SealError, KeyError, TypeError, ValueError) as error:
                raise ValueError(f"{origin}: invalid release seal: {error}") from error
            tag = re.fullmatch(r"firefox-(\d+\.\d+(?:\.\d+)?)-r[1-9]\d*", seal.tag)
            if not tag or tag.group(1) != seal.upstream_version:
                raise ValueError(f"{origin}: release seal tag must match its upstream version")
            if not re.fullmatch(r"[0-9a-fA-F]{40}", seal.source_commit):
                raise ValueError(f"{origin}: release seal needs its full source commit")
            ranges = [tuple(int(part) for part in version.split("."))
                      for version in (seal.playwright_min, seal.playwright_max)
                      if isinstance(version, str) and re.fullmatch(r"\d+\.\d+\.\d+", version)]
            if len(ranges) != 2 or ranges[0] > ranges[1]:
                raise ValueError(f"{origin}: release seal needs a valid Playwright range")
            if not seal.assets or "build_id" in data:
                raise ValueError(f"{origin}: release seal needs downloadable assets with per-asset BuildIDs")
            legs = set()
            for asset in seal.assets.values():
                if any(not isinstance(value, str) for value in
                       (asset.platform, asset.arch, asset.entry_rel, asset.sha256,
                        asset.build_id, asset.omni_sha256)):
                    raise ValueError(f"{origin}: release seal asset {asset.name!r} has invalid field types")
                leg = (asset.platform, asset.arch)
                entry = PurePosixPath(asset.entry_rel)
                if (leg not in SUPPORTED_LEGS or leg in legs or
                        not re.fullmatch(r"[0-9a-fA-F]{64}", asset.sha256) or
                        not re.fullmatch(r"\d{14}", asset.build_id) or
                        type(data["assets"][asset.name].get("size")) is not int or asset.size <= 0 or
                        not asset.entry_rel or entry.is_absolute() or ".." in entry.parts or
                        (asset.omni_sha256 and not re.fullmatch(r"[0-9a-fA-F]{64}", asset.omni_sha256))):
                    raise ValueError(f"{origin}: release seal asset {asset.name!r} has invalid platform, arch or identity")
                legs.add(leg)


def build_release(root: Path, tag: str, outdir: Path, *, builder=_build) -> list[Path]:
    root = Path(root).resolve()
    outdir = Path(outdir)
    if not outdir.is_absolute():
        outdir = root / outdir
    name, version = project_identity(root)
    if tag != f"v{version}":
        raise ValueError(f"tag {tag!r} does not match {name} version {version!r}; expected v{version}")
    if outdir.exists() and (not outdir.is_dir() or any(outdir.iterdir())):
        raise ValueError(f"release output directory must be empty: {outdir}")
    outdir.mkdir(parents=True, exist_ok=True)
    builder(root, outdir)
    artifacts = sorted(outdir.iterdir())
    wheels = [path for path in artifacts if path.name.endswith(".whl")]
    sdists = [path for path in artifacts if path.name.endswith(".tar.gz")]
    if len(artifacts) != 2 or len(wheels) != 1 or len(sdists) != 1:
        raise ValueError("a release build must produce exactly one wheel and one sdist")
    for artifact in artifacts:
        metadata = BytesParser().parsebytes(_metadata(artifact))
        if _name(metadata.get("Name", "")) != _name(name) or metadata.get("Version") != version:
            raise ValueError(f"{artifact.name} metadata does not match {name} {version}: "
                             f"Name={metadata.get('Name')!r}, Version={metadata.get('Version')!r}")
    if _name(name) == "invisible-core":
        _check_core_seals(root, artifacts)
    checksums = "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
                        for path in artifacts)
    (outdir / "SHA256SUMS").write_text(checksums, encoding="ascii")
    print(f"GitHub Release {tag}: {name} {version}; wheel, sdist and SHA256SUMS verified")
    return artifacts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--tag", required=True)
    parser.add_argument("--outdir", type=Path, default=Path("dist"))
    arguments = parser.parse_args(argv)
    try:
        build_release(arguments.project_root, arguments.tag, arguments.outdir)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError,
            zipfile.BadZipFile, tarfile.TarError) as error:
        print(f"GitHub release check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
