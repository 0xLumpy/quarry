from __future__ import annotations

import importlib.metadata
import importlib.resources
import json
import os
import pathlib
import tarfile
import zipfile

import pytest


pytestmark = pytest.mark.packaging

ROOT = pathlib.Path(__file__).resolve().parents[1]
MAX_ARCHIVE_FILES = 2_000
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024


def _artifacts() -> tuple[pathlib.Path, pathlib.Path]:
    raw = os.environ.get("QUARRY_PACKAGE_ARTIFACT_DIR", "")
    assert raw, "QUARRY_PACKAGE_ARTIFACT_DIR must name the candidate build directory"
    root = pathlib.Path(raw).resolve(strict=True)
    assert root.is_dir()
    wheels = sorted(root.glob("quarry_recon-*.whl"))
    sdists = sorted(root.glob("quarry_recon-*.tar.gz"))
    assert len(wheels) == 1
    assert len(sdists) == 1
    return wheels[0], sdists[0]


def _safe_member(name: str) -> pathlib.PurePosixPath:
    assert name and "\\" not in name and "\x00" not in name
    path = pathlib.PurePosixPath(name)
    assert not path.is_absolute()
    assert ".." not in path.parts
    assert path.as_posix() == name.rstrip("/")
    return path


def test_candidate_archives_are_bounded_and_path_safe():
    wheel, sdist = _artifacts()
    assert 0 < wheel.stat().st_size <= MAX_ARCHIVE_BYTES
    assert 0 < sdist.stat().st_size <= MAX_ARCHIVE_BYTES

    with zipfile.ZipFile(wheel) as archive:
        members = archive.infolist()
        assert 0 < len(members) <= MAX_ARCHIVE_FILES
        assert sum(member.file_size for member in members) <= MAX_ARCHIVE_BYTES
        paths = [_safe_member(member.filename) for member in members]
        assert not any("__pycache__" in path.parts or path.suffix == ".pyc" for path in paths)
        assert not any("tests" in path.parts for path in paths)

    with tarfile.open(sdist, mode="r:gz") as archive:
        members = archive.getmembers()
        assert 0 < len(members) <= MAX_ARCHIVE_FILES
        assert sum(member.size for member in members) <= MAX_ARCHIVE_BYTES
        paths = [_safe_member(member.name) for member in members]
        assert all(member.isfile() or member.isdir() for member in members)
        relative = {pathlib.PurePosixPath(*path.parts[1:]).as_posix() for path in paths}
        assert {"LICENSE", "README.md", "pyproject.toml"} <= relative
        assert "src/quarry_recon/data/target.template.yaml" in relative
        assert "src/quarry_recon/data/tools.yaml" in relative


def test_wheel_carries_spdx_license_and_runtime_data():
    wheel, _sdist = _artifacts()
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        metadata_name = next(name for name in names if name.endswith(".dist-info/METADATA"))
        metadata = archive.read(metadata_name).decode("utf-8", "strict")
        assert "License-Expression: MIT\n" in metadata
        assert "Requires-Python: >=3.10\n" in metadata
        assert any(name.endswith(".dist-info/licenses/LICENSE") for name in names)
        assert "quarry_recon/data/target.template.yaml" in names
        assert "quarry_recon/data/tools.yaml" in names


def test_installed_candidate_comes_from_the_wheel_and_exposes_the_cli():
    distribution = importlib.metadata.distribution("quarry-recon")
    assert distribution.version == "0.3.9"
    console_scripts = {
        entry.name: entry.value
        for entry in distribution.entry_points
        if entry.group == "console_scripts"
    }
    assert console_scripts["quarry"] == "quarry_recon.cli:cli"
    package = importlib.resources.files("quarry_recon")
    assert package.joinpath("data/target.template.yaml").is_file()
    assert package.joinpath("data/tools.yaml").is_file()
    if os.environ.get("QUARRY_EXPECT_WHEEL_INSTALL") == "1":
        installed = {
            pathlib.PurePosixPath(str(path)).as_posix()
            for path in distribution.files or ()
        }
        assert "quarry_recon/data/target.template.yaml" in installed
        assert "quarry_recon/data/tools.yaml" in installed


def test_dependency_audit_emits_a_vulnerability_free_cyclonedx_document():
    raw = os.environ.get("QUARRY_DEPENDENCY_SBOM", "")
    assert raw, "QUARRY_DEPENDENCY_SBOM must name the pip-audit output"
    path = pathlib.Path(raw).resolve(strict=True)
    assert path.is_file() and 0 < path.stat().st_size <= 8 * 1024 * 1024
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.4"
    assert document.get("vulnerabilities") in (None, [])
    components = document["components"]
    assert 3 <= len(components) <= 64
    names = {row["name"].lower() for row in components}
    assert {"click", "idna", "pyyaml"} <= names
    assert all(isinstance(row.get("version"), str) and row["version"] for row in components)
