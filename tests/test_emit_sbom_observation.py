"""Focused unit checks for the installed-prefix C-SBOM producer helpers."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
from importlib.metadata import FileHash, PackagePath
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.offline
SPEC = importlib.util.spec_from_file_location(
    "emit_sbom_observation",
    ROOT / "scripts" / "emit_sbom_observation.py",
)
assert SPEC and SPEC.loader
producer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(producer)


def _record_path(value: str, body: bytes, *, blank: bool = False) -> PackagePath:
    path = PackagePath(value)
    if blank:
        path.hash = None
        path.size = None
    else:
        encoded = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b"=")
        path.hash = FileHash("sha256=" + encoded.decode("ascii"))
        path.size = len(body)
    return path


class _Distribution:
    def __init__(
        self,
        prefix: Path,
        name: str,
        version: str,
        *,
        license_value: str = "MIT",
        requires: tuple[str, ...] = (),
    ):
        self._prefix = prefix
        self.metadata = {"License": license_value, "Name": name}
        self.version = version
        self.requires = requires
        module = f"lib/{name}/__init__.py"
        record = f"lib/{name}-{version}.dist-info/RECORD"
        module_path = prefix / module
        record_path = prefix / record
        module_path.parent.mkdir(parents=True, exist_ok=True)
        record_path.parent.mkdir(parents=True, exist_ok=True)
        module_body = f"{name} {version}\n".encode()
        module_path.write_bytes(module_body)
        record_path.write_bytes(b"record\n")
        self.files = [
            _record_path(module, module_body),
            _record_path(record, b"record\n", blank=True),
        ]

    def locate_file(self, listed: PackagePath) -> Path:
        return self._prefix / listed


def test_marker_rows_cover_python_platform_and_extra():
    environment = {
        "extra": "",
        "platform_system": "Linux",
        "python_version": "3.10",
    }
    assert producer._requirement("tomli; python_version < '3.11'", environment) == (
        "tomli",
        True,
    )
    assert producer._requirement(
        "colorama; platform_system == 'Windows'", environment
    ) == ("colorama", False)
    assert producer._requirement("ruff; extra == 'all'", environment) == ("ruff", False)


def test_regular_file_normalizes_prefix_relative_console_path_and_refuses_symlink(
    tmp_path,
):
    prefix = tmp_path / "prefix"
    console = prefix / "bin" / "quarry"
    console.parent.mkdir(parents=True)
    console.write_bytes(b"quarry\n")
    (prefix / "lib" / "python" / "site-packages").mkdir(parents=True)
    located = prefix / "lib" / "python" / "site-packages" / "../../../bin" / "quarry"
    resolved, digest, size = producer._regular_file(located, prefix)
    assert resolved == console and digest == producer._digest(b"quarry\n") and size == 7
    link = prefix / "bin" / "linked"
    link.symlink_to(console)
    with pytest.raises(SystemExit, match="non-symlink"):
        producer._regular_file(link, prefix)
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside\n")
    with pytest.raises(SystemExit, match="escapes prefix"):
        producer._regular_file(outside, prefix)


def test_component_reconciles_record_and_active_installed_version(tmp_path):
    prefix = tmp_path / "prefix"
    root = _Distribution(
        prefix,
        "root",
        "1.0",
        requires=("dependency>=2.0",),
    )
    dependency = _Distribution(prefix, "dependency", "2.1")
    distributions = {"root": root, "dependency": dependency}
    component = producer._component(
        root,
        distributions=distributions,
        prefix=prefix,
        marker_environment={"extra": "", "python_version": "3.10"},
        total_bytes=[0],
    )
    assert component["active_dependencies"] == ["dependency"]

    dependency.version = "1.9"
    with pytest.raises(SystemExit, match="does not satisfy"):
        producer._component(
            root,
            distributions=distributions,
            prefix=prefix,
            marker_environment={"extra": "", "python_version": "3.10"},
            total_bytes=[0],
        )

    dependency.version = "2.1"
    root.files[0].hash = FileHash("sha256=" + "A" * 43)
    with pytest.raises(SystemExit, match="does not match installed bytes"):
        producer._component(
            root,
            distributions=distributions,
            prefix=prefix,
            marker_environment={"extra": "", "python_version": "3.10"},
            total_bytes=[0],
        )


def test_component_requires_license_and_one_blank_record_self_row(tmp_path):
    prefix = tmp_path / "prefix"
    missing_license = _Distribution(prefix, "missing-license", "1", license_value="")
    with pytest.raises(SystemExit, match="no license assertion"):
        producer._component(
            missing_license,
            distributions={"missing-license": missing_license},
            prefix=prefix,
            marker_environment={"extra": "", "python_version": "3.10"},
            total_bytes=[0],
        )

    malformed = _Distribution(prefix, "malformed", "1")
    malformed.files[-1].size = 7
    with pytest.raises(SystemExit, match="self-row is not blank"):
        producer._component(
            malformed,
            distributions={"malformed": malformed},
            prefix=prefix,
            marker_environment={"extra": "", "python_version": "3.10"},
            total_bytes=[0],
        )
