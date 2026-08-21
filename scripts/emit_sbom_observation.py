#!/usr/bin/env python3
"""Emit one bounded raw C-SBOM observation from an installed P0 prefix.

This deliberately has no project imports: it is run by the freshly installed
prefix interpreter, and records what that interpreter can actually reach.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.metadata as metadata
import json
import os
import platform
import re
import stat
import sys
from pathlib import Path
from typing import Any


MAX_COMPONENTS = 128
MAX_FILES_PER_COMPONENT = 4_000
MAX_REQUIREMENTS_PER_COMPONENT = 256
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_FILE_BYTES = 256 * 1024 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_TEXT = 4_096


def _canonical(value: Any) -> bytes:
    return (
        json.dumps(
            value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode("ascii")
        + b"\n"
    )


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _regular_file(path: Path, prefix: Path) -> tuple[Path, str, int]:
    try:
        # Do not let Path.resolve turn a symlink into an apparently safe file.
        before = path.lstat()
    except OSError as exc:
        raise SystemExit(f"missing installed distribution file: {path}: {exc}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise SystemExit(
            f"installed distribution file is not a regular non-symlink: {path}"
        )
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(prefix)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"installed distribution file escapes prefix: {path}") from exc
    if before.st_size > MAX_FILE_BYTES:
        raise SystemExit(f"installed distribution file exceeds bound: {path}")
    hasher = hashlib.sha256()
    with path.open("rb", buffering=1024 * 1024) as source:
        while chunk := source.read(1024 * 1024):
            hasher.update(chunk)
    after = path.lstat()
    if (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise SystemExit(f"installed distribution file changed while observed: {path}")
    return resolved, "sha256:" + hasher.hexdigest(), before.st_size


def _requirement(raw: str, marker_environment: dict[str, str]) -> tuple[str, bool]:
    """Use pip's vendored parser when present; unsupported parsing is closed."""
    try:
        from pip._vendor.packaging.requirements import Requirement
    except ImportError as exc:
        raise SystemExit(
            "pip vendored packaging is required for C-SBOM marker parsing"
        ) from exc
    try:
        parsed = Requirement(raw)
        active = parsed.marker is None or parsed.marker.evaluate(marker_environment)
    except Exception as exc:  # packaging owns its grammar; do not emulate it here.
        raise SystemExit(f"unsupported Requires-Dist row: {raw!r}: {exc}") from exc
    return _name(parsed.name), bool(active)


def _component(  # noqa: C901 - bounded filesystem and metadata validation is intentionally local.
    distribution: metadata.Distribution,
    *,
    distributions: dict[str, metadata.Distribution],
    prefix: Path,
    marker_environment: dict[str, str],
    total_bytes: list[int],
) -> dict[str, Any]:
    raw_name = distribution.metadata.get("Name")
    version = distribution.version
    if not raw_name or not version:
        raise SystemExit("installed distribution has no Name or Version metadata")
    files = distribution.files
    if files is None:
        raise SystemExit(f"installed distribution has no RECORD file list: {raw_name}")
    rows = []
    record_rows = 0
    seen_paths: set[str] = set()
    for listed in files:
        location = Path(distribution.locate_file(listed))
        resolved, digest, size = _regular_file(location, prefix)
        relative = resolved.relative_to(prefix).as_posix()
        if relative in seen_paths:
            raise SystemExit(
                "distribution RECORD path is duplicated after normalization: "
                f"{raw_name}: {relative}"
            )
        seen_paths.add(relative)
        listed_hash = getattr(listed, "hash", None)
        listed_size = getattr(listed, "size", None)
        is_record = relative.endswith(".dist-info/RECORD")
        if is_record:
            record_rows += 1
            if listed_hash is not None or listed_size is not None:
                raise SystemExit(
                    f"distribution RECORD self-row is not blank: {raw_name}"
                )
        else:
            if listed_hash is None or listed_size is None:
                raise SystemExit(
                    f"distribution RECORD row omits hash or size: {raw_name}: {listed}"
                )
            if listed_hash.mode != "sha256" or type(listed_size) is not int:
                raise SystemExit(
                    f"distribution RECORD row uses unsupported integrity fields: "
                    f"{raw_name}: {listed}"
                )
            observed_record_hash = (
                base64.urlsafe_b64encode(bytes.fromhex(digest.removeprefix("sha256:")))
                .rstrip(b"=")
                .decode("ascii")
            )
            if listed_hash.value != observed_record_hash or listed_size != size:
                raise SystemExit(
                    f"distribution RECORD row does not match installed bytes: "
                    f"{raw_name}: {listed}"
                )
        total_bytes[0] += size
        if total_bytes[0] > MAX_TOTAL_FILE_BYTES:
            raise SystemExit("reachable distribution content exceeds total bound")
        rows.append({"digest": digest, "path": relative, "size": size})
        if len(rows) > MAX_FILES_PER_COMPONENT:
            raise SystemExit(f"distribution file count exceeds bound: {raw_name}")
    if record_rows != 1:
        raise SystemExit(
            f"distribution has no one exact blank RECORD self-row: {raw_name}"
        )
    rows.sort(key=lambda row: row["path"])
    requirements = []
    for raw in distribution.requires or ():
        dependency, active = _requirement(raw, marker_environment)
        if active:
            target = distributions.get(dependency)
            if target is None:
                raise SystemExit(
                    f"active dependency is absent from installed prefix: {dependency}"
                )
            try:
                from pip._vendor.packaging.requirements import Requirement

                parsed = Requirement(raw)
                satisfied = parsed.specifier.contains(target.version, prereleases=True)
            except Exception as exc:
                raise SystemExit(
                    f"cannot verify installed dependency version for {raw!r}: {exc}"
                ) from exc
            if not satisfied:
                raise SystemExit(
                    "installed dependency version does not satisfy active requirement: "
                    f"{raw!r}: {target.version}"
                )
        requirements.append({"active": active, "name": dependency, "raw": raw})
        if len(requirements) > MAX_REQUIREMENTS_PER_COMPONENT:
            raise SystemExit(
                f"distribution requirement count exceeds bound: {raw_name}"
            )
    requirements.sort(key=lambda row: row["raw"])
    if len({row["raw"] for row in requirements}) != len(requirements):
        raise SystemExit(f"distribution has duplicate Requires-Dist rows: {raw_name}")
    active_dependencies = sorted(row["name"] for row in requirements if row["active"])
    if len(set(active_dependencies)) != len(active_dependencies):
        raise SystemExit(
            f"distribution has duplicate active dependency edges: {raw_name}"
        )
    license_value = (
        distribution.metadata.get("License-Expression")
        or distribution.metadata.get("License")
        or ""
    ).strip()
    if not license_value:
        raise SystemExit(f"installed distribution has no license assertion: {raw_name}")
    if len(license_value) > MAX_TEXT or any(
        ord(character) < 0x20 for character in license_value
    ):
        raise SystemExit(f"distribution license is unsafe: {raw_name}")
    return {
        "active_dependencies": active_dependencies,
        "content_digest": _digest(_canonical(rows)),
        "files": rows,
        "license": license_value,
        "name": _name(raw_name),
        "raw_requirements": requirements,
        "version": version,
    }


def main() -> None:  # noqa: C901 - one-shot collector keeps the invocation auditable.
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel", required=True)
    parser.add_argument("--output", required=True)
    arguments = parser.parse_args()
    prefix = Path(sys.prefix).resolve(strict=True)
    wheel = Path(arguments.wheel).resolve(strict=True)
    _resolved_wheel, wheel_digest, wheel_size = _regular_file(wheel, wheel.parent)
    try:
        from pip._vendor.packaging import __version__ as packaging_version
        from pip._vendor.packaging.markers import default_environment
    except ImportError as exc:
        raise SystemExit(
            "pip vendored packaging is required for C-SBOM marker parsing"
        ) from exc
    marker_environment = {
        key: str(value) for key, value in default_environment().items()
    }
    marker_environment["extra"] = ""
    if any(
        len(key) > 128 or len(value) > MAX_TEXT
        for key, value in marker_environment.items()
    ):
        raise SystemExit("marker environment exceeds bounds")
    distributions: dict[str, metadata.Distribution] = {}
    for distribution in metadata.distributions():
        raw_name = distribution.metadata.get("Name")
        if raw_name:
            normalized = _name(raw_name)
            if normalized in distributions:
                raise SystemExit(
                    f"duplicate installed distribution metadata: {normalized}"
                )
            distributions[normalized] = distribution
    root = "quarry-recon"
    if root not in distributions:
        raise SystemExit("installed prefix does not contain quarry-recon")
    components: dict[str, dict[str, Any]] = {}
    total_bytes = [0]
    pending = [root]
    while pending:
        current = pending.pop()
        if current in components:
            continue
        distribution = distributions.get(current)
        if distribution is None:
            raise SystemExit(
                f"active dependency is absent from installed prefix: {current}"
            )
        component = _component(
            distribution,
            distributions=distributions,
            prefix=prefix,
            marker_environment=marker_environment,
            total_bytes=total_bytes,
        )
        components[current] = component
        pending.extend(reversed(component["active_dependencies"]))
        if len(components) > MAX_COMPONENTS:
            raise SystemExit("reachable distribution closure exceeds bound")
    ordered = [components[name] for name in sorted(components)]
    graph = [
        {
            "dependencies": row["active_dependencies"],
            "name": row["name"],
            "version": row["version"],
        }
        for row in ordered
    ]
    document = {
        "artifact_type": "sbom-observation",
        "components": ordered,
        "dependency_graph_digest": _digest(_canonical(graph)),
        "environment": {
            "architecture": platform.machine().lower(),
            "isolation_profile": None,
            "os": sys.platform,
            "python": platform.python_version(),
            "runner_image": None,
        },
        "interpreter": {
            "base_prefix": sys.base_prefix,
            "executable": os.path.realpath(sys.executable),
            "implementation": platform.python_implementation().lower(),
            "prefix": str(prefix),
            "version": sys.version,
        },
        "marker_environment": dict(sorted(marker_environment.items())),
        "marker_evaluator": {
            "implementation": "pip._vendor.packaging",
            "version": packaging_version,
        },
        "package": {"name": root, "version": components[root]["version"]},
        "producer": {
            "digest": _regular_file(Path(__file__), Path(__file__).parent)[1],
            "name": "sbom-observation-producer",
        },
        "schema_version": "quarry.gate-artifact.v1",
        "source_wheel": {"digest": wheel_digest, "size": wheel_size},
    }
    output = Path(arguments.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    encoded = _canonical(document)
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise SystemExit("C-SBOM observation exceeds output bound")
    output.write_bytes(encoded)


if __name__ == "__main__":
    main()
