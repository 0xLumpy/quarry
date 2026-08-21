#!/usr/bin/env python3
"""Emit the one B-STATIC-SECURITY finding artifact from the shard-0 CI scans."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import subprocess
from pathlib import Path

if __package__:
    from . import check_security_exceptions as exception_check
else:  # pragma: no cover - exercised by the CI command-line invocation
    import check_security_exceptions as exception_check


ROOT = Path(__file__).resolve().parents[1]


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
        + b"\n"
    )


def _call_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return None if base is None else base + "." + node.attr
    return None


def _unsafe_inventory(unsafe_apis: set[str]) -> list[dict[str, object]]:
    entries = []
    for path in sorted((ROOT / "src/quarry_recon").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            api = _call_name(node.func)
            if api not in unsafe_apis:
                continue
            rel = path.relative_to(ROOT).as_posix()
            entries.append(
                {
                    "api": api,
                    "id": "unsafe-api-"
                    + rel.removeprefix("src/quarry_recon/")
                    .removesuffix(".py")
                    .replace("_", "-")
                    .replace("/", "-")
                    + f"-{node.lineno:03d}",
                    "line": node.lineno,
                    "path": rel,
                    "source": "ast",
                }
            )
    return sorted(
        entries,
        key=lambda item: (str(item["path"]), int(item["line"]), str(item["api"])),
    )


def _bandit(policy: dict) -> tuple[list[dict], list[dict]]:
    project = exception_check.tomllib.loads(
        (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )
    manifest = exception_check._read_manifest()
    expected_rows = exception_check._expected(
        manifest,
        exception_check._version(project["project"]["version"]),
    )
    if exception_check._observed() != expected_rows:
        raise SystemExit(
            "Bandit high-severity findings differ from reviewed exceptions"
        )
    suppressions = []
    for exception in manifest["exceptions"]:
        key = (exception["path"], exception["line"], exception["test_id"])
        stable = hashlib.sha256(("\0".join(map(str, key))).encode()).hexdigest()[:20]
        suppressions.append(
            {
                "expires_before": exception["expires_before"],
                "finding_id": "bandit-" + stable,
                "id": "security-suppression-" + stable,
                "owner": exception["owner"],
                "rationale": exception["rationale"],
            }
        )
    return [], sorted(suppressions, key=lambda item: item["id"])


def _tracked_secret_scan() -> None:
    listed = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    if listed.returncode:
        raise SystemExit("git ls-files failed before the tracked-file secret scan")
    paths = [
        value.decode("utf-8", "strict") for value in listed.stdout.split(b"\0") if value
    ]
    if not paths or paths != sorted(paths) or len(paths) != len(set(paths)):
        raise SystemExit("tracked-file secret scan received a noncanonical Git roster")
    completed = subprocess.run(
        [
            "detect-secrets-hook",
            "--baseline",
            ".secrets.baseline",
            "--no-verify",
            *paths,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode:
        raise SystemExit("detect-secrets tracked-file baseline check failed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--h0-fragment", required=True, type=Path)
    parser.add_argument("--job-instance-id", required=True)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    policy = json.loads(args.policy.read_bytes())
    if policy["schema_version"] != "quarry.static-security-policy.v1":
        raise SystemExit("unsupported static security policy")
    expected_job = ".github/workflows/ci.yml#jobs.offline[python-version=3.12,shard=0]"
    if args.job_instance_id != expected_job:
        raise SystemExit("static security must bind the exact Python 3.12 shard-0 job")
    _tracked_secret_scan()
    findings, suppressions = _bandit(policy)
    inventory = _unsafe_inventory(set(policy["unsafe_apis"]))
    if [
        {key: value for key, value in row.items() if key != "source"}
        for row in inventory
    ] != policy["ast_inventory"]["entries"]:
        raise SystemExit("unsafe API inventory differs from frozen policy")
    body = {
        "artifact_type": "security-scan-fragment",
        "ast_inventory": inventory,
        "dependency_manifest": {
            "digest": _digest(ROOT / "pyproject.toml"),
            "name": "package-metadata",
            "path": "pyproject.toml",
        },
        "detect_secrets_baseline_digest": _digest(ROOT / ".secrets.baseline"),
        "findings": findings,
        "h0_fragment_digest": _digest(args.h0_fragment),
        "h0_property_tests": policy["h0_property_tests"],
        "job_instance_id": args.job_instance_id,
        "policy_digest": _digest(args.policy),
        "release": policy["release"],
        "schema_version": "quarry.static-security-scan-fragment.v1",
        "suppressions": suppressions,
        "scan_tools": [
            {"name": "bandit", "version": policy["bandit"]["version"]},
            {"name": "detect-secrets", "version": policy["detect_secrets"]["version"]},
        ],
        "unsuppressed_findings": len(findings),
    }
    args.output.write_bytes(_canonical(body))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
