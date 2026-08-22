from __future__ import annotations

import json
import pathlib
import re
import stat

import pytest
import yaml

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 only
    import tomli as tomllib


pytestmark = pytest.mark.offline

ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECKOUT = "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09"
SETUP_PYTHON = "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1"
UPLOAD_ARTIFACT = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"


def _text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_public_project_integrity_files_are_committed_in_shape():
    license_text = _text("LICENSE")
    assert license_text.startswith("MIT License\n")
    assert "Permission is hereby granted, free of charge" in license_text
    assert "THE SOFTWARE IS PROVIDED \"AS IS\"" in license_text

    notice = _text("NOTICE")
    assert "release-evidence schemas" in notice

    security = _text("SECURITY.md")
    assert "/security/advisories/new" in security
    assert "Do not include credentials" in security
    assert "authorized" in security

    contributing = _text("CONTRIBUTING.md")
    assert "exactly one primary lane" in contributing
    assert "RELEASE-PROCESS.md" in contributing

    changelog = _text("CHANGELOG.md")
    assert changelog.index("## [Unreleased]") < changelog.index("## [0.3.9]")
    assert "remains unreleased" in changelog

    release_process = _text("docs/releases/RELEASE-PROCESS.md")
    release_process_words = " ".join(release_process.split())
    for phrase in ("Nomination and evidence", "Approval, tag, and publication", "Do not rebuild"):
        assert phrase in release_process_words


def test_package_metadata_uses_spdx_and_pinned_ci_tools():
    project = tomllib.loads(_text("pyproject.toml"))
    assert project["project"]["version"] == "0.3.9"
    assert project["project"]["license"] == "MIT"
    assert project["project"]["license-files"] == ["LICENSE", "NOTICE"]
    assert project["build-system"]["requires"] == ["setuptools==80.9.0"]
    ci = project["project"]["optional-dependencies"]["ci"]
    expected = {
        "bandit",
        "build",
        "coverage",
        "detect-secrets",
        "mypy",
        "pip-audit",
        "ruff",
        "twine",
    }
    assert {item.split("==", 1)[0] for item in ci} == expected
    assert all(re.fullmatch(r"[a-z-]+==[0-9]+(?:\.[0-9]+)+", item) for item in ci)


def test_pull_request_ci_selects_every_public_nonlive_lane_separately():
    workflow = yaml.safe_load(_text(".github/workflows/ci.yml"))
    assert workflow["permissions"] == {"contents": "read"}
    jobs = workflow["jobs"]
    assert set(jobs) == {"offline", "integration", "package"}
    expected = {
        "offline": ("H0-hermetic", "offline"),
        "integration": ("H1-tool-integration", "integration"),
        "package": ("P0-package-supply", "packaging"),
    }
    for name, job in jobs.items():
        lane, marker = expected[name]
        assert job["env"]["QUARRY_PRIMARY_LANE"] == lane
        pytest_steps = [step for step in job["steps"] if f"pytest -m {marker}" in step.get("run", "")]
        assert len(pytest_steps) == 1
        assert all("verify-quarry-live.sh" not in step.get("run", "") for step in job["steps"])
        actions = [step["uses"] for step in job["steps"] if "uses" in step]
        expected_actions = [CHECKOUT, SETUP_PYTHON]
        if name == "package":
            expected_actions.extend([UPLOAD_ARTIFACT, UPLOAD_ARTIFACT, UPLOAD_ARTIFACT])
        assert actions == expected_actions
        assert "strategy" not in job
        setup = next(step for step in job["steps"] if step.get("uses") == SETUP_PYTHON)
        assert setup["with"]["python-version"] == "3.12"
    assert jobs["offline"]["timeout-minutes"] == 120
    assert jobs["integration"]["timeout-minutes"] <= 45
    assert jobs["package"]["timeout-minutes"] <= 45
    expected_pytest = {
        "offline": "pytest -m offline",
        "integration": "pytest -m integration -ra",
        "package": "pytest -m packaging",
    }
    for name, command in expected_pytest.items():
        step = next(
            step for step in jobs[name]["steps"]
            if f"pytest -m {expected[name][1]}" in step.get("run", "")
        )
        assert step["run"] == command
        assert step["env"]["PYTHONPATH"] == \
            "${{ github.workspace }}/src:${{ github.workspace }}"
        assert not any(
            token in step["run"]
            for token in (
                "--quarry-shard-", "--quarry-taxonomy-manifest",
                "--quarry-h0-shard-report", "coverage",
                "emit_coverage_shard.py",
            )
        )
    package_steps = jobs["package"]["steps"]
    build_index = next(
        index for index, step in enumerate(package_steps)
        if step.get("name") == "Build clean candidate worktrees twice and retain combined logs"
    )
    upload = package_steps[build_index + 1]
    assert upload["name"] == "Upload bounded clean-build logs"
    assert upload["uses"] == UPLOAD_ARTIFACT
    assert upload["with"]["path"].splitlines() == [
        "${{ runner.temp }}/quarry-build-a.log",
        "${{ runner.temp }}/quarry-build-b.log",
    ]
    install_smoke = next(
        step for step in package_steps
        if step.get("name") == "Install and smoke the candidate wheel in a disposable prefix"
    )
    assert 'wheels=("$RUNNER_TEMP"/quarry-build-a/dist/*.whl)' in install_smoke["run"]
    assert 'zipfile.ZipFile(os.environ["WHEEL"])' in install_smoke["run"]
    assert 'importlib.metadata' not in install_smoke["run"]
    assert '"$wheel"' in install_smoke["run"]
    sbom_observe = [step for step in package_steps if step.get("name") == "Observe installed runtime C-SBOM closure"]
    sbom_upload = [step for step in package_steps if step.get("name") == "Upload raw C-SBOM observation"]
    assert len(sbom_observe) == len(sbom_upload) == 1
    observe = sbom_observe[0]
    assert 'env -u PYTHONPATH "$install_prefix/bin/python" scripts/emit_sbom_observation.py' in observe["run"]
    assert '--wheel "${wheels[0]}"' in observe["run"]
    assert '--output "$RUNNER_TEMP/sbom-observation-3.12.json"' in observe["run"]
    upload = sbom_upload[0]
    assert upload["uses"] == UPLOAD_ARTIFACT
    assert upload["with"] == {
        "name": "sbom-observation-3.12",
        "path": "${{ runner.temp }}/sbom-observation-3.12.json",
        "if-no-files-found": "error",
    }
    audit = [step for step in package_steps if step.get("name") == "Audit the exact resolved C-SBOM dependency closure once"]
    audit_upload = [step for step in package_steps if step.get("name") == "Upload raw C-VULNERABILITY observation"]
    enforce = [step for step in package_steps if step.get("name") == "Enforce the retained pip-audit result without rerunning it"]
    assert len(audit) == len(audit_upload) == len(enforce) == 1
    assert audit[0]["run"].count("pip-audit --strict --no-deps --disable-pip -r /dev/stdin --format cyclonedx-json --progress-spinner off") == 1
    assert "scripts/emit_vulnerability_requirements.py" in audit[0]["run"]
    assert audit_upload[0]["uses"] == UPLOAD_ARTIFACT
    assert audit_upload[0]["if"] == "${{ always() }}"
    assert audit_upload[0]["with"] == {
        "name": "vulnerability-observation-3.12",
        "path": "${{ runner.temp }}/vulnerability-observation-3.12.json",
        "if-no-files-found": "error",
    }
    assert enforce[0]["if"] == "${{ always() }}"
    assert "exit_status" in enforce[0]["run"] and "pip-audit --" not in enforce[0]["run"]


def test_offline_and_authorized_live_diagnostics_are_separate():
    offline_path = ROOT / "scripts/verify-quarry.sh"
    live_path = ROOT / "scripts/verify-quarry-live.sh"
    offline = offline_path.read_text(encoding="utf-8")
    live = live_path.read_text(encoding="utf-8")
    assert "RANGE_APEX" not in offline
    assert "QUARRY_LIVE_APPROVED" not in offline
    assert "0xlumpy.cc" not in offline
    assert "contact=disabled" in offline
    gate = live.index('if [[ "${QUARRY_LIVE_APPROVED:-}" != "1" ]]')
    target = live.index('if [[ -z "${RANGE_APEX:-}" ]]')
    first_effect = min(live.index("timeout 45 dnsx"), live.index("timeout 45 httpx"))
    assert gate < target < first_effect
    assert "RANGE_APEX:-0xlumpy.cc" not in live
    assert stat.S_IMODE(live_path.stat().st_mode) == 0o755
    assert stat.S_IMODE(offline_path.stat().st_mode) == 0o755


def test_security_gates_are_fail_closed_and_reviewable():
    exceptions = json.loads(_text("release/evidence/security-exceptions-v1.json"))
    assert exceptions["schema_version"] == "quarry.security-exceptions.v1"
    assert exceptions["policy"] == {
        "bandit_confidence": "HIGH",
        "bandit_severity": "HIGH",
        "unexpected_findings": "fail",
    }
    assert len(exceptions["exceptions"]) == 4
    assert all(row["expires_before"] == "0.4.0" for row in exceptions["exceptions"])
    assert len({(row["path"], row["line"], row["test_id"]) for row in exceptions["exceptions"]}) == 4

    baseline = json.loads(_text(".secrets.baseline"))
    findings = [row for rows in baseline["results"].values() for row in rows]
    assert findings
    assert all(row.get("is_secret") is False for row in findings)
    assert "python scripts/emit_static_security.py" not in _text(".github/workflows/ci.yml")
    producer = _text("scripts/emit_static_security.py")
    assert '"detect-secrets-hook"' in producer
    assert '"--baseline"' in producer and '".secrets.baseline"' in producer
