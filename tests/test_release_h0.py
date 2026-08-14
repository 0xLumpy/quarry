"""Focused H0 tests for the OPEN-only development collection diagnostic."""
from __future__ import annotations

import json
import os
import signal
import stat
import time
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from quarry_recon import release_evidence as evidence
from quarry_recon import release_h0 as h0
from quarry_recon import release_h0_inner as inner

pytestmark = pytest.mark.offline
_ROOT = Path(__file__).resolve().parents[1]


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _identity(*, package_version: str = "0.3.9") -> dict:
    inputs = [
        {"digest": _digest("a"), "name": name, "path": path}
        for name, path in sorted({
            **evidence.DEFAULT_IDENTITY_INPUTS,
            **evidence.FUTURE_RUNNER_INPUTS,
        }.items())
    ]
    return {
        "dirty": False,
        "git_commit": "1" * 40,
        "git_tree": "2" * 40,
        "inputs": inputs,
        "package_version": package_version,
        "package_version_sources": [
            {
                "digest": _digest("a"),
                "path": "pyproject.toml",
                "value": package_version,
            },
            {
                "digest": _digest("a"),
                "path": "src/quarry_recon/__init__.py",
                "value": package_version,
            },
        ],
        "release": evidence.RELEASE_SCOPE,
        "schema_version": evidence.CANDIDATE_SCHEMA,
        "schema_versions": dict(evidence.SCHEMA_VERSIONS),
        "source_tree_digest": _digest("b"),
        "source_tree_digest_algorithm": evidence.SOURCE_TREE_ALGORITHM,
        "submodules": [],
    }


def _runtime() -> dict:
    components = [
        {
            "digest": _digest(character),
            "name": name,
            "path": f"/usr/lib/python3/site-packages/{name}/__init__.py",
            "version": "8.4.1" if name == "pytest" else "1.0",
        }
        for name, character in zip(("click", "idna", "pytest", "yaml"), "cdef")
    ]
    return {
        "architecture": "x86_64",
        "host_kernel": "6.1.0",
        "host_os": "Linux",
        "probe": {
            "components": components,
            "implementation": "CPython",
            "python_version": "3.13.7",
        },
    }


def _artifact_bodies(
    identity: dict,
    runtime: dict,
    taxonomy: dict | None = None,
) -> dict[str, bytes]:
    bodies = {
        name: f"{name}\n".encode("ascii")
        for name in h0._ARTIFACT_MEDIA_TYPES
    }
    bodies["candidate-identity"] = h0._canonical_line(identity)
    bodies["development-profile"] = h0._canonical_line(h0._EXPECTED_PROFILE)
    bodies["pytest-taxonomy"] = evidence.canonical_json_bytes(taxonomy or _taxonomy())
    bodies["runtime"] = h0._canonical_line(runtime)
    return bodies


def _toolchain() -> dict:
    return {
        "tools": [{
            "digest": _digest("9"),
            "name": "python",
            "path": "/usr/bin/python3.13",
            "version": "Python 3.13.7",
        }],
    }


def _taxonomy() -> dict:
    return {
        "collector": {
            "python_implementation": "CPython",
            "python_version": "3.13.7",
            "version": "8.4.1",
        },
    }


def _output_artifacts() -> dict[str, bytes]:
    return _artifact_bodies(_identity(), _runtime())


def _output_bundle() -> tuple[dict[str, bytes], bytes]:
    identity = _identity()
    runtime = _runtime()
    taxonomy = _taxonomy()
    artifacts = _artifact_bodies(identity, runtime, taxonomy)
    summary = h0.build_nonauthoritative_summary(
        identity=identity,
        profile=h0._EXPECTED_PROFILE,
        taxonomy=taxonomy,
        artifact_bodies=artifacts,
        runtime=runtime,
        started_at="2026-08-14T10:00:00Z",
        finished_at="2026-08-14T10:00:01Z",
    )
    return artifacts, h0._canonical_line(summary)


def test_development_profile_and_schema_are_exact_canonical_contracts():
    profile_body = (
        _ROOT / evidence.H0_DEVELOPMENT_PROFILE_PATH
    ).read_bytes()
    schema_body = (
        _ROOT / evidence.H0_DEVELOPMENT_PROFILE_SCHEMA_PATH
    ).read_bytes()
    profile = h0.read_development_profile(profile_body)
    schema = h0._read_development_profile_schema(schema_body, profile)

    assert profile_body == h0._canonical_line(profile)
    assert schema_body == h0._canonical_line(schema)
    assert schema["properties"] == {
        name: {"const": value} for name, value in profile.items()
    }
    assert schema["required"] == sorted(profile)
    assert profile["status"] == "open"
    assert "gate_id" not in profile
    assert profile["fallback"] == "none"
    assert profile["publication"].endswith("nonauthoritative-summary-last")
    assert profile["pytest_arguments"][:2] == ["-p", "no:cacheprovider"]
    assert profile["pytest_arguments"][2] == "--collect-only"


def test_profile_reader_rejects_noncanonical_or_mutated_profiles():
    profile = deepcopy(h0._EXPECTED_PROFILE)
    profile["bwrap_options"][0] = "--share-net"
    with pytest.raises(h0.H0RunnerError, match="open-only contract"):
        h0.read_development_profile(h0._canonical_line(profile))
    with pytest.raises(h0.H0RunnerError, match="canonical"):
        h0.read_development_profile(json.dumps(h0._EXPECTED_PROFILE).encode() + b"\n")


def test_profile_schema_reader_rejects_one_security_const_mutation():
    schema_path = _ROOT / evidence.H0_DEVELOPMENT_PROFILE_SCHEMA_PATH
    schema = json.loads(schema_path.read_bytes())
    schema["properties"]["bwrap_options"]["const"][0] = "--share-net"
    body = h0._canonical_line(schema)
    with pytest.raises(h0.H0RunnerError, match="freeze every exact profile value"):
        h0._read_development_profile_schema(body, h0._EXPECTED_PROFILE)


def test_h0_contracts_are_future_inputs_without_v1_registry_mutation():
    expected = {
        "h0-development-profile": "release/evidence/h0-development-profile-v1.json",
        "h0-development-profile-schema": (
            "release/evidence/schemas/h0-development-profile-v1.schema.json"
        ),
        "h0-inner-launcher": "src/quarry_recon/release_h0_inner.py",
        "h0-private-identity-worker": "src/quarry_recon/release_h0_identity.py",
        "h0-runner": "src/quarry_recon/release_h0.py",
    }
    assert {name: evidence.FUTURE_RUNNER_INPUTS[name] for name in expected} == expected
    assert set(expected).isdisjoint(evidence.DEFAULT_IDENTITY_INPUTS)
    assert h0.H0_DEVELOPMENT_PROFILE_SCHEMA not in evidence.SCHEMA_VERSIONS.values()
    assert evidence.H0_DEVELOPMENT_PROFILE_SCHEMA_PATH not in evidence.SCHEMA_PATHS.values()


def test_parser_requires_every_explicit_authority():
    parser = h0._parser()
    parsed = parser.parse_args([
        "--repository", "/candidate",
        "--output-directory", "/evidence/out",
        "--git", "/usr/bin/git",
        "--bwrap", "/usr/bin/bwrap",
        "--python", "/usr/bin/python3.13",
    ])
    assert vars(parsed) == {
        "repository": "/candidate",
        "output_directory": "/evidence/out",
        "git": "/usr/bin/git",
        "bwrap": "/usr/bin/bwrap",
        "python": "/usr/bin/python3.13",
    }
    with pytest.raises(SystemExit):
        parser.parse_args(["--repository", "/candidate"])


@pytest.mark.parametrize("path", ["git", "./git", "/usr/bin/../bin/git"])
def test_tool_open_refuses_relative_or_non_normalized_paths(path):
    with pytest.raises(h0.H0RunnerError, match="absolute|normalized"):
        h0._open_tool(path, "git")


def test_tool_open_refuses_a_missing_absolute_executable():
    with pytest.raises(h0.H0RunnerError):
        h0._open_tool("/usr/bin/quarry-definitely-missing-h0-tool", "git")


def test_bwrap_argv_is_the_exact_fd_mounted_blank_root_contract():
    bwrap = h0._ToolPin("bwrap", "/usr/bin/bwrap", 91, (), _digest("1"))
    python = h0._ToolPin("python", "/usr/bin/python3.13", 92, (), _digest("2"))
    argv = h0._build_bwrap_argv(
        h0._EXPECTED_PROFILE,
        bwrap=bwrap,
        python=python,
        candidate_fd=71,
        work_fd=72,
        runtime_fd=73,
        status_fd=74,
        isolation_fd=75,
    )

    expected = [
        "/usr/bin/bwrap",
        "--unshare-user", "--unshare-all", "--disable-userns",
        "--assert-userns-disabled", "--die-with-parent", "--new-session",
        "--clearenv", "--cap-drop", "ALL",
        "--hostname", "quarry-h0-development", "--json-status-fd", "74",
        "--tmpfs", "/",
        "--dir", "/candidate", "--ro-bind-fd", "71", "/candidate",
        "--dir", "/work", "--bind-fd", "72", "/work",
        "--dir", "/usr", "--ro-bind-fd", "73", "/usr",
        "--ro-bind-fd", "92", "/usr/bin/python3.13",
        "--symlink", "usr/bin", "/bin",
        "--symlink", "usr/lib", "/lib",
        "--symlink", "usr/lib64", "/lib64",
        "--proc", "/proc", "--remount-ro", "/proc", "--dev", "/dev",
    ]
    for item in h0._EXPECTED_PROFILE["environment"]:
        expected.extend(("--setenv", item["name"], item["value"]))
    expected.extend((
        "--chdir", "/candidate", "--", "/usr/bin/python3.13",
        "-I", "-B", "/candidate/src/quarry_recon/release_h0_inner.py",
        "--isolation-fd", "75",
    ))
    assert argv == expected
    assert "91" not in argv
    assert "--bind" not in argv and "--ro-bind" not in argv
    assert not {"/etc", "/home", "/host", "/sys", "/tmp"}.intersection(argv)


def _bwrap_status_document() -> tuple[dict, bytes]:
    start = {"child-pid": 901}
    for index, name in enumerate(h0._BWRAP_STATUS_NAMES, start=200):
        start[f"{name}-namespace"] = index
    body = (
        evidence.canonical_json_bytes(start) + b"\n"
        + evidence.canonical_json_bytes({"exit-code": 0}) + b"\n"
    )
    return h0._parse_bwrap_status(body)


def test_bwrap_status_parser_requires_two_exact_success_documents():
    record, canonical = _bwrap_status_document()
    assert canonical == h0._canonical_line(record)
    start = record["documents"][0]
    bad = evidence.canonical_json_bytes(start) + b"\n"
    with pytest.raises(h0.H0RunnerError, match="exactly two"):
        h0._parse_bwrap_status(bad)
    failed = (
        evidence.canonical_json_bytes(start) + b"\n"
        + evidence.canonical_json_bytes({"exit-code": 1}) + b"\n"
    )
    with pytest.raises(h0.H0RunnerError, match="successful"):
        h0._parse_bwrap_status(failed)


def _isolation_fixture(tmp_path: Path) -> tuple[dict, dict, list[dict], tuple[os.stat_result, ...]]:
    candidate = tmp_path / "candidate"
    work = tmp_path / "work"
    runtime = tmp_path / "runtime"
    candidate.mkdir()
    work.mkdir()
    runtime.mkdir()
    stats = (os.stat(candidate), os.stat(work), os.stat(runtime))
    status, _body = _bwrap_status_document()
    start = status["documents"][0]
    host_namespaces = [
        {"name": name, "value": f"{name}:[{100 + index}]"}
        for index, name in enumerate(h0._NAMESPACE_NAMES)
    ]
    namespaces = []
    for index, name in enumerate(h0._NAMESPACE_NAMES):
        inode = start.get(f"{name}-namespace", 300 + index)
        namespaces.append({"name": name, "value": f"{name}:[{inode}]"})
    report = {
        "checks": {
            "candidate_read_only": True,
            "candidate_source_exact": True,
            "cwd_exact": True,
            "dev_isolated": True,
            "effective_capabilities_empty": True,
            "environment_exact": True,
            "fd_inventory_exact": True,
            "forbidden_roots_absent": True,
            "hostname_exact": True,
            "no_git_visible": True,
            "proc_read_only": True,
            "report_fd_is_pipe": True,
            "runtime_read_only": True,
            "work_read_write": True,
        },
        "effective_capabilities": "0000000000000000",
        "environment": h0._EXPECTED_PROFILE["environment"],
        "gid": 1000,
        "hostname": "quarry-h0-development",
        "mounts": [
            {
                "device": stats[0].st_dev,
                "inode": stats[0].st_ino,
                "path": "/candidate",
                "read_only": True,
            },
            {"device": 1, "inode": 2, "path": "/dev", "read_only": False},
            {"device": 1, "inode": 3, "path": "/proc", "read_only": True},
            {
                "device": stats[2].st_dev,
                "inode": stats[2].st_ino,
                "path": "/usr",
                "read_only": True,
            },
            {
                "device": stats[1].st_dev,
                "inode": stats[1].st_ino,
                "path": "/work",
                "read_only": False,
            },
        ],
        "namespaces": namespaces,
        "open_descriptors": [0, 1, 2, 75],
        "root_entries": h0._EXPECTED_ROOT_ENTRIES,
        "schema_version": h0.H0_ISOLATION_REPORT_SCHEMA,
        "uid": 1000,
    }
    return report, status, host_namespaces, stats


def test_isolation_report_binds_mount_fds_namespaces_environment_and_report_fd(tmp_path):
    report, status, host_namespaces, stats = _isolation_fixture(tmp_path)
    body = h0._canonical_line(report)
    assert h0._validate_isolation_report(
        body,
        profile=h0._EXPECTED_PROFILE,
        host_namespaces=host_namespaces,
        candidate_stat=stats[0],
        work_stat=stats[1],
        runtime_stat=stats[2],
        bwrap_status=status,
        expected_report_fd=75,
    ) == report

    report["open_descriptors"].append(91)
    with pytest.raises(h0.H0RunnerError, match="descriptor inventory"):
        h0._validate_isolation_report(
            h0._canonical_line(report),
            profile=h0._EXPECTED_PROFILE,
            host_namespaces=host_namespaces,
            candidate_stat=stats[0],
            work_stat=stats[1],
            runtime_stat=stats[2],
            bwrap_status=status,
            expected_report_fd=75,
        )


def test_isolation_report_rejects_a_host_namespace_reuse(tmp_path):
    report, status, host_namespaces, stats = _isolation_fixture(tmp_path)
    report["namespaces"][0]["value"] = host_namespaces[0]["value"]
    with pytest.raises(h0.H0RunnerError, match="not isolated"):
        h0._validate_isolation_report(
            h0._canonical_line(report),
            profile=h0._EXPECTED_PROFILE,
            host_namespaces=host_namespaces,
            candidate_stat=stats[0],
            work_stat=stats[1],
            runtime_stat=stats[2],
            bwrap_status=status,
            expected_report_fd=75,
        )


def test_summary_builder_has_no_release_authority_and_keeps_a_taxonomy_open():
    identity = _identity()
    runtime = _runtime()
    artifacts = _artifact_bodies(identity, runtime)
    summary = h0.build_nonauthoritative_summary(
        identity=identity,
        profile=h0._EXPECTED_PROFILE,
        taxonomy=_taxonomy(),
        artifact_bodies=artifacts,
        runtime=runtime,
        started_at="2026-08-14T10:00:00Z",
        finished_at="2026-08-14T10:00:01Z",
    )

    assert summary["authority"] == "none"
    assert summary["purpose"] == "development-diagnostic-only"
    assert summary["promotion_eligible"] is False
    assert summary["a_taxonomy"] == {
        "id": "A-TAXONOMY",
        "reason": "non-nominated 0.3.9/development host runtime",
        "status": "open",
    }
    assert not set(summary).intersection({
        "assertions", "required", "selection", "signature", "status",
    })
    assert [record["name"] for record in summary["runner_inputs"]] == sorted(
        evidence.FUTURE_RUNNER_INPUTS
    )
    artifact_digests = {
        record["name"]: record["digest"] for record in summary["artifact_digests"]
    }
    assert artifact_digests == {
        name: h0._raw_digest(body) for name, body in artifacts.items()
    }
    assert h0._validate_nonauthoritative_summary(
        summary,
        artifact_bodies=artifacts,
    ) == summary


def test_summary_builder_refuses_package_or_collector_provenance_drift():
    runtime = _runtime()
    bad_identity = _identity(package_version="0.3.10")
    with pytest.raises(h0.H0RunnerError, match="other than 0.3.9"):
        h0.build_nonauthoritative_summary(
            identity=bad_identity,
            profile=h0._EXPECTED_PROFILE,
            taxonomy=_taxonomy(),
            artifact_bodies=_artifact_bodies(bad_identity, runtime),
            runtime=runtime,
            started_at="2026-08-14T10:00:00Z",
            finished_at="2026-08-14T10:00:01Z",
        )

    identity = _identity()
    taxonomy = _taxonomy()
    taxonomy["collector"]["version"] = "0"
    with pytest.raises(h0.H0RunnerError, match="provenance"):
        h0.build_nonauthoritative_summary(
            identity=identity,
            profile=h0._EXPECTED_PROFILE,
            taxonomy=taxonomy,
            artifact_bodies=_artifact_bodies(identity, runtime, taxonomy),
            runtime=runtime,
            started_at="2026-08-14T10:00:00Z",
            finished_at="2026-08-14T10:00:01Z",
        )


def test_output_bundle_is_private_create_only_and_summary_last(tmp_path):
    artifacts, summary_body = _output_bundle()
    observations = []

    def settle() -> None:
        output = tmp_path / "evidence"
        observations.append((output / h0._SUMMARY_FILENAME).read_bytes())

    output = h0._publish_output_bundle(
        tmp_path, "evidence", artifacts, summary_body, settle
    )
    assert output == tmp_path / "evidence"
    assert observations == [summary_body]
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    summary_path = output / "NOT-RELEASE-EVIDENCE.json"
    assert summary_path.read_bytes() == summary_body
    assert stat.S_IMODE(summary_path.stat().st_mode) == 0o600
    for name, filename in h0._OUTPUT_FILENAMES.items():
        target = output / filename
        assert target.read_bytes() == artifacts[name]
        assert stat.S_IMODE(target.stat().st_mode) == 0o600

    with pytest.raises(h0.H0RunnerError, match="overwrite"):
        h0._publish_output_bundle(tmp_path, "evidence", artifacts, summary_body, lambda: None)


def test_settle_fault_after_rename_can_leave_only_an_authority_none_summary(tmp_path):
    artifacts, summary_body = _output_bundle()
    original = tmp_path / "evidence"
    moved = tmp_path / "moved"

    def rename_then_expire() -> None:
        original.rename(moved)
        raise h0.H0DeadlineError("injected deadline")

    with pytest.raises(h0.H0DeadlineError, match="injected"):
        h0._publish_output_bundle(
            tmp_path,
            "evidence",
            artifacts,
            summary_body,
            rename_then_expire,
        )
    assert not original.exists()
    assert moved.is_dir()
    summary = h0._read_canonical_line(
        (moved / h0._SUMMARY_FILENAME).read_bytes(),
        "left diagnostic summary",
    )
    assert summary["authority"] == "none"
    assert summary["promotion_eligible"] is False
    assert not any("gate" in path.name.lower() for path in moved.iterdir())


def test_publication_boundary_rejects_promotion_like_summary_extensions(tmp_path):
    artifacts, summary_body = _output_bundle()
    summary = h0._read_canonical_line(summary_body, "test summary")
    summary["signature"] = None
    with pytest.raises(h0.H0RunnerError, match="top-level shape"):
        h0._publish_output_bundle(
            tmp_path,
            "evidence",
            artifacts,
            h0._canonical_line(summary),
            lambda: None,
        )
    assert not (tmp_path / "evidence").exists()


def test_runner_contains_no_canonical_gate_builder_or_filename():
    source = (_ROOT / "src/quarry_recon/release_h0.py").read_text(encoding="utf-8")
    assert "build_open_gate_record" not in source
    assert "A-TAXONOMY.open.json" not in source
    assert not hasattr(h0, "build_open_gate_record")


@pytest.mark.parametrize("operation", ["open", "fstat", "read", "close"])
def test_artifact_verify_fault_removes_created_file(tmp_path, monkeypatch, operation):
    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    real_open = h0.os.open
    real_fstat = h0.os.fstat
    real_read = h0.os.read
    real_close = h0.os.close
    opens = []
    verify_fd = None

    def wrapped_open(path, flags, *args, **kwargs):
        nonlocal verify_fd
        if path == "artifact.json":
            opens.append(path)
            if len(opens) == 2 and operation == "open":
                raise OSError("injected verify open")
        descriptor = real_open(path, flags, *args, **kwargs)
        if path == "artifact.json" and len(opens) == 2:
            verify_fd = descriptor
        return descriptor

    def wrapped_fstat(descriptor):
        if operation == "fstat" and descriptor == verify_fd:
            raise OSError("injected verify fstat")
        return real_fstat(descriptor)

    def wrapped_read(descriptor, maximum):
        if operation == "read" and descriptor == verify_fd:
            raise OSError("injected verify read")
        return real_read(descriptor, maximum)

    def wrapped_close(descriptor):
        if operation == "close" and descriptor == verify_fd:
            real_close(descriptor)
            raise OSError("injected verify close")
        return real_close(descriptor)

    monkeypatch.setattr(h0.os, "open", wrapped_open)
    monkeypatch.setattr(h0.os, "fstat", wrapped_fstat)
    monkeypatch.setattr(h0.os, "read", wrapped_read)
    monkeypatch.setattr(h0.os, "close", wrapped_close)
    try:
        with pytest.raises(h0.H0RunnerError):
            h0._write_new_private_at(directory_fd, "artifact.json", b"validated\n")
        assert not (tmp_path / "artifact.json").exists()
    finally:
        real_close(directory_fd)


def test_private_scratch_ignores_tmpdir_and_is_pairwise_disjoint(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "output"
    monkeypatch.setenv("TMPDIR", os.fspath(source))
    scratch = h0._private_scratch_directory(os.fspath(source), output)
    try:
        assert scratch.parent == Path("/tmp")
        assert stat.S_IMODE(scratch.stat().st_mode) == 0o700
        assert not scratch.is_relative_to(source)
        assert not output.is_relative_to(scratch)
    finally:
        h0.shutil.rmtree(scratch)


def test_private_scratch_cleans_a_post_creation_validation_failure(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    fake_scratch = source / "leaked"
    fake_scratch.mkdir(mode=0o700)
    monkeypatch.setattr(h0.tempfile, "mkdtemp", lambda **_kwargs: os.fspath(fake_scratch))
    with pytest.raises(h0.H0RunnerError, match="pairwise disjoint"):
        h0._private_scratch_directory(os.fspath(source), tmp_path / "output")
    assert not fake_scratch.exists()


def test_deadline_restore_retry_preserves_the_first_original_mask(monkeypatch):
    original = {signal.SIGUSR1}
    restored_masks = []
    setmask_calls = 0

    def fake_mask(how, mask):
        nonlocal setmask_calls
        if how == signal.SIG_SETMASK:
            setmask_calls += 1
            restored_masks.append(set(mask))
            if setmask_calls == 1:
                raise KeyboardInterrupt
        return {signal.SIGALRM}

    monkeypatch.setattr(h0.signal, "pthread_sigmask", fake_mask)
    monkeypatch.setattr(h0.signal, "setitimer", lambda *_args: (0.0, 0.0))
    monkeypatch.setattr(h0.signal, "sigpending", lambda: set())
    monkeypatch.setattr(h0.signal, "signal", lambda *_args: None)
    control = h0._DeadlineControl(
        time.monotonic() + 10,
        signal.SIG_DFL,
        (0.0, 0.0),
        original,
    )
    with pytest.raises(KeyboardInterrupt):
        control.settle()
    assert not control.restored
    assert control.previous_mask == original
    control.abort()
    assert control.restored
    assert restored_masks == [original, original]


@pytest.mark.parametrize(
    ("write_fault", "close_fault", "expected"),
    [
        (KeyboardInterrupt(), OSError("close"), KeyboardInterrupt),
        (SystemExit(9), KeyboardInterrupt(), SystemExit),
        (OSError("write"), KeyboardInterrupt(), 70),
        (None, SystemExit(11), SystemExit),
    ],
)
def test_inner_report_write_and_close_fault_precedence(
    monkeypatch, write_fault, close_fault, expected
):
    monkeypatch.setattr(inner.sys, "argv", ["inner", "--isolation-fd", "9"])
    monkeypatch.setattr(inner, "_isolation_report", lambda _descriptor: ({}, True))

    def write(_descriptor, _body):
        if write_fault is not None:
            raise write_fault

    def close(_descriptor):
        raise close_fault

    monkeypatch.setattr(inner, "_write_all", write)
    monkeypatch.setattr(inner.os, "close", close)
    if isinstance(expected, int):
        assert inner.main() == expected
    else:
        with pytest.raises(expected) as caught:
            inner.main()
        if expected is SystemExit:
            expected_code = write_fault.code if isinstance(write_fault, SystemExit) else close_fault.code
            assert caught.value.code == expected_code


def _assert_descriptor_closed(descriptor: int, fstat=os.fstat) -> None:
    with pytest.raises(OSError) as caught:
        fstat(descriptor)
    assert caught.value.errno == 9


def test_mount_open_closes_its_fd_when_post_open_fstat_fails(tmp_path, monkeypatch):
    real_open = h0.os.open
    real_fstat = h0.os.fstat
    opened = []

    def tracked_open(path, flags, *args, **kwargs):
        descriptor = real_open(path, flags, *args, **kwargs)
        opened.append(descriptor)
        return descriptor

    monkeypatch.setattr(h0.os, "open", tracked_open)
    monkeypatch.setattr(
        h0.os,
        "fstat",
        lambda _descriptor: (_ for _ in ()).throw(OSError("injected fstat")),
    )
    with pytest.raises(h0.H0RunnerError, match="O_PATH"):
        h0._open_mount_directory(tmp_path, "candidate")
    assert len(opened) == 1
    _assert_descriptor_closed(opened[0], real_fstat)


def test_runtime_mount_closes_transferred_fd_when_second_fstat_fails(tmp_path, monkeypatch):
    descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    real_fstat = os.fstat
    monkeypatch.setattr(h0, "_open_mount_directory", lambda _path, _name: descriptor)
    monkeypatch.setattr(
        h0.os,
        "fstat",
        lambda _descriptor: (_ for _ in ()).throw(OSError("injected runtime fstat")),
    )
    with pytest.raises(h0.H0RunnerError, match="verify opened /usr"):
        h0._open_runtime_mount(h0._EXPECTED_PROFILE)
    _assert_descriptor_closed(descriptor, real_fstat)


def _dummy_pin(name: str, path: str, descriptor: int) -> h0._ToolPin:
    return h0._ToolPin(name, path, descriptor, (), _digest("8"))


def test_bwrap_pipe_acquisition_closes_first_pair_if_second_pipe_fails(monkeypatch):
    real_pipe2 = os.pipe2
    real_fstat = os.fstat
    opened = []

    def second_fails(flags):
        if opened:
            raise OSError("injected second pipe failure")
        pair = real_pipe2(flags)
        opened.extend(pair)
        return pair

    monkeypatch.setattr(h0.os, "pipe2", second_fails)
    with pytest.raises(OSError, match="second pipe"):
        h0._execute_bwrap(
            h0._EXPECTED_PROFILE,
            bwrap=_dummy_pin("bwrap", "/usr/bin/bwrap", 91),
            python=_dummy_pin("python", "/usr/bin/python3.13", 92),
            candidate_fd=71,
            work_fd=72,
            runtime_fd=73,
            runtime_signature=(),
            host_namespaces=[],
            deadline=time.monotonic() + 10,
        )
    assert len(opened) == 2
    for descriptor in opened:
        _assert_descriptor_closed(descriptor, real_fstat)


def test_bwrap_argv_fault_closes_all_four_untransferred_channels(monkeypatch):
    real_pipe2 = os.pipe2
    real_fstat = os.fstat
    opened = []

    def tracked_pipe(flags):
        pair = real_pipe2(flags)
        opened.extend(pair)
        return pair

    monkeypatch.setattr(h0.os, "pipe2", tracked_pipe)
    monkeypatch.setattr(
        h0,
        "_build_bwrap_argv",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(h0.H0RunnerError("argv fault")),
    )
    with pytest.raises(h0.H0RunnerError, match="argv fault"):
        h0._execute_bwrap(
            h0._EXPECTED_PROFILE,
            bwrap=_dummy_pin("bwrap", "/usr/bin/bwrap", 91),
            python=_dummy_pin("python", "/usr/bin/python3.13", 92),
            candidate_fd=71,
            work_fd=72,
            runtime_fd=73,
            runtime_signature=(),
            host_namespaces=[],
            deadline=time.monotonic() + 10,
        )
    assert len(opened) == 4
    for descriptor in opened:
        _assert_descriptor_closed(descriptor, real_fstat)


def test_spawn_owns_channels_before_nondefault_sigchld_refusal(monkeypatch):
    first = os.pipe2(os.O_CLOEXEC)
    second = os.pipe2(os.O_CLOEXEC)
    descriptors = (*first, *second)
    real_fstat = os.fstat
    real_getsignal = signal.getsignal

    def getsignal(sig):
        if sig == signal.SIGCHLD:
            return signal.SIG_IGN
        return real_getsignal(sig)

    monkeypatch.setattr(h0.signal, "getsignal", getsignal)
    with pytest.raises(h0.H0RunnerError, match="SIGCHLD"):
        h0._spawn_bounded(
            ["/unused"],
            deadline=time.monotonic() + 10,
            extra_readers={"first": (first[0], 100), "second": (second[0], 100)},
            close_after_spawn=(first[1], second[1]),
        )
    for descriptor in descriptors:
        _assert_descriptor_closed(descriptor, real_fstat)


def _closed_process_streams():
    streams = []
    for _index in range(2):
        read_fd, write_fd = os.pipe()
        os.close(write_fd)
        streams.append(os.fdopen(read_fd, "rb", buffering=0))
    return streams


def test_spawn_captures_popen_stream_owners_before_close_after_fault(monkeypatch):
    stdout, stderr = _closed_process_streams()

    class Process:
        pid = 123456
        returncode = 0

        def __init__(self):
            self.stdout = stdout
            self.stderr = stderr

    monkeypatch.setattr(h0.subprocess, "Popen", lambda *_args, **_kwargs: Process())

    def close_then_fail(descriptors):
        while descriptors:
            os.close(descriptors.pop())
        raise h0.H0RunnerError("injected close-after fault")

    monkeypatch.setattr(h0, "_close_descriptors", close_then_fail)
    write_fd = os.open("/dev/null", os.O_WRONLY)
    with pytest.raises(h0.H0RunnerError, match="close-after"):
        h0._spawn_bounded(
            ["/unused"],
            deadline=time.monotonic() + 10,
            close_after_spawn=(write_fd,),
        )
    assert stdout.closed and stderr.closed


@pytest.mark.parametrize("wait_gap", ["result", "waitpid"])
def test_spawn_never_resignals_after_leader_release_begins(monkeypatch, wait_gap):
    stdout, stderr = _closed_process_streams()
    signals = []

    class Process:
        pid = 123456

        def __init__(self):
            self.stdout = stdout
            self.stderr = stderr
            self.returncode = None
            self.wait_calls = 0

        def wait(self, timeout=None):
            self.wait_calls += 1
            if wait_gap == "waitpid" and self.wait_calls == 1:
                raise KeyboardInterrupt
            if wait_gap == "waitpid" and self.wait_calls == 2:
                raise ChildProcessError
            self.returncode = 0
            return 0

    process = Process()
    monkeypatch.setattr(h0.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(h0, "_leader_exited_unreaped", lambda _process: True)
    monkeypatch.setattr(
        h0,
        "_signal_process_group",
        lambda _process, sig: signals.append(sig),
    )
    if wait_gap == "result":
        monkeypatch.setattr(
            h0,
            "_ProcessResult",
            lambda **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt()),
        )
    with pytest.raises(KeyboardInterrupt):
        h0._spawn_bounded(["/unused"], deadline=time.monotonic() + 10)
    assert signals == [signal.SIGKILL]
    assert process.returncode is not None
    assert stdout.closed and stderr.closed


@pytest.mark.parametrize("fault_at", ["kill", "wait"])
def test_termination_retries_cancellation_until_kill_and_reap_settle(monkeypatch, fault_at):
    signals = []

    class Process:
        pid = 123456
        returncode = None
        wait_calls = 0

        def wait(self, timeout=None):
            self.wait_calls += 1
            if fault_at == "wait" and self.wait_calls == 1:
                raise KeyboardInterrupt
            self.returncode = -signal.SIGKILL
            return self.returncode

    process = Process()
    kill_calls = 0

    def signal_group(_process, sig):
        nonlocal kill_calls
        signals.append(sig)
        if sig == signal.SIGKILL:
            kill_calls += 1
            if fault_at == "kill" and kill_calls == 1:
                raise KeyboardInterrupt

    monkeypatch.setattr(h0, "_signal_process_group", signal_group)
    monkeypatch.setattr(h0, "_TERMINATION_GRACE_SECONDS", 0.01)
    monkeypatch.setattr(h0.time, "sleep", lambda _seconds: None)
    with pytest.raises(KeyboardInterrupt):
        h0._terminate_and_reap(process)
    assert process.returncode == -signal.SIGKILL
    assert process.wait_calls >= 1
    expected_kills = 2 if fault_at == "kill" else 1
    assert signals.count(signal.SIGKILL) == expected_kills


def test_deadline_setup_failure_rolls_back_partial_signal_contract(monkeypatch):
    state = {"handler": signal.SIG_DFL, "timer": (0.0, 0.0), "mask": set()}
    arm_attempted = False

    monkeypatch.setattr(h0.signal, "getsignal", lambda _sig: state["handler"])
    monkeypatch.setattr(h0.signal, "getitimer", lambda _which: state["timer"])

    def change_handler(_sig, handler):
        state["handler"] = handler

    def set_timer(_which, seconds, interval=0.0):
        nonlocal arm_attempted
        state["timer"] = (float(seconds), float(interval))
        if seconds and not arm_attempted:
            arm_attempted = True
            raise OSError("injected timer install")
        return (0.0, 0.0)

    def change_mask(how, mask):
        prior = set(state["mask"])
        if how == signal.SIG_BLOCK:
            state["mask"].update(mask)
        elif how == signal.SIG_SETMASK:
            state["mask"] = set(mask)
        return prior

    monkeypatch.setattr(h0.signal, "signal", change_handler)
    monkeypatch.setattr(h0.signal, "setitimer", set_timer)
    monkeypatch.setattr(h0.signal, "pthread_sigmask", change_mask)
    monkeypatch.setattr(h0.signal, "sigpending", lambda: set())
    with pytest.raises(OSError, match="timer install"), h0._wall_deadline(10):
        raise AssertionError("deadline setup unexpectedly succeeded")
    assert state == {"handler": signal.SIG_DFL, "timer": (0.0, 0.0), "mask": set()}


def test_candidate_pytest_shadow_is_not_an_attested_runtime_collector(tmp_path):
    shadow = tmp_path / "candidate" / "src" / "pytest.py"
    shadow.parent.mkdir(parents=True)
    shadow.write_text("__version__ = 'forged'\n", encoding="utf-8")
    assert not inner._runtime_module_is_under_usr(SimpleNamespace(__file__=os.fspath(shadow)))
    assert not inner._runtime_module_is_under_usr(SimpleNamespace(__file__=None))
