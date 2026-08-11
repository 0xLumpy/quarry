"""Phase 1 repository identity: confined IDs, reconciled no-follow reads, and closed entity vocabulary."""
from __future__ import annotations

import errno
import json
import os
import stat
import time

import pytest
from click.testing import CliRunner

from quarry_recon import campaign, store
from quarry_recon.cli import cli
from quarry_recon.repository_identity import (InvalidCampaignId, InvalidRunId, valid_campaign_id,
                                               InvalidArtifactComponent, valid_run_id, valid_segment,
                                               validate_artifact_component, validate_run_id)
from quarry_recon.state import ContractError


pytestmark = pytest.mark.offline

STARTED = "2026-08-11T10:20:30+00:00"


def _identity(run_id: str, *, target: str = "acme.example", started: str = STARTED) -> dict:
    return {"run_id": run_id, "target": target, "started": started}


def _manual_run(project, run_id="fixed", *, identity_file="run.json", target="acme.example", started=STARTED):
    directory = project / "recon" / run_id
    directory.mkdir(parents=True)
    (directory / identity_file).write_text(json.dumps(_identity(run_id, target=target, started=started)))
    return directory


def _tree_signature(root):
    if not root.exists():
        return None
    out = []
    for path in [root, *sorted(root.rglob("*"))]:
        info = path.lstat()
        out.append((str(path.relative_to(root)), stat.S_IFMT(info.st_mode), stat.S_IMODE(info.st_mode),
                    info.st_ino, info.st_size, info.st_mtime_ns, os.readlink(path) if path.is_symlink() else None))
    return out


@pytest.mark.parametrize("value", [
    "r1", "fixed", "20260811-102030-deadbeef", "A", "a.b-c_d", "x" * 64,
])
def test_safe_legacy_and_current_ids_share_one_grammar(value):
    assert valid_segment(value) and valid_run_id(value) and valid_campaign_id(value)


@pytest.mark.parametrize("value", [
    None, b"run", [], {}, "", ".", "..", "/absolute", "a/b", r"a\b", "a\0b", "a\nb", "å", "x" * 65,
])
def test_opaque_id_grammar_rejects_non_ascii_routes_and_controls(value):
    assert not valid_segment(value)
    with pytest.raises(InvalidRunId):
        validate_run_id(value)


def test_opaque_id_validation_does_not_execute_string_subclass_hash():
    class HostileString(str):
        def __hash__(self):
            raise AssertionError("identity validation executed an untrusted hash hook")

    value = HostileString("fixed")
    assert not valid_segment(value)
    with pytest.raises(InvalidRunId):
        validate_run_id(value)


@pytest.mark.parametrize("reserved", ["state", "campaigns"])
def test_repository_namespaces_are_reserved_for_runs_and_campaigns(tmp_path, reserved):
    assert not valid_run_id(reserved) and not valid_campaign_id(reserved)
    with pytest.raises(InvalidRunId):
        store.Run.open(tmp_path, "target", reserved)
    with pytest.raises(InvalidCampaignId):
        campaign.Campaign(tmp_path, reserved)
    assert not (tmp_path / "recon").exists(), "validation must precede path creation"


@pytest.mark.parametrize("bad", ["../escape", "a/b", r"a\b", "/tmp/escape", "x" * 65])
def test_open_rejects_run_id_before_joining_or_creating(tmp_path, bad):
    with pytest.raises(InvalidRunId):
        store.Run.open(tmp_path, "target", bad)
    assert not (tmp_path / "recon").exists()


@pytest.mark.parametrize("bad", ["../escape", "a/b", r"a\b", "/tmp/escape", "state", "campaigns"])
def test_named_create_rejects_run_id_before_repository_creation(tmp_path, bad):
    with pytest.raises(InvalidRunId):
        store.Run.create(tmp_path, "target", run_id=bad)
    assert not (tmp_path / "recon").exists()


@pytest.mark.parametrize("command", ["status", "report"])
def test_cli_run_selector_rejects_traversal_as_invalid_input(tmp_path, command):
    profile = tmp_path / "target.yaml"
    profile.write_text("TARGET: acme.example\nAPEX_DOMAINS:\n  - acme.example\n")
    result = CliRunner().invoke(cli, [command, "-t", str(profile), "--run", "../escape", "--json"])
    assert result.exit_code == 2, result.output
    assert json.loads(result.stdout)["outcome"] == "invalid"
    assert not (tmp_path / "recon").exists()


@pytest.mark.parametrize("target", [None, 7, "", "   "])
def test_create_rejects_invalid_target_before_repository_creation(tmp_path, target):
    with pytest.raises(ContractError):
        store.Run.create(tmp_path, target)
    assert not (tmp_path / "recon").exists()


def test_open_list_and_latest_are_pure_reads(tmp_path):
    directory = _manual_run(tmp_path)
    os.chmod(tmp_path / "recon", 0o755)
    os.chmod(directory, 0o755)
    os.chmod(directory / "run.json", 0o644)
    before = _tree_signature(tmp_path / "recon")

    opened = store.Run.open(tmp_path, "acme.example", "fixed")
    listed = store.Run.list_runs(tmp_path)
    latest = store.Run.latest(tmp_path)

    assert opened.started == STARTED and listed == [directory] and latest.run_id == "fixed"
    assert _tree_signature(tmp_path / "recon") == before
    for name in ("raw", "normalized", "reports", "exports"):
        assert not (directory / name).exists()


@pytest.mark.parametrize("kwargs", [
    {},
    {"run_id": "fixed"},
    {"run_id": "fixed", "load_started": True,
     "_identity": {"run_id": "fixed", "target": "acme.example", "started": STARTED}},
])
def test_public_constructor_cannot_bypass_repository_factories(tmp_path, kwargs):
    with pytest.raises(ContractError, match="construct runs through"):
        store.Run(tmp_path, "acme.example", **kwargs)
    assert not (tmp_path / "recon").exists()


def test_explicit_named_create_is_atomic_and_never_attaches(tmp_path):
    created = store.Run.create(tmp_path, "acme.example", run_id="fixed")
    before = _tree_signature(created.dir)

    with pytest.raises(FileExistsError):
        store.Run.create(tmp_path, "acme.example", run_id="fixed")

    assert _tree_signature(created.dir) == before
    assert store.Run.open(tmp_path, "acme.example", "fixed").started == created.started


def test_latest_carries_one_validated_snapshot_without_rereading(tmp_path, monkeypatch):
    _manual_run(tmp_path)
    reads = []
    original = store._read_identity_file

    def counted(run_fd, name):
        reads.append(name)
        return original(run_fd, name)

    monkeypatch.setattr(store, "_read_identity_file", counted)
    latest = store.Run.latest(tmp_path)
    assert latest.run_id == "fixed"
    assert reads == ["run.json", "manifest.json"]


@pytest.mark.parametrize("kept, malformed", [
    ("run.json", "manifest.json"),
    ("manifest.json", "run.json"),
])
def test_malformed_regular_secondary_keeps_valid_identity_recoverable(tmp_path, kept, malformed):
    directory = _manual_run(tmp_path, identity_file=kept)
    (directory / malformed).write_text("{broken")
    before = _tree_signature(tmp_path / "recon")

    opened = store.Run.open(tmp_path, "acme.example", "fixed")
    assert opened.run_id == "fixed"
    assert store.Run.list_runs(tmp_path) == [directory]
    assert _tree_signature(tmp_path / "recon") == before


def test_deeply_nested_secondary_is_a_typed_malformed_document(tmp_path):
    directory = _manual_run(tmp_path, identity_file="manifest.json")
    (directory / "run.json").write_text("[" * 2000 + "]" * 2000)

    opened = store.Run.open(tmp_path, "acme.example", "fixed")
    assert opened.run_id == "fixed"


def test_stable_oversized_secondary_is_bounded_and_recoverable(tmp_path):
    directory = _manual_run(tmp_path, identity_file="manifest.json")
    (directory / "run.json").write_bytes(b"x" * (store._MAX_IDENTITY_BYTES + 1))
    assert store.Run.open(tmp_path, "acme.example", "fixed").run_id == "fixed"


@pytest.mark.parametrize("oversized", [False, True])
def test_identity_mutation_during_read_fails_closed_even_with_valid_fallback(tmp_path, monkeypatch,
                                                                             oversized):
    directory = _manual_run(tmp_path, identity_file="manifest.json")
    payload = (b"x" * (store._MAX_IDENTITY_BYTES + 1) if oversized
               else json.dumps(_identity("fixed")).encode())
    (directory / "run.json").write_bytes(payload)
    original = store._identity_stat
    calls = 0

    def changed(fd):
        nonlocal calls
        calls += 1
        snapshot = original(fd)
        return snapshot if calls == 1 else (*snapshot[:-1], snapshot[-1] + 1)

    monkeypatch.setattr(store, "_identity_stat", changed)
    with pytest.raises(ContractError, match="changed while it was being read"):
        store.Run.open(tmp_path, "acme.example", "fixed")


def test_systemic_identity_file_failure_never_falls_back_to_an_older_run(tmp_path, monkeypatch):
    older = _manual_run(tmp_path, "older")
    newer = _manual_run(tmp_path, "newer")
    (older / "run.json").write_text(json.dumps(_identity(
        "older", started="2026-08-11T10:20:29+00:00")))
    (newer / "run.json").write_text(json.dumps(_identity(
        "newer", started="2026-08-11T10:20:31+00:00")))
    newer_inode = newer.stat().st_ino
    original = store.os.open

    def exhausted(path, flags, *args, **kwargs):
        dfd = kwargs.get("dir_fd")
        if path == "run.json" and dfd is not None and os.fstat(dfd).st_ino == newer_inode:
            raise OSError(errno.EMFILE, "too many open files")
        return original(path, flags, *args, **kwargs)

    monkeypatch.setattr(store.os, "open", exhausted)
    with pytest.raises(ContractError, match="cannot be opened safely"):
        store.Run.latest(tmp_path)


@pytest.mark.parametrize("field, value", [
    ("run_id", "another-run"),
    ("target", "other.example"),
    ("started", "2026-08-11T10:20:31+00:00"),
])
def test_well_formed_identity_mismatch_is_rejected(tmp_path, field, value):
    directory = _manual_run(tmp_path)
    manifest = _identity("fixed")
    manifest[field] = value
    (directory / "manifest.json").write_text(json.dumps(manifest))

    with pytest.raises(ContractError):
        store.Run.open(tmp_path, "acme.example", "fixed")
    assert store.Run.list_runs(tmp_path) == []


def test_caller_target_must_match_repository_identity(tmp_path):
    directory = _manual_run(tmp_path)
    before = _tree_signature(tmp_path / "recon")
    with pytest.raises(ContractError, match="belongs to target"):
        store.Run.open(tmp_path, "other.example", "fixed")
    assert _tree_signature(tmp_path / "recon") == before
    assert not (directory / "raw").exists()


def test_symlinked_run_directory_is_never_opened_or_listed(tmp_path):
    outside = _manual_run(tmp_path / "outside")
    recon = tmp_path / "project" / "recon"
    recon.mkdir(parents=True)
    os.symlink(outside, recon / "fixed")

    with pytest.raises(ContractError):
        store.Run.open(tmp_path / "project", "acme.example", "fixed")
    assert store.Run.list_runs(tmp_path / "project") == []


def test_systemic_enumeration_open_failure_does_not_select_an_older_run(tmp_path, monkeypatch):
    _manual_run(tmp_path)
    original = store.os.open

    def exhausted(path, flags, *args, **kwargs):
        if path == "fixed" and kwargs.get("dir_fd") is not None:
            raise OSError(errno.EMFILE, "too many open files")
        return original(path, flags, *args, **kwargs)

    monkeypatch.setattr(store.os, "open", exhausted)
    with pytest.raises(ContractError, match="cannot be opened while enumerating"):
        store.Run.list_runs(tmp_path)


def test_latest_reconciles_the_profile_target(tmp_path):
    _manual_run(tmp_path, target="acme.example")
    with pytest.raises(ContractError, match="latest run .* belongs to target"):
        store.Run.latest(tmp_path, "other.example")


@pytest.mark.parametrize("command", ["status", "report"])
def test_empty_explicit_run_selector_is_invalid_not_latest(tmp_path, command):
    profile = tmp_path / "target.yaml"
    profile.write_text("TARGET: acme.example\nAPEX_DOMAINS:\n  - acme.example\n")
    _manual_run(tmp_path)

    result = CliRunner().invoke(cli, [command, "-t", str(profile), "--run", "", "--json"])
    assert result.exit_code == 2, result.output
    assert json.loads(result.stdout)["outcome"] == "invalid"


@pytest.mark.parametrize("value", ["", ".", "..", "../x", "a/b", r"a\b", "a\0b", "a\nb", "x" * 256])
def test_artifact_components_are_one_bounded_non_control_component(value):
    with pytest.raises(InvalidArtifactComponent):
        validate_artifact_component(value)
    assert validate_artifact_component("2001:db8::1 evidence.json") == "2001:db8::1 evidence.json"


@pytest.mark.parametrize("position", ["phase", "tool", "name"])
def test_raw_artifact_identity_refuses_before_creating_directories(tmp_path, position):
    run = store.Run.create(tmp_path, "acme.example")
    before = _tree_signature(run.dir)
    values = {"phase": "params", "tool": "nuclei", "name": "findings.jsonl"}
    values[position] = "../escape"

    with pytest.raises(InvalidArtifactComponent):
        run.raw_path(values["phase"], values["tool"], values["name"])
    assert _tree_signature(run.dir) == before


@pytest.mark.parametrize("linked", ["run.json", "manifest.json"])
def test_any_symlinked_identity_file_invalidates_the_run(tmp_path, linked):
    directory = tmp_path / "recon" / "fixed"
    directory.mkdir(parents=True)
    safe = "manifest.json" if linked == "run.json" else "run.json"
    (directory / safe).write_text(json.dumps(_identity("fixed")))
    external = tmp_path / "external.json"
    external.write_text(json.dumps(_identity("fixed")))
    os.symlink(external, directory / linked)

    with pytest.raises(ContractError):
        store.Run.open(tmp_path, "acme.example", "fixed")
    assert store.Run.list_runs(tmp_path) == []


@pytest.mark.parametrize("kind", ["fifo", "directory"])
def test_non_regular_identity_refuses_promptly_even_with_valid_fallback(tmp_path, kind):
    directory = _manual_run(tmp_path, identity_file="manifest.json")
    unsafe = directory / "run.json"
    if kind == "fifo":
        os.mkfifo(unsafe)
    else:
        unsafe.mkdir()

    started = time.monotonic()
    with pytest.raises(ContractError, match="not a regular file"):
        store.Run.open(tmp_path, "acme.example", "fixed")
    assert time.monotonic() - started < 1.0
    assert store.Run.list_runs(tmp_path) == []


@pytest.mark.parametrize("operation", [
    lambda run: store.canonical_key("unknown", {"value": "x"}),
    lambda run: run.add("unknown", {"value": "x"}),
    lambda run: run.inherit("unknown", {"value": "x"}),
    lambda run: run.read("unknown"),
    lambda run: run.read_folded("unknown"),
    lambda run: run.count("unknown"),
    lambda run: run.values("unknown"),
    lambda run: run._entity_file("unknown"),
    lambda run: run._fold_refused_path("unknown"),
    lambda run: store.material("unknown", {"value": "x"}),
    lambda run: store.fingerprint("unknown", {"value": "x"}),
    lambda run: store.merge("unknown", {}, {"value": "x"}),
    lambda run: store.adds_material("unknown", {}, {"value": "x"}),
])
def test_unknown_entity_refuses_before_path_or_cache_side_effect(tmp_path, operation):
    run = store.Run.create(tmp_path, "acme.example")
    before_tree = _tree_signature(run.dir)
    before_caches = (dict(run._records), dict(run._folded), dict(run._counts_cache))

    with pytest.raises(ContractError, match="unknown entity"):
        operation(run)

    assert _tree_signature(run.dir) == before_tree
    assert (run._records, run._folded, run._counts_cache) == before_caches


def test_entity_validation_does_not_execute_string_subclass_hash(tmp_path):
    class HostileEntity(str):
        def __hash__(self):
            raise AssertionError("entity validation executed an untrusted hash hook")

    run = store.Run.create(tmp_path, "acme.example")
    with pytest.raises(ContractError, match="unknown entity"):
        run.read(HostileEntity("subdomain"))
