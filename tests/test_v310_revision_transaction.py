"""V310-03: a revision is a certified staged candidate whose pointer publishes last."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from quarry_recon import oob, privfs, revision
from quarry_recon.store import Run

pytestmark = pytest.mark.offline


def _sealed(tmp_path) -> Run:
    run = Run.create(tmp_path / "project", "example.com")
    run.add("subdomain", {"host": "base.example.com"})
    run.write_state("running")
    run.write_state("finalizing")
    run.write_manifest({}, ["horizontal"], metrics=None, policy=None)
    run.write_state("finished")
    return run


def _generic_revision(run: Run, entity: str, record: dict):
    sink = revision.ingest(run, "v310.fixture")
    assert sink.add(entity, record)
    return sink.commit()


def _oob_revision(run: Run, tmp_path):
    source = tmp_path / "callback.jsonl"
    source.write_text(json.dumps({
        "protocol": "dns",
        "unique-id": "csession01",
        "full-id": "qlate.csession01",
        "q-type": "A",
        "remote-address": "203.0.113.9",
        "timestamp": "2026-08-14T12:00:00Z",
    }) + "\n")
    return oob.import_file(run, source)["revision"]


def test_disjoint_revisions_republish_the_full_effective_overlay(tmp_path):
    run = _sealed(tmp_path)
    first = _generic_revision(run, "url", {"url": "https://base.example.com/late"})
    second = _generic_revision(run, "secret", {"id": "late-secret", "value": "fixture"})

    assert (first.revision, second.revision) == (1, 2)
    assert second.entity_counts == {"secret": 1, "subdomain": 1, "url": 1}
    assert set(second.entity_digests) == set(second.entity_counts)
    assert revision.combined_fold(run.dir, "url").records
    assert revision.combined_fold(run.dir, "secret").records

    view = run.dir / "revisions" / second.views["dir"] / "exports"
    assert view.joinpath("urls.txt").read_text().splitlines() == ["https://base.example.com/late"]
    assert json.loads(view.joinpath("secrets.jsonl").read_text())["id"] == "late-secret"


def test_revision_binds_pointer_entities_segments_raw_and_views(tmp_path):
    run = _sealed(tmp_path)
    published = _oob_revision(run, tmp_path)
    pointer = json.loads(revision.pointer_path(run.dir).read_text())

    assert pointer["pointer_digest"] == revision._pointer_digest(pointer)
    assert published.raw_files
    assert set(published.entity_digests) == set(published.entity_counts)
    assert revision.missing_views(run.dir) == []

    hotlist = run.dir / "revisions" / published.views["dir"] / "HOTLIST.md"
    hotlist.write_text(hotlist.read_text() + "changed derived bytes\n")
    stale = revision.read(run.dir)
    assert stale.status == "valid" and stale.stale_views == ["HOTLIST.md"]
    assert revision.missing_views(run.dir) == ["HOTLIST.md"]


@pytest.mark.parametrize("claim", ["pointer", "entity", "segment", "raw"])
def test_evidence_corruption_matrix_fails_closed(tmp_path, claim):
    run = _sealed(tmp_path)
    published = _oob_revision(run, tmp_path)
    pointer_path = revision.pointer_path(run.dir)
    pointer = json.loads(pointer_path.read_text())

    if claim == "pointer":
        pointer["created"] += "-tampered"
        pointer_path.write_text(json.dumps(pointer))
    elif claim == "entity":
        entity = next(iter(pointer["entity_digests"]))
        pointer["entity_digests"][entity] = "0" * 64
        pointer["pointer_digest"] = revision._pointer_digest(pointer)
        pointer_path.write_text(json.dumps(pointer))
    elif claim == "segment":
        segment = revision._segment_path(run.dir, published.segments[0]["file"])
        segment.write_bytes(segment.read_bytes() + b"{}\n")
    else:
        raw_ref = next(iter(published.raw_files))
        raw_path = run.dir / raw_ref
        raw_path.write_bytes(raw_path.read_bytes() + b"changed\n")

    assert revision.read(run.dir).status == "unusable"
    assert revision.combined_counts(run.dir) == {}


@pytest.mark.parametrize("stage", ["segment", "render", "certify", "fsync", "pointer"])
def test_staged_faults_leave_the_prior_pointer_byte_identical(tmp_path, monkeypatch, stage):
    run = _sealed(tmp_path)
    _generic_revision(run, "url", {"url": "https://base.example.com/first"})
    before = revision.pointer_path(run.dir).read_bytes()
    sink = revision.ingest(run, "v310.fixture")
    assert sink.add("secret", {"id": "second", "value": "fixture"})

    def boom(*_args, **_kwargs):
        raise OSError(f"injected {stage} fault")

    if stage == "segment":
        real_write = privfs.write_private

        def write(path, text, **kwargs):
            path = Path(path)
            if path.name == revision.SEGMENT_NAME and path.parent.name == "rev0002":
                boom()
            return real_write(path, text, **kwargs)

        monkeypatch.setattr(privfs, "write_private", write)
    elif stage == "render":
        monkeypatch.setattr(sink, "_render_views", boom)
    elif stage == "certify":
        real_certify = revision._certify_document

        def certify(run_dir, document):
            if document.get("revision") == 2:
                return revision.Revision(revision=2, status="unusable", reason="injected certification fault")
            return real_certify(run_dir, document)

        monkeypatch.setattr(revision, "_certify_document", certify)
    elif stage == "fsync":
        monkeypatch.setattr(revision, "_fsync_tree", boom)
    else:
        monkeypatch.setattr(revision, "_publish_pointer", boom)

    with pytest.raises(revision.RevisionError):
        sink.commit()

    assert revision.pointer_path(run.dir).read_bytes() == before
    prior = revision.read(run.dir)
    assert (prior.status, prior.revision) == ("valid", 1)
    assert "rev0002" in prior.orphans


def test_durability_barriers_precede_pointer_publication(tmp_path, monkeypatch):
    run = _sealed(tmp_path)
    sink = revision.ingest(run, "v310.fixture")
    assert sink.add("url", {"url": "https://base.example.com/late"})
    events = []
    real_tree = revision._fsync_tree
    real_raw = revision._fsync_raw_claims
    real_directory = revision._fsync_directory
    real_publish = revision._publish_pointer

    def tree(path, **kwargs):
        events.append("tree")
        return real_tree(path, **kwargs)

    def raw(run_dir, claims, **kwargs):
        events.append("raw")
        return real_raw(run_dir, claims, **kwargs)

    def directory(path, **kwargs):
        events.append(f"directory:{path}")
        return real_directory(path, **kwargs)

    def publish(path, document, **kwargs):
        events.append("pointer")
        return real_publish(path, document, **kwargs)

    monkeypatch.setattr(revision, "_fsync_tree", tree)
    monkeypatch.setattr(revision, "_fsync_raw_claims", raw)
    monkeypatch.setattr(revision, "_fsync_directory", directory)
    monkeypatch.setattr(revision, "_publish_pointer", publish)

    assert sink.commit().status == "valid"
    pointer_index = events.index("pointer")
    assert {"tree", "raw"}.issubset(events[:pointer_index])
    assert f"directory:{revision.revisions_dir(run.dir)}" in events[:pointer_index]
    assert f"directory:{run.dir}" in events[:pointer_index]


def test_post_swap_directory_fsync_fault_restores_the_prior_pointer(tmp_path, monkeypatch):
    run = _sealed(tmp_path)
    _generic_revision(run, "url", {"url": "https://base.example.com/first"})
    before = revision.pointer_path(run.dir).read_bytes()
    sink = revision.ingest(run, "v310.fixture")
    assert sink.add("secret", {"id": "second", "value": "fixture"})
    real_replace = revision.os.replace
    real_fsync = revision.os.fsync
    state = {"pointer_replaced": False, "faulted": False}

    def replace(source, destination, *args, **kwargs):
        result = real_replace(source, destination, *args, **kwargs)
        if destination == revision.POINTER_NAME:
            state["pointer_replaced"] = True
        return result

    def fsync(fd):
        if state["pointer_replaced"] and not state["faulted"]:
            state["faulted"] = True
            raise OSError("injected post-swap directory fsync fault")
        return real_fsync(fd)

    monkeypatch.setattr(revision.os, "replace", replace)
    monkeypatch.setattr(revision.os, "fsync", fsync)

    with pytest.raises(revision.RevisionError):
        sink.commit()

    assert state == {"pointer_replaced": True, "faulted": True}
    assert revision.pointer_path(run.dir).read_bytes() == before
    assert (revision.read(run.dir).status, revision.read(run.dir).revision) == ("valid", 1)


def test_close_after_effect_is_reconciled_as_a_landed_revision(tmp_path, monkeypatch):
    run = _sealed(tmp_path)
    sink = revision.ingest(run, "v310.fixture")
    assert sink.add("url", {"url": "https://base.example.com/late"})
    real_replace = revision.os.replace
    real_close = revision.os.close
    state = {"pointer_replaced": False, "faulted": False}

    def replace(source, destination, *args, **kwargs):
        result = real_replace(source, destination, *args, **kwargs)
        if destination == revision.POINTER_NAME:
            state["pointer_replaced"] = True
        return result

    def close(fd):
        if state["pointer_replaced"] and not state["faulted"]:
            try:
                is_directory = Path(f"/proc/self/fd/{fd}").is_dir()
            except OSError:
                is_directory = False
            if is_directory:
                state["faulted"] = True
                real_close(fd)
                raise OSError("injected close-after-effect")
        return real_close(fd)

    monkeypatch.setattr(revision.os, "replace", replace)
    monkeypatch.setattr(revision.os, "close", close)

    published = sink.commit()

    assert state == {"pointer_replaced": True, "faulted": True}
    assert sink.revised is True
    assert (published.status, published.revision) == ("valid", 1)
    assert (revision.read(run.dir).status, revision.read(run.dir).revision) == ("valid", 1)


@pytest.mark.parametrize("sentinel", [KeyboardInterrupt("cancel"), SystemExit("exit")])
def test_close_after_effect_preserves_control_flow_and_marks_landed(
    tmp_path, monkeypatch, sentinel,
):
    run = _sealed(tmp_path)
    sink = revision.ingest(run, "v310.fixture")
    assert sink.add("url", {"url": "https://base.example.com/late"})
    real_replace = revision.os.replace
    real_close = revision.os.close
    state = {"pointer_replaced": False, "faulted": False}

    def replace(source, destination, *args, **kwargs):
        result = real_replace(source, destination, *args, **kwargs)
        if destination == revision.POINTER_NAME:
            state["pointer_replaced"] = True
        return result

    def close(fd):
        if state["pointer_replaced"] and not state["faulted"]:
            try:
                is_directory = Path(f"/proc/self/fd/{fd}").is_dir()
            except OSError:
                is_directory = False
            if is_directory:
                state["faulted"] = True
                real_close(fd)
                raise sentinel
        return real_close(fd)

    monkeypatch.setattr(revision.os, "replace", replace)
    monkeypatch.setattr(revision.os, "close", close)

    with pytest.raises(type(sentinel)) as caught:
        sink.commit()

    assert caught.value is sentinel
    assert sink.revised is True
    assert (revision.read(run.dir).status, revision.read(run.dir).revision) == ("valid", 1)


def test_failed_rollback_is_reconciled_to_the_landed_pointer(tmp_path, monkeypatch):
    run = _sealed(tmp_path)
    _generic_revision(run, "url", {"url": "https://base.example.com/first"})
    sink = revision.ingest(run, "v310.fixture")
    assert sink.add("secret", {"id": "second", "value": "fixture"})
    real_replace = revision.os.replace
    real_fsync = revision.os.fsync
    real_open = revision.os.open
    state = {"pointer_replaced": False, "fsync_faulted": False, "rollback_refused": False}

    def replace(source, destination, *args, **kwargs):
        result = real_replace(source, destination, *args, **kwargs)
        if destination == revision.POINTER_NAME:
            state["pointer_replaced"] = True
        return result

    def fsync(fd):
        if state["pointer_replaced"] and not state["fsync_faulted"]:
            state["fsync_faulted"] = True
            raise OSError("injected first directory fsync fault")
        return real_fsync(fd)

    def opened(path, *args, **kwargs):
        if state["fsync_faulted"] and isinstance(path, str) and path.endswith(".rollback"):
            state["rollback_refused"] = True
            raise OSError("injected rollback create fault")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(revision.os, "replace", replace)
    monkeypatch.setattr(revision.os, "fsync", fsync)
    monkeypatch.setattr(revision.os, "open", opened)

    published = sink.commit()

    assert all(state.values())
    assert sink.revised is True
    assert (published.status, published.revision) == ("valid", 2)
    assert (revision.read(run.dir).status, revision.read(run.dir).revision) == ("valid", 2)


def test_rollback_file_is_fsynced_before_it_replaces_the_pointer(tmp_path, monkeypatch):
    run = _sealed(tmp_path)
    _generic_revision(run, "url", {"url": "https://base.example.com/first"})
    sink = revision.ingest(run, "v310.fixture")
    assert sink.add("secret", {"id": "second", "value": "fixture"})
    real_replace = revision.os.replace
    real_fsync = revision.os.fsync
    real_open = revision.os.open
    rollback_fds = set()
    events = []
    state = {"pointer_replaced": False, "faulted": False}

    def opened(path, *args, **kwargs):
        fd = real_open(path, *args, **kwargs)
        if isinstance(path, str) and path.endswith(".rollback"):
            rollback_fds.add(fd)
        return fd

    def replace(source, destination, *args, **kwargs):
        if isinstance(source, str) and source.endswith(".rollback"):
            events.append("rollback-replace")
        result = real_replace(source, destination, *args, **kwargs)
        if destination == revision.POINTER_NAME:
            state["pointer_replaced"] = True
        return result

    def fsync(fd):
        if fd in rollback_fds:
            events.append("rollback-file-fsync")
        if state["pointer_replaced"] and not state["faulted"]:
            state["faulted"] = True
            raise OSError("injected post-swap fsync fault")
        return real_fsync(fd)

    monkeypatch.setattr(revision.os, "open", opened)
    monkeypatch.setattr(revision.os, "replace", replace)
    monkeypatch.setattr(revision.os, "fsync", fsync)

    with pytest.raises(revision.RevisionError):
        sink.commit()

    assert events.index("rollback-file-fsync") < events.index("rollback-replace")
    assert (revision.read(run.dir).status, revision.read(run.dir).revision) == ("valid", 1)


@pytest.mark.parametrize("sentinel", [KeyboardInterrupt("cancel"), SystemExit("exit")])
def test_restored_pointer_settlement_preserves_control_flow(
    tmp_path, monkeypatch, sentinel,
):
    run = _sealed(tmp_path)
    _generic_revision(run, "url", {"url": "https://base.example.com/first"})
    before = revision.pointer_path(run.dir).read_bytes()
    sink = revision.ingest(run, "v310.fixture")
    assert sink.add("secret", {"id": "second", "value": "fixture"})
    real_replace = revision.os.replace
    real_fsync = revision.os.fsync
    real_fsync_directory = revision._fsync_directory
    state = {"pointer_replaced": False, "fsync_faulted": False,
             "rollback_replaced": False, "cancelled": False}

    def replace(source, destination, *args, **kwargs):
        result = real_replace(source, destination, *args, **kwargs)
        if isinstance(source, str) and source.endswith(".rollback"):
            state["rollback_replaced"] = True
        elif destination == revision.POINTER_NAME:
            state["pointer_replaced"] = True
        return result

    def fsync(fd):
        if state["pointer_replaced"] and not state["fsync_faulted"]:
            state["fsync_faulted"] = True
            raise OSError("injected first directory fsync fault")
        return real_fsync(fd)

    def fsync_directory(path, **kwargs):
        if state["rollback_replaced"] and not state["cancelled"]:
            state["cancelled"] = True
            raise sentinel
        return real_fsync_directory(path, **kwargs)

    monkeypatch.setattr(revision.os, "replace", replace)
    monkeypatch.setattr(revision.os, "fsync", fsync)
    monkeypatch.setattr(revision, "_fsync_directory", fsync_directory)

    with pytest.raises(type(sentinel)) as caught:
        sink.commit()

    assert caught.value is sentinel
    assert all(state.values())
    assert sink.revised is False
    assert revision.pointer_path(run.dir).read_bytes() == before
    assert (revision.read(run.dir).status, revision.read(run.dir).revision) == ("valid", 1)


def test_canonical_revision_directory_substitution_never_returns_success(tmp_path, monkeypatch):
    run = _sealed(tmp_path)
    sink = revision.ingest(run, "v310.fixture")
    assert sink.add("url", {"url": "https://base.example.com/late"})
    root = revision.revisions_dir(run.dir)
    displaced = run.dir / "revisions-displaced"
    real_replace = revision.os.replace
    state = {"substituted": False}

    def replace(source, destination, *args, **kwargs):
        if destination == revision.POINTER_NAME and not state["substituted"]:
            root.rename(displaced)
            revision.privfs.private_dir(root)
            state["substituted"] = True
        return real_replace(source, destination, *args, **kwargs)

    monkeypatch.setattr(revision.os, "replace", replace)

    with pytest.raises(revision.RevisionPublicationError, match="ambiguous") as caught:
        sink.commit()

    assert caught.value.outcome == "ambiguous"
    assert sink.revised is False
    assert revision.read(run.dir).status == "absent"


def test_pointer_settlement_requires_the_original_run_directory_even_after_durability(tmp_path):
    run = _sealed(tmp_path)
    published = _generic_revision(run, "url", {"url": "https://base.example.com/late"})
    pointer = revision.pointer_path(run.dir)
    document = revision._strict_json(pointer.read_bytes(), "revision pointer")
    candidate = revision._certify_document(run.dir, document)
    assert (candidate.status, candidate.revision) == ("valid", published.revision)
    run_identity = revision._private_directory_identity(run.dir)
    revisions_identity = revision._private_directory_identity(revision.revisions_dir(run.dir))
    canonical = run.dir
    held = canonical.parent / f"{canonical.name}-held"
    canonical.rename(held)
    privfs.private_dir(canonical)
    for child in list(held.iterdir()):
        child.rename(canonical / child.name)

    settlement = revision._settle_pointer_fault(
        canonical, document, candidate, None, revisions_identity, run_identity,
        already_durable=True,
    )

    assert settlement.outcome == "ambiguous"
    assert revision._private_directory_identity(canonical) != run_identity
    assert revision._private_directory_identity(revision.revisions_dir(canonical)) == revisions_identity


@pytest.mark.parametrize("sentinel", [KeyboardInterrupt("cancel"), SystemExit("exit")])
def test_prepublication_control_flow_is_preserved_exactly(tmp_path, monkeypatch, sentinel):
    run = _sealed(tmp_path)
    sink = revision.ingest(run, "v310.fixture")
    assert sink.add("url", {"url": "https://base.example.com/late"})

    def stop(*_args, **_kwargs):
        raise sentinel

    monkeypatch.setattr(sink, "_render_views", stop)
    with pytest.raises(type(sentinel)) as caught:
        sink.commit()
    assert caught.value is sentinel
    assert sink.revised is False
    assert revision.read(run.dir).status == "absent"


@pytest.mark.parametrize("sentinel", [KeyboardInterrupt("cancel"), SystemExit("exit")])
def test_pointer_temp_close_control_flow_is_not_masked(tmp_path, monkeypatch, sentinel):
    run = _sealed(tmp_path)
    sink = revision.ingest(run, "v310.fixture")
    assert sink.add("url", {"url": "https://base.example.com/late"})
    real_close = revision.os.close
    state = {"faulted": False}

    def close(fd):
        target = ""
        try:
            target = revision.os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            pass
        if (not state["faulted"] and ".revision.json." in target and target.endswith(".tmp")):
            state["faulted"] = True
            real_close(fd)
            raise sentinel
        return real_close(fd)

    monkeypatch.setattr(revision.os, "close", close)
    with pytest.raises(type(sentinel)) as caught:
        sink.commit()

    assert state["faulted"] is True
    assert caught.value is sentinel
    assert sink.revised is False
    assert revision.read(run.dir).status == "absent"


def test_segment_mutation_during_barrier_is_refused_before_pointer(tmp_path, monkeypatch):
    run = _sealed(tmp_path)
    sink = revision.ingest(run, "v310.fixture")
    assert sink.add("url", {"url": "https://base.example.com/late"})
    real_fsync_tree = revision._fsync_tree

    def mutate(path, **kwargs):
        real_fsync_tree(path, **kwargs)
        path.joinpath(revision.SEGMENT_NAME).write_bytes(
            path.joinpath(revision.SEGMENT_NAME).read_bytes() + b"{}\n",
        )

    monkeypatch.setattr(revision, "_fsync_tree", mutate)
    with pytest.raises(revision.RevisionError, match="changed during durability"):
        sink.commit()
    assert revision.read(run.dir).status == "absent"


def test_raw_mutation_during_barrier_is_refused_and_never_published(tmp_path, monkeypatch):
    run = _sealed(tmp_path)
    real_fsync_raw = revision._fsync_raw_claims

    def mutate(run_dir, claims, **kwargs):
        real_fsync_raw(run_dir, claims, **kwargs)
        ref = next(iter(claims))
        path = Path(run_dir) / ref
        path.write_bytes(path.read_bytes() + b"changed\n")

    monkeypatch.setattr(revision, "_fsync_raw_claims", mutate)
    with pytest.raises(revision.RevisionError, match="changed during durability"):
        _oob_revision(run, tmp_path)
    assert revision.read(run.dir).status == "absent"


def test_tree_durability_never_follows_a_swapped_ancestor(tmp_path, monkeypatch):
    root = privfs.private_dir(tmp_path / "tree")
    nested = privfs.private_dir(root / "nested")
    privfs.write_private(nested / "proof.json", "{}\n")
    outside = privfs.private_dir(tmp_path / "outside")
    privfs.write_private(outside / "outside.json", "outside\n")
    outside_inode = (outside / "outside.json").stat().st_ino
    real_open = revision.os.open
    real_fsync = revision.os.fsync
    root_identity = revision._private_directory_identity(root)
    state = {"swapped": False, "outside_synced": False}

    def swap(component, flags, *args, dir_fd=None, **kwargs):
        if (component == "nested" and dir_fd is not None
                and flags & getattr(os, "O_DIRECTORY", 0) and not state["swapped"]):
            state["swapped"] = True
            nested.rename(root / "held")
            (root / "nested").symlink_to(outside, target_is_directory=True)
        return real_open(component, flags, *args, dir_fd=dir_fd, **kwargs)

    def observe(fd):
        try:
            if os.fstat(fd).st_ino == outside_inode:
                state["outside_synced"] = True
        except OSError:
            pass
        return real_fsync(fd)

    monkeypatch.setattr(revision.os, "open", swap)
    monkeypatch.setattr(revision.os, "fsync", observe)
    with pytest.raises(OSError):
        revision._fsync_tree(root, root_identity=root_identity)
    assert state == {"swapped": True, "outside_synced": False}


@pytest.mark.parametrize("operation", ["tree", "directory"])
def test_durability_rejects_a_swapped_and_restored_root_name(
    tmp_path, monkeypatch, operation,
):
    root = privfs.private_dir(tmp_path / "tree")
    privfs.write_private(root / "actual.json", "actual\n")
    decoy = privfs.private_dir(tmp_path / "decoy")
    privfs.write_private(decoy / "decoy.json", "decoy\n")
    held = tmp_path / "held"
    expected = revision._private_directory_identity(root)
    real_open = revision.os.open
    state = {"swapped": False}

    def swap(component, flags, *args, dir_fd=None, **kwargs):
        if (component == root.name and dir_fd is not None
                and flags & getattr(os, "O_DIRECTORY", 0) and not state["swapped"]):
            state["swapped"] = True
            root.rename(held)
            decoy.rename(root)
            try:
                return real_open(component, flags, *args, dir_fd=dir_fd, **kwargs)
            finally:
                root.rename(decoy)
                held.rename(root)
        return real_open(component, flags, *args, dir_fd=dir_fd, **kwargs)

    monkeypatch.setattr(revision.os, "open", swap)
    with pytest.raises(OSError, match="authority changed before open"):
        if operation == "tree":
            revision._fsync_tree(root, root_identity=expected)
        else:
            revision._fsync_directory(root, directory_identity=expected)
    assert state["swapped"] is True
    assert (root / "actual.json").read_text() == "actual\n"
    assert (decoy / "decoy.json").read_text() == "decoy\n"


@pytest.mark.parametrize("level", ["directory", "file"])
def test_raw_durability_rejects_descendant_aba_substitution(tmp_path, monkeypatch, level):
    run_dir = privfs.private_dir(tmp_path / "run")
    revisions = privfs.private_dir(run_dir / "revisions")
    raw = privfs.private_dir(revisions / "raw")
    actual_dir = privfs.private_dir(raw / "a")
    decoy_dir = privfs.private_dir(raw / "decoy")
    actual = actual_dir / "proof.bin"
    decoy = decoy_dir / "proof.bin"
    privfs.write_private(actual, "same bytes\n")
    privfs.write_private(decoy, "same bytes\n")
    ref = "revisions/raw/a/proof.bin"
    root_identity = revision._private_directory_identity(revisions)
    identities = {}
    claims = revision._raw_file_claims(
        run_dir, [{"record": {"raw_ref": ref}}], root_identity=root_identity,
        identity_claims=identities,
    )
    real_open = revision.os.open
    state = {"swapped": False}

    def swap(component, flags, *args, dir_fd=None, **kwargs):
        target = "a" if level == "directory" else actual.name
        if component == target and dir_fd is not None and not state["swapped"]:
            state["swapped"] = True
            if level == "directory":
                held = raw / "held"
                actual_dir.rename(held)
                decoy_dir.rename(actual_dir)
                try:
                    return real_open(component, flags, *args, dir_fd=dir_fd, **kwargs)
                finally:
                    actual_dir.rename(decoy_dir)
                    held.rename(actual_dir)
            held = actual_dir / "held.bin"
            actual.rename(held)
            decoy.rename(actual)
            try:
                return real_open(component, flags, *args, dir_fd=dir_fd, **kwargs)
            finally:
                actual.rename(decoy)
                held.rename(actual)
        return real_open(component, flags, *args, dir_fd=dir_fd, **kwargs)

    monkeypatch.setattr(revision.os, "open", swap)
    with pytest.raises(OSError, match="revision raw .* authority changed"):
        revision._fsync_raw_claims(
            run_dir, claims, root_identity=root_identity,
            identity_claims=identities,
        )
    assert state["swapped"] is True
    assert actual.read_text() == decoy.read_text() == "same bytes\n"


def test_tree_durability_rewalks_canonical_names_after_fsync(tmp_path, monkeypatch):
    root = privfs.private_dir(tmp_path / "tree")
    actual = root / "proof.bin"
    privfs.write_private(actual, "same bytes\n")
    decoy = tmp_path / "decoy.bin"
    privfs.write_private(decoy, "same bytes\n")
    held = root / "held.bin"
    actual_inode = actual.stat().st_ino
    root_identity = revision._private_directory_identity(root)
    real_fsync = revision.os.fsync
    state = {"swapped": False, "actual_synced": False, "decoy_synced": False}

    def swap(fd):
        inode = os.fstat(fd).st_ino
        if inode == actual_inode and not state["swapped"]:
            state["swapped"] = True
            actual.rename(held)
            decoy.rename(actual)
        if inode == actual_inode:
            state["actual_synced"] = True
        elif state["swapped"] and inode == actual.stat().st_ino:
            state["decoy_synced"] = True
        return real_fsync(fd)

    monkeypatch.setattr(revision.os, "fsync", swap)
    with pytest.raises(OSError, match="changed during durability"):
        revision._fsync_tree(root, root_identity=root_identity)
    assert state == {"swapped": True, "actual_synced": True, "decoy_synced": False}


def test_raw_durability_rewalks_descendant_names_after_fsync(tmp_path, monkeypatch):
    run_dir = privfs.private_dir(tmp_path / "run")
    revisions = privfs.private_dir(run_dir / "revisions")
    raw = privfs.private_dir(revisions / "raw")
    actual_dir = privfs.private_dir(raw / "a")
    decoy_dir = privfs.private_dir(raw / "decoy")
    actual = actual_dir / "proof.bin"
    decoy = decoy_dir / "proof.bin"
    privfs.write_private(actual, "same bytes\n")
    privfs.write_private(decoy, "same bytes\n")
    ref = "revisions/raw/a/proof.bin"
    root_identity = revision._private_directory_identity(revisions)
    identities = {}
    claims = revision._raw_file_claims(
        run_dir, [{"record": {"raw_ref": ref}}], root_identity=root_identity,
        identity_claims=identities,
    )
    actual_inode = actual.stat().st_ino
    held = raw / "held"
    real_fsync = revision.os.fsync
    state = {"swapped": False}

    def swap(fd):
        if os.fstat(fd).st_ino == actual_inode and not state["swapped"]:
            state["swapped"] = True
            actual_dir.rename(held)
            decoy_dir.rename(actual_dir)
        return real_fsync(fd)

    monkeypatch.setattr(revision.os, "fsync", swap)
    with pytest.raises(OSError, match="directory name changed during durability"):
        revision._fsync_raw_claims(
            run_dir, claims, root_identity=root_identity,
            identity_claims=identities,
        )
    assert state["swapped"] is True


def test_raw_durability_closes_an_unsafe_descendant_on_every_refusal(tmp_path):
    run_dir = privfs.private_dir(tmp_path / "run")
    revisions = privfs.private_dir(run_dir / "revisions")
    raw = privfs.private_dir(revisions / "raw")
    actual_dir = privfs.private_dir(raw / "a")
    actual = actual_dir / "proof.bin"
    privfs.write_private(actual, "proof\n")
    ref = "revisions/raw/a/proof.bin"
    root_identity = revision._private_directory_identity(revisions)
    identities = {}
    claims = revision._raw_file_claims(
        run_dir, [{"record": {"raw_ref": ref}}], root_identity=root_identity,
        identity_claims=identities,
    )
    actual_dir.chmod(0o755)
    before = len(os.listdir("/proc/self/fd"))

    for _ in range(32):
        with pytest.raises(OSError, match="unsafe private directory"):
            revision._fsync_raw_claims(
                run_dir, claims, root_identity=root_identity,
                identity_claims=identities,
            )

    assert len(os.listdir("/proc/self/fd")) == before


def test_oob_close_after_effect_keeps_the_landed_raw_proof(tmp_path, monkeypatch):
    run = _sealed(tmp_path)
    real_replace = revision.os.replace
    real_close = revision.os.close
    state = {"pointer_replaced": False, "faulted": False}

    def replace(source, destination, *args, **kwargs):
        result = real_replace(source, destination, *args, **kwargs)
        if destination == revision.POINTER_NAME:
            state["pointer_replaced"] = True
        return result

    def close(fd):
        if state["pointer_replaced"] and not state["faulted"]:
            try:
                is_directory = Path(f"/proc/self/fd/{fd}").is_dir()
            except OSError:
                is_directory = False
            if is_directory:
                state["faulted"] = True
                real_close(fd)
                raise OSError("injected close-after-effect")
        return real_close(fd)

    monkeypatch.setattr(revision.os, "replace", replace)
    monkeypatch.setattr(revision.os, "close", close)

    published = _oob_revision(run, tmp_path)

    assert (published.status, published.revision) == ("valid", 1)
    raw_ref = next(iter(published.raw_files))
    assert (run.dir / raw_ref).is_file()
    assert revision.read(run.dir).status == "valid"


def test_settlement_fsyncs_an_identical_pointer_substituted_during_publication(
    tmp_path, monkeypatch,
):
    run = _sealed(tmp_path)
    sink = revision.ingest(run, "v310.fixture")
    assert sink.add("url", {"url": "https://base.example.com/late"})
    real_replace = revision.os.replace
    real_fsync = revision.os.fsync
    state = {"replaced": False, "swapped": False, "decoy_inode": None,
             "decoy_fsynced": False}

    def replace(source, destination, *args, **kwargs):
        result = real_replace(source, destination, *args, **kwargs)
        if destination == revision.POINTER_NAME:
            state["replaced"] = True
        return result

    def fsync(fd):
        try:
            target = Path(os.readlink(f"/proc/self/fd/{fd}"))
            inode = os.fstat(fd).st_ino
        except OSError:
            target = Path()
            inode = -1
        if (state["replaced"] and not state["swapped"]
                and target == revision.revisions_dir(run.dir)):
            pointer = revision.pointer_path(run.dir)
            held = pointer.parent / "held-pointer.json"
            decoy = pointer.parent / "decoy-pointer.json"
            decoy.write_bytes(pointer.read_bytes())
            decoy.chmod(0o600)
            state["decoy_inode"] = decoy.stat().st_ino
            pointer.rename(held)
            decoy.rename(pointer)
            state["swapped"] = True
        if inode == state["decoy_inode"]:
            state["decoy_fsynced"] = True
        return real_fsync(fd)

    monkeypatch.setattr(revision.os, "replace", replace)
    monkeypatch.setattr(revision.os, "fsync", fsync)
    published = sink.commit()

    assert (published.status, published.revision) == ("valid", 1)
    assert state == {"replaced": True, "swapped": True,
                     "decoy_inode": revision.pointer_path(run.dir).stat().st_ino,
                     "decoy_fsynced": True}
    assert revision.read(run.dir).status == "valid"


def test_pointer_substitution_during_final_run_fsync_is_ambiguous(
    tmp_path, monkeypatch,
):
    run = _sealed(tmp_path)
    sink = revision.ingest(run, "v310.fixture")
    assert sink.add("url", {"url": "https://base.example.com/late"})
    real_fsync = revision.os.fsync
    state = {"swapped": False}

    def fsync(fd):
        try:
            target = Path(os.readlink(f"/proc/self/fd/{fd}"))
        except OSError:
            target = Path()
        pointer = revision.pointer_path(run.dir)
        if target == run.dir and pointer.exists() and not state["swapped"]:
            held = pointer.parent / "held-pointer.json"
            decoy = pointer.parent / "decoy-pointer.json"
            decoy.write_bytes(pointer.read_bytes())
            decoy.chmod(0o600)
            pointer.rename(held)
            decoy.rename(pointer)
            state["swapped"] = True
        return real_fsync(fd)

    monkeypatch.setattr(revision.os, "fsync", fsync)
    with pytest.raises(revision.RevisionPublicationError, match="ambiguous") as caught:
        sink.commit()

    assert caught.value.outcome == "ambiguous"
    assert state["swapped"] is True
    assert sink.revised is False


@pytest.mark.parametrize("prior", [False, True])
def test_post_durability_segment_substitution_never_settles_landed(
    tmp_path, monkeypatch, prior,
):
    run = _sealed(tmp_path)
    if prior:
        _generic_revision(run, "url", {"url": "https://base.example.com/first"})
    sink = revision.ingest(run, "v310.fixture")
    assert sink.add("secret", {"id": "late", "value": "fixture"})
    number = 1 if not prior else 1
    target = revision.revisions_dir(run.dir) / revision._rev_name(number) / revision.SEGMENT_NAME
    real_fsync = revision.os.fsync
    state = {"swapped": False}

    def fsync(fd):
        try:
            opened = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            opened = ""
        if (not state["swapped"] and ".revision.json." in opened
                and opened.endswith(".tmp")):
            held = target.parent / "held-segment.jsonl"
            decoy = target.parent / "decoy-segment.jsonl"
            decoy.write_bytes(target.read_bytes())
            decoy.chmod(0o600)
            target.rename(held)
            decoy.rename(target)
            state["swapped"] = True
        return real_fsync(fd)

    monkeypatch.setattr(revision.os, "fsync", fsync)
    with pytest.raises(revision.RevisionPublicationError, match="ambiguous") as caught:
        sink.commit()

    assert caught.value.outcome == "ambiguous"
    assert state["swapped"] is True
    assert sink.revised is False
