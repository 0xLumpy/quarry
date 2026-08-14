"""V310-03: a revision is a certified staged candidate whose pointer publishes last."""
from __future__ import annotations

import json
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

    def tree(path):
        events.append("tree")
        return real_tree(path)

    def raw(run_dir, claims):
        events.append("raw")
        return real_raw(run_dir, claims)

    def directory(path):
        events.append(f"directory:{path}")
        return real_directory(path)

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

    def fsync_directory(path):
        if state["rollback_replaced"] and not state["cancelled"]:
            state["cancelled"] = True
            raise sentinel
        return real_fsync_directory(path)

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

    def mutate(path):
        real_fsync_tree(path)
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

    def mutate(run_dir, claims):
        real_fsync_raw(run_dir, claims)
        ref = next(iter(claims))
        path = Path(run_dir) / ref
        path.write_bytes(path.read_bytes() + b"changed\n")

    monkeypatch.setattr(revision, "_fsync_raw_claims", mutate)
    with pytest.raises(revision.RevisionError, match="changed during durability"):
        _oob_revision(run, tmp_path)
    assert revision.read(run.dir).status == "absent"


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
