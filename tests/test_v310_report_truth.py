from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import pytest

from quarry_recon import privfs, report_truth, revision, store


pytestmark = pytest.mark.offline


def _seal(tmp_path, rows=()):
    run = store.Run.create(tmp_path / "project", "example.com")
    for entity, record in rows:
        run.add(entity, record)
    run.write_state("running")
    run.write_state("finalizing")
    run.write_manifest({}, ["fixture"], metrics=None, policy=None)
    run.write_state("finished")
    return run


def _late_revision(run):
    sink = revision.ingest(run, "report.fixture")
    assert sink.add("url", {"url": "https://late.example.com/", "sources": ["fixture"]})
    published = sink.commit()
    assert published is not None and published.status == "valid"
    return published


def _replace_segment_and_reseal(run, body: bytes) -> dict:
    document = json.loads(revision.pointer_path(run.dir).read_text())
    segment = document["supplement"]["segments"][0]
    path = revision._segment_path(run.dir, segment["file"])
    path.write_bytes(body)
    segment.update({
        "bytes": len(body), "lines": len(body.splitlines()), "digest": revision._sha(body),
    })
    document["supplement"]["lines"] = sum(
        item["lines"] for item in document["supplement"]["segments"]
    )
    document["supplement"]["digest"] = revision._chain_digest(
        document["supplement"]["segments"],
    )
    document["digest"] = revision._evidence_digest(
        base=document["base"]["manifest_digest"],
        supplement=document["supplement"]["digest"],
        counts=document["entity_counts"], entity_digests=document["entity_digests"],
        raw_files=document["raw_files"],
    )
    document["pointer_digest"] = revision._pointer_digest(document)
    revision.pointer_path(run.dir).write_bytes(revision._pointer_bytes(document))
    return document


def test_every_effective_entity_is_projected_exactly_once_and_deterministically(tmp_path):
    run = _seal(tmp_path, [
        ("subdomain", {"host": "A.example.com", "sources": ["fixture"]}),
        ("url", {"url": "https://a.example.com/?token=target-secret", "sources": ["fixture"]}),
        ("secret", {"id": "s1", "value": "target-secret", "sources": ["fixture"]}),
    ])

    first = report_truth.build_private_report(run)
    second = report_truth.build_private_report(store.Run.open(run.project_dir, run.target, run.run_id))

    assert report_truth.canonical_json_bytes(first) == report_truth.canonical_json_bytes(second)
    assert first["counts"]["input"] == first["counts"]["included"] == 3
    assert first["counts"]["omitted"] == 0
    assert {row["entity"] for row in first["observations"]} == {"subdomain", "url", "secret"}
    assert len({row["observation_id"] for row in first["observations"]}) == 3
    assert any(row["record"].get("value") == "target-secret" for row in first["observations"])
    assert any("token=target-secret" in row["record"].get("url", "") for row in first["observations"])


def test_rich_24068_row_projection_has_full_coverage_and_repeat_digest(tmp_path):
    """Mirror the audited rich-report cardinality without importing private source bytes."""
    run = store.Run.create(tmp_path / "project", "rich.example")
    rows = [
        json.dumps(
            {
                "id": f"review-{index:05d}",
                "klass": "synthetic-rich",
                "value": f"https://rich.example/evidence/{index}?target=exact-{index}",
                "sources": ["synthetic-rich"],
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        for index in range(24_068)
    ]
    privfs.write_private(run.normalized / "review.jsonl", "\n".join(rows) + "\n")
    run.write_state("running")
    run.write_state("finalizing")
    run.write_manifest({}, ["synthetic-rich"], metrics=None, policy=None)
    run.write_state("finished")

    first = report_truth.canonical_json_bytes(report_truth.build_private_report(run))
    second = report_truth.canonical_json_bytes(report_truth.build_private_report(run))
    parsed = report_truth.read_private_report(first)
    assert first == second
    assert parsed["counts"]["input"] == parsed["counts"]["included"] == 24_068
    assert parsed["counts"]["omitted"] == 0
    assert parsed["counts"]["by_entity"]["review"] == 24_068
    assert len({row["observation_id"] for row in parsed["observations"]}) == 24_068


def test_absolute_in_run_raw_reference_is_canonicalized_and_attested(tmp_path):
    run = store.Run.create(tmp_path / "project", "example.com")
    raw = run._replace_artifact(
        store.MutationScope.BASE_EVIDENCE, ("raw", "fixture", "finding.json"), b"proof\n",
    )
    run.add("finding", {
        "id": "finding-1", "template": "fixture", "matched": "https://example.com/",
        "severity": "high", "sources": ["fixture"], "raw_ref": str(raw),
    })
    run.write_state("running")
    run.write_state("finalizing")
    run.write_manifest({}, ["fixture"], metrics=None, policy=None)
    run.write_state("finished")

    report = report_truth.build_private_report(run)
    [finding] = [row for row in report["observations"] if row["entity"] == "finding"]
    assert finding["source_ref"] == "normalized/finding.jsonl"
    assert finding["source_refs"] == ["normalized/finding.jsonl"]
    assert finding["record_refs"] == ["raw/fixture/finding.json"]
    assert finding["record"]["raw_ref"] == "raw/fixture/finding.json"
    assert [ref["path"] for ref in finding["artifact_refs"]] == [
        "normalized/finding.jsonl", "raw/fixture/finding.json",
    ]


def test_finding_without_attested_raw_proof_fails_closed(tmp_path):
    run = _seal(tmp_path, [("finding", {
        "id": "finding-1", "template": "fixture", "matched": "https://example.com/",
        "severity": "high", "sources": ["fixture"],
    })])
    with pytest.raises(report_truth.ReportTruthError, match="no attested raw proof"):
        report_truth.build_private_report(run)


@pytest.mark.parametrize("bad", [
    "../outside", "/etc/passwd", "raw/../outside", "raw\\outside", "raw//outside",
    " raw/fixture.json", "raw/fixture.json ",
])
def test_unsafe_or_unattested_provenance_fails_closed(tmp_path, bad):
    run = _seal(tmp_path, [("url", {"url": "https://example.com/", "raw_ref": bad})])
    with pytest.raises(report_truth.ReportTruthError, match="reference"):
        report_truth.build_private_report(run)


def test_nested_provenance_is_bound_and_cannot_be_silently_dropped(tmp_path):
    run = store.Run.create(tmp_path / "project", "example.com")
    raw = run._replace_artifact(
        store.MutationScope.BASE_EVIDENCE, ("raw", "fixture", "nested.json"), b"{}\n",
    )
    run.add("review", {
        "id": "nested", "klass": "fixture", "value": "x",
        "occurrences": [{"file": "bundle.js", "line": 7, "raw_ref": str(raw)}],
    })
    run.write_state("running")
    run.write_state("finalizing")
    run.write_manifest({}, ["fixture"], metrics=None, policy=None)
    run.write_state("finished")
    report = report_truth.build_private_report(run)
    [row] = [item for item in report["observations"] if item["entity"] == "review"]
    assert any(ref["path"] == "raw/fixture/nested.json" for ref in row["artifact_refs"])


def test_opaque_provider_payload_cannot_invent_a_filesystem_reference(tmp_path):
    run = _seal(tmp_path, [("review", {
        "id": "opaque", "klass": "fixture", "value": "x",
        "provider_record": {
            "raw_ref": "../../target-controlled", "request": {"raw_ref": "/etc/passwd"},
        },
    })])
    report = report_truth.build_private_report(run)
    [row] = [item for item in report["observations"] if item["entity"] == "review"]
    assert row["record"]["provider_record"]["raw_ref"] == "../../target-controlled"
    assert [item["path"] for item in row["artifact_refs"]] == ["normalized/review.jsonl"]


def test_reader_rejects_noncanonical_or_forged_reconciliation(tmp_path):
    report = report_truth.build_private_report(_seal(tmp_path, [("subdomain", {"host": "a.example.com"})]))
    body = report_truth.canonical_json_bytes(report)
    assert report_truth.read_private_report(body) == report
    with pytest.raises(report_truth.ReportTruthError, match="canonical"):
        report_truth.read_private_report(json.dumps(report).encode() + b"\n")
    forged = copy.deepcopy(report)
    forged["counts"]["input"] += 1
    with pytest.raises(report_truth.ReportTruthError, match="reconcile"):
        report_truth.verify_private_report(forged)
    forged = copy.deepcopy(report)
    forged["observations"][0]["record"]["host"] = "b.example.com"
    with pytest.raises(report_truth.ReportTruthError, match="key"):
        report_truth.verify_private_report(forged)


def test_reader_cannot_drop_or_substitute_a_record_provenance_edge(tmp_path):
    run = store.Run.create(tmp_path / "project", "example.com")
    raw = run._replace_artifact(
        store.MutationScope.BASE_EVIDENCE, ("raw", "fixture", "proof.json"), b"{}\n",
    )
    run.add("review", {"id": "proof", "value": "x", "raw_ref": str(raw)})
    run.write_state("running")
    run.write_state("finalizing")
    run.write_manifest({}, ["fixture"], metrics=None, policy=None)
    run.write_state("finished")
    report = report_truth.build_private_report(run)
    [row] = [item for item in report["observations"] if item["entity"] == "review"]

    forged = copy.deepcopy(report)
    forged_row = next(item for item in forged["observations"] if item["entity"] == "review")
    forged_row["record_refs"] = []
    forged_row["artifact_refs"] = [
        ref for ref in forged_row["artifact_refs"]
        if ref["path"] == forged_row["source_ref"]
    ]
    with pytest.raises(report_truth.ReportTruthError, match="artifact paths"):
        report_truth.verify_private_report(forged)

    assert row["record_refs"] == ["raw/fixture/proof.json"]


@pytest.mark.parametrize("field,value", [
    ("digest", "sha256:" + "0" * 64),
    ("bytes", 999),
    ("rows", 999),
    ("media_type", "application/json"),
])
def test_one_artifact_path_has_one_descriptor_across_all_observations(tmp_path, field, value):
    report = report_truth.build_private_report(_seal(tmp_path, [
        ("subdomain", {"host": "a.example.com"}),
        ("subdomain", {"host": "b.example.com"}),
    ]))
    forged = copy.deepcopy(report)
    second = forged["observations"][1]
    assert second["artifact_refs"][0]["path"] == "normalized/subdomain.jsonl"
    second["artifact_refs"][0][field] = value

    with pytest.raises(report_truth.ReportTruthError, match="conflicting descriptors"):
        report_truth.verify_private_report(forged)
    with pytest.raises(report_truth.ReportTruthError, match="conflicting descriptors"):
        report_truth.read_private_report(report_truth.canonical_json_bytes(forged))


def test_base_source_roster_cannot_be_replaced_by_an_arbitrary_artifact(tmp_path):
    report = report_truth.build_private_report(
        _seal(tmp_path, [("subdomain", {"host": "a.example.com"})]),
    )
    forged = copy.deepcopy(report)
    row = forged["observations"][0]
    row["source_ref"] = "raw/forged-source.bin"
    row["source_refs"] = ["raw/forged-source.bin"]
    row["artifact_refs"][0]["path"] = "raw/forged-source.bin"
    row["artifact_refs"][0]["media_type"] = "application/octet-stream"
    row["artifact_refs"][0]["rows"] = None

    with pytest.raises(report_truth.ReportTruthError, match="artifact paths"):
        report_truth.verify_private_report(forged)


def test_projection_consumes_the_manifest_authenticated_row_snapshot(tmp_path, monkeypatch):
    run = _seal(tmp_path, [("review", {"id": "same", "klass": "fixture", "value": "ORIGINAL"})])

    # The old projector reopened the entity through Run.read after the strict
    # manifest pass.  A swap/restore confined to that reopen projected FORGED
    # while retaining ORIGINAL's artifact digest.
    monkeypatch.setattr(
        store.Run, "open",
        classmethod(lambda *_a, **_k: pytest.fail("private report reopened authenticated base rows")),
    )
    report = report_truth.build_private_report(run)
    [row] = [item for item in report["observations"] if item["entity"] == "review"]
    assert row["record"]["value"] == "ORIGINAL"


@pytest.mark.parametrize("replacement", ["symlink", "hardlink", "regular", "torn"])
def test_base_private_report_presence_requires_exact_private_current_bytes(tmp_path, replacement):
    run = _seal(tmp_path, [("subdomain", {"host": "a.example.com"})])
    path = run.reports / "private-report.json"
    privfs.write_private(
        path,
        report_truth.canonical_json_bytes(report_truth.build_private_report(run)).decode(),
    )
    assert report_truth.published_private_report_current(run)

    path.unlink()
    attacker = run.reports / "attacker.json"
    if replacement == "symlink":
        privfs.write_private(attacker, "not a report\n")
        path.symlink_to(attacker.name)
    elif replacement == "hardlink":
        privfs.write_private(attacker, "not a report\n")
        path.hardlink_to(attacker)
    elif replacement == "regular":
        privfs.write_private(path, "not a report\n")
    else:
        privfs.write_private(path, '{"schema_version":"quarry.private-report.v2"')

    assert not report_truth.published_private_report_current(run)


def test_reader_rejects_source_and_record_reference_aliasing(tmp_path):
    run = store.Run.create(tmp_path / "project", "example.com")
    raw = run._replace_artifact(
        store.MutationScope.BASE_EVIDENCE, ("raw", "fixture", "proof.json"), b"{}\n",
    )
    run.add("review", {"id": "proof", "value": "x", "raw_ref": str(raw)})
    run.write_state("running")
    run.write_state("finalizing")
    run.write_manifest({}, ["fixture"], metrics=None, policy=None)
    run.write_state("finished")
    report = report_truth.build_private_report(run)
    row = next(item for item in report["observations"] if item["entity"] == "review")
    row["record_refs"] = [row["source_ref"], *row["record_refs"]]

    with pytest.raises(report_truth.ReportTruthError, match="artifact paths"):
        report_truth.verify_private_report(report)


def test_private_report_schema_accepts_the_exact_runtime_document(tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (Path(__file__).parents[1] / "release" / "evidence" / "schemas"
         / "private-report-v2.schema.json").read_text(),
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    document = report_truth.build_private_report(
        _seal(tmp_path, [("subdomain", {"host": "a.example.com"})]),
    )
    jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker(),
    ).validate(document)
    forged = copy.deepcopy(document)
    forged["source_view"]["revision"] = 1
    forged["source_view"]["revision_digest"] = "sha256:" + "0" * 64
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(
            schema, format_checker=jsonschema.FormatChecker(),
        ).validate(forged)
    with pytest.raises(report_truth.ReportTruthError, match="base private report"):
        report_truth.verify_private_report(forged)
    forged = copy.deepcopy(document)
    forged["observations"][0]["source_ref"] = "raw/forged-source.bin"
    forged["observations"][0]["source_refs"] = ["raw/forged-source.bin"]
    assert not jsonschema.Draft202012Validator(schema).is_valid(forged)


def test_private_report_byte_envelope_refuses_instead_of_truncating(tmp_path, monkeypatch):
    run = _seal(tmp_path, [("subdomain", {"host": "a.example.com"})])
    document = report_truth.build_private_report(run)
    body = report_truth.canonical_json_bytes(document)
    monkeypatch.setattr(report_truth, "MAX_PRIVATE_REPORT_BYTES", len(body) - 1)
    with pytest.raises(report_truth.ReportTruthError, match="support envelope"):
        report_truth.read_private_report(body)
    with pytest.raises(report_truth.ReportTruthError, match="support envelope"):
        report_truth.build_private_report(run)


def test_legacy_lifecycle_appearance_during_projection_fails_closed(tmp_path, monkeypatch):
    run = _seal(tmp_path, [("subdomain", {"host": "a.example.com"})])
    run.state_path.unlink()
    original = report_truth.run_manifest.read
    calls = 0

    def racing_read(*args, **kwargs):
        nonlocal calls
        result = original(*args, **kwargs)
        calls += 1
        if calls == 1:
            run.state_path.write_text("{}\n")
        return result

    monkeypatch.setattr(report_truth.run_manifest, "read", racing_read)
    with pytest.raises(report_truth.ReportTruthError, match="lifecycle appeared"):
        report_truth.build_private_report(run)


def test_revision_projection_uses_the_certified_combined_view(tmp_path):
    run = _seal(tmp_path, [("subdomain", {"host": "base.example.com"})])
    sink = revision.ingest(run, "report.fixture")
    assert sink.add("url", {"url": "https://late.example.com/"})
    published = sink.commit()
    assert published is not None and published.status == "valid"
    assert "private-report.json" in published.views["files"]

    report = report_truth.build_private_report(run)
    assert report["source_view"]["kind"] == "revision"
    assert report["source_view"]["revision"] == 1
    assert report["counts"]["input"] == 2
    late = next(row for row in report["observations"] if row["entity"] == "url")
    assert late["source_ref"] == "revisions/rev0001/observations.jsonl"
    stored = (run.dir / "revisions" / published.views["dir"] / "private-report.json").read_bytes()
    assert report_truth.read_private_report(stored, expected=report) == report


def test_merged_revision_observation_binds_base_and_every_segment(tmp_path):
    run = _seal(tmp_path, [("subdomain", {"host": "merge.example.com", "sources": ["base"]})])
    first = revision.ingest(run, "report.one")
    assert not first.add("subdomain", {"host": "merge.example.com", "sources": ["one"]})
    assert first.commit().status == "valid"
    second = revision.ingest(run, "report.two")
    assert not second.add("subdomain", {"host": "merge.example.com", "sources": ["two"]})
    assert second.commit().status == "valid"

    report = report_truth.build_private_report(run)
    [row] = [item for item in report["observations"] if item["entity"] == "subdomain"]
    assert row["record"]["sources"] == ["base", "one", "two"]
    assert [item["path"] for item in row["artifact_refs"]] == [
        "normalized/subdomain.jsonl",
        "revisions/rev0001/observations.jsonl",
        "revisions/rev0002/observations.jsonl",
    ]


@pytest.mark.parametrize("damage", ["mode", "hardlink"])
def test_revision_segment_must_remain_owner_private_and_single_link(tmp_path, damage):
    run = _seal(tmp_path, [("subdomain", {"host": "base.example.com"})])
    sink = revision.ingest(run, "report.segment-authority")
    assert sink.add("url", {"url": "https://late.example.com/"})
    published = sink.commit()
    segment = run.dir / "revisions" / published.segments[0]["file"]

    if damage == "mode":
        segment.chmod(0o644)
    else:
        os.link(segment, tmp_path / "external-segment-link")

    reopened = revision.read(run.dir)
    assert reopened.status == "unusable"
    with pytest.raises(report_truth.ReportTruthError, match="unusable revision"):
        report_truth.build_private_report(run)


def test_revision_reader_pins_each_ancestor_against_pathname_swap(tmp_path, monkeypatch):
    root = privfs.private_dir(tmp_path / "root")
    managed = privfs.private_dir(root / "rev0001")
    outside = privfs.private_dir(tmp_path / "outside")
    privfs.write_private(managed / "observations.jsonl", "INSIDE\n")
    privfs.write_private(outside / "observations.jsonl", "OUTSIDE\n")
    held = root / "held"
    original_open = revision.os.open
    raced = False

    def swapping_open(name, flags, *args, **kwargs):
        nonlocal raced
        if name == "observations.jsonl" and kwargs.get("dir_fd") is not None and not raced:
            raced = True
            managed.rename(held)
            managed.symlink_to(outside, target_is_directory=True)
            try:
                return original_open(name, flags, *args, **kwargs)
            finally:
                managed.unlink()
                held.rename(managed)
        return original_open(name, flags, *args, **kwargs)

    monkeypatch.setattr(revision.os, "open", swapping_open)
    assert revision._read_regular(
        managed / "observations.jsonl", root=root, maximum=1024,
    ) == b"INSIDE\n"
    assert raced and not managed.is_symlink()


def test_revision_reader_relinquishes_every_descriptor_on_repeated_failure(tmp_path):
    root = privfs.private_dir(tmp_path / "root")
    before = len(os.listdir("/proc/self/fd"))
    for _index in range(64):
        with pytest.raises(OSError):
            revision._read_regular(root / "absent.json", root=root, maximum=1024)
    assert len(os.listdir("/proc/self/fd")) == before


def test_revision_pointer_and_segments_require_canonical_delimiters(tmp_path):
    run = _seal(tmp_path)
    _late_revision(run)
    pointer = revision.pointer_path(run.dir)
    pointer.write_bytes(pointer.read_bytes()[:-1])
    assert revision.read(run.dir).status == "unusable"

    run = _seal(tmp_path / "segment")
    published = _late_revision(run)
    segment = revision._segment_path(run.dir, published.segments[0]["file"])
    _replace_segment_and_reseal(run, segment.read_bytes()[:-1])
    broken = revision.read(run.dir)
    assert broken.status == "unusable" and "not the one" in broken.reason


@pytest.mark.parametrize("poison", [
    b'{"schema_version":2,"schema_version":2}\n',
    b'{"schema_version":NaN}\n',
    b'{"schema_version":9223372036854775808}\n',
])
def test_revision_pointer_refuses_nonportable_json_before_semantic_use(tmp_path, poison):
    run = _seal(tmp_path)
    privfs.private_dir(revision.revisions_dir(run.dir))
    privfs.write_private(revision.pointer_path(run.dir), poison.decode("ascii"))
    broken = revision.read(run.dir)
    assert broken.status == "unusable" and "pointer is unreadable" in broken.reason


@pytest.mark.parametrize("member", ["duplicate", "nan", "integer"])
def test_revision_segment_refuses_nonportable_complete_rows(tmp_path, member):
    run = _seal(tmp_path)
    published = _late_revision(run)
    segment = revision._segment_path(run.dir, published.segments[0]["file"])
    row = json.loads(segment.read_text().splitlines()[0])
    if member == "duplicate":
        body = json.dumps(row).replace('"seq": 1', '"seq": 1, "seq": 1').encode() + b"\n"
    else:
        row["record"]["poison"] = float("nan") if member == "nan" else 1 << 63
        body = json.dumps(row).encode() + b"\n"
    _replace_segment_and_reseal(run, body)
    broken = revision.read(run.dir)
    assert broken.status == "unusable" and "unusable supplement row" in broken.reason


def test_revision_size_claims_refuse_before_file_allocation(tmp_path, monkeypatch):
    run = _seal(tmp_path)
    _late_revision(run)
    document = json.loads(revision.pointer_path(run.dir).read_text())
    document["supplement"]["segments"][0]["bytes"] = revision.MAX_REVISION_SEGMENT_BYTES + 1

    def forbidden(*_args, **_kwargs):
        raise AssertionError("oversized segment was opened")

    monkeypatch.setattr(revision, "_read_regular", forbidden)
    broken = revision._certify_document(run.dir, document)
    assert broken.status == "unusable" and "claim is malformed" in broken.reason


def test_revision_sparse_oversized_pointer_is_rejected_before_read(tmp_path, monkeypatch):
    run = _seal(tmp_path)
    privfs.private_dir(revision.revisions_dir(run.dir))
    pointer = revision.pointer_path(run.dir)
    privfs.write_private(pointer, "{}\n")
    with pointer.open("r+b") as handle:
        handle.truncate(revision.MAX_REVISION_POINTER_BYTES + 1)

    called = False
    original = revision.os.read

    def observed_read(*args, **kwargs):
        nonlocal called
        called = True
        return original(*args, **kwargs)

    monkeypatch.setattr(revision.os, "read", observed_read)
    assert revision.read(run.dir).status == "unusable"
    assert called is False


def test_revision_created_timestamp_is_valid_before_the_view_can_certify(tmp_path):
    run = _seal(tmp_path)
    _late_revision(run)
    document = json.loads(revision.pointer_path(run.dir).read_text())
    document["created"] = "not-a-time"
    document["pointer_digest"] = revision._pointer_digest(document)
    revision.pointer_path(run.dir).write_bytes(revision._pointer_bytes(document))
    broken = revision.read(run.dir)
    assert broken.status == "unusable" and "timestamp" in broken.reason


def test_private_report_rechecks_the_complete_revision_pointer_identity(tmp_path, monkeypatch):
    run = _seal(tmp_path)
    _late_revision(run)
    original = revision.read
    calls = 0

    def racing(run_dir):
        nonlocal calls
        observed = original(run_dir)
        calls += 1
        if calls > 1:
            observed = copy.deepcopy(observed)
            observed.created = "2026-08-15T00:00:00Z"
            observed.pointer_digest = "0" * 64
        return observed

    monkeypatch.setattr(revision, "read", racing)
    with pytest.raises(report_truth.ReportTruthError, match="revision changed"):
        report_truth.build_private_report(run)


def test_private_report_rejects_noncanonical_revision_source_aliases(tmp_path):
    run = _seal(tmp_path)
    _late_revision(run)
    document = report_truth.build_private_report(run)
    row = next(item for item in document["observations"] if item["entity"] == "url")
    canonical = "revisions/rev0001/observations.jsonl"
    alias = "revisions/rev00001/observations.jsonl"
    row["source_ref"] = alias
    row["source_refs"] = [alias if ref == canonical else ref for ref in row["source_refs"]]
    for artifact in row["artifact_refs"]:
        if artifact["path"] == canonical:
            artifact["path"] = alias
    with pytest.raises(report_truth.ReportTruthError, match="reconcile"):
        report_truth.verify_private_report(document)


def test_revision_root_inventory_is_bounded_and_never_follows_aliases(tmp_path, monkeypatch):
    run = _seal(tmp_path)
    _late_revision(run)
    (revision.revisions_dir(run.dir) / "rev9999").symlink_to(tmp_path, target_is_directory=True)
    monkeypatch.setattr(revision, "MAX_REVISION_ROOT_ENTRIES", 1)
    broken = revision.read(run.dir)
    assert broken.status == "unusable" and "object-count bound" in broken.reason


def test_late_growth_refusal_persists_until_the_exact_material_is_admitted(tmp_path, monkeypatch):
    run = _seal(tmp_path, [("review", {"id": "same", "value": "A" * 80})])
    now = "2026-08-15T12:00:00Z"
    monkeypatch.setattr(store, "_utc", lambda: now)
    incoming = {"id": "same", "value": "B" * 80, "first_seen": now, "last_seen": now}
    base = run.read("review")[0]
    candidate_size = store._record_bytes(store.merge("review", base, incoming))
    assert max(store._record_bytes(base), store._record_bytes(incoming)) < candidate_size
    monkeypatch.setattr(revision.envelope, "MAX_BYTES_PER_KEY", candidate_size - 1)

    sink = revision.ingest(run, "report.growth")
    assert sink.add("review", {"id": "same", "value": "B" * 80}) is False
    sink.commit()
    held = revision.refusals(run.dir)
    assert len(held) == 1 and held[0]["kind"] == "growth" and held[0]["fp"]

    monkeypatch.setattr(revision.envelope, "MAX_BYTES_PER_KEY", candidate_size + 1024)
    retry = revision.ingest(run, "report.growth")
    assert retry.add("review", {"id": "same", "value": "B" * 80}) is False
    retry.commit()
    assert revision.refusals(run.dir) == []


def test_late_new_key_cannot_cross_the_declared_corpus_byte_envelope(tmp_path, monkeypatch):
    run = _seal(tmp_path, [("review", {"id": "base", "value": "A" * 40})])
    now = "2026-08-15T12:00:00Z"
    monkeypatch.setattr(store, "_utc", lambda: now)
    incoming = {"id": "new", "value": "B" * 40, "first_seen": now, "last_seen": now}
    base_bytes = sum(store._record_bytes(row) for row in run.read("review"))
    monkeypatch.setattr(
        revision.envelope, "MAX_CORPUS_BYTES_PER_ENTITY",
        base_bytes + store._record_bytes(incoming) - 1,
    )
    sink = revision.ingest(run, "report.corpus")
    assert sink.add("review", {"id": "new", "value": "B" * 40}) is False
    sink.commit()
    assert revision.refusals(run.dir)[0]["kind"] == "corpus"


def test_revision_certification_refuses_a_symlinked_base_manifest_even_with_identical_bytes(tmp_path):
    run = _seal(tmp_path, [("subdomain", {"host": "base.example.com"})])
    sink = revision.ingest(run, "report.manifest-authority")
    assert sink.add("url", {"url": "https://late.example.com/"})
    assert sink.commit().status == "valid"

    manifest = run.dir / "manifest.json"
    outside = tmp_path / "manifest-copy.json"
    outside.write_bytes(manifest.read_bytes())
    manifest.unlink()
    manifest.symlink_to(outside)

    reopened = revision.read(run.dir)
    assert reopened.status == "unusable"
    assert revision.combined_view(run, reopened) is None


def test_rebuild_detects_any_authoritative_difference(tmp_path):
    run = _seal(tmp_path, [("subdomain", {"host": "a.example.com"})])
    expected = report_truth.build_private_report(run)
    forged = copy.deepcopy(expected)
    forged["target"] = "other.example"
    with pytest.raises(report_truth.ReportTruthError, match="authoritative rebuilt"):
        report_truth.verify_private_report(forged, expected=expected)


@pytest.mark.parametrize("mutate,reason", [
    (lambda d: d["source_view"].__setitem__("manifest_digest", "sha256:" + "A" * 64),
     "canonical SHA-256"),
    (lambda d: d["source_view"].__setitem__("generated_at", "2026-01-01 00:00:00+00:00"),
     "RFC3339"),
    (lambda d: d["counts"].__setitem__("input", True), "portable count"),
    (lambda d: d["observations"][0].__setitem__("key", " "), "identity"),
    (lambda d: d["observations"][0]["artifact_refs"][0].__setitem__("path", "../escape"),
     "artifact path"),
    (lambda d: d["observations"][0]["artifact_refs"][0].__setitem__("path", "raw/line\nfeed"),
     "artifact path"),
    (lambda d: d["observations"][0]["artifact_refs"][0].__setitem__("media_type", "text/plain"),
     "descriptor"),
])
def test_structural_contract_rejects_schema_runtime_boundary_forgeries(tmp_path, mutate, reason):
    report = report_truth.build_private_report(
        _seal(tmp_path, [("subdomain", {"host": "a.example.com"})]),
    )
    forged = copy.deepcopy(report)
    mutate(forged)
    with pytest.raises(report_truth.ReportTruthError, match=reason):
        report_truth.verify_private_report(forged)
