"""V310-04: a campaign terminal is the semantic fold of its complete child history."""
from __future__ import annotations

import json
import os

import pytest

from quarry_recon import campaign, remainder
from quarry_recon.state import Coverage


pytestmark = pytest.mark.offline
LANE = "enrich.a1d_brute"


def _rem(*, now=0, terminal=None):
    return remainder.Remainder(
        lane=LANE, unit=f"{LANE}:targets", measure="targets", model="project_progress",
        now=now, terminal=dict(terminal or {}),
    ).as_record()


def _summary(*, remainders=(), gaps=(), coverage=(), faults=(), verdict=None):
    gaps = list(gaps)
    return {
        "verdict": verdict or ("complete_with_gaps" if gaps else "complete"),
        "remainders": list(remainders), "gaps": gaps, "coverage": list(coverage),
        "faults": list(faults), "provider_spend": [],
    }


def _gap(*, source="probe.httpx", measure="hosts"):
    return {"phase": "probe", "tool": source, "kind": "timeout", "status": "coverage:timeout",
            "measure": measure, "why": "timed out", "eligible": 50, "omitted": 40,
            "output_lines": 10}


def _covered(*, source="probe.httpx", measure="hosts"):
    return Coverage(source_id=source, measure=measure, eligible=50, tested=50, omitted=0).to_dict()


def _absorbed(*, new=0, unusable=None):
    result = campaign.AbsorbResult(new=new, unusable=dict(unusable or {}))
    result.absorbed = True
    return result


def _decide(book, summary, *, child, previous=None, idle=0, new=0, max_children=10):
    return campaign.decide(
        summary, _absorbed(new=new), settlement=book, children=child,
        previous_retriable=previous, idle_children=idle, max_children=max_children,
    )


def _manifest(ledger, decision, summary, *, run_id, new=0):
    union = campaign.Union(ledger.dir / "union.json", create=True)
    if union.status == "new":
        union.save()
    child = ledger.reserve()
    ledger.started(child, run_id)
    ledger.manifested(child, summary=summary, absorbed=_absorbed(new=new), decision=decision)
    return child


def test_a_later_silent_child_cannot_launder_an_earlier_gap():
    book = campaign.Settlement()
    first = _decide(book, _summary(remainders=[_rem(now=1)], gaps=[_gap()]), child=1, new=1)
    second = _decide(book, _summary(remainders=[_rem()]), child=2,
                     previous=first.retriable)
    final = _decide(book, _summary(remainders=[_rem()]), child=3,
                    previous=second.retriable)

    assert first.stop is None and second.progressed
    assert final.stop == "fixed_point_with_gaps" and not final.success
    assert [(gap["source_id"], gap["first_child"]) for gap in final.open_gaps] == [
        ("probe.httpx", 1)]
    assert second.resolved_gaps == [], "absence is not resolution evidence"


def test_optional_gap_identity_fields_have_a_total_canonical_order():
    book = campaign.Settlement()
    summary = _summary(gaps=[_gap(), _gap(measure=None)])
    decision = _decide(book, summary, child=1)
    assert decision.stop == "fixed_point_with_gaps"
    assert [gap["measure"] for gap in decision.open_gaps] == [None, "hosts"]


def test_only_matching_positive_coverage_resolves_the_historical_gap():
    book = campaign.Settlement()
    first = _decide(book, _summary(remainders=[_rem(now=1)], gaps=[_gap()]), child=1, new=1)
    second = _decide(book, _summary(remainders=[_rem()], coverage=[_covered()]), child=2,
                     previous=first.retriable)
    final = _decide(book, _summary(remainders=[_rem()]), child=3,
                    previous=second.retriable)

    assert [gap["source_id"] for gap in second.resolved_gaps] == ["probe.httpx"]
    assert second.open_gaps == []
    assert (final.stop, final.success) == ("fixed_point", True)


@pytest.mark.parametrize("proof", [
    _covered(source="probe.other"),
    _covered(measure="urls"),
    Coverage(source_id="probe.httpx", measure="hosts", eligible=50, tested=10,
             omitted=40).to_dict(),
], ids=["wrong-source", "wrong-measure", "incomplete-coverage"])
def test_mismatched_or_incomplete_coverage_cannot_resolve_a_gap(proof):
    book = campaign.Settlement()
    first = _decide(book, _summary(remainders=[_rem(now=1)], gaps=[_gap()]), child=1, new=1)
    second = _decide(book, _summary(remainders=[_rem()], coverage=[proof]), child=2,
                     previous=first.retriable)
    final = _decide(book, _summary(remainders=[_rem()]), child=3,
                    previous=second.retriable)
    assert second.resolved_gaps == []
    assert final.stop == "fixed_point_with_gaps"


def test_matching_obligation_evidence_can_resolve_an_unmeasured_remainder_gap():
    book = campaign.Settlement()
    invalid = {"lane": LANE, "unit": f"{LANE}:targets", "invalid": "unmeasured"}
    gap = {"phase": "enrich", "tool": LANE, "kind": "unknown", "status": "remainder:unknown",
           "why": "unmeasured", "output_lines": 0}
    first = _decide(book, _summary(remainders=[invalid], gaps=[gap]), child=1)
    second = _decide(book, _summary(remainders=[_rem()]), child=2,
                     previous=first.retriable)
    assert [record["source_id"] for record in second.resolved_gaps] == [LANE]
    assert second.open_gaps == []


def test_gap_history_and_resolution_survive_reload(tmp_path):
    ledger = campaign.Campaign(tmp_path, "c-history")
    book = campaign.Settlement()
    summary1 = _summary(remainders=[_rem(now=1)], gaps=[_gap()])
    first = _decide(book, summary1, child=1, new=1)
    _manifest(ledger, first, summary1, run_id="run-1", new=1)

    reopened = campaign.Campaign(tmp_path, "c-history")
    assert reopened.status == "valid" and reopened.open_gaps == first.open_gaps
    restored = campaign.Settlement()
    restored.adopt(reopened.children[0]["obligations"],
                   open_gaps=reopened.children[0]["open_gaps"])
    summary2 = _summary(remainders=[_rem()], coverage=[_covered()])
    second = _decide(restored, summary2, child=2, previous=first.retriable)
    _manifest(reopened, second, summary2, run_id="run-2")

    again = campaign.Campaign(tmp_path, "c-history")
    assert again.status == "valid"
    assert again.children[1]["resolved_gaps"] == first.open_gaps
    assert again.open_gaps == []


def _finished(tmp_path, cid="c-finished", *, abandoned=False):
    ledger = campaign.Campaign(tmp_path, cid)
    if abandoned:
        lost = ledger.reserve()
        ledger.started(lost, "run-lost")
        ledger.abandoned(lost, "manifest was never committed", elapsed_s=1)
    book = campaign.Settlement()
    summary = _summary(remainders=[_rem()])
    decision = _decide(book, summary, child=len(ledger.children) + 1)
    _manifest(ledger, decision, summary, run_id="run-final")
    ledger.finish(decision)
    return ledger


@pytest.mark.parametrize("mutate,reason", [
    (lambda doc: doc["stop"].update(success=False), "success"),
    (lambda doc: doc["stop"].update(clean=False), "clean"),
    (lambda doc: doc["stop"].update(cause="terminal", success=False, clean=False), "terminal"),
    (lambda doc: doc["stop"].update(terminal={"entitlement": 1}), "non-terminal"),
    (lambda doc: doc.update(open_gaps=[{
        "source_id": "forged", "kind": "unknown", "measure": None, "unit": None,
        "eligible": None, "tested": None, "omitted": None, "reason": "forged",
        "first_child": 1, "last_child": 1,
    }]), "open gaps"),
], ids=["success", "clean", "terminal", "non-terminal", "open-gaps"])
def test_contradictory_terminal_documents_are_unusable(tmp_path, mutate, reason):
    ledger = _finished(tmp_path)
    document = json.loads(ledger.path.read_text())
    mutate(document)
    ledger.path.write_text(json.dumps(document))
    reopened = campaign.Campaign(tmp_path, ledger.campaign_id)
    assert reopened.status == "unusable" and reason in reopened.reason


def test_a_forged_resolution_without_matching_evidence_is_unusable(tmp_path):
    ledger = campaign.Campaign(tmp_path, "c-forged-resolution")
    book = campaign.Settlement()
    first_summary = _summary(remainders=[_rem(now=1)], gaps=[_gap()])
    first = _decide(book, first_summary, child=1, new=1)
    _manifest(ledger, first, first_summary, run_id="run-1", new=1)
    second_summary = _summary(remainders=[_rem()])
    second = _decide(book, second_summary, child=2, previous=first.retriable)
    _manifest(ledger, second, second_summary, run_id="run-2")

    document = json.loads(ledger.path.read_text())
    document["children"][1]["resolved_gaps"] = document["children"][1]["open_gaps"]
    document["children"][1]["open_gaps"] = []
    document["open_gaps"] = []
    ledger.path.write_text(json.dumps(document))
    reopened = campaign.Campaign(tmp_path, ledger.campaign_id)
    assert reopened.status == "unusable" and "no matching positive evidence" in reopened.reason


def test_persisted_spend_rows_must_keep_the_strict_run_summary_shape(tmp_path):
    ledger = _finished(tmp_path, "c-spend-shape")
    document = json.loads(ledger.path.read_text())
    document["children"][0]["provider_spend"] = [{"lane": LANE, "amount": 1}]
    ledger.path.write_text(json.dumps(document))
    reopened = campaign.Campaign(tmp_path, ledger.campaign_id)
    assert reopened.status == "unusable" and "provider_spend" in reopened.reason


def test_duplicate_coverage_proofs_are_not_a_second_resolution_fact(tmp_path):
    ledger = campaign.Campaign(tmp_path, "c-duplicate-proof")
    book = campaign.Settlement()
    summary = _summary(remainders=[_rem()], coverage=[_covered()])
    decision = _decide(book, summary, child=1)
    _manifest(ledger, decision, summary, run_id="run-covered")
    ledger.finish(decision)

    document = json.loads(ledger.path.read_text())
    document["children"][0]["coverage"] *= 2
    ledger.path.write_text(json.dumps(document))
    reopened = campaign.Campaign(tmp_path, ledger.campaign_id)
    assert reopened.status == "unusable" and "duplicate" in reopened.reason


def test_an_intentional_limit_does_not_redefine_fixed_point_cleanliness(tmp_path):
    ledger = campaign.Campaign(tmp_path, "c-intentional-limit")
    book = campaign.Settlement()
    summary = _summary(remainders=[_rem()], verdict="complete_with_limits")
    decision = _decide(book, summary, child=1)
    _manifest(ledger, decision, summary, run_id="run-limited")
    ledger.finish(decision)
    assert ledger.stop["success"] is True and ledger.stop["clean"] is True


def test_fixed_point_success_can_coexist_with_abandonment_but_is_not_clean(tmp_path):
    ledger = _finished(tmp_path, "c-abandoned", abandoned=True)
    assert ledger.stop["cause"] == "fixed_point" and ledger.stop["success"] is True
    assert ledger.stop["clean"] is False and ledger.truth.abandoned == 1
    reopened = campaign.Campaign(tmp_path, ledger.campaign_id)
    assert reopened.status == "valid" and reopened.truth.clean is False


def test_terminal_breakdown_must_equal_the_final_obligation_totals(tmp_path):
    ledger = campaign.Campaign(tmp_path, "c-terminal")
    book = campaign.Settlement()
    summary = _summary(remainders=[_rem(terminal={"entitlement": 2})])
    decision = _decide(book, summary, child=1)
    _manifest(ledger, decision, summary, run_id="run-terminal")
    ledger.finish(decision)
    assert ledger.stop["terminal"] == {"entitlement": 2}

    document = json.loads(ledger.path.read_text())
    document["stop"]["terminal"] = {"entitlement": 1}
    ledger.path.write_text(json.dumps(document))
    reopened = campaign.Campaign(tmp_path, ledger.campaign_id)
    assert reopened.status == "unusable" and "obligation totals" in reopened.reason


def test_a_manifested_child_cannot_erase_the_mandatory_obligation_roster(tmp_path):
    ledger = _finished(tmp_path, "c-roster-base")
    document = json.loads(ledger.path.read_text())
    assert document["children"][0]["obligations"]
    document["children"][0]["obligations"] = []
    ledger.path.write_text(json.dumps(document))

    reopened = campaign.Campaign(tmp_path, ledger.campaign_id)
    assert reopened.status == "unusable" and "omits required obligation" in reopened.reason


def test_a_later_child_cannot_erase_a_previously_named_obligation_unit(tmp_path):
    ledger = campaign.Campaign(tmp_path, "c-roster-history")
    book = campaign.Settlement()
    extra = remainder.Remainder(
        lane=LANE, unit=f"{LANE}:candidate_pairs", measure="candidate_pairs",
        model="project_progress", now=0,
    ).as_record()
    first_summary = _summary(remainders=[_rem(now=1), extra])
    first = _decide(book, first_summary, child=1, new=1)
    _manifest(ledger, first, first_summary, run_id="run-1", new=1)
    second_summary = _summary(remainders=[_rem(now=1), extra])
    second = _decide(book, second_summary, child=2, previous=first.retriable)
    _manifest(ledger, second, second_summary, run_id="run-2")

    document = json.loads(ledger.path.read_text())
    document["children"][1]["obligations"] = [
        record for record in document["children"][1]["obligations"]
        if record["unit"] != f"{LANE}:candidate_pairs"
    ]
    ledger.path.write_text(json.dumps(document))
    reopened = campaign.Campaign(tmp_path, ledger.campaign_id)
    assert reopened.status == "unusable" and "omits required obligation" in reopened.reason


def test_a_symlinked_campaign_directory_cannot_supply_or_receive_the_ledger(tmp_path):
    outside = tmp_path / "outside"
    external = campaign.Campaign(outside, "c-escaped")
    external.abandoned(external.reserve(), "outside fixture")
    before = external.path.read_bytes()

    victim = tmp_path / "victim"
    campaigns = victim / "recon" / "campaigns"
    campaigns.mkdir(parents=True)
    (campaigns / "c-escaped").symlink_to(external.dir, target_is_directory=True)
    escaped = campaign.Campaign(victim, "c-escaped")

    assert escaped.status == "unusable"
    with pytest.raises(campaign.UnionUnusable):
        escaped.reserve()
    assert external.path.read_bytes() == before


@pytest.mark.parametrize("damage", ["symlink", "hardlink", "mode", "fifo"])
def test_a_nonprivate_or_nonregular_ledger_is_never_campaign_authority(tmp_path, damage):
    ledger = campaign.Campaign(tmp_path, f"c-ledger-{damage}")
    ledger.abandoned(ledger.reserve(), "fixture")
    external = tmp_path / f"outside-{damage}.json"
    external.write_bytes(ledger.path.read_bytes())

    if damage == "symlink":
        ledger.path.unlink()
        ledger.path.symlink_to(external)
    elif damage == "hardlink":
        ledger.path.unlink()
        os.link(external, ledger.path)
    elif damage == "mode":
        ledger.path.chmod(0o644)
    else:
        ledger.path.unlink()
        os.mkfifo(ledger.path)

    assert campaign.Campaign(tmp_path, ledger.campaign_id).status == "unusable"


def test_a_ledger_changed_during_its_descriptor_read_is_unusable(tmp_path, monkeypatch):
    ledger = campaign.Campaign(tmp_path, "c-ledger-moving")
    ledger.abandoned(ledger.reserve(), "fixture")
    real_read = campaign.os.read
    state = {"changed": False}

    def read(fd, amount):
        chunk = real_read(fd, amount)
        if chunk and not state["changed"]:
            state["changed"] = True
            ledger.path.write_bytes(ledger.path.read_bytes() + b" ")
        return chunk

    monkeypatch.setattr(campaign.os, "read", read)
    reopened = campaign.Campaign(tmp_path, ledger.campaign_id)
    assert state["changed"] and reopened.status == "unusable"
    assert "changed while it was read" in reopened.reason


def test_union_recovery_is_a_permanent_campaign_cleanliness_debt(tmp_path):
    cid = "c-union-recovery"
    union = campaign.Union.for_campaign(tmp_path, cid, create=True)
    union.recover("audit evidence loss")
    ledger = _finished(tmp_path, cid)

    assert ledger.stop["recovered"] is True and ledger.stop["clean"] is False
    reopened = campaign.Campaign(tmp_path, cid)
    assert reopened.status == "valid" and reopened.truth.recovered and not reopened.truth.clean

    document = json.loads(ledger.path.read_text())
    document["stop"].update(recovered=False, clean=True)
    ledger.path.write_text(json.dumps(document))
    contradicted = campaign.Campaign(tmp_path, cid)
    assert contradicted.status == "unusable" and "union history" in contradicted.reason


def test_a_finished_campaign_cannot_read_clean_after_its_union_is_deleted(tmp_path):
    ledger = _finished(tmp_path, "c-union-deleted")
    assert campaign.Campaign(tmp_path, ledger.campaign_id).truth.clean is True
    for artifact in ledger.dir.glob("union*"):
        artifact.unlink()

    reopened = campaign.Campaign(tmp_path, ledger.campaign_id)
    assert reopened.status == "unusable"
    assert "union is unusable" in reopened.reason and "manifested child run" in reopened.reason


@pytest.mark.parametrize("artifact", ["pointer", "generation"])
def test_a_symlinked_union_artifact_cannot_certify_campaign_cleanliness(tmp_path, artifact):
    ledger = _finished(tmp_path, f"c-union-symlink-{artifact}")
    union = campaign.Union.for_campaign(tmp_path, ledger.campaign_id, create=False)
    assert union.status == "valid" and ledger.truth.clean is True
    selected = union.path if artifact == "pointer" else union.dir / campaign._generation_file(
        union.generation,
    )
    outside = tmp_path / f"outside-{artifact}"
    outside.write_bytes(selected.read_bytes())
    outside.chmod(0o600)
    selected.unlink()
    selected.symlink_to(outside)

    reopened = campaign.Campaign(tmp_path, ledger.campaign_id)
    assert reopened.status == "unusable"
    assert "unusable" in reopened.reason


@pytest.mark.parametrize("disposition", ["terminal", "remainder"])
def test_a_zero_count_obligation_cannot_claim_a_nonzero_disposition(tmp_path, disposition):
    ledger = _finished(tmp_path, f"c-obligation-{disposition}")
    document = json.loads(ledger.path.read_text())
    obligation = next(
        record for record in document["children"][0]["obligations"]
        if record["disposition"] == "known_zero"
    )
    obligation["disposition"] = disposition
    ledger.path.write_text(json.dumps(document))

    reopened = campaign.Campaign(tmp_path, ledger.campaign_id)
    assert reopened.status == "unusable"
    assert "lane-level disposition contradicts" in reopened.reason
