"""Step 0 typed-state contracts: model the shapes the store/records emit, enforce the declared invariants,
survive persistence exactly, and validate against one resolvable schema. Additive — no emitter changed."""
import pytest

from quarry_recon import events, state
from quarry_recon.remainder import Remainder

pytestmark = pytest.mark.offline


def _cov(source, measure, kinds: dict, **kw) -> state.Coverage:
    """A consistent Coverage from {kind: (eligible, tested, omitted)} — both by_kind and units, reconciled."""
    by_kind = {k: {"eligible": e, "tested": t, "omitted": o} for k, (e, t, o) in kinds.items()}
    units = [{"unit": k, "eligible": e, "tested": t, "omitted": o, "kind": k} for k, (e, t, o) in kinds.items()]
    tot = [sum(v[i] for v in kinds.values()) for i in range(3)]
    return state.Coverage(source, measure, eligible=tot[0], tested=tot[1], omitted=tot[2],
                          by_kind=by_kind, units=units, **kw)


# ── round-trip + serialized-shape validity ────────────────────────────────────────────────────────
def test_records_round_trip_and_validate_against_schema():
    samples = {
        "Fault": state.Fault("machinery", where="httpx", detail="boom"),
        "Coverage": _cov("probe.httpx", "hosts", {"cap": (10, 7, 3)}),
        "Gap": state.Gap("probe.httpx", kind="cap", measure="hosts", eligible=10, tested=7, omitted=3),
        "WorkUnit": state.WorkUnit("vertical.subfinder", inputs={"root": "x"}),
        "PolicyDecision": state.PolicyDecision("oos", subject="jobs.example.com", rule="^jobs\\."),
        "RunState": state.RunState("finalizing"),
    }
    for name, rec in samples.items():
        d = rec.to_dict()
        assert type(rec).from_dict(d) == rec
        state.validate_serialized(name, d)


# ── CommandResult persistence + bool/exit invariants ──────────────────────────────────────────────
def test_command_result_persistence_preserves_exit_code():
    for kw, code in [(dict(outcome="failed"), 5), (dict(interrupted=True), 130),
                     (dict(coverage="gapped"), 4), (dict(outcome="refused"), 6),
                     (dict(machinery_after_start=True), 5)]:
        cr = state.CommandResult("run", **kw)
        assert cr.exit_code == code
        back = state.CommandResult.from_dict(cr.to_dict())
        assert back == cr and back.exit_code == code
        state.validate_serialized("CommandResult", cr.to_dict())


def test_command_result_summary_cannot_contradict_its_records():
    with pytest.raises(state.ContractError):
        state.CommandResult("run", faults=[state.Fault("machinery")])          # challenging fault, completed
    with pytest.raises(state.ContractError):
        state.CommandResult("run", gaps=[state.Gap("s", kind="cap")])          # gaps, clean coverage
    state.CommandResult("run", faults=[state.Fault("optional_tool_failed")])   # non-challenging: may stay clean
    state.CommandResult("run", outcome="failed", coverage="gapped",            # a consistent failing result
                        faults=[state.Fault("machinery")], gaps=[state.Gap("s", kind="cap")])


def test_command_result_rejects_bad_input():
    cr = state.CommandResult("run", outcome="failed", coverage="gapped",
                             faults=[state.Fault("machinery")], gaps=[state.Gap("s", kind="cap")])
    assert isinstance(state.CommandResult.from_dict(cr.to_dict()).faults[0], state.Fault)
    for bad in ({**cr.to_dict(), "exit_code": 0},                      # tampered exit
                {**cr.to_dict(), "exit_code": False},                  # bool-as-int exit
                {"command": "run", "exit_code": 0, "schema_version": 999},   # future schema
                {"command": "run", "outcome": "completed", "coverage": "clean"}):  # no exit_code
        with pytest.raises(state.ContractError):
            state.CommandResult.from_dict(bad)
    with pytest.raises(state.ContractError):
        state.CommandResult("run", faults=[{"kind": "machinery"}])           # only Fault objects
    with pytest.raises(state.ContractError):                                  # nested non-bool causal flag
        state.CommandResult.from_dict({**cr.to_dict(),
                                       "faults": [{"kind": "machinery", "challenges_completeness": 1}]})
    with pytest.raises(state.ContractError):
        state.CommandResult("run", interrupted="false")                      # string flag can't flip exit
    with pytest.raises(state.ContractError):
        state.CommandResult("run", schema_version=999)                       # direct construction is gated
    with pytest.raises(state.ContractError):
        state.compute_exit("bogus", "clean")                                 # unknown outcome != clean 0
    with pytest.raises(state.ContractError):
        state.compute_exit("completed", "clean", interrupted="false")        # string flag must not flip exit


# ── Fault ──────────────────────────────────────────────────────────────────────────────────────
def test_fault_rules():
    assert state.Fault("machinery").challenges_completeness is True
    assert state.Fault("optional_tool_failed").challenges_completeness is False
    with pytest.raises(state.ContractError):
        state.Fault("bogus")
    with pytest.raises(state.ContractError):
        state.Fault("machinery", challenges_completeness=False)


# ── Coverage: reconcile headline + by_kind + units (two-sided or neither) ─────────────────────────
def test_coverage_parses_store_aggregate():
    assert _cov("vertical.subfinder", "apex", {"cap": (3, 2, 1)}).challenges_completeness()


def test_coverage_rejects_malformed_accounting():
    with pytest.raises(state.ContractError):
        state.Coverage("s", "m", eligible=0, tested=0, omitted=2, valid=True)            # headline inconsistent
    with pytest.raises(state.ContractError):
        state.Coverage("s", "m", eligible=1, tested=1, valid=True,                       # units do not reconcile
                       by_kind={"cap": {"eligible": 1, "tested": 1, "omitted": 0}},
                       units=[{"unit": "u", "eligible": 999, "tested": 999, "omitted": 0, "kind": "cap"}])
    with pytest.raises(state.ContractError):        # attribution differs (units cap / by_kind sample)
        state.Coverage("s", "m", eligible=4, tested=3, omitted=1, valid=True,
                       by_kind={"sample": {"eligible": 4, "tested": 3, "omitted": 1}},
                       units=[{"unit": "u", "eligible": 4, "tested": 3, "omitted": 1, "kind": "cap"}])
    with pytest.raises(state.ContractError):        # one-sided: by_kind without units
        state.Coverage("s", "m", eligible=1, tested=1, omitted=0, valid=True,
                       by_kind={"cap": {"eligible": 1, "tested": 1, "omitted": 0}})
    with pytest.raises(state.ContractError):        # one-sided: units without by_kind
        state.Coverage("s", "m", eligible=1, tested=0, omitted=1, valid=True,
                       units=[{"unit": "u", "eligible": 1, "tested": 0, "omitted": 1, "kind": "cap"}])
    with pytest.raises(state.ContractError):
        state.Coverage("s", "m", eligible=None)                                          # explicit null counter
    with pytest.raises(state.ContractError):
        state.Coverage("s", "m", valid="yes")
    with pytest.raises(state.ContractError):
        state.Coverage("s", "m", by_kind={"cap": {"eligible": "3"}})                     # string counter
    with pytest.raises(state.ContractError):
        state.Coverage("s", "m", by_kind={"nonsense": {}})                               # unknown kind


def test_coverage_challenges_and_softness_ignore_zero_omission_kinds():
    cov = _cov("s", "m", {"sample": (1, 0, 1), "cap": (3, 3, 0)})     # only the soft kind omitted
    assert cov.is_soft() and not cov.challenges_completeness()
    assert state.Gap.for_coverage(cov) == []
    gap_cov = _cov("s", "m", {"sample": (1, 0, 1), "cap": (3, 0, 3)})  # cap actually omitted -> gates
    assert not gap_cov.is_soft()
    assert [g.kind for g in state.Gap.for_coverage(gap_cov)] == ["cap"]
    assert [g.kind for g in state.Gap.for_coverage(state.Coverage("s", "m", valid=False))] == ["unknown"]


# ── Gap ──────────────────────────────────────────────────────────────────────────────────────
def test_gap_kind_required_and_constrained():
    with pytest.raises(TypeError):
        state.Gap("s")                                       # kind is required
    with pytest.raises(state.ContractError):
        state.Gap("s", kind="cap", challenges_completeness=False)
    with pytest.raises(state.ContractError):
        state.Gap("s", kind="not_a_kind")
    state.Gap("s", kind="mixed")     # allowed


# ── Remainder: authoritative, parsed exactly + strict containers ──────────────────────────────────
def test_remainder_is_authoritative():
    assert state.Remainder is Remainder


def test_parse_remainder_is_strict():
    rec = {"lane": "enrich.a1d_brute", "unit": "enrich.a1d_brute", "measure": "pairs",
           "model": "project_progress", "retriable": {"now": 5, "cooldown": 0},
           "terminal": {"machinery": 2}, "detail": {"sub": 3}}
    r = state.parse_remainder(rec)
    assert r.terminal == {"machinery": 2} and r.now == 5 and r.detail == {"sub": 3}
    for bad in ({"now": True, "cooldown": 0}, {"now": None, "cooldown": 0}, {"now": "5", "cooldown": 0},
                {"now": 1.0, "cooldown": 0}, {"now": -1, "cooldown": 0}):
        with pytest.raises(state.ContractError):
            state.parse_remainder({**rec, "retriable": bad})
    for bad_container in (None, [], "x"):
        with pytest.raises(state.ContractError):
            state.parse_remainder({**rec, "retriable": bad_container})
        with pytest.raises(state.ContractError):
            state.parse_remainder({**rec, "terminal": bad_container})
    with pytest.raises(state.ContractError):
        state.parse_remainder({**rec, "terminal": {"machinery": False}})
    with pytest.raises(ValueError):
        state.parse_remainder({**rec, "terminal": {"not_a_cause": 1}})


# ── WorkUnit: adapter vs record version; fingerprint required + verified ───────────────────────────
def test_workunit_versions_and_fingerprint():
    wu = state.WorkUnit("crawl.jxscout_ast", inputs={"b": 1}, adapter_schema_version=2)
    assert wu.fingerprint() == events.work_unit("crawl.jxscout_ast", inputs={"b": 1}, schema_version=2)
    assert state.WorkUnit.from_dict(wu.to_dict()) == wu
    state.validate_serialized("WorkUnit", wu.to_dict())
    with pytest.raises(state.ContractError):
        state.WorkUnit.from_dict({**wu.to_dict(), "record_schema_version": 999})
    with pytest.raises(state.ContractError):
        state.WorkUnit.from_dict({"source_id": "x", "inputs": {"b": 1}})            # no fingerprint
    with pytest.raises(state.ContractError):
        state.WorkUnit.from_dict({"source_id": "x", "inputs": {"b": 1}, "fingerprint": "deadbeef"})  # mismatch
    with pytest.raises(state.ContractError):
        state.WorkUnit("x", record_schema_version=999)       # direct construction is gated
    with pytest.raises(state.ContractError):
        state.WorkUnit("x", adapter_schema_version=True)     # bool adapter version


# ── PolicyDecision / RunState / exit precedence ───────────────────────────────────────────────────
def test_policy_runstate_exit():
    with pytest.raises(state.ContractError):
        state.PolicyDecision("bogus", subject="x")
    with pytest.raises(state.ContractError):
        state.RunState("banana")
    assert state.RunState("finalization_failed").can_transition("finalizing")
    assert not state.RunState("finished").can_transition("running")
    assert state.compute_exit("failed", "gapped", interrupted=True) == 130
    assert state.compute_exit("completed", "gapped", machinery_after_start=True) == 5


# ── one resolvable schema document with full nested constraints ───────────────────────────────────
def test_schema_validates_nested_contract():
    doc = state.all_schemas()
    defs = doc["$defs"]
    assert set(defs) >= {"Fault", "Coverage", "Gap", "Remainder", "WorkUnit", "PolicyDecision",
                         "RunState", "CommandResult"}
    for d in defs.values():
        for prop in d.get("properties", {}).values():
            ref = (prop.get("items") or {}).get("$ref")
            if ref:
                assert ref.rsplit("/", 1)[-1] in defs
    assert "fingerprint" in defs["WorkUnit"]["required"]
    assert defs["CommandResult"]["properties"]["exit_code"]["enum"] == list(state.EXIT_CODES)
    good_rem = {"lane": "l", "unit": "u", "measure": "m", "model": "project_progress",
                "retriable": {"now": 1, "cooldown": 0}, "terminal": {"machinery": 2}, "detail": {}}
    state.validate_serialized("Remainder", good_rem)
    with pytest.raises(state.ContractError):
        state.validate_serialized("Remainder", {**good_rem, "terminal": {"machinery": "bad"}})
    with pytest.raises(state.ContractError):
        state.validate_serialized("Remainder", {**good_rem, "retriable": {"now": "five", "cooldown": -9}})
    with pytest.raises(state.ContractError):
        state.validate_serialized("Remainder", {**good_rem, "terminal": {"bogus": 1}})       # bad cause key
    good_cov = _cov("s", "m", {"cap": (1, 1, 0)}).to_dict()
    state.validate_serialized("Coverage", good_cov)
    with pytest.raises(state.ContractError):
        state.validate_serialized("Coverage", {**good_cov, "by_kind": {"cap": {"eligible": "3"}}})
    with pytest.raises(state.ContractError):
        state.validate_serialized("Coverage", {**good_cov, "by_kind": {"bogus": {}}})        # bad kind key
    with pytest.raises(state.ContractError):
        state.validate_serialized("CommandResult", {**state.CommandResult("run").to_dict(), "schema_version": 999})
