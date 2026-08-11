"""QR39-005 — the corpus/RSS envelope is DECLARED and ENFORCED, not merely measured.

The evidence store folds each entity log fully into memory, so a Run's resident set grows with its corpus
(QR39-041/v0.4 removes the ceiling). Until then a Run publishes an exact envelope and refuses — never
silently drops — ingest past it, recording a durable, resumable remainder. These gate that envelope on
committed, versioned fixtures: peak RSS, ingest, reopen, disk, overflow-remainder and crash recovery.
"""
import json
import os
import tracemalloc
from pathlib import Path

import pytest

from quarry_recon import envelope
from quarry_recon.remainder import LANE_MODEL
from quarry_recon.store import REFUSED_DEDUP_CACHE, Run, fold_observations

pytestmark = pytest.mark.offline

_FIXTURES = json.loads((Path(__file__).parent / "fixtures" / "qr39_005"
                        / "envelope-fixtures.json").read_text())


def _fill(run: Run, entity: str, n: int) -> int:
    return sum(run.add(entity, {"host": f"h{i}.example.com"}) for i in range(n))


def _vmrss_kb() -> int:
    with open("/proc/self/status") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    return 0


def _peak_rss_delta_mb(fn):
    """Run `fn`, sampling REAL process RSS (/proc VmRSS) in a background thread; return (result, peak delta MiB).
    Unlike tracemalloc this includes SQLite/native allocations, so it proves the published PROCESS-RSS ceiling."""
    import threading
    import time
    base = _vmrss_kb()
    peak = [base]
    sampling = threading.Event()
    sampling.set()

    def _sample():
        while sampling.is_set():
            peak[0] = max(peak[0], _vmrss_kb())
            time.sleep(0.002)

    th = threading.Thread(target=_sample)
    th.start()
    try:
        result = fn()
    finally:
        sampling.clear()
        th.join()
    return result, (peak[0] - base) / 1024


def _env_record(entity: str = "subdomain", *, now: int = 0, cooldown: int = 0, terminal: dict | None = None) -> dict:
    """A canonical `store.envelope` remainder record (as the manifest persists it), built via the contract."""
    from quarry_recon.remainder import Remainder
    r = Remainder(lane="store.envelope", unit=f"store.envelope:{entity}", measure="keys",
                  model="project_progress", now=now, cooldown=cooldown, terminal=dict(terminal or {}),
                  detail={"entity": entity})
    r.validate()
    return r.as_record()


def _fold_with_remainder(tmp_path, name: str, remainders: list):
    from quarry_recon.store import fold_run_entity
    run = Run.create(tmp_path, name)
    run.add("subdomain", {"host": "a.example.com"})
    run.write_manifest({}, [], metrics=None, policy=None)
    man = json.loads(run.manifest_path.read_text())
    man["envelope_remainder"] = {"remainders": remainders}
    run.manifest_path.write_text(json.dumps(man))
    return fold_run_entity(run.dir, "subdomain")


def test_envelope_is_declared_and_versioned():
    d = envelope.declaration()
    assert d["version"] == envelope.ENVELOPE_VERSION == _FIXTURES["envelope_version"]
    assert d["max_keys_per_entity"] == envelope.MAX_KEYS_PER_ENTITY > 0
    assert d["rss_budget_mb"] == envelope.RSS_BUDGET_MB
    assert LANE_MODEL[envelope.ENVELOPE_LANE] == "project_progress"


@pytest.mark.parametrize("fx", _FIXTURES["fixtures"], ids=lambda f: f["name"])
def test_fixture_stays_inside_the_declared_envelope(tmp_path: Path, fx: dict):
    assert fx["keys"] <= envelope.MAX_KEYS_PER_ENTITY   # a within-envelope fixture never overflows
    run = Run.create(tmp_path, "audit")
    added = _fill(run, "subdomain", fx["keys"])
    assert added == fx["keys"]                          # every distinct key ingested
    assert run.count("subdomain") == fx["keys"]
    assert run.envelope_remainder() is None             # within the envelope: nothing owed

    disk_mb = (run.normalized / "subdomain.jsonl").stat().st_size / 1024 / 1024
    assert disk_mb <= fx["disk_mb_max"], f"{disk_mb:.2f} MiB on disk > {fx['disk_mb_max']}"

    # reopen (fold) peak RSS: the enforced gate, on the versioned threshold
    tracemalloc.start()
    folded = fold_observations(run.normalized / "subdomain.jsonl", max_keys=envelope.MAX_KEYS_PER_ENTITY)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert len(folded.records) == fx["keys"] and folded.refused == 0
    peak_mb = peak / 1024 / 1024
    assert peak_mb <= fx["reopen_rss_mb_max"], f"reopen peak {peak_mb:.1f} MiB > {fx['reopen_rss_mb_max']}"

    # query/export path also materializes within the envelope
    assert len(run.read("subdomain")) == fx["keys"]
    assert len(run.values("subdomain")) == fx["keys"]


def test_ingest_past_the_envelope_refuses_with_a_durable_remainder(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(envelope, "MAX_KEYS_PER_ENTITY", 50)   # a cheap cap; the mechanism is size-independent
    run = Run.create(tmp_path, "audit")
    added = _fill(run, "subdomain", 130)
    assert added == 50 and run.count("subdomain") == 50       # bounded exactly at the declared cap

    rem = run.envelope_remainder()
    assert rem is not None and rem["max_keys_per_entity"] == 50
    (record,) = rem["remainders"]
    assert record["lane"] == "store.envelope" and record["model"] == "project_progress"
    assert record["terminal"]["unschedulable"] == 80        # the 80 refused keys are OWED, never dropped
    assert record["retriable"] == {"now": 0, "cooldown": 0}  # no repeat under the current bound advances
    assert run._envelope_path.exists()                       # persisted durably, not just in memory


def test_existing_key_merge_is_not_refused_at_the_cap(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(envelope, "MAX_KEYS_PER_ENTITY", 10)
    run = Run.create(tmp_path, "audit")
    _fill(run, "subdomain", 40)
    assert run.count("subdomain") == 10
    # a repeat observation of an in-corpus key still merges its provenance (membership does not grow)
    run.add("subdomain", {"host": "h0.example.com", "sources": ["second-source"]})
    assert run.count("subdomain") == 10
    merged = next(r for r in run.read("subdomain") if r.get("host") == "h0.example.com")
    assert "second-source" in merged.get("sources", [])


def test_overflow_remainder_survives_reopen(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(envelope, "MAX_KEYS_PER_ENTITY", 20)
    run = Run.create(tmp_path, "audit")
    _fill(run, "subdomain", 75)
    run.write_manifest({}, [], metrics=None, policy=None)
    manifest = json.loads(run.manifest_path.read_text())
    assert manifest["envelope"]["max_keys_per_entity"] == 20
    assert manifest["envelope_remainder"]["remainders"][0]["terminal"]["unschedulable"] == 55

    reopened = Run.open(tmp_path, "audit", run.run_id)
    assert reopened.count("subdomain") == 20
    assert reopened.envelope_remainder()["remainders"][0]["terminal"]["unschedulable"] == 55


def test_overflow_marker_is_durable_before_finalisation(tmp_path: Path, monkeypatch):
    # a crash BEFORE write_manifest still leaves a durable remainder marker on disk (first-refusal persist)
    monkeypatch.setattr(envelope, "MAX_KEYS_PER_ENTITY", 10)
    run = Run.create(tmp_path, "audit")
    _fill(run, "subdomain", 40)
    assert run._envelope_path.exists()                       # persisted mid-ingest, no finalisation needed
    reopened = Run.open(tmp_path, "audit", run.run_id)
    assert reopened.count("subdomain") == 10
    rem = reopened.envelope_remainder()
    assert rem is not None and rem["remainders"][0]["terminal"]["unschedulable"] >= 1


def test_reopen_of_a_pre_oversized_log_is_bounded(tmp_path: Path, monkeypatch):
    # a log written past the envelope (e.g. by an older/bigger-host run) still materialises bounded on reopen
    monkeypatch.setattr(envelope, "MAX_KEYS_PER_ENTITY", 30)
    run = Run.create(tmp_path, "audit")
    path = run.normalized / "subdomain.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as fh:
        for i in range(100):
            fh.write(json.dumps({"host": f"h{i}.example.com"}) + "\n")
    folded = fold_observations(path, max_keys=30)
    assert len(folded.records) == 30 and folded.refused == 70

    reopened = Run.open(tmp_path, "audit", run.run_id)
    assert reopened.count("subdomain") == 30                 # never materialises the whole oversized log
    assert reopened.envelope_remainder()["remainders"][0]["terminal"]["unschedulable"] == 70


def test_finished_run_fold_is_unbounded_by_default(tmp_path: Path):
    # the store is NOT rewritten: the default fold (finished-run / campaign reads) keeps full materialisation
    run = Run.create(tmp_path, "audit")
    _fill(run, "subdomain", 200)
    folded = fold_observations(run.normalized / "subdomain.jsonl")   # no max_keys -> unbounded
    assert len(folded.records) == 200 and folded.refused == 0


# ── the byte envelope: per-key AND corpus bytes, not just a distinct-key count ────────────────────────

def test_envelope_declares_byte_ceilings():
    d = envelope.declaration()
    assert d["max_bytes_per_key"] == envelope.MAX_BYTES_PER_KEY > 0
    assert d["max_corpus_bytes_per_entity"] == envelope.MAX_CORPUS_BYTES_PER_ENTITY > 0


def test_oversized_record_is_refused_into_the_remainder(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(envelope, "MAX_BYTES_PER_KEY", 200)
    run = Run.create(tmp_path, "audit")
    assert run.add("subdomain", {"host": "h0.example.com"}) is True                 # a normal record fits
    assert run.add("subdomain", {"host": "big.example.com", "blob": "x" * 500}) is False  # one huge record
    assert run.count("subdomain") == 1
    rem = run.envelope_remainder()["remainders"][0]
    assert rem["terminal"]["unschedulable"] == 1                    # the refused identity is owed, not dropped
    assert rem["detail"]["refused_by_kind"] == {"bytes": 1}


def test_corpus_bytes_ceiling_refuses_new_keys_under_the_key_cap(tmp_path: Path, monkeypatch):
    # far below MAX_KEYS: the summed-bytes ceiling, not the key count, is what binds here
    monkeypatch.setattr(envelope, "MAX_CORPUS_BYTES_PER_ENTITY", 400)
    run = Run.create(tmp_path, "audit")
    added = _fill(run, "subdomain", 50)
    assert 0 < added < 50 and run.count("subdomain") == added
    rem = run.envelope_remainder()["remainders"][0]
    assert rem["detail"]["refused_by_kind"] == {"corpus": 50 - added}
    assert rem["terminal"]["unschedulable"] == 50 - added


def test_unbounded_growth_of_an_existing_key_is_refused(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(envelope, "MAX_BYTES_PER_KEY", 400)
    run = Run.create(tmp_path, "audit")
    run.add("subdomain", {"host": "h0.example.com"})
    # enrich the SAME key with fresh provenance until a merge would breach the per-key ceiling
    for i in range(200):
        run.add("subdomain", {"host": "h0.example.com", "sources": [f"s{i}-{'y' * 20}"]})
    assert run.count("subdomain") == 1                              # membership never grew
    merged = run.read("subdomain")[0]
    assert len(json.dumps(merged, ensure_ascii=False).encode()) <= 400    # the record did not grow unbounded
    rem = run.envelope_remainder()["remainders"][0]
    assert rem["detail"]["refused_by_kind"].get("growth", 0) >= 1   # the refused growth is owed


def test_refused_identity_count_is_distinct_and_survives_reload(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(envelope, "MAX_KEYS_PER_ENTITY", 5)
    run = Run.create(tmp_path, "audit")
    _fill(run, "subdomain", 5)                                      # fill to the cap
    for _ in range(4):
        run.add("subdomain", {"host": "over.example.com"})         # ONE over-envelope identity, observed 4x
    rem = run.envelope_remainder()["remainders"][0]
    assert rem["terminal"]["unschedulable"] == 1                    # DISTINCT identities, not observations
    reopened = Run.open(tmp_path, "audit", run.run_id)
    assert reopened.envelope_remainder()["remainders"][0]["terminal"]["unschedulable"] == 1  # exact after reload


def test_overflow_gates_the_run_verdict_and_summary_remainders(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(envelope, "MAX_KEYS_PER_ENTITY", 10)
    run = Run.create(tmp_path, "audit")
    _fill(run, "subdomain", 25)
    summary = run._run_summary()
    assert summary["verdict"] == "complete_with_gaps"              # an overflowed run does NOT finalise clean
    env_rows = [r for r in summary["remainders"] if r.get("lane") == "store.envelope"]
    assert env_rows and env_rows[0]["terminal"]["unschedulable"] == 15
    assert any(g.get("status") == "envelope_overflow" for g in summary["gaps"])


def test_fold_counts_distinct_refused_keys_not_observations(tmp_path: Path):
    # a log with the SAME over-cap key repeated is one refused identity, not many
    path = tmp_path / "subdomain.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as fh:
        for h in ("a", "b", "c"):                                  # 3 keys within a cap of 2 -> 1 refused
            fh.write(json.dumps({"host": f"{h}.example.com"}) + "\n")
        for _ in range(5):                                         # c re-observed 5 more times: still 1 refused
            fh.write(json.dumps({"host": "c.example.com"}) + "\n")
    folded = fold_observations(path, max_keys=2)
    assert len(folded.records) == 2 and folded.refused == 1
    assert folded.refused_keys == {"c.example.com"}


# ── the envelope is enforced on the REOPEN/FOLD path, exact & durable, with bounded memory (round-2) ───

def test_reopen_refuses_an_over_byte_single_key_record(tmp_path: Path, monkeypatch):
    # a single-key record written past the BYTE envelope (older/bigger-host run) is refused on reopen — the
    # key limit alone would have admitted it, since the key count is 1
    monkeypatch.setattr(envelope, "MAX_BYTES_PER_KEY", 100)
    run = Run.create(tmp_path, "audit")
    path = run.normalized / "subdomain.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"host": "h.example.com", "blob": "x" * 2000}) + "\n")   # ~2 KiB, one key
    reopened = Run.open(tmp_path, "audit", run.run_id)
    assert reopened.count("subdomain") == 0                        # the over-byte record is never materialised
    rem = reopened.envelope_remainder()["remainders"][0]
    assert rem["detail"]["refused_by_kind"] == {"bytes": 1}
    assert rem["terminal"]["unschedulable"] == 1


def test_reopen_refuses_new_keys_past_the_corpus_byte_ceiling(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(envelope, "MAX_CORPUS_BYTES_PER_ENTITY", 400)
    run = Run.create(tmp_path, "audit")
    path = run.normalized / "subdomain.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as fh:
        for i in range(50):
            fh.write(json.dumps({"host": f"h{i}.example.com"}) + "\n")
    reopened = Run.open(tmp_path, "audit", run.run_id)
    n = reopened.count("subdomain")
    assert 0 < n < 50                                             # the corpus-byte ceiling bound it below the key cap
    rem = reopened.envelope_remainder()["remainders"][0]
    assert rem["detail"]["refused_by_kind"].get("corpus", 0) == 50 - n


def test_overflow_keeps_resident_memory_bounded_not_N(tmp_path: Path, monkeypatch):
    # 999 refused identities must NOT leave 999 identities resident: the ledger is the exact record, RAM is capped
    monkeypatch.setattr(envelope, "MAX_KEYS_PER_ENTITY", 1)
    run = Run.create(tmp_path, "audit")
    added = _fill(run, "subdomain", 1000)
    assert added == 1 and run.count("subdomain") == 1
    resident = len(run._refused_cache["subdomain"])
    assert resident <= REFUSED_DEDUP_CACHE < 999                  # bounded, independent of the 999 refused
    # yet the durable ledger is exact and survives reopen
    assert run.envelope_remainder()["remainders"][0]["terminal"]["unschedulable"] == 999
    reopened = Run.open(tmp_path, "audit", run.run_id)
    assert reopened.envelope_remainder()["remainders"][0]["terminal"]["unschedulable"] == 999


def test_a_ledger_write_failure_is_surfaced_not_false_clean(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(envelope, "MAX_KEYS_PER_ENTITY", 1)
    run = Run.create(tmp_path, "audit")
    run.add("subdomain", {"host": "kept.example.com"})           # one admitted key

    def _boom(entity, key, kind):
        raise OSError("disk full")

    monkeypatch.setattr(run, "_append_refused", _boom)           # the durable ledger cannot be written
    for i in range(3):
        run.add("subdomain", {"host": f"lost{i}.example.com"})   # refusals that fail to persist
    summary = run._run_summary()
    assert summary["verdict"] != "complete"                      # a lost refusal never reads as clean/complete
    assert summary["phase_exceptions"]                           # the durability failure is surfaced, not swallowed
    assert any(f["kind"] == "phase_exception" for f in summary["faults"])


# ── round-3: the envelope holds on the finished/campaign fold, durably, fail-closed, bounded, dedup'd ──

def test_finished_and_campaign_fold_refuse_an_oversized_record(tmp_path: Path, monkeypatch):
    # the finished-run reconciliation a campaign absorbs must not present an over-envelope record as clean
    from quarry_recon.store import fold_run_entity
    monkeypatch.setattr(envelope, "MAX_BYTES_PER_KEY", 100)
    run = Run.create(tmp_path, "audit")
    path = run.normalized / "subdomain.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"host": "h.example.com", "blob": "x" * 2000}) + "\n")   # ~2 KiB, one key
    run.write_manifest({}, [], metrics=None, policy=None)
    folded = fold_run_entity(run.dir, "subdomain")
    assert len(folded.records) == 0                              # the oversized record is never materialised
    assert all("blob" not in r for r in folded.records.values())


def test_a_prior_durability_failure_keeps_a_reopen_gapped(tmp_path: Path, monkeypatch):
    # a ledger-write failure persists a durable marker, so a fresh reopen stays gapped, never a false fixed_point
    monkeypatch.setattr(envelope, "MAX_KEYS_PER_ENTITY", 1)
    run = Run.create(tmp_path, "audit")
    run.add("subdomain", {"host": "kept.example.com"})
    monkeypatch.setattr(run, "_append_refused",
                        lambda e, k, ki: (_ for _ in ()).throw(OSError("disk full")))
    for i in range(3):
        run.add("subdomain", {"host": f"lost{i}.example.com"})
    assert run._degraded_path.exists()                          # durable, not just an in-memory note
    run.write_manifest({}, [], metrics=None, policy=None)
    reopened = Run.open(tmp_path, "audit", run.run_id)          # a fresh instance with no in-memory notes
    summary = reopened._run_summary()
    assert summary["verdict"] != "complete"                     # the gap survives reopen
    assert summary["phase_exceptions"]


def test_a_damaged_ledger_fails_closed_without_crashing(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(envelope, "MAX_KEYS_PER_ENTITY", 1)
    run = Run.create(tmp_path, "audit")
    run.add("subdomain", {"host": "a.example.com"})
    run.add("subdomain", {"host": "b.example.com"})              # one real refusal on the ledger
    with open(run._refused_path, "a") as fh:                     # inject damage: valid non-object JSON + malformed
        fh.write("5\n")
        fh.write("[1, 2]\n")
        fh.write("{not json\n")
    rem = run.envelope_remainder()                              # must NOT crash on the non-object lines
    assert rem["remainders"][0]["terminal"]["unschedulable"] == 1   # the real refusal still counts
    summary = run._run_summary()
    assert summary["verdict"] == "complete_with_gaps"          # damage fails CLOSED, never silently dropped
    assert any("unreadable" in e for e in summary["phase_exceptions"])


def test_reopen_does_not_duplicate_refusal_rows(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(envelope, "MAX_KEYS_PER_ENTITY", 1)
    run = Run.create(tmp_path, "audit")
    path = run.normalized / "subdomain.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as fh:
        for i in range(5):
            fh.write(json.dumps({"host": f"h{i}.example.com"}) + "\n")   # 4 over a cap of 1
    for _ in range(5):
        Run.open(tmp_path, "audit", run.run_id).count("subdomain")       # five reopens each re-fold the log
    final = Run.open(tmp_path, "audit", run.run_id)
    rows = sum(1 for _ in open(final._fold_refused_path("subdomain")))
    assert rows == 4                                            # idempotent across reopens, not 4 * 5
    assert final.envelope_remainder()["remainders"][0]["terminal"]["unschedulable"] == 4


def test_no_unenforced_disk_budget_is_published():
    # the append-only log's on-disk size is not bounded by the corpus envelope, so no disk budget is published
    assert "disk_budget_mb" not in envelope.declaration()
    assert set(envelope.declaration()) == {"version", "max_keys_per_entity", "rss_budget_mb",
                                           "max_bytes_per_key", "max_corpus_bytes_per_entity"}


# ── round-4: growth-only overflow degrades the fold; ledger validation; durability marker failure ─────

def test_finished_fold_degrades_on_a_growth_refusal_with_unchanged_count(tmp_path: Path, monkeypatch):
    # an on-disk log carrying an over-byte ENRICHMENT of an existing key: the distinct-key count is unchanged,
    # so a count-only check reads `valid`; the refused growth must still degrade the fold (no clean fixed_point)
    from quarry_recon.store import fold_run_entity
    monkeypatch.setattr(envelope, "MAX_BYTES_PER_KEY", 200)
    run = Run.create(tmp_path, "audit")
    path = run.normalized / "subdomain.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as fh:
        fh.write(json.dumps({"host": "h.example.com"}) + "\n")
        fh.write(json.dumps({"host": "h.example.com", "blob": "x" * 500}) + "\n")   # growth past the ceiling
    run.write_manifest({}, [], metrics=None, policy=None)
    folded = fold_run_entity(run.dir, "subdomain")
    assert len(folded.records) == 1                            # the distinct-key count is unchanged
    assert folded.status == "degraded" and not folded.trustworthy
    summary = json.loads(run.manifest_path.read_text())["summary"]
    assert summary["verdict"] != "complete"                   # the run's own remainder carries the growth refusal
    assert any(r.get("lane") == "store.envelope" for r in summary["remainders"])


def test_an_unreadable_fold_ledger_dir_fails_closed(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(envelope, "MAX_KEYS_PER_ENTITY", 1)
    run = Run.create(tmp_path, "audit")
    path = run.normalized / "subdomain.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as fh:
        for i in range(5):
            fh.write(json.dumps({"host": f"h{i}.example.com"}) + "\n")
    Run.open(tmp_path, "audit", run.run_id).count("subdomain")     # writes envelope-fold-refused/subdomain.jsonl
    os.chmod(run._fold_refused_dir, 0o000)
    try:
        reopened = Run.open(tmp_path, "audit", run.run_id)
        summary = reopened._run_summary()
        assert summary["verdict"] != "complete"                   # never a clean verdict over an unreadable ledger
        assert summary["phase_exceptions"]
    finally:
        os.chmod(run._fold_refused_dir, 0o755)


def test_out_of_vocabulary_ledger_lines_are_damage_not_a_crash(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(envelope, "MAX_KEYS_PER_ENTITY", 1)
    run = Run.create(tmp_path, "audit")
    run.add("subdomain", {"host": "a.example.com"})
    run.add("subdomain", {"host": "b.example.com"})               # one real refusal
    with open(run._refused_path, "a") as fh:
        fh.write(json.dumps({"entity": "subdomain", "key": "z", "kind": {"a": 1}}) + "\n")   # dict kind
        fh.write(json.dumps({"entity": "subdomain", "key": "y", "kind": "weird"}) + "\n")    # unknown kind
        fh.write(json.dumps({"entity": "not_an_entity", "key": "q", "kind": "key"}) + "\n")  # unknown entity
    rem = run.envelope_remainder()                               # must NOT crash sqlite on the dict kind
    assert rem["remainders"][0]["terminal"]["unschedulable"] == 1    # only the real refusal counts
    summary = run._run_summary()
    assert summary["verdict"] == "complete_with_gaps"           # fails closed
    assert any("unreadable" in e for e in summary["phase_exceptions"])


def test_finalize_groups_are_bounded_by_the_entity_enum(tmp_path: Path, monkeypatch):
    # a crafted ledger with 20k distinct entities must not build 20k in-memory groups; unknown entities are damage
    monkeypatch.setattr(envelope, "MAX_KEYS_PER_ENTITY", 1)
    run = Run.create(tmp_path, "audit")
    run.add("subdomain", {"host": "a.example.com"})
    run.add("subdomain", {"host": "b.example.com"})
    with open(run._refused_path, "a") as fh:
        for i in range(20_000):
            fh.write(json.dumps({"entity": f"crafted{i}", "key": "x", "kind": "key"}) + "\n")
    rem = run.envelope_remainder()
    assert len(rem["remainders"]) == 1                          # only the real `subdomain` entity survives
    assert rem["remainders"][0]["detail"]["entity"] == "subdomain"


def test_a_durability_marker_write_failure_is_surfaced(tmp_path: Path, monkeypatch):
    import quarry_recon.store as store_mod
    monkeypatch.setattr(envelope, "MAX_KEYS_PER_ENTITY", 1)
    run = Run.create(tmp_path, "audit")
    run.add("subdomain", {"host": "kept.example.com"})
    orig = store_mod._atomic_write

    def _block_marker(path, text):
        if str(path).endswith("envelope-degraded.json"):
            raise OSError("read-only fs")                       # ledger AND marker share an unwritable fs
        return orig(path, text)

    monkeypatch.setattr(store_mod, "_atomic_write", _block_marker)
    monkeypatch.setattr(run, "_append_refused",
                        lambda e, k, ki: (_ for _ in ()).throw(OSError("disk full")))
    for i in range(3):
        run.add("subdomain", {"host": f"lost{i}.example.com"})
    summary = run._run_summary()
    assert summary["verdict"] != "complete"
    assert any("marker unwritable" in e for e in summary["phase_exceptions"])   # loud, never swallowed


# ── round-5: live refusals survive reopen; marker-loss survives via manifest; bounded surrogate-safe fold ─

def test_a_live_refusal_makes_a_reopened_run_untrustworthy(tmp_path: Path, monkeypatch):
    # live refusals never reach the normalized log; folding rows alone would read the run as clean, but its
    # finalized manifest records the refusal, so the finished/campaign fold must stay degraded (not trustworthy)
    from quarry_recon.store import fold_run_entity
    monkeypatch.setattr(envelope, "MAX_KEYS_PER_ENTITY", 1)
    run = Run.create(tmp_path, "audit")
    run.add("subdomain", {"host": "a.example.com"})           # admitted -> on the log
    run.add("subdomain", {"host": "b.example.com"})           # LIVE refused -> only in the ledger
    run.write_manifest({}, [], metrics=None, policy=None)
    folded = fold_run_entity(run.dir, "subdomain")
    assert folded.status == "degraded" and not folded.trustworthy
    assert "1" in folded.reason


def test_marker_unwritable_gap_survives_reopen_via_the_manifest(tmp_path: Path, monkeypatch):
    import quarry_recon.store as store_mod
    monkeypatch.setattr(envelope, "MAX_KEYS_PER_ENTITY", 1)
    run = Run.create(tmp_path, "audit")
    run.add("subdomain", {"host": "kept.example.com"})
    orig = store_mod._atomic_write

    def _block_marker(path, text):
        if str(path).endswith("envelope-degraded.json"):
            raise OSError("read-only fs")                     # only the standalone marker is unwritable
        return orig(path, text)

    monkeypatch.setattr(store_mod, "_atomic_write", _block_marker)
    monkeypatch.setattr(run, "_append_refused",
                        lambda e, k, ki: (_ for _ in ()).throw(OSError("disk full")))
    for i in range(3):
        run.add("subdomain", {"host": f"lost{i}.example.com"})
    run.write_manifest({}, [], metrics=None, policy=None)     # the manifest IS writable and records the gap
    assert "envelope_degraded" in json.loads(run.manifest_path.read_text())
    monkeypatch.setattr(store_mod, "_atomic_write", orig)     # marker still missing on disk
    reopened = Run.open(tmp_path, "audit", run.run_id)        # fresh instance, no in-memory notes
    summary = reopened._run_summary()
    assert summary["verdict"] != "complete"                  # the gap is recovered from the manifest
    assert summary["phase_exceptions"]


def test_a_surrogate_or_overlong_ledger_key_is_damage_not_a_crash(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(envelope, "MAX_KEYS_PER_ENTITY", 1)
    run = Run.create(tmp_path, "audit")
    run.add("subdomain", {"host": "a.example.com"})
    run.add("subdomain", {"host": "b.example.com"})           # one real refusal
    with open(run._refused_path, "a") as fh:
        fh.write(json.dumps({"entity": "subdomain", "key": "x\ud800y", "kind": "key"}) + "\n")   # lone surrogate
        fh.write(json.dumps({"entity": "subdomain", "key": "z" * 20000, "kind": "key"}) + "\n")  # over-long
    rem = run.envelope_remainder()                            # must NOT crash sqlite on the surrogate bind
    assert rem["remainders"][0]["terminal"]["unschedulable"] == 1   # only the real refusal counts
    summary = run._run_summary()
    assert summary["verdict"] == "complete_with_gaps"        # both anomalous lines fail closed as damage
    assert any("unreadable" in e for e in summary["phase_exceptions"])


def test_finalize_fold_stays_under_the_rss_budget_on_a_large_refusal_set(tmp_path: Path, monkeypatch):
    # REAL process RSS (VmRSS), not tracemalloc, so SQLite/native allocations count toward the declared ceiling
    if not os.path.exists("/proc/self/status"):
        pytest.skip("needs /proc for a real RSS measurement")
    monkeypatch.setattr(envelope, "MAX_KEYS_PER_ENTITY", 1)
    run = Run.create(tmp_path, "audit")
    run.add("subdomain", {"host": "a.example.com"})
    n = 100_000
    with open(run._refused_path, "a") as fh:
        for i in range(n):
            fh.write(json.dumps({"entity": "subdomain", "key": f"k{i}-{'x' * 200}.example.com",
                                 "kind": "key"}) + "\n")       # long-ish keys, well within the length cap
    rem, peak_mb = _peak_rss_delta_mb(run.envelope_remainder)
    assert rem["remainders"][0]["terminal"]["unschedulable"] == n   # exact
    assert peak_mb < envelope.RSS_BUDGET_MB                    # real VmRSS delta stays under the declared ceiling


def test_an_oversized_ledger_line_is_rejected_without_materializing(tmp_path: Path, monkeypatch):
    # a giant line must be rejected as damage BEFORE json.loads, so real process RSS never spikes to hold it
    if not os.path.exists("/proc/self/status"):
        pytest.skip("needs /proc for a real RSS measurement")
    monkeypatch.setattr(envelope, "MAX_KEYS_PER_ENTITY", 1)
    run = Run.create(tmp_path, "audit")
    run.add("subdomain", {"host": "a.example.com"})
    run.add("subdomain", {"host": "b.example.com"})           # one real refusal
    big = "z" * (72 * 1024 * 1024)                            # a 72 MiB key on one ledger line
    with open(run._refused_path, "a") as fh:
        fh.write(json.dumps({"entity": "subdomain", "key": big, "kind": "key"}) + "\n")
    rem, peak_mb = _peak_rss_delta_mb(run.envelope_remainder)
    assert peak_mb < envelope.RSS_BUDGET_MB                   # the 72 MiB line never lands in memory
    assert rem["remainders"][0]["terminal"]["unschedulable"] == 1   # it is damage; only the real refusal counts
    assert any("unreadable" in e for e in run._run_summary()["phase_exceptions"])


def test_a_persisted_durability_gap_keeps_a_finished_fold_untrustworthy(tmp_path: Path, monkeypatch):
    from quarry_recon.store import fold_run_entity
    monkeypatch.setattr(envelope, "MAX_KEYS_PER_ENTITY", 1)
    run = Run.create(tmp_path, "audit")
    run.add("subdomain", {"host": "a.example.com"})
    run.write_manifest({}, [], metrics=None, policy=None)
    man = json.loads(run.manifest_path.read_text())
    man["envelope_degraded"] = {"ledger:subdomain": "EXCEPTION: envelope refusal ledger unwritable"}
    run.manifest_path.write_text(json.dumps(man))
    folded = fold_run_entity(run.dir, "subdomain")
    assert folded.status == "degraded" and not folded.trustworthy   # a persisted durability gap fails closed


def test_a_malformed_envelope_remainder_fails_closed_but_clean_stays_trustworthy(tmp_path: Path, monkeypatch):
    from quarry_recon.store import fold_run_entity
    monkeypatch.setattr(envelope, "MAX_KEYS_PER_ENTITY", 1)
    run = Run.create(tmp_path, "audit")
    run.add("subdomain", {"host": "a.example.com"})
    run.write_manifest({}, [], metrics=None, policy=None)
    man = json.loads(run.manifest_path.read_text())
    man["envelope_remainder"] = {"remainders": "GARBAGE"}     # present but unreadable -> never read as zero
    run.manifest_path.write_text(json.dumps(man))
    assert not fold_run_entity(run.dir, "subdomain").trustworthy
    # a genuinely clean run (no remainder, no degraded field) must still fold trustworthy — no false positives
    clean = Run.create(tmp_path, "clean")
    clean.add("subdomain", {"host": "a.example.com"})
    clean.write_manifest({}, [], metrics=None, policy=None)
    assert fold_run_entity(clean.dir, "subdomain").trustworthy


def test_a_non_int_remainder_counter_fails_closed(tmp_path: Path, monkeypatch):
    # a well-formed record whose counter is the wrong type is an UNREADABLE refusal claim: coercing it to 0
    # would let a gapped run be absorbed, so the contract rejects it and the fold fails closed
    monkeypatch.setattr(envelope, "MAX_KEYS_PER_ENTITY", 1)
    for bad in ("1", 1.0, True, -1, None):                     # wrong-type / negative terminal counter
        rec = {**_env_record(), "terminal": {"unschedulable": bad}}
        assert not _fold_with_remainder(tmp_path, f"t-{bad!r}", [rec]).trustworthy
    rec = {**_env_record(), "retriable": {"now": "x", "cooldown": 0}}   # a wrong-type retriable counter too
    assert not _fold_with_remainder(tmp_path, "retriable", [rec]).trustworthy


def test_any_outstanding_remainder_work_degrades_not_just_unschedulable(tmp_path: Path, monkeypatch):
    # retriable.now, retriable.cooldown, and ANY terminal cause are all outstanding work — not only unschedulable
    monkeypatch.setattr(envelope, "MAX_KEYS_PER_ENTITY", 1)
    for rec in (_env_record(now=3),
                _env_record(cooldown=2),
                _env_record(terminal={"machinery": 1}),
                _env_record(terminal={"dependency": 4}),
                _env_record(terminal={"unschedulable": 5})):
        folded = _fold_with_remainder(tmp_path, "o", [rec])
        assert folded.status == "degraded" and not folded.trustworthy
    # a fully well-formed record with nothing outstanding still folds trustworthy (no false positive)
    assert _fold_with_remainder(tmp_path, "clean", [_env_record()]).trustworthy
    # a refusal for a DIFFERENT entity leaves this one trustworthy (per-entity)
    assert _fold_with_remainder(tmp_path, "other", [_env_record(entity="url", terminal={"unschedulable": 3})]).trustworthy


def test_a_structurally_invalid_remainder_fails_closed_via_the_contract(tmp_path: Path, monkeypatch):
    # parsed through the AUTHORITATIVE remainder contract: a missing required field, an unknown key, a
    # bad model/measure, or a missing entity all fail closed — the partial value never reads as clean
    monkeypatch.setattr(envelope, "MAX_KEYS_PER_ENTITY", 1)
    good = _env_record(terminal={"unschedulable": 2})
    bad_records = [
        {k: v for k, v in good.items() if k != "model"},          # missing required field
        {k: v for k, v in good.items() if k != "measure"},        # missing required field
        {**good, "surprise": 1},                                  # unknown top-level key
        {**good, "model": "rerun_same_work"},                     # model contradicts the declared lane model
        {**good, "measure": ""},                                  # empty measure
    ]
    for i, rec in enumerate(bad_records):
        folded = _fold_with_remainder(tmp_path, f"bad-{i}", [rec])
        assert not folded.trustworthy, f"record #{i} should fail closed: {rec}"
        assert "malformed" in folded.reason
    # the well-formed record it was derived from still parses and degrades on its real refusal
    assert not _fold_with_remainder(tmp_path, "good", [good]).trustworthy


def test_an_invalid_envelope_identity_keeps_work_outstanding(tmp_path: Path, monkeypatch):
    # a record owes 3 units under the unit `store.envelope:subdomain`; a detail.entity that is bogus, empty,
    # or mismatched (or an unknown nested retriable key) is never a clean signal -> the work stays OUTSTANDING
    monkeypatch.setattr(envelope, "MAX_KEYS_PER_ENTITY", 1)

    def _under_subdomain(detail_entity=..., extra_retriable=None):
        rec = _env_record(entity="subdomain", terminal={"unschedulable": 3})   # unit == store.envelope:subdomain
        if detail_entity is not ...:
            rec["detail"] = {} if detail_entity is None else {"entity": detail_entity}
        if extra_retriable is not None:
            rec["retriable"] = {**rec["retriable"], **extra_retriable}
        return rec

    for label, rec in (("bogus", _under_subdomain("bogus")),
                       ("empty", _under_subdomain("")),
                       ("missing", _under_subdomain(None)),
                       ("mismatch", _under_subdomain("url")),            # a valid entity, but not the unit's
                       ("unknown-retriable", _under_subdomain(extra_retriable={"surprise": 5}))):
        folded = _fold_with_remainder(tmp_path, f"id-{label}", [rec])
        assert folded.status == "degraded" and not folded.trustworthy, f"{label} must stay outstanding"
    # an unknown entity in the UNIT itself is not attributable -> fail closed
    bad_unit = _env_record(entity="subdomain", terminal={"unschedulable": 3})
    bad_unit["unit"] = "store.envelope:bogus"
    assert not _fold_with_remainder(tmp_path, "bad-unit", [bad_unit]).trustworthy
    # a fully valid identity for a DIFFERENT entity still leaves this fold trustworthy (attribution by unit)
    assert _fold_with_remainder(tmp_path, "other", [_env_record(entity="url", terminal={"unschedulable": 3})]).trustworthy
