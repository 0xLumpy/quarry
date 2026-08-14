"""v0.3.8 dalfox v3 contract — permanent (pytest-gated) coverage of the parser fail-closed matrix, the
exit-code<->findings agreement, immutable retry evidence, engine-identity resume, and truthful
EMPTY/SUCCESS/PARTIAL verdicts. Hermetic (no network/subprocess — exec_tool is mocked)."""
import json
import os
import pathlib
import tempfile

import pytest

from quarry_recon import events, secrets, settings
from quarry_recon.phases import params
from quarry_recon.runner import RunResult, Status

pytestmark = pytest.mark.offline

#: 3.2.0 always emits `incomplete` AND `target_summary` (measured), and the lane reconciles the summary
#: against the batch it submitted — so a fixture without them is testing an artifact Quarry refuses,
#: not the case it means to test (review#37, Lumpy). `_meta(n, targets)` builds an honest one.
#: sentinel: expand to the ACTUAL batch the lane submitted. The lane reconciles the summary against
#: its own input by MEMBERSHIP (review#38), so a fixture with a hard-coded target list is testing a
#: mismatch it never meant to create. `_exec` expands this from the `-i file` argument.
BATCH = "@@BATCH@@"


def _meta(n, targets=(BATCH,), status=None, dedup=0):
    return json.dumps({"meta": {
        "findings_count": n, "incomplete": False, "dedup_mode": "signature",
        "targets_deduplicated": dedup, "total_requests": 1,
        "target_summary": [{"target": t, "status": status or ("findings" if n else "clean"),
                            "findings_count": n} for t in targets]}}) + "\n"


META1 = _meta(1)
META0 = _meta(0)
R_ROW = '{"type":"R","param":"q","data":"http://h/p?q=1","method":"GET","location":"Query"}\n'


def _p(txt):
    """(findings, READABLE) — the structural verdict this suite was written against.

    review#13 (Lumpy) split the parser's single boolean into separate facts: `readable` is the
    structural one these cases assert, and completeness/skips are asked separately (see
    `TestMetaRowIsRead`). `_art` returns the whole record for the tests that need it."""
    f, art = _art(txt)
    return f, art.readable


def _art(txt):
    p = pathlib.Path(tempfile.mktemp()); p.write_text(txt)
    out = []
    n, art = params.scan_dalfox_jsonl(p, out.append)
    assert n == len(out), "the streamed count and the sink must agree"
    return out, art


class TestParserMatrix:
    def test_happy_path(self):
        f, ok = _p(META1 + R_ROW)
        assert ok and len(f) == 1 and f[0]["template"] == "xss-candidate" and f[0]["confirmed"] is False

    @pytest.mark.parametrize("txt", [
        '{"meta":{"findings_count":2}}\n{"type":"R","param":"q","data":"http://h/p?q=1"}\n',  # count mismatch
        '{"type":"R","param":"q","data":"http://h/p?q=1"}\n',                                 # no meta row
        META1 + 'broken{\n',                                                                  # torn line
        META1 + '{"type":"Z","param":"q","data":"http://h/p?q=1"}\n',                          # unknown type
        META1 + '{"type":["R"],"param":"q","data":"http://h/p?q=1"}\n',                        # non-scalar type
        META1 + '{"type":"R","param":"q","data":"http://h:bad/p?q=1"}\n',                      # bad :port (must not raise)
        META1 + '{"type":"R","param":"q"}\n',                                                  # missing data
        META1 + '[1,2,3]\n',                                                                   # non-object row
        '{"meta":{"findings_count":"1"}}\n' + R_ROW,                                           # non-int meta count
        '{"meta":{"findings_count":true}}\n' + R_ROW,                                          # r10#3: bool count (subclasses int)
        '{"meta":{"findings_count":-1}}\n',                                                    # r10#3: negative count
        META1 + META1,                                                                         # r10#3: TWO meta rows
        R_ROW + META1,                                                                         # r10#3: meta not in first position
    ])
    def test_fail_closed(self, txt):
        _, ok = _p(txt)
        assert ok is False

    def test_missing_file(self):
        n, art = params.scan_dalfox_jsonl(pathlib.Path("/nonexistent/x.jsonl"))
        f = []
        assert f == [] and art.readable is False

    def test_bad_port_row_dropped_but_valid_row_kept(self):
        # review-r9#3: a bad-port row is rejected (ok=False) but MUST NOT abort the parse — a valid row survives
        f, ok = _p('{"meta":{"findings_count":2}}\n'
                   '{"type":"R","param":"q","data":"http://h:bad/p?q=1"}\n'
                   '{"type":"R","param":"q","data":"http://h/ok?q=1","method":"GET","location":"Query"}\n')
        assert ok is False and len(f) == 1 and "ok" in f[0]["id"]


class TestIdentity:
    def test_distinct_routes_never_collapse(self):
        f, _ = _p('{"meta":{"findings_count":2}}\n'
                  '{"type":"V","param":"q","data":"http://h/search?q=1","method":"GET","location":"Query"}\n'
                  '{"type":"R","param":"q","data":"http://h/admin?q=1","method":"GET","location":"Query"}\n')
        assert len({r["id"] for r in f}) == 2

    def test_ast_dom_dual_sink_distinct(self):
        ev1 = 'http://h/x:1:5 - (Source: URLSearchParams.get(q), Sink: innerHTML)'
        ev2 = 'http://h/x:2:1 - (Source: location.hash, Sink: document.write)'
        f, _ = _p('{"meta":{"findings_count":2}}\n'
                  '{"type":"A","param":"-","data":"http://h/x","evidence":"%s"}\n'
                  '{"type":"A","param":"-","data":"http://h/x","evidence":"%s"}\n' % (ev1, ev2))
        assert len({r["id"] for r in f}) == 2 and all(r["template"] == "dom-xss-static" for r in f)

    def test_ipv6_authority_not_ambiguous(self):
        # review-r10#2: [::1]:80 (host ::1, port 80) and [::1:80] (host ::1:80, no port) must NOT collapse
        f, _ = _p('{"meta":{"findings_count":2}}\n'
                  '{"type":"R","param":"q","data":"http://[::1]:80/p?q=1","method":"GET","location":"Query"}\n'
                  '{"type":"R","param":"q","data":"http://[::1:80]/p?q=1","method":"GET","location":"Query"}\n')
        assert len({r["id"] for r in f}) == 2


# ── _dalfox_xss_fast harness (mocked exec_tool + engine identity) ─────────────────────────────
class _R:
    def __init__(s, d): s.dir = d; s.added = []
    def raw_path(s, ph, tl, nm):
        p = s.dir / "raw" / ph / tl / nm; p.parent.mkdir(parents=True, exist_ok=True); return p
    def add(s, e, rec):
        if rec["id"] in {a["id"] for a in s.added}:
            return False
        s.added.append(rec); return True


class _C:
    def __init__(s, d): s.run = _R(d); s.http_timeout = 600; s._d = d
    def write_list(s, nm, it):
        p = s._d / "work" / nm; p.parent.mkdir(parents=True, exist_ok=True); p.write_text("\n".join(it)); return p


class _Prof:
    http_rl = 0


def _fresh(monkeypatch, tmp_path, engine="v3.1.2"):
    monkeypatch.setattr(settings, "concurrency", lambda k, d=None: {"DALFOX_CHUNK": 1, "DALFOX_TARGETS": 4}.get(k, d))
    monkeypatch.setattr(settings, "workers", lambda t, d: d)
    monkeypatch.setattr(secrets, "oob", lambda: {})
    monkeypatch.setattr(params, "_dalfox_engine_id", lambda: engine)
    events.reset(); events.configure(tmp_path)
    return _C(tmp_path)


def _exec(artifact, rc, started=True):
    """A fake runner result that carries the runner's OWN contract.

    `meta["started"]` is how `runner.run` proves a process really launched (review#21): a fake that
    omits it claims a launch the real runner would not, and any caller counting invocations would be
    tested against a lie. `started=False` models a missing binary / refused launch."""
    def fx(t, cmd, timeout=None, **k):
        cf = pathlib.Path(cmd[cmd.index("-o") + 1]); cf.parent.mkdir(parents=True, exist_ok=True)
        art = artifact
        if BATCH in art:
            # expand the sentinel to the batch this invocation was actually given
            bf = pathlib.Path(cmd[cmd.index("file") + 1])
            urls = [u for u in bf.read_text().splitlines() if u.strip()]
            rows = []
            for line in art.splitlines(True):
                if BATCH not in line:
                    rows.append(line); continue
                o = json.loads(line)
                proto = o["meta"]["target_summary"][0]
                o["meta"]["target_summary"] = [dict(proto, target=u) for u in urls]
                rows.append(json.dumps(o) + "\n")
            art = "".join(rows)
        cf.write_text(art)
        return RunResult("dalfox", cmd, Status.SUCCESS if rc in (0, 1) else Status.FAILED, rc, 0.1, cf, 0,
                         meta={"started": started})
    return fx


def _state(c):
    p = c.run.raw_path("params", "dalfox", "chunks.state.json")
    return json.loads(p.read_text()) if p.exists() else {"chunks": {}}   # nuclei-parity: completion map


class TestExitMatrix:
    # review-r9#2: exit code and parsed findings must AGREE for a chunk to settle CLEAN.
    @pytest.mark.parametrize("rc,art,verdict,done", [
        (0, META0,          Status.EMPTY,   True),    # 0 + valid empty  -> EMPTY, done
        (1, META1 + R_ROW,  Status.SUCCESS, True),    # 1 + valid finds  -> SUCCESS, done
        (0, META1 + R_ROW,  Status.PARTIAL, False),   # 0 WITH findings  -> disagreement -> PARTIAL, retryable
        (1, META0,          Status.PARTIAL, False),   # 1 with NO finds  -> disagreement -> PARTIAL
        (2, META1 + R_ROW,  Status.PARTIAL, False),   # hard exit        -> PARTIAL (evidence kept)
    ])
    def test_matrix(self, monkeypatch, tmp_path, rc, art, verdict, done):
        c = _fresh(monkeypatch, tmp_path)
        monkeypatch.setattr(params, "exec_tool", _exec(art, rc))
        r = params._dalfox_xss_fast(c, ["http://h/p?q="], _Prof())
        assert r.status == verdict
        assert ("0" in _state(c)["chunks"]) == done   # completion map: clean chunk only


class TestVerdict:
    def test_all_empty_reports_empty_and_survives_full_resume(self, monkeypatch, tmp_path):
        # review-r9#5: every chunk clean-empty -> source EMPTY (not SUCCESS); a full resume keeps EMPTY
        c = _fresh(monkeypatch, tmp_path)
        monkeypatch.setattr(params, "exec_tool", _exec(META0, 0))
        r = params._dalfox_xss_fast(c, ["http://h/a?q=", "http://h/b?q="], _Prof())
        assert r.status == Status.EMPTY
        called = []
        base = _exec(META0, 0)
        monkeypatch.setattr(params, "exec_tool", lambda *a, **k: (called.append(1), base(*a, **k))[1])
        r2 = params._dalfox_xss_fast(c, ["http://h/a?q=", "http://h/b?q="], _Prof())
        assert r2.status == Status.EMPTY and called == []   # all skipped, verdict still EMPTY


class TestRetryEvidence:
    def test_noncurrent_preserved_prior_is_never_parsed_hashed_or_reported(
        self, monkeypatch, tmp_path,
    ):
        c = _fresh(monkeypatch, tmp_path)
        observed = {"cf": None, "parsed": [], "hashed": []}
        real_scan = params.scan_dalfox_jsonl
        real_hash = params._sha256_file

        def noncurrent_result(_tool, cmd, **_kwargs):
            cf = pathlib.Path(cmd[cmd.index("-o") + 1])
            cf.parent.mkdir(parents=True, exist_ok=True)
            cf.write_text(META1 + R_ROW)              # preserved PRIOR at the canonical final
            observed["cf"] = cf
            return RunResult(
                "dalfox", cmd, Status.FAILED, 2, 0.1, None, 0,
                meta={
                    "started": True,
                    "native_outputs": {"current_paths": []},
                    "native_output_ownership_settled": True,
                },
            )

        def scan(path, *args, **kwargs):
            observed["parsed"].append(pathlib.Path(path))
            return real_scan(path, *args, **kwargs)

        def digest(path):
            observed["hashed"].append(pathlib.Path(path))
            return real_hash(path)

        monkeypatch.setattr(params, "exec_tool", noncurrent_result)
        monkeypatch.setattr(params, "scan_dalfox_jsonl", scan)
        monkeypatch.setattr(params, "_sha256_file", digest)

        result = params._dalfox_xss_fast(c, ["http://h/p?q="], _Prof())

        cf = observed["cf"]
        assert cf is not None and cf.is_file(), "the preserved prior must remain on disk"
        assert cf not in observed["parsed"] and cf not in observed["hashed"]
        assert result.status is Status.PARTIAL and c.run.added == []
        state = _state(c)
        assert state.get("chunks") == {} and state.get("evidence") == {}
        rows = [json.loads(line) for line in (tmp_path / "events.jsonl").read_text().splitlines()]
        assert all(row.get("raw_ref") != str(cf) for row in rows)

    def test_retry_preserves_prior_attempt_artifact(self, monkeypatch, tmp_path):
        # review-r9#1: a degraded chunk's raw evidence lives in an IMMUTABLE attempt dir; a retry writes a new
        # attempt dir and never overwrites it (an already-ingested finding's raw_ref stays valid)
        c = _fresh(monkeypatch, tmp_path)
        art = META1 + R_ROW
        monkeypatch.setattr(params, "exec_tool", _exec(art, 2))    # hard exit -> degraded, NOT done
        params._dalfox_xss_fast(c, ["http://h/p?q="], _Prof())
        base = tmp_path / "raw" / "params" / "dalfox"
        a1 = list(base.glob("wu_*/attempt_*/findings_0.jsonl"))
        assert len(a1) == 1 and a1[0].exists()
        monkeypatch.setattr(params, "exec_tool", _exec(art, 1))    # retry succeeds
        params._dalfox_xss_fast(c, ["http://h/p?q="], _Prof())
        attempts = list(base.glob("wu_*/attempt_*"))
        assert len(attempts) == 2 and a1[0].exists()               # prior attempt evidence RETAINED

    def test_finding_in_degraded_attempt_survives_empty_retry(self, monkeypatch, tmp_path):
        # review-r10#1 truth conflict: a finding kept in a DEGRADED attempt is not lost when the retry is
        # clean-empty — the source verdict is SUCCESS (not EMPTY) and matched stays >=1
        c = _fresh(monkeypatch, tmp_path)
        monkeypatch.setattr(params, "exec_tool", _exec(META1 + R_ROW, 2))   # degraded WITH a finding
        r1 = params._dalfox_xss_fast(c, ["http://h/p?q="], _Prof())
        assert r1.status == Status.PARTIAL and len(c.run.added) == 1
        monkeypatch.setattr(params, "exec_tool", _exec(META0, 0))          # retry: clean-empty
        r2 = params._dalfox_xss_fast(c, ["http://h/p?q="], _Prof())
        assert r2.status == Status.SUCCESS and len(c.run.added) == 1        # NOT EMPTY; finding retained + deduped


class TestEngineResume:
    def test_verified_engine_resumes_done_chunk(self, monkeypatch, tmp_path):
        c = _fresh(monkeypatch, tmp_path, engine="v3.1.2")
        calls = []
        base = _exec(META1 + R_ROW, 1)
        monkeypatch.setattr(params, "exec_tool", lambda *a, **k: (calls.append(1), base(*a, **k))[1])
        params._dalfox_xss_fast(c, ["http://h/p?q="], _Prof())   # runs, done
        params._dalfox_xss_fast(c, ["http://h/p?q="], _Prof())   # resume -> skipped
        assert len(calls) == 1

    def test_unverified_engine_is_non_resumable(self, monkeypatch, tmp_path):
        # review-r9#4: an unverified engine (nonce) must NOT resume — the chunk re-runs
        monkeypatch.setattr(settings, "concurrency", lambda k, d=None: {"DALFOX_CHUNK": 1, "DALFOX_TARGETS": 4}.get(k, d))
        monkeypatch.setattr(settings, "workers", lambda t, d: d)
        monkeypatch.setattr(secrets, "oob", lambda: {})
        monkeypatch.setattr(params, "_dalfox_engine_id", lambda: "unverified-" + os.urandom(4).hex())
        events.reset(); events.configure(tmp_path); c = _C(tmp_path)
        calls = []
        base = _exec(META1 + R_ROW, 1)
        monkeypatch.setattr(params, "exec_tool", lambda *a, **k: (calls.append(1), base(*a, **k))[1])
        params._dalfox_xss_fast(c, ["http://h/p?q="], _Prof())
        params._dalfox_xss_fast(c, ["http://h/p?q="], _Prof())
        assert len(calls) == 2   # non-resumable -> re-ran


def _dfdir(tmp_path):
    return tmp_path / "raw" / "params" / "dalfox"


class TestCompletionValidation:
    # review-r11#1: a completion is trusted to SKIP only if the artifact is present, unchanged (sha), parses
    # clean, AND agrees with the recorded outcome. Any tamper -> the chunk RE-RUNS (never a silent skip).
    def _clean(self, monkeypatch, tmp_path):
        c = _fresh(monkeypatch, tmp_path)
        monkeypatch.setattr(params, "exec_tool", _exec(META1 + R_ROW, 1))   # clean SUCCESS
        params._dalfox_xss_fast(c, ["http://h/p?q="], _Prof())
        return c

    def _reran(self, monkeypatch, c):
        calls = []
        base = _exec(META1 + R_ROW, 1)
        monkeypatch.setattr(params, "exec_tool", lambda *a, **k: (calls.append(1), base(*a, **k))[1])
        params._dalfox_xss_fast(c, ["http://h/p?q="], _Prof())
        return bool(calls)

    def _art(self, tmp_path):
        return next(_dfdir(tmp_path).glob("wu_*/attempt_*/findings_0.jsonl"))

    def _state(self, c):
        return c.run.raw_path("params", "dalfox", "chunks.state.json")

    def test_valid_completion_is_skipped(self, monkeypatch, tmp_path):
        c = self._clean(monkeypatch, tmp_path)
        assert self._reran(monkeypatch, c) is False            # untouched -> skipped

    def test_missing_artifact_reruns(self, monkeypatch, tmp_path):
        c = self._clean(monkeypatch, tmp_path)
        self._art(tmp_path).unlink()
        assert self._reran(monkeypatch, c) is True

    def test_malformed_artifact_reruns(self, monkeypatch, tmp_path):
        c = self._clean(monkeypatch, tmp_path)
        self._art(tmp_path).write_text("garbage{")            # sha + parse both fail
        assert self._reran(monkeypatch, c) is True

    def test_changed_but_parseable_artifact_reruns(self, monkeypatch, tmp_path):
        c = self._clean(monkeypatch, tmp_path)
        self._art(tmp_path).write_text(META0)                 # valid JSONL but sha differs + disagrees with SUCCESS
        assert self._reran(monkeypatch, c) is True

    def test_changed_evidence_contributes_no_findings(self, monkeypatch, tmp_path):
        # review-r12: a completion tampered to inject a FABRICATED finding is rejected by both the completion AND
        # the evidence digest — the chunk reruns AND the fabricated row is never aggregated.
        c = _fresh(monkeypatch, tmp_path)
        monkeypatch.setattr(params, "exec_tool", _exec(META0, 0))          # run1: clean-empty
        params._dalfox_xss_fast(c, ["http://h/p?q="], _Prof())
        assert c.run.added == []
        self._art(tmp_path).write_text(META1 + '{"type":"R","param":"q","data":"http://EVIL/x?q=1",'
                                               '"method":"GET","location":"Query"}\n')   # inject a fabricated finding
        calls = []
        base = _exec(META0, 0)                                              # rerun ALSO clean-empty: the ONLY possible
        monkeypatch.setattr(params, "exec_tool", lambda *a, **k: (calls.append(1), base(*a, **k))[1])   # finding source
        params._dalfox_xss_fast(c, ["http://h/p?q="], _Prof())             # would be the tampered evidence
        assert calls == [1]                                                # reran (completion digest failed)
        assert c.run.added == []                                            # tampered evidence NOT ingested (digest)

    def test_outcome_disagreement_reruns(self, monkeypatch, tmp_path):
        c = self._clean(monkeypatch, tmp_path)
        sp = self._state(c); st = json.loads(sp.read_text())
        st["chunks"]["0"]["outcome"] = "EMPTY"                # artifact has findings but state says EMPTY
        sp.write_text(json.dumps(st))
        assert self._reran(monkeypatch, c) is True

    def test_path_traversal_rel_rejected(self, monkeypatch, tmp_path):
        c = self._clean(monkeypatch, tmp_path)
        sp = self._state(c); st = json.loads(sp.read_text())
        st["chunks"]["0"]["rel"] = "../../../../etc/passwd"
        sp.write_text(json.dumps(st))
        assert self._reran(monkeypatch, c) is True

    def test_foreign_work_unit_rejected(self, monkeypatch, tmp_path):
        c = self._clean(monkeypatch, tmp_path)
        sp = self._state(c); st = json.loads(sp.read_text())
        st["work_unit"] = "SOME-OTHER-WORK-UNIT"
        sp.write_text(json.dumps(st))
        assert self._reran(monkeypatch, c) is True


class TestProvenance:
    def test_every_attempt_observation_reaches_run_add(self, monkeypatch, tmp_path):
        # review-r11#2: a finding seen in TWO attempts is passed to Run.add() BOTH times (distinct raw_refs, so
        # C09 merges provenance) — never pre-dedup'd. `matched` still counts the distinct id once.
        c = _fresh(monkeypatch, tmp_path)
        calls = []
        orig = c.run.add
        c.run.add = lambda e, rec: (calls.append((rec["id"], rec["raw_ref"])), orig(e, rec))[1]
        monkeypatch.setattr(params, "exec_tool", _exec(META1 + R_ROW, 2))   # attempt1: degraded WITH finding X
        params._dalfox_xss_fast(c, ["http://h/p?q="], _Prof())
        monkeypatch.setattr(params, "exec_tool", _exec(META1 + R_ROW, 1))   # attempt2: clean SUCCESS, same id X
        params._dalfox_xss_fast(c, ["http://h/p?q="], _Prof())
        raw_refs = {rr for (i, rr) in calls if i.startswith("xss-candidate:")}
        assert len(raw_refs) == 2 and len(c.run.added) == 1   # both attempts' raw_refs reached add(); deduped to 1 entity


class TestMetaRowIsRead:
    """review#13 (Lumpy, P1): `_parse_dalfox_jsonl` validated only `findings_count`, so a batch with
    `meta.incomplete=true`, `SESSION_LOST` or `TRUNCATED_PER_HOST_CAP` parsed as clean and became
    resumably complete. dalfox reports those honestly — Quarry threw them away.

    Field names and values taken from a REAL 3.2.0 artifact and from dalfox's own source
    (`src/cmd/mod.rs` error codes, `src/cmd/scan/output.rs` statuses)."""

    @staticmethod
    def _meta(**kw):
        import json
        m = {"dalfox_version": "3.2.0", "findings_count": 0, "incomplete": False,
             "total_requests": 21, "targets_deduplicated": 0,
             "target_summary": [{"target": "http://h/a", "status": "clean", "findings_count": 0}]}
        m.update(kw)
        return json.dumps({"meta": m}) + "\n"

    @staticmethod
    def _t(target, status, code=None):
        d = {"target": target, "status": status, "findings_count": 0}
        if code:
            d["error_code"] = code
        return d

    def test_a_clean_batch_is_complete_and_execution_done(self):
        _f, art = _art(self._meta())
        assert art.readable and art.complete and art.execution_done
        assert art.skipped == () and art.version == "3.2.0"
        assert art.total_requests == 21 and art.deduplicated == 0
        assert art.coverage_reason() == "every target covered"

    def test_meta_incomplete_is_NOT_a_finished_batch(self):
        """`meta.incomplete` is dalfox's own "do not trust this run" flag."""
        _f, art = _art(self._meta(incomplete=True))
        assert art.readable, "the artifact still PARSES — that is a separate question"
        assert not art.complete and not art.execution_done
        assert "session died" in art.coverage_reason()

    def test_a_SKIPPED_target_is_not_covered(self):
        _f, art = _art(self._meta(target_summary=[
            self._t("http://h/a", "clean"), self._t("http://h/b", "skipped", "SESSION_LOST")]))
        assert art.readable and not art.complete
        assert len(art.skipped) == 1 and art.skipped[0][0] == "http://h/b"

    def test_a_RETRIABLE_omission_keeps_the_chunk_unfinished(self):
        """The environment failed; a later attempt may cover it. The chunk must NOT be recorded done."""
        for code in ("CONNECTION_FAILED", "DNS_RESOLUTION_FAILED", "TLS_HANDSHAKE_FAILED",
                     "REQUEST_TIMEOUT", "SESSION_LOST"):
            _f, art = _art(self._meta(target_summary=[self._t("http://h/b", "skipped", code)]))
            assert art.retriable and not art.execution_done, code
            assert code in art.coverage_reason()

    def test_a_DETERMINISTIC_omission_finishes_the_chunk_and_is_REPORTED(self):
        """Retrying omits exactly the same targets for ever, so execution is done — and the gap is
        coverage, not a retry (`quarry-execution-vs-coverage`)."""
        for code in ("CONTENT_TYPE_MISMATCH", "TRUNCATED_PER_HOST_CAP"):
            _f, art = _art(self._meta(target_summary=[self._t("http://h/b", "skipped", code)]))
            assert art.deterministic and art.execution_done, code
            assert not art.complete, "…but the batch is NOT complete"
            assert code in art.coverage_reason()

    def test_an_UNKNOWN_code_is_treated_as_retriable(self):
        """dalfox may gain other incomplete states. An omission we cannot explain must not silently
        become a finished chunk."""
        _f, art = _art(self._meta(target_summary=[self._t("http://h/b", "skipped", "SOMETHING_NEW")]))
        assert art.unclassified and not art.execution_done
        assert "unclassified" in art.coverage_reason()

    def test_status_incomplete_counts_as_not_covered(self):
        """dalfox: "the distinction that matters to a consumer: neither is `clean`"."""
        _f, art = _art(self._meta(target_summary=[
            self._t("http://h/b", "incomplete", "SESSION_LOST")]))
        assert len(art.skipped) == 1 and not art.execution_done

    def test_a_TORN_artifact_is_unreadable_regardless_of_meta(self):
        """Structural validity and scan completeness are DIFFERENT questions — the whole point of the
        split. A perfect meta row does not rescue a torn artifact."""
        _f, art = _art(self._meta(findings_count=5))          # count disagrees with 0 findings
        assert not art.readable and not art.execution_done

    def test_findings_survive_an_incomplete_batch(self):
        """Valid findings are kept whatever the batch's disposition — they are evidence we paid for."""
        f, art = _art(self._meta(findings_count=1, incomplete=True) + R_ROW)
        assert len(f) == 1 and art.readable and not art.execution_done

    def test_the_REAL_302_artifact_shape_parses(self):
        """The exact meta row a 3.2.0 run produced on this box."""
        real = ('{"meta":{"dalfox_version":"3.2.0","dedup_mode":"exact","findings_count":0,'
                '"incomplete":false,"scan_duration_ms":1044,"target_summary":[{"findings_count":0,'
                '"status":"clean","target":"http://127.0.0.1:8731/?q=1"}],"targets":["batch.txt"],'
                '"targets_deduplicated":0,"total_requests":21}}\n')
        _f, art = _art(real)
        assert art.readable and art.complete and art.execution_done and art.version == "3.2.0"


class TestTheCapCannotDecideOurMembership:
    """dalfox's `--max-targets-per-host` (default 100) DROPS targets past it. Preventative (Lumpy): pass
    a value that cannot truncate the chunk we submitted, so the cap can never decide Quarry's membership
    whatever `DALFOX_CHUNK` is set to. The meta row is still parsed — dalfox may gain other states."""

    @staticmethod
    def _cmd(batch_len):
        prof = type("P", (), {"http_rl": 0})()
        return params._dalfox_cmd("b.txt", "o.jsonl", prof, batch_len)

    def test_the_per_host_value_covers_the_whole_chunk(self):
        for n in (1, 40, 250, 5000):
            cmd = self._cmd(n)
            i = cmd.index("--max-targets-per-host")
            assert int(cmd[i + 1]) >= n, n

    def test_a_chunk_LARGER_than_dalfox_default_is_not_truncated(self):
        """The case that bites: an operator raises DALFOX_CHUNK past dalfox's default of 100."""
        cmd = self._cmd(250)
        assert int(cmd[cmd.index("--max-targets-per-host") + 1]) == 250

    def test_it_is_never_zero(self):
        assert int(self._cmd(0)[self._cmd(0).index("--max-targets-per-host") + 1]) >= 1


class TestARetryOwesOnlyWhatFailed:
    """review#14 (Lumpy, P1): a chunk that failed on ONE `SESSION_LOST` target re-ran its whole input
    file on resume — re-requesting every target that had already succeeded. That is someone else's site
    hit again for nothing.

    dalfox names the affected URLs in `target_summary`, so the persisted remainder is exactly those:
    covered targets stay covered, deterministic omissions stay terminal, and only retriable/unknown
    omissions are rescheduled."""

    A, B, C = "http://h/a?q=", "http://h/b?q=", "http://h/c?q="

    @staticmethod
    def _art(entries, count=0, incomplete=False):
        import json as _json
        return _json.dumps({"meta": {
            "dalfox_version": "3.2.0", "findings_count": count, "incomplete": incomplete,
            "target_summary": entries}}) + "\n"

    @staticmethod
    def _t(url, status="clean", code=None):
        d = {"target": url, "status": status, "findings_count": 0}
        if code:
            d["error_code"] = code
        return d

    def _lane(self, monkeypatch, tmp_path, chunk=3):
        monkeypatch.setattr(settings, "concurrency",
                            lambda k, d=None: {"DALFOX_CHUNK": chunk, "DALFOX_TARGETS": 4}.get(k, d))
        monkeypatch.setattr(settings, "workers", lambda t, d: d)
        monkeypatch.setattr(secrets, "oob", lambda: {})
        monkeypatch.setattr(params, "_dalfox_engine_id", lambda: "v3.2.0")
        events.reset(); events.configure(tmp_path)
        return _C(tmp_path)

    @staticmethod
    def _exec_capture(artifact, rc, seen):
        def fx(t, cmd, timeout=None, **k):
            bf = pathlib.Path(cmd[cmd.index("file") + 1])
            seen.append([u for u in bf.read_text().splitlines() if u])
            cf = pathlib.Path(cmd[cmd.index("-o") + 1]); cf.parent.mkdir(parents=True, exist_ok=True)
            cf.write_text(artifact)
            return RunResult("dalfox", cmd, Status.SUCCESS if rc in (0, 1) else Status.FAILED, rc, 0.1,
                             cf, 0, meta={"started": True})
        return fx

    def test_only_the_RETRIABLE_target_is_re_requested(self, monkeypatch, tmp_path):
        c = self._lane(monkeypatch, tmp_path)
        cands = [self.A, self.B, self.C]
        first = self._art([self._t(self.A), self._t(self.B),
                           self._t(self.C, "skipped", "SESSION_LOST")])
        seen: list = []
        monkeypatch.setattr(params, "exec_tool", self._exec_capture(first, 0, seen))
        params._dalfox_xss_fast(c, cands, _Prof())
        assert seen == [cands], "the first attempt scans the whole chunk"
        st = _state(c)
        assert st["remainder"]["0"] == [self.C], st.get("remainder")
        assert "0" not in st["chunks"], "the chunk is not done"

        # …resume: ONLY the owed target goes back out
        seen2: list = []
        monkeypatch.setattr(params, "exec_tool",
                            self._exec_capture(self._art([self._t(self.C)]), 0, seen2))
        params._dalfox_xss_fast(c, cands, _Prof())
        assert seen2 == [[self.C]], seen2
        st2 = _state(c)
        assert "0" in st2["chunks"], "the chunk settles clean once the owed target lands"
        assert "0" not in st2.get("remainder", {}), "…and owes nothing"

    def test_a_DETERMINISTIC_omission_is_never_rescheduled(self, monkeypatch, tmp_path):
        """Retrying omits exactly the same target for ever. It is a terminal coverage gap."""
        c = self._lane(monkeypatch, tmp_path)
        cands = [self.A, self.B]
        art = self._art([self._t(self.A), self._t(self.B, "skipped", "TRUNCATED_PER_HOST_CAP")])
        seen: list = []
        monkeypatch.setattr(params, "exec_tool", self._exec_capture(art, 0, seen))
        params._dalfox_xss_fast(c, cands, _Prof())
        st = _state(c)
        assert "0" in st["chunks"], "execution IS done — nothing to retry"
        assert not st.get("remainder", {}).get("0"), "and nothing is owed"

    def test_an_UNKNOWN_code_is_owed_too(self, monkeypatch, tmp_path):
        c = self._lane(monkeypatch, tmp_path)
        cands = [self.A, self.B]
        art = self._art([self._t(self.A), self._t(self.B, "skipped", "SOMETHING_NEW")])
        monkeypatch.setattr(params, "exec_tool", self._exec_capture(art, 0, []))
        params._dalfox_xss_fast(c, cands, _Prof())
        assert _state(c)["remainder"]["0"] == [self.B]

    def test_an_UNREADABLE_artifact_owes_the_WHOLE_chunk(self, monkeypatch, tmp_path):
        """An artifact we could not read says nothing about individual targets. Naming a subset there
        would silently drop the rest."""
        c = self._lane(monkeypatch, tmp_path)
        cands = [self.A, self.B]
        monkeypatch.setattr(params, "exec_tool",
                            self._exec_capture('{"meta":{"findings_count":9}}\n', 0, []))
        params._dalfox_xss_fast(c, cands, _Prof())
        st = _state(c)
        assert not st.get("remainder", {}).get("0"), "no named remainder"
        assert "0" not in st["chunks"], "…so the whole chunk is still owed"
        seen: list = []
        monkeypatch.setattr(params, "exec_tool",
                            self._exec_capture(self._art([self._t(self.A), self._t(self.B)]), 0, seen))
        params._dalfox_xss_fast(c, cands, _Prof())
        assert seen == [cands], "the full chunk re-runs, because we never learned which target failed"

    def test_findings_from_the_partial_attempt_are_RETAINED_and_deduped(self, monkeypatch, tmp_path):
        c = self._lane(monkeypatch, tmp_path)
        cands = [self.A, self.B]
        first = (self._art([self._t(self.A, "findings"), self._t(self.B, "skipped", "SESSION_LOST")],
                           count=1) + R_ROW)
        monkeypatch.setattr(params, "exec_tool", self._exec_capture(first, 1, []))
        params._dalfox_xss_fast(c, cands, _Prof())
        n_after_first = len([a for a in c.run.added if a.get("template")])
        assert n_after_first >= 1, "the partial attempt's finding is evidence and is kept"
        # the retry re-reports the SAME finding: it must not double-count
        monkeypatch.setattr(params, "exec_tool",
                            self._exec_capture(self._art([self._t(self.B, "findings")], count=1)
                                               + R_ROW, 1, []))
        params._dalfox_xss_fast(c, cands, _Prof())
        ids = [a["id"] for a in c.run.added if a.get("template")]
        assert len(ids) == len(set(ids)), ids

    def test_a_stale_remainder_naming_nothing_falls_back_to_the_chunk(self, monkeypatch, tmp_path):
        """The candidate set changed under us: a remembered URL is gone. Re-run the chunk rather than
        scan nothing and call it done."""
        c = self._lane(monkeypatch, tmp_path)
        art = self._art([self._t(self.A), self._t(self.B, "skipped", "SESSION_LOST")])
        monkeypatch.setattr(params, "exec_tool", self._exec_capture(art, 0, []))
        params._dalfox_xss_fast(c, [self.A, self.B], _Prof())
        assert _state(c)["remainder"]["0"] == [self.B]
        seen: list = []
        monkeypatch.setattr(params, "exec_tool",
                            self._exec_capture(self._art([self._t(self.A), self._t(self.C)]), 0, seen))
        params._dalfox_xss_fast(c, [self.A, self.C], _Prof())      # B no longer a candidate
        assert seen == [[self.A, self.C]], seen

    def test_a_MIXED_chunk_owes_only_the_retriable_one(self, monkeypatch, tmp_path):
        """Both kinds in one chunk: the deterministic omission is terminal coverage and must NOT be
        rescheduled alongside the retriable one."""
        c = self._lane(monkeypatch, tmp_path)
        cands = [self.A, self.B, self.C]
        art = self._art([self._t(self.A),
                         self._t(self.B, "skipped", "TRUNCATED_PER_HOST_CAP"),
                         self._t(self.C, "skipped", "SESSION_LOST")])
        monkeypatch.setattr(params, "exec_tool", self._exec_capture(art, 0, []))
        params._dalfox_xss_fast(c, cands, _Prof())
        st = _state(c)
        assert "0" not in st["chunks"], "a retriable omission keeps the chunk unfinished"
        assert st["remainder"]["0"] == [self.C], st["remainder"]

    def test_an_unreadable_artifact_owes_the_chunk_even_WITH_a_target_summary(self, monkeypatch,
                                                                             tmp_path):
        """The meta row can name a skip while the artifact is still torn (count disagreement). We do not
        know what the rest of the file lost, so the whole chunk stays owed."""
        c = self._lane(monkeypatch, tmp_path)
        cands = [self.A, self.B]
        torn = self._art([self._t(self.A), self._t(self.B, "skipped", "SESSION_LOST")], count=7)
        monkeypatch.setattr(params, "exec_tool", self._exec_capture(torn, 0, []))
        params._dalfox_xss_fast(c, cands, _Prof())
        st = _state(c)
        assert "0" not in st["chunks"]
        assert not st.get("remainder", {}).get("0"), "an unreadable artifact names no remainder"
        seen: list = []
        monkeypatch.setattr(params, "exec_tool",
                            self._exec_capture(self._art([self._t(self.A), self._t(self.B)]), 0, seen))
        params._dalfox_xss_fast(c, cands, _Prof())
        assert seen == [cands], "so the FULL chunk re-runs"

    def _cov(self, tmp_path, tag, measure):
        evs = [json.loads(x) for x in (tmp_path / tag / "events.jsonl").read_text().splitlines()]
        return [e for e in evs if e.get("measure") == measure]

    def _lane_in(self, monkeypatch, tmp_path, tag):
        """A FRESH lifecycle over the same project: new events sink, same chunk state on disk."""
        monkeypatch.setattr(settings, "concurrency",
                            lambda k, d=None: {"DALFOX_CHUNK": 3, "DALFOX_TARGETS": 4}.get(k, d))
        monkeypatch.setattr(settings, "workers", lambda t, d: d)
        monkeypatch.setattr(secrets, "oob", lambda: {})
        monkeypatch.setattr(params, "_dalfox_engine_id", lambda: "v3.2.0")
        events.reset(); events.configure(tmp_path / tag)
        return _C(tmp_path)

    def test_a_terminal_gap_SURVIVES_the_successful_retry(self, monkeypatch, tmp_path):
        """review#15 (Lumpy, P1): attempt 1 truncates `b` and loses `c`; attempt 2 re-runs `c` alone and
        succeeds. `b`'s omission must still be named — in a FRESH process — and neither `a` nor `b` may
        be requested again."""
        cands = [self.A, self.B, self.C]
        seen: list = []

        c1 = self._lane_in(monkeypatch, tmp_path, "run1")
        monkeypatch.setattr(params, "exec_tool", self._exec_capture(
            self._art([self._t(self.A),
                       self._t(self.B, "skipped", "TRUNCATED_PER_HOST_CAP"),
                       self._t(self.C, "skipped", "SESSION_LOST")]), 0, seen))
        params._dalfox_xss_fast(c1, cands, _Prof())

        c2 = self._lane_in(monkeypatch, tmp_path, "run2")     # fresh lifecycle, same state file
        monkeypatch.setattr(params, "exec_tool",
                            self._exec_capture(self._art([self._t(self.C)]), 0, seen))
        params._dalfox_xss_fast(c2, cands, _Prof())

        assert seen == [cands, [self.C]], seen
        assert not any(self.A in b for b in seen[1:]), "a must not be re-requested"
        assert not any(self.B in b for b in seen[1:]), "b must not be re-requested"

        rows = self._cov(tmp_path, "run2", "dalfox_targets")
        assert rows, "the terminal gap must be re-reported by the run that did NOT observe it"
        assert rows[-1]["omitted"] == 1 and self.B in rows[-1]["reason"]
        assert "TRUNCATED_PER_HOST_CAP" in rows[-1]["reason"]
        # review#16 (Lumpy): a truncating ceiling is NOT a timeout. The manifest is operator evidence,
        # so each code carries the kind that describes it — and both still fold as gaps.
        assert rows[-1]["kind"] == events.COVERAGE_CAP, rows[-1]["kind"]

        st = _state(c2)
        assert st["terminal"]["0"] == [{"url": self.B, "code": "TRUNCATED_PER_HOST_CAP"}]
        assert "0" in st["chunks"] and not st.get("remainder", {}).get("0")

    def test_the_terminal_set_does_not_double_count_across_attempts(self, monkeypatch, tmp_path):
        """Two attempts observing the SAME truncation must leave one row, not two."""
        cands = [self.A, self.B, self.C]
        art = self._art([self._t(self.A),
                         self._t(self.B, "skipped", "TRUNCATED_PER_HOST_CAP"),
                         self._t(self.C, "skipped", "SESSION_LOST")])
        for tag in ("r1", "r2"):
            c = self._lane_in(monkeypatch, tmp_path, tag)
            monkeypatch.setattr(params, "exec_tool", self._exec_capture(art, 0, []))
            params._dalfox_xss_fast(c, cands, _Prof())
        st = _state(self._lane_in(monkeypatch, tmp_path, "r3"))
        assert len(st["terminal"]["0"]) == 1, st["terminal"]

    def test_a_run_that_scans_NOTHING_still_reports_the_gap(self, monkeypatch, tmp_path):
        """Everything already complete: the chunk is skipped entirely, and the terminal gap must still
        reach this run's manifest."""
        cands = [self.A, self.B]
        c1 = self._lane_in(monkeypatch, tmp_path, "a1")
        monkeypatch.setattr(params, "exec_tool", self._exec_capture(
            self._art([self._t(self.A), self._t(self.B, "skipped", "TRUNCATED_PER_HOST_CAP")]), 0, []))
        params._dalfox_xss_fast(c1, cands, _Prof())
        assert "0" in _state(c1)["chunks"], "deterministic-only -> the chunk IS done"

        called: list = []
        c2 = self._lane_in(monkeypatch, tmp_path, "a2")
        monkeypatch.setattr(params, "exec_tool",
                            lambda *a, **k: called.append(1) or pytest.fail("re-scanned a done chunk"))
        params._dalfox_xss_fast(c2, cands, _Prof())
        assert called == []
        rows = self._cov(tmp_path, "a2", "dalfox_targets")
        assert rows and rows[-1]["omitted"] == 1 and self.B in rows[-1]["reason"]

    def test_each_terminal_code_carries_the_kind_that_DESCRIBES_it(self, monkeypatch, tmp_path):
        """review#16 (Lumpy): `TRUNCATED_PER_HOST_CAP` and `CONTENT_TYPE_MISMATCH` are not timeouts, and
        the manifest is operator evidence — a misleading label must not become permanent vocabulary."""
        cands = [self.A, self.B, self.C]
        c = self._lane_in(monkeypatch, tmp_path, "k1")
        monkeypatch.setattr(params, "exec_tool", self._exec_capture(
            self._art([self._t(self.A),
                       self._t(self.B, "skipped", "TRUNCATED_PER_HOST_CAP"),
                       self._t(self.C, "skipped", "CONTENT_TYPE_MISMATCH")]), 0, []))
        params._dalfox_xss_fast(c, cands, _Prof())
        rows = self._cov(tmp_path, "k1", "dalfox_targets")
        by_kind = {r["kind"]: r for r in rows}
        assert events.COVERAGE_TIMEOUT not in by_kind, "neither of these is a timeout"
        assert by_kind[events.COVERAGE_CAP]["omitted"] == 1
        assert self.B in by_kind[events.COVERAGE_CAP]["reason"]
        assert by_kind[events.COVERAGE_TOOL_OMISSION]["omitted"] == 1
        assert self.C in by_kind[events.COVERAGE_TOOL_OMISSION]["reason"]
        # distinct UNITS, or reconciliation (latest per source+unit) would drop one of them
        assert len({r["unit"] for r in rows}) == 2, [r["unit"] for r in rows]

    def test_a_RETRIABLE_failure_keeps_the_timeout_kind(self):
        """`timeout` is right for these: input the target/network cost us."""
        from quarry_recon.phases import params as P
        assert set(P._DALFOX_RETRIABLE) >= {"REQUEST_TIMEOUT", "CONNECTION_FAILED", "SESSION_LOST"}
        assert set(P._DALFOX_TERMINAL_KIND) == set(P._DALFOX_DETERMINISTIC)
        assert events.COVERAGE_TIMEOUT not in P._DALFOX_TERMINAL_KIND.values()

    def test_a_tool_omission_still_gates_the_verdict_as_a_GAP(self):
        """Renaming the disposition must not soften it: only SAMPLE and PROVIDER are soft limits."""
        import inspect
        from quarry_recon import store
        src = inspect.getsource(store)
        i = src.index("COVERAGE_SAMPLE, events.COVERAGE_PROVIDER")
        assert "coverage_limits.append" in src[i:i + 200]
        assert events.COVERAGE_TOOL_OMISSION not in (events.COVERAGE_SAMPLE, events.COVERAGE_PROVIDER)


def _pytest_raises(exc):
    return pytest.raises(exc)


class TestBlindXssChannel:
    """4.3.D under the agreed contract (review#12, Lumpy):

      * `--blind-oob` is the channel — dalfox mints a callback PER PAYLOAD and correlates each
        interaction to target/param/location/method/payload, so a beacon names the injection that
        produced it.
      * CORRELATION IS DALFOX'S, always. It mints the nonce, registers, polls, waits and maps the hit
        back; Quarry imports it, so findings carry `oob_owner: dalfox`. The SERVER is a separate
        ownership question: ProjectDiscovery's public pool by default (its operator sees the raw
        callbacks, and Quarry holds no credential for it), yours when `oob.callback_server` is set —
        and only then does Quarry own credential handling (review#19, Lumpy).
      * Never auto-enabled, but ONE gate: `MODES.BLIND_XSS` arms it, and the backend follows the
        configured keys (self-hosted when `oob.callback_server` is set, public otherwise).
      * Exactly ONE channel: `--blind-oob`. Nothing else is emitted, and no configuration adds a
        second one, so a finding has one callback lifecycle and one correlation owner.
    """

    class _P:
        http_rl = 0
        blind_xss = False

    @staticmethod
    def _oob(monkeypatch, **kw):
        monkeypatch.setattr(secrets, "oob", lambda: dict(kw))

    @classmethod
    def _P_armed(cls):
        p = cls._P(); p.blind_xss = True; return p

    def _cmd(self, monkeypatch, prof, **oob):
        self._oob(monkeypatch, **oob)
        return params._dalfox_cmd("b.txt", "o.jsonl", prof, 1)

    def test_it_is_OFF_unless_explicitly_armed(self, monkeypatch):
        cmd = self._cmd(monkeypatch, self._P(), callback_server="oob.mine.test")
        assert not any(c.startswith("--blind-oob") for c in cmd), cmd
        plan = params._blind_oob_plan(self._P())
        assert not plan["armed"] and "MODES.BLIND_XSS is off" in plan["reason"]

    def test_a_self_hosted_server_is_used_with_its_secret(self, monkeypatch, tmp_path):
        """review#17 (Lumpy): the token must NOT reach argv — `/proc/<pid>/cmdline` is readable by every
        process of this user, and redacting our own logs does not change that. dalfox reads
        `scan.blind_oob_secret` from a `--config` TOML, so it travels in a 0600 file."""
        import stat
        self._oob(monkeypatch, callback_server="oob.mine.test", auth_token="T0K")
        p = self._P(); p.blind_xss = True
        out = tmp_path / "findings.jsonl"
        cmd = params._dalfox_cmd(tmp_path / "b.txt", out, p, 1)
        assert "--blind-oob=oob.mine.test" in cmd, cmd
        assert "--blind-oob-secret" not in cmd, "the secret must never be an argument"
        assert not any("T0K" in c for c in cmd), cmd
        assert "--config" not in cmd, "the builder must not create a file it cannot destroy"
        # …the CALLER owns the credential's lifetime, so the flag only appears when it hands one over
        with params.blind_oob_credential("T0K") as cred:
            with_cred = params._dalfox_cmd(tmp_path / "b.txt", out, p, 1, cred)
            assert with_cred[with_cred.index("--config") + 1] == str(cred)
            assert not any("T0K" in c for c in with_cred), with_cred
            assert stat.S_IMODE(cred.stat().st_mode) == 0o600, oct(cred.stat().st_mode)
        del stat

    def test_no_config_file_is_written_without_a_secret(self, monkeypatch, tmp_path):
        self._oob(monkeypatch, callback_server="oob.mine.test")     # server, no token
        p = self._P(); p.blind_xss = True
        cmd = params._dalfox_cmd(tmp_path / "b.txt", tmp_path / "o.jsonl", p, 1)
        assert "--config" not in cmd and not list(tmp_path.glob("*.toml"))

    def test_the_secret_never_reaches_the_recorded_command(self, monkeypatch, tmp_path):
        """The work-unit config and every telemetry copy of the command must be secret-free too."""
        self._oob(monkeypatch, callback_server="oob.mine.test", auth_token="T0K")
        p = self._P(); p.blind_xss = True
        cmd = params._dalfox_cmd(tmp_path / "b.txt", tmp_path / "o.jsonl", p, 1)
        assert "T0K" not in " ".join(str(c) for c in cmd)

    def test_the_server_is_ONE_argv_token(self, monkeypatch):
        """`--blind-oob[=<domains>]` takes its value attached. A separate `=host` argument would be
        parsed as a TARGET — measured against the 3.2.0 binary."""
        p = self._P(); p.blind_xss = True
        cmd = self._cmd(monkeypatch, p, callback_server="oob.mine.test")
        assert "=oob.mine.test" not in cmd, cmd
        assert not any(c.startswith("=") for c in cmd)

    def test_ONE_gate_arms_it_and_public_is_the_plain_default(self, monkeypatch):
        """Lumpy, 2026-08-06: a second flag for the PUBLIC backend was inconsistent — nuclei's OAST and
        Quarry's own SSRF probes already use public interactsh ungated — and it put the common case (no
        self-hosted server) behind two flags, which mostly meant no blind XSS at all. Arming IS the
        consent."""
        p = self._P(); p.blind_xss = True
        cmd = self._cmd(monkeypatch, p)                     # no callback_server configured
        assert "--blind-oob" in cmd and not any(c.startswith("--blind-oob=") for c in cmd)
        plan = params._blind_oob_plan(p)
        assert plan["armed"] and plan["backend"] == "public" and plan["channel"] == "native"
        assert "REFUSED" not in plan["reason"]

    def test_the_plan_REASON_names_whose_server_it_is(self, monkeypatch):
        """The reason is what the operator reads in the record. `backend: public` is a field name;
        "ProjectDiscovery's pool, its operator sees the raw callbacks" is the fact behind it."""
        self._oob(monkeypatch)
        pub = params._blind_oob_plan(self._P_armed())["reason"]
        assert "ProjectDiscovery" in pub and "raw callbacks" in pub
        self._oob(monkeypatch, callback_server="oob.mine.test")
        own = params._blind_oob_plan(self._P_armed())["reason"]
        assert "ProjectDiscovery" not in own and "oob.mine.test" in own

    def test_a_configured_server_moves_the_backend_without_another_flag(self, monkeypatch):
        p = self._P(); p.blind_xss = True
        cmd = self._cmd(monkeypatch, p, callback_server="oob.mine.test")
        assert "--blind-oob=oob.mine.test" in cmd

    def test_the_token_is_optional_for_a_self_hosted_server(self, monkeypatch):
        """Plenty of interactsh instances run open."""
        p = self._P(); p.blind_xss = True
        cmd = self._cmd(monkeypatch, p, callback_server="oob.mine.test")   # no token
        assert "--blind-oob=oob.mine.test" in cmd and "--config" not in cmd
        assert params._blind_oob_plan(p)["secret"] == ""

    def test_there_is_exactly_ONE_channel(self, monkeypatch):
        """Blind XSS is `--blind-oob` and nothing else: one channel means one callback lifecycle and
        one correlation owner per finding. The `-b` assertions here are regression guards — a second
        channel would double the blind payloads and the requests they cost."""
        p = self._P(); p.blind_xss = True
        cmd = self._cmd(monkeypatch, p, callback_server="oob.mine.test")
        plan = params._blind_oob_plan(p)
        assert plan["channel"] == "native" and plan["armed"] and plan["backend"] == "self-hosted"
        assert "--blind-oob=oob.mine.test" in cmd and "-b" not in cmd

    def test_an_unarmed_profile_emits_no_channel_at_all(self, monkeypatch):
        cmd = self._cmd(monkeypatch, self._P(), callback_server="oob.mine.test")
        assert not any(c.startswith("--blind-oob") for c in cmd) and "-b" not in cmd, cmd
        assert params._blind_oob_plan(self._P())["channel"] == "off"

    def test_the_arming_flags_do_not_fail_open_on_quoted_yaml(self):
        """An arming flag must never be enabled by a QUOTED string, and a quoted value must fail LOUD in
        validation rather than silently leave the lane disabled against operator intent."""
        import tempfile as _tf
        import pytest as _pt
        from quarry_recon.config import ProfileError, TargetProfile
        prof = TargetProfile.__new__(TargetProfile)
        prof.modes = {"BLIND_XSS": "true"}
        assert prof.blind_xss is False
        # …and a quoted value fails LOUD through the real loader
        for bad in ("BLIND_XSS",):
            f = pathlib.Path(_tf.mkdtemp()) / "target.yaml"
            f.write_text("target: acme.com\nscope:\n  in: [acme.com]\n"
                         f"MODES:\n  {bad}: \"true\"\n")
            with _pt.raises(ProfileError):
                TargetProfile.load(f)

    def test_every_arming_flag_defaults_to_OFF(self):
        """An absent mode must never arm a lane: public OOB sends callbacks to a third party, and that
        must not happen because a key was missing."""
        from quarry_recon.config import TargetProfile
        prof = TargetProfile.__new__(TargetProfile)
        prof.modes = {}
        assert prof.blind_xss is False
        assert not hasattr(prof, "blind_xss_public"), "the second gate is gone, not renamed"
        assert not hasattr(prof, "blind_xss_dual"), "dual mode is gone, not renamed"

    def test_an_OOB_finding_records_dalfox_as_the_OWNER(self):
        row = ('{"type":"V","param":"q","data":"http://h/p?q=1","method":"GET","location":"Query",'
               '"detection_method":"oob","confidence_reason":"callback received","inject_type":"inHTML"}\n')
        f, art = _art(_meta(1) + row)
        assert art.readable and f[0]["oob_owner"] == "dalfox"
        assert f[0]["detection_method"] == "oob"
        assert f[0]["confidence_reason"] == "callback received" and f[0]["inject_type"] == "inHTML"

    def test_a_NON_oob_finding_claims_no_oob_owner(self):
        f, _art_ = _art(META1 + R_ROW)
        assert "oob_owner" not in f[0]

    def test_the_credential_file_is_DESTROYED_after_the_run(self):
        """review#18 (Lumpy): a 0600 file is right DURING execution and wrong afterwards."""
        import stat
        with params.blind_oob_credential("SEKRET") as cfg:
            assert cfg.is_file() and stat.S_IMODE(cfg.stat().st_mode) == 0o600
            assert json.loads(cfg.read_text()) == {"scan": {"blind_oob_secret": "SEKRET"}}
            kept = cfg
        assert not kept.exists(), "the credential outlived the scan"
        assert not kept.parent.exists(), "…and so did its directory"

    def test_it_is_destroyed_even_when_the_body_RAISES(self):
        kept = None
        with pytest.raises(RuntimeError):
            with params.blind_oob_credential("SEKRET") as cfg:
                kept = cfg
                raise RuntimeError("timeout / parse failure / runner exception")
        assert kept is not None and not kept.exists()

    def test_it_never_lives_in_the_RUN_directory(self, tmp_path):
        """It would otherwise reach raw publication, manifests, exports, digests and resume artifacts."""
        with params.blind_oob_credential("SEKRET") as cfg:
            assert tmp_path not in cfg.parents, cfg
            assert "raw" not in cfg.parts and "recon" not in cfg.parts, cfg

    def test_the_value_is_SERIALIZED_not_interpolated(self):
        """A token with quotes and backslashes must survive intact — escaping is the serializer's job."""
        nasty = 'tok"with\\quotes\nand\tcontrol'
        with params.blind_oob_credential(nasty) as cfg:
            assert json.loads(cfg.read_text())["scan"]["blind_oob_secret"] == nasty

    def test_an_EXISTING_path_or_symlink_is_refused_not_followed(self, tmp_path, monkeypatch):
        """`O_CREAT | O_EXCL | O_NOFOLLOW`: a planted symlink must not be written through."""
        import tempfile as _tf
        victim = tmp_path / "victim"
        victim.write_text("untouched")
        d = pathlib.Path(_tf.mkdtemp(prefix=params._OOB_CRED_PREFIX))
        (d / ("cfg" + params._OOB_CRED_SUFFIX)).symlink_to(victim)
        monkeypatch.setattr(_tf, "mkdtemp", lambda *a, **k: str(d))
        monkeypatch.setattr(params.__dict__.get("tempfile", _tf), "mkdtemp",
                            lambda *a, **k: str(d), raising=False)
        # DOCTRINE (review#19): a refused path RAISES — it must not degrade into an unauthenticated run
        with _pytest_raises(params.OobCredentialError):
            with params.blind_oob_credential("SEKRET"):
                pass
        assert victim.read_text() == "untouched", "the symlink target was written through"
        # …and the refusal leaves NO litter: unlinking a symlink removes the link, not its target
        assert not d.exists(), "a refused creation left its directory behind"
        assert victim.exists(), "…and it must not have deleted the target"

    def test_no_file_at_all_without_a_secret(self):
        with params.blind_oob_credential("") as cfg:
            assert cfg is None

    def test_a_stale_DANGLING_link_is_swept_too(self):
        """A refused creation, or a killed run, can leave a symlink whose target is gone. `is_file()`
        follows the link and answers False for a dangling one — which left the litter for ever."""
        import tempfile as _tf, os as _os, time as _t
        d = pathlib.Path(_tf.mkdtemp(prefix=params._OOB_CRED_PREFIX))
        (d / ("cfg" + params._OOB_CRED_SUFFIX)).symlink_to(d / "does-not-exist")
        old = _t.time() - 7200
        _os.utime(d, (old, old))
        assert params.sweep_stale_oob_creds() >= 1
        assert not d.exists(), "a dangling link kept its directory alive"

    def test_a_stale_credential_from_a_KILLED_run_is_swept(self):
        import tempfile as _tf, os as _os, time as _t
        d = pathlib.Path(_tf.mkdtemp(prefix=params._OOB_CRED_PREFIX))
        f = d / ("cfg" + params._OOB_CRED_SUFFIX)
        f.write_text('{"scan":{"blind_oob_secret":"LEFTOVER"}}')
        old = _t.time() - 7200
        _os.utime(d, (old, old))
        assert params.sweep_stale_oob_creds() >= 1
        assert not f.exists() and not d.exists()

    def test_the_sweep_leaves_a_LIVE_scans_credential_alone(self):
        with params.blind_oob_credential("SEKRET") as cfg:
            params.sweep_stale_oob_creds()
            assert cfg.is_file(), "a running scan's credential must not be swept"

    def test_the_sweep_touches_nothing_it_did_not_create(self):
        import tempfile as _tf
        other = pathlib.Path(_tf.mkdtemp(prefix="someone-elses-"))
        keep = other / "important.json"
        keep.write_text("x")
        import os as _os, time as _t
        old = _t.time() - 7200
        _os.utime(other, (old, old))
        # …and an EMPTY foreign directory must survive too: a broad glob would rmdir it
        empty = pathlib.Path(_tf.mkdtemp(prefix="someone-elses-empty-"))
        _os.utime(empty, (old, old))
        params.sweep_stale_oob_creds()
        assert keep.exists(), "the sweep is not a glob over the temp dir"
        assert empty.is_dir(), "the sweep removed a directory it did not create"

    def test_the_lane_sweeps_before_it_writes_a_new_one(self):
        import inspect
        src = inspect.getsource(params._dalfox_xss_fast)
        assert "sweep_stale_oob_creds()" in src

    def test_a_credential_failure_REFUSES_rather_than_running_unauthenticated(self, monkeypatch):
        """review#19 (Lumpy): yielding None on failure still emitted `--blind-oob=<server>` without
        `--config`, so an operator who configured an AUTHENTICATED backend silently got a different
        scan — one that finishes with no callbacks and looks valid."""
        import tempfile as _tf
        monkeypatch.setattr(_tf, "mkdtemp",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("read-only /tmp")))
        with pytest.raises(params.OobCredentialError) as caught:
            with params.blind_oob_credential("SEKRET"):
                pytest.fail("the body must never run without the credential")
        assert "could not be written" in str(caught.value)

    def test_the_lane_reports_the_refusal_as_a_GAP_and_scans_nothing(self, monkeypatch, tmp_path):
        c = TestARetryOwesOnlyWhatFailed._lane_in(TestARetryOwesOnlyWhatFailed(),
                                                  monkeypatch, tmp_path, "cred")
        monkeypatch.setattr(secrets, "oob",
                            lambda: {"callback_server": "oob.mine.test", "auth_token": "T0K"})
        monkeypatch.setattr(params, "_make_oob_credential",
                            lambda s: (_ for _ in ()).throw(params.OobCredentialError("disk full")))
        monkeypatch.setattr(params, "exec_tool",
                            lambda *a, **k: pytest.fail("dalfox ran without its credential"))
        prof = type("P", (), {"http_rl": 0, "blind_xss": True, "blind_xss_dual": False})()
        params._dalfox_xss_fast(c, ["http://h/a?q="], prof)
        evs = [json.loads(x) for x in (tmp_path / "cred" / "events.jsonl").read_text().splitlines()]
        rows = [e for e in evs if e.get("measure") == "dalfox_targets"
                and "credential" in (e.get("unit") or "")]
        assert rows and rows[-1]["omitted"] == 1 and rows[-1]["tested"] == 0
        assert "refusing to run it unauthenticated" in rows[-1]["reason"]

    def test_an_exception_from_the_BODY_propagates_unchanged(self):
        """`shodan_host._open_lock` records this exact defect: one `try` over acquisition AND the
        protected body means a body exception is caught, the generator yields twice, and contextlib
        replaces the real failure with `generator didn't stop after throw()`."""
        class _Boom(Exception):
            pass
        with pytest.raises(_Boom, match="the REAL failure"):
            with params.blind_oob_credential("SEKRET"):
                raise _Boom("the REAL failure from exec_tool")

    def test_acquisition_is_settled_before_the_protected_yield(self):
        import inspect
        src = inspect.getsource(params.blind_oob_credential)
        body = src[src.index("if not secret"):]
        assert "except Exception" not in body, "the yield must sit in try/FINALLY only"
        assert "_make_oob_credential" in body and body.index("_make_oob_credential") < body.index("yield path")


class TestTheOobPolicyIsPartOfTheWorkIdentity:
    """The OOB policy is part of the work's identity: arming blind XSS after a completed reflected scan
    must NOT reuse the old chunks and inject no blind payload — that is a lane which looks done and
    never ran what was just enabled. Switching backend (public <-> self-hosted, or one server to
    another) has the same effect and must invalidate the same state."""

    @staticmethod
    def _wu(monkeypatch, tmp_path, tag, oob, **modes):
        monkeypatch.setattr(settings, "concurrency",
                            lambda k, d=None: {"DALFOX_CHUNK": 1, "DALFOX_TARGETS": 4}.get(k, d))
        monkeypatch.setattr(settings, "workers", lambda t, d: d)
        monkeypatch.setattr(secrets, "oob", lambda: oob)
        monkeypatch.setattr(params, "_dalfox_engine_id", lambda: "v3.2.0")
        monkeypatch.setattr(params, "exec_tool", _exec(META0, 0))
        events.reset(); events.configure(tmp_path / tag)
        c = _C(tmp_path / tag)
        prof = type("P", (), {"http_rl": 0, "blind_xss": False, **modes})()
        params._dalfox_xss_fast(c, ["http://h/a?q="], prof)
        st = json.loads((c.run.raw_path("params", "dalfox", "chunks.state.json")).read_text())
        return st["work_unit"]

    def test_arming_native_OOB_invalidates_a_reflected_only_resume(self, monkeypatch, tmp_path):
        off = self._wu(monkeypatch, tmp_path, "a", {})
        on = self._wu(monkeypatch, tmp_path, "b", {"callback_server": "s.test"}, blind_xss=True)
        assert off != on, "the old chunks would have been reused and no blind payload sent"

    def test_switching_BACKEND_invalidates_it_too(self, monkeypatch, tmp_path):
        pub = self._wu(monkeypatch, tmp_path, "c", {}, blind_xss=True)
        own = self._wu(monkeypatch, tmp_path, "d", {"callback_server": "s.test"}, blind_xss=True)
        assert pub != own

    def test_switching_SERVER_invalidates_it_too(self, monkeypatch, tmp_path):
        s1 = self._wu(monkeypatch, tmp_path, "e", {"callback_server": "s1.test"}, blind_xss=True)
        s2 = self._wu(monkeypatch, tmp_path, "f", {"callback_server": "s2.test"}, blind_xss=True)
        assert s1 != s2

    def test_the_identity_carries_NO_secret_and_NO_server_name(self, monkeypatch, tmp_path):
        """A work unit is reported. It must not carry infrastructure, and never the token."""
        import inspect
        src = inspect.getsource(params._dalfox_xss_fast)
        seg = src[src.index('"oob_channel"'):src.index('"chunk": chunk_n')]
        assert "fingerprint" in seg and '_plan_for_run["secret"]' not in seg.replace(
            'bool(_plan_for_run["secret"])', "")
        assert 'secrets.fingerprint(_plan_for_run["server"])' in seg


class TestPolicyIsNotExecution:
    """review#20 (Lumpy): `armed` describes the POLICY the operator chose; it says nothing about whether
    any invocation actually ran with that channel. One record driven off `armed` let a single run say
    both "not scanned, credential transport failed" AND "the armed channel was tested"."""

    @staticmethod
    def _lane(monkeypatch, tmp_path, tag):
        monkeypatch.setattr(settings, "concurrency",
                            lambda k, d=None: {"DALFOX_CHUNK": 1, "DALFOX_TARGETS": 4}.get(k, d))
        monkeypatch.setattr(settings, "workers", lambda t, d: d)
        monkeypatch.setattr(params, "_dalfox_engine_id", lambda: "v3.2.0")
        events.reset(); events.configure(tmp_path / tag)
        return _C(tmp_path / tag)

    @staticmethod
    def _cov(tmp_path, tag, measure):
        evs = [json.loads(x) for x in (tmp_path / tag / "events.jsonl").read_text().splitlines()]
        return [e for e in evs if e.get("measure") == measure]

    @staticmethod
    def _prof(**kw):
        return type("P", (), {"http_rl": 0, "blind_xss": False, **kw})()

    def test_a_credential_refusal_does_NOT_also_claim_the_channel_was_tested(self, monkeypatch,
                                                                            tmp_path):
        c = self._lane(monkeypatch, tmp_path, "r")
        monkeypatch.setattr(secrets, "oob",
                            lambda: {"callback_server": "oob.mine.test", "auth_token": "T0K"})
        monkeypatch.setattr(params, "_make_oob_credential",
                            lambda s: (_ for _ in ()).throw(params.OobCredentialError("disk full")))
        monkeypatch.setattr(params, "exec_tool",
                            lambda *a, **k: pytest.fail("dalfox ran without its credential"))
        params._dalfox_xss_fast(c, ["http://h/a?q="], self._prof(blind_xss=True))
        chan = self._cov(tmp_path, "r", "blind_xss_channel")
        assert chan, "an attempted invocation must still report its execution outcome"
        assert chan[-1]["tested"] == 0 and chan[-1]["omitted"] == 1, chan[-1]
        assert "credential transport failed" in chan[-1]["reason"]
        # …and the DECISION is recorded separately, inert in the verdict
        pol = self._cov(tmp_path, "r", "blind_xss_policy")
        assert pol and pol[-1]["omitted"] == 0 and "channel=native" in pol[-1]["reason"]

    def test_a_launched_invocation_reports_the_channel_as_run(self, monkeypatch, tmp_path):
        c = self._lane(monkeypatch, tmp_path, "ok")
        monkeypatch.setattr(secrets, "oob", lambda: {"callback_server": "oob.mine.test"})
        monkeypatch.setattr(params, "exec_tool", _exec(META0, 0))
        params._dalfox_xss_fast(c, ["http://h/a?q="], self._prof(blind_xss=True))
        chan = self._cov(tmp_path, "ok", "blind_xss_channel")
        assert chan[-1]["tested"] == 1 and chan[-1]["omitted"] == 0
        assert "1/1 dalfox invocation(s) STARTED with the armed blind-XSS channel" in chan[-1]["reason"]

    def test_a_lifecycle_that_RAN_NOTHING_asserts_no_execution(self, monkeypatch, tmp_path):
        """Everything already complete: policy is still stated, execution claims nothing."""
        c = self._lane(monkeypatch, tmp_path, "a")
        monkeypatch.setattr(secrets, "oob", lambda: {"callback_server": "oob.mine.test"})
        monkeypatch.setattr(params, "exec_tool", _exec(META0, 0))
        params._dalfox_xss_fast(c, ["http://h/a?q="], self._prof(blind_xss=True))
        c2 = self._lane(monkeypatch, tmp_path, "b")
        c2.run.dir = c.run.dir
        monkeypatch.setattr(params, "exec_tool",
                            lambda *a, **k: pytest.fail("a completed chunk was re-scanned"))
        params._dalfox_xss_fast(c2, ["http://h/a?q="], self._prof(blind_xss=True))
        assert self._cov(tmp_path, "b", "blind_xss_channel") == [], "nothing ran; nothing to claim"
        assert self._cov(tmp_path, "b", "blind_xss_policy"), "…but the decision is still recorded"

    def test_an_unarmed_run_claims_no_execution_either(self, monkeypatch, tmp_path):
        c = self._lane(monkeypatch, tmp_path, "off")
        monkeypatch.setattr(secrets, "oob", lambda: {})
        monkeypatch.setattr(params, "exec_tool", _exec(META0, 0))
        params._dalfox_xss_fast(c, ["http://h/a?q="], self._prof())
        assert self._cov(tmp_path, "off", "blind_xss_channel") == []
        pol = self._cov(tmp_path, "off", "blind_xss_policy")
        assert pol and "channel=off" in pol[-1]["reason"] and pol[-1]["omitted"] == 0

    def test_a_launch_that_never_happened_is_NOT_counted(self, monkeypatch, tmp_path):
        """review#21 (Lumpy): `launched` incremented before `exec_tool`, so a missing binary, a refused
        launch or a `Popen` that raised all counted as a process that ran with the armed channel."""
        c = self._lane(monkeypatch, tmp_path, "nolaunch")
        monkeypatch.setattr(secrets, "oob", lambda: {"callback_server": "oob.mine.test"})
        monkeypatch.setattr(params, "exec_tool", _exec(META0, 0, started=False))
        params._dalfox_xss_fast(c, ["http://h/a?q="], self._prof(blind_xss=True))
        chan = self._cov(tmp_path, "nolaunch", "blind_xss_channel")
        assert chan and chan[-1]["tested"] == 0 and chan[-1]["omitted"] == 1, chan[-1]
        assert "did not:" in chan[-1]["reason"] and "dalfox did not start" in chan[-1]["reason"]

    def test_the_runner_only_claims_started_without_a_pid(self):
        """The contract behind the counter; this unit exercises only child-free paths."""
        from quarry_recon import runner
        assert runner.skipped("x", "no key").started is False
        assert runner.RunResult("t", [], Status.SUCCESS, 0, 0.0, None, 0).started is False, \
            "absence must be the safe answer — a result that never says so did NOT start"
        assert runner.RunResult("t", [], Status.SUCCESS, 0, 0.0, None, 0,
                                meta={"started": True}).started is True

    def test_a_missing_binary_never_claims_started(self, monkeypatch):
        """No subprocess involved: `run` refuses before Popen when the binary is not on PATH."""
        from quarry_recon import runner
        monkeypatch.setattr(runner, "have", lambda b: False)
        r = runner.run("nope-xyz-not-a-binary", ["nope-xyz-not-a-binary"])
        assert r.status == Status.SKIPPED and r.started is False

    def test_started_is_set_ONLY_once_Popen_returns(self, monkeypatch, tmp_path):
        """Drives the REAL `runner.run` with a faked `Popen`, so the contract is exercised without
        spawning anything; ordinary, non-synthetic H0 nodes reject a real spawn."""
        import io
        import subprocess as _sp
        from quarry_recon import runner

        class _Proc:
            pid = 4242
            returncode = 0

            def __init__(self):
                self.stdout, self.stderr, self.stdin = io.BytesIO(b""), io.BytesIO(b""), io.BytesIO()

            def wait(self, timeout=None):
                return 0

            def poll(self):
                return 0

        monkeypatch.setattr(runner, "have", lambda b: True)
        monkeypatch.setattr(_sp, "Popen", lambda *a, **k: _Proc())
        assert runner.run("fake", ["fake"]).started is True

        # …and a launch that RAISES is a typed machinery fault, never an escape (QR39-001)
        def boom(*a, **k):
            raise OSError("exec format error")
        monkeypatch.setattr(_sp, "Popen", boom)
        r = runner.run("fake", ["fake"])
        assert r.started is False and r.status is runner.Status.FAILED
        assert any(f["kind"] == "machinery" for f in r.meta.get("faults", []))

    def test_BOTH_records_survive_an_exception_in_the_loop(self, monkeypatch, tmp_path):
        """The policy is knowable before execution and the attempt is a fact — an exception must take
        neither with it, and must itself arrive unchanged."""
        c = self._lane(monkeypatch, tmp_path, "boom")
        monkeypatch.setattr(secrets, "oob", lambda: {"callback_server": "oob.mine.test"})

        def explode(*a, **k):
            raise RuntimeError("bookkeeping blew up mid-loop")
        monkeypatch.setattr(params, "exec_tool", explode)
        with pytest.raises(RuntimeError, match="bookkeeping blew up"):
            params._dalfox_xss_fast(c, ["http://h/a?q="], self._prof(blind_xss=True))
        assert self._cov(tmp_path, "boom", "blind_xss_policy"), "the decision was lost"
        chan = self._cov(tmp_path, "boom", "blind_xss_channel")
        assert chan and chan[-1]["tested"] == 0 and chan[-1]["omitted"] == 1, "the attempt was lost"

    def test_the_policy_record_precedes_the_first_chunk(self, monkeypatch, tmp_path):
        c = self._lane(monkeypatch, tmp_path, "order")
        monkeypatch.setattr(secrets, "oob", lambda: {"callback_server": "oob.mine.test"})
        monkeypatch.setattr(params, "exec_tool", _exec(META0, 0))
        params._dalfox_xss_fast(c, ["http://h/a?q="], self._prof(blind_xss=True))
        evs = [json.loads(x) for x in (tmp_path / "order" / "events.jsonl").read_text().splitlines()]
        pol = next(i for i, e in enumerate(evs) if e.get("measure") == "blind_xss_policy")
        first_chunk = next(i for i, e in enumerate(evs)
                           if e.get("event") == "tool_start" and e.get("input_total") == 1)
        assert pol < first_chunk, "the decision must be on the record before anything runs"


class TestDoctorHasONEOobSection:
    """Lumpy, 2026-08-07: the tool sat in the phase-grouped list and the callback backend had its own
    block further down, so one output carried two `[oob]` headers saying half a thing each. One
    section: the tool that makes the callbacks, and the server they come back to.

    The blind-XSS channel is deliberately absent — it is resolved from a TARGET's `MODES.BLIND_XSS`, so
    it is armed for one engagement and not the next, and doctor is installation-scoped. The how and the
    why live in the docs; `_blind_oob_plan` is still the single resolver and the lane reports it when it
    runs (`TestBlindXssChannel`)."""

    @staticmethod
    def _doctor(monkeypatch, oob, *, installed=True, tools=("interactsh-client",)):
        """Doctor PROBES every tool, and an offline test may not spawn processes — so the registry is
        narrowed to the tools under test and their health is stated rather than measured. What is being
        asserted here is the RENDERING."""
        from click.testing import CliRunner
        from quarry_recon import cli
        from quarry_recon.registry import Tool, load_tools
        sel = [t for t in load_tools() if t.bin in tools]
        monkeypatch.setattr(cli, "load_tools", lambda *a, **k: sel)
        monkeypatch.setattr(cli, "tools_by_phase", lambda *a, **k: sel)
        monkeypatch.setattr(Tool, "installed", property(lambda self: installed))
        monkeypatch.setattr(cli, "health", lambda t: {"installed": installed, "identity": t.pin or "",
                                                      "drift": "ok", "capability": True, "ok": True})
        monkeypatch.setattr(cli, "_doctor_version", lambda t, ident: t.pin or "")
        monkeypatch.setattr(secrets, "oob", lambda: dict(oob))
        res = CliRunner().invoke(cli.doctor, [])
        assert res.exception is None or isinstance(res.exception, SystemExit), res.exception
        return res.output

    def _block(self, monkeypatch, oob):
        out = self._doctor(monkeypatch, oob)
        assert out.count("[oob]") == 1, out
        return [l for l in out[out.index("[oob]"):].splitlines()[1:] if l.strip()][:2]

    def test_there_is_exactly_one_oob_header(self, monkeypatch):
        assert self._doctor(monkeypatch, {}).count("[oob]") == 1

    def test_it_holds_the_tool_and_the_server(self, monkeypatch):
        first, second = self._block(monkeypatch, {})
        assert "interactsh-client" in first and "v1.3.1" in first, first
        assert "callback server:" in second and "not set" in second, second

    def test_the_tool_is_no_longer_in_the_phase_list(self, monkeypatch):
        """It was under [params] — one consumer of the callback layer, not the tool's purpose."""
        from quarry_recon.registry import load_tools
        t = next(x for x in load_tools() if x.bin == "interactsh-client")
        assert t.phase == "oob"
        out = self._doctor(monkeypatch, {})
        assert out.index("interactsh-client") > out.index("[oob]"), "printed in the oob block only"

    def test_a_configured_server_shows_its_ADDRESS(self, monkeypatch):
        """Not a secret, and seeing it is how an operator confirms the one they set is the one in use."""
        _tool, srv = self._block(monkeypatch, {"callback_server": "oob.mine.test"})
        assert "callback server:" in srv and "oob.mine.test" in srv, srv

    def test_the_TOKEN_never_appears(self, monkeypatch):
        out = self._doctor(monkeypatch, {"callback_server": "oob.mine.test",
                                         "auth_token": "SUPERSECRETTOKEN"})
        assert "SUPERSECRETTOKEN" not in out

    def test_no_per_TARGET_channel_and_no_how_to_prose(self, monkeypatch):
        out = self._doctor(monkeypatch, {"callback_server": "oob.mine.test"})
        blk = out[out.index("[oob]"):]
        for noise in ("MODES.BLIND_XSS", "channel", "correlation owned by", "to use your own"):
            assert noise not in blk, (noise, blk[:400])

    def test_a_MISSING_required_oob_tool_is_still_a_blocker(self, monkeypatch):
        """It is printed elsewhere now; it must not stop being COUNTED."""
        out = self._doctor(monkeypatch, {}, installed=False)
        assert "MISSING — quarry install --only interactsh-client" in out
        assert "NOT READY" in out, out[-400:]


class TestThe320AdoptionIsMEASURED:
    """dalfox 3.2.0 flags, adopted (or refused) on what the real binary was observed to do on
    2026-08-07 — not on what the changelog claims."""

    class _P:
        http_rl = 0
        blind_xss = False

    def _cmd(self, monkeypatch):
        monkeypatch.setattr(secrets, "oob", lambda: {})
        return params._dalfox_cmd("b.txt", "o.jsonl", self._P(), 1)

    def test_dedup_is_requested_by_SIGNATURE(self, monkeypatch):
        cmd = self._cmd(monkeypatch)
        assert cmd[cmd.index("--dedup-urls") + 1] == "signature"

    def test_full_request_and_response_are_requested(self, monkeypatch):
        cmd = self._cmd(monkeypatch)
        assert "--include-request" in cmd and "--include-response" in cmd

    def test_scan_timeout_is_NOT_passed(self, monkeypatch):
        """MEASURED: a target whose injection stage `--scan-timeout` cuts is reported
        `status: "clean", incomplete: false` — byte-identical to a target that really was scanned and
        found nothing. Quarry cannot report coverage it cannot observe, so the flag stays off until
        dalfox surfaces the cut in the artifact."""
        assert not any(c.startswith("--scan-timeout") for c in self._cmd(monkeypatch))

    def test_the_request_and_response_are_kept_WHOLE_on_the_finding(self):
        req = "GET /s?q=%3Csvg+onload%3Dalert%281%29%3E HTTP/1.1\r\nHost: t\r\n" + "X" * 5000
        rec = params._dalfox_finding({"type": "V", "param": "q", "data": "http://t/s?q=1",
                                      "message_id": 1, "request": req, "response": "<html>" + "y" * 5000})
        assert rec["request"] == req, "the evidence is the product; it is not previewed or truncated"
        assert rec["response"].endswith("y" * 10)

    def test_a_MISSING_request_does_not_become_the_string_None(self):
        rec = params._dalfox_finding({"type": "R", "param": "q", "data": "http://t/s?q=1",
                                      "message_id": 2})
        assert rec["request"] is None and rec["response"] is None

    def test_a_NON_STRING_request_is_refused_rather_than_coerced(self):
        rec = params._dalfox_finding({"type": "R", "param": "q", "data": "http://t/s?q=1",
                                      "message_id": 3, "request": {"raw": "x"}, "response": 7})
        assert rec["request"] is None and rec["response"] is None

    def test_the_artifact_carries_what_dalfox_SAYS_it_deduplicated(self, tmp_path):
        """`dedup_mode` and `targets_deduplicated` are dalfox's own words about the target set it
        actually scanned — a build that ignored the flag must not read as the policy we asked for."""
        p = tmp_path / "a.jsonl"
        p.write_text(json.dumps({"meta": {"findings_count": 0, "dedup_mode": "signature",
                                          "targets_deduplicated": 7, "total_requests": 22,
                                          "incomplete": False, "target_summary": [],
                                          "dalfox_version": "3.2.0"}}) + "\n")
        _f, art = params.scan_dalfox_jsonl(p)
        assert art.readable and art.dedup_mode == "signature"
        assert art.deduplicated == 7 and art.total_requests == 22

    def test_a_DIFFERENT_dedup_mode_is_readable_not_silently_accepted(self, tmp_path):
        p = tmp_path / "a.jsonl"
        p.write_text(json.dumps({"meta": {"findings_count": 0, "dedup_mode": "exact",
                                          "targets_deduplicated": 0, "incomplete": False,
                                          "target_summary": []}}) + "\n")
        _f, art = params.scan_dalfox_jsonl(p)
        assert art.dedup_mode == "exact", "the lane compares this against what it asked for"

    def test_an_ABSENT_dedup_mode_is_UNKNOWN_not_an_agreement(self, tmp_path):
        """review#35 (Lumpy): `str(x or "")` turned an absent field into `""`, which the lane read as
        "no disagreement". An artifact that does not say which target set it scanned has not agreed
        with us — the findings are still evidence, the POLICY CLAIM is what is unknown."""
        p = tmp_path / "a.jsonl"
        p.write_text(json.dumps({"meta": {"findings_count": 0, "incomplete": False,
                                          "target_summary": []}}) + "\n")
        _f, art = params.scan_dalfox_jsonl(p)
        assert art.dedup_mode == "unknown" and art.readable

    def test_a_NON_STRING_dedup_mode_is_unknown_not_stringified(self, tmp_path):
        """`{'mode': 'signature'}` was becoming the literal string `"{'mode': 'signature'}"`."""
        for bad in ({"mode": "signature"}, ["signature"], 7, True, "SIGNATURE", "made-up"):
            p = tmp_path / "b.jsonl"
            p.write_text(json.dumps({"meta": {"findings_count": 0, "dedup_mode": bad,
                                              "incomplete": False, "target_summary": []}}) + "\n")
            _f, art = params.scan_dalfox_jsonl(p)
            assert art.dedup_mode == "unknown", bad

    def test_an_artifact_with_NO_meta_row_claims_no_policy(self, tmp_path):
        """The default is a claim like any other: an artifact that never told us what it deduplicated
        must not read as having agreed with the flag we passed."""
        assert params.DalfoxArtifact(readable=False).dedup_mode == "unknown"
        p = tmp_path / "nometa.jsonl"
        p.write_text(json.dumps({"type": "R", "param": "q", "data": "http://h/p?q=1",
                                 "message_id": 1}) + "\n")
        _f, art = params.scan_dalfox_jsonl(p)
        assert art.dedup_mode == "unknown" and not art.readable

    def test_a_NEGATIVE_count_is_not_operator_facing_measurement(self, tmp_path):
        """`-7 requests` and `-3 targets collapsed` were summed and shown. A count that cannot be true
        is an unreadable field, and `None` says exactly that."""
        p = tmp_path / "c.jsonl"
        p.write_text(json.dumps({"meta": {"findings_count": 0, "total_requests": -7,
                                          "targets_deduplicated": -3, "incomplete": False,
                                          "target_summary": [], "dedup_mode": "signature"}}) + "\n")
        _f, art = params.scan_dalfox_jsonl(p)
        assert art.total_requests is None and art.deduplicated is None
        assert art.readable, "a bad METRIC does not make the findings untrustworthy"

    def test_a_negative_findings_count_still_fails_the_artifact(self, tmp_path):
        """…but the count that has to AGREE with the rows does gate it."""
        p = tmp_path / "d.jsonl"
        p.write_text(json.dumps({"meta": {"findings_count": -1}}) + "\n")
        _f, art = params.scan_dalfox_jsonl(p)
        assert not art.readable

    def test_signature_dedup_is_the_identity_our_canonicalizer_ALREADY_uses(self):
        """Measured on the real binary: `signature` collapses URLs differing only in parameter VALUES
        and keeps http/https apart — the same key as `_canonicalize_candidates`. So on this lane the
        flag is a second net, not the runtime win the backlog assumed; `targets_deduplicated` is
        reported so the residual is a measured number at the next OTC run."""
        reps, stats = params._canonicalize_candidates(
            ["http://t/s?q=1", "http://t/s?q=2", "https://t/s?q=1"])
        assert sorted(reps) == ["http://t/s?q=1", "https://t/s?q=1"], reps
        assert stats["raw_candidates"] == 3 and stats["canonical_candidates"] == 2


class TestTheScanCOSTIsReported:
    """`total_requests` and `targets_deduplicated` were parsed in 4.3 and surfaced NOWHERE, which made
    the meta row half-read: dalfox told us what the scan cost and what it collapsed, and the operator
    saw neither. Reported on the lane's result, so the residual duplicate rate over our own
    canonicalizer is a MEASURED number at the next OTC run."""

    META = ('{"meta":{"findings_count":0,"incomplete":false,"dedup_mode":"signature",'
            '"targets_deduplicated":4,"total_requests":37,"dalfox_version":"3.2.0",'
            '"target_summary":[]}}\n')

    def test_the_note_carries_requests_and_collapsed_targets(self, monkeypatch, tmp_path):
        c = _fresh(monkeypatch, tmp_path)
        monkeypatch.setattr(params, "exec_tool", _exec(self.META, 0))
        r = params._dalfox_xss_fast(c, ["http://h/p?q="], _Prof())
        assert "37 request(s)" in r.note, r.note
        assert "4 duplicate target(s) collapsed by dalfox" in r.note, r.note

    def test_a_zero_collapse_is_not_noise(self, monkeypatch, tmp_path):
        """Our canonicalizer already collapses this shape, so 0 is the EXPECTED reading — and saying
        "0 collapsed" on every run trains an operator to ignore the line."""
        c = _fresh(monkeypatch, tmp_path)
        meta = self.META.replace('"targets_deduplicated":4', '"targets_deduplicated":0')
        monkeypatch.setattr(params, "exec_tool", _exec(meta, 0))
        r = params._dalfox_xss_fast(c, ["http://h/p?q="], _Prof())
        assert "collapsed" not in r.note and "37 request(s)" in r.note, r.note

    def test_a_DIFFERENT_dedup_mode_is_said_out_loud(self, monkeypatch, tmp_path):
        """We asked for `signature`. A build that ignored the flag scanned a different target set than
        the one we think we asked for, and "N targets scanned" then means something else."""
        c = _fresh(monkeypatch, tmp_path)
        meta = self.META.replace('"dedup_mode":"signature"', '"dedup_mode":"exact"')
        monkeypatch.setattr(params, "exec_tool", _exec(meta, 0))
        r = params._dalfox_xss_fast(c, ["http://h/p?q="], _Prof())
        assert "dedup_mode=exact" in r.note and "NOT the `signature` we asked for" in r.note, r.note

    def test_the_agreed_mode_says_nothing(self, monkeypatch, tmp_path):
        c = _fresh(monkeypatch, tmp_path)
        monkeypatch.setattr(params, "exec_tool", _exec(self.META, 0))
        r = params._dalfox_xss_fast(c, ["http://h/p?q="], _Prof())
        assert "dedup_mode" not in r.note, r.note

    def test_the_cost_ACCUMULATES_across_chunks(self, monkeypatch, tmp_path):
        c = _fresh(monkeypatch, tmp_path)                       # DALFOX_CHUNK=1 -> one chunk per URL
        monkeypatch.setattr(params, "exec_tool", _exec(self.META, 0))
        r = params._dalfox_xss_fast(c, ["http://h/a?q=", "http://h/b?q="], _Prof())
        assert "2 chunk(s)" in r.note and "74 request(s)" in r.note, r.note
        assert "8 duplicate target(s)" in r.note, r.note


class TestTheParserHoldsONEFindingAtATime:
    """review#35 (Lumpy): with `--include-response` a finding carries a whole HTTP response. The old
    parser read the entire file into a str, copied it again through `splitlines()`, and held every
    finding at once — so an artifact dalfox had already written successfully could OOM the process that
    came to read it, and again on resume. Preserve every byte; bound how many are held at once."""

    @staticmethod
    def _artifact(tmp_path, n, body_kb=64):
        rows = [json.dumps({"meta": {"findings_count": n, "incomplete": False,
                                     "dedup_mode": "signature", "targets_deduplicated": 0,
                                     "total_requests": 1,
                                     "target_summary": [{"target": f"http://h/p{i}?q=1",
                                                         "status": "findings", "findings_count": 1}
                                                        for i in range(n)]}})]
        for i in range(n):
            rows.append(json.dumps({"type": "R", "param": "q", "data": f"http://h/p?q={i}",
                                    "message_id": i, "request": "GET /p HTTP/1.1\r\n" + "x" * (body_kb * 1024),
                                    "response": "y" * (body_kb * 1024)}))
        p = tmp_path / "big.jsonl"
        p.write_text("\n".join(rows) + "\n")
        return p

    def test_no_finding_list_is_ever_materialised(self, tmp_path):
        """The sink sees each finding; the parser returns a COUNT. There is no list to grow."""
        p = self._artifact(tmp_path, 20, body_kb=16)
        live = []

        def sink(rec):
            live.append(1)
            assert len(rec["response"]) == 16 * 1024, "and it is the WHOLE response, not a preview"
        n, art = params.scan_dalfox_jsonl(p, sink)
        assert n == 20 and len(live) == 20 and art.readable

    def test_peak_memory_does_not_scale_with_the_ARTIFACT(self, tmp_path):
        """The measurement that matters: 40 findings x 256 KiB is ~20 MiB of artifact, and the parser
        must not be holding it. Sampled with tracemalloc while the sink discards each record."""
        import tracemalloc
        p = self._artifact(tmp_path, 40, body_kb=256)
        assert p.stat().st_size > 18 * 1024 * 1024, p.stat().st_size
        tracemalloc.start()
        n, art = params.scan_dalfox_jsonl(p, lambda rec: None)
        _cur, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        assert n == 40 and art.readable
        assert peak < 6 * 1024 * 1024, f"peak {peak} — the artifact is being held, not streamed"

    def test_a_retaining_sink_is_the_CALLERS_choice_not_the_parsers(self, tmp_path):
        p = self._artifact(tmp_path, 5, body_kb=8)
        kept = []
        n, _art = params.scan_dalfox_jsonl(p, kept.append)
        assert n == len(kept) == 5, "a caller that wants them all can still have them"

    def test_a_bad_BYTE_costs_its_row_not_the_whole_artifact(self, tmp_path):
        """It used to strict-decode the entire file, so one bad byte discarded every finding beside it."""
        p = tmp_path / "mixed.jsonl"
        good = json.dumps({"type": "R", "param": "q", "data": "http://h/p?q=1", "message_id": 1})
        p.write_bytes((json.dumps({"meta": {"findings_count": 2, "incomplete": False,
                                            "target_summary": []}}) + "\n" + good + "\n").encode()
                      + b'{"type":"R","param":"q","data":"http://h/p?q=\xff","message_id":2}\n')
        kept = []
        n, art = params.scan_dalfox_jsonl(p, kept.append)
        assert n == 1 and len(kept) == 1, "the readable finding is KEPT"
        assert not art.readable, "…and the artifact is still marked untrustworthy, exactly as before"

    def test_the_lane_streams_its_ingest_too(self, monkeypatch, tmp_path):
        """The other half: the lane used to build a list of every finding across every retained
        artifact before adding any of them to the store."""
        c = _fresh(monkeypatch, tmp_path)
        rows = [json.dumps({"meta": {"findings_count": 3, "incomplete": False,
                                     "dedup_mode": "signature", "targets_deduplicated": 0,
                                     "total_requests": 3,
                                     "target_summary": [{"target": "http://h/p?q=", "status": "findings",
                                                         "findings_count": 3}]}})]
        # DISTINCT ROUTES: findings key on path+param+method, not on the parameter VALUE, so three
        # `?q=` URLs on one path are one finding by design.
        for i in range(3):
            rows.append(json.dumps({"type": "R", "param": "q", "data": f"http://h/p{i}?q=1",
                                    "message_id": i, "response": "z" * 4096}))
        monkeypatch.setattr(params, "exec_tool", _exec("\n".join(rows) + "\n", 1))
        r = params._dalfox_xss_fast(c, ["http://h/p?q="], _Prof())
        assert r.status is Status.SUCCESS and len(c.run.added) == 3
        assert all(len(a["response"]) == 4096 for a in c.run.added), "every byte still stored"


class TestTheADOPTIONIsPartOfTheWorkIdentity:
    """review#36 (Lumpy): the 3.2.0 adoption changed WHAT AN ARTIFACT CONTAINS (full request/response)
    and WHICH TARGET SET was scanned (signature dedup). A chunk completed before it is still
    structurally valid, so resume would accept it and skip work whose evidence we just decided we need."""

    def _wu(self, monkeypatch, tmp_path, tag):
        c = _fresh(monkeypatch, tmp_path / tag)
        seen = {}
        real = events.work_unit
        monkeypatch.setattr(events, "work_unit",
                            lambda sid, inputs=None, config=None: seen.setdefault("cfg", dict(config or {}))
                            and real(sid, inputs=inputs, config=config) or real(sid, inputs=inputs, config=config))
        monkeypatch.setattr(params, "exec_tool", _exec(META0, 0))
        params._dalfox_xss_fast(c, ["http://h/p?q="], _Prof())
        return seen["cfg"]

    def test_the_mode_names_the_evidence_and_dedup_contract(self, monkeypatch, tmp_path):
        cfg = self._wu(monkeypatch, tmp_path, "a")
        assert cfg["mode"] == "v3-fast-reflected+evidence+sigdedup", cfg["mode"]

    def test_a_PRE_ADOPTION_completion_cannot_be_resumed_into(self, monkeypatch, tmp_path):
        """The behavioural half: the identity has to actually differ from the old one, or nothing is
        invalidated."""
        old = dict(self._wu(monkeypatch, tmp_path, "b"), mode="v3-fast-reflected")
        new = self._wu(monkeypatch, tmp_path, "c")
        assert events.work_unit("x", inputs={"h": []}, config=old) != \
            events.work_unit("x", inputs={"h": []}, config=new)


class TestASinkFailureIsTheCALLERS:
    def test_a_storage_error_is_RAISED_not_reported_as_a_bad_artifact(self, tmp_path):
        """It was swallowed by the artifact-I/O boundary: `(0, readable=False)` came back while earlier
        rows had already landed, and the real failure — the disk — disappeared."""
        p = tmp_path / "a.jsonl"
        p.write_text(json.dumps({"meta": {"findings_count": 1, "incomplete": False,
                                          "target_summary": []}}) + "\n"
                     + json.dumps({"type": "R", "param": "q", "data": "http://h/p?q=1",
                                   "message_id": 1}) + "\n")

        def _full(rec):
            raise OSError(28, "No space left on device")
        with pytest.raises(OSError) as e:
            params.scan_dalfox_jsonl(p, _full)
        assert e.value.errno == 28

    def test_an_artifact_read_error_is_still_a_bad_artifact(self, tmp_path):
        """…and the other side of the boundary is unchanged."""
        n, art = params.scan_dalfox_jsonl(tmp_path / "missing.jsonl", lambda r: None)
        assert n == 0 and not art.readable


class TestVerdictDrivingMetadataIsExactlyTyped:
    """`incomplete` decides whether a chunk may be marked resumably complete, and `target_summary` is
    where a SKIPPED target is named. Malformed input must not be able to say a scan finished cleanly."""

    def _art(self, tmp_path, meta):
        p = tmp_path / "m.jsonl"
        p.write_text(json.dumps({"meta": meta}) + "\n")
        return params.scan_dalfox_jsonl(p)[1]

    def test_a_STRING_incomplete_does_not_read_as_complete(self, tmp_path):
        art = self._art(tmp_path, {"findings_count": 0, "incomplete": "true", "target_summary": []})
        assert not art.readable, "'true' is not True — and it must not become 'not incomplete'"
        assert not art.complete

    def test_a_real_boolean_still_works_both_ways(self, tmp_path):
        assert self._art(tmp_path, {"findings_count": 0, "incomplete": False,
                                    "target_summary": []}).complete
        assert not self._art(tmp_path, {"findings_count": 0, "incomplete": True,
                                        "target_summary": []}).complete

    def test_a_DICT_target_summary_is_not_no_targets_skipped(self, tmp_path):
        art = self._art(tmp_path, {"findings_count": 0, "incomplete": False,
                                   "target_summary": {"target": "http://h/a"}})
        assert not art.readable and not art.execution_done

    def test_a_non_object_ROW_in_the_summary_invalidates_it(self, tmp_path):
        art = self._art(tmp_path, {"findings_count": 0, "incomplete": False,
                                   "target_summary": ["http://h/a"]})
        assert not art.readable

    def test_summary_fields_are_not_stringified_into_a_fake_record(self, tmp_path):
        art = self._art(tmp_path, {"findings_count": 0, "incomplete": False,
                                   "target_summary": [{"target": {"u": "x"}, "status": 7,
                                                       "error_code": ["CONNECTION_FAILED"]}]})
        assert not art.readable
        assert art.skipped == (), "no record is better than a record made of str() of junk"

    def test_a_WELL_FORMED_skip_is_still_read(self, tmp_path):
        art = self._art(tmp_path, {"findings_count": 0, "incomplete": False,
                                   "target_summary": [
                                       {"target": "http://h/a", "status": "clean"},
                                       {"target": "http://h/b", "status": "skipped",
                                        "error_code": "CONNECTION_FAILED"}]})
        assert art.readable and art.skipped == (("http://h/b", "skipped", "CONNECTION_FAILED"),)

    def test_a_missing_error_code_is_empty_not_invalid(self, tmp_path):
        art = self._art(tmp_path, {"findings_count": 0, "incomplete": False,
                                   "target_summary": [{"target": "http://h/b", "status": "skipped"}]})
        assert art.readable and art.skipped == (("http://h/b", "skipped", ""),)


class TestEveryTargetIsACCOUNTEDFor:
    """review#37 (Lumpy): `complete` meant "no LISTED target was skipped", which says nothing about
    targets that were never listed. A batch of 40 with `target_summary: []` was clean and resumably
    complete — and the 40 would be dropped for ever on the next run."""

    def test_the_contract_fields_are_REQUIRED_not_merely_well_typed(self, tmp_path):
        """`{"findings_count": 0}` certified a clean, resumably complete chunk. 3.2.0 always emits both
        (measured), so their absence is an artifact that does not implement the contract we resume on."""
        p = tmp_path / "m.jsonl"
        p.write_text(json.dumps({"meta": {"findings_count": 0}}) + "\n")
        _n, art = params.scan_dalfox_jsonl(p)
        assert not art.readable and not art.complete and not art.execution_done

    def test_incomplete_alone_is_not_enough(self, tmp_path):
        p = tmp_path / "m.jsonl"
        p.write_text(json.dumps({"meta": {"findings_count": 0, "incomplete": False}}) + "\n")
        assert not params.scan_dalfox_jsonl(p)[1].readable

    def test_target_summary_alone_is_not_enough(self, tmp_path):
        p = tmp_path / "m.jsonl"
        p.write_text(json.dumps({"meta": {"findings_count": 0, "target_summary": []}}) + "\n")
        assert not params.scan_dalfox_jsonl(p)[1].readable

    def test_every_accounted_target_is_carried_whatever_its_status(self, tmp_path):
        p = tmp_path / "m.jsonl"
        p.write_text(json.dumps({"meta": {
            "findings_count": 0, "incomplete": False,
            "target_summary": [{"target": "http://h/a", "status": "clean"},
                               {"target": "http://h/b", "status": "skipped",
                                "error_code": "CONNECTION_FAILED"}]}}) + "\n")
        art = params.scan_dalfox_jsonl(p)[1]
        assert art.summary_targets == ("http://h/a", "http://h/b")

    def test_an_UNACCOUNTED_target_keeps_the_chunk_retryable(self, monkeypatch, tmp_path):
        """The lane is the only place that knows what was submitted."""
        events.reset(); events.configure(tmp_path)
        c = _fresh(monkeypatch, tmp_path)
        monkeypatch.setattr(settings, "concurrency",
                            lambda k, d=None: {"DALFOX_CHUNK": 2, "DALFOX_TARGETS": 4}.get(k, d))
        # dalfox reports ONE of the two submitted targets and says nothing about the other
        monkeypatch.setattr(params, "exec_tool", _exec(_meta(0, targets=("http://h/a?q=",)), 0))
        r = params._dalfox_xss_fast(c, ["http://h/a?q=", "http://h/b?q="], _Prof())
        assert r.status == Status.PARTIAL, r.status
        assert _state(c)["chunks"] == {}, "an unaccounted target must not become resumably done"
        evs = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()]
        acc = [e for e in evs if e.get("measure") == "dalfox_accounting"]
        assert acc and "never reported in any state" in acc[-1]["reason"], acc
        assert "http://h/b?q=" in acc[-1]["reason"], "and it NAMES the one nobody reported"
        events.reset()

    def test_the_unlisted_target_is_what_the_RETRY_OWES(self, monkeypatch, tmp_path):
        """review#38 (Lumpy): the remainder held only the rows dalfox NAMED, so an unlisted target
        cleared it and the next lifecycle re-sent the whole batch — someone else's site, hit again for
        targets that had already answered."""
        c = _fresh(monkeypatch, tmp_path)
        monkeypatch.setattr(settings, "concurrency",
                            lambda k, d=None: {"DALFOX_CHUNK": 2, "DALFOX_TARGETS": 4}.get(k, d))
        monkeypatch.setattr(params, "exec_tool", _exec(_meta(0, targets=("http://h/a?q=",)), 0))
        params._dalfox_xss_fast(c, ["http://h/a?q=", "http://h/b?q="], _Prof())
        assert _state(c).get("remainder") == {"0": ["http://h/b?q="]}, _state(c)
        sent = []

        def _spy(t, cmd, timeout=None, **k):
            bf = pathlib.Path(cmd[cmd.index("file") + 1])
            sent.extend(u for u in bf.read_text().splitlines() if u.strip())
            return _exec(_meta(0, targets=("http://h/b?q=",)), 0)(t, cmd, timeout, **k)
        monkeypatch.setattr(params, "exec_tool", _spy)
        params._dalfox_xss_fast(c, ["http://h/a?q=", "http://h/b?q="], _Prof())
        assert sent == ["http://h/b?q="], f"the retry re-sent {sent}"

    def test_a_summary_that_REPEATS_one_target_is_not_two(self, monkeypatch, tmp_path):
        """`[a,b]` answered by `[a,a]` balanced arithmetically and was marked done."""
        events.reset(); events.configure(tmp_path)
        c = _fresh(monkeypatch, tmp_path)
        monkeypatch.setattr(settings, "concurrency",
                            lambda k, d=None: {"DALFOX_CHUNK": 2, "DALFOX_TARGETS": 4}.get(k, d))
        monkeypatch.setattr(params, "exec_tool",
                            _exec(_meta(0, targets=("http://h/a?q=", "http://h/a?q=")), 0))
        r = params._dalfox_xss_fast(c, ["http://h/a?q=", "http://h/b?q="], _Prof())
        assert r.status == Status.PARTIAL and _state(c)["chunks"] == {}
        reason = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()
                  if json.loads(x).get("measure") == "dalfox_accounting"][-1]["reason"]
        assert "reported more times than dedup_mode=signature allows" in reason, reason
        assert "http://h/b?q=" in reason, reason
        events.reset()

    def test_a_FOREIGN_target_invalidates_the_accounting(self, monkeypatch, tmp_path):
        """`[a,b]` answered by `[a,c]`: the artifact is describing another scan."""
        events.reset(); events.configure(tmp_path)
        c = _fresh(monkeypatch, tmp_path)
        monkeypatch.setattr(settings, "concurrency",
                            lambda k, d=None: {"DALFOX_CHUNK": 2, "DALFOX_TARGETS": 4}.get(k, d))
        monkeypatch.setattr(params, "exec_tool",
                            _exec(_meta(0, targets=("http://h/a?q=", "http://h/c?q=")), 0))
        r = params._dalfox_xss_fast(c, ["http://h/a?q=", "http://h/b?q="], _Prof())
        assert r.status == Status.PARTIAL and _state(c)["chunks"] == {}
        reason = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()
                  if json.loads(x).get("measure") == "dalfox_accounting"][-1]["reason"]
        assert "NOT in this batch: http://h/c?q=" in reason, reason
        events.reset()

    def test_an_IMPOSSIBLE_dedup_claim_is_refused(self, monkeypatch, tmp_path):
        """An empty summary with `deduplicated=99` balanced arithmetically too."""
        events.reset(); events.configure(tmp_path)
        c = _fresh(monkeypatch, tmp_path)
        monkeypatch.setattr(settings, "concurrency",
                            lambda k, d=None: {"DALFOX_CHUNK": 2, "DALFOX_TARGETS": 4}.get(k, d))
        art = json.dumps({"meta": {"findings_count": 0, "incomplete": False,
                                   "dedup_mode": "signature", "targets_deduplicated": 99,
                                   "target_summary": []}}) + "\n"
        monkeypatch.setattr(params, "exec_tool", _exec(art, 0))
        r = params._dalfox_xss_fast(c, ["http://h/a?q=", "http://h/b?q="], _Prof())
        assert r.status == Status.PARTIAL and _state(c)["chunks"] == {}
        reason = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()
                  if json.loads(x).get("measure") == "dalfox_accounting"][-1]["reason"]
        assert "claims 99 target(s) collapsed" in reason and "0 duplicate(s)" in reason, reason
        events.reset()

    def test_DEDUP_is_accounted_for_rather_than_read_as_a_shortfall(self, monkeypatch, tmp_path):
        """With signature dedup dalfox scans one target per SIGNATURE, so the expected accounting is
        the batch's distinct signatures. (The earlier version of this test was invalid: `/a?q=` and
        `/b?q=` have different paths, so signature dedup could never collapse one into the other —
        review#38.) Same path, same parameter names, different values: one signature, one report."""
        events.reset(); events.configure(tmp_path)
        c = _fresh(monkeypatch, tmp_path)
        monkeypatch.setattr(settings, "concurrency",
                            lambda k, d=None: {"DALFOX_CHUNK": 2, "DALFOX_TARGETS": 4}.get(k, d))
        monkeypatch.setattr(params, "exec_tool",
                            _exec(_meta(0, targets=("http://h/a?q=1",), dedup=1), 0))
        r = params._dalfox_xss_fast(c, ["http://h/a?q=1", "http://h/a?q=2"], _Prof())
        assert r.status == Status.EMPTY, r.status
        assert _state(c)["chunks"], "one target collapsed into the other; nothing is missing"
        evs = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()]
        assert not [e for e in evs if e.get("measure") == "dalfox_accounting"]
        events.reset()

    def test_the_signature_is_the_one_our_canonicalizer_uses(self):
        sig = params._dalfox_signature
        assert sig("http://h/a?q=1") == sig("http://h/a?q=2"), "values do not change the identity"
        assert sig("http://h/a?q=1") != sig("http://h/b?q=1"), "paths do"
        assert sig("http://h/a?q=1") != sig("https://h/a?q=1"), "and so does scheme"
        assert sig("http://h/a?q=1&z=2") != sig("http://h/a?q=1"), "…and the parameter NAMES"

    def test_a_fully_accounted_chunk_is_still_done(self, monkeypatch, tmp_path):
        c = _fresh(monkeypatch, tmp_path)
        monkeypatch.setattr(settings, "concurrency",
                            lambda k, d=None: {"DALFOX_CHUNK": 2, "DALFOX_TARGETS": 4}.get(k, d))
        monkeypatch.setattr(params, "exec_tool",
                            _exec(_meta(0, targets=("http://h/a?q=", "http://h/b?q=")), 0))
        r = params._dalfox_xss_fast(c, ["http://h/a?q=", "http://h/b?q="], _Prof())
        assert r.status == Status.EMPTY and _state(c)["chunks"]


class TestAccountingFollowsTheREPORTEDMode:
    """review#39 (Lumpy): the reconciliation applied signature semantics unconditionally. A fully
    covered `exact` scan of `a?q=1` and `a?q=2` read as one signature reported twice, returned PARTIAL
    on every lifecycle, and — with no remainder — re-sent the whole batch for ever. It also turned a
    DISCLOSED mode difference into a failure, which the note beside it says it is not."""

    @staticmethod
    def _art(n, targets, mode, dedup=0):
        return json.dumps({"meta": {
            "findings_count": n, "incomplete": False, "dedup_mode": mode,
            "targets_deduplicated": dedup, "total_requests": 1,
            "target_summary": [{"target": t, "status": "clean", "findings_count": 0}
                               for t in targets]}}) + "\n"

    def _run(self, monkeypatch, tmp_path, art, batch):
        events.reset(); events.configure(tmp_path)
        c = _fresh(monkeypatch, tmp_path)
        monkeypatch.setattr(settings, "concurrency",
                            lambda k, d=None: {"DALFOX_CHUNK": 4, "DALFOX_TARGETS": 4}.get(k, d))
        monkeypatch.setattr(params, "exec_tool", _exec(art, 0))
        r = params._dalfox_xss_fast(c, batch, _Prof())
        evs = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()]
        acc = [e for e in evs if e.get("measure") == "dalfox_accounting"]
        events.reset()
        return r, _state(c), acc

    def test_an_EXACT_scan_that_covered_everything_is_DONE(self, monkeypatch, tmp_path):
        """Both targets reported, nothing collapsed — under `exact` that is complete coverage."""
        batch = ["http://h/a?q=1", "http://h/a?q=2"]
        r, st, acc = self._run(monkeypatch, tmp_path, self._art(0, batch, "exact"), batch)
        assert r.status == Status.EMPTY, r.status
        assert st["chunks"] and not acc, acc

    def test_an_EXACT_scan_that_missed_one_still_owes_it(self, monkeypatch, tmp_path):
        batch = ["http://h/a?q=1", "http://h/a?q=2"]
        r, st, acc = self._run(monkeypatch, tmp_path,
                               self._art(0, ["http://h/a?q=1"], "exact"), batch)
        assert r.status == Status.PARTIAL and st["chunks"] == {}
        assert st.get("remainder") == {"0": ["http://h/a?q=2"]}, st
        assert "http://h/a?q=2" in acc[-1]["reason"]

    def test_OFF_expects_every_input_line_including_repeats(self, monkeypatch, tmp_path):
        batch = ["http://h/a?q=1", "http://h/a?q=1"]
        r, st, acc = self._run(monkeypatch, tmp_path, self._art(0, batch, "off"), batch)
        assert r.status == Status.EMPTY and st["chunks"] and not acc, acc

    def test_OFF_REQUIRES_every_occurrence_not_merely_permits_them(self, monkeypatch, tmp_path):
        """review#40 (Lumpy): `[a,a]` with ONE `a` reported was clean — the check only looked for
        missing KEYS and over-reporting, never for under-reported occurrences."""
        batch = ["http://h/a?q=1", "http://h/a?q=1"]
        r, st, acc = self._run(monkeypatch, tmp_path,
                               self._art(0, ["http://h/a?q=1"], "off"), batch)
        assert r.status == Status.PARTIAL and st["chunks"] == {}
        assert "1 submitted occurrence(s) were never reported" in acc[-1]["reason"], acc
        assert st.get("remainder") == {"0": ["http://h/a?q=1"]}, "and one occurrence is still owed"

    def test_OFF_owes_the_MISSING_multiplicity_not_the_whole_group(self, monkeypatch, tmp_path):
        batch = ["http://h/a?q=1", "http://h/a?q=1", "http://h/a?q=1"]
        r, st, _acc = self._run(monkeypatch, tmp_path,
                                self._art(0, ["http://h/a?q=1", "http://h/a?q=1"], "off"), batch)
        assert r.status == Status.PARTIAL
        assert st.get("remainder") == {"0": ["http://h/a?q=1"]}, st

    def test_OFF_keeps_the_MULTIPLICITY_in_the_remainder(self, monkeypatch, tmp_path):
        """Two occurrences owed means two scans owed; collapsing them under-serves the retry."""
        batch = ["http://h/a?q=1"] * 3
        _r, st, _acc = self._run(monkeypatch, tmp_path,
                                 self._art(0, ["http://h/a?q=1"], "off"), batch)
        assert st.get("remainder") == {"0": ["http://h/a?q=1", "http://h/a?q=1"]}, st

    def test_BOTH_a_retryable_failure_and_an_ambiguity_are_recorded(self, monkeypatch, tmp_path):
        """Distinct units: reconciliation keeps one record per (source, unit), so a membership doubt
        must not displace a genuine accounting failure — they are different facts about one chunk."""
        batch = ["http://h/a?q=1", "http://h/a?q=2", "http://h/b?q=1"]
        events.reset(); events.configure(tmp_path)
        c = _fresh(monkeypatch, tmp_path)
        monkeypatch.setattr(settings, "concurrency",
                            lambda k, d=None: {"DALFOX_CHUNK": 4, "DALFOX_TARGETS": 4}.get(k, d))
        monkeypatch.setattr(params, "exec_tool",
                            _exec(self._art(0, ["http://h/a?q=1"], "made-up-mode"), 0))
        r = params._dalfox_xss_fast(c, batch, _Prof())
        evs = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()]
        units = {e["unit"]: e for e in evs if e.get("measure") in ("dalfox_accounting",
                                                                  "dalfox_membership")}
        assert len(units) == 2, units
        assert any("http://h/b?q=1" in e["reason"] for e in units.values() if
                   e["measure"] == "dalfox_accounting")
        assert any("http://h/a?q=2" in e["reason"] for e in units.values() if
                   e["measure"] == "dalfox_membership")
        assert r.status == Status.PARTIAL, "the RETRYABLE half still gates the chunk"
        events.reset()

    def test_OFF_with_a_collapse_claim_contradicts_itself(self, monkeypatch, tmp_path):
        batch = ["http://h/a?q=1", "http://h/a?q=2"]
        r, _st, acc = self._run(monkeypatch, tmp_path,
                                self._art(0, batch, "off", dedup=1), batch)
        assert r.status == Status.PARTIAL
        assert "under dedup_mode=off this batch has 0 duplicate(s)" in acc[-1]["reason"]

    def test_SIGNATURE_still_collapses_by_parameter_names(self, monkeypatch, tmp_path):
        batch = ["http://h/a?q=1", "http://h/a?q=2"]
        r, st, acc = self._run(monkeypatch, tmp_path,
                               self._art(0, ["http://h/a?q=1"], "signature", dedup=1), batch)
        assert r.status == Status.EMPTY and st["chunks"] and not acc, acc

    def test_an_UNKNOWN_mode_is_UNDECIDABLE_not_clean(self, monkeypatch, tmp_path):
        """review#40 (Lumpy): signature is the LEAST demanding identity, so using it for an unknown mode
        certified coverage that `exact`/`off` would have denied — `a?q=1` reported, `a?q=2` not, is
        complete under signature and short under exact. The chunk is execution-complete (retrying under
        the same unreadable policy changes nothing) and its COVERAGE is unknown."""
        batch = ["http://h/a?q=1", "http://h/a?q=2"]
        art = self._art(0, ["http://h/a?q=1"], "made-up-mode")     # -> dedup_mode "unknown"
        r, st, acc = self._run(monkeypatch, tmp_path, art, batch)
        assert st["chunks"], "no retry loop: the same policy would be as unreadable next time"
        assert not acc, "…and it is not reported as a retryable accounting failure"
        assert r.status == Status.EMPTY

    def test_the_undecidable_membership_is_RECORDED(self, monkeypatch, tmp_path):
        batch = ["http://h/a?q=1", "http://h/a?q=2"]
        art = self._art(0, ["http://h/a?q=1"], "made-up-mode")
        events.reset(); events.configure(tmp_path)
        c = _fresh(monkeypatch, tmp_path)
        monkeypatch.setattr(settings, "concurrency",
                            lambda k, d=None: {"DALFOX_CHUNK": 4, "DALFOX_TARGETS": 4}.get(k, d))
        monkeypatch.setattr(params, "exec_tool", _exec(art, 0))
        params._dalfox_xss_fast(c, batch, _Prof())
        evs = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()]
        mem = [e for e in evs if e.get("measure") == "dalfox_membership"]
        assert mem and mem[-1]["kind"] == "unknown", evs
        assert "membership cannot be decided" in mem[-1]["reason"]
        assert "http://h/a?q=2" in mem[-1]["reason"], "and it NAMES what it cannot decide"
        assert "coverage is UNKNOWN rather than clean" in mem[-1]["reason"]
        events.reset()

    def test_an_unknown_mode_that_reported_EVERYTHING_is_simply_clean(self, monkeypatch, tmp_path):
        batch = ["http://h/a?q=1", "http://h/a?q=2"]
        r, st, acc = self._run(monkeypatch, tmp_path, self._art(0, batch, "made-up-mode"), batch)
        assert r.status == Status.EMPTY and st["chunks"] and not acc
        evs_dir = tmp_path / "events.jsonl"
        assert not [e for e in (json.loads(x) for x in evs_dir.read_text().splitlines())
                    if e.get("measure") == "dalfox_membership"], "nothing was ambiguous"

    def test_but_an_unknown_mode_still_owes_a_target_nobody_mentioned(self, monkeypatch, tmp_path):
        """The weakest claim that cannot be wrong: a signature absent from the summary was genuinely
        never mentioned, whatever policy produced it."""
        batch = ["http://h/a?q=1", "http://h/b?q=1"]
        art = self._art(0, ["http://h/a?q=1"], "made-up-mode")
        r, st, acc = self._run(monkeypatch, tmp_path, art, batch)
        assert r.status == Status.PARTIAL and st.get("remainder") == {"0": ["http://h/b?q=1"]}
        assert "http://h/b?q=1" in acc[-1]["reason"]

    def test_and_the_unknown_policy_is_DISCLOSED_on_the_result(self, monkeypatch, tmp_path):
        batch = ["http://h/a?q=1"]
        events.reset(); events.configure(tmp_path)
        c = _fresh(monkeypatch, tmp_path)
        monkeypatch.setattr(params, "exec_tool",
                            _exec(self._art(0, batch, "made-up-mode"), 0))
        r = params._dalfox_xss_fast(c, batch, _Prof())
        assert "dedup_mode=unknown" in r.note and "NOT the `signature` we asked for" in r.note
        events.reset()


class TestAmbiguityAndMultiplicitySURVIVEAResume:
    """review#41 (Lumpy): both facts were correct WITHIN one attempt and lost across lifecycles — the
    chunk is recorded complete, so the next run skips it and re-derives nothing, and a fresh coverage
    generation retires the old record."""

    @staticmethod
    def _art(n, targets, mode, dedup=0):
        return json.dumps({"meta": {
            "findings_count": n, "incomplete": False, "dedup_mode": mode,
            "targets_deduplicated": dedup, "total_requests": 1,
            "target_summary": [{"target": t, "status": "clean", "findings_count": 0}
                               for t in targets]}}) + "\n"

    def _membership(self, tmp_path):
        evs = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()]
        return [e for e in evs if e.get("measure") == "dalfox_membership"]

    def test_the_undecidable_membership_is_RE_EMITTED_on_a_resume(self, monkeypatch, tmp_path):
        batch = ["http://h/a?q=1", "http://h/a?q=2"]
        events.reset(); events.configure(tmp_path)
        c = _fresh(monkeypatch, tmp_path)
        monkeypatch.setattr(settings, "concurrency",
                            lambda k, d=None: {"DALFOX_CHUNK": 4, "DALFOX_TARGETS": 4}.get(k, d))
        monkeypatch.setattr(params, "exec_tool",
                            _exec(self._art(0, ["http://h/a?q=1"], "made-up-mode"), 0))
        params._dalfox_xss_fast(c, batch, _Prof())
        assert self._membership(tmp_path), "recorded on the first run"
        assert _state(c)["membership"], "…and PERSISTED with the state"

        # a fresh lifecycle: the chunk is complete, so nothing runs — and the doubt must still be there
        (tmp_path / "events.jsonl").unlink()
        events.reset(); events.configure(tmp_path)
        monkeypatch.setattr(params, "exec_tool",
                            lambda *a, **k: pytest.fail("a completed chunk was re-scanned"))
        params._dalfox_xss_fast(c, batch, _Prof())
        mem = self._membership(tmp_path)
        assert mem, "an unresolved doubt must not quietly become a clean run"
        assert "http://h/a?q=2" in mem[-1]["reason"] and mem[-1]["kind"] == "unknown"
        events.reset()

    def test_a_REMAINDER_ONLY_retry_does_not_clear_doubt_it_never_touched(self, monkeypatch, tmp_path):
        """review#42 (Lumpy), and my previous test asserted the bug: the first attempt leaves `a?q=2`
        undecidable and owes only `b?q=1`; the retry scans `b?q=1` alone and used to clear the doubt
        about `a?q=2` — a question answered by a scan that never asked it."""
        batch = ["http://h/a?q=1", "http://h/a?q=2", "http://h/b?q=1"]
        events.reset(); events.configure(tmp_path)
        c = _fresh(monkeypatch, tmp_path)
        monkeypatch.setattr(settings, "concurrency",
                            lambda k, d=None: {"DALFOX_CHUNK": 4, "DALFOX_TARGETS": 4}.get(k, d))
        monkeypatch.setattr(params, "exec_tool",
                            _exec(self._art(0, ["http://h/a?q=1"], "made-up-mode"), 0))
        params._dalfox_xss_fast(c, batch, _Prof())
        assert _state(c)["membership"] == {"0": ["http://h/a?q=2"]}, _state(c)
        assert _state(c)["remainder"] == {"0": ["http://h/b?q=1"]}

        # the retry scans ONLY the owed target and reconciles it cleanly
        monkeypatch.setattr(params, "exec_tool",
                            _exec(self._art(0, ["http://h/b?q=1"], "signature"), 0))
        params._dalfox_xss_fast(c, batch, _Prof())
        assert _state(c)["membership"] == {"0": ["http://h/a?q=2"]}, \
            "the retry never scanned a?q=2; it cannot answer for it"

    def test_an_UNREADABLE_retry_clears_nothing(self, monkeypatch, tmp_path):
        """The chunk must still be RETRYABLE for this to be reachable at all — an ambiguity on an
        otherwise clean chunk is recorded done and never re-runs, so a foreign target keeps it open."""
        batch = ["http://h/a?q=1", "http://h/a?q=2"]
        c = _fresh(monkeypatch, tmp_path)
        monkeypatch.setattr(settings, "concurrency",
                            lambda k, d=None: {"DALFOX_CHUNK": 4, "DALFOX_TARGETS": 4}.get(k, d))
        monkeypatch.setattr(params, "exec_tool",
                            _exec(self._art(0, ["http://h/a?q=1", "http://h/zzz?q=1"],
                                            "made-up-mode"), 0))
        params._dalfox_xss_fast(c, batch, _Prof())
        assert _state(c)["membership"] == {"0": ["http://h/a?q=2"]}
        assert _state(c)["chunks"] == {}, "a foreign target keeps the chunk retryable"
        monkeypatch.setattr(params, "exec_tool", _exec("{not json\n", 2))   # unreadable retry
        params._dalfox_xss_fast(c, batch, _Prof())
        assert _state(c)["membership"] == {"0": ["http://h/a?q=2"]}, _state(c)

    def test_a_FULL_readable_re_scan_DOES_clear_it(self, monkeypatch, tmp_path):
        """The other direction: an attempt that actually scanned the target and reconciled it resolves
        the doubt — it is a reading of an attempt, not a permanent verdict."""
        batch = ["http://h/a?q=1", "http://h/a?q=2"]
        c = _fresh(monkeypatch, tmp_path)
        monkeypatch.setattr(settings, "concurrency",
                            lambda k, d=None: {"DALFOX_CHUNK": 4, "DALFOX_TARGETS": 4}.get(k, d))
        # first attempt: ambiguous AND not clean (a foreign target keeps the chunk retryable), so the
        # chunk is not recorded done and the next lifecycle re-scans the whole batch
        monkeypatch.setattr(params, "exec_tool",
                            _exec(self._art(0, ["http://h/a?q=1", "http://h/zzz?q=1"],
                                            "made-up-mode"), 0))
        params._dalfox_xss_fast(c, batch, _Prof())
        assert _state(c)["membership"] == {"0": ["http://h/a?q=2"]}, _state(c)
        monkeypatch.setattr(params, "exec_tool", _exec(self._art(0, batch, "exact"), 0))
        params._dalfox_xss_fast(c, batch, _Prof())
        assert not _state(c).get("membership"), _state(c)

    def test_the_stored_ambiguity_is_TARGETS_not_prose(self, monkeypatch, tmp_path):
        """A sentence cannot be cleared per identity."""
        batch = ["http://h/a?q=1", "http://h/a?q=2"]
        c = _fresh(monkeypatch, tmp_path)
        monkeypatch.setattr(settings, "concurrency",
                            lambda k, d=None: {"DALFOX_CHUNK": 4, "DALFOX_TARGETS": 4}.get(k, d))
        monkeypatch.setattr(params, "exec_tool",
                            _exec(self._art(0, ["http://h/a?q=1"], "made-up-mode"), 0))
        params._dalfox_xss_fast(c, batch, _Prof())
        assert _state(c)["membership"] == {"0": ["http://h/a?q=2"]}

    def test_the_resume_CONSUMES_the_owed_multiplicity(self, monkeypatch, tmp_path):
        """The state stored two owed occurrences of one URL; `set()` then selected all three originals,
        so a target that had already answered was requested again."""
        batch = ["http://h/a?q=1"] * 3
        c = _fresh(monkeypatch, tmp_path)
        monkeypatch.setattr(settings, "concurrency",
                            lambda k, d=None: {"DALFOX_CHUNK": 4, "DALFOX_TARGETS": 4}.get(k, d))
        monkeypatch.setattr(params, "exec_tool",
                            _exec(self._art(0, ["http://h/a?q=1"], "off"), 0))
        params._dalfox_xss_fast(c, batch, _Prof())
        assert _state(c)["remainder"] == {"0": ["http://h/a?q=1", "http://h/a?q=1"]}
        sent = []

        def _spy(t, cmd, timeout=None, **k):
            bf = pathlib.Path(cmd[cmd.index("file") + 1])
            sent.append(len([u for u in bf.read_text().splitlines() if u.strip()]))
            return _exec(self._art(0, ["http://h/a?q=1", "http://h/a?q=1"], "off"), 0)(t, cmd, timeout, **k)
        monkeypatch.setattr(params, "exec_tool", _spy)
        params._dalfox_xss_fast(c, batch, _Prof())
        assert sent == [2], f"the retry sent {sent} target(s), not the two that were owed"

    def test_a_remainder_of_one_still_resumes_one(self, monkeypatch, tmp_path):
        """The ordinary case must not regress while fixing the counted one."""
        batch = ["http://h/a?q=1", "http://h/b?q=1"]
        c = _fresh(monkeypatch, tmp_path)
        monkeypatch.setattr(settings, "concurrency",
                            lambda k, d=None: {"DALFOX_CHUNK": 4, "DALFOX_TARGETS": 4}.get(k, d))
        monkeypatch.setattr(params, "exec_tool",
                            _exec(self._art(0, ["http://h/a?q=1"], "exact"), 0))
        params._dalfox_xss_fast(c, batch, _Prof())
        assert _state(c)["remainder"] == {"0": ["http://h/b?q=1"]}
        sent = []

        def _spy(t, cmd, timeout=None, **k):
            bf = pathlib.Path(cmd[cmd.index("file") + 1])
            sent.extend(u for u in bf.read_text().splitlines() if u.strip())
            return _exec(self._art(0, ["http://h/b?q=1"], "exact"), 0)(t, cmd, timeout, **k)
        monkeypatch.setattr(params, "exec_tool", _spy)
        params._dalfox_xss_fast(c, batch, _Prof())
        assert sent == ["http://h/b?q=1"], sent


class TestOFFOwesEveryOCCURRENCE:
    """review#43 (Lumpy): under `dedup_mode=off` each `target_summary` row IS an occurrence. Both halves
    of the remainder — the rows dalfox NAMED as failed, and the occurrences it never reported — were
    being set-deduplicated, so three owed scans persisted as one."""

    @staticmethod
    def _art(targets_with_status, dedup=0):
        return json.dumps({"meta": {
            "findings_count": 0, "incomplete": False, "dedup_mode": "off",
            "targets_deduplicated": dedup, "total_requests": 1,
            "target_summary": [{"target": t, "status": st, "findings_count": 0,
                                **({"error_code": ec} if ec else {})}
                               for t, st, ec in targets_with_status]}}) + "\n"

    def _run(self, monkeypatch, tmp_path, art, batch):
        c = _fresh(monkeypatch, tmp_path)
        monkeypatch.setattr(settings, "concurrency",
                            lambda k, d=None: {"DALFOX_CHUNK": 8, "DALFOX_TARGETS": 4}.get(k, d))
        monkeypatch.setattr(params, "exec_tool", _exec(art, 0))
        params._dalfox_xss_fast(c, batch, _Prof())
        return c

    def test_a_named_failure_plus_unlisted_occurrences_are_ALL_owed(self, monkeypatch, tmp_path):
        """Codex's reproduction: 3 identical inputs, 1 reported SESSION_LOST -> 1 named + 2 unlisted."""
        batch = ["http://h/a?q=1"] * 3
        c = self._run(monkeypatch, tmp_path,
                      self._art([("http://h/a?q=1", "skipped", "SESSION_LOST")]), batch)
        assert _state(c)["remainder"] == {"0": ["http://h/a?q=1"] * 3}, _state(c)

    def test_and_the_retry_sends_all_three(self, monkeypatch, tmp_path):
        batch = ["http://h/a?q=1"] * 3
        c = self._run(monkeypatch, tmp_path,
                      self._art([("http://h/a?q=1", "skipped", "SESSION_LOST")]), batch)
        sent = []

        def _spy(t, cmd, timeout=None, **k):
            bf = pathlib.Path(cmd[cmd.index("file") + 1])
            sent.append(len([u for u in bf.read_text().splitlines() if u.strip()]))
            return _exec(self._art([("http://h/a?q=1", "clean", None)] * 3), 0)(t, cmd, timeout, **k)
        monkeypatch.setattr(params, "exec_tool", _spy)
        params._dalfox_xss_fast(c, batch, _Prof())
        assert sent == [3], f"the retry sent {sent}, not the three occurrences owed"

    def test_named_failures_alone_keep_their_multiplicity(self, monkeypatch, tmp_path):
        """Two occurrences reported, BOTH failed: two scans owed, not one."""
        batch = ["http://h/a?q=1"] * 2
        c = self._run(monkeypatch, tmp_path,
                      self._art([("http://h/a?q=1", "skipped", "SESSION_LOST")] * 2), batch)
        assert _state(c)["remainder"] == {"0": ["http://h/a?q=1"] * 2}, _state(c)

    def test_signature_mode_dedupes_a_target_dalfox_NAMED_twice(self, monkeypatch, tmp_path):
        """One identity is one scan under `signature`, so two failure rows for the same target owe ONE
        retry — unlike `off`, where two rows are two occurrences. (A named failure and an unlisted
        target can never overlap in this mode: a named target is by definition reported, so the
        subtraction beside the dedupe is inert here — the dedupe is what carries the rule.)"""
        batch = ["http://h/a?q=1"]
        art = json.dumps({"meta": {
            "findings_count": 0, "incomplete": False, "dedup_mode": "signature",
            "targets_deduplicated": 0, "total_requests": 1,
            "target_summary": [{"target": "http://h/a?q=1", "status": "skipped",
                                "error_code": "SESSION_LOST", "findings_count": 0}] * 2}}) + "\n"
        c = self._run(monkeypatch, tmp_path, art, batch)
        assert _state(c)["remainder"] == {"0": ["http://h/a?q=1"]}, _state(c)

    def test_signature_mode_still_DEDUPES_the_remainder(self, monkeypatch, tmp_path):
        """One identity is one scan there, so a named failure and an unlisted target that share it must
        not be owed twice."""
        batch = ["http://h/a?q=1", "http://h/a?q=2", "http://h/b?q=1"]
        art = json.dumps({"meta": {
            "findings_count": 0, "incomplete": False, "dedup_mode": "signature",
            "targets_deduplicated": 1, "total_requests": 1,
            "target_summary": [{"target": "http://h/a?q=1", "status": "skipped",
                                "error_code": "SESSION_LOST", "findings_count": 0}]}}) + "\n"
        c = self._run(monkeypatch, tmp_path, art, batch)
        assert _state(c)["remainder"] == {"0": ["http://h/a?q=1", "http://h/b?q=1"]}, _state(c)


class TestNamedFailuresCollapseByTheMODESIdentity:
    """review#44 (Lumpy): the remainder deduped named failures by the EXACT URL while claiming "one
    signature identity owes one retry" — so `/a?q=1` and `/a?q=2`, one signature and both
    `SESSION_LOST`, were owed twice under `dedup_mode=signature`. A test that only repeats an identical
    URL passes exact-URL dedup and proves nothing about the rule."""

    @staticmethod
    def _art(mode, rows, dedup=0):
        return json.dumps({"meta": {
            "findings_count": 0, "incomplete": False, "dedup_mode": mode,
            "targets_deduplicated": dedup, "total_requests": 1,
            "target_summary": [{"target": t, "status": "skipped", "error_code": "SESSION_LOST",
                                "findings_count": 0} for t in rows]}}) + "\n"

    def _run(self, monkeypatch, tmp_path, art, batch):
        c = _fresh(monkeypatch, tmp_path)
        monkeypatch.setattr(settings, "concurrency",
                            lambda k, d=None: {"DALFOX_CHUNK": 8, "DALFOX_TARGETS": 4}.get(k, d))
        monkeypatch.setattr(params, "exec_tool", _exec(art, 0))
        params._dalfox_xss_fast(c, batch, _Prof())
        return _state(c).get("remainder", {})

    def test_SIGNATURE_collapses_two_URLs_that_share_one(self, monkeypatch, tmp_path):
        batch = ["http://h/a?q=1", "http://h/a?q=2"]
        rem = self._run(monkeypatch, tmp_path, self._art("signature", batch, dedup=1), batch)
        assert rem == {"0": ["http://h/a?q=1"]}, rem

    def test_SIGNATURE_keeps_two_URLs_with_DIFFERENT_signatures(self, monkeypatch, tmp_path):
        batch = ["http://h/a?q=1", "http://h/b?q=1"]
        rem = self._run(monkeypatch, tmp_path, self._art("signature", batch), batch)
        assert rem == {"0": ["http://h/a?q=1", "http://h/b?q=1"]}, rem

    def test_EXACT_keeps_them_because_the_URLs_differ(self, monkeypatch, tmp_path):
        """The same two URLs, a different policy, a different answer — which is the whole point."""
        batch = ["http://h/a?q=1", "http://h/a?q=2"]
        rem = self._run(monkeypatch, tmp_path, self._art("exact", batch), batch)
        assert rem == {"0": ["http://h/a?q=1", "http://h/a?q=2"]}, rem

    def test_EXACT_collapses_a_target_named_twice(self, monkeypatch, tmp_path):
        batch = ["http://h/a?q=1"]
        rem = self._run(monkeypatch, tmp_path,
                        self._art("exact", ["http://h/a?q=1", "http://h/a?q=1"]), batch)
        assert rem == {"0": ["http://h/a?q=1"]}, rem

    def test_UNKNOWN_collapses_NOTHING(self, monkeypatch, tmp_path):
        """Re-scanning is the safe error under a policy we cannot read; dropping an owed scan is not."""
        batch = ["http://h/a?q=1", "http://h/a?q=2"]
        rem = self._run(monkeypatch, tmp_path, self._art("made-up-mode", batch), batch)
        assert rem == {"0": ["http://h/a?q=1", "http://h/a?q=2"]}, rem

    def test_UNKNOWN_keeps_even_a_REPEATED_url(self, monkeypatch, tmp_path):
        """The case exact-URL dedup would collapse: under an unreadable policy those two rows might be
        two occurrences (`off`) or one target named twice (`exact`), and we cannot tell — so both are
        owed."""
        batch = ["http://h/a?q=1"]
        rem = self._run(monkeypatch, tmp_path,
                        self._art("made-up-mode", ["http://h/a?q=1", "http://h/a?q=1"]), batch)
        assert rem == {"0": ["http://h/a?q=1", "http://h/a?q=1"]}, rem

    def test_the_helper_states_the_rule_directly(self):
        named = ["http://h/a?q=1", "http://h/a?q=2", "http://h/b?q=1"]
        assert params._dedupe_owed(named, "off") == named
        assert params._dedupe_owed(named, "unknown") == named
        repeated = ["http://h/a?q=1", "http://h/a?q=1"]
        assert params._dedupe_owed(repeated, "unknown") == repeated, "unknown collapses NOTHING"
        assert params._dedupe_owed(repeated, "exact") == ["http://h/a?q=1"]
        assert params._dedupe_owed(named, "exact") == named
        assert params._dedupe_owed(named, "signature") == ["http://h/a?q=1", "http://h/b?q=1"]
