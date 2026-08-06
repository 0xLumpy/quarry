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

META1 = '{"meta":{"findings_count":1}}\n'
META0 = '{"meta":{"findings_count":0}}\n'
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
    return params._parse_dalfox_jsonl(p)


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
        f, art = params._parse_dalfox_jsonl(pathlib.Path("/nonexistent/x.jsonl"))
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


def _exec(artifact, rc):
    def fx(t, cmd, timeout=None, **k):
        cf = pathlib.Path(cmd[cmd.index("-o") + 1]); cf.parent.mkdir(parents=True, exist_ok=True); cf.write_text(artifact)
        return RunResult("dalfox", cmd, Status.SUCCESS if rc in (0, 1) else Status.FAILED, rc, 0.1, cf, 0)
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
        monkeypatch.setattr(params, "exec_tool", _exec("{\"meta\":{\"findings_count\":0}}\n", 0))  # retry: clean-empty
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
                             cf, 0)
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

      * `--blind-oob` is the primary channel — dalfox mints a callback PER PAYLOAD and correlates each
        interaction to target/param/location/method/payload. One `-b` URL covers a whole invocation and
        cannot do that.
      * OWNERSHIP IS DALFOX'S. It mints the nonce, registers, polls, waits and maps the hit back. Quarry
        owns the server + credentials and imports the correlation, so findings carry `oob_owner: dalfox`.
      * Never auto-enabled: `MODES.BLIND_XSS` arms it, and a PUBLIC backend needs its own permission.
      * `-b` is an opt-in legacy collector, never paired automatically.
    """

    class _P:
        http_rl = 0
        blind_xss = False
        blind_xss_public = False
        blind_xss_dual = False

    @staticmethod
    def _oob(monkeypatch, **kw):
        monkeypatch.setattr(secrets, "oob", lambda: dict(kw))

    def _cmd(self, monkeypatch, prof, **oob):
        self._oob(monkeypatch, **oob)
        return params._dalfox_cmd("b.txt", "o.jsonl", prof, 1)

    def test_it_is_OFF_unless_explicitly_armed(self, monkeypatch):
        cmd = self._cmd(monkeypatch, self._P(), interactsh_server="oob.mine.test")
        assert not any(c.startswith("--blind-oob") for c in cmd), cmd
        plan = params._blind_oob_plan(self._P())
        assert not plan["armed"] and "MODES.BLIND_XSS is off" in plan["reason"]

    def test_a_self_hosted_server_is_used_with_its_secret(self, monkeypatch, tmp_path):
        """review#17 (Lumpy): the token must NOT reach argv — `/proc/<pid>/cmdline` is readable by every
        process of this user, and redacting our own logs does not change that. dalfox reads
        `scan.blind_oob_secret` from a `--config` TOML, so it travels in a 0600 file."""
        import stat
        self._oob(monkeypatch, interactsh_server="oob.mine.test", interactsh_token="T0K")
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
        self._oob(monkeypatch, interactsh_server="oob.mine.test")     # server, no token
        p = self._P(); p.blind_xss = True
        cmd = params._dalfox_cmd(tmp_path / "b.txt", tmp_path / "o.jsonl", p, 1)
        assert "--config" not in cmd and not list(tmp_path.glob("*.toml"))

    def test_the_secret_never_reaches_the_recorded_command(self, monkeypatch, tmp_path):
        """The work-unit config and every telemetry copy of the command must be secret-free too."""
        self._oob(monkeypatch, interactsh_server="oob.mine.test", interactsh_token="T0K")
        p = self._P(); p.blind_xss = True
        cmd = params._dalfox_cmd(tmp_path / "b.txt", tmp_path / "o.jsonl", p, 1)
        assert "T0K" not in " ".join(str(c) for c in cmd)

    def test_the_server_is_ONE_argv_token(self, monkeypatch):
        """`--blind-oob[=<domains>]` takes its value attached. A separate `=host` argument would be
        parsed as a TARGET — measured against the 3.2.0 binary."""
        p = self._P(); p.blind_xss = True
        cmd = self._cmd(monkeypatch, p, interactsh_server="oob.mine.test")
        assert "=oob.mine.test" not in cmd, cmd
        assert not any(c.startswith("=") for c in cmd)

    def test_a_PUBLIC_backend_is_REFUSED_without_its_own_permission(self, monkeypatch):
        p = self._P(); p.blind_xss = True
        cmd = self._cmd(monkeypatch, p)                     # no interactsh_server configured
        assert not any(c.startswith("--blind-oob") for c in cmd), cmd
        plan = params._blind_oob_plan(p)
        assert not plan["armed"] and plan["backend"] == "public"
        assert "REFUSED" in plan["reason"] and "BLIND_XSS_PUBLIC" in plan["reason"]

    def test_public_is_used_once_explicitly_permitted(self, monkeypatch):
        p = self._P(); p.blind_xss = True; p.blind_xss_public = True
        cmd = self._cmd(monkeypatch, p)
        assert "--blind-oob" in cmd and not any(c.startswith("--blind-oob=") for c in cmd)
        assert "--blind-oob-secret" not in cmd, "no secret for a public backend"

    def test_a_self_hosted_server_needs_no_public_permission(self, monkeypatch):
        p = self._P(); p.blind_xss = True                   # blind_xss_public stays False
        cmd = self._cmd(monkeypatch, p, interactsh_server="oob.mine.test")
        assert "--blind-oob=oob.mine.test" in cmd

    def test_b_is_NOT_paired_automatically(self, monkeypatch):
        """dalfox fires BOTH channels when both are set — duplicate payloads, extra requests, two
        callback lifecycles. `-b` stays an explicit operator choice."""
        p = self._P(); p.blind_xss = True
        cmd = self._cmd(monkeypatch, p, interactsh_server="oob.mine.test")
        assert "-b" not in cmd, cmd

    def test_a_dormant_legacy_url_does_not_silently_double_the_channels(self, monkeypatch):
        """review#17 (Lumpy): with BLIND_XSS armed AND a historical `blind_xss_url` present, the lane
        emitted BOTH — duplicate payloads because a dormant setting existed, not because anyone chose
        it. It refuses and names the knob instead."""
        p = self._P(); p.blind_xss = True
        cmd = self._cmd(monkeypatch, p, interactsh_server="oob.mine.test",
                        blind_xss_url="https://col.example")
        assert not any(c.startswith("--blind-oob") for c in cmd) and "-b" not in cmd, cmd
        plan = params._blind_oob_plan(p)
        assert plan["channel"] == "conflict" and not plan["armed"]
        assert "BLIND_XSS_DUAL" in plan["reason"] and "REFUSED" in plan["reason"]

    def test_dual_mode_runs_BOTH_only_when_explicitly_permitted(self, monkeypatch):
        p = self._P(); p.blind_xss = True; p.blind_xss_dual = True
        cmd = self._cmd(monkeypatch, p, interactsh_server="oob.mine.test",
                        blind_xss_url="https://col.example")
        assert "--blind-oob=oob.mine.test" in cmd and cmd[cmd.index("-b") + 1] == "https://col.example"
        plan = params._blind_oob_plan(p)
        assert plan["channel"] == "dual" and "DOUBLES" in plan["reason"]

    def test_a_legacy_channel_is_an_explicit_CHOICE_not_a_fallback(self, monkeypatch):
        """A refused native channel must not fall back to the collector: the operator armed the native
        one, and quietly using a different channel is not what they asked for."""
        p = self._P(); p.blind_xss = True                    # no server, no public permission
        cmd = self._cmd(monkeypatch, p, blind_xss_url="https://col.example")
        plan = params._blind_oob_plan(p)
        assert plan["channel"] == "conflict", plan["channel"]
        assert "-b" not in cmd, "a refusal is not a fallback"

    def test_b_still_works_as_an_opt_in_legacy_collector(self, monkeypatch):
        cmd = self._cmd(monkeypatch, self._P(), blind_xss_url="https://col.example")
        assert cmd[cmd.index("-b") + 1] == "https://col.example"
        assert not any(c.startswith("--blind-oob") for c in cmd), "…and does not arm the OOB channel"

    def test_the_arming_flags_do_not_fail_open_on_quoted_yaml(self):
        """An arming flag must never be enabled by a QUOTED string, and a quoted value must fail LOUD in
        validation rather than silently leave the lane disabled against operator intent."""
        import tempfile as _tf
        import pytest as _pt
        from quarry_recon.config import ProfileError, TargetProfile
        prof = TargetProfile.__new__(TargetProfile)
        prof.modes = {"BLIND_XSS": "true", "BLIND_XSS_PUBLIC": "true", "BLIND_XSS_DUAL": "true"}
        assert prof.blind_xss is False and prof.blind_xss_public is False
        assert prof.blind_xss_dual is False
        # …and a quoted value fails LOUD through the real loader
        for bad in ("BLIND_XSS", "BLIND_XSS_PUBLIC", "BLIND_XSS_DUAL"):
            f = pathlib.Path(_tf.mkdtemp()) / "target.yaml"
            f.write_text("target: acme.com\nscope:\n  in: [acme.com]\n"
                         f"MODES:\n  {bad}: \"true\"\n")
            with _pt.raises(ProfileError):
                TargetProfile.load(f)

    def test_every_arming_flag_defaults_to_OFF(self):
        """An absent mode must never arm a lane: dual mode doubles blind payloads, and public OOB sends
        callbacks to a third party. Neither may happen because a key was missing."""
        from quarry_recon.config import TargetProfile
        prof = TargetProfile.__new__(TargetProfile)
        prof.modes = {}
        assert prof.blind_xss is False
        assert prof.blind_xss_public is False
        assert prof.blind_xss_dual is False

    def test_an_OOB_finding_records_dalfox_as_the_OWNER(self):
        row = ('{"type":"V","param":"q","data":"http://h/p?q=1","method":"GET","location":"Query",'
               '"detection_method":"oob","confidence_reason":"callback received","inject_type":"inHTML"}\n')
        f, art = _art('{"meta":{"findings_count":1,"incomplete":false}}\n' + row)
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
                            lambda: {"interactsh_server": "oob.mine.test", "interactsh_token": "T0K"})
        monkeypatch.setattr(params, "_make_oob_credential",
                            lambda s: (_ for _ in ()).throw(params.OobCredentialError("disk full")))
        monkeypatch.setattr(params, "exec_tool",
                            lambda *a, **k: pytest.fail("dalfox ran without its credential"))
        prof = type("P", (), {"http_rl": 0, "blind_xss": True, "blind_xss_public": False,
                              "blind_xss_dual": False})()
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
    """review#19 (Lumpy): the work unit fingerprinted only the legacy collector, so arming native OOB
    after a completed reflected scan reused the old chunks and injected NO blind payload — a lane that
    looks done and never ran what was just enabled."""

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
        prof = type("P", (), {"http_rl": 0, "blind_xss": False, "blind_xss_public": False,
                              "blind_xss_dual": False, **modes})()
        params._dalfox_xss_fast(c, ["http://h/a?q="], prof)
        st = json.loads((c.run.raw_path("params", "dalfox", "chunks.state.json")).read_text())
        return st["work_unit"]

    def test_arming_native_OOB_invalidates_a_reflected_only_resume(self, monkeypatch, tmp_path):
        off = self._wu(monkeypatch, tmp_path, "a", {})
        on = self._wu(monkeypatch, tmp_path, "b", {"interactsh_server": "s.test"}, blind_xss=True)
        assert off != on, "the old chunks would have been reused and no blind payload sent"

    def test_switching_BACKEND_invalidates_it_too(self, monkeypatch, tmp_path):
        pub = self._wu(monkeypatch, tmp_path, "c", {}, blind_xss=True, blind_xss_public=True)
        own = self._wu(monkeypatch, tmp_path, "d", {"interactsh_server": "s.test"}, blind_xss=True)
        assert pub != own

    def test_switching_SERVER_invalidates_it_too(self, monkeypatch, tmp_path):
        s1 = self._wu(monkeypatch, tmp_path, "e", {"interactsh_server": "s1.test"}, blind_xss=True)
        s2 = self._wu(monkeypatch, tmp_path, "f", {"interactsh_server": "s2.test"}, blind_xss=True)
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
        return type("P", (), {"http_rl": 0, "blind_xss": False, "blind_xss_public": False,
                              "blind_xss_dual": False, **kw})()

    def test_a_credential_refusal_does_NOT_also_claim_the_channel_was_tested(self, monkeypatch,
                                                                            tmp_path):
        c = self._lane(monkeypatch, tmp_path, "r")
        monkeypatch.setattr(secrets, "oob",
                            lambda: {"interactsh_server": "oob.mine.test", "interactsh_token": "T0K"})
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
        monkeypatch.setattr(secrets, "oob", lambda: {"interactsh_server": "oob.mine.test"})
        monkeypatch.setattr(params, "exec_tool", _exec(META0, 0))
        params._dalfox_xss_fast(c, ["http://h/a?q="], self._prof(blind_xss=True))
        chan = self._cov(tmp_path, "ok", "blind_xss_channel")
        assert chan[-1]["tested"] == 1 and chan[-1]["omitted"] == 0
        assert "1/1 invocation(s) started with the armed blind-XSS channel" in chan[-1]["reason"]

    def test_a_lifecycle_that_RAN_NOTHING_asserts_no_execution(self, monkeypatch, tmp_path):
        """Everything already complete: policy is still stated, execution claims nothing."""
        c = self._lane(monkeypatch, tmp_path, "a")
        monkeypatch.setattr(secrets, "oob", lambda: {"interactsh_server": "oob.mine.test"})
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
