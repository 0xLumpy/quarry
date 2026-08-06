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
