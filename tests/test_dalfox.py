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
        assert params._parse_dalfox_jsonl(pathlib.Path("/nonexistent/x.jsonl")) == ([], False)

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
