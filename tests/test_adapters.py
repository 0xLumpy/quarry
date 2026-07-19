"""File-output status adapters — the shared matrix and each tool's fail-closed parser.

These are the highest-risk code in the recon path: a laundered status (a degraded/failed run reported
SUCCESS) or a crash on a malformed artifact both corrupt the run verdict. Every case here mirrors a
verify-quarry.sh regression, now as a hermetic offline test.
"""
import json

import pytest

from quarry_recon.runner import (RunResult, Status, ffuf_results, reclassify_ffuf,
                                  reclassify_from_artifact, reclassify_from_files)

pytestmark = pytest.mark.offline


def _r(status, exit_code=0, stderr_tail=""):
    return RunResult("t", [], status, exit_code, 0.1, None, 0, stderr_tail=stderr_tail)


# ── shared core: reclassify_from_artifact (T1.6) ──────────────────────────────
class TestReclassifyFromArtifact:
    def test_skipped_untouched(self):
        assert reclassify_from_artifact(_r(Status.SKIPPED), 5).status == Status.SKIPPED

    @pytest.mark.parametrize("n,expect", [(3, Status.SUCCESS), (0, Status.EMPTY), (None, Status.PARTIAL)])
    def test_clean(self, n, expect):
        assert reclassify_from_artifact(_r(Status.SUCCESS), n).status == expect

    @pytest.mark.parametrize("hard", [Status.FAILED, Status.TIMED_OUT, Status.BLOCKED])
    def test_degraded_with_findings_is_partial_never_success(self, hard):
        assert reclassify_from_artifact(_r(hard), 2).status == Status.PARTIAL

    @pytest.mark.parametrize("hard", [Status.FAILED, Status.TIMED_OUT, Status.BLOCKED])
    def test_degraded_empty_keeps_hard_state(self, hard):
        # an empty/absent artifact preserves nothing → the hard state stands
        assert reclassify_from_artifact(_r(hard), 0).status == hard
        assert reclassify_from_artifact(_r(hard), None).status == hard

    def test_partial_is_not_clean(self):
        # PARTIAL + findings must stay PARTIAL, never be laundered up to SUCCESS
        assert reclassify_from_artifact(_r(Status.PARTIAL), 2).status == Status.PARTIAL

    @pytest.mark.parametrize("bad", [-1, True, 1.5, "2"])
    def test_invalid_count_fails_closed(self, bad):
        # bool/float/str/negative → treated as None (no trustworthy count), so clean → PARTIAL not SUCCESS
        assert reclassify_from_artifact(_r(Status.SUCCESS), bad).status == Status.PARTIAL

    def test_gowitness_wrapper_de_launders(self):
        # reclassify_from_files (gowitness) delegates to the core: FAILED + shots is PARTIAL, not SUCCESS
        assert reclassify_from_files(_r(Status.FAILED), 1, "screenshot").status == Status.PARTIAL
        assert reclassify_from_files(_r(Status.EMPTY), 9, "screenshot").status == Status.SUCCESS


# ── ffuf artifact adapter (batch 3 + T2.2) ────────────────────────────────────
class TestFfuf:
    def _art(self, tmp_path, payload):
        p = tmp_path / "o.json"
        p.write_text(json.dumps(payload) if not isinstance(payload, str) else payload)
        return p

    def test_results_root_validation(self, tmp_path):
        assert ffuf_results(self._art(tmp_path, {"results": [{"u": 1}]})) == [{"u": 1}]
        assert ffuf_results(self._art(tmp_path, [])) is None          # bare list root → None (no AttributeError)
        assert ffuf_results(self._art(tmp_path, {"results": "x"})) is None
        assert ffuf_results(tmp_path / "nope.json") is None

    def test_hits_hidden_by_silent_become_success(self, tmp_path):
        a = self._art(tmp_path, {"results": [{"u": 1}]})
        assert reclassify_ffuf(_r(Status.EMPTY), a).status == Status.SUCCESS

    def test_blocked_matrix_keyed_on_exit(self, tmp_path):
        empty = self._art(tmp_path, {"results": []})
        # clean exit + block signature + 0 → PARTIAL (completed); nonzero exit + 0 → stays BLOCKED
        assert reclassify_ffuf(RunResult("ffuf", [], Status.BLOCKED, 0, 0.1, empty, 0), empty).status == Status.PARTIAL
        assert reclassify_ffuf(RunResult("ffuf", [], Status.BLOCKED, 1, 0.1, empty, 0), empty).status == Status.BLOCKED

    def test_hard_state_not_laundered(self, tmp_path):
        hits = self._art(tmp_path, {"results": [{"u": 1}]})
        assert reclassify_ffuf(RunResult("ffuf", [], Status.FAILED, 0, 0.1, hits, 0), hits).status == Status.PARTIAL
        empty = self._art(tmp_path, {"results": []})
        assert reclassify_ffuf(RunResult("ffuf", [], Status.FAILED, 0, 0.1, empty, 0), empty).status == Status.FAILED

    def test_native_maxtime_demotes_clean_to_partial(self, tmp_path):
        # ffuf -maxtime stops mid-wordlist, finalizes the artifact, exits clean → must NOT be SUCCESS/EMPTY
        mt = "[WARN] Maximum running time for entire process reached, exiting."
        hits = self._art(tmp_path, {"results": [{"u": 1}]})
        empty = self._art(tmp_path, {"results": []})
        assert reclassify_ffuf(RunResult("ffuf", [], Status.EMPTY, 0, 0.1, hits, 0, stderr_tail=mt), hits).status == Status.PARTIAL
        assert reclassify_ffuf(RunResult("ffuf", [], Status.EMPTY, 0, 0.1, empty, 0, stderr_tail=mt), empty).status == Status.PARTIAL


# ── gitleaks report adapter (T1.3) ────────────────────────────────────────────
class TestGitleaks:
    def _rep(self, tmp_path, content):
        from quarry_recon.phases import crawl
        p = tmp_path / "rep.json"
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content)
        r = _r(Status.EMPTY)
        return crawl._gitleaks_status(r, p), r.status

    def test_clean_findings(self, tmp_path):
        items, st = self._rep(tmp_path, '[{"RuleID":"aws","Secret":"x"}]')
        assert items == [{"RuleID": "aws", "Secret": "x"}] and st == Status.SUCCESS

    def test_clean_empty(self, tmp_path):
        assert self._rep(tmp_path, "[]") == ([], Status.EMPTY)

    @pytest.mark.parametrize("bad", ['{"x":1}', "null", '[{"a":1},"nope"]', "GARBAGE{", b"\xff\xfe"])
    def test_malformed_root_or_row_returns_none(self, tmp_path, bad):
        items, st = self._rep(tmp_path, bad)
        assert items is None and st == Status.PARTIAL       # clean run but no trustworthy report → PARTIAL

    def test_hard_state_kept(self, tmp_path):
        # FAILED + a valid empty report: the report parses ([]), but a degraded run keeps its hard state
        from quarry_recon.phases import crawl
        p = tmp_path / "r.json"
        p.write_text("[]")
        r = _r(Status.FAILED)
        assert crawl._gitleaks_status(r, p) == [] and r.status == Status.FAILED


# ── smap -oJ adapter (T1.6) ───────────────────────────────────────────────────
class TestSmap:
    def _art(self, tmp_path, payload, raw=None):
        p = tmp_path / "s.json"
        p.write_bytes(raw) if raw is not None else p.write_text(json.dumps(payload))
        return p

    def _rec(self, ip="1.2.3.4", uh="h.example.com", ports=((80, "http"),)):
        return {"ip": ip, "user_hostname": uh, "hostnames": ["sh.com"],
                "ports": [{"port": p, "service": s} for p, s in ports]}

    def test_parse_valid(self, tmp_path):
        from quarry_recon.phases import probe
        recs, complete = probe._smap_records(self._art(tmp_path, [self._rec()]))
        assert recs == [("1.2.3.4", "h.example.com", ["sh.com"], [(80, "http")])] and complete

    def test_keeps_valid_drops_malformed(self, tmp_path):
        from quarry_recon.phases import probe
        recs, complete = probe._smap_records(self._art(tmp_path, [
            self._rec(),
            ["not-a-dict"],
            {"ip": "bad", "ports": []},                      # invalid IP
            {"ip": "5.6.7.8", "user_hostname": "b.example.com", "hostnames": [],
             "ports": [{"port": 22, "service": "ssh"}, {"port": 99999}, {"port": True}]},
        ]))
        assert not complete                                  # malformed rows/ports seen
        assert [r[0] for r in recs] == ["1.2.3.4", "5.6.7.8"]
        assert recs[1][3] == [(22, "ssh")]                   # out-of-range 99999 + bool port dropped

    @pytest.mark.parametrize("bad", [None])
    def test_unreadable_root_none(self, tmp_path, bad):
        from quarry_recon.phases import probe
        assert probe._smap_records(tmp_path / "nope.json") == (None, False)
        assert probe._smap_records(self._art(tmp_path, {"not": "list"})) == (None, False)
        assert probe._smap_records(self._art(tmp_path, None, raw=b"GARBAGE{")) == (None, False)


# ── nmap -oX adapter (T1.6) ───────────────────────────────────────────────────
class TestNmap:
    FIN = '<runstats><finished exit="success"/></runstats>'

    def _xml(self, tmp_path, hosts, fin=None):
        p = tmp_path / "n.xml"
        p.write_text(f'<?xml version="1.0"?><nmaprun>{hosts}{self.FIN if fin is None else fin}</nmaprun>')
        return p

    HOST = ('<host><address addr="1.2.3.4" addrtype="ipv4"/><ports>'
            '<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.20"/></port>'
            '<port protocol="tcp" portid="443"><state state="closed"/></port>'
            '<port protocol="tcp" portid="8080"><state state="open"/></port></ports></host>')

    def test_open_ports_complete(self, tmp_path):
        from quarry_recon.phases import probe
        svcs, complete = probe._nmap_services(self._xml(tmp_path, self.HOST))
        assert svcs == [("1.2.3.4", 80, "tcp", "http", "nginx", "1.20"), ("1.2.3.4", 8080, "tcp", "", "", "")]
        assert complete                                      # 443 closed skipped; clean finish

    def test_no_finished_marker_incomplete_keeps_rows(self, tmp_path):
        from quarry_recon.phases import probe
        svcs, complete = probe._nmap_services(self._xml(tmp_path, self.HOST, fin=""))
        assert len(svcs) == 2 and not complete               # rows kept, but completion uncertain → caller PARTIAL

    def test_errored_finish_incomplete(self, tmp_path):
        from quarry_recon.phases import probe
        _, complete = probe._nmap_services(self._xml(tmp_path, self.HOST,
                                                     fin='<runstats><finished exit="error"/></runstats>'))
        assert not complete

    @pytest.mark.parametrize("bad", ["<nmaprun><host", "<other/>"])
    def test_malformed_or_wrong_root_none(self, tmp_path, bad):
        from quarry_recon.phases import probe
        p = tmp_path / "b.xml"
        p.write_text(bad)
        assert probe._nmap_services(p) == (None, False)
