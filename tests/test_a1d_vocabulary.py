"""A1d's mined vocabulary and the wildcard HTTP differentiator — what they RAN, and what they lost.

Split out of `test_crawl_fetch_lanes.py` because the subject is `vertical._wildcard_differentiate` and
`enrich._a1d_recursive_brute`, not the crawl fetch lanes: the crawl side only produces the wordlist.
The shared doubles (`_Ctx`, the scope stub) live with the crawl lanes and are imported from there.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from quarry_recon import events
from quarry_recon.phases import crawl

from test_crawl_fetch_lanes import _Ctx, TestXnLinkFinderHasOneLifecycle

pytestmark = pytest.mark.offline


class TestA1dVocabularyLossReachesTheVerdict:
    """review-B-audit-11#1: the loss was a REASON-ONLY coverage event, which the reconciler ignores — so a
    run that silently dropped brute vocabulary still read `complete`."""

    _S = TestXnLinkFinderHasOneLifecycle._S

    def _verdict(self, tmp_path, wordlist_bytes):
        from quarry_recon import store
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            def fake_exec(tool, cmd, **k):
                pathlib.Path(cmd[cmd.index("-o") + 1]).write_text("https://api.acme.com/x\n")
                pathlib.Path(cmd[cmd.index("-op") + 1]).write_text("")
                if "-os" in cmd:
                    pathlib.Path(cmd[cmd.index("-os") + 1]).write_text("[]")
                if "-owl" in cmd:
                    pathlib.Path(cmd[cmd.index("-owl") + 1]).write_bytes(wordlist_bytes)
                from quarry_recon.runner import RunResult
                return RunResult(tool, cmd, crawl.Status.SUCCESS, 0, 0.1, None, 1)

            import unittest.mock as _m
            with _m.patch.object(crawl, "exec_tool", fake_exec), \
                 _m.patch.object(crawl, "have", lambda t: True), \
                 _m.patch.object(crawl, "_xnl_engine", lambda: "8.2"):
                ctx = _Ctx(run.dir, [])
                ctx.run = run
                ctx.scope = self._S()
                ctx.scope.passive_only = False
                d = tmp_path / "in" / "js"
                d.mkdir(parents=True, exist_ok=True)
                (d / "a.js").write_text("var x = 1;")
                crawl._xnl_lane(ctx, [(str(d), "js", False)])
            run.write_manifest({}, ["crawl"])
            return json.loads(run.manifest_path.read_text())["summary"]
        finally:
            events.reset()

    def test_a_DROPPED_wordlist_line_gates_the_run_verdict(self, tmp_path):
        s = self._verdict(tmp_path, b"good\nbad\xffword\n")
        assert s["verdict"] != "complete", s
        assert any(g.get("measure") == "wordlist_lines" or "wordlist" in str(g)
                   for g in s.get("gaps", []) + s.get("coverage", [])), s

    def test_a_CLEAN_wordlist_leaves_the_verdict_complete(self, tmp_path):
        s = self._verdict(tmp_path, b"good\nfine\n")
        assert s["verdict"] == "complete", s

    def test_an_UNREADABLE_vocabulary_is_a_DEGRADED_A1d_not_a_clean_skip(self, tmp_path, monkeypatch):
        """review-B-audit-11#2: `_target_wordlist` swallowed every OSError, so A1d recorded "no
        target-specific words mined from crawl" — our failure to read reported as the target having none.
        The record must be degraded, which is what reaches the run verdict."""
        from quarry_recon import store
        from quarry_recon.phases import enrich
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            wl_dir = run.dir / "raw" / "crawl" / "xnLinkFinder"
            wl_dir.mkdir(parents=True, exist_ok=True)
            (wl_dir / "js_wordlist.txt").write_bytes(b"internal\napi\n")
            real = pathlib.Path.read_bytes

            def denied(self, *a, **k):
                if self.name.endswith("_wordlist.txt"):
                    raise PermissionError("denied")
                return real(self, *a, **k)

            monkeypatch.setattr(pathlib.Path, "read_bytes", denied)
            monkeypatch.setattr(enrich, "have", lambda t: False)      # no brute in this test
            ctx = _Ctx(run.dir, [])
            ctx.run = run
            ctx.scope = self._S()
            ctx.scope.passive_only = False
            ctx.profile = type("P", (), {"apex_domains": ["acme.com"], "http_rl": 0, "dns_rate": 0})()
            from quarry_recon.phases import vertical
            monkeypatch.setattr(vertical, "_wordlist", lambda c: None)
            enrich._a1d_recursive_brute(ctx)
            run.write_manifest({}, ["enrich"])
            summary = json.loads(run.manifest_path.read_text())["summary"]
            assert summary["verdict"] != "complete", summary
            whys = " ".join(str(g) for g in summary.get("gaps", []) + summary.get("failures", []))
            assert "unreadable" in whys.lower(), summary
            # ...and the lane never claims the target simply had no vocabulary
            # review-B-audit-12#1: ONE attempt, ONE record — exact count and status, never `any(...)`
            a1d = [r for r in run.tool_runs("enrich") if r.tool == "a1d"]
            assert len(a1d) == 1, a1d
            assert a1d[0].status == "failed", a1d
            assert "ALL 1 mined wordlist artifact(s) unreadable" in (a1d[0].note or ""), a1d
            assert "no target-specific words mined" not in (a1d[0].note or ""), a1d
        finally:
            events.reset()

    def test_a_DROPPED_LINE_still_lets_A1d_run_but_says_so(self, tmp_path, monkeypatch):
        from quarry_recon import store
        from quarry_recon.phases import enrich, vertical
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            wl_dir = run.dir / "raw" / "crawl" / "xnLinkFinder"
            wl_dir.mkdir(parents=True, exist_ok=True)
            (wl_dir / "js_wordlist.txt").write_bytes(b"internal\nbad\xffword\n")
            from quarry_recon.runner import RunResult as _RR
            monkeypatch.setattr(enrich, "have", lambda t: True)
            monkeypatch.setattr(enrich, "exec_tool",
                                lambda tool, cmd, raw_path=None, timeout=None, **k: _RR(
                                    tool, cmd, crawl.Status.EMPTY, 0, 0.1, None, 0))
            monkeypatch.setattr(vertical, "_resolvers", lambda c: (tmp_path / "r", tmp_path / "rt"))
            monkeypatch.setattr(vertical, "_wordlist", lambda c: None)
            ctx = _Ctx(run.dir, [])
            ctx.run = run
            ctx.scope = self._S()
            ctx.scope.passive_only = False
            ctx.profile = type("P", (), {"apex_domains": ["acme.com"], "http_rl": 0, "dns_rate": 0})()
            enrich._a1d_recursive_brute(ctx)
            run.write_manifest({}, ["enrich"])
            summary = json.loads(run.manifest_path.read_text())["summary"]
            assert summary["verdict"] != "complete", summary
            whys = " ".join(str(g) for g in summary.get("gaps", []))
            assert "not valid" in whys and "ran with less than its eligible work" in whys, summary
            a1d = [r for r in run.tool_runs("enrich") if r.tool == "a1d"]
            assert len(a1d) == 1 and a1d[0].status == "partial", a1d
        finally:
            events.reset()

    def _a1d(self, tmp_path, monkeypatch, files: dict, deny=(), base=None, base_deny=False,
             puredns=False):
        """Drive A1d on a REAL Run with the given mined wordlist artifacts, and return (records, summary)."""
        from quarry_recon import store
        from quarry_recon.phases import enrich, vertical
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            wl_dir = run.dir / "raw" / "crawl" / "xnLinkFinder"
            wl_dir.mkdir(parents=True, exist_ok=True)
            for name, body in files.items():
                (wl_dir / name).write_bytes(body)
            base_path = None
            if base is not None:
                base_path = tmp_path / "base.txt"
                base_path.write_bytes(base)
            real = pathlib.Path.read_bytes

            def picky(self, *a, **k):
                if self.name in deny or (base_deny and base_path is not None and self.name == base_path.name):
                    raise PermissionError("denied")
                return real(self, *a, **k)

            monkeypatch.setattr(pathlib.Path, "read_bytes", picky)
            monkeypatch.setattr(enrich, "have", lambda t: puredns)
            monkeypatch.setattr(vertical, "_wordlist", lambda c: base_path)
            if puredns:
                from quarry_recon.runner import RunResult as _RR
                monkeypatch.setattr(vertical, "_resolvers",
                                    lambda c: (tmp_path / "r.txt", tmp_path / "rt.txt"))
                monkeypatch.setattr(enrich, "exec_tool",
                                    lambda tool, cmd, raw_path=None, timeout=None, **k: _RR(
                                        tool, cmd, crawl.Status.EMPTY, 0, 0.1, None, 0))
            ctx = _Ctx(run.dir, [])
            ctx.run = run
            ctx.scope = self._S()
            ctx.scope.passive_only = False
            ctx.profile = type("P", (), {"apex_domains": ["acme.com"], "http_rl": 0, "dns_rate": 0})()
            enrich._a1d_recursive_brute(ctx)
            run.write_manifest({}, ["enrich"])
            recs = [r for r in run.tool_runs("enrich") if r.tool == "a1d"]
            return recs, json.loads(run.manifest_path.read_text())["summary"]
        finally:
            events.reset()

    def test_ONE_unreadable_beside_a_readable_EMPTY_file_does_not_claim_ALL(self, tmp_path, monkeypatch):
        """review-B-audit-12#1: the FAILED note asserted every artifact was unreadable whenever ANY was."""
        recs, summary = self._a1d(tmp_path, monkeypatch,
                                  {"a_wordlist.txt": b"", "b_wordlist.txt": b"internal\n"},
                                  deny=("b_wordlist.txt",))
        assert len(recs) == 1 and recs[0].status == "failed", recs
        assert "ALL" not in (recs[0].note or ""), recs
        assert "1/2 mined wordlist artifact(s) unreadable" in recs[0].note, recs
        assert "yielded 0 usable word(s)" in recs[0].note, recs
        assert summary["verdict"] != "complete", summary

    def test_a_LOSS_with_surviving_words_is_exactly_one_PARTIAL(self, tmp_path, monkeypatch):
        recs, summary = self._a1d(tmp_path, monkeypatch,
                                  {"a_wordlist.txt": b"internal\napi\n", "b_wordlist.txt": b"x\n"},
                                  deny=("b_wordlist.txt",), puredns=True)
        assert len(recs) == 1 and recs[0].status == "partial", recs
        assert "ran with less than its eligible work" in recs[0].note, recs
        assert "1/2 mined wordlist artifact(s) unreadable" in recs[0].note, recs
        assert summary["verdict"] != "complete", summary

    def test_NO_words_and_NO_loss_is_exactly_one_SKIP(self, tmp_path, monkeypatch):
        recs, summary = self._a1d(tmp_path, monkeypatch, {"a_wordlist.txt": b""})
        assert len(recs) == 1 and recs[0].status == "skipped", recs
        assert "no target-specific words mined" in (recs[0].note or ""), recs
        assert summary["verdict"] == "complete", summary

    def test_only_UNDECODABLE_lines_and_no_words_is_one_FAILED(self, tmp_path, monkeypatch):
        recs, _summary = self._a1d(tmp_path, monkeypatch, {"a_wordlist.txt": b"\xff\xfe\n"})
        assert len(recs) == 1 and recs[0].status == "failed", recs
        assert "not valid UTF-8" in recs[0].note, recs

    # ── audit-12#2 the BASE vocabulary read is inside the boundary ───────────────────────────────
    def test_an_UNREADABLE_base_wordlist_does_not_abort_the_phase(self, tmp_path, monkeypatch):
        """review-B-audit-12#2: this read sat outside every boundary — it escaped A1d, recorded nothing,
        and took the rest of enrich with it."""
        recs, summary = self._a1d(tmp_path, monkeypatch, {"a_wordlist.txt": b"internal\n"},
                                  base=b"api\nwww\n", base_deny=True, puredns=True)
        assert len(recs) == 1 and recs[0].status == "partial", recs
        assert "base wordlist could not be read" in recs[0].note, recs
        assert "NOT deduped" in recs[0].note, recs
        assert summary["verdict"] != "complete", summary

    def test_an_UNDECODABLE_base_line_is_counted_not_replaced(self, tmp_path, monkeypatch):
        recs, _summary = self._a1d(tmp_path, monkeypatch, {"a_wordlist.txt": b"internal\n"},
                                   base=b"api\nbad\xffword\n", puredns=True)
        assert len(recs) == 1 and recs[0].status == "partial", recs
        assert "1 base wordlist line(s) not valid UTF-8" in recs[0].note, recs

    def test_a_LOCATOR_that_raises_is_contained_too(self, tmp_path, monkeypatch):
        from quarry_recon.phases import enrich, vertical
        from quarry_recon import store
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            wl_dir = run.dir / "raw" / "crawl" / "xnLinkFinder"
            wl_dir.mkdir(parents=True, exist_ok=True)
            (wl_dir / "a_wordlist.txt").write_bytes(b"internal\n")
            from quarry_recon.runner import RunResult as _RR
            monkeypatch.setattr(enrich, "have", lambda t: True)
            monkeypatch.setattr(enrich, "exec_tool",
                                lambda tool, cmd, raw_path=None, timeout=None, **k: _RR(
                                    tool, cmd, crawl.Status.EMPTY, 0, 0.1, None, 0))
            monkeypatch.setattr(vertical, "_resolvers", lambda c: (tmp_path / "r", tmp_path / "rt"))
            monkeypatch.setattr(vertical, "_wordlist",
                                lambda c: (_ for _ in ()).throw(OSError("resolver dir gone")))
            ctx = _Ctx(run.dir, [])
            ctx.run = run
            ctx.scope = self._S()
            ctx.scope.passive_only = False
            ctx.profile = type("P", (), {"apex_domains": ["acme.com"], "http_rl": 0, "dns_rate": 0})()
            enrich._a1d_recursive_brute(ctx)          # must NOT raise
            recs = [r for r in run.tool_runs("enrich") if r.tool == "a1d"]
            assert len(recs) == 1 and recs[0].status == "partial", recs
            assert "could not be located" in recs[0].note, recs
        finally:
            events.reset()

    # ── audit-13#1 eligible A1d work that was never submitted is REPORTED ────────────────────────
    def test_a_MISSING_puredns_never_silently_drops_the_apex_brute(self, tmp_path, monkeypatch):
        """review-B-audit-13#1: the apex brute was skipped with no result at all, so a run showed a mined
        wordlist, no brute, and nothing saying why."""
        recs, summary = self._a1d(tmp_path, monkeypatch, {"a_wordlist.txt": b"internal\napi\n"},
                                  puredns=False)
        a1d = [r for r in recs if r.tool == "a1d"]
        assert len(a1d) == 1 and a1d[0].status == "failed", recs
        assert "did NOT run" in a1d[0].note and "1 apex brute(s) unsubmitted" in a1d[0].note, a1d
        assert summary["verdict"] != "complete", summary

    def test_the_MISSING_tool_itself_is_recorded_with_the_unsubmitted_count(self, tmp_path, monkeypatch):
        from quarry_recon import store
        from quarry_recon.phases import enrich, vertical
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            wl = run.dir / "raw" / "crawl" / "xnLinkFinder"
            wl.mkdir(parents=True, exist_ok=True)
            (wl / "a_wordlist.txt").write_bytes(b"internal\napi\n")
            monkeypatch.setattr(enrich, "have", lambda t: False)
            monkeypatch.setattr(vertical, "_wordlist", lambda c: None)
            ctx = _Ctx(run.dir, [])
            ctx.run = run
            ctx.scope = self._S()
            ctx.scope.passive_only = False
            ctx.profile = type("P", (), {"apex_domains": ["acme.com", "acme.net"], "http_rl": 0,
                                         "dns_rate": 0})()
            enrich._a1d_recursive_brute(ctx)
            pd = [r for r in run.tool_runs("enrich") if r.tool == "puredns"]
            assert len(pd) == 1 and pd[0].status == "skipped", pd
            assert "2 A1d apex brute(s) unsubmitted" in (pd[0].note or ""), pd
            a1d = [r for r in run.tool_runs("enrich") if r.tool == "a1d"]
            assert len(a1d) == 1 and "2 apex brute(s) unsubmitted" in a1d[0].note, a1d
        finally:
            events.reset()

    def test_a_CLEAN_A1d_that_actually_ran_records_no_extra_outcome(self, tmp_path, monkeypatch):
        recs, summary = self._a1d(tmp_path, monkeypatch, {"a_wordlist.txt": b"internal\napi\n"},
                                  puredns=True)
        assert [r for r in recs if r.tool == "a1d"] == [], recs
        assert summary["verdict"] == "complete", summary

    # ── audit-13#2 a base-only loss is not damage when nothing was mined ─────────────────────────
    def test_a_BASE_failure_with_NO_mined_words_is_still_a_clean_SKIP(self, tmp_path, monkeypatch):
        """The base list exists only to dedup mined words against; with none mined it had no work."""
        recs, summary = self._a1d(tmp_path, monkeypatch, {"a_wordlist.txt": b""},
                                  base=b"api\n", base_deny=True)
        assert len(recs) == 1 and recs[0].status == "skipped", recs
        assert "no target-specific words mined" in (recs[0].note or ""), recs
        assert "deduped" not in (recs[0].note or ""), recs
        assert summary["verdict"] == "complete", summary

    def test_a_MINED_failure_with_no_words_is_still_a_FAILURE(self, tmp_path, monkeypatch):
        """...but damage to the MINED input is a different fact and still fails."""
        recs, summary = self._a1d(tmp_path, monkeypatch, {"a_wordlist.txt": b"x\n"},
                                  deny=("a_wordlist.txt",), base=b"api\n", base_deny=True)
        assert len(recs) == 1 and recs[0].status == "failed", recs
        assert "mined input was DAMAGED" in recs[0].note, recs
        assert summary["verdict"] != "complete", summary

    # ── audit-14 wildcard zones EXISTING is not the wildcard pass RUNNING ────────────────────────
    def _a1d_zones(self, tmp_path, monkeypatch, *, zones=("z.acme.com",), httpx=True, puredns=False,
                   passive=False, wordlist=True, generic=b"api\nwww\n"):
        from quarry_recon import store
        from quarry_recon.phases import enrich, probe, vertical
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            wl = run.dir / "raw" / "crawl" / "xnLinkFinder"
            wl.mkdir(parents=True, exist_ok=True)
            (wl / "a_wordlist.txt").write_bytes(b"internal\napi\n")
            from quarry_recon.runner import RunResult as _RR
            monkeypatch.setattr(enrich, "have", lambda t: puredns)
            monkeypatch.setattr(vertical, "have", lambda t: httpx and t == "httpx")
            monkeypatch.setattr(vertical, "_wordlist", lambda c: (tmp_path / "base.txt")
                                if wordlist else None)
            (tmp_path / "base.txt").write_bytes(generic)
            monkeypatch.setattr(probe, "_vhost_wordlist", lambda: None)
            monkeypatch.setattr(enrich, "exec_tool",
                                lambda tool, cmd, raw_path=None, timeout=None, **k: _RR(
                                    tool, cmd, crawl.Status.EMPTY, 0, 0.1, None, 0))
            monkeypatch.setattr(vertical, "exec_tool",
                                lambda tool, cmd, raw_path=None, timeout=None, **k: _RR(
                                    tool, cmd, crawl.Status.EMPTY, 0, 0.1, None, 0))
            # `_resolvers` writes a trusted-resolver list through `ctx.tmp` when none is configured — the
            # fixture must not depend on the host having one (it does not in the hermetic gate).
            monkeypatch.setattr(vertical, "_resolvers", lambda c: (tmp_path / "r", tmp_path / "rt"))
            ctx = _Ctx(run.dir, [])
            ctx.run = run
            ctx.scope = self._S()
            ctx.scope.passive_only = passive
            ctx.scope.is_oos = lambda h: False
            ctx.profile = type("P", (), {"apex_domains": ["acme.com"], "http_rl": 0, "dns_rate": 0})()
            run._vals = getattr(run, "_vals", {})
            monkeypatch.setattr(type(run), "values",
                                lambda self, kind: list(zones) if kind == "wildcard_zone" else [],
                                raising=False)
            enrich._a1d_recursive_brute(ctx)
            return [r for r in run.tool_runs("enrich") if r.tool == "a1d"]
        finally:
            events.reset()

    def test_wildcard_zones_that_were_never_PROBED_are_reported(self, tmp_path, monkeypatch):
        """review-B-audit-14: `ran` was inferred from the zones EXISTING, so a run with no httpx claimed
        it "ran with less than its eligible work" while nothing had been submitted at all."""
        recs = self._a1d_zones(tmp_path, monkeypatch, httpx=False, puredns=False)
        assert len(recs) == 1 and recs[0].status == "failed", recs
        assert "did NOT run" in recs[0].note, recs
        assert "1/1 wildcard zone(s) not differentiated (httpx is not installed)" in recs[0].note, recs

    def test_A1d_runs_the_wildcard_pass_on_its_OWN_vocabulary(self, tmp_path, monkeypatch):
        """review-B-audit-15#1: a missing GENERIC list used to block the pass entirely — but A1d only gets
        here having mined a non-empty target vocabulary, which is exactly what this pass needs."""
        from quarry_recon.phases import vertical
        monkeypatch.setattr(vertical.netguard, "contact_state",
                            lambda host, block_private=False: ("public", False, None))
        monkeypatch.setattr(vertical.netguard, "_block_private", lambda ctx: False)
        monkeypatch.setattr(vertical.netguard, "self_deny_list", lambda: "127.0.0.1")
        recs = self._a1d_zones(tmp_path, monkeypatch, httpx=True, wordlist=False, puredns=True)
        assert recs == [], recs               # the pass RAN: nothing unsubmitted, nothing to report

    def test_the_pass_is_blocked_only_when_BOTH_word_sources_are_empty(self, tmp_path, monkeypatch):
        from quarry_recon.phases import vertical
        st = {}
        events.reset(); events.configure(tmp_path)
        ctx = _Ctx(tmp_path, [])
        ctx.scope = self._S()
        ctx.scope.passive_only = False
        ctx.scope.is_oos = lambda h: False
        monkeypatch.setattr(vertical, "have", lambda t: True)
        monkeypatch.setattr(vertical, "_wordlist", lambda c: None)
        from quarry_recon.phases import probe
        monkeypatch.setattr(probe, "_vhost_wordlist", lambda: None)
        assert vertical._wildcard_differentiate(ctx, {"z.acme.com"}, extra_words=[], stats=st) == set()
        assert st["blocked_reason"] == "no usable vocabulary", st
        assert st["probed_zones"] == 0, st

    def test_PASSIVE_mode_never_claims_the_wildcard_pass_ran(self, tmp_path, monkeypatch):
        """passive_only returns before A1d entirely — nothing may be recorded as run."""
        recs = self._a1d_zones(tmp_path, monkeypatch, passive=True)
        assert recs == [], recs

    def test_the_apex_brute_alone_still_counts_as_HAVING_RUN(self, tmp_path, monkeypatch):
        """With puredns present the lane DID run, so an unprobed wildcard set is PARTIAL, not FAILED."""
        recs = self._a1d_zones(tmp_path, monkeypatch, httpx=False, puredns=True)
        assert len(recs) == 1 and recs[0].status == "partial", recs
        assert "ran with less than its eligible work" in recs[0].note, recs
        assert "wildcard zone(s) not differentiated" in recs[0].note, recs

    def test_a_FULLY_PROBED_wildcard_set_reports_nothing_unsubmitted(self, tmp_path, monkeypatch):
        """The other half of audit-14: when the pass really does probe every zone, there is no
        unsubmitted work to report — the count comes from what ran, not from what existed."""
        from quarry_recon.phases import vertical
        monkeypatch.setattr(vertical.netguard, "contact_state",
                            lambda host, block_private=False: ("public", False, None))
        monkeypatch.setattr(vertical.netguard, "_block_private", lambda ctx: False)
        monkeypatch.setattr(vertical.netguard, "self_deny_list", lambda: "127.0.0.1")
        # TWO zones: a per-zone counter that only ever reports "1" is not counting what it probed
        recs = self._a1d_zones(tmp_path, monkeypatch, zones=("z.acme.com", "y.acme.com"),
                               httpx=True, puredns=True, wordlist=True)
        assert recs == [], recs

    def test_a_zone_the_SELF_GUARD_skipped_is_unsubmitted_not_probed(self, tmp_path, monkeypatch):
        """The guard refuses to vhost-scan a wildcard that resolves to the scan box. That zone was NOT
        differentiated, and the count must say so rather than credit the loop entry."""
        from quarry_recon.phases import vertical
        monkeypatch.setattr(vertical.netguard, "contact_state",
                            lambda host, block_private=False: ("self", True, None))
        monkeypatch.setattr(vertical.netguard, "_block_private", lambda ctx: False)
        monkeypatch.setattr(vertical.netguard, "self_deny_list", lambda: "127.0.0.1")
        recs = self._a1d_zones(tmp_path, monkeypatch, httpx=True, puredns=True, wordlist=True)
        assert len(recs) == 1 and recs[0].status == "partial", recs
        assert "1/1 wildcard zone(s) not differentiated" in recs[0].note, recs

    # ── audit-15#2/#3/#4 stats hygiene, named omissions, honest attribution ──────────────────────
    def _differ_ctx(self, tmp_path, monkeypatch, *, guard="public"):
        from quarry_recon.phases import probe, vertical
        events.reset(); events.configure(tmp_path)
        ctx = _Ctx(tmp_path, [])
        ctx.scope = self._S()
        ctx.scope.passive_only = False
        ctx.scope.is_oos = lambda h: False
        from quarry_recon.runner import RunResult as _RR
        monkeypatch.setattr(vertical, "have", lambda t: True)
        monkeypatch.setattr(probe, "_vhost_wordlist", lambda: None)
        monkeypatch.setattr(vertical, "_wordlist", lambda c: None)
        monkeypatch.setattr(vertical, "exec_tool",
                            lambda tool, cmd, raw_path=None, timeout=None, **k: _RR(
                                tool, cmd, crawl.Status.EMPTY, 0, 0.1, None, 0))
        monkeypatch.setattr(vertical.netguard, "_block_private", lambda c: False)
        monkeypatch.setattr(vertical.netguard, "self_deny_list", lambda: "127.0.0.1")
        monkeypatch.setattr(vertical.netguard, "contact_state",
                            lambda host, block_private=False: (guard, guard != "public", None))
        return ctx

    def test_a_REUSED_stats_dict_never_reports_a_previous_call(self, tmp_path, monkeypatch):
        """review-B-audit-15#2: `setdefault` is not a snapshot — a second call could report this call's
        eligible count beside the previous call's probed count."""
        from quarry_recon.phases import vertical
        ctx = self._differ_ctx(tmp_path, monkeypatch)
        st = {}
        vertical._wildcard_differentiate(ctx, {"a.acme.com", "b.acme.com"}, extra_words=["api"], stats=st)
        assert st["probed_zones"] == 2, st
        vertical._wildcard_differentiate(ctx, {"out.of.scope.example"}, extra_words=["api"], stats=st)
        assert st == {"eligible_zones": 0, "probed_zones": 0,
                      "blocked_reason": "no in-scope wildcard zone",
                      "blocked": {"zone_cap": 0, "self_or_private": 0}}, st

    def test_a_GUARD_refusal_says_so_instead_of_blaming_the_cap(self, tmp_path, monkeypatch):
        from quarry_recon.phases import vertical
        ctx = self._differ_ctx(tmp_path, monkeypatch, guard="self")
        st = {}
        vertical._wildcard_differentiate(ctx, {"a.acme.com"}, extra_words=["api"], stats=st)
        assert st["probed_zones"] == 0 and st["blocked"]["self_or_private"] == 1, st
        assert "self/private contact guard" in st["blocked_reason"], st
        assert "cap" not in st["blocked_reason"], st

    def test_a_CAP_and_a_GUARD_are_reported_as_the_two_facts_they_are(self, tmp_path, monkeypatch):
        from quarry_recon.phases import vertical
        ctx = self._differ_ctx(tmp_path, monkeypatch, guard="self")
        st = {}
        zones = {f"z{i}.acme.com" for i in range(7)}          # 7 zones, cap 5, all guard-refused
        vertical._wildcard_differentiate(ctx, zones, extra_words=["api"], stats=st)
        assert st["blocked"] == {"zone_cap": 2, "self_or_private": 5}, st
        assert "2 zone(s) over the 5-zone cap" in st["blocked_reason"], st
        assert "5 zone(s) refused by the self/private contact guard" in st["blocked_reason"], st

    def test_the_A1d_pass_keeps_its_OWN_lifecycle_in_the_MANIFEST(self, tmp_path, monkeypatch):
        """review-B-audit-15#4 / 16#3: distinct units stopped the replacement, but both events still wore
        `vertical.wildcard_http`, and reconciliation aggregates PER SOURCE — so A1d's work was still filed
        under the vertical pass. Asserted on the reconciled manifest, not on raw events."""
        from quarry_recon import store
        from quarry_recon.phases import vertical
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            ctx = self._differ_ctx(tmp_path, monkeypatch)
            events.configure(run.dir)                  # the differ writes into THIS run's log
            ctx.run = run
            vertical._wildcard_differentiate(ctx, {"a.acme.com"}, extra_words=["api"], label="wildcard")
            vertical._wildcard_differentiate(ctx, {"b.acme.com", "c.acme.com"}, extra_words=["api"],
                                             phase="enrich", label="wildcard-a1d",
                                             source_id="enrich.wildcard_a1d")
            run.write_manifest({}, ["vertical", "enrich"])
            summary = json.loads(run.manifest_path.read_text())["summary"]
            cov = {(c["source_id"], c["measure"]): c for c in summary.get("coverage", [])}
            assert ("vertical.wildcard_http", "zones") in cov, cov
            assert ("enrich.wildcard_a1d", "zones") in cov, cov
            assert cov[("vertical.wildcard_http", "zones")]["eligible"] == 1, cov
            assert cov[("enrich.wildcard_a1d", "zones")]["eligible"] == 2, cov
        finally:
            events.reset()

    # ── audit-16#1 a word is not a name until it is a LABEL ─────────────────────────────────────
    def test_a_URL_SHAPED_word_can_never_introduce_another_authority(self, tmp_path, monkeypatch):
        """A generic line like `https://outside.example/private` would have built
        `https://outside.example/private.<zone>` — whose authority httpx resolves as `outside.example`,
        a host the contact guard never saw. Proven by reading the candidate file the differ writes."""
        from quarry_recon.phases import vertical
        ctx = self._differ_ctx(tmp_path, monkeypatch)
        st = {}
        vertical._wildcard_differentiate(
            ctx, {"wild.acme.com"},
            extra_words=["https://outside.example/private", "evil.example.com", "ok", "under_score",
                         "-lead", "trail-", "a" * 64, "UPPER"],
            label="wildcard", stats=st)
        cand = ctx.run.dir / "work" / "wildcard_cand_wild_acme_com.txt"
        lines = [ln for ln in cand.read_text().splitlines() if ln.strip()]
        for ln in lines:
            assert ln.endswith(".wild.acme.com"), ln
            assert "/" not in ln and ":" not in ln, ln
            # the label part must be exactly one label
            assert "." not in ln[: -len(".wild.acme.com")], ln
        assert "ok.wild.acme.com" in lines and "upper.wild.acme.com" in lines, lines
        assert st["vocabulary"]["rejected"] == 6, st          # url, dotted, underscore, -lead, trail-, 64ch
        assert st["vocabulary"]["accepted"] == 2, st

    def test_REJECTED_and_UNDECODABLE_vocabulary_reaches_the_verdict(self, tmp_path, monkeypatch):
        from quarry_recon import store
        from quarry_recon.phases import vertical
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            ctx = self._differ_ctx(tmp_path, monkeypatch)
            events.configure(run.dir)
            ctx.run = run
            wl = tmp_path / "generic.txt"
            wl.write_bytes(b"good\nhttps://outside.example/x\nbad\xffword\n")
            monkeypatch.setattr(vertical, "_wordlist", lambda c: wl)
            vertical._wildcard_differentiate(ctx, {"a.acme.com"}, extra_words=["api"], label="wildcard")
            run.write_manifest({}, ["vertical"])
            summary = json.loads(run.manifest_path.read_text())["summary"]
            assert summary["verdict"] != "complete", summary
            cov = {(c["source_id"], c["measure"]): c for c in summary.get("coverage", [])}
            # review-B-audit-18#1: PARSING and SELECTION are sequential stages over the same words, so
            # they have their OWN measures — one rollup, one homogeneous denominator, never summed.
            parse = cov[("vertical.wildcard_http", "vocabulary_entries")]
            assert (parse["eligible"], parse["tested"], parse["omitted"]) == (4, 2, 2), parse
            cap = cov[("vertical.wildcard_http", "vocabulary_words")]
            assert (cap["eligible"], cap["tested"], cap["omitted"]) == (2, 2, 0), cap
        finally:
            events.reset()

    def test_a_PRESENT_but_UNREADABLE_wordlist_is_not_a_clean_run(self, tmp_path, monkeypatch):
        from quarry_recon import store
        from quarry_recon.phases import vertical
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            ctx = self._differ_ctx(tmp_path, monkeypatch)
            events.configure(run.dir)
            ctx.run = run
            wl = tmp_path / "generic.txt"
            wl.write_bytes(b"good\n")
            monkeypatch.setattr(vertical, "_wordlist", lambda c: wl)
            real = pathlib.Path.read_bytes
            monkeypatch.setattr(pathlib.Path, "read_bytes",
                                lambda self, *a, **k: (_ for _ in ()).throw(PermissionError("denied"))
                                if self.name == "generic.txt" else real(self, *a, **k))
            st = {}
            vertical._wildcard_differentiate(ctx, {"a.acme.com"}, extra_words=["api"], label="wildcard",
                                             stats=st)
            assert st["vocabulary"]["unreadable"] is True, st
            # the ZONE reason stays zone-scoped — the pass RAN on the caller's own word, and WHY the
            # generic vocabulary is missing lives in `vocabulary` (review-B-audit-18#2)
            assert st["blocked_reason"] == "", st
            run.write_manifest({}, ["vertical"])
            summary = json.loads(run.manifest_path.read_text())["summary"]
            assert summary["verdict"] != "complete", summary
            cov = {(c["source_id"], c["measure"]): c for c in summary["coverage"]}
            assert cov[("vertical.wildcard_http", "vocabulary_entries")]["valid"] is False, cov
        finally:
            events.reset()

    def test_A1d_reports_UNUSABLE_vocabulary_even_when_every_zone_was_probed(self, tmp_path, monkeypatch):
        """review-B-audit-16#2: the vocabulary stats were only consulted when zones went unsubmitted, so a
        fully probed run with a half-rejected wordlist reported nothing at all."""
        from quarry_recon.phases import vertical
        monkeypatch.setattr(vertical.netguard, "contact_state",
                            lambda host, block_private=False: ("public", False, None))
        monkeypatch.setattr(vertical.netguard, "_block_private", lambda ctx: False)
        monkeypatch.setattr(vertical.netguard, "self_deny_list", lambda: "127.0.0.1")
        recs = self._a1d_zones(tmp_path, monkeypatch, httpx=True, puredns=True,
                               generic=b"good\nhttps://outside.example/x\nbad\xffword\n")
        assert len(recs) == 1 and recs[0].status == "partial", recs
        assert "2 wildcard vocabulary word(s) unusable" in recs[0].note, recs
        assert "not a single DNS label" in recs[0].note, recs

    def test_A1d_reports_an_UNREADABLE_generic_wordlist(self, tmp_path, monkeypatch):
        from quarry_recon.phases import vertical
        monkeypatch.setattr(vertical.netguard, "contact_state",
                            lambda host, block_private=False: ("public", False, None))
        monkeypatch.setattr(vertical.netguard, "_block_private", lambda ctx: False)
        monkeypatch.setattr(vertical.netguard, "self_deny_list", lambda: "127.0.0.1")
        real = pathlib.Path.read_bytes
        monkeypatch.setattr(pathlib.Path, "read_bytes",
                            lambda self, *a, **k: (_ for _ in ()).throw(PermissionError("denied"))
                            if self.name == "base.txt" else real(self, *a, **k))
        recs = self._a1d_zones(tmp_path, monkeypatch, httpx=True, puredns=True)
        assert len(recs) == 1 and recs[0].status == "partial", recs
        assert "present and UNREADABLE" in recs[0].note, recs
        assert "only the mined vocabulary was used" in recs[0].note, recs

    # ── audit-17 the CAP is a fact, the label check is exact, and a clean pass CLEARS ────────────
    def test_the_WORD_CAP_is_reported_not_silent(self, tmp_path, monkeypatch):
        """review-B-audit-17#1: `words[:5000]` dropped valid labels and then called the truncated count
        "accepted", so thousands of withheld words produced no omission at all."""
        from quarry_recon import store
        from quarry_recon.phases import vertical
        monkeypatch.setattr(vertical, "WILDCARD_WORD_CAP", 3)
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            ctx = self._differ_ctx(tmp_path, monkeypatch)
            events.configure(run.dir)
            ctx.run = run
            st = {}
            vertical._wildcard_differentiate(ctx, {"a.acme.com"},
                                             extra_words=[f"w{i}" for i in range(10)],
                                             label="wildcard", stats=st)
            assert st["vocabulary"]["usable"] == 10, st
            assert st["vocabulary"]["selected"] == 3 and st["vocabulary"]["withheld"] == 7, st
            assert st["blocked_reason"] == "", st        # the CAP is a vocabulary fact, not a zone one
            run.write_manifest({}, ["vertical"])
            summary = json.loads(run.manifest_path.read_text())["summary"]
            assert summary["verdict"] != "complete", summary
            cov = {(c["source_id"], c["measure"]): c for c in summary["coverage"]}
            cap = cov[("vertical.wildcard_http", "vocabulary_words")]
            assert (cap["eligible"], cap["tested"], cap["omitted"]) == (10, 3, 7), cap
            parse = cov[("vertical.wildcard_http", "vocabulary_entries")]
            assert parse["omitted"] == 0 and parse["eligible"] == 10, parse   # nothing was PARSE-rejected
        finally:
            events.reset()

    def test_a_TRAILING_NEWLINE_is_not_a_valid_label(self, tmp_path, monkeypatch):
        """review-B-audit-17#2: `$` matches before a final newline and `.match()` need not consume the
        whole string, so `safe\n` passed and kept its newline into a name we would contact."""
        from quarry_recon.phases import vertical
        assert vertical._DNS_LABEL_RX.fullmatch("safe")
        assert not vertical._DNS_LABEL_RX.fullmatch("safe\n")
        assert not vertical._DNS_LABEL_RX.fullmatch("safe\nevil.example")
        ctx = self._differ_ctx(tmp_path, monkeypatch)
        st = {}
        vertical._wildcard_differentiate(ctx, {"a.acme.com"}, extra_words=["safe\n", "API", "api"],
                                         label="wildcard", stats=st)
        cand = [ln for ln in (ctx.run.dir / "work" / "wildcard_cand_a_acme_com.txt").read_text()
                .splitlines() if ln.strip()]
        assert not any("\n" in ln or ln.startswith("safe") for ln in cand), cand
        # ...and canonicalisation happens BEFORE dedup: API and api are ONE contacted name
        assert st["vocabulary"]["usable"] == 1 and cand.count("api.a.acme.com") == 1, (st, cand)

    def test_a_CLEAN_vocabulary_CLEARS_an_earlier_gap(self, tmp_path, monkeypatch):
        """review-B-audit-17#3: latest-per-unit means a clean pass must SAY it is clean."""
        from quarry_recon import store
        from quarry_recon.phases import vertical
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            ctx = self._differ_ctx(tmp_path, monkeypatch)
            events.configure(run.dir)
            ctx.run = run
            bad = tmp_path / "bad.txt"
            bad.write_bytes(b"good\nhttps://outside.example/x\n")
            monkeypatch.setattr(vertical, "_wordlist", lambda c: bad)
            vertical._wildcard_differentiate(ctx, {"a.acme.com"}, extra_words=["api"], label="wildcard")
            good = tmp_path / "good.txt"
            good.write_bytes(b"good\nfine\n")
            monkeypatch.setattr(vertical, "_wordlist", lambda c: good)
            vertical._wildcard_differentiate(ctx, {"a.acme.com"}, extra_words=["api"], label="wildcard")
            run.write_manifest({}, ["vertical"])
            summary = json.loads(run.manifest_path.read_text())["summary"]
            cov = {(c["source_id"], c["measure"]): c for c in summary["coverage"]}
            parse = cov[("vertical.wildcard_http", "vocabulary_entries")]
            assert parse["omitted"] == 0, parse                # the second pass CLEARED it
            assert parse["eligible"] == 3, parse
        finally:
            events.reset()

    def test_A1d_reports_words_WITHHELD_by_the_cap(self, tmp_path, monkeypatch):
        """The cap is a policy bound on A1d's own vocabulary too — silently applying it hides work."""
        from quarry_recon.phases import vertical
        monkeypatch.setattr(vertical, "WILDCARD_WORD_CAP", 1)
        monkeypatch.setattr(vertical.netguard, "contact_state",
                            lambda host, block_private=False: ("public", False, None))
        monkeypatch.setattr(vertical.netguard, "_block_private", lambda ctx: False)
        monkeypatch.setattr(vertical.netguard, "self_deny_list", lambda: "127.0.0.1")
        recs = self._a1d_zones(tmp_path, monkeypatch, httpx=True, puredns=True,
                               generic=b"one\ntwo\nthree\n")
        assert len(recs) == 1 and recs[0].status == "partial", recs
        assert "usable wildcard word(s) withheld by the word cap" in recs[0].note, recs

    def test_a_MIXED_zone_and_vocabulary_failure_names_each_fact_ONCE(self, tmp_path, monkeypatch):
        """review-B-audit-18#2: the zone reason carried the vocabulary facts too, and A1d appended them
        again — a simultaneous zone cap and word cap named the word cap twice."""
        from quarry_recon.phases import vertical
        monkeypatch.setattr(vertical, "WILDCARD_WORD_CAP", 1)
        monkeypatch.setattr(vertical.netguard, "contact_state",
                            lambda host, block_private=False: ("public", False, None))
        monkeypatch.setattr(vertical.netguard, "_block_private", lambda ctx: False)
        monkeypatch.setattr(vertical.netguard, "self_deny_list", lambda: "127.0.0.1")
        recs = self._a1d_zones(tmp_path, monkeypatch, zones=tuple(f"z{i}.acme.com" for i in range(7)),
                               httpx=True, puredns=True, generic=b"one\ntwo\nthree\n")
        assert len(recs) == 1 and recs[0].status == "partial", recs
        note = recs[0].note
        assert note.count("withheld by the word cap") == 1, note
        assert note.count("zone-zone cap") == 0 and note.count("5-zone cap") == 1, note
        assert "wildcard zone(s) not differentiated" in note, note

    def test_the_zone_reason_stays_ZONE_only(self, tmp_path, monkeypatch):
        from quarry_recon.phases import vertical
        monkeypatch.setattr(vertical, "WILDCARD_WORD_CAP", 1)
        ctx = self._differ_ctx(tmp_path, monkeypatch, guard="self")
        st = {}
        vertical._wildcard_differentiate(ctx, {f"z{i}.acme.com" for i in range(7)},
                                         extra_words=["one", "two", "three"], label="wildcard", stats=st)
        assert "cap" in st["blocked_reason"] and "guard" in st["blocked_reason"], st
        assert "word" not in st["blocked_reason"] and "vocabulary" not in st["blocked_reason"], st
        assert st["vocabulary"]["withheld"] == 2, st

    def test_PARSE_coverage_counts_ENTRIES_and_selection_counts_NAMES(self, tmp_path, monkeypatch):
        """review-B-audit-19#1: `rejected` counted raw entries while `usable` counted unique canonical
        names, so `API`, `api`, `bad/url` reported eligible=2 for three entries."""
        from quarry_recon import store
        from quarry_recon.phases import vertical
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            ctx = self._differ_ctx(tmp_path, monkeypatch)
            events.configure(run.dir)
            ctx.run = run
            st = {}
            vertical._wildcard_differentiate(ctx, {"a.acme.com"},
                                             extra_words=["API", "api", "bad/url"],
                                             label="wildcard", stats=st)
            assert st["vocabulary"]["entries"] == 3, st
            assert st["vocabulary"]["valid_entries"] == 2 and st["vocabulary"]["rejected"] == 1, st
            assert st["vocabulary"]["usable"] == 1 and st["vocabulary"]["selected"] == 1, st
            run.write_manifest({}, ["vertical"])
            summary = json.loads(run.manifest_path.read_text())["summary"]
            cov = {(c["source_id"], c["measure"]): c for c in summary["coverage"]}
            parse = cov[("vertical.wildcard_http", "vocabulary_entries")]
            assert (parse["eligible"], parse["tested"], parse["omitted"]) == (3, 2, 1), parse
            sel = cov[("vertical.wildcard_http", "vocabulary_words")]
            assert (sel["eligible"], sel["tested"], sel["omitted"]) == (1, 1, 0), sel
            # dedup is NOT a loss: one name, contacted once
            cand = [ln for ln in (ctx.run.dir / "work" / "wildcard_cand_a_acme_com.txt").read_text()
                    .splitlines() if ln.strip()]
            assert cand.count("api.a.acme.com") == 1, cand
        finally:
            events.reset()

    def test_the_SELECTION_stage_does_not_claim_the_names_were_probed(self, tmp_path, monkeypatch):
        """review-B-audit-19#2: selection is not execution — with every zone refused by the contact guard,
        `zones` correctly reports 0 probed, so this record must not say the words were probed."""
        from quarry_recon.phases import vertical
        events.reset(); events.configure(tmp_path)
        ctx = self._differ_ctx(tmp_path, monkeypatch, guard="self")
        events.configure(tmp_path)
        vertical._wildcard_differentiate(ctx, {"a.acme.com"}, extra_words=["api"], label="wildcard")
        evs = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        sel = [e for e in evs if e.get("measure") == "vocabulary_words"][-1]
        zones = [e for e in evs if e.get("measure") == "zones"][-1]
        assert "SELECTED for probing" in sel["reason"], sel
        assert "probed" not in sel["reason"].replace("for probing", ""), sel
        assert zones["tested"] == 0, zones

    def _vertical_manifest(self, tmp_path, monkeypatch, *, httpx=True, wordlist=None, zones=("z.acme.com",)):
        """Drive the VERTICAL caller — which passes no stats — and read the real manifest."""
        from quarry_recon import store
        from quarry_recon.phases import probe, vertical
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            ctx = self._differ_ctx(tmp_path, monkeypatch)
            events.configure(run.dir)
            ctx.run = run
            monkeypatch.setattr(vertical, "have", lambda t: httpx)
            monkeypatch.setattr(probe, "_vhost_wordlist", lambda: None)
            monkeypatch.setattr(vertical, "_wordlist", lambda c: wordlist)
            vertical._wildcard_differentiate(ctx, set(zones), label="wildcard")   # no stats, like production
            run.write_manifest({}, ["vertical"])
            return run, json.loads(run.manifest_path.read_text())["summary"]
        finally:
            events.reset()

    def test_a_HARD_GATE_still_reports_the_undifferentiated_zones(self, tmp_path, monkeypatch):
        """review-B-audit-20#1: the vertical caller passes no stats, so an early return recorded NOTHING —
        one eligible zone, zero differentiated, verdict `complete`."""
        run, summary = self._vertical_manifest(tmp_path, monkeypatch, wordlist=None)
        assert summary["verdict"] != "complete", summary
        cov = {(c["source_id"], c["measure"]): c for c in summary["coverage"]}
        zc = cov[("vertical.wildcard_http", "zones")]
        assert (zc["eligible"], zc["tested"], zc["omitted"]) == (1, 0, 1), zc
        assert "no usable vocabulary" in str(zc), zc

    def test_a_MISSING_httpx_is_reported_as_a_gap_AND_a_skip(self, tmp_path, monkeypatch):
        run, summary = self._vertical_manifest(tmp_path, monkeypatch, httpx=False)
        assert summary["verdict"] != "complete", summary
        cov = {(c["source_id"], c["measure"]): c for c in summary["coverage"]}
        zc = cov[("vertical.wildcard_http", "zones")]
        assert (zc["eligible"], zc["tested"], zc["omitted"]) == (1, 0, 1), zc
        hx = [r for r in run.tool_runs("vertical") if r.tool == "httpx"]
        assert len(hx) == 1 and hx[0].status == "skipped", hx
        assert "1 wildcard zone(s) undifferentiated" in (hx[0].note or ""), hx

    def test_NO_eligible_zone_is_a_valid_zero_not_a_gap(self, tmp_path, monkeypatch):
        run, summary = self._vertical_manifest(tmp_path, monkeypatch, zones=("out.of.scope.example",),
                                               wordlist=None)
        cov = {(c["source_id"], c["measure"]): c for c in summary["coverage"]}
        zc = cov[("vertical.wildcard_http", "zones")]
        assert (zc["eligible"], zc["tested"], zc["omitted"]) == (0, 0, 0), zc
        assert summary["verdict"] == "complete", summary

    def test_ENTRIES_counts_everything_the_input_offered(self, tmp_path, monkeypatch):
        """review-B-audit-20#2: `entries` was assigned after undecodable lines had been dropped, so stats
        said 1 while the coverage denominator said 2."""
        from quarry_recon.phases import vertical
        ctx = self._differ_ctx(tmp_path, monkeypatch)
        wl = tmp_path / "generic.txt"
        wl.write_bytes(b"good\nbad\xffword\nhttps://outside.example/x\n")
        monkeypatch.setattr(vertical, "_wordlist", lambda c: wl)
        st = {}
        vertical._wildcard_differentiate(ctx, {"a.acme.com"}, extra_words=["api"], label="wildcard",
                                         stats=st)
        v = st["vocabulary"]
        assert v["entries"] == v["valid_entries"] + v["rejected"] + v["undecodable"], v
        assert (v["entries"], v["valid_entries"], v["rejected"], v["undecodable"]) == (4, 2, 1, 1), v

    def test_A1d_vocabulary_drops_UNDECODABLE_wordlist_lines(self, tmp_path, monkeypatch):
        """review-B-audit-10#2: these words drive an ACTIVE puredns brute, and `_target_wordlist` decoded
        whole files with `errors="replace"` — so a line the crawl boundary rejected still produced labels.
        review-B-audit-11#2: the loss is REPORTED to the caller instead of vanishing."""
        from quarry_recon.phases import vertical
        events.reset(); events.configure(tmp_path)
        ctx = _Ctx(tmp_path, [])
        wl_dir = ctx.run.dir / "raw" / "crawl" / "xnLinkFinder"
        wl_dir.mkdir(parents=True, exist_ok=True)
        (wl_dir / "js_wordlist.txt").write_bytes(b"internal\nadmin\xffsecret\n")
        loss = {}
        words = vertical._target_wordlist(ctx, set(), loss=loss)
        assert "internal" in words, words
        assert not any("admin" in w or "secret" in w for w in words), words
        assert loss["dropped_lines"] == 1 and loss["unreadable_files"] == 0 and loss["files"] == 1, loss

    def test_an_UNREADABLE_A1d_wordlist_is_reported_not_swallowed(self, tmp_path, monkeypatch):
        """review-B-audit-11#2: every OSError was skipped, so "we cannot read any of it" looked exactly
        like "the crawl mined nothing"."""
        from quarry_recon.phases import vertical
        events.reset(); events.configure(tmp_path)
        ctx = _Ctx(tmp_path, [])
        wl_dir = ctx.run.dir / "raw" / "crawl" / "xnLinkFinder"
        wl_dir.mkdir(parents=True, exist_ok=True)
        (wl_dir / "js_wordlist.txt").write_bytes(b"internal\n")
        real = pathlib.Path.read_bytes

        def denied(self, *a, **k):
            if self.name.endswith("_wordlist.txt"):
                raise PermissionError("denied")
            return real(self, *a, **k)

        monkeypatch.setattr(pathlib.Path, "read_bytes", denied)
        loss = {}
        words = vertical._target_wordlist(ctx, set(), loss=loss)
        assert words == [] and loss["unreadable_files"] == 1 and loss["files"] == 1, (words, loss)



    # ── audit-10#2 rejected bytes never become ACTIVE vocabulary ─────────────────────────────────
