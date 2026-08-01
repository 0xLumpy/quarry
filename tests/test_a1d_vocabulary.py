"""A1d's mined vocabulary and the wildcard HTTP differentiator — what they RAN, and what they lost.

Split out of `test_crawl_fetch_lanes.py` because the subject is `vertical._wildcard_differentiate` and
`enrich._a1d_recursive_brute`, not the crawl fetch lanes: the crawl side only produces the wordlist.
The shared doubles (`_Ctx`, the scope stub) live with the crawl lanes and are imported from there.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from quarry_recon import events, sweep
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

            real_open = pathlib.Path.open

            def picky_open(self, *a, **k):
                if base_deny and base_path is not None and self.name == base_path.name:
                    raise PermissionError("denied")     # the base list is STREAMED, not read whole
                return real_open(self, *a, **k)

            monkeypatch.setattr(pathlib.Path, "read_bytes", picky)
            monkeypatch.setattr(pathlib.Path, "open", picky_open)
            monkeypatch.setattr(enrich, "have", lambda t: puredns)
            monkeypatch.setattr(vertical, "_wordlist", lambda c: base_path)   # the BASE dictionary
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
            # the A1d BASE dictionary and the wildcard GENERIC list are separate inputs: the giant DNS
            # list is no longer a vhost fallback (step 4 measurement #2)
            (tmp_path / "base.txt").write_bytes(b"")
            monkeypatch.setattr(vertical, "_wordlist", lambda c: (tmp_path / "base.txt")
                                if wordlist else None)
            (tmp_path / "vhost.txt").write_bytes(generic)
            monkeypatch.setattr(probe, "_vhost_wordlist",
                                lambda: (tmp_path / "vhost.txt") if wordlist else None)
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
                      # v52#1: selection and execution carry their own causes now
                      "selection_reason": "no in-scope wildcard zone", "gate_reason": "",
                      "eligibility_known": True,
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
        zones = {f"z{i}.acme.com" for i in range(7)}          # 7 zones, allowance 5, all guard-refused
        vertical._wildcard_differentiate(ctx, zones, extra_words=["api"], stats=st)
        # v62: the guard is a SELECTION fact settled over every eligible zone, and the allowance can only
        # defer what the guard leaves contactable — here, nothing.
        assert st["blocked"] == {"zone_cap": 0, "self_or_private": 7}, st
        assert "refused by the self/private contact guard" in st["blocked_reason"], st
        assert "allowance" not in st["blocked_reason"], st

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
        # the candidate file carries a per-INVOCATION token now (v50#1), so it is found by prefix
        cand = next((ctx.run.dir / "work").glob("wildcard_cand_wild_acme_com_*.txt"))
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
            from quarry_recon.phases import probe
            monkeypatch.setattr(probe, "_vhost_wordlist", lambda: wl)
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
            from quarry_recon.phases import probe
            monkeypatch.setattr(probe, "_vhost_wordlist", lambda: wl)
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
                            if self.name == "vhost.txt" else real(self, *a, **k))
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
        cand = [ln for ln in next((ctx.run.dir / "work").glob("wildcard_cand_a_acme_com_*.txt")).read_text()
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
            from quarry_recon.phases import probe
            monkeypatch.setattr(probe, "_vhost_wordlist", lambda: bad)
            vertical._wildcard_differentiate(ctx, {"a.acme.com"}, extra_words=["api"], label="wildcard")
            good = tmp_path / "good.txt"
            good.write_bytes(b"good\nfine\n")
            monkeypatch.setattr(probe, "_vhost_wordlist", lambda: good)
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
        assert note.count("zone-zone cap") == 0 and note.count("5-zone per-run allowance") == 1, note
        assert "wildcard zone(s) not differentiated" in note, note

    def test_the_zone_reason_stays_ZONE_only(self, tmp_path, monkeypatch):
        from quarry_recon.phases import vertical
        monkeypatch.setattr(vertical, "WILDCARD_WORD_CAP", 1)
        ctx = self._differ_ctx(tmp_path, monkeypatch, guard="self")
        st = {}
        vertical._wildcard_differentiate(ctx, {f"z{i}.acme.com" for i in range(7)},
                                         extra_words=["one", "two", "three"], label="wildcard", stats=st)
        assert "guard" in st["blocked_reason"], st
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
            cand = [ln for ln in next((ctx.run.dir / "work").glob("wildcard_cand_a_acme_com_*.txt")).read_text()
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
        # v51#1: SELECTION succeeded — the zone was eligible and chosen — and EXECUTION is the gap.
        zc = cov[("vertical.wildcard_http", "zones")]
        assert (zc["eligible"], zc["tested"], zc["omitted"]) == (1, 1, 0), zc
        ex = cov[("vertical.wildcard_http", "zone_execution")]
        assert (ex["eligible"], ex["tested"], ex["omitted"]) == (1, 0, 1), ex
        assert "no usable vocabulary" in str(ex), ex

    def test_a_MISSING_httpx_is_reported_as_a_gap_AND_a_skip(self, tmp_path, monkeypatch):
        run, summary = self._vertical_manifest(tmp_path, monkeypatch, httpx=False)
        assert summary["verdict"] != "complete", summary
        cov = {(c["source_id"], c["measure"]): c for c in summary["coverage"]}
        zc = cov[("vertical.wildcard_http", "zones")]
        assert (zc["eligible"], zc["tested"], zc["omitted"]) == (1, 1, 0), zc
        ex = cov[("vertical.wildcard_http", "zone_execution")]
        assert (ex["eligible"], ex["tested"], ex["omitted"]) == (1, 0, 1), ex
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
        from quarry_recon.phases import probe
        monkeypatch.setattr(probe, "_vhost_wordlist", lambda: wl)
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
        words = vertical._target_wordlist(ctx, loss=loss)
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
        words = vertical._target_wordlist(ctx, loss=loss)
        assert words == [] and loss["unreadable_files"] == 1 and loss["files"] == 1, (words, loss)



    # ── audit-10#2 rejected bytes never become ACTIVE vocabulary ─────────────────────────────────

    # ── step 4 measurement follow-ups ───────────────────────────────────────────────────────────
    def test_the_DNS_brute_list_is_NEVER_a_vhost_fallback(self, tmp_path, monkeypatch):
        """measurement#2: `_vhost_wordlist` promises never to fall back to the big DNS list, and
        `_wildcard_differentiate` did exactly that — MEASURED at 6,037,953 candidate hosts per zone, of
        which the 5000-word cap probed 0.1%."""
        import inspect
        from quarry_recon.phases import probe, vertical
        src = inspect.getsource(vertical._wildcard_differentiate)
        assert "_vhost_wordlist() or _wordlist(ctx)" not in src, src[:0]
        events.reset(); events.configure(tmp_path)
        ctx = self._differ_ctx(tmp_path, monkeypatch)
        huge = tmp_path / "dns.txt"
        huge.write_text("\n".join(f"d{i}" for i in range(1000)))
        monkeypatch.setattr(vertical, "_wordlist", lambda c: huge)      # the DNS list IS configured
        monkeypatch.setattr(probe, "_vhost_wordlist", lambda: None)     # ...but no dedicated vhost list
        st = {}
        vertical._wildcard_differentiate(ctx, {"a.acme.com"}, extra_words=["api"], label="wildcard",
                                         stats=st)
        assert st["vocabulary"]["entries"] == 1, st          # ONLY the caller's word
        assert st["vocabulary"]["absent"] is True, st

    def test_VERTICAL_reports_a_vocabulary_gap_when_no_vhost_list_exists(self, tmp_path, monkeypatch):
        """Without a dedicated list the vertical pass has no vocabulary of its own — it must say so and
        probe nothing, not borrow the DNS list."""
        from quarry_recon import store
        from quarry_recon.phases import probe, vertical
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            ctx = self._differ_ctx(tmp_path, monkeypatch)
            events.configure(run.dir)
            ctx.run = run
            huge = tmp_path / "dns.txt"
            huge.write_text("\n".join(f"d{i}" for i in range(1000)))
            monkeypatch.setattr(vertical, "_wordlist", lambda c: huge)
            monkeypatch.setattr(probe, "_vhost_wordlist", lambda: None)
            vertical._wildcard_differentiate(ctx, {"a.acme.com"}, label="wildcard")   # no extra_words
            run.write_manifest({}, ["vertical"])
            summary = json.loads(run.manifest_path.read_text())["summary"]
            assert summary["verdict"] != "complete", summary
            cov = {(c["source_id"], c["measure"]): c for c in summary["coverage"]}
            zc = cov[("vertical.wildcard_http", "zones")]
            assert (zc["eligible"], zc["tested"], zc["omitted"]) == (1, 1, 0), zc
            ex = cov[("vertical.wildcard_http", "zone_execution")]
            assert (ex["eligible"], ex["tested"], ex["omitted"]) == (1, 0, 1), ex
            assert "no usable vocabulary" in str(ex), ex
        finally:
            events.reset()

    def test_A1d_still_runs_on_its_OWN_words_without_a_vhost_list(self, tmp_path, monkeypatch):
        from quarry_recon.phases import vertical
        monkeypatch.setattr(vertical.netguard, "contact_state",
                            lambda host, block_private=False: ("public", False, None))
        monkeypatch.setattr(vertical.netguard, "_block_private", lambda ctx: False)
        monkeypatch.setattr(vertical.netguard, "self_deny_list", lambda: "127.0.0.1")
        recs = self._a1d_zones(tmp_path, monkeypatch, httpx=True, puredns=True, wordlist=False)
        assert recs == [], recs        # the pass RAN on the mined vocabulary; nothing unsubmitted

    def test_the_BASE_dictionary_is_STREAMED_not_materialised(self, tmp_path, monkeypatch):
        """measurement#3: the base set was 9,544,235 words / 1.5 GB RSS, built only to subtract a few
        thousand mined labels. Only OUR side belongs in memory."""
        import inspect
        from quarry_recon.phases import enrich
        src = inspect.getsource(enrich._a1d_subtract_base)
        assert 'open("rb")' in src and "read_bytes()" not in src, src
        # ...and only OUR side is held: the membership test is against the mined set, so the base file
        # contributes nothing to memory beyond the words it actually hits
        assert "w in mined" in src, src
        base = tmp_path / "base.txt"
        base.write_bytes(b"api\nwww\n# comment\nbad\xffline\n")
        loss = {}
        kept = enrich._a1d_subtract_base(None, ["portal", "api", "internal", "www"],
                                         lambda c: base, loss)
        assert kept == ["portal", "internal"], kept          # ENCOUNTER order, not sorted
        assert loss["base_dropped_lines"] == 1, loss

    def test_the_subtraction_keeps_reporting_its_failures(self, tmp_path, monkeypatch):
        from quarry_recon.phases import enrich
        loss = {}
        kept = enrich._a1d_subtract_base(None, ["api", "internal"],
                                         lambda c: (_ for _ in ()).throw(OSError("gone")), loss)
        assert kept == ["api", "internal"] and "could not be located" in loss["base_error"], (kept, loss)
        missing = tmp_path / "nope.txt"
        loss2 = {}
        kept2 = enrich._a1d_subtract_base(None, ["api"], lambda c: missing, loss2)
        assert kept2 == ["api"] and "could not be read" in loss2["base_error"], (kept2, loss2)

    def test_the_A1d_SPEND_BOUND_is_actually_applied(self, tmp_path, monkeypatch):
        """The cap is unchanged by step 4, and it is applied to the list handed to puredns — not merely
        declared as a constant."""
        from quarry_recon import store
        from quarry_recon.phases import enrich, probe, vertical
        monkeypatch.setattr(enrich, "A1D_WORD_CAP", 50)
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            wl = run.dir / "raw" / "crawl" / "xnLinkFinder"
            wl.mkdir(parents=True, exist_ok=True)
            (wl / "a_wordlist.txt").write_text("\n".join(f"word{i:04d}" for i in range(500)))
            cmds = []
            from quarry_recon.runner import RunResult as _RR
            monkeypatch.setattr(enrich, "have", lambda t: t == "puredns")
            monkeypatch.setattr(vertical, "_wordlist", lambda c: None)
            monkeypatch.setattr(probe, "_vhost_wordlist", lambda: None)
            monkeypatch.setattr(vertical, "_resolvers", lambda c: (tmp_path / "r", tmp_path / "rt"))
            monkeypatch.setattr(enrich, "exec_tool",
                                lambda tool, cmd, raw_path=None, timeout=None, **k: (
                                    cmds.append(cmd), _RR(tool, cmd, crawl.Status.EMPTY, 0, 0.1, None, 0))[1])
            ctx = _Ctx(run.dir, [])
            ctx.run = run
            ctx.scope = self._S()
            ctx.scope.passive_only = False
            ctx.scope.is_oos = lambda h: False
            ctx.profile = type("P", (), {"apex_domains": ["acme.com"], "http_rl": 0, "dns_rate": 0})()
            enrich._a1d_recursive_brute(ctx)
            assert cmds and cmds[0][0] == "puredns", cmds
            # step 4.2: the bound is per APEX across the sweep's bucket invocations, not one file
            submitted = [w for c in cmds for w in pathlib.Path(c[2]).read_text().split()]
            assert 0 < len(submitted) <= 50, len(submitted)
            assert len(submitted) == len(set(submitted)), "a word was submitted twice"
            recs = [r for r in run.tool_runs("enrich") if r.tool == "a1d"]
            assert len(recs) == 1 and recs[0].status == "partial", recs
            assert "450/500 candidate(s) withheld by the 50-per-apex A1d spend bound" in recs[0].note, recs
        finally:
            events.reset()

    def test_the_DNS_and_WILDCARD_selections_are_INDEPENDENT(self, tmp_path, monkeypatch):
        """review-step4-remeasure#3: both lanes were handed the SAME list, so widening the puredns
        selection in 4.2 would have silently widened HTTP work in a lane 4.3 has not scheduled yet."""
        from quarry_recon import store
        from quarry_recon.phases import enrich, probe, vertical
        monkeypatch.setattr(enrich, "A1D_WORD_CAP", 1)
        monkeypatch.setattr(enrich, "A1D_WILDCARD_WORD_CAP", 3)
        monkeypatch.setattr(vertical.netguard, "contact_state",
                            lambda host, block_private=False: ("public", False, None))
        monkeypatch.setattr(vertical.netguard, "_block_private", lambda ctx: False)
        monkeypatch.setattr(vertical.netguard, "self_deny_list", lambda: "127.0.0.1")
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            wl = run.dir / "raw" / "crawl" / "xnLinkFinder"
            wl.mkdir(parents=True, exist_ok=True)
            (wl / "a_wordlist.txt").write_text("\n".join(f"word{i:03d}" for i in range(20)))
            from quarry_recon.runner import RunResult as _RR
            cmds = []
            monkeypatch.setattr(enrich, "have", lambda t: True)
            monkeypatch.setattr(vertical, "have", lambda t: True)
            monkeypatch.setattr(vertical, "_wordlist", lambda c: None)
            monkeypatch.setattr(probe, "_vhost_wordlist", lambda: None)
            monkeypatch.setattr(vertical, "_resolvers", lambda c: (tmp_path / "r", tmp_path / "rt"))
            for mod in (enrich, vertical):
                monkeypatch.setattr(mod, "exec_tool",
                                    lambda tool, cmd, raw_path=None, timeout=None, **k: (
                                        cmds.append(cmd),
                                        _RR(tool, cmd, crawl.Status.EMPTY, 0, 0.1, None, 0))[1])
            monkeypatch.setattr(type(run), "values",
                                lambda self, kind: ["z.acme.com"] if kind == "wildcard_zone" else [],
                                raising=False)
            ctx = _Ctx(run.dir, [])
            ctx.run = run
            ctx.scope = self._S()
            ctx.scope.passive_only = False
            ctx.scope.is_oos = lambda h: False
            ctx.profile = type("P", (), {"apex_domains": ["acme.com"], "http_rl": 0, "dns_rate": 0})()
            enrich._a1d_recursive_brute(ctx)

            pd = [c for c in cmds if c[0] == "puredns"]
            hx = [c for c in cmds if c[0] == "httpx"]
            assert pd and hx, cmds
            dns_words = pathlib.Path(pd[0][2]).read_text().split()
            wc_cands = [x for x in pathlib.Path(hx[0][hx[0].index("-l") + 1]).read_text().split() if x]
            assert len(dns_words) == 1, dns_words                 # the DNS bound
            assert len(wc_cands) == 3 + 2, wc_cands               # the wildcard bound + 2 baseline names
            recs = [r for r in run.tool_runs("enrich") if r.tool == "a1d"]
            assert len(recs) == 1 and recs[0].status == "partial", recs
            assert "19/20 candidate(s) withheld by the 1-per-apex A1d spend bound" in recs[0].note, recs
            assert "17/20 mined word(s) withheld from the wildcard differ" in recs[0].note, recs
        finally:
            events.reset()

    def test_both_SPEND_BOUNDS_exist_and_are_unchanged(self, tmp_path, monkeypatch):
        from quarry_recon.phases import enrich, vertical
        assert enrich.A1D_WORD_CAP == 2000                  # puredns, per apex
        assert enrich.A1D_WILDCARD_WORD_CAP == 2000         # the wildcard differ, per zone
        assert vertical.WILDCARD_WORD_CAP == 5000           # the differ's own ceiling over its full input

    def _a1d_brute_only(self, tmp_path, monkeypatch, *, words: int, zones=()):
        """A puredns run with a generous DNS bound and (by default) NO wildcard zone."""
        from quarry_recon import store
        from quarry_recon.phases import enrich, probe, vertical
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            wl = run.dir / "raw" / "crawl" / "xnLinkFinder"
            wl.mkdir(parents=True, exist_ok=True)
            (wl / "a_wordlist.txt").write_text("\n".join(f"word{i:04d}" for i in range(words)))
            from quarry_recon.runner import RunResult as _RR
            monkeypatch.setattr(enrich, "A1D_WORD_CAP", words)         # the DNS lane takes everything
            monkeypatch.setattr(enrich, "A1D_WILDCARD_WORD_CAP", 2)    # ...the wildcard lane would not
            monkeypatch.setattr(enrich, "have", lambda t: True)
            monkeypatch.setattr(vertical, "have", lambda t: True)
            monkeypatch.setattr(vertical, "_wordlist", lambda c: None)
            monkeypatch.setattr(probe, "_vhost_wordlist", lambda: None)
            monkeypatch.setattr(vertical, "_resolvers", lambda c: (tmp_path / "r", tmp_path / "rt"))
            monkeypatch.setattr(vertical.netguard, "contact_state",
                                lambda host, block_private=False: ("public", False, None))
            monkeypatch.setattr(vertical.netguard, "_block_private", lambda ctx: False)
            monkeypatch.setattr(vertical.netguard, "self_deny_list", lambda: "127.0.0.1")
            for mod in (enrich, vertical):
                monkeypatch.setattr(mod, "exec_tool",
                                    lambda tool, cmd, raw_path=None, timeout=None, **k: _RR(
                                        tool, cmd, crawl.Status.EMPTY, 0, 0.1, None, 0))
            monkeypatch.setattr(type(run), "values",
                                lambda self, kind: list(zones) if kind == "wildcard_zone" else [],
                                raising=False)
            ctx = _Ctx(run.dir, [])
            ctx.run = run
            ctx.scope = self._S()
            ctx.scope.passive_only = False
            ctx.scope.is_oos = lambda h: False
            ctx.profile = type("P", (), {"apex_domains": ["acme.com"], "http_rl": 0, "dns_rate": 0})()
            enrich._a1d_recursive_brute(ctx)
            run.write_manifest({}, ["enrich"])
            return ([r for r in run.tool_runs("enrich") if r.tool == "a1d"],
                    json.loads(run.manifest_path.read_text())["summary"])
        finally:
            events.reset()

    def test_NO_wildcard_zone_means_NO_wildcard_withholding(self, tmp_path, monkeypatch):
        """review-step4-remeasure2#1: the withholding was computed before the zone set was even read, so a
        puredns-only run degraded itself over vocabulary no work wanted."""
        recs, summary = self._a1d_brute_only(tmp_path, monkeypatch, words=10)
        assert recs == [], recs
        assert summary["verdict"] == "complete", summary

    def test_only_OUT_OF_SCOPE_zones_also_means_no_withholding(self, tmp_path, monkeypatch):
        recs, _summary = self._a1d_brute_only(tmp_path, monkeypatch, words=10,
                                              zones=("z.somewhere-else.example",))
        assert recs == [], recs

    def test_an_ELIGIBLE_zone_DOES_report_the_withholding(self, tmp_path, monkeypatch):
        """The other half: with real wildcard work, the words its bound withheld are a fact again."""
        recs, summary = self._a1d_brute_only(tmp_path, monkeypatch, words=10, zones=("z.acme.com",))
        assert len(recs) == 1 and recs[0].status == "partial", recs
        assert "8/10 mined word(s) withheld from the wildcard differ" in recs[0].note, recs
        assert "A1d spend bound" not in recs[0].note, recs          # the DNS lane took everything
        assert summary["verdict"] != "complete", summary

    # ── step 4.2: the apex brute is SCHEDULED ────────────────────────────────────────────────────
    def _scheduled(self, tmp_path, monkeypatch, *, words, cap=6, run_name="t"):
        """Drive A1d's real brute through the sweep and return (submitted words, project dir)."""
        from quarry_recon import store
        from quarry_recon.phases import enrich, probe, vertical
        monkeypatch.setattr(enrich, "A1D_WORD_CAP", cap)
        run = store.Run.create(tmp_path, run_name)
        events.reset(); events.configure(run.dir)
        try:
            wl = run.dir / "raw" / "crawl" / "xnLinkFinder"
            wl.mkdir(parents=True, exist_ok=True)
            (wl / "js_wordlist.txt").write_text("\n".join(words))
            from quarry_recon.runner import RunResult as _RR
            cmds = []
            monkeypatch.setattr(enrich, "have", lambda t: True)
            monkeypatch.setattr(vertical, "have", lambda t: False)          # no wildcard pass here
            monkeypatch.setattr(vertical, "_wordlist", lambda c: None)
            monkeypatch.setattr(probe, "_vhost_wordlist", lambda: None)
            monkeypatch.setattr(vertical, "_resolvers", lambda c: (tmp_path / "r", tmp_path / "rt"))
            monkeypatch.setattr(enrich, "exec_tool",
                                lambda tool, cmd, raw_path=None, timeout=None, **k: (
                                    cmds.append(cmd), _RR(tool, cmd, crawl.Status.EMPTY, 0, 0.1, None, 0))[1])
            ctx = _Ctx(run.dir, [])
            ctx.run = run
            ctx.scope = self._S()
            ctx.scope.passive_only = False
            ctx.scope.is_oos = lambda h: False
            ctx.profile = type("P", (), {"apex_domains": ["acme.com"], "http_rl": 0, "dns_rate": 0})()
            enrich._a1d_recursive_brute(ctx)
            submitted = [w for c in cmds if c[0] == "puredns"
                         for w in pathlib.Path(c[2]).read_text().split()]
            return submitted, run
        finally:
            events.reset()

    def test_the_SPEND_is_unchanged_but_the_SELECTION_rotates(self, tmp_path, monkeypatch):
        """4.2's whole claim: the same number of candidates per apex, but a bounded run advances instead
        of re-submitting the lexicographic prefix forever."""
        words = [f"word{i:03d}" for i in range(30)]
        first, _run1 = self._scheduled(tmp_path, monkeypatch, words=words)
        assert 0 < len(first) <= 6, first
        second, _run2 = self._scheduled(tmp_path, monkeypatch, words=words, run_name="t2")
        assert 0 < len(second) <= 6, second
        assert not (set(first) & set(second)), "the second run re-submitted the first run's prefix"

    def test_the_rotation_state_is_PROJECT_scoped(self, tmp_path, monkeypatch):
        _submitted, run = self._scheduled(tmp_path, monkeypatch, words=[f"w{i:03d}" for i in range(10)])
        state = tmp_path / "recon" / "state" / "sched" / f"v{sweep.SCHEMA}" / "a1d_brute.json"
        assert state.exists(), list((tmp_path / "recon" / "state").rglob("*"))
        assert not (run.dir / "recon").exists()          # evidence is run-scoped, scheduling is not

    def test_the_lane_reports_SELECTION_and_OUTCOME_coverage(self, tmp_path, monkeypatch):
        _submitted, run = self._scheduled(tmp_path, monkeypatch, words=[f"w{i:03d}" for i in range(30)])
        evs = [json.loads(l) for l in (run.dir / "events.jsonl").read_text().splitlines()]
        cov = {e.get("measure"): e for e in evs if e.get("event") == "coverage_partial"}
        assert cov["candidate_pairs"]["eligible"] == 30, cov["candidate_pairs"]
        assert 0 < cov["candidate_pairs"]["tested"] <= 6, cov["candidate_pairs"]
        assert cov["candidate_pairs"]["omitted"] > 0 and cov["candidate_pairs"]["kind"] == "cap"
        assert cov["slot_outcomes"]["eligible"] == cov["slot_outcomes"]["tested"], cov["slot_outcomes"]
        assert all(e.get("source_id") == "enrich.a1d_brute"
                   for e in evs if e.get("measure") in ("candidate_pairs", "slot_outcomes"))

    def test_a_SECOND_LIFECYCLE_on_one_project_submits_nothing(self, tmp_path, monkeypatch):
        """One sweeper per lane: the contender reports a zero-evidence gap instead of duplicate traffic."""
        from quarry_recon import budget as _b
        sched = tmp_path / "recon" / "state" / "sched" / f"v{sweep.SCHEMA}"
        sched.mkdir(parents=True, exist_ok=True)
        with _b.state_lock(sched / "a1d_brute.lock"):
            submitted, run = self._scheduled(tmp_path, monkeypatch, words=[f"w{i:03d}" for i in range(10)])
        assert submitted == [], submitted
        evs = [json.loads(l) for l in (run.dir / "events.jsonl").read_text().splitlines()]
        sel = [e for e in evs if e.get("measure") == "candidate_pairs"][-1]
        assert sel["tested"] == 0 and sel["omitted"] == 10, sel
        assert "another lifecycle" in sel["reason"], sel

    def test_a_MISSING_puredns_reserves_nothing_and_is_recorded_ONCE(self, tmp_path, monkeypatch):
        """The dependency gate is the SWEEP's — one authority. The lane still records the skip with the
        unsubmitted count, and no rotation state is created."""
        from quarry_recon import store
        from quarry_recon.phases import enrich, probe, vertical
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            wl = run.dir / "raw" / "crawl" / "xnLinkFinder"
            wl.mkdir(parents=True, exist_ok=True)
            (wl / "js_wordlist.txt").write_text("internal\napi\n")
            monkeypatch.setattr(enrich, "have", lambda t: False)
            monkeypatch.setattr(vertical, "have", lambda t: False)
            monkeypatch.setattr(vertical, "_wordlist", lambda c: None)
            monkeypatch.setattr(probe, "_vhost_wordlist", lambda: None)
            ctx = _Ctx(run.dir, [])
            ctx.run = run
            ctx.scope = self._S()
            ctx.scope.passive_only = False
            ctx.scope.is_oos = lambda h: False
            ctx.profile = type("P", (), {"apex_domains": ["acme.com"], "http_rl": 0, "dns_rate": 0})()
            enrich._a1d_recursive_brute(ctx)
            pd = [r for r in run.tool_runs("enrich") if r.tool == "puredns"]
            assert len(pd) == 1 and pd[0].status == "skipped", pd
            assert "1 A1d apex brute(s) unsubmitted" in (pd[0].note or ""), pd
            assert not (tmp_path / "recon" / "state" / "sched" / f"v{sweep.SCHEMA}"
                    / "a1d_brute.json").exists()
            evs = [json.loads(l) for l in (run.dir / "events.jsonl").read_text().splitlines()]
            sel = [e for e in evs if e.get("measure") == "candidate_pairs"][-1]
            assert (sel["tested"], sel["omitted"]) == (0, 2) and "not installed" in sel["reason"], sel
        finally:
            events.reset()

    def test_the_scheduled_prefix_is_ATTRIBUTED_to_the_artifact_that_produced_it(self, tmp_path,
                                                                                 monkeypatch):
        from quarry_recon import store
        from quarry_recon.phases import enrich, probe, vertical
        monkeypatch.setattr(enrich, "A1D_WORD_CAP", 4)
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            wl = run.dir / "raw" / "crawl" / "xnLinkFinder"
            wl.mkdir(parents=True, exist_ok=True)
            (wl / "js_wordlist.txt").write_text("\n".join(f"jsword{i:02d}" for i in range(10)))
            (wl / "katana_wordlist.txt").write_text("\n".join(f"katword{i:02d}" for i in range(10)))
            from quarry_recon.runner import RunResult as _RR
            monkeypatch.setattr(enrich, "have", lambda t: True)
            monkeypatch.setattr(vertical, "have", lambda t: False)
            monkeypatch.setattr(vertical, "_wordlist", lambda c: None)
            monkeypatch.setattr(probe, "_vhost_wordlist", lambda: None)
            monkeypatch.setattr(vertical, "_resolvers", lambda c: (tmp_path / "r", tmp_path / "rt"))
            monkeypatch.setattr(enrich, "exec_tool",
                                lambda tool, cmd, raw_path=None, timeout=None, **k: _RR(
                                    tool, cmd, crawl.Status.EMPTY, 0, 0.1, None, 0))
            ctx = _Ctx(run.dir, [])
            ctx.run = run
            ctx.scope = self._S()
            ctx.scope.passive_only = False
            ctx.scope.is_oos = lambda h: False
            ctx.profile = type("P", (), {"apex_domains": ["acme.com"], "http_rl": 0, "dns_rate": 0})()
            enrich._a1d_recursive_brute(ctx)
            evs = [json.loads(l) for l in (run.dir / "events.jsonl").read_text().splitlines()]
            attr = [e for e in evs if e.get("unit") == "attribution"][-1]["selection_attribution"]
            assert attr["eligible"] == 20 and 0 < attr["scheduled"] <= 4, attr
            assert set(attr["per_source_eligible"]) <= {"js_wordlist.txt", "katana_wordlist.txt"}, attr
            assert sum(attr["per_source_scheduled"].values()) == attr["scheduled"], attr
        finally:
            events.reset()

    def test_the_source_is_REGISTRY_GATED_and_BRACKETED(self, tmp_path, monkeypatch):
        """v17#1: an absent registry entry must stop active DNS traffic, and a multi-bucket sweep still
        owes the source exactly ONE terminal."""
        from quarry_recon.phases import enrich
        submitted, run = self._scheduled(tmp_path, monkeypatch, words=[f"w{i:03d}" for i in range(8)])
        evs = [json.loads(l) for l in (run.dir / "events.jsonl").read_text().splitlines()]
        starts = [e for e in evs if e.get("event") == "tool_start" and e.get("source_id") == "enrich.a1d_brute"]
        fins = [e for e in evs if e.get("event") == "tool_finish" and e.get("source_id") == "enrich.a1d_brute"]
        assert len(starts) == 1 and len(fins) == 1, (starts, fins)
        assert starts[0]["input_total"] == 1 and fins[0]["status"] in ("success", "empty"), fins

        monkeypatch.setattr(enrich, "registered", lambda sid: False)
        blocked, _run2 = self._scheduled(tmp_path, monkeypatch, words=["one", "two"], run_name="t2")
        assert blocked == [], blocked

    def test_a_SCHEMA_bump_starts_a_FRESH_rotation(self, tmp_path, monkeypatch):
        """v17#2: without the schema in the PATH, bumping it met a document RotationProgress refuses to
        overwrite — and the lane could never reserve again until an operator deleted the file."""
        words = [f"w{i:03d}" for i in range(8)]
        first, _r1 = self._scheduled(tmp_path, monkeypatch, words=words)
        assert first, "the first schema never ran"
        monkeypatch.setattr(sweep, "SCHEMA", sweep.SCHEMA + 1)
        second, _r2 = self._scheduled(tmp_path, monkeypatch, words=words, run_name="t2")
        assert second, "a schema bump bricked the lane"
        base = tmp_path / "recon" / "state" / "sched"
        assert (base / f"v{sweep.SCHEMA - 1}" / "a1d_brute.json").exists()
        assert (base / f"v{sweep.SCHEMA}" / "a1d_brute.json").exists()

    def test_a_CONTENDED_sweep_is_not_blamed_on_a_missing_tool(self, tmp_path, monkeypatch):
        """v17#3: every unattempted apex used to be reported as "puredns is not installed"."""
        from quarry_recon import budget as _b
        sched = tmp_path / "recon" / "state" / "sched" / f"v{sweep.SCHEMA}"
        sched.mkdir(parents=True, exist_ok=True)
        with _b.state_lock(sched / "a1d_brute.lock"):
            submitted, run = self._scheduled(tmp_path, monkeypatch, words=["one", "two"])
        assert submitted == []
        recs = [r for r in run.tool_runs("enrich") if r.tool == "a1d"]
        assert len(recs) == 1 and "another lifecycle" in recs[0].note, recs
        assert "not installed" not in recs[0].note, recs
        assert not [r for r in run.tool_runs("enrich") if r.tool == "puredns"], "a false dependency record"
        fin = [json.loads(l) for l in (run.dir / "events.jsonl").read_text().splitlines()
               if json.loads(l).get("event") == "tool_finish"
               and json.loads(l).get("source_id") == "enrich.a1d_brute"]
        assert fin and fin[-1]["status"] == "failed", fin        # zero evidence under contention

    def test_the_WITHHELD_count_is_the_scheduler_s_own_arithmetic(self, tmp_path, monkeypatch):
        """v17#4: whole buckets can underfill the bound, so `corpus - cap` disagreed with coverage."""
        submitted, run = self._scheduled(tmp_path, monkeypatch, words=[f"w{i:03d}" for i in range(9)],
                                         cap=4)
        evs = [json.loads(l) for l in (run.dir / "events.jsonl").read_text().splitlines()]
        sel = [e for e in evs if e.get("measure") == "candidate_pairs"][-1]
        recs = [r for r in run.tool_runs("enrich") if r.tool == "a1d"]
        assert len(submitted) == sel["tested"], (submitted, sel)
        assert f"{sel['omitted']}/{sel['eligible']} candidate(s) withheld" in recs[0].note, (recs, sel)

    def test_a_BOUND_stop_is_not_reported_as_wall_clock_exhaustion(self, tmp_path, monkeypatch):
        _submitted, run = self._scheduled(tmp_path, monkeypatch, words=[f"w{i:03d}" for i in range(9)],
                                          cap=4)
        evs = [json.loads(l) for l in (run.dir / "events.jsonl").read_text().splitlines()]
        sel = [e for e in evs if e.get("measure") == "candidate_pairs"][-1]
        assert sel["kind"] == "cap", sel
        assert "per-target candidate bound" in sel["reason"], sel
        assert "0s of 0s" not in sel["reason"], sel

    def test_a_tool_that_vanishes_MID_SWEEP_is_not_a_missing_dependency(self, tmp_path, monkeypatch):
        """v17#3: a SKIPPED result mid-sweep is not "puredns is not installed" — the earlier buckets ran.
        It also does not count as an apex we brute-forced."""
        from quarry_recon import store
        from quarry_recon.phases import enrich, probe, vertical
        monkeypatch.setattr(sweep, "BUCKETS", 4)
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 1)     # per-SLOT statuses: one slot per invocation
        monkeypatch.setattr(enrich, "A1D_WORD_CAP", 50)
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            wl = run.dir / "raw" / "crawl" / "xnLinkFinder"
            wl.mkdir(parents=True, exist_ok=True)
            (wl / "js_wordlist.txt").write_text("\n".join(f"w{i:03d}" for i in range(12)))
            from quarry_recon.runner import RunResult as _RR
            seen = []

            def flaky(tool, cmd, raw_path=None, timeout=None, **k):
                seen.append(cmd)
                status = crawl.Status.EMPTY if len(seen) == 1 else crawl.Status.SKIPPED
                return _RR(tool, cmd, status, 0, 0.1, None, 0)

            monkeypatch.setattr(enrich, "have", lambda t: True)
            monkeypatch.setattr(vertical, "have", lambda t: False)
            monkeypatch.setattr(vertical, "_wordlist", lambda c: None)
            monkeypatch.setattr(probe, "_vhost_wordlist", lambda: None)
            monkeypatch.setattr(vertical, "_resolvers", lambda c: (tmp_path / "r", tmp_path / "rt"))
            monkeypatch.setattr(enrich, "exec_tool", flaky)
            ctx = _Ctx(run.dir, [])
            ctx.run = run
            ctx.scope = self._S()
            ctx.scope.passive_only = False
            ctx.scope.is_oos = lambda h: False
            ctx.profile = type("P", (), {"apex_domains": ["acme.com"], "http_rl": 0, "dns_rate": 0})()
            enrich._a1d_recursive_brute(ctx)
            assert len(seen) == 2, seen
            pd = [r for r in run.tool_runs("enrich") if r.tool == "puredns" and r.status == "skipped"]
            assert len(pd) == 1, pd          # the SKIPPED invocation itself, NOT a "not installed" record
            assert "not installed" not in " ".join(r.note or "" for r in pd), pd
            recs = [r for r in run.tool_runs("enrich") if r.tool == "a1d"]
            assert len(recs) == 1 and "the tool did not run" in recs[0].note, recs
            # the apex WAS brute-forced (the first bucket ran), so nothing is "unsubmitted" for it
            assert "apex brute(s) unsubmitted" not in recs[0].note, recs
            # ...and the source terminal is NOT a skip: work happened before the tool vanished
            fins = [json.loads(l) for l in (run.dir / "events.jsonl").read_text().splitlines()
                    if json.loads(l).get("event") == "tool_finish"
                    and json.loads(l).get("source_id") == "enrich.a1d_brute"]
            assert len(fins) == 1 and fins[0]["status"] != "skipped", fins
        finally:
            events.reset()

    def test_the_withheld_count_survives_an_UNDERFILLED_bound(self, tmp_path, monkeypatch):
        """v17#4: whole buckets can leave the bound unspent, so `corpus - cap` overstates what ran."""
        # MEASURED split at BUCKETS=2 over these 8 words: 5 + 3. With a bound of 7 the second bucket
        # would cross it, so the sweep submits 5 and leaves 3 — the bound is UNDERFILLED by 2.
        monkeypatch.setattr(sweep, "BUCKETS", 2)
        submitted, run = self._scheduled(tmp_path, monkeypatch, words=[f"w{i:03d}" for i in range(8)],
                                         cap=7)
        evs = [json.loads(l) for l in (run.dir / "events.jsonl").read_text().splitlines()]
        sel = [e for e in evs if e.get("measure") == "candidate_pairs"][-1]
        recs = [r for r in run.tool_runs("enrich") if r.tool == "a1d"]
        assert len(submitted) == sel["tested"] == 5, (submitted, sel)     # a whole bucket was skipped
        assert sel["omitted"] == 3 != 8 - 7, sel                          # `corpus - cap` would say 1
        assert f"{sel['omitted']}/{sel['eligible']} candidate(s) withheld" in recs[0].note, (recs, sel)

    def test_an_apex_whose_FIRST_invocation_never_ran_is_unsubmitted(self, tmp_path, monkeypatch):
        """v17#3 (the other half): a SKIPPED invocation is not an apex we brute-forced."""
        from quarry_recon import store
        from quarry_recon.phases import enrich, probe, vertical
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            wl = run.dir / "raw" / "crawl" / "xnLinkFinder"
            wl.mkdir(parents=True, exist_ok=True)
            (wl / "js_wordlist.txt").write_text("one\ntwo\n")
            from quarry_recon.runner import RunResult as _RR
            monkeypatch.setattr(enrich, "have", lambda t: True)
            monkeypatch.setattr(vertical, "have", lambda t: False)
            monkeypatch.setattr(vertical, "_wordlist", lambda c: None)
            monkeypatch.setattr(probe, "_vhost_wordlist", lambda: None)
            monkeypatch.setattr(vertical, "_resolvers", lambda c: (tmp_path / "r", tmp_path / "rt"))
            monkeypatch.setattr(enrich, "exec_tool",
                                lambda tool, cmd, raw_path=None, timeout=None, **k: _RR(
                                    tool, cmd, crawl.Status.SKIPPED, None, 0.0, None, 0))
            ctx = _Ctx(run.dir, [])
            ctx.run = run
            ctx.scope = self._S()
            ctx.scope.passive_only = False
            ctx.scope.is_oos = lambda h: False
            ctx.profile = type("P", (), {"apex_domains": ["acme.com"], "http_rl": 0, "dns_rate": 0})()
            enrich._a1d_recursive_brute(ctx)
            recs = [r for r in run.tool_runs("enrich") if r.tool == "a1d"]
            assert len(recs) == 1, recs
            assert "1 apex brute(s) unsubmitted (the tool did not run)" in recs[0].note, recs
        finally:
            events.reset()

    def test_the_BUCKET_COUNT_is_read_at_call_time(self, tmp_path, monkeypatch):
        """A default argument would freeze the module constant at import, so a bucket-count change (with
        its schema bump) would silently keep the old slot space."""
        before = sweep.bucket_of("alpha")
        monkeypatch.setattr(sweep, "BUCKETS", 3)
        assert sweep.bucket_of("alpha") != before or sweep.BUCKETS == 3
        assert int(sweep.bucket_of("alpha")) < 3, sweep.bucket_of("alpha")

    # ── v18: the lane's own lifecycle boundary ───────────────────────────────────────────────────
    def test_a_disabled_BRUTE_does_not_suppress_the_WILDCARD_lane(self, tmp_path, monkeypatch):
        """v18#1: they are separate registered sources. One being unavailable must not silence the other."""
        from quarry_recon.phases import enrich, vertical
        monkeypatch.setattr(enrich, "registered", lambda s: s != "enrich.a1d_brute")
        monkeypatch.setattr(vertical.netguard, "contact_state",
                            lambda host, block_private=False: ("public", False, None))
        monkeypatch.setattr(vertical.netguard, "_block_private", lambda ctx: False)
        monkeypatch.setattr(vertical.netguard, "self_deny_list", lambda: "127.0.0.1")
        seen: list = []
        real_cov = events.coverage_partial
        monkeypatch.setattr(events, "coverage_partial",
                            lambda sid, **k: (seen.append({"source_id": sid, **k}), real_cov(sid, **k))[1])
        recs = self._a1d_zones(tmp_path, monkeypatch, zones=("z.acme.com",), httpx=True, puredns=True)
        # the WILDCARD pass ran under its own source even though the brute's source was rejected
        wl_evs = seen
        zones_cov = [e for e in wl_evs if e.get("measure") == "zones"]
        assert zones_cov and zones_cov[-1]["source_id"] == "enrich.wildcard_a1d", wl_evs[-3:]
        assert zones_cov[-1]["tested"] == 1, zones_cov[-1]
        assert not any(e.get("source_id") == "enrich.a1d_brute" for e in wl_evs), "the brute ran anyway"
        assert not any("wildcard zone(s) not differentiated" in (r.note or "") for r in recs), recs
        # ...and the unsubmitted brute names the REAL cause, not a missing binary (v19#2)
        assert any("the source is not registered" in (r.note or "") for r in recs), recs
        assert not any("puredns is not installed" in (r.note or "") for r in recs), recs

    def test_CANCELLATION_closes_the_source_lifecycle_before_propagating(self, tmp_path, monkeypatch):
        """v18#2: a `tool_start` with no `tool_finish` is a source that never answered."""
        from quarry_recon import store
        from quarry_recon.phases import enrich, probe, vertical
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            wl = run.dir / "raw" / "crawl" / "xnLinkFinder"
            wl.mkdir(parents=True, exist_ok=True)
            (wl / "js_wordlist.txt").write_text("one\ntwo\n")
            monkeypatch.setattr(enrich, "have", lambda t: True)
            monkeypatch.setattr(vertical, "have", lambda t: False)
            monkeypatch.setattr(vertical, "_wordlist", lambda c: None)
            monkeypatch.setattr(probe, "_vhost_wordlist", lambda: None)
            monkeypatch.setattr(vertical, "_resolvers", lambda c: (tmp_path / "r", tmp_path / "rt"))
            monkeypatch.setattr(enrich, "exec_tool",
                                lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt("ctrl-c")))
            ctx = _Ctx(run.dir, [])
            ctx.run = run
            ctx.scope = self._S()
            ctx.scope.passive_only = False
            ctx.scope.is_oos = lambda h: False
            ctx.profile = type("P", (), {"apex_domains": ["acme.com"], "http_rl": 0, "dns_rate": 0})()
            with pytest.raises(KeyboardInterrupt):
                enrich._a1d_recursive_brute(ctx)
            evs = [json.loads(l) for l in (run.dir / "events.jsonl").read_text().splitlines()]
            starts = [e for e in evs if e.get("event") == "tool_start"
                      and e.get("source_id") == "enrich.a1d_brute"]
            fins = [e for e in evs if e.get("event") == "tool_finish"
                    and e.get("source_id") == "enrich.a1d_brute"]
            assert len(starts) == len(fins) == 1, (starts, fins)
            assert "CANCELLED" in (fins[0].get("reason") or ""), fins
        finally:
            events.reset()

    def test_a_NON_CONTENTION_sweep_failure_still_terminates_the_source(self, tmp_path, monkeypatch):
        from quarry_recon.phases import enrich
        monkeypatch.setattr(enrich.sweep, "run_sweep",
                            lambda **k: (_ for _ in ()).throw(OSError("read-only filesystem")))
        submitted, run = self._scheduled(tmp_path, monkeypatch, words=["one", "two"])
        evs = [json.loads(l) for l in (run.dir / "events.jsonl").read_text().splitlines()]
        fins = [e for e in evs if e.get("event") == "tool_finish"
                and e.get("source_id") == "enrich.a1d_brute"]
        assert len(fins) == 1 and fins[0]["status"] == "failed", fins
        assert "read-only filesystem" in fins[0]["reason"], fins

    @pytest.mark.parametrize("statuses,produced_hosts,want", [
        (["empty", "empty"], 0, "empty"),          # the runner answered, nothing was found
        (["success"], 1, "success"),               # a host came back
        (["failed", "empty"], 0, "failed"),        # a slot did not answer and nothing was produced
        (["failed", "success"], 1, "partial"),     # a slot did not answer but evidence exists
    ])
    def test_the_TERMINAL_follows_production_and_slot_classes(self, tmp_path, monkeypatch,
                                                              statuses, produced_hosts, want):
        """v18#3: `slots_obtained` counts SUCCESS *and* EMPTY, so an all-empty sweep read SUCCESS and a
        failed one read EMPTY, while failed/timed-out slots never reached the terminal at all."""
        from quarry_recon import store
        from quarry_recon.phases import enrich, probe, vertical
        monkeypatch.setattr(sweep, "BUCKETS", len(statuses))
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 1)     # one status per SLOT, so one slot per call
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            wl = run.dir / "raw" / "crawl" / "xnLinkFinder"
            wl.mkdir(parents=True, exist_ok=True)
            (wl / "js_wordlist.txt").write_text("\n".join(f"w{i:03d}" for i in range(8)))
            from quarry_recon.runner import RunResult as _RR
            seq = list(statuses)

            def fake(tool, cmd, raw_path=None, timeout=None, **k):
                st = getattr(crawl.Status, seq.pop(0).upper()) if seq else crawl.Status.EMPTY
                if produced_hosts and st is crawl.Status.SUCCESS and raw_path is not None:
                    raw_path.parent.mkdir(parents=True, exist_ok=True)
                    raw_path.write_text("found.acme.com\n")
                return _RR(tool, cmd, st, 0, 0.1, raw_path if st is crawl.Status.SUCCESS else None, 0)

            monkeypatch.setattr(enrich, "have", lambda t: True)
            monkeypatch.setattr(vertical, "have", lambda t: False)
            monkeypatch.setattr(vertical, "_wordlist", lambda c: None)
            monkeypatch.setattr(probe, "_vhost_wordlist", lambda: None)
            monkeypatch.setattr(vertical, "_resolvers", lambda c: (tmp_path / "r", tmp_path / "rt"))
            monkeypatch.setattr(enrich, "exec_tool", fake)
            ctx = _Ctx(run.dir, [])
            ctx.run = run
            ctx.scope = self._S()
            ctx.scope.passive_only = False
            ctx.scope.is_oos = lambda h: False
            ctx.profile = type("P", (), {"apex_domains": ["acme.com"], "http_rl": 0, "dns_rate": 0})()
            enrich._a1d_recursive_brute(ctx)
            fins = [json.loads(l) for l in (run.dir / "events.jsonl").read_text().splitlines()
                    if json.loads(l).get("event") == "tool_finish"
                    and json.loads(l).get("source_id") == "enrich.a1d_brute"]
            assert len(fins) == 1 and fins[0]["status"] == want, (fins, statuses)
            assert fins[0]["produced"]["subdomains"] == produced_hosts, fins
        finally:
            events.reset()

    # ── v19: the boundary covers reporting, and each remainder keeps its own cause ───────────────
    def test_a_failing_REPORT_still_terminates_the_source(self, tmp_path, monkeypatch):
        """v19#1: reporting is fallible too — `record()` can raise before the terminal was emitted."""
        from quarry_recon import store
        from quarry_recon.phases import enrich, probe, vertical
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            wl = run.dir / "raw" / "crawl" / "xnLinkFinder"
            wl.mkdir(parents=True, exist_ok=True)
            (wl / "js_wordlist.txt").write_text("one\ntwo\n")
            monkeypatch.setattr(enrich, "have", lambda t: True)
            monkeypatch.setattr(vertical, "have", lambda t: False)
            monkeypatch.setattr(vertical, "_wordlist", lambda c: None)
            monkeypatch.setattr(probe, "_vhost_wordlist", lambda: None)
            monkeypatch.setattr(vertical, "_resolvers", lambda c: (tmp_path / "r", tmp_path / "rt"))
            monkeypatch.setattr(enrich, "_a1d_fold_sweep",
                                lambda *a, **k: (_ for _ in ()).throw(OSError("record failed")))
            from quarry_recon.runner import RunResult as _RR
            monkeypatch.setattr(enrich, "exec_tool",
                                lambda tool, cmd, raw_path=None, timeout=None, **k: _RR(
                                    tool, cmd, crawl.Status.EMPTY, 0, 0.1, None, 0))
            ctx = _Ctx(run.dir, [])
            ctx.run = run
            ctx.scope = self._S()
            ctx.scope.passive_only = False
            ctx.scope.is_oos = lambda h: False
            ctx.profile = type("P", (), {"apex_domains": ["acme.com"], "http_rl": 0, "dns_rate": 0})()
            enrich._a1d_recursive_brute(ctx)                 # must NOT raise
            evs = [json.loads(l) for l in (run.dir / "events.jsonl").read_text().splitlines()]
            starts = [e for e in evs if e.get("event") == "tool_start"
                      and e.get("source_id") == "enrich.a1d_brute"]
            fins = [e for e in evs if e.get("event") == "tool_finish"
                    and e.get("source_id") == "enrich.a1d_brute"]
            assert len(starts) == len(fins) == 1, (starts, fins)
            assert "record failed" in (fins[0].get("reason") or ""), fins
        finally:
            events.reset()

    def test_the_terminal_is_emitted_EXACTLY_ONCE_on_cancellation(self, tmp_path, monkeypatch):
        from quarry_recon import store
        from quarry_recon.phases import enrich, probe, vertical
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            wl = run.dir / "raw" / "crawl" / "xnLinkFinder"
            wl.mkdir(parents=True, exist_ok=True)
            (wl / "js_wordlist.txt").write_text("one\ntwo\n")
            monkeypatch.setattr(enrich, "have", lambda t: True)
            monkeypatch.setattr(vertical, "have", lambda t: False)
            monkeypatch.setattr(vertical, "_wordlist", lambda c: None)
            monkeypatch.setattr(probe, "_vhost_wordlist", lambda: None)
            monkeypatch.setattr(vertical, "_resolvers", lambda c: (tmp_path / "r", tmp_path / "rt"))
            monkeypatch.setattr(enrich, "exec_tool",
                                lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt("ctrl-c")))
            ctx = _Ctx(run.dir, [])
            ctx.run = run
            ctx.scope = self._S()
            ctx.scope.passive_only = False
            ctx.scope.is_oos = lambda h: False
            ctx.profile = type("P", (), {"apex_domains": ["acme.com"], "http_rl": 0, "dns_rate": 0})()
            with pytest.raises(KeyboardInterrupt):
                enrich._a1d_recursive_brute(ctx)
            fins = [json.loads(l) for l in (run.dir / "events.jsonl").read_text().splitlines()
                    if json.loads(l).get("event") == "tool_finish"
                    and json.loads(l).get("source_id") == "enrich.a1d_brute"]
            assert len(fins) == 1 and "CANCELLED" in fins[0]["reason"], fins
        finally:
            events.reset()

    def test_a_CONTENDED_remainder_is_not_blamed_on_the_spend_bound(self, tmp_path, monkeypatch):
        """v19#2: contention, dependency, machinery and the clock all leave a remainder — none of them is
        the cap withholding work."""
        from quarry_recon import budget as _b
        sched = tmp_path / "recon" / "state" / "sched" / f"v{sweep.SCHEMA}"
        sched.mkdir(parents=True, exist_ok=True)
        with _b.state_lock(sched / "a1d_brute.lock"):
            _submitted, run = self._scheduled(tmp_path, monkeypatch,
                                              words=[f"w{i:03d}" for i in range(10)])
        recs = [r for r in run.tool_runs("enrich") if r.tool == "a1d"]
        assert len(recs) == 1, recs
        assert "spend bound" not in recs[0].note, recs
        assert "another lifecycle" in recs[0].note, recs

    def test_the_WILDCARD_note_keeps_the_WORD_denominator(self, tmp_path, monkeypatch):
        """v19#3: `after_base` is retained WORDS; the scheduler's candidate-target pairs are a different
        unit, and two apexes made the wildcard note read `8/20` for a 10-word corpus."""
        from quarry_recon.phases import enrich, vertical
        monkeypatch.setattr(enrich, "A1D_WILDCARD_WORD_CAP", 1)
        monkeypatch.setattr(vertical.netguard, "contact_state",
                            lambda host, block_private=False: ("public", False, None))
        monkeypatch.setattr(vertical.netguard, "_block_private", lambda ctx: False)
        monkeypatch.setattr(vertical.netguard, "self_deny_list", lambda: "127.0.0.1")
        recs = self._a1d_zones(tmp_path, monkeypatch, zones=("z.acme.com",), httpx=True, puredns=True)
        assert len(recs) == 1, recs
        # the mined corpus here is "internal" + "api" = 2 WORDS. With two apexes the scheduler would count
        # 4 candidate PAIRS; this note must still speak in words.
        assert "1/2 mined word(s) withheld from the wildcard differ" in recs[0].note, recs

    def test_the_unreadable_sentence_counts_WORDS_not_candidate_pairs(self, tmp_path, monkeypatch):
        """v19#3 (the other half): `_a1d_loss_why(produced=…)` renders "the readable N yielded X usable
        word(s)". With two apexes the scheduler's candidate PAIRS are double the words."""
        from quarry_recon import store
        from quarry_recon.phases import enrich, probe, vertical
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            wl = run.dir / "raw" / "crawl" / "xnLinkFinder"
            wl.mkdir(parents=True, exist_ok=True)
            (wl / "a_wordlist.txt").write_text("internal\napi\nportal\n")   # 3 usable words
            (wl / "b_wordlist.txt").write_text("unreadable\n")
            real = pathlib.Path.read_bytes
            monkeypatch.setattr(pathlib.Path, "read_bytes",
                                lambda self, *a, **k: (_ for _ in ()).throw(PermissionError("denied"))
                                if self.name == "b_wordlist.txt" else real(self, *a, **k))
            from quarry_recon.runner import RunResult as _RR
            monkeypatch.setattr(enrich, "have", lambda t: True)
            monkeypatch.setattr(vertical, "have", lambda t: False)
            monkeypatch.setattr(vertical, "_wordlist", lambda c: None)
            monkeypatch.setattr(probe, "_vhost_wordlist", lambda: None)
            monkeypatch.setattr(vertical, "_resolvers", lambda c: (tmp_path / "r", tmp_path / "rt"))
            monkeypatch.setattr(enrich, "exec_tool",
                                lambda tool, cmd, raw_path=None, timeout=None, **k: _RR(
                                    tool, cmd, crawl.Status.EMPTY, 0, 0.1, None, 0))
            ctx = _Ctx(run.dir, [])
            ctx.run = run
            ctx.scope = self._S()
            ctx.scope.passive_only = False
            ctx.scope.is_oos = lambda h: False
            ctx.profile = type("P", (), {"apex_domains": ["acme.com", "acme.net"], "http_rl": 0,
                                         "dns_rate": 0})()          # 3 words x 2 apexes = 6 PAIRS
            enrich._a1d_recursive_brute(ctx)
            recs = [r for r in run.tool_runs("enrich") if r.tool == "a1d"]
            assert len(recs) == 1, recs
            assert "yielded 3 usable word(s)" in recs[0].note, recs   # words, never the 6 pairs
        finally:
            events.reset()

    def test_a_failing_RESOLVER_SETUP_terminates_A1d_and_lets_the_wildcard_lane_run(self, tmp_path,
                                                                                    monkeypatch):
        """v20#1: `_resolvers()` used to run BEFORE the registry gate and before `tool_start`, so an
        OSError aborted the whole enrich phase — no A1d terminal at all, and the wildcard lane silenced
        with it."""
        from quarry_recon import store
        from quarry_recon.phases import enrich, probe, vertical
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            wl = run.dir / "raw" / "crawl" / "xnLinkFinder"
            wl.mkdir(parents=True, exist_ok=True)
            (wl / "js_wordlist.txt").write_text("one\ntwo\n")
            reached = []
            monkeypatch.setattr(enrich, "have", lambda t: True)
            monkeypatch.setattr(vertical, "have", lambda t: True)
            monkeypatch.setattr(vertical, "_wordlist", lambda c: None)
            monkeypatch.setattr(probe, "_vhost_wordlist", lambda: None)
            monkeypatch.setattr(vertical, "_resolvers",
                                lambda c: (_ for _ in ()).throw(OSError("no resolver file")))
            monkeypatch.setattr(vertical, "_wildcard_differentiate",
                                lambda *a, **k: reached.append(a) or {})
            ctx = _Ctx(run.dir, [])
            ctx.run = run
            ctx.scope = self._S()
            ctx.scope.passive_only = False
            ctx.scope.is_oos = lambda h: False
            ctx.profile = type("P", (), {"apex_domains": ["acme.com"], "http_rl": 0, "dns_rate": 0})()
            monkeypatch.setattr(type(run), "values",
                                lambda self, kind: ["z.acme.com"] if kind == "wildcard_zone" else [],
                                raising=False)
            enrich._a1d_recursive_brute(ctx)                 # the phase survives the setup failure
            evs = [json.loads(l) for l in (run.dir / "events.jsonl").read_text().splitlines()]
            starts = [e for e in evs if e.get("event") == "tool_start"
                      and e.get("source_id") == "enrich.a1d_brute"]
            fins = [e for e in evs if e.get("event") == "tool_finish"
                    and e.get("source_id") == "enrich.a1d_brute"]
            assert len(starts) == len(fins) == 1, (starts, fins)
            assert "no resolver file" in (fins[0].get("reason") or ""), fins
            assert reached, "the wildcard lane must still run after a failed brute setup"
        finally:
            events.reset()

    def test_the_DEPENDENCY_is_observed_ONCE_for_setup_and_for_the_gate(self, tmp_path, monkeypatch):
        """v20#1 (the other half): two independent `have()` observations authorised execution with
        UNINITIALISED resolver paths — puredns ran with `--resolvers-trusted None`."""
        from quarry_recon import store
        from quarry_recon.phases import enrich, probe, vertical
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            wl = run.dir / "raw" / "crawl" / "xnLinkFinder"
            wl.mkdir(parents=True, exist_ok=True)
            (wl / "js_wordlist.txt").write_text("one\ntwo\n")
            seen = []
            answers = iter([False])                  # the FIRST observation says no; any later one says yes
            monkeypatch.setattr(enrich, "have", lambda t: next(answers, True))
            monkeypatch.setattr(vertical, "have", lambda t: False)
            monkeypatch.setattr(vertical, "_wordlist", lambda c: None)
            monkeypatch.setattr(probe, "_vhost_wordlist", lambda: None)
            monkeypatch.setattr(vertical, "_resolvers",
                                lambda c: (_ for _ in ()).throw(AssertionError("setup must not run")))
            monkeypatch.setattr(enrich, "exec_tool", lambda tool, cmd, **k: seen.append(cmd))
            ctx = _Ctx(run.dir, [])
            ctx.run = run
            ctx.scope = self._S()
            ctx.scope.passive_only = False
            ctx.scope.is_oos = lambda h: False
            ctx.profile = type("P", (), {"apex_domains": ["acme.com"], "http_rl": 0, "dns_rate": 0})()
            enrich._a1d_recursive_brute(ctx)
            assert seen == [], seen        # never executed on the strength of a SECOND observation
            fins = [json.loads(l) for l in (run.dir / "events.jsonl").read_text().splitlines()
                    if json.loads(l).get("event") == "tool_finish"
                    and json.loads(l).get("source_id") == "enrich.a1d_brute"]
            assert len(fins) == 1 and "not installed" in fins[0]["reason"], fins
        finally:
            events.reset()

    def test_ONE_puredns_call_now_carries_several_SLOTS(self, tmp_path, monkeypatch):
        """Step 4.2 batching, at the lane: the spend is unchanged, the number of processes is not. A
        puredns invocation costs ~1.04s before it resolves anything (measured), which the one-slot-per-call
        driver paid once per slot."""
        from quarry_recon import store
        from quarry_recon.phases import enrich, probe, vertical
        monkeypatch.setattr(enrich, "A1D_WORD_CAP", 6)
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            wl = run.dir / "raw" / "crawl" / "xnLinkFinder"
            wl.mkdir(parents=True, exist_ok=True)
            (wl / "js_wordlist.txt").write_text("\n".join(f"word{i:03d}" for i in range(30)))
            from quarry_recon.runner import RunResult as _RR
            cmds, raws = [], []
            monkeypatch.setattr(enrich, "have", lambda t: True)
            monkeypatch.setattr(vertical, "have", lambda t: False)
            monkeypatch.setattr(vertical, "_wordlist", lambda c: None)
            monkeypatch.setattr(probe, "_vhost_wordlist", lambda: None)
            monkeypatch.setattr(vertical, "_resolvers", lambda c: (tmp_path / "r", tmp_path / "rt"))
            monkeypatch.setattr(enrich, "exec_tool",
                                lambda tool, cmd, raw_path=None, timeout=None, **k: (
                                    cmds.append(cmd), raws.append(raw_path),
                                    _RR(tool, cmd, crawl.Status.EMPTY, 0, 0.1, None, 0))[2])
            ctx = _Ctx(run.dir, [])
            ctx.run = run
            ctx.scope = self._S()
            ctx.scope.passive_only = False
            ctx.scope.is_oos = lambda h: False
            ctx.profile = type("P", (), {"apex_domains": ["acme.com"], "http_rl": 0, "dns_rate": 0})()
            enrich._a1d_recursive_brute(ctx)
            assert len(cmds) == 1, cmds                       # ONE process for the whole allowance
            submitted = pathlib.Path(cmds[0][2]).read_text().split()
            assert len(submitted) == 6, submitted             # the spend bound is unchanged
            # the wordlist and the raw artifact are named by the INVOCATION, not by one of its slots
            assert "+" in pathlib.Path(cmds[0][2]).name, cmds[0][2]
            assert len(raws) == 1 and "+" in raws[0].name, raws
            assert raws[0].name.startswith("a1d-brute-acme.com-"), raws
        finally:
            events.reset()

    def test_the_RESUME_KEY_covers_the_invocation_maximum(self, tmp_path, monkeypatch):
        """The maximum shapes the PARTITION (slots are split against the smaller of it and the spend
        bound), so a run under a different one is a different question — driven through the LANE, so the
        key is the one it really emits."""
        def _key(where, maximum, name):
            with pytest.MonkeyPatch.context() as mp:
                mp.setattr(sweep, "MAX_BATCH_WORDS", maximum)
                _submitted, run = self._scheduled(where, mp, words=[f"word{i:03d}" for i in range(9)],
                                                  run_name=name)
            starts = [json.loads(l) for l in (run.dir / "events.jsonl").read_text().splitlines()
                      if json.loads(l).get("event") == "tool_start"
                      and json.loads(l).get("source_id") == "enrich.a1d_brute"]
            assert len(starts) == 1, starts
            return starts[0]["work_unit"]

        wide = _key(tmp_path / "a", 25000, "wide")
        narrow = _key(tmp_path / "b", 3, "narrow")
        again = _key(tmp_path / "c", 25000, "again")
        assert wide != narrow, (wide, narrow)
        assert wide == again, (wide, again)

    def test_UNSCHEDULABLE_candidates_reach_the_A1d_verdict(self, tmp_path, monkeypatch):
        """A slot no bound can admit is neither a resumable remainder nor cap withholding, and the lane
        must say so rather than report a clean run."""
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 2)
        monkeypatch.setattr(sweep, "allocate", lambda words, *, cap: {"000": list(words)})
        _submitted, run = self._scheduled(tmp_path, monkeypatch,
                                          words=[f"word{i:03d}" for i in range(5)])
        recs = [r for r in run.tool_runs("enrich") if r.tool == "a1d"]
        assert len(recs) == 1, recs
        # v37#2: the WHOLE note, not a substring — the same loss was rendered twice and the unsubmitted
        # apex claimed "no reason recorded" beside the reason.
        assert recs[0].note == ("A1d did NOT run (5 candidate(s) in 1 slot(s) cannot be scheduled under "
                                "the current bounds and will NOT be retried; 1 apex brute(s) unsubmitted "
                                "(no candidate is schedulable under the current bounds))"), recs[0].note
        assert recs[0].note.count("cannot be scheduled") == 1, recs[0].note
        assert "can never be scheduled" not in recs[0].note, recs[0].note

    def test_the_RESUME_KEY_identifies_the_VOCABULARY_not_just_the_apexes(self, tmp_path, monkeypatch):
        """v37#1: two entirely different corpora over the same apexes emitted the SAME work unit, so a
        resume check could not tell them apart."""
        def _key(where, words, name):
            with pytest.MonkeyPatch.context() as mp:
                _submitted, run = self._scheduled(where, mp, words=words, run_name=name)
            starts = [json.loads(l) for l in (run.dir / "events.jsonl").read_text().splitlines()
                      if json.loads(l).get("event") == "tool_start"
                      and json.loads(l).get("source_id") == "enrich.a1d_brute"]
            assert len(starts) == 1, starts
            return starts[0]["work_unit"]

        one = _key(tmp_path / "a", [f"alpha{i:03d}" for i in range(9)], "one")
        two = _key(tmp_path / "b", [f"bravo{i:03d}" for i in range(9)], "two")
        again = _key(tmp_path / "c", [f"alpha{i:03d}" for i in range(9)], "again")
        assert one != two, (one, two)
        assert one == again, (one, again)

    def test_the_TERMINAL_counts_failures_in_BOTH_currencies(self, tmp_path, monkeypatch):
        """With batching, ten failed slots may be one failed call or ten — the slot map alone cannot say."""
        from quarry_recon import store
        from quarry_recon.phases import enrich, probe, vertical
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            wl = run.dir / "raw" / "crawl" / "xnLinkFinder"
            wl.mkdir(parents=True, exist_ok=True)
            (wl / "js_wordlist.txt").write_text("\n".join(f"word{i:03d}" for i in range(4)))
            from quarry_recon.runner import RunResult as _RR
            monkeypatch.setattr(enrich, "have", lambda t: True)
            monkeypatch.setattr(vertical, "have", lambda t: False)
            monkeypatch.setattr(vertical, "_wordlist", lambda c: None)
            monkeypatch.setattr(probe, "_vhost_wordlist", lambda: None)
            monkeypatch.setattr(vertical, "_resolvers", lambda c: (tmp_path / "r", tmp_path / "rt"))
            monkeypatch.setattr(enrich, "exec_tool",
                                lambda tool, cmd, raw_path=None, timeout=None, **k: _RR(
                                    tool, cmd, crawl.Status.FAILED, 1, 0.1, None, 0))
            ctx = _Ctx(run.dir, [])
            ctx.run = run
            ctx.scope = self._S()
            ctx.scope.passive_only = False
            ctx.scope.is_oos = lambda h: False
            ctx.profile = type("P", (), {"apex_domains": ["acme.com"], "http_rl": 0, "dns_rate": 0})()
            enrich._a1d_recursive_brute(ctx)
            fins = [json.loads(l) for l in (run.dir / "events.jsonl").read_text().splitlines()
                    if json.loads(l).get("event") == "tool_finish"
                    and json.loads(l).get("source_id") == "enrich.a1d_brute"]
            assert len(fins) == 1 and fins[0]["status"] == "failed", fins
            assert "in 1 invocation(s) {'failed': 1}" in fins[0]["reason"], fins[0]["reason"]
            assert "slot outcomes {'failed': 4}" in fins[0]["reason"], fins[0]["reason"]
        finally:
            events.reset()

    def test_an_ordinary_MACHINERY_error_is_never_hidden_by_its_wording(self, tmp_path, monkeypatch):
        """v38: unschedulable work used to be recognised by matching English in the machinery list, so an
        unrelated failure carrying the same phrase would have been filtered out of the verdict."""
        from quarry_recon.phases import enrich
        real = enrich._a1d_sweep

        def sweeping(*a, **k):
            out = real(*a, **k)
            out.machinery.append("puredns can never be scheduled by this host's cgroup")
            return out

        monkeypatch.setattr(enrich, "_a1d_sweep", sweeping)
        _submitted, run = self._scheduled(tmp_path, monkeypatch,
                                          words=[f"word{i:03d}" for i in range(9)])
        recs = [r for r in run.tool_runs("enrich") if r.tool == "a1d"]
        assert len(recs) == 1 and "cgroup" in recs[0].note, recs

    def test_UNSCHEDULABLE_work_alone_still_DEGRADES_the_terminal(self, tmp_path, monkeypatch):
        """The counter drives it, not a machinery sentence: nothing ran, so the source is not clean."""
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 2)
        monkeypatch.setattr(sweep, "allocate", lambda words, *, cap: {"000": list(words)})
        _submitted, run = self._scheduled(tmp_path, monkeypatch,
                                          words=[f"word{i:03d}" for i in range(5)])
        fins = [json.loads(l) for l in (run.dir / "events.jsonl").read_text().splitlines()
                if json.loads(l).get("event") == "tool_finish"
                and json.loads(l).get("source_id") == "enrich.a1d_brute"]
        assert len(fins) == 1 and fins[0]["status"] == "failed", fins
        assert fins[0]["reason"] == ("5 candidate(s) in 1 slot(s) cannot be scheduled under the current "
                                     "bounds"), fins[0]["reason"]

    def test_UNSCHEDULABLE_work_does_not_SUPPRESS_the_returned_classes(self, tmp_path, monkeypatch):
        """v39#1: the terminal checked unschedulable work first and returned only that sentence, so the
        slot and invocation class maps it promises vanished. The facts are orthogonal."""
        from quarry_recon import store
        from quarry_recon.phases import enrich, probe, vertical
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            wl = run.dir / "raw" / "crawl" / "xnLinkFinder"
            wl.mkdir(parents=True, exist_ok=True)
            (wl / "js_wordlist.txt").write_text("\n".join(f"word{i:03d}" for i in range(7)))
            real = sweep.allocate
            # three candidates in a slot nothing can admit, the rest schedulable
            monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 4)
            monkeypatch.setattr(sweep, "allocate",
                                lambda words, *, cap: {"000": sorted(words)[:5],
                                                       **real(sorted(words)[5:], cap=cap)})
            from quarry_recon.runner import RunResult as _RR
            monkeypatch.setattr(enrich, "have", lambda t: True)
            monkeypatch.setattr(vertical, "have", lambda t: False)
            monkeypatch.setattr(vertical, "_wordlist", lambda c: None)
            monkeypatch.setattr(probe, "_vhost_wordlist", lambda: None)
            monkeypatch.setattr(vertical, "_resolvers", lambda c: (tmp_path / "r", tmp_path / "rt"))
            monkeypatch.setattr(enrich, "exec_tool",
                                lambda tool, cmd, raw_path=None, timeout=None, **k: _RR(
                                    tool, cmd, crawl.Status.FAILED, 1, 0.1, None, 0))
            ctx = _Ctx(run.dir, [])
            ctx.run = run
            ctx.scope = self._S()
            ctx.scope.passive_only = False
            ctx.scope.is_oos = lambda h: False
            ctx.profile = type("P", (), {"apex_domains": ["acme.com"], "http_rl": 0, "dns_rate": 0})()
            enrich._a1d_recursive_brute(ctx)
            fins = [json.loads(l) for l in (run.dir / "events.jsonl").read_text().splitlines()
                    if json.loads(l).get("event") == "tool_finish"
                    and json.loads(l).get("source_id") == "enrich.a1d_brute"]
            assert len(fins) == 1 and fins[0]["status"] == "failed", fins
            reason = fins[0]["reason"]
            assert "slot outcomes" in reason and "invocation(s)" in reason, reason
            assert "5 candidate(s) in 1 slot(s) cannot be scheduled" in reason, reason
        finally:
            events.reset()

    @pytest.mark.parametrize("mode,want_status,want_head", [
        ("contended", "failed", "another lifecycle"),
        ("dependency", "skipped", "not installed"),
    ])
    def test_an_EARLY_terminal_path_still_carries_the_unschedulable_fact(self, tmp_path, monkeypatch,
                                                                        mode, want_status, want_head):
        """v40: contention and a pre-attempt dependency returned their own sentence and dropped the
        structured facts they coexisted with."""
        from quarry_recon import budget as _b, store
        from quarry_recon.phases import enrich, probe, vertical
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            wl = run.dir / "raw" / "crawl" / "xnLinkFinder"
            wl.mkdir(parents=True, exist_ok=True)
            (wl / "js_wordlist.txt").write_text("\n".join(f"word{i:03d}" for i in range(5)))
            monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 2)
            # one slot nothing can admit, one the lane could have run — so the dependency and contention
            # paths are really reached (a wholly unschedulable workload short-circuits before both)
            monkeypatch.setattr(sweep, "allocate",
                                lambda words, *, cap: {"000": sorted(words)[:3], "001": sorted(words)[3:]})
            from quarry_recon.runner import RunResult as _RR
            monkeypatch.setattr(enrich, "have", lambda t: mode != "dependency")
            monkeypatch.setattr(vertical, "have", lambda t: False)
            monkeypatch.setattr(vertical, "_wordlist", lambda c: None)
            monkeypatch.setattr(probe, "_vhost_wordlist", lambda: None)
            monkeypatch.setattr(vertical, "_resolvers", lambda c: (tmp_path / "r", tmp_path / "rt"))
            monkeypatch.setattr(enrich, "exec_tool",
                                lambda tool, cmd, raw_path=None, timeout=None, **k: _RR(
                                    tool, cmd, crawl.Status.EMPTY, 0, 0.1, None, 0))
            ctx = _Ctx(run.dir, [])
            ctx.run = run
            ctx.scope = self._S()
            ctx.scope.passive_only = False
            ctx.scope.is_oos = lambda h: False
            ctx.profile = type("P", (), {"apex_domains": ["acme.com"], "http_rl": 0, "dns_rate": 0})()
            sched = (pathlib.Path(run.project_dir) / "recon" / "state" / "sched" / f"v{sweep.SCHEMA}")
            sched.mkdir(parents=True, exist_ok=True)
            if mode == "contended":
                with _b.state_lock(sched / "a1d_brute.lock"):
                    enrich._a1d_recursive_brute(ctx)
            else:
                enrich._a1d_recursive_brute(ctx)
            fins = [json.loads(l) for l in (run.dir / "events.jsonl").read_text().splitlines()
                    if json.loads(l).get("event") == "tool_finish"
                    and json.loads(l).get("source_id") == "enrich.a1d_brute"]
            assert len(fins) == 1 and fins[0]["status"] == want_status, fins
            reason = fins[0]["reason"]
            assert want_head in reason, reason                          # the STOP still leads
            assert "3 candidate(s) in 1 slot(s) cannot be scheduled" in reason, reason
        finally:
            events.reset()

    def test_a_tool_that_VANISHES_mid_sweep_is_not_a_clean_run(self, tmp_path, monkeypatch):
        """The dependency stop degrades the source even when every slot it DID reach came back clean:
        `slots_obtained` counts EMPTY, so without this the lane read EMPTY with no gap."""
        from quarry_recon import store
        from quarry_recon.phases import enrich, probe, vertical
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            wl = run.dir / "raw" / "crawl" / "xnLinkFinder"
            wl.mkdir(parents=True, exist_ok=True)
            (wl / "js_wordlist.txt").write_text("\n".join(f"word{i:03d}" for i in range(4)))
            monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 1)     # one slot per invocation
            from quarry_recon.runner import RunResult as _RR
            statuses = [crawl.Status.EMPTY, crawl.Status.SKIPPED]
            monkeypatch.setattr(enrich, "have", lambda t: True)
            monkeypatch.setattr(vertical, "have", lambda t: False)
            monkeypatch.setattr(vertical, "_wordlist", lambda c: None)
            monkeypatch.setattr(probe, "_vhost_wordlist", lambda: None)
            monkeypatch.setattr(vertical, "_resolvers", lambda c: (tmp_path / "r", tmp_path / "rt"))
            monkeypatch.setattr(enrich, "exec_tool",
                                lambda tool, cmd, raw_path=None, timeout=None, **k: _RR(
                                    tool, cmd, statuses.pop(0) if statuses else crawl.Status.SKIPPED,
                                    0, 0.1, None, 0))
            ctx = _Ctx(run.dir, [])
            ctx.run = run
            ctx.scope = self._S()
            ctx.scope.passive_only = False
            ctx.scope.is_oos = lambda h: False
            ctx.profile = type("P", (), {"apex_domains": ["acme.com"], "http_rl": 0, "dns_rate": 0})()
            enrich._a1d_recursive_brute(ctx)
            fins = [json.loads(l) for l in (run.dir / "events.jsonl").read_text().splitlines()
                    if json.loads(l).get("event") == "tool_finish"
                    and json.loads(l).get("source_id") == "enrich.a1d_brute"]
            assert len(fins) == 1, fins
            assert fins[0]["status"] == "failed", fins           # NOT empty: a slot never got a tool
            assert "the tool did not run" in fins[0]["reason"], fins
        finally:
            events.reset()

    @pytest.mark.parametrize("found,want", [(False, "empty"), (True, "success")])
    def test_a_CLEAN_terminal_carries_NO_reason_field(self, tmp_path, monkeypatch, found, want):
        """v41: the reason is joined from facts, and a clean run has none — an empty string is a field
        carrying no reason, where `None` is omitted entirely."""
        from quarry_recon import store
        from quarry_recon.phases import enrich, probe, vertical
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            wl = run.dir / "raw" / "crawl" / "xnLinkFinder"
            wl.mkdir(parents=True, exist_ok=True)
            (wl / "js_wordlist.txt").write_text("\n".join(f"word{i:03d}" for i in range(4)))
            from quarry_recon.runner import RunResult as _RR

            def _tool(tool, cmd, raw_path=None, timeout=None, **k):
                if found and raw_path is not None:
                    raw_path.write_text("word000.acme.com\n")
                return _RR(tool, cmd, crawl.Status.SUCCESS if found else crawl.Status.EMPTY,
                           0, 0.1, raw_path if found else None, 0)

            monkeypatch.setattr(enrich, "have", lambda t: True)
            monkeypatch.setattr(vertical, "have", lambda t: False)
            monkeypatch.setattr(vertical, "_wordlist", lambda c: None)
            monkeypatch.setattr(probe, "_vhost_wordlist", lambda: None)
            monkeypatch.setattr(vertical, "_resolvers", lambda c: (tmp_path / "r", tmp_path / "rt"))
            monkeypatch.setattr(enrich, "exec_tool", _tool)
            ctx = _Ctx(run.dir, [])
            ctx.run = run
            ctx.scope = self._S()
            ctx.scope.passive_only = False
            ctx.scope.is_oos = lambda h: False
            ctx.profile = type("P", (), {"apex_domains": ["acme.com"], "http_rl": 0, "dns_rate": 0})()
            enrich._a1d_recursive_brute(ctx)
            fins = [json.loads(l) for l in (run.dir / "events.jsonl").read_text().splitlines()
                    if json.loads(l).get("event") == "tool_finish"
                    and json.loads(l).get("source_id") == "enrich.a1d_brute"]
            assert len(fins) == 1 and fins[0]["status"] == want, fins
            assert "reason" not in fins[0], fins            # omitted, never an empty string
        finally:
            events.reset()


class TestTheWildcardDifferHasItsOwnLifecycle:
    """Step 4.3: until now `enrich.wildcard_a1d` and `vertical.wildcard_http` were coverage identities
    only — they emitted coverage under their id but never a start or a terminal, so a manifest could not
    tell a pass that never ran from one that ran and found nothing."""

    class _S:
        passive_only = False

        def in_scope(self, h):
            return h.endswith("acme.com")

        def is_oos(self, h):
            return False

    def _differ(self, tmp_path, monkeypatch, *, zones=("z.acme.com",), httpx=True, words=("api",),
                sid="enrich.wildcard_a1d", rows=None, caught=None, preload=(), st=None,
                status=None, raw=None, break_record=None, raw_bytes=None, run=None, statuses=None,
                no_artifact=False, no_write=False, guard=None, tool=None):
        from quarry_recon import store
        from quarry_recon.phases import probe, vertical
        fresh = run is None
        run = run or store.Run.create(tmp_path, "t")
        if fresh:
            events.reset()
        events.configure(run.dir)      # a REUSED run keeps writing to its own event log
        try:
            monkeypatch.setattr(vertical, "have", lambda t: httpx)
            monkeypatch.setattr(probe, "_vhost_wordlist", lambda: None)
            monkeypatch.setattr(vertical.netguard, "contact_state",
                                lambda host, block_private=False: (guard or "public",
                                                                   guard is not None, None))
            monkeypatch.setattr(vertical.netguard, "_block_private", lambda ctx: False)
            monkeypatch.setattr(vertical.netguard, "self_deny_list", lambda: "127.0.0.1")
            from quarry_recon.runner import RunResult as _RR

            seq = list(statuses or [])

            def _tool(tool, cmd, raw_path=None, timeout=None, **k):
                st_now = seq.pop(0) if seq else None
                if st_now is crawl.Status.SKIPPED:
                    return _RR(tool, cmd, st_now, None, 0.0, None, 0)   # no process ran
                if no_artifact:
                    return _RR(tool, cmd, crawl.Status.SUCCESS, 0, 0.1, None, 0)  # answered, no output
                if no_write:
                    # a timeout that produced NOTHING: the requested file is never written
                    return _RR(tool, cmd, status or crawl.Status.TIMED_OUT, None, 0.1, None, 0)
                if raw is not None and raw_path is not None:
                    cand = pathlib.Path(cmd[cmd.index("-l") + 1]).read_text().split()
                    # v44#6: the artifact is built from the REAL candidate list, so a baseline row matches
                    # the invocation's own random controls instead of a name it never submitted.
                    text = (raw(cand) if callable(raw) else raw)
                    blob = text.encode("utf-8") if isinstance(text, str) else text
                    if raw_bytes is not None:
                        blob = raw_bytes + blob            # an undecodable row IN FRONT of readable ones
                    raw_path.write_bytes(blob)
                    return _RR(tool, cmd, status or crawl.Status.SUCCESS, 0, 0.1, raw_path, 0)
                if status is not None:
                    return _RR(tool, cmd, status, 1, 0.1, None, 0)
                if rows is not None and raw_path is not None:
                    cand = pathlib.Path(cmd[cmd.index("-l") + 1]).read_text().split()
                    bogus = [c for c in cand if c.startswith("quarry-wc-")]
                    out = [json.dumps({"input": b, "status_code": 200, "content_length": 5,
                                       "title": "wc", "favicon": "x"}) for b in bogus]
                    out += [json.dumps(r) for r in rows]
                    raw_path.write_text("\n".join(out) + "\n")
                return _RR(tool, cmd, st_now or crawl.Status.SUCCESS, 0, 0.1, raw_path, 0)

            monkeypatch.setattr(vertical, "exec_tool", tool or _tool)
            ctx = _Ctx(run.dir, [])
            ctx.run = run
            ctx.scope = self._S()
            ctx.profile = type("P", (), {"apex_domains": ["acme.com"], "http_rl": 0, "dns_rate": 0})()
            for kind, row in preload:
                run.add(kind, row)
            self._last_run = run
            if break_record is not None:
                real_record = type(run).record

                def _boom(self, phase, result):
                    if result.tool == "wildcard-differ":
                        raise break_record
                    return real_record(self, phase, result)

                monkeypatch.setattr(type(run), "record", _boom, raising=False)
            kept = set()
            try:
                kept = vertical._wildcard_differentiate(ctx, set(zones), extra_words=list(words),
                                                        phase="enrich", label="wildcard-a1d",
                                                        source="wildcard-http-a1d", source_id=sid,
                                                        stats=st)
            except BaseException as e:      # `caught` lets a test inspect the LIFECYCLE of a raising run
                if caught is None:
                    raise
                caught.append(e)
            log = run.dir / "events.jsonl"
            evs = [json.loads(l) for l in log.read_text().splitlines()] if log.exists() else []
            self._events = evs
            return kept, [e for e in evs if e.get("event") in ("tool_start", "tool_finish")
                          and e.get("source_id") == sid]
        finally:
            if fresh:
                events.reset()

    def test_the_pass_emits_exactly_ONE_start_and_ONE_terminal(self, tmp_path, monkeypatch):
        kept, life = self._differ(tmp_path, monkeypatch, rows=[])
        assert [e["event"] for e in life] == ["tool_start", "tool_finish"], life
        assert life[0]["input_total"] == 1 and life[0]["work_unit"] == life[1]["work_unit"]

    def test_a_pass_that_found_a_VHOST_is_a_SUCCESS(self, tmp_path, monkeypatch):
        kept, life = self._differ(tmp_path, monkeypatch,
                                  rows=[{"input": "api.z.acme.com", "status_code": 200,
                                         "content_length": 99, "title": "real", "favicon": "y"}])
        assert kept == {"api.z.acme.com"}, kept
        assert life[-1]["status"] == "success" and life[-1]["produced"] == {"subdomains": 1}

    def test_a_pass_that_probed_and_found_NOTHING_is_EMPTY(self, tmp_path, monkeypatch):
        kept, life = self._differ(tmp_path, monkeypatch, rows=[])
        assert kept == set() and life[-1]["status"] == "empty", life

    def test_a_MISSING_httpx_is_a_SKIP_with_its_reason(self, tmp_path, monkeypatch):
        kept, life = self._differ(tmp_path, monkeypatch, httpx=False)
        assert life[-1]["status"] == "skipped" and "httpx" in life[-1]["reason"], life

    def test_NO_eligible_zone_is_a_clean_EMPTY(self, tmp_path, monkeypatch):
        kept, life = self._differ(tmp_path, monkeypatch, zones=("z.example.org",))
        assert life[-1]["status"] == "empty" and life[0]["input_total"] == 0, life

    def test_NO_usable_vocabulary_is_a_SKIP(self, tmp_path, monkeypatch):
        kept, life = self._differ(tmp_path, monkeypatch, words=())
        assert life[-1]["status"] == "skipped" and "vocabulary" in life[-1]["reason"], life

    def test_a_DISABLED_lane_runs_nothing_and_CLAIMS_nothing(self, tmp_path, monkeypatch):
        from quarry_recon.phases import vertical
        monkeypatch.setattr(vertical, "registered", lambda sid: False)
        kept, life = self._differ(tmp_path, monkeypatch, rows=[])
        assert kept == set() and life == [], life

    def test_a_RAISING_pass_still_closes_its_lifecycle(self, tmp_path, monkeypatch):
        from quarry_recon.phases import vertical
        monkeypatch.setattr(vertical, "_wc_differentiate",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("differ exploded")))
        kept, life = self._differ(tmp_path, monkeypatch, rows=[])
        assert [e["event"] for e in life] == ["tool_start", "tool_finish"], life
        assert life[-1]["status"] == "failed" and "differ exploded" in life[-1]["reason"], life

    def test_CANCELLATION_closes_the_lifecycle_before_propagating(self, tmp_path, monkeypatch):
        from quarry_recon.phases import vertical
        monkeypatch.setattr(vertical, "_wc_differentiate",
                            lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt("ctrl-c")))
        caught = []
        _kept, life = self._differ(tmp_path, monkeypatch, rows=[], caught=caught)
        assert caught and isinstance(caught[0], KeyboardInterrupt), caught
        assert [e["event"] for e in life] == ["tool_start", "tool_finish"], life
        assert life[-1]["status"] == "failed" and "CANCELLED" in life[-1]["reason"], life

    def test_a_cancelled_pass_that_ALREADY_found_hosts_is_PARTIAL(self, tmp_path, monkeypatch):
        from quarry_recon.phases import vertical
        real = vertical._wc_differentiate

        def half(*a, **k):
            k["kept"].add("api.z.acme.com")
            raise KeyboardInterrupt("ctrl-c")

        monkeypatch.setattr(vertical, "_wc_differentiate", half)
        caught = []
        _kept, life = self._differ(tmp_path, monkeypatch, rows=[], caught=caught)
        assert life[-1]["status"] == "partial" and "evidence KEPT" in life[-1]["reason"], life

    def test_the_TWO_lanes_keep_SEPARATE_lifecycles(self, tmp_path, monkeypatch):
        _k, life = self._differ(tmp_path, monkeypatch, rows=[], sid="vertical.wildcard_http")
        assert [e["source_id"] for e in life] == ["vertical.wildcard_http"] * 2, life

    def test_a_FAILED_lifecycle_reaches_the_manifest_VERDICT(self, tmp_path, monkeypatch):
        """v42#1: the manifest folds recorded RunResults, not lifecycle events, so a differ that exploded
        left the run reading `complete` with no failure and no gap."""
        from quarry_recon.phases import vertical
        monkeypatch.setattr(vertical, "_wc_differentiate",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("differ exploded")))
        kept, life = self._differ(tmp_path, monkeypatch, rows=[])
        assert life[-1]["status"] == "failed", life
        run = self._last_run
        summary = run._run_summary()
        assert summary["verdict"] != "complete", summary
        assert any("differ exploded" in (f.get("why") or "") for f in summary["failures"]), summary

    def test_an_ALREADY_KNOWN_host_still_counts_as_PRODUCTION(self, tmp_path, monkeypatch):
        """v42#2: `Run.add` answers "new entity", not "accepted observation" — a host another source had
        already found was differentiated here and reported as EMPTY with nothing produced."""
        rows = [{"input": "api.z.acme.com", "status_code": 200, "content_length": 99,
                 "title": "real", "favicon": "y"}]
        kept, life = self._differ(tmp_path, monkeypatch, rows=rows,
                                  preload=[("subdomain", {"host": "api.z.acme.com",
                                                          "sources": ["subfinder"]})])
        assert kept == {"api.z.acme.com"}, kept
        assert life[-1]["status"] == "success" and life[-1]["produced"] == {"subdomains": 1}, life

    def test_the_WORK_UNIT_binds_the_ORDERED_vocabulary_actually_submitted(self, tmp_path, monkeypatch):
        """v42#3: a set digest could not tell `["api", "admin"]` from its reverse, and a cap selects a
        PREFIX — so the two submit different names."""
        from quarry_recon.phases import vertical
        monkeypatch.setattr(vertical, "WILDCARD_WORD_CAP", 1)
        _k1, life1 = self._differ(tmp_path / "a", monkeypatch, rows=[], words=("api", "admin"))
        _k2, life2 = self._differ(tmp_path / "b", monkeypatch, rows=[], words=("admin", "api"))
        _k3, life3 = self._differ(tmp_path / "c", monkeypatch, rows=[], words=("api", "admin"))
        assert life1[0]["work_unit"] != life2[0]["work_unit"], (life1[0], life2[0])
        assert life1[0]["work_unit"] == life3[0]["work_unit"]
        # v50#3: with NO cap in the way the two orders submit the SAME file — `write_list` sorts and
        # deduplicates — so they are the same work, and the key says so. Order only decides WHICH words a
        # cap selects, and that difference is a difference in MEMBERS (above).
        monkeypatch.setattr(vertical, "WILDCARD_WORD_CAP", 5000)
        _k4, life4 = self._differ(tmp_path / "d", monkeypatch, rows=[], words=("api", "admin"))
        _k5, life5 = self._differ(tmp_path / "e", monkeypatch, rows=[], words=("admin", "api"))
        assert life4[0]["work_unit"] == life5[0]["work_unit"], (life4[0], life5[0])

    def test_a_REFUSED_lane_leaves_the_carrier_EMPTY(self, tmp_path, monkeypatch):
        """v42#4: eligibility was written before the gate, so a disabled lane made its caller report
        withheld words and undifferentiated zones for a pass that never existed."""
        from quarry_recon.phases import vertical
        monkeypatch.setattr(vertical, "registered", lambda sid: False)
        st = {}
        kept, life = self._differ(tmp_path, monkeypatch, rows=[], st=st)
        assert kept == set() and life == []
        assert st == {"eligible_zones": 0, "probed_zones": 0, "blocked_reason": "",
                      "selection_reason": "", "gate_reason": "", "eligibility_known": False,
                      "blocked": {"zone_cap": 0, "self_or_private": 0}}, st

    def test_a_SETUP_failure_still_emits_a_START_and_a_TERMINAL(self, tmp_path, monkeypatch):
        """v42#5: eligibility and the work unit were built before the protected interval, so a scope
        failure escaped without either event."""
        from quarry_recon.phases import vertical
        monkeypatch.setattr(vertical, "_wc_eligible_zones",
                            lambda ctx, zones: (_ for _ in ()).throw(TypeError("bad zone iterable")))
        kept, life = self._differ(tmp_path, monkeypatch, rows=[])
        assert [e["event"] for e in life] == ["tool_start", "tool_finish"], life
        assert life[-1]["status"] == "failed" and "bad zone iterable" in life[-1]["reason"], life

    def test_a_CAPPED_pass_is_NOT_a_failed_tool(self, tmp_path, monkeypatch):
        """v43#1: every degraded terminal recorded a synthetic failure, so a normal capped run reported
        `tools_failed=1` with nothing failed. The cap is an omission the coverage record already owns."""
        from quarry_recon.phases import vertical
        monkeypatch.setattr(vertical, "WILDCARD_ZONES_PER_RUN", 1)
        kept, life = self._differ(tmp_path, monkeypatch, rows=[],
                                  zones=("a.acme.com", "b.acme.com"))
        # v44#1: a CLEAN operator boundary is LIMITED — nothing went wrong, and the run behaved exactly
        # as configured. Not FAILED, and not a failed tool either.
        assert life[-1]["status"] == "limited" and "deferred to a later run by the 1-zone per-run allowance" in life[-1]["reason"], life
        summary = self._last_run._run_summary()
        assert summary.get("tools_failed", 0) == 0, summary
        assert not any(r.tool == "wildcard-differ" for r in self._last_run.tool_runs("enrich"))

    def test_a_MACHINERY_failure_is_still_recorded(self, tmp_path, monkeypatch):
        from quarry_recon.phases import vertical
        monkeypatch.setattr(vertical, "_wc_differentiate",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("differ exploded")))
        kept, life = self._differ(tmp_path, monkeypatch, rows=[])
        assert life[-1]["status"] == "failed"
        assert any(r.tool == "wildcard-differ" for r in self._last_run.tool_runs("enrich"))
        assert self._last_run._run_summary()["verdict"] != "complete"

    def test_a_FAILED_invocation_is_not_a_clean_EMPTY(self, tmp_path, monkeypatch):
        """v43#2: the terminal read "did we contact the zone", so a failed httpx left the source reporting
        a clean EMPTY over full zone coverage."""
        kept, life = self._differ(tmp_path, monkeypatch, status=crawl.Status.FAILED)
        assert life[-1]["status"] == "failed", life
        assert "zone outcomes {'failed': 1}" in life[-1]["reason"], life

    def test_a_TIMED_OUT_invocation_that_still_found_a_host_is_PARTIAL(self, tmp_path, monkeypatch):
        """v44#6: the old fixture hard-coded a bogus hostname that never matched the invocation's random
        controls, so it passed on `kept == set()` and proved nothing."""
        def raw(cands):
            bogus = [c for c in cands if c.startswith("quarry-wc-")]
            rows = [json.dumps({"input": b, "status_code": 200, "content_length": 5,
                                "title": "wc", "favicon": "x"}) for b in bogus]
            rows.append(json.dumps({"input": "api.z.acme.com", "status_code": 200,
                                    "content_length": 99, "title": "real", "favicon": "y"}))
            return "\n".join(rows)

        kept, life = self._differ(tmp_path, monkeypatch, status=crawl.Status.TIMED_OUT, raw=raw)
        assert kept == {"api.z.acme.com"}, kept          # the evidence a timed-out call still returned
        assert life[-1]["status"] == "partial", life
        assert "zone outcomes {'timed_out': 1}" in life[-1]["reason"], life

    def test_MALFORMED_output_is_a_PARSE_GAP_not_a_clean_answer(self, tmp_path, monkeypatch):
        """v43#3: unreadable rows were discarded silently, so a truncated artifact read EMPTY with full
        coverage."""
        def raw(cands):
            bogus = [c for c in cands if c.startswith("quarry-wc-")]
            return "\n".join([json.dumps({"input": bogus[0], "status_code": 200, "content_length": 5,
                                          "title": "wc", "favicon": "x"}),
                              '{"input": "api.z.acme.com", "status_code":',   # truncated
                              "[1, 2, 3]",                                    # not an object
                              json.dumps({"input": "api.z.acme.com", "status_code": "200"})])  # bad type

        kept, life = self._differ(tmp_path, monkeypatch, raw=raw)
        assert life[-1]["status"] == "failed", life
        assert "3 unparseable output row(s)" in life[-1]["reason"], life

    def test_the_RESOLVED_observation_does_not_depend_on_subdomain_NOVELTY(self, tmp_path, monkeypatch):
        """v43#4: the resolved write sat inside the new-subdomain branch, so a host another source had
        already found left `resolved` empty."""
        rows = [{"input": "api.z.acme.com", "status_code": 200, "content_length": 99,
                 "title": "real", "favicon": "y", "a": ["1.2.3.4"]}]
        kept, life = self._differ(tmp_path, monkeypatch, rows=rows,
                                  preload=[("subdomain", {"host": "api.z.acme.com",
                                                          "sources": ["subfinder"]})])
        resolved = list(self._last_run.read("resolved"))
        assert kept == {"api.z.acme.com"} and resolved, (kept, resolved)
        assert resolved[-1].get("a") == ["1.2.3.4"], resolved

    def test_an_UNRECORDABLE_outcome_propagates_instead_of_reading_CLEAN(self, tmp_path, monkeypatch):
        """v43#5: a generic terminal is not folded into the verdict, so a failure to record the outcome
        left the manifest `complete`."""
        from quarry_recon.phases import vertical
        monkeypatch.setattr(vertical, "_wc_differentiate",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("differ exploded")))
        caught = []
        kept, life = self._differ(tmp_path, monkeypatch, rows=[], caught=caught,
                                  break_record=OSError("read-only manifest"))
        assert life[-1]["status"] == "failed" and "could not be recorded" in life[-1]["reason"], life
        assert caught and isinstance(caught[0], RuntimeError), caught
        assert "read-only manifest" in str(caught[0]), caught

    def test_a_LIVE_candidate_survives_an_ABSENT_baseline(self, tmp_path, monkeypatch):
        """v44#4: the whole zone was discarded when the random controls did not respond — throwing away
        the very evidence this pass exists to find."""
        def raw(cands):
            return json.dumps({"input": "api.z.acme.com", "status_code": 200, "content_length": 99,
                               "title": "real", "favicon": "y"})

        kept, life = self._differ(tmp_path, monkeypatch, raw=raw)
        assert kept == {"api.z.acme.com"}, kept
        # nothing went WRONG — the controls simply did not answer — so the pass stays clean and says so
        assert life[-1]["status"] == "success", life
        assert "1 zone(s) answered with NO wildcard baseline" in life[-1]["reason"], life

    def test_an_UNDECODABLE_row_costs_ONE_row_not_the_artifact(self, tmp_path, monkeypatch):
        """v44#5: `read_text()` made one invalid UTF-8 byte abort the whole artifact as machinery."""
        def raw(cands):
            bogus = [c for c in cands if c.startswith("quarry-wc-")]
            return "\n".join([json.dumps({"input": b, "status_code": 200, "content_length": 5,
                                          "title": "wc", "favicon": "x"}) for b in bogus] +
                             [json.dumps({"input": "api.z.acme.com", "status_code": 200,
                                          "content_length": 99, "title": "real", "favicon": "y"})])

        kept, life = self._differ(tmp_path, monkeypatch, raw=raw, raw_bytes=b"\xff\xfe not utf-8\n")
        assert kept == {"api.z.acme.com"}, kept          # the readable rows still count
        assert life[-1]["status"] == "partial" and "1 unparseable output row(s)" in life[-1]["reason"]

    def test_a_row_for_a_name_we_never_SUBMITTED_is_not_our_evidence(self, tmp_path, monkeypatch):
        def raw(cands):
            bogus = [c for c in cands if c.startswith("quarry-wc-")]
            return "\n".join([json.dumps({"input": b, "status_code": 200, "content_length": 5,
                                          "title": "wc", "favicon": "x"}) for b in bogus] +
                             [json.dumps({"input": "evil.attacker.example", "status_code": 200,
                                          "content_length": 99, "title": "x", "favicon": "y"})])

        kept, life = self._differ(tmp_path, monkeypatch, raw=raw)
        assert kept == set(), kept
        assert "1 unparseable output row(s)" in life[-1]["reason"], life

    def test_OUTPUT_ROW_coverage_is_emitted_every_run(self, tmp_path, monkeypatch):
        """v44#2: parse loss reached only the generic terminal, which the manifest does not fold."""
        def raw(cands):
            bogus = [c for c in cands if c.startswith("quarry-wc-")]
            return "\n".join([json.dumps({"input": bogus[0], "status_code": 200, "content_length": 5,
                                          "title": "wc", "favicon": "x"}), "{oops"])

        kept, life = self._differ(tmp_path, monkeypatch, raw=raw)
        cov = [e for e in self._events if e.get("measure") == "output_rows"]
        assert cov and (cov[-1]["eligible"], cov[-1]["tested"], cov[-1]["omitted"]) == (2, 1, 1), cov
        assert cov[-1]["kind"] == "timeout", cov
        # ...and a CLEAN rerun in the SAME run supersedes it: coverage is latest-per-(source, unit), so
        # the reconciled rollup — not just the raw record — must stop reporting the gap (v45#5).
        run = self._last_run
        agg = {(a["source_id"], a["measure"]): a for a in run._run_summary()["coverage"]}
        assert agg[("enrich.wildcard_a1d", "output_rows")]["omitted"] == 1, agg
        _k2, _l2 = self._differ(tmp_path, monkeypatch, rows=[], run=run)
        agg2 = {(a["source_id"], a["measure"]): a for a in run._run_summary()["coverage"]}
        assert agg2[("enrich.wildcard_a1d", "output_rows")]["omitted"] == 0, agg2

    def test_a_FIRST_CALL_skip_contacts_nothing_at_all(self, tmp_path, monkeypatch):
        """v44#3: `probed_zones` advanced before the process could even start, so a SKIPPED invocation
        earned zone-coverage credit and told A1d the pass had run."""
        kept, life = self._differ(tmp_path, monkeypatch, status=crawl.Status.SKIPPED,
                                  zones=("a.acme.com", "b.acme.com"))
        assert life[-1]["status"] == "skipped", life          # nothing was contacted at all
        assert "httpx did not run" in life[-1]["reason"], life

    def test_a_TRUE_MID_RUN_skip_is_DEPENDENCY_LOSS_not_a_clean_limit(self, tmp_path, monkeypatch):
        """v45#1: one zone answered, then the tool stopped running. That is not policy bounding — the
        remainder went unprobed because httpx vanished, and the record must read as a gap."""
        kept, life = self._differ(tmp_path, monkeypatch, rows=[],
                                  zones=("a.acme.com", "b.acme.com"),
                                  statuses=[crawl.Status.SUCCESS, crawl.Status.SKIPPED])
        assert life[-1]["status"] == "failed", life           # trouble, and nothing was produced
        assert "httpx did not run" in life[-1]["reason"], life
        # v50#2: SELECTION says both zones were chosen (no cap withheld anything); EXECUTION is the gap
        sel = [e for e in self._events if e.get("measure") == "zones"][-1]
        assert sel["kind"] == "cap" and (sel["eligible"], sel["tested"]) == (2, 2), sel
        ex = [e for e in self._events if e.get("measure") == "zone_execution"][-1]
        assert ex["kind"] == "timeout" and (ex["eligible"], ex["tested"], ex["omitted"]) == (2, 1, 1), ex

    def test_a_row_with_NO_status_code_is_not_a_live_host(self, tmp_path, monkeypatch):
        """v45#2: the signature fields were all optional, so `{"input": "api.z.acme.com"}` was rescued as
        a live vhost on the strength of the name alone."""
        kept, life = self._differ(tmp_path, monkeypatch,
                                  raw=lambda cands: json.dumps({"input": "api.z.acme.com"}))
        assert kept == set(), kept
        assert "1 unparseable output row(s)" in life[-1]["reason"], life

    def test_a_STRUCTURED_favicon_is_a_parse_gap_not_a_crash(self, tmp_path, monkeypatch):
        """`favicon` enters `_sig`'s set, so a list there raised instead of costing one row."""
        def raw(cands):
            bogus = [c for c in cands if c.startswith("quarry-wc-")]
            return "\n".join([json.dumps({"input": bogus[0], "status_code": 200, "content_length": 5,
                                          "title": "wc", "favicon": "x"}),
                              json.dumps({"input": "api.z.acme.com", "status_code": 200,
                                          "content_length": 9, "title": "t", "favicon": [1, 2]}),
                              json.dumps({"input": "api.z.acme.com", "status_code": 200,
                                          "content_length": 9, "title": "t", "a": {"not": "a list"}})])

        kept, life = self._differ(tmp_path, monkeypatch, raw=raw)
        assert kept == set(), kept
        assert "2 unparseable output row(s)" in life[-1]["reason"], life

    def test_an_ANSWER_with_NO_artifact_is_a_gap_not_a_clean_empty(self, tmp_path, monkeypatch):
        """v45#4: a returned SUCCESS whose output file never appeared emitted a clean 0/0 row record."""
        kept, life = self._differ(tmp_path, monkeypatch, rows=[], no_artifact=True)
        assert life[-1]["status"] == "failed", life
        assert "1 invocation(s) produced no artifact" in life[-1]["reason"], life

    def test_the_PARSER_SCHEMA_is_part_of_the_work_unit(self, tmp_path, monkeypatch):
        """v45#3: per-line decoding, foreign-row rejection and baseline-less rescue all changed what the
        same artifact MEANS, so the identity has to change with them."""
        from quarry_recon.phases import vertical
        assert vertical.WC_PARSER_SCHEMA == 2
        _k1, life1 = self._differ(tmp_path / "a", monkeypatch, rows=[])
        monkeypatch.setattr(vertical, "WC_PARSER_SCHEMA", 3)
        _k2, life2 = self._differ(tmp_path / "b", monkeypatch, rows=[])
        assert life1[0]["work_unit"] != life2[0]["work_unit"], (life1[0], life2[0])

    def test_a_MISSING_artifact_gates_the_manifest_VERDICT(self, tmp_path, monkeypatch):
        """v46#1: the terminal said FAILED while the recorded invocation stayed SUCCESS and every
        coverage record said `omitted=0`, so the run reconciled as complete."""
        kept, life = self._differ(tmp_path, monkeypatch, rows=[], no_artifact=True)
        assert life[-1]["status"] == "failed", life
        summary = self._last_run._run_summary()
        assert summary["verdict"] != "complete", summary
        agg = {(a["source_id"], a["measure"]): a for a in summary["coverage"]}
        art = agg[("enrich.wildcard_a1d", "output_artifacts")]
        assert (art["eligible"], art["tested"], art["omitted"]) == (1, 0, 1), art
        # ...and a later clean pass in the SAME run clears it
        _k2, _l2 = self._differ(tmp_path, monkeypatch, rows=[], run=self._last_run)
        agg2 = {(a["source_id"], a["measure"]): a for a in self._last_run._run_summary()["coverage"]}
        assert agg2[("enrich.wildcard_a1d", "output_artifacts")]["omitted"] == 0, agg2

    @pytest.mark.parametrize("row,why", [
        ({"status_code": -1, "content_length": 9, "title": "t"}, "an impossible status code"),
        ({"status_code": 999, "content_length": 9, "title": "t"}, "a status outside the HTTP range"),
        ({"status_code": 200, "content_length": -5, "title": "t"}, "a negative body length"),
        ({"status_code": 200, "content_length": 9, "favicon": True}, "a bool favicon"),
        ({"status_code": 200, "content_length": 9, "a": ["not-an-ip"]}, "an address that is not one"),
    ])
    def test_a_row_whose_VALUES_are_impossible_is_not_evidence(self, tmp_path, monkeypatch, row, why):
        """v46#2: types were checked, values were not — `status_code=-1` and `a=["not-an-ip"]` became a
        successful host and a persisted resolution."""
        def raw(cands):
            bogus = [c for c in cands if c.startswith("quarry-wc-")]
            return "\n".join([json.dumps({"input": bogus[0], "status_code": 200, "content_length": 5,
                                          "title": "wc", "favicon": "x"}),
                              json.dumps({"input": "api.z.acme.com", **row})])

        kept, life = self._differ(tmp_path, monkeypatch, raw=raw)
        assert kept == set(), (why, kept)
        assert "1 unparseable output row(s)" in life[-1]["reason"], (why, life)
        assert list(self._last_run.read("resolved")) == [], why

    def test_the_JSON_CONSTANT_hook_refuses_them_by_itself(self):
        """Defence in depth: no field accepts a float today, so the hook is not observable through the
        lane — it is tested directly rather than left unproven."""
        from quarry_recon.phases import vertical
        for token in ("NaN", "Infinity", "-Infinity"):
            with pytest.raises(ValueError):
                vertical._wc_reject_constant(token)

    def test_NON_STANDARD_json_constants_are_refused(self, tmp_path, monkeypatch):
        """`NaN` and `Infinity` are not JSON. v47#3: the constant has to sit in a field the validator
        IGNORES — otherwise the field check kills the row anyway and the hook proves nothing. Here the
        row is valid and distinct, so without the hook it becomes host evidence."""
        def raw(cands):
            bogus = [c for c in cands if c.startswith("quarry-wc-")]
            return "\n".join([json.dumps({"input": bogus[0], "status_code": 200, "content_length": 5,
                                          "title": "wc", "favicon": "x"}),
                              '{"input": "api.z.acme.com", "status_code": 200, "content_length": 99, '
                              '"title": "real", "favicon": "y", "response_time": NaN}'])

        kept, life = self._differ(tmp_path, monkeypatch, raw=raw)
        assert kept == set(), kept                 # WITHOUT the hook this row is a live host
        assert "1 unparseable output row(s)" in life[-1]["reason"], life

    def test_a_PACKED_INT_is_not_an_address(self, tmp_path, monkeypatch):
        """v47#1: `ipaddress.ip_address` accepts an int (and a bool) as a packed IPv4 value, so `a: [1]`
        parsed and was stored verbatim."""
        def raw(cands):
            bogus = [c for c in cands if c.startswith("quarry-wc-")]
            return "\n".join([json.dumps({"input": bogus[0], "status_code": 200, "content_length": 5,
                                          "title": "wc", "favicon": "x"}),
                              json.dumps({"input": "api.z.acme.com", "status_code": 200,
                                          "content_length": 99, "title": "real", "a": [1]})])

        kept, life = self._differ(tmp_path, monkeypatch, raw=raw)
        assert kept == set() and list(self._last_run.read("resolved")) == [], kept
        assert "1 unparseable output row(s)" in life[-1]["reason"], life

    def test_an_ADDRESS_is_stored_CANONICALLY(self, tmp_path, monkeypatch):
        rows = [{"input": "api.z.acme.com", "status_code": 200, "content_length": 99,
                 "title": "real", "favicon": "y", "a": ["01.2.3.004"]}]
        kept, life = self._differ(tmp_path, monkeypatch, rows=rows)
        # a leading-zero octet is not a valid IPv4 string in Python's strict parser: a parse gap, not a
        # silently "fixed" address
        assert kept == set(), kept
        rows = [{"input": "api.z.acme.com", "status_code": 200, "content_length": 99,
                 "title": "real", "favicon": "y", "a": ["1.2.3.4"]}]
        kept, life = self._differ(tmp_path / "ok", monkeypatch, rows=rows)
        assert kept == {"api.z.acme.com"}
        assert list(self._last_run.read("resolved"))[-1]["a"] == ["1.2.3.4"]

    def test_a_FAILED_invocation_with_no_artifact_is_COUNTABLE_coverage(self, tmp_path, monkeypatch):
        """v47#2: `omitted > eligible` made reconciliation drop the measure as invalid and report 0/0/0
        beside a reason that said one artifact was missing."""
        kept, life = self._differ(tmp_path, monkeypatch, status=crawl.Status.FAILED)
        agg = {(a["source_id"], a["measure"]): a
               for a in self._last_run._run_summary()["coverage"]}
        art = agg[("enrich.wildcard_a1d", "output_artifacts")]
        assert (art["eligible"], art["tested"], art["omitted"]) == (1, 0, 1), art
        assert art["valid"] is True, art

    def test_a_CLEAN_EMPTY_invocation_is_not_a_missing_artifact(self, tmp_path, monkeypatch):
        """v48#1: `RunResult.raw_path` means "captured non-empty stdout", not "the requested file
        exists". `runner.run` writes the file and returns None for a clean EMPTY, so every legitimate
        zero-result httpx call was being reported as a missing artifact."""
        from quarry_recon.runner import RunResult as _RR
        from quarry_recon.phases import probe, vertical
        from quarry_recon import store
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            monkeypatch.setattr(vertical, "have", lambda t: True)
            monkeypatch.setattr(probe, "_vhost_wordlist", lambda: None)
            monkeypatch.setattr(vertical.netguard, "contact_state",
                                lambda host, block_private=False: ("public", False, None))
            monkeypatch.setattr(vertical.netguard, "_block_private", lambda ctx: False)
            monkeypatch.setattr(vertical.netguard, "self_deny_list", lambda: "127.0.0.1")

            def _tool(tool, cmd, raw_path=None, timeout=None, **k):
                raw_path.write_text("")                     # the file EXISTS and is empty, as httpx left it
                return _RR(tool, cmd, crawl.Status.EMPTY, 0, 0.1, None, 0)   # ...and stdout was empty

            monkeypatch.setattr(vertical, "exec_tool", _tool)
            ctx = _Ctx(run.dir, [])
            ctx.run = run
            ctx.scope = self._S()
            ctx.profile = type("P", (), {"apex_domains": ["acme.com"], "http_rl": 0, "dns_rate": 0})()
            vertical._wildcard_differentiate(ctx, {"z.acme.com"}, extra_words=["api"], phase="enrich",
                                             label="wildcard-a1d", source="wildcard-http-a1d",
                                             source_id="enrich.wildcard_a1d")
            evs = [json.loads(l) for l in (run.dir / "events.jsonl").read_text().splitlines()]
            fin = [e for e in evs if e.get("event") == "tool_finish"][-1]
            assert fin["status"] == "empty", fin            # a clean nothing-found, not a failure
            art = [e for e in evs if e.get("measure") == "output_artifacts"][-1]
            assert (art["eligible"], art["tested"], art["omitted"]) == (1, 1, 0), art
            assert "returned invocation(s)" in art["reason"], art
        finally:
            events.reset()

    def test_a_RETRY_can_never_ingest_a_PREVIOUS_attempt_s_artifact(self, tmp_path, monkeypatch):
        """v49#1: the requested path was stable per zone, so a timed-out retry that wrote nothing re-read
        the earlier attempt's file and reported its findings as its own."""
        rows = [{"input": "api.z.acme.com", "status_code": 200, "content_length": 99,
                 "title": "real", "favicon": "y"}]
        kept1, life1 = self._differ(tmp_path, monkeypatch, rows=rows)
        assert kept1 == {"api.z.acme.com"} and life1[-1]["produced"] == {"subdomains": 1}
        kept2, life2 = self._differ(tmp_path, monkeypatch, rows=rows, no_write=True,
                                    run=self._last_run)
        assert kept2 == set(), kept2                       # nothing was written, so nothing is ingested
        assert life2[-1]["produced"] == {"subdomains": 0}, life2
        assert life2[-1]["status"] == "failed", life2
        art = [e for e in self._events if e.get("measure") == "output_artifacts"][-1]
        assert (art["eligible"], art["tested"], art["omitted"]) == (1, 0, 1), art

    def test_two_invocations_of_one_ZONE_keep_SEPARATE_artifacts(self, tmp_path, monkeypatch):
        rows = [{"input": "api.z.acme.com", "status_code": 200, "content_length": 99,
                 "title": "real", "favicon": "y"}]
        self._differ(tmp_path, monkeypatch, rows=rows)
        run = self._last_run
        self._differ(tmp_path, monkeypatch, rows=rows, run=run)
        arts = sorted((run.dir / "raw" / "enrich" / "wildcard-a1d").glob("z.acme.com-*.jsonl"))
        assert len(arts) == 2, arts                        # one per invocation, never overwritten

    def test_an_UNREADABLE_artifact_is_NOT_a_missing_one(self, tmp_path, monkeypatch):
        """v49#2: PermissionError and FileNotFoundError were both "produced none"."""
        real = pathlib.Path.read_bytes
        monkeypatch.setattr(pathlib.Path, "read_bytes",
                            lambda self, *a, **k: (_ for _ in ()).throw(PermissionError("denied"))
                            if self.suffix == ".jsonl" else real(self, *a, **k))
        kept, life = self._differ(tmp_path, monkeypatch, rows=[])
        assert life[-1]["status"] == "failed", life
        assert "1 artifact(s) present and UNREADABLE (z.acme.com: PermissionError)" in life[-1]["reason"]
        art = [e for e in self._events if e.get("measure") == "output_artifacts"][-1]
        assert (art["eligible"], art["tested"], art["omitted"]) == (1, 0, 1), art
        assert "0 produced none, 1 unreadable" in art["reason"], art

    def test_a_CAPPED_zone_is_not_relabelled_by_an_execution_gap(self, tmp_path, monkeypatch):
        """v50#2: one record carried both questions, so a parse error in the zone we DID probe turned the
        policy-capped remainder into a timeout."""
        from quarry_recon.phases import vertical
        monkeypatch.setattr(vertical, "WILDCARD_ZONES_PER_RUN", 1)

        def raw(cands):
            bogus = [c for c in cands if c.startswith("quarry-wc-")]
            return "\n".join([json.dumps({"input": bogus[0], "status_code": 200, "content_length": 5,
                                          "title": "wc", "favicon": "x"}), "{oops"])

        kept, life = self._differ(tmp_path, monkeypatch, raw=raw,
                                  zones=("a.acme.com", "b.acme.com"))
        sel = [e for e in self._events if e.get("measure") == "zones"][-1]
        assert sel["kind"] == "cap" and (sel["eligible"], sel["tested"], sel["omitted"]) == (2, 1, 1), sel
        assert "deferred to a later run by the 1-zone per-run allowance" in sel["reason"], sel
        # v51#2: EXECUTION is complete — the one selected zone returned — so it is NOT timeout-class.
        # The parse loss lives in its own measure.
        ex = [e for e in self._events if e.get("measure") == "zone_execution"][-1]
        assert ex["kind"] == "cap" and (ex["eligible"], ex["tested"], ex["omitted"]) == (1, 1, 0), ex
        rows = [e for e in self._events if e.get("measure") == "output_rows"][-1]
        assert rows["omitted"] == 1, rows

    def test_a_GUARD_refusal_is_a_SELECTION_fact_not_an_execution_one(self, tmp_path, monkeypatch):
        kept, life = self._differ(tmp_path, monkeypatch, rows=[], guard="self")
        sel = [e for e in self._events if e.get("measure") == "zones"][-1]
        assert (sel["eligible"], sel["tested"], sel["omitted"]) == (1, 0, 1), sel
        assert sel["kind"] == "cap" and "contact guard" in sel["reason"], sel
        ex = [e for e in self._events if e.get("measure") == "zone_execution"][-1]
        assert (ex["eligible"], ex["tested"], ex["omitted"]) == (0, 0, 0), ex

    def test_the_INVOCATION_PAIR_is_kept_whole(self, tmp_path, monkeypatch):
        """v50#1: only the output carried a token, so a retry overwrote the exact contacted set — random
        baselines included — that the earlier recorded command still points at."""
        rows = [{"input": "api.z.acme.com", "status_code": 200, "content_length": 99,
                 "title": "real", "favicon": "y"}]
        self._differ(tmp_path, monkeypatch, rows=rows)
        run = self._last_run
        self._differ(tmp_path, monkeypatch, rows=rows, run=run)
        cands = sorted((run.dir / "work").glob("wildcard-a1d_cand_z_acme_com_*.txt"))
        arts = sorted((run.dir / "raw" / "enrich" / "wildcard-a1d").glob("z.acme.com-*.jsonl"))
        assert len(cands) == 2 and len(arts) == 2, (cands, arts)
        # the pair shares ONE token, so an artifact can always be traced to the exact list it probed
        assert {c.stem.rsplit("_", 1)[-1] for c in cands} == {a.stem.rsplit("-", 1)[-1] for a in arts}

    def test_a_HARD_GATE_keeps_the_SELECTION_cap_and_the_EXECUTION_gap_apart(self, tmp_path,
                                                                            monkeypatch):
        """v51#1: a run capped to one zone AND missing httpx reported the whole eligible set as a
        timeout, losing the clean one-zone selection."""
        from quarry_recon.phases import vertical
        monkeypatch.setattr(vertical, "WILDCARD_ZONES_PER_RUN", 1)
        kept, life = self._differ(tmp_path, monkeypatch, httpx=False,
                                  zones=("a.acme.com", "b.acme.com"))
        sel = [e for e in self._events if e.get("measure") == "zones"][-1]
        assert sel["kind"] == "cap" and (sel["eligible"], sel["tested"], sel["omitted"]) == (2, 1, 1), sel
        ex = [e for e in self._events if e.get("measure") == "zone_execution"][-1]
        assert ex["kind"] == "timeout" and (ex["eligible"], ex["tested"], ex["omitted"]) == (1, 0, 1), ex
        assert "httpx is not installed" in ex["reason"], ex

    def test_NO_eligible_zone_reports_a_clean_ZERO_on_both_measures(self, tmp_path, monkeypatch):
        kept, life = self._differ(tmp_path, monkeypatch, zones=("z.example.org",))
        for measure in ("zones", "zone_execution"):
            rec = [e for e in self._events if e.get("measure") == measure][-1]
            assert (rec["eligible"], rec["tested"], rec["omitted"]) == (0, 0, 0), rec
            assert rec["kind"] == "cap", rec

    def test_SELECTION_and_EXECUTION_carry_their_OWN_causes(self, tmp_path, monkeypatch):
        """v52#1: one reason was appended to both, so the CAP's omitted zone claimed httpx caused it."""
        from quarry_recon.phases import vertical
        monkeypatch.setattr(vertical, "WILDCARD_ZONES_PER_RUN", 1)
        kept, life = self._differ(tmp_path, monkeypatch, httpx=False,
                                  zones=("a.acme.com", "b.acme.com"))
        sel = [e for e in self._events if e.get("measure") == "zones"][-1]
        assert "deferred to a later run by the 1-zone per-run allowance" in sel["reason"], sel
        assert "httpx" not in sel["reason"], sel
        ex = [e for e in self._events if e.get("measure") == "zone_execution"][-1]
        assert "httpx is not installed" in ex["reason"], ex
        assert "zone cap" not in ex["reason"], ex

    def test_a_GUARD_refusal_is_a_SELECTION_cause(self, tmp_path, monkeypatch):
        kept, life = self._differ(tmp_path, monkeypatch, rows=[], guard="self")
        sel = [e for e in self._events if e.get("measure") == "zones"][-1]
        assert "contact guard" in sel["reason"] and sel["omitted"] == 1, sel
        ex = [e for e in self._events if e.get("measure") == "zone_execution"][-1]
        assert "contact guard" not in ex["reason"], ex

    @pytest.mark.parametrize("boom,want", [(OSError("differ exploded"), "failed"),
                                           (KeyboardInterrupt("ctrl-c"), "failed")])
    def test_an_EXCEPTIONAL_exit_still_reports_every_record(self, tmp_path, monkeypatch, boom, want):
        """v52#2: an exception or a cancellation jumped past the body's reporting tail, so selection and
        execution accounting disappeared even though the machinery failure kept the verdict honest."""
        from quarry_recon.phases import vertical

        def explode(*a, **k):
            k["st"]["probed_zones"] = 0
            raise boom

        monkeypatch.setattr(vertical, "_wc_differentiate", explode)
        caught = []
        kept, life = self._differ(tmp_path, monkeypatch, rows=[], caught=caught,
                                  zones=("a.acme.com", "b.acme.com"))
        assert life[-1]["status"] == want, life
        sel = [e for e in self._events if e.get("measure") == "zones"][-1]
        ex = [e for e in self._events if e.get("measure") == "zone_execution"][-1]
        assert (sel["eligible"], sel["tested"]) == (2, 2), sel
        assert (ex["eligible"], ex["tested"], ex["omitted"]) == (2, 0, 2), ex
        assert ex["kind"] == "timeout", ex
        for measure in ("output_rows", "output_artifacts"):
            assert [e for e in self._events if e.get("measure") == measure], measure

    def test_a_REPORTING_failure_is_MACHINERY_not_a_clean_run(self, tmp_path, monkeypatch):
        """v53#1: a lane that reported NOTHING still finished EMPTY with no reason and a complete
        verdict — losing the accounting is machinery, not a footnote."""
        from quarry_recon.phases import vertical
        monkeypatch.setattr(vertical, "_wc_report",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("event log gone")))
        kept, life = self._differ(tmp_path, monkeypatch, rows=[])
        assert life[-1]["status"] == "failed", life
        assert "coverage could not be reported (OSError: event log gone)" in life[-1]["reason"], life
        summary = self._last_run._run_summary()
        assert summary["verdict"] != "complete", summary
        assert any(r.tool == "wildcard-differ" for r in self._last_run.tool_runs("enrich"))

    def test_a_RETURNED_invocation_is_counted_before_the_ledger_write(self, tmp_path, monkeypatch):
        """v53#2: `record()` raising left `zone_execution` claiming the call never came back."""
        from quarry_recon.phases import vertical
        from quarry_recon import store
        real = store.Run.record

        def _boom(self, phase, result):
            if result.tool == "httpx":
                raise OSError("manifest is read-only")
            return real(self, phase, result)

        monkeypatch.setattr(store.Run, "record", _boom, raising=False)
        kept, life = self._differ(tmp_path, monkeypatch, rows=[])
        ex = [e for e in self._events if e.get("measure") == "zone_execution"][-1]
        assert (ex["eligible"], ex["tested"], ex["omitted"]) == (1, 1, 0), ex
        assert life[-1]["status"] == "failed" and "read-only" in life[-1]["reason"], life

    def test_a_SETUP_failure_keeps_the_zone_CAP_in_the_denominator(self, tmp_path, monkeypatch):
        """v53#3: the cap was only set inside the body, so a setup failure reported every eligible zone
        as selected."""
        from quarry_recon.phases import vertical
        monkeypatch.setattr(vertical, "WILDCARD_ZONES_PER_RUN", 1)
        monkeypatch.setattr(vertical, "_wc_vocabulary",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("wordlist vanished")))
        kept, life = self._differ(tmp_path, monkeypatch, rows=[],
                                  zones=("a.acme.com", "b.acme.com"))
        sel = [e for e in self._events if e.get("measure") == "zones"][-1]
        assert (sel["eligible"], sel["tested"], sel["omitted"]) == (2, 1, 1), sel
        assert "deferred to a later run by the 1-zone per-run allowance" in sel["reason"], sel
        ex = [e for e in self._events if e.get("measure") == "zone_execution"][-1]
        assert (ex["eligible"], ex["tested"], ex["omitted"]) == (1, 0, 1), ex

    @pytest.mark.parametrize("mode,check", [("no_artifact", "artifacts"), ("skip", "stopped")])
    def test_EVERY_observable_fact_is_committed_before_the_ledger_write(self, tmp_path, monkeypatch,
                                                                       mode, check):
        """v54#1: only the returned counter had moved. A returned call that wrote no file still reported
        an artifact, and a SKIPPED result lost "httpx did not run", when `record()` raised."""
        from quarry_recon import store
        real = store.Run.record

        def _boom(self, phase, result):
            if result.tool == "httpx":
                raise OSError("manifest is read-only")
            return real(self, phase, result)

        monkeypatch.setattr(store.Run, "record", _boom, raising=False)
        kw = {"no_artifact": True} if mode == "no_artifact" else {"status": crawl.Status.SKIPPED}
        kept, life = self._differ(tmp_path, monkeypatch, rows=[], zones=("a.acme.com", "b.acme.com"),
                                  **kw)
        if check == "artifacts":
            # v56: this zone's facts are kept, and there is NO further contact after a write we could
            # not make — so exactly one zone was contacted
            art = [e for e in self._events if e.get("measure") == "output_artifacts"][-1]
            assert (art["eligible"], art["tested"], art["omitted"]) == (1, 0, 1), art
        else:
            ex = [e for e in self._events if e.get("measure") == "zone_execution"][-1]
            assert "httpx did not run" in ex["reason"], ex
            assert (ex["eligible"], ex["tested"], ex["omitted"]) == (2, 0, 2), ex
            assert "could not be recorded" not in ex["reason"], ex   # the SKIP is the first cause
        assert life[-1]["status"] == "failed" and "read-only" in life[-1]["reason"], life

    def test_UNKNOWN_eligibility_is_not_an_EMPTY_set(self, tmp_path, monkeypatch):
        """v54#2: a scope filter that raised was indistinguishable from a successfully computed empty
        set — the reporter emitted clean 0/0/0 for both."""
        from quarry_recon.phases import vertical
        monkeypatch.setattr(vertical, "_wc_eligible_zones",
                            lambda ctx, zones: (_ for _ in ()).throw(TypeError("scope exploded")))
        kept, life = self._differ(tmp_path, monkeypatch, rows=[],
                                  zones=("a.acme.com", "b.acme.com"))
        for measure in ("zones", "zone_execution"):
            rec = [e for e in self._events if e.get("measure") == measure][-1]
            assert rec["kind"] == "unknown", rec
            assert rec.get("eligible") is None, rec
            assert "could not be determined" in rec["reason"], rec
        assert life[-1]["status"] == "failed" and "scope exploded" in life[-1]["reason"], life
        assert self._last_run._run_summary()["verdict"] != "complete"

    def test_a_LEDGER_failure_never_costs_the_EVIDENCE(self, tmp_path, monkeypatch):
        """v55: the bytes were already in hand, but a raising `record()` exited before row accounting and
        ingestion — so a valid host was dropped and the artifact reported as offering no rows."""
        from quarry_recon import store
        real = store.Run.record

        def _boom(self, phase, result):
            if result.tool == "httpx":
                raise OSError("manifest is read-only")
            return real(self, phase, result)

        monkeypatch.setattr(store.Run, "record", _boom, raising=False)
        rows = [{"input": "api.z.acme.com", "status_code": 200, "content_length": 99,
                 "title": "real", "favicon": "y", "a": ["1.2.3.4"]}]
        kept, life = self._differ(tmp_path, monkeypatch, rows=rows)
        assert kept == {"api.z.acme.com"}, kept                      # the finding survives
        assert list(self._last_run.read("resolved")), "the resolved observation survives too"
        rowsc = [e for e in self._events if e.get("measure") == "output_rows"][-1]
        assert (rowsc["eligible"], rowsc["tested"], rowsc["omitted"]) == (3, 3, 0), rowsc
        art = [e for e in self._events if e.get("measure") == "output_artifacts"][-1]
        assert (art["eligible"], art["tested"], art["omitted"]) == (1, 1, 0), art
        # ...and the run still FAILS on the write it could not make
        assert life[-1]["status"] == "partial" and "read-only" in life[-1]["reason"], life
        assert self._last_run._run_summary()["verdict"] != "complete"

    def test_a_LEDGER_failure_STOPS_further_contact(self, tmp_path, monkeypatch):
        """v56: the lane kept probing after a write it could not make — unrecorded traffic, and a later
        exit could carry the known failure away."""
        from quarry_recon import store
        real = store.Run.record
        seen = []

        def _boom(self, phase, result):
            if result.tool == "httpx":
                seen.append(result)
                raise OSError("manifest is read-only")
            return real(self, phase, result)

        monkeypatch.setattr(store.Run, "record", _boom, raising=False)
        rows = [{"input": "api.a.acme.com", "status_code": 200, "content_length": 99,
                 "title": "real", "favicon": "y"}]
        kept, life = self._differ(tmp_path, monkeypatch, rows=rows,
                                  zones=("a.acme.com", "b.acme.com"))
        assert len(seen) == 1, seen                       # exactly ONE zone was contacted
        assert kept == {"api.a.acme.com"}, kept           # its evidence still landed
        ex = [e for e in self._events if e.get("measure") == "zone_execution"][-1]
        assert (ex["eligible"], ex["tested"], ex["omitted"]) == (2, 1, 1), ex
        assert "could not be recorded" in ex["reason"], ex
        assert life[-1]["status"] == "partial" and "read-only" in life[-1]["reason"], life

    def test_a_CANCELLATION_after_a_ledger_failure_keeps_BOTH_facts(self, tmp_path, monkeypatch):
        """v56: the terminal said only CANCELLED and the ledger failure vanished."""
        from quarry_recon import store
        from quarry_recon.phases import vertical
        real = store.Run.record

        def _boom(self, phase, result):
            if result.tool == "httpx":
                raise OSError("manifest is read-only")
            return real(self, phase, result)

        monkeypatch.setattr(store.Run, "record", _boom, raising=False)
        real_add = store.Run.add

        def _cancel(self, kind, row):
            raise KeyboardInterrupt("ctrl-c")

        monkeypatch.setattr(store.Run, "add", _cancel, raising=False)
        rows = [{"input": "api.a.acme.com", "status_code": 200, "content_length": 99,
                 "title": "real", "favicon": "y"}]
        caught = []
        kept, life = self._differ(tmp_path, monkeypatch, rows=rows, caught=caught,
                                  zones=("a.acme.com", "b.acme.com"))
        assert caught and isinstance(caught[0], KeyboardInterrupt), caught
        assert "CANCELLED mid-differ" in life[-1]["reason"], life
        assert "not recorded" in life[-1]["reason"] and "read-only" in life[-1]["reason"], life

    def test_an_UNRECORDED_invocation_keeps_its_OUTCOME_in_the_terminal(self, tmp_path, monkeypatch):
        """v57: raising the ledger error skipped `_wc_terminal`, so a timed-out invocation whose own
        RunResult never reached the ledger left NO durable trace of the timeout."""
        from quarry_recon import store
        real = store.Run.record

        def _boom(self, phase, result):
            if result.tool == "httpx":
                raise OSError("manifest is read-only")
            return real(self, phase, result)

        monkeypatch.setattr(store.Run, "record", _boom, raising=False)
        kept, life = self._differ(tmp_path, monkeypatch, status=crawl.Status.TIMED_OUT, rows=[])
        reason = life[-1]["reason"]
        assert "zone outcomes {'timed_out': 1}" in reason, reason
        assert "read-only" in reason, reason
        assert reason.count("manifest is read-only") == 1, reason      # named once, not twice

    def test_a_SKIPPED_invocation_and_a_LEDGER_failure_both_reach_the_terminal(self, tmp_path,
                                                                              monkeypatch):
        from quarry_recon import store
        real = store.Run.record

        def _boom(self, phase, result):
            if result.tool == "httpx":
                raise OSError("manifest is read-only")
            return real(self, phase, result)

        monkeypatch.setattr(store.Run, "record", _boom, raising=False)
        kept, life = self._differ(tmp_path, monkeypatch, status=crawl.Status.SKIPPED, rows=[],
                                  zones=("a.acme.com", "b.acme.com"))
        reason = life[-1]["reason"]
        assert "httpx did not run" in reason, reason        # the first cause survives
        assert "read-only" in reason, reason

    def test_a_CANCELLATION_keeps_the_ZONE_facts_gathered_before_it(self, tmp_path, monkeypatch):
        """v57: the cancellation reason was built from scratch, so a zone that had already come back
        timed out left no trace in the terminal."""
        from quarry_recon.phases import vertical
        from quarry_recon.runner import RunResult as _RR
        calls = []

        def _tool(tool, cmd, raw_path=None, timeout=None, **k):
            calls.append(cmd)
            if len(calls) == 1:
                return _RR(tool, cmd, crawl.Status.TIMED_OUT, None, 0.1, None, 0)
            raise KeyboardInterrupt("ctrl-c")

        monkeypatch.setattr(vertical, "exec_tool", _tool)
        caught = []
        kept, life = self._differ(tmp_path, monkeypatch, rows=[], caught=caught,
                                  zones=("a.acme.com", "b.acme.com"), tool=_tool)
        assert caught and isinstance(caught[0], KeyboardInterrupt), caught
        reason = life[-1]["reason"]
        assert "zone outcomes {'timed_out': 1}" in reason, reason
        assert "CANCELLED mid-differ" in reason, reason

    @pytest.mark.parametrize("boom", [OSError("scope exploded"), KeyboardInterrupt("ctrl-c")])
    def test_an_exit_BEFORE_eligibility_never_claims_there_were_no_zones(self, tmp_path, monkeypatch,
                                                                        boom):
        """v58#1: `_wc_terminal` reads zero-initialised counters, so an exit before eligibility was known
        added "no in-scope wildcard zone" — contradicting the UNKNOWN coverage the same run emits."""
        from quarry_recon.phases import vertical
        monkeypatch.setattr(vertical, "_wc_eligible_zones",
                            lambda ctx, zones: (_ for _ in ()).throw(boom))
        caught = []
        kept, life = self._differ(tmp_path, monkeypatch, rows=[], caught=caught,
                                  zones=("a.acme.com", "b.acme.com"))
        reason = life[-1]["reason"]
        assert "no in-scope wildcard zone" not in reason, reason
        assert "never determined" in reason, reason
        rec = [e for e in self._events if e.get("measure") == "zones"][-1]
        assert rec["kind"] == "unknown", rec

    def test_TWO_identical_failures_are_BOTH_named(self, tmp_path, monkeypatch):
        """v58#2: the ledger fact was dropped when its rendered text appeared in the reason — two
        independent failures can carry the same type and message."""
        from quarry_recon import store
        real_record, real_add = store.Run.record, store.Run.add

        def _rec(self, phase, result):
            if result.tool == "httpx":
                raise OSError("disk is read-only")
            return real_record(self, phase, result)

        def _add(self, kind, row):
            if kind == "subdomain":
                raise OSError("disk is read-only")       # a DIFFERENT failure, same words
            return real_add(self, kind, row)

        monkeypatch.setattr(store.Run, "record", _rec, raising=False)
        monkeypatch.setattr(store.Run, "add", _add, raising=False)
        rows = [{"input": "api.z.acme.com", "status_code": 200, "content_length": 99,
                 "title": "real", "favicon": "y"}]
        kept, life = self._differ(tmp_path, monkeypatch, rows=rows)
        reason = life[-1]["reason"]
        # the ingest failure reaches the terminal through the scheduler's machinery detail, and the
        # unrecorded RESULT is named separately — two facts, not one collapsed into the other
        assert "OSError: disk is read-only" in reason, reason
        assert "1 tool result(s) not recorded" in reason, reason
