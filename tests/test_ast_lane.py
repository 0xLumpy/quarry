"""`crawl.jxscout_ast` — COLLECT ONCE, INTERPRET LATER.

This lane analyses a bundle exactly once and publishes the complete immutable artifact. It normalises
nothing and names no entity: what the analyzer emitted is evidence, and the interpretation belongs to a
later step (notes/current/AST-ANALYZER-LANE-DESIGN.md). So what is pinned here is the collection
contract — the work unit that makes a re-run skip finished bundles, the containment the analysis runs
under, and the dispositions that keep a failure from reading as an empty answer.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from quarry_recon.phases import crawl


class _Scope:
    def in_scope(self, host):
        return True

    def active_allowed(self, host):
        return True


@pytest.fixture(autouse=True)
def _no_bus(monkeypatch):
    """The unit MACHINERY is stubbed by default: these are offline tests, and `cgroup.clear/stop` talk to
    the session bus. The tests that are ABOUT that machinery override this and drive it directly."""
    monkeypatch.setattr(crawl.cgroup, "clear", lambda unit: None)
    monkeypatch.setattr(crawl.cgroup, "stop", lambda unit, budget_s=30.0: True)


def _ctx(tmp_path):
    from quarry_recon import store
    run = store.Run.create(tmp_path, "acme.com")
    return type("C", (), {"run": run, "scope": _Scope(), "echo": lambda *a, **k: None,
                          "profile": type("P", (), {})()})(), run


def _ledger(pairs):
    return type("L", (), {"items": lambda self=None: iter(pairs)})()


def _bundle(tmp_path, name="b.js", size=200):
    f = tmp_path / name
    f.write_text("x" * size)
    return f


class TestTheMemoryPolicyIsAREQUESTWithEvidence:
    """`RLIMIT_AS` measures address space and is not the production cap; the cgroup is. The request is
    sized from the bundle because the analyzer's appetite scales with it — MEASURED at 165-225x."""

    def test_the_request_scales_with_the_bundle(self):
        assert crawl._ast_mem_request_mb(30 * 1024 * 1024) == 30 * crawl._AST_MEM_PER_MB

    def test_a_tiny_bundle_still_gets_the_floor(self):
        assert crawl._ast_mem_request_mb(1024) == crawl._AST_MEM_FLOOR_MB

    def test_a_bundle_over_the_policy_is_a_GAP_not_a_skip(self, tmp_path, monkeypatch):
        """A silent skip would leave the largest bundles — the ones jsluice gives up on — missing with
        no record that anything was owed."""
        ctx, _run = _ctx(tmp_path)
        art = _bundle(tmp_path, size=64 * 1024 * 1024)
        monkeypatch.setattr(crawl, "run_contract", lambda *a, **k: pytest.fail("it launched anyway"))
        disp, res, meta = crawl._ast_analyze(ctx, art, "d" * 64, "eng")
        assert disp == "over-memory-policy" and res is None
        assert meta["mem_request_mb"] > crawl._AST_MEM_CEILING_MB

    def test_admission_refuses_when_the_host_has_less_than_the_request(self, tmp_path, monkeypatch):
        ctx, _run = _ctx(tmp_path)
        art = _bundle(tmp_path)
        monkeypatch.setattr(crawl, "_ast_headroom_mb", lambda: 64)
        monkeypatch.setattr(crawl, "run_contract", lambda *a, **k: pytest.fail("it launched anyway"))
        disp, _res, meta = crawl._ast_analyze(ctx, art, "d" * 64, "eng")
        assert disp == "insufficient-headroom" and meta["headroom_mb"] == 64

    def test_admission_is_not_a_GUARANTEE_and_the_lane_says_so(self):
        """Another process can take the memory a moment later, so the cgroup — not this check — is the
        boundary. The docstring is the contract; the test is that it has not quietly become a promise."""
        assert "does not guarantee" in crawl._ast_headroom_mb.__doc__.replace("\n", " ").lower()


class TestContainmentOrNothing:
    def test_no_bwrap_or_no_cgroup_means_the_lane_does_not_run(self, tmp_path, monkeypatch):
        monkeypatch.setattr(crawl.shutil, "which", lambda n: None)
        assert crawl._ast_command(_bundle(tmp_path), tmp_path / "o", tmp_path / "e",
                                  tmp_path / "p", 1024, tmp_path, "quarry-ast-test") == []

    def test_the_command_carries_every_measured_bound(self, tmp_path, monkeypatch):
        """HERMETIC on purpose: this is about the COMMAND SHAPE, not about what happens to be on the
        host's PATH. An earlier version stubbed the analyzer shim but not bun, so on a shell without bun
        the builder correctly returned nothing and the test read that as a broken contract. Whether the
        real sandbox works is the integration probe's job."""
        fake = {}
        for name in ("bwrap", "bun", crawl.AST_SHIM, "systemd-run", "systemctl"):
            f = tmp_path / name
            f.write_text("#!/bin/sh\n")
            f.chmod(0o755)
            fake[name] = str(f)
        monkeypatch.setattr(crawl.shutil, "which", lambda n: fake.get(n))
        monkeypatch.setattr(crawl.cgroup.shutil, "which", lambda n: fake.get(n))
        engine, native = tmp_path / "ast-analyzer.js", tmp_path / "parser.node"
        engine.write_text("//")
        native.write_bytes(b"\x00")
        monkeypatch.setattr(crawl, "AST_ENGINE", engine)
        monkeypatch.setattr(crawl, "AST_NATIVE", native)
        art = _bundle(tmp_path)
        cmd = crawl._ast_command(art, tmp_path / "o", tmp_path / "e", tmp_path / "p", 4096, tmp_path,
                                 "quarry-ast-test")
        joined = " ".join(cmd)
        assert "MemoryMax=4096M" in joined and "MemorySwapMax=0" in joined, "the cgroup IS the cap"
        assert f"ulimit -v {crawl._AST_ADDRESS_SPACE_MB * 1024}" in joined, \
            "address space stays as a secondary guard, it is just not the production cap"
        assert "--unshare-all" in joined and "--clearenv" in joined
        assert "--ro-bind / /" not in joined and " / /" not in joined, "read-only is not absent"
        assert str(art) in joined and "memory.peak" in joined, \
            "the unit's own peak is read while the unit still exists"
        assert "--unit=quarry-ast-test" in joined, \
            "the unit name is the LANE's, so the lane can stop what it started"
        assert f"> {tmp_path / 'o'}" in joined, "output goes to a bounded FILE, not into Quarry's memory"

    def test_a_missing_RUNTIME_is_a_refusal_not_a_silent_uncontained_run(self, tmp_path, monkeypatch):
        """Every piece is required: no bwrap, no cgroup, no bun, no engine — each on its own means the
        lane does not run. bun in particular: the analyzer FAILS under node, so falling back would
        produce an empty answer that looks like a clean one."""
        base = {"bwrap": "/x/bwrap", "bun": "/x/bun", crawl.AST_SHIM: "/x/shim",
                "systemd-run": "/x/sr", "systemctl": "/x/sc"}
        engine, native = tmp_path / "e.js", tmp_path / "p.node"
        engine.write_text("//")
        native.write_bytes(b"\x00")
        monkeypatch.setattr(crawl, "AST_ENGINE", engine)
        monkeypatch.setattr(crawl, "AST_NATIVE", native)
        for missing in ("bwrap", "bun", crawl.AST_SHIM, "systemd-run"):
            table = {k: v for k, v in base.items() if k != missing}
            monkeypatch.setattr(crawl.shutil, "which", lambda n, t=table: t.get(n))
            monkeypatch.setattr(crawl.cgroup.shutil, "which", lambda n, t=table: t.get(n))
            assert crawl._ast_command(_bundle(tmp_path), tmp_path / "o", tmp_path / "e",
                                      tmp_path / "p", 1024, tmp_path, "u") == [], \
                f"a missing {missing} did not stop the lane"


class TestTheWorkUnitMakesARerunSKIP:
    @staticmethod
    def _fake(monkeypatch, tmp_path, *, out="[]", rc=0, peak=b"104857600"):
        from quarry_recon.runner import RunResult, Status
        seen = {}

        def fake_contract(source_id, cmd, work_unit=None, timeout=None, **kw):
            seen["work_unit"], seen["cmd"] = work_unit, cmd
            joined = " ".join(cmd)
            dest = pathlib.Path(joined.split("> ", 1)[1].split(" 2> ")[0])
            dest.write_text(out)
            peakp = pathlib.Path(joined.rsplit("> ", 1)[1].split(" 2>")[0])
            peakp.write_bytes(peak)
            return RunResult(source_id, cmd, Status.SUCCESS if rc == 0 else Status.FAILED, rc, 1.0,
                             None, 0)
        monkeypatch.setattr(crawl, "run_contract", fake_contract)
        monkeypatch.setattr(crawl, "_ast_command",
                            lambda bundle, out_, err_, peak_, mem, scratch, unit:
                            ["/bin/true", f"> {out_} 2> {err_}", f"> {peak_} 2>"])
        # the fake never starts a unit, so there is nothing to stop; the REAL stop path has its own test
        monkeypatch.setattr(crawl.cgroup, "stop", lambda unit, budget_s=30.0: True)
        return seen

    def test_the_lane_IS_REACHED_from_the_phase(self, monkeypatch):
        """A lane with no caller cannot be enabled, and every claim about it would be about a helper.
        MODES.JS_AST gates it; the phase must call it when that is set and never when it is not."""
        import inspect
        src = inspect.getsource(crawl.run)
        assert "_ast_bundles(ctx" in src, "the phase never calls the lane"
        assert "js_ast" in src, "the call is not gated by MODES.JS_AST"

    def test_the_unit_is_the_BUNDLE_plus_the_engine_and_the_policy(self, tmp_path, monkeypatch):
        """A different analyzer build is different work: the same bytes must not resume as already done
        just because an artifact with that name exists. The identity is a HASH, so each component is
        pinned by changing it alone and requiring the identity to move."""
        seen = self._fake(monkeypatch, tmp_path)
        ctx, _run = _ctx(tmp_path)

        # ONE change at a time, restored after: accumulated patches masked a missing identity field —
        # the wall change from an earlier assertion kept the unit moving after the ceiling stopped
        # participating at all.
        defaults = {k: getattr(crawl, k) for k in
                    ("_AST_WALL_S", "_AST_OUTPUT_MB", "_AST_ADDRESS_SPACE_MB")}

        def unit_for(digest="a" * 64, engine="eng", **policy):
            for k, v in defaults.items():
                monkeypatch.setattr(crawl, k, v)
            for k, v in policy.items():
                monkeypatch.setattr(crawl, k, v)
            crawl._ast_analyze(ctx, _bundle(tmp_path), digest, engine)
            return seen["work_unit"]

        base = unit_for()
        assert unit_for() == base, "the same bytes, engine and policy are the same work"
        assert unit_for(digest="b" * 64) != base, "the bundle's CONTENT digest identifies the work"
        assert unit_for(engine="another-build") != base, "the executable is part of the identity"
        assert unit_for(_AST_WALL_S=defaults["_AST_WALL_S"] * 2) != base, "so is the wall it ran under"
        assert unit_for(_AST_OUTPUT_MB=defaults["_AST_OUTPUT_MB"] * 2) != base, "and the output ceiling"
        assert unit_for(_AST_ADDRESS_SPACE_MB=1234) != base, "and the address-space guard"

    def test_the_engine_identity_covers_the_native_parser_and_is_not_frozen(self, tmp_path, monkeypatch):
        """A module-level constant would pin whatever was on disk at import and survive an install that
        replaced the engine underneath it — and the native parser changes the answer too."""
        a = tmp_path / "engine.js"
        b = tmp_path / "parser.node"
        a.write_text("one")
        b.write_text("two")
        monkeypatch.setattr(crawl, "AST_ENGINE", a)
        monkeypatch.setattr(crawl, "AST_NATIVE", b)
        first = crawl._ast_engine_digest()
        b.write_text("a different native parser")
        assert crawl._ast_engine_digest() != first, "the parser is part of the executable's identity"
        a.write_text("a different analyzer build")
        assert crawl._ast_engine_digest() not in (first,), "and so is the bundle, re-read each time"

    def test_the_measured_peak_is_recorded_beside_the_request(self, tmp_path, monkeypatch):
        """The 300x request is provisional; requested-vs-actual is what revises it."""
        self._fake(monkeypatch, tmp_path, peak=b"2701131776")
        ctx, _run = _ctx(tmp_path)
        _d, _res, meta = crawl._ast_analyze(ctx, _bundle(tmp_path), "d" * 64, "eng")
        assert meta["mem_peak_mb"] == 2576 and meta["mem_request_mb"] == crawl._AST_MEM_FLOOR_MB


class TestTheArtifactIsTheProduct:
    def test_a_result_is_published_content_bound(self, tmp_path, monkeypatch):
        TestTheWorkUnitMakesARerunSKIP._fake(monkeypatch, tmp_path,
                                             out='[{"analyzerName":"fetch","value":"/api/x"}]')
        ctx, run = _ctx(tmp_path)
        disp, res, meta = crawl._ast_analyze(ctx, _bundle(tmp_path), "a" * 64, "eng")
        assert disp == "success" and meta["matches"] == 1
        dest = pathlib.Path(meta["artifact"])
        assert dest.exists() and json.loads(dest.read_text())[0]["value"] == "/api/x"
        assert res.raw_path == dest
        # the WORK identity is in the name: a different engine is different work and must not overwrite
        other = crawl._ast_analyze(ctx, _bundle(tmp_path), "a" * 64, "a-newer-engine")[2]["artifact"]
        assert other != str(dest) and pathlib.Path(other).exists() and dest.exists()

    def test_an_EMPTY_answer_is_still_published(self, tmp_path, monkeypatch):
        """`[]` is evidence that the bundle was read and declared nothing — deleting it would make
        'we looked' indistinguishable from 'we never got there'."""
        TestTheWorkUnitMakesARerunSKIP._fake(monkeypatch, tmp_path, out="[]")
        ctx, run = _ctx(tmp_path)
        disp, _res, meta = crawl._ast_analyze(ctx, _bundle(tmp_path), "b" * 64, "eng")
        assert disp == "empty" and pathlib.Path(meta["artifact"]).exists()

    def test_a_FAILED_publication_is_not_a_result(self, tmp_path, monkeypatch):
        TestTheWorkUnitMakesARerunSKIP._fake(monkeypatch, tmp_path, out='[{"a":1}]')
        monkeypatch.setattr(crawl.budget, "publish_bytes", lambda *a, **k: False)
        ctx, _run = _ctx(tmp_path)
        disp, res, _meta = crawl._ast_analyze(ctx, _bundle(tmp_path), "c" * 64, "eng")
        assert disp == "unpublished" and res.raw_path is None

    def test_UNPARSEABLE_output_is_a_gap_not_an_empty_answer(self, tmp_path, monkeypatch):
        """One JSON document: a cut is not a shorter list."""
        TestTheWorkUnitMakesARerunSKIP._fake(monkeypatch, tmp_path, out='[{"a":1},{"b"')
        ctx, _run = _ctx(tmp_path)
        assert crawl._ast_analyze(ctx, _bundle(tmp_path), "e" * 64, "eng")[0] == "unparseable"

    @pytest.mark.parametrize("rc,expect", [(137, "oom-killed"), (-9, "oom-killed"), (134, "oom-killed"),
                                           (1, "analyzer-error")])
    def test_a_KILL_never_reads_as_no_findings(self, tmp_path, monkeypatch, rc, expect):
        """The cgroup kill and the analyzer's own caught allocation failure both produce empty output.
        Reading either as 'this bundle contains nothing' is how a coverage number becomes a lie."""
        TestTheWorkUnitMakesARerunSKIP._fake(monkeypatch, tmp_path, out="", rc=rc)
        ctx, _run = _ctx(tmp_path)
        assert crawl._ast_analyze(ctx, _bundle(tmp_path), "f" * 64, "eng")[0] == expect


class TestTheLaneStopsWhatItStarted:
    """`run_contract`'s timeout kills the systemd-run CLIENT; the service is not in that process group.
    A lane that returned while a unit kept running would leave up to the memory cap in use."""

    def test_a_run_always_tries_to_stop_its_unit(self, tmp_path, monkeypatch):
        stopped = []
        TestTheWorkUnitMakesARerunSKIP._fake(monkeypatch, tmp_path)
        monkeypatch.setattr(crawl.cgroup, "stop", lambda unit, budget_s=30.0: stopped.append(unit) or True)
        ctx, _run = _ctx(tmp_path)
        crawl._ast_analyze(ctx, _bundle(tmp_path), "a" * 64, "eng")
        assert len(stopped) == 1 and stopped[0].startswith("quarry-ast-")

    def test_the_unit_is_stopped_even_when_the_run_RAISES(self, tmp_path, monkeypatch):
        stopped = []
        monkeypatch.setattr(crawl, "_ast_command",
                            lambda *a, **k: ["/bin/true", "> /dev/null 2> /dev/null", "> /dev/null 2>"])
        monkeypatch.setattr(crawl, "run_contract",
                            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
        monkeypatch.setattr(crawl.cgroup, "stop", lambda unit, budget_s=30.0: stopped.append(unit) or True)
        ctx, _run = _ctx(tmp_path)
        with pytest.raises(RuntimeError):
            crawl._ast_analyze(ctx, _bundle(tmp_path), "a" * 64, "eng")
        assert stopped, "an exception must not leave the service running"

    def test_an_UNSETTLED_unit_is_not_a_result(self, tmp_path, monkeypatch):
        """If the service cannot be confirmed stopped it may still be running under its cap, so whatever
        landed on disk is not something to certify."""
        TestTheWorkUnitMakesARerunSKIP._fake(monkeypatch, tmp_path, out='[{"a":1}]')
        monkeypatch.setattr(crawl.cgroup, "stop", lambda unit, budget_s=30.0: False)
        ctx, _run = _ctx(tmp_path)
        disp, _res, meta = crawl._ast_analyze(ctx, _bundle(tmp_path), "a" * 64, "eng")
        assert disp == "unit-unsettled" and meta["unit_settled"] is False


class TestResumeIsALEDGERNotAnEvent:
    """`run_contract` emits the work unit as evidence; it does not skip anything. Without a completion
    ledger every run re-analyses every bundle — 100 s each on the big ones."""

    def test_a_second_run_skips_completed_work(self, tmp_path, monkeypatch):
        TestTheWorkUnitMakesARerunSKIP._fake(monkeypatch, tmp_path, out='[{"a":1}]')
        monkeypatch.setattr(crawl, "have", lambda b: True)
        monkeypatch.setattr(crawl, "_ast_engine_digest", lambda: "engine-1")
        ctx, run = _ctx(tmp_path)
        art = _bundle(tmp_path)
        assert crawl._ast_bundles(ctx, _ledger([("https://acme.com/b.js", art)])) == 1
        fresh = type("C", (), {"run": run, "scope": _Scope(), "echo": lambda *a, **k: None,
                               "profile": type("P", (), {})()})()
        assert crawl._ast_bundles(fresh, _ledger([("https://acme.com/b.js", art)])) == 0
        assert fresh._ast_stats["dispositions"] == {"resumed": 1}
        assert fresh._ast_stats["published"] == 1, "a resumed bundle is COVERED, not omitted"

    def test_a_NEW_ENGINE_is_new_work(self, tmp_path, monkeypatch):
        """The ledger key is the full identity, so a replaced analyzer does not resume as done."""
        TestTheWorkUnitMakesARerunSKIP._fake(monkeypatch, tmp_path, out='[{"a":1}]')
        monkeypatch.setattr(crawl, "have", lambda b: True)
        monkeypatch.setattr(crawl, "_ast_engine_digest", lambda: "engine-1")
        ctx, run = _ctx(tmp_path)
        art = _bundle(tmp_path)
        crawl._ast_bundles(ctx, _ledger([("https://acme.com/b.js", art)]))
        monkeypatch.setattr(crawl, "_ast_engine_digest", lambda: "engine-2")
        fresh = type("C", (), {"run": run, "scope": _Scope(), "echo": lambda *a, **k: None,
                               "profile": type("P", (), {})()})()
        assert crawl._ast_bundles(fresh, _ledger([("https://acme.com/b.js", art)])) == 1
        assert fresh._ast_stats["dispositions"] == {"success": 1}


class TestEveryCoverageRecordSURVIVES:
    def test_the_records_do_not_overwrite_each_other(self, tmp_path, monkeypatch):
        """Reconciliation keeps the LATEST record per (source, unit). The memory note shared the bundle
        unit and silently replaced the eligible/tested row — the one number the lane exists to report."""
        from quarry_recon import events, store
        run = store.Run.create(tmp_path, "acme.com")
        events.configure(run.dir)
        try:
            TestTheWorkUnitMakesARerunSKIP._fake(monkeypatch, tmp_path, out='[{"a":1}]',
                                                 peak=b"1073741824")
            monkeypatch.setattr(crawl, "have", lambda b: True)
            monkeypatch.setattr(crawl.budget.Ledger, "save", lambda self: False)
            ctx = type("C", (), {"run": run, "scope": _Scope(), "echo": lambda *a, **k: None,
                                 "profile": type("P", (), {})()})()
            arts = [(f"https://acme.com/{i}.js", _bundle(tmp_path, f"{i}.js")) for i in range(2)]
            big = tmp_path / "huge.js"                       # one bundle over the policy: omitted > 0
            big.write_bytes(b"x" * (64 * 1024 * 1024))
            arts.append(("https://acme.com/huge.js", big))
            crawl._ast_bundles(ctx, _ledger(arts))
            run.write_manifest(profile_summary={}, phases_run=["crawl"])
            rows = {c["measure"]: c for c in run._run_summary()["coverage"]
                    if c["source_id"] == "crawl.jxscout_ast"}
            assert {"bundles", "memory", "resume"} <= set(rows), set(rows)
            assert rows["bundles"]["omitted"] == 1, \
                "the eligible/tested row is the one the lane exists to publish"
        finally:
            events.reset()


class TestResumabilityIsCLAIMEDOnlyWhenItPersists:
    def test_a_ledger_that_did_not_save_is_a_declared_gap(self, tmp_path, monkeypatch):
        """The artifacts landed, but the next run cannot know that. Reporting full coverage and silently
        re-analysing everything next time is the failure this catches."""
        from quarry_recon import events, store
        run = store.Run.create(tmp_path, "acme.com")
        events.configure(run.dir)
        try:
            TestTheWorkUnitMakesARerunSKIP._fake(monkeypatch, tmp_path, out='[{"a":1}]')
            monkeypatch.setattr(crawl, "have", lambda b: True)
            monkeypatch.setattr(crawl.budget.Ledger, "save", lambda self: False)
            ctx = type("C", (), {"run": run, "scope": _Scope(), "echo": lambda *a, **k: None,
                                 "profile": type("P", (), {})()})()
            crawl._ast_bundles(ctx, _ledger([("https://acme.com/b.js", _bundle(tmp_path))]))
            run.write_manifest(profile_summary={}, phases_run=["crawl"])
            cov = [c for c in run._run_summary()["coverage"]
                   if c["source_id"] == "crawl.jxscout_ast" and c["measure"] == "resume"]
            assert cov and "did NOT persist" in cov[0]["reason"]
            assert ctx._ast_stats["dispositions"]["ledger-unsaved"] == 1
        finally:
            events.reset()

    def test_a_saved_ledger_declares_nothing(self, tmp_path, monkeypatch):
        from quarry_recon import events, store
        run = store.Run.create(tmp_path, "acme.com")
        events.configure(run.dir)
        try:
            TestTheWorkUnitMakesARerunSKIP._fake(monkeypatch, tmp_path, out='[{"a":1}]')
            monkeypatch.setattr(crawl, "have", lambda b: True)
            ctx = type("C", (), {"run": run, "scope": _Scope(), "echo": lambda *a, **k: None,
                                 "profile": type("P", (), {})()})()
            crawl._ast_bundles(ctx, _ledger([("https://acme.com/b.js", _bundle(tmp_path))]))
            run.write_manifest(profile_summary={}, phases_run=["crawl"])
            assert not [c for c in run._run_summary()["coverage"]
                        if c["source_id"] == "crawl.jxscout_ast" and c["measure"] == "resume"]
        finally:
            events.reset()


class TestTheLaneReportsWhatItDidNotRead:
    def test_a_missing_tool_with_work_is_a_recorded_skip(self, tmp_path, monkeypatch):
        monkeypatch.setattr(crawl, "have", lambda b: False)
        ctx, run = _ctx(tmp_path)
        art = _bundle(tmp_path)
        assert crawl._ast_bundles(ctx, _ledger([("https://acme.com/b.js", art)])) == 0
        assert any(r.tool == crawl.AST_SHIM for r in run._tool_runs)
        assert ctx._ast_stats["dispositions"]["missing-tool"] == 1

    def test_a_missing_tool_with_NO_work_is_a_clean_zero(self, tmp_path, monkeypatch):
        monkeypatch.setattr(crawl, "have", lambda b: False)
        ctx, run = _ctx(tmp_path)
        assert crawl._ast_bundles(ctx, _ledger([])) == 0
        assert not run._tool_runs, "nothing to skip, so nothing to report"
        assert not getattr(ctx, "_ast_stats", {}).get("dispositions")

    def test_a_shared_refusal_belongs_to_every_bundle_it_stopped(self, tmp_path, monkeypatch):
        """With no containment the loop stops at the first bundle; counting only that one would report
        the rest as covered when none was analysed."""
        from quarry_recon import events, store
        run = store.Run.create(tmp_path, "acme.com")
        events.configure(run.dir)
        try:
            monkeypatch.setattr(crawl, "have", lambda b: True)
            monkeypatch.setattr(crawl, "_ast_command", lambda *a, **k: [])
            arts = [(f"https://acme.com/{i}.js", _bundle(tmp_path, f"{i}.js")) for i in range(6)]
            ctx = type("C", (), {"run": run, "scope": _Scope(), "echo": lambda *a, **k: None,
                                 "profile": type("P", (), {})()})()
            crawl._ast_bundles(ctx, _ledger(arts))
            run.write_manifest(profile_summary={}, phases_run=["crawl"])
            cov = [c for c in run._run_summary()["coverage"]
                   if c["source_id"] == "crawl.jxscout_ast" and c["measure"] == "bundles"][0]
            assert ctx._ast_stats["dispositions"]["no-containment"] == 6
            assert cov["omitted"] == 6 and cov["tested"] == 0
        finally:
            events.reset()

    def test_the_lane_FETCHES_nothing_and_names_no_entity(self, tmp_path, monkeypatch):
        """Collection only. Anything derived from the artifact is a later step, and nothing is requested
        because the analyzer mentioned it."""
        TestTheWorkUnitMakesARerunSKIP._fake(monkeypatch, tmp_path,
                                             out='[{"analyzerName":"robust-paths","value":"/api/x"}]')
        monkeypatch.setattr(crawl, "have", lambda b: True)
        monkeypatch.setattr(crawl.fetch, "scoped_get",
                            lambda *a, **k: pytest.fail("the lane made a request"))
        ctx, run = _ctx(tmp_path)
        crawl._ast_bundles(ctx, _ledger([("https://acme.com/b.js", _bundle(tmp_path))]))
        assert run.values("js_url") == [] and run.values("url") == []
