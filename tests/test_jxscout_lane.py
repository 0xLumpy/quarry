"""The lazy-CHUNK lane — candidates in, `js_url` out.

A bundle's loader names JS that nothing links to, so no crawler reaches it. The analyzer is a candidate
PRODUCER and nothing else: Quarry owns resolution, scope, rate, fetching, evidence and resume. What is
pinned here is that boundary, the resolution details the upstream tool gets wrong (port, query, public
path), and the dispositions — because this analyzer's empty answer is ambiguous and its failures can be
silent.
"""
from __future__ import annotations

import pathlib

import pytest

from quarry_recon import policy, settings
from quarry_recon.phases import crawl


def _stub_shim(monkeypatch, tmp_path):
    """Resolve the SHIM without requiring it to be installed on this host.

    The analyzer is an OPTIONAL install, so an offline test that only reaches the sandbox when
    `~/.local/bin` happens to be on PATH is not a test — measured in a clean env (`env -i`, PATH=/usr/bin:
    /bin) every disposition silently became `no-sandbox` and passed nothing it claimed to pin. bwrap
    itself is NOT stubbed: the argv these tests assert on has to be the one the real builder produces."""
    stub = tmp_path / crawl.JXSCOUT_SHIM
    if not stub.exists():
        stub.write_text("#!/bin/sh\nexit 0\n")
        stub.chmod(0o755)
    real = crawl.shutil.which
    monkeypatch.setattr(crawl.shutil, "which",
                        lambda name, *a, **k: str(stub) if name == crawl.JXSCOUT_SHIM
                        else real(name, *a, **k))
    return stub


class _Scope:
    def __init__(self, apexes=("acme.com",), oos=()):
        self.apexes, self.oos = apexes, set(oos)

    def in_scope(self, host):
        host = (host or "").lower()
        return any(host == a or host.endswith("." + a) for a in self.apexes) and host not in self.oos

    def active_allowed(self, host):
        return self.in_scope(host)


class TestResolutionIsOURS:
    """The analyzer returns what the loader COMPUTES — no scheme, no host, no public path. Everything
    that turns that into a URL is Quarry's, including the parts upstream's own resolver drops."""

    def test_the_PORT_survives(self):
        """`url.URL{Host: parsedURL.Hostname()}` upstream strips it, so every chunk of a bundle served on
        a non-standard port is fetched from the wrong origin."""
        got = crawl._jxscout_resolve("https://app.acme.com:8443/static/js/main.js",
                                     "chunks/a.js", "/assets/")
        assert got == "https://app.acme.com:8443/assets/chunks/a.js"

    def test_the_QUERY_survives(self):
        got = crawl._jxscout_resolve("https://acme.com/static/js/main.js",
                                     "js/app_Login.js?id=8dc7d97f", "/build/")
        assert got == "https://acme.com/build/js/app_Login.js?id=8dc7d97f"
        assert got.endswith("?id=8dc7d97f"), "a chunk path may legitimately carry a query"

    def test_the_PUBLIC_PATH_is_read_from_the_bundle(self):
        """The analyzer evaluates the chunk-NAME function only; the prefix lives in a different
        expression it never touches, so a candidate arrives without it."""
        text = '(()=>{var r={};r.p="/assets/";r.u=(i)=>"static/js/"+i+".js";})()'
        assert crawl._jxscout_public_path(text) == "/assets/"
        assert crawl._jxscout_resolve("https://acme.com/static/js/main.js",
                                      "static/js/143.js", "/assets/") == \
            "https://acme.com/assets/static/js/143.js"

    def test_without_a_public_path_it_resolves_beside_the_BUNDLE(self):
        assert crawl._jxscout_resolve("https://acme.com/static/js/main.js", "143.js", "") == \
            "https://acme.com/static/js/143.js"

    def test_a_root_relative_candidate_already_carries_its_prefix(self):
        assert crawl._jxscout_resolve("https://acme.com/static/js/main.js", "/assets/x.js", "/build/") == \
            "https://acme.com/assets/x.js"

    @pytest.mark.parametrize("public", ["https://evil.example/", "//evil.example/", "/a/../../b/"])
    def test_a_hostile_public_path_cannot_MOVE_THE_ORIGIN(self, public):
        """A bundle is untrusted input. A public path that changes the origin, or walks out of the tree,
        would turn chunk discovery into a fetch primitive pointed wherever the bundle likes — so the
        assertion is about the RESULTING URL, not about the string being tidied."""
        text = f'var r={{}};r.p="{public}";'
        got = crawl._jxscout_resolve("https://acme.com/js/main.js", "chunk.js",
                                     crawl._jxscout_public_path(text))
        assert got is None or got.startswith("https://acme.com/"), got
        assert got is None or "evil.example" not in got

    @pytest.mark.parametrize("cand", ["//evil.example/x.js", "../../../etc/passwd",
                                      "a\nb.js", "a b.js", "", "x" * 3000])
    def test_a_hostile_CANDIDATE_is_refused(self, cand):
        assert crawl._jxscout_resolve("https://acme.com/js/main.js", cand, "") is None

    def test_an_ABSOLUTE_candidate_is_kept_for_SCOPE_to_judge(self):
        got = crawl._jxscout_resolve("https://acme.com/js/main.js", "https://cdn.other/x.js", "")
        assert got == "https://cdn.other/x.js"     # scope drops it later; resolution does not lie about it


class TestTheLaneBoundary:
    @staticmethod
    def _ctx(tmp_path, run, scope=None, brute=0):
        prof = type("P", (), {"js_chunk_brute": brute})()
        return type("C", (), {"run": run, "scope": scope or _Scope(), "profile": prof,
                              "echo": lambda *_a, **_k: None})()

    @staticmethod
    def _ledger(pairs):
        return type("L", (), {"items": lambda self=None: iter(pairs)})()

    def _run(self, tmp_path):
        from quarry_recon import store
        return store.Run.create(tmp_path, "acme.com")

    def test_a_candidate_becomes_a_JS_URL(self, tmp_path, monkeypatch):
        art = tmp_path / "b.js"
        art.write_text('var r={};r.p="/assets/";')
        monkeypatch.setattr(crawl, "have", lambda _b: True)
        monkeypatch.setattr(crawl, "_jxscout_analyze",
                            lambda c, a, limit, timeout=60: (["chunks/lazy.js"], "success", None))
        run = self._run(tmp_path)
        added = crawl._jxscout_chunks(self._ctx(tmp_path, run),
                                      self._ledger([("https://acme.com/js/main.js", art)]))
        assert added == 1
        assert run.values("js_url") == ["https://acme.com/assets/chunks/lazy.js"]

    def test_an_OOS_chunk_is_observed_but_never_QUEUED(self, tmp_path, monkeypatch):
        art = tmp_path / "b.js"; art.write_text("x")
        monkeypatch.setattr(crawl, "have", lambda _b: True)
        monkeypatch.setattr(crawl, "_jxscout_analyze",
                            lambda c, a, limit, timeout=60: (["https://cdn.other/x.js"], "success", None))
        run = self._run(tmp_path)
        assert crawl._jxscout_chunks(self._ctx(tmp_path, run),
                                     self._ledger([("https://acme.com/js/main.js", art)])) == 0
        assert run.values("js_url") == []

    def test_the_lane_FETCHES_nothing_itself(self, tmp_path, monkeypatch):
        """Its whole contract is candidate production: the fetch, the rate and the budget belong to the
        JS lane, which is also where resume lives."""
        art = tmp_path / "b.js"; art.write_text("x")
        monkeypatch.setattr(crawl, "have", lambda _b: True)
        monkeypatch.setattr(crawl, "_jxscout_analyze",
                            lambda c, a, limit, timeout=60: (["chunks/a.js"], "success", None))
        monkeypatch.setattr(crawl.fetch, "scoped_get",
                            lambda *a, **k: pytest.fail("the lane made a request"))
        crawl._jxscout_chunks(self._ctx(tmp_path, self._run(tmp_path)),
                              self._ledger([("https://acme.com/js/main.js", art)]))

    def test_a_bundle_is_analysed_ONCE_across_rounds(self, tmp_path, monkeypatch):
        art = tmp_path / "b.js"; art.write_text("x")
        seen = []
        monkeypatch.setattr(crawl, "have", lambda _b: True)
        monkeypatch.setattr(crawl, "_jxscout_analyze",
                            lambda c, a, limit, timeout=60: (seen.append(a) or (["c.js"], "success", None)))
        run = self._run(tmp_path)
        ctx = self._ctx(tmp_path, run)
        led = self._ledger([("https://acme.com/js/main.js", art)])
        crawl._jxscout_chunks(ctx, led)
        crawl._jxscout_chunks(ctx, self._ledger([("https://acme.com/js/main.js", art)]))
        assert len(seen) == 1, "re-analysing the same artifact re-pays for it every round"

    def test_a_MISSING_tool_with_work_to_do_is_a_recorded_skip(self, tmp_path, monkeypatch):
        monkeypatch.setattr(crawl, "have", lambda _b: False)
        run = self._run(tmp_path)
        art = tmp_path / "b.js"; art.write_text("x")
        assert crawl._jxscout_chunks(self._ctx(tmp_path, run),
                                     self._ledger([("https://acme.com/js/main.js", art)])) == 0
        assert any(r.tool == crawl.JXSCOUT_SHIM for r in run._tool_runs), \
            "an absent optional tool is a recorded SKIP, never silence"

    def test_a_MISSING_tool_with_NO_work_is_a_clean_zero(self, tmp_path, monkeypatch):
        """Capability only matters once the lane has bundles to read. Asking first made an absent
        OPTIONAL tool a dependency failure on every run with no JS at all."""
        monkeypatch.setattr(crawl, "have", lambda _b: False)
        run = self._run(tmp_path)
        ctx = self._ctx(tmp_path, run)
        assert crawl._jxscout_chunks(ctx, self._ledger([])) == 0
        assert not run._tool_runs, "nothing to skip, so nothing to report"
        assert not getattr(ctx, "_jxscout_stats", {}).get("dispositions")


class TestDispositionsAreNotGuesses:
    """Every ending is recorded through the contract, and each one means something different. The child
    writes its candidates to a FILE it cannot overrun — the runner reads stdout into Quarry's own memory,
    where no limit of the child's applies."""

    @staticmethod
    def _fake(monkeypatch, tmp_path, *, exit_code=0, out="", status=None, size=None):
        from quarry_recon.runner import RunResult, Status
        from quarry_recon import store
        _stub_shim(monkeypatch, tmp_path)

        def fake_contract(source_id, cmd, work_unit=None, timeout=None, env=None, **kw):
            # the command ends with `sh -c '... > <file>'`: write what the child would have written
            dest = pathlib.Path(cmd[-1].split("> ", 1)[1].split(" 2> ")[0].strip("'"))
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(out if size is None else "x" * size)
            return RunResult(source_id, cmd,
                             status or (Status.SUCCESS if exit_code == 0 else Status.FAILED),
                             exit_code, 0.1, None, len(out.splitlines()))
        monkeypatch.setattr(crawl, "run_contract", fake_contract)
        run = store.Run.create(tmp_path, "acme.com")
        return type("C", (), {"run": run})(), run

    def test_a_clean_run_with_candidates_is_SUCCESS(self, tmp_path, monkeypatch):
        ctx, _ = self._fake(monkeypatch, tmp_path, out="a.js\nb.js\n")
        cands, disp, _res = crawl._jxscout_analyze(ctx, tmp_path / "x.js", 0)
        assert (cands, disp) == (["a.js", "b.js"], "success")

    def test_a_clean_run_with_none_is_EMPTY_and_that_is_ambiguous(self, tmp_path, monkeypatch):
        """The parser is error-TOLERANT: a bundle it could not understand exits 0 with nothing, exactly
        like one that genuinely declares no chunks. `empty` may never be read as proof."""
        ctx, _ = self._fake(monkeypatch, tmp_path, out="")
        assert crawl._jxscout_analyze(ctx, tmp_path / "x.js", 0)[1] == "empty"

    def test_exit_1_is_the_ENGINE_refusing(self, tmp_path, monkeypatch):
        ctx, _ = self._fake(monkeypatch, tmp_path, exit_code=1, out="")
        assert crawl._jxscout_analyze(ctx, tmp_path / "x.js", 0)[1] == "engine-error"

    def test_a_SIGNAL_is_a_gap_not_an_answer(self, tmp_path, monkeypatch):
        """A memory or output kill can be entirely silent. Reading that as 'no chunks' would certify
        coverage of a bundle nobody analysed."""
        ctx, _ = self._fake(monkeypatch, tmp_path, exit_code=-9, out="")
        assert crawl._jxscout_analyze(ctx, tmp_path / "x.js", 0)[1] == "killed"

    def test_a_TIMEOUT_is_its_own_disposition(self, tmp_path, monkeypatch):
        from quarry_recon.runner import Status
        ctx, _ = self._fake(monkeypatch, tmp_path, exit_code=-15, out="", status=Status.TIMED_OUT)
        assert crawl._jxscout_analyze(ctx, tmp_path / "x.js", 0)[1] == "timeout"

    def test_hitting_the_output_CEILING_is_a_remainder_not_a_result(self, tmp_path, monkeypatch):
        """Truncating to the first N rows and calling it success reports a coverage number nobody
        measured: what else the bundle named was cut off, so it is UNKNOWN."""
        ctx, _ = self._fake(monkeypatch, tmp_path, size=crawl._JXSCOUT_OUTPUT_MB * 1024 * 1024)
        assert crawl._jxscout_analyze(ctx, tmp_path / "x.js", 0)[1] == "truncated"

    def test_NO_SANDBOX_means_the_lane_does_not_run(self, tmp_path, monkeypatch):
        monkeypatch.setattr(crawl, "_jxscout_sandbox", lambda c, o, e: [])
        monkeypatch.setattr(crawl, "run_contract",
                            lambda *a, **k: pytest.fail("ran the analyzer uncontained"))
        from quarry_recon import store
        ctx = type("C", (), {"run": store.Run.create(tmp_path, "acme.com")})()
        cands, disp, res = crawl._jxscout_analyze(ctx, tmp_path / "x.js", 0)
        assert (cands, disp) == ([], "no-sandbox") and "EVALUATES" in (res.note or "")

    def test_the_filesystem_is_an_ALLOW_LIST_not_the_host(self, tmp_path, monkeypatch):
        """Read-only is not unavailable. `--ro-bind / /` stopped writes and left every readable file on
        the host available to code we deliberately evaluate — Quarry's own secrets.yaml, SSH material,
        prior engagements' evidence — and the containment has to hold even if the interpreter is
        escaped."""
        _stub_shim(monkeypatch, tmp_path)
        if not crawl.shutil.which("bwrap"):
            pytest.skip("bwrap not installed on this host")
        (tmp_path / "b.js").write_text("x")
        cmd = crawl._jxscout_sandbox([crawl.JXSCOUT_SHIM, str(tmp_path / "b.js"), "0"],
                                     tmp_path / "out.txt", tmp_path / "err.txt")
        assert cmd, "the builder refused with bwrap present — the containment claim is untested"
        assert "--ro-bind" in cmd and cmd[cmd.index("--ro-bind") + 1] != "/", "the host root is mounted"
        assert "/" not in [cmd[i + 1] for i, a in enumerate(cmd) if a in ("--ro-bind", "--bind")]
        joined = " ".join(cmd)
        assert "--unshare-all" in cmd and "--clearenv" in cmd, \
            "an inherited env hands provider keys to target code"
        # the ONE writable path, and the ONE input
        binds = [cmd[i + 1] for i, a in enumerate(cmd) if a == "--bind"]
        assert binds == [str(tmp_path)], binds
        assert str(tmp_path / "b.js") in joined

    @pytest.mark.integration          # spawns the REAL sandbox: the claim is about the namespace itself
    @pytest.mark.skipif(not __import__("shutil").which("bwrap"), reason="bwrap not installed")
    @pytest.mark.parametrize("path", [".config/quarry/secrets.yaml", ".ssh", "workspace"])
    def test_the_operators_own_files_are_NOT_in_the_namespace(self, tmp_path, monkeypatch, path):
        """Measured through the real sandbox: not merely unwritable — absent."""
        import subprocess
        _stub_shim(monkeypatch, tmp_path)
        (tmp_path / "b.js").write_text("x")
        cmd = crawl._jxscout_sandbox(["jxscout-chunks", str(tmp_path / "b.js"), "0"],
                                     tmp_path / "out.txt", tmp_path / "err.txt")
        target = str(pathlib.Path.home() / path)
        probe = cmd[:cmd.index("sh")] + ["sh", "-c", f"ls -d {target} 2>&1 || true"]
        got = subprocess.run(probe, capture_output=True, text=True, timeout=60).stdout
        assert target not in got.split("\n")[0] or "No such file" in got, got[:120]

    def test_the_sandbox_carries_EVERY_measured_limit(self, tmp_path, monkeypatch):
        """Isolation is not containment: the probe measured that a counting loop runs to the wall clock,
        that Buffers escape the heap flag, and that output must be bounded in the CHILD."""
        _stub_shim(monkeypatch, tmp_path)
        if not crawl.shutil.which("bwrap"):
            pytest.skip("bwrap not installed on this host")
        (tmp_path / "b.js").write_text("x")
        cmd = crawl._jxscout_sandbox([crawl.JXSCOUT_SHIM, str(tmp_path / "b.js"), "0"],
                                     tmp_path / "out.txt", tmp_path / "err.txt")
        assert cmd, "the builder refused with bwrap present — the containment claim is untested"
        joined = " ".join(cmd)
        assert "--unshare-all" in cmd and "--die-with-parent" in cmd
        assert f"ulimit -v {crawl._JXSCOUT_ADDRESS_SPACE_MB * 1024}" in joined
        assert f"ulimit -f {crawl._JXSCOUT_OUTPUT_MB * 2048}" in joined
        assert f"--max-old-space-size={crawl._JXSCOUT_HEAP_MB}" in joined, \
            "the heap cap rides in the sandbox now that the env is cleared"
        assert f"> {tmp_path / 'out.txt'}" in joined, \
            "candidates must land in a bounded FILE, not in Quarry's own stdout buffer"
        assert f"2> {tmp_path / 'err.txt'}" in joined, \
            "stderr is captured through a PIPE by the runner — unbounded in OUR memory unless redirected"
        assert "--bind" in cmd and str(tmp_path) in cmd, "exactly one writable path"

    def test_the_node_HEAP_is_capped_inside_the_SANDBOX(self, tmp_path, monkeypatch):
        """It used to ride in the runner's `env=`, which `--clearenv` now wipes — so the sandbox has to
        set it, or the cap silently stops applying."""
        seen = {}
        _stub_shim(monkeypatch, tmp_path)

        def fake_contract(source_id, cmd, work_unit=None, timeout=None, env=None, **kw):
            from quarry_recon.runner import RunResult, Status
            seen["cmd"] = list(cmd)
            pathlib.Path(cmd[-1].split("> ", 1)[1].split(" 2> ")[0].strip("'")).write_text("")
            return RunResult(source_id, cmd, Status.SUCCESS, 0, 0.1, None, 0)
        monkeypatch.setattr(crawl, "run_contract", fake_contract)
        from quarry_recon import store
        (tmp_path / "x.js").write_text("x")
        ctx = type("C", (), {"run": store.Run.create(tmp_path, "acme.com")})()
        crawl._jxscout_analyze(ctx, tmp_path / "x.js", 0)
        joined = " ".join(seen["cmd"])
        if "bwrap" not in joined:
            pytest.skip("bwrap not installed on this host")
        assert "--clearenv" in joined, "an inherited env hands provider keys to target code"
        assert f"--max-old-space-size={crawl._JXSCOUT_HEAP_MB}" in joined

    def test_every_invocation_is_RECORDED(self, tmp_path, monkeypatch):
        """A phase may not hide a subprocess: the manifest must show this tool ran."""
        ctx, run = self._fake(monkeypatch, tmp_path, out="chunks/a.js\n")
        art = tmp_path / "b.js"; art.write_text("x")
        monkeypatch.setattr(crawl, "have", lambda _b: True)
        full = type("C", (), {"run": run, "scope": _Scope(), "echo": lambda *a, **k: None,
                              "profile": type("P", (), {"js_chunk_brute": 0})()})()
        crawl._jxscout_chunks(full, type("L", (), {
            "items": lambda self=None: iter([("https://acme.com/js/main.js", art)])})())
        assert any(r.tool == "crawl.jxscout_chunks" for r in run._tool_runs)


class TestTheWritablePathIsPRIVATEToEachInvocation:
    """Bundles are mutually untrusted. Sharing one writable output directory between them let bundle N
    rewrite, truncate or delete bundle N-1's artifacts — inventing candidates attributed to another
    bundle, inside the evidence trail the sandbox exists to protect."""

    @staticmethod
    def _recorder(monkeypatch, tmp_path, *, out="a.js\n", err="", publish=True):
        """Runs the REAL analyze path, capturing what the sandbox was actually pointed at."""
        from quarry_recon.runner import RunResult, Status
        _stub_shim(monkeypatch, tmp_path)
        seen: list = []

        def fake_contract(source_id, cmd, work_unit=None, timeout=None, **kw):
            joined = " ".join(cmd)
            binds = [cmd[i + 1] for i, a in enumerate(cmd) if a == "--bind"]
            dest = pathlib.Path(cmd[-1].split("> ", 1)[1].split(" 2> ")[0].strip("'"))
            edest = pathlib.Path(cmd[-1].rsplit("2> ", 1)[1].strip().strip("'"))
            # what the sandbox can WRITE TO, and what was already sitting there when it started
            seen.append({"cmd": cmd, "binds": binds, "argv": joined, "out": dest, "err": edest,
                         "visible": sorted(x.name for b in binds for x in pathlib.Path(b).iterdir())})
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(out)
            if err:
                edest.write_text(err)
            return RunResult(source_id, cmd, Status.SUCCESS, 0, 0.1, None, len(out.splitlines()))
        monkeypatch.setattr(crawl, "run_contract", fake_contract)
        if not publish:
            monkeypatch.setattr(crawl.budget, "publish_bytes", lambda *a, **k: False)
        return seen

    def test_the_bind_is_NOT_the_shared_evidence_DIRECTORY(self, tmp_path, monkeypatch):
        from quarry_recon import store
        seen = self._recorder(monkeypatch, tmp_path)
        run = store.Run.create(tmp_path, "acme.com")
        (tmp_path / "x.js").write_text("x")
        crawl._jxscout_analyze(type("C", (), {"run": run})(), tmp_path / "x.js", 0)
        if "bwrap" not in seen[0]["argv"]:
            pytest.skip("bwrap not installed on this host")
        shared = run.raw_path("crawl", "jxscout", "x.txt").parent
        assert seen[0]["binds"] and str(shared) not in seen[0]["binds"], seen[0]["binds"]
        assert str(run.dir) not in seen[0]["argv"], \
            "the run's evidence tree must not be in the namespace at all"

    def test_a_LATER_bundle_cannot_see_an_EARLIER_ones_artifacts(self, tmp_path, monkeypatch):
        """The measurable claim: what the second invocation could reach when it started."""
        from quarry_recon import store
        seen = self._recorder(monkeypatch, tmp_path)
        run = store.Run.create(tmp_path, "acme.com")
        ctx = type("C", (), {"run": run})()
        for name in ("first.js", "second.js"):
            (tmp_path / name).write_text("x")
            crawl._jxscout_analyze(ctx, tmp_path / name, 0)
        if "bwrap" not in seen[0]["argv"]:
            pytest.skip("bwrap not installed on this host")
        assert seen[0]["binds"] != seen[1]["binds"], "one shared scratch is one tamperable evidence dir"
        assert seen[1]["visible"] == [], seen[1]["visible"]
        assert str(seen[0]["out"]) not in seen[1]["argv"]
        for rec in seen:                                       # and nothing survives the invocation
            assert not any(pathlib.Path(b).exists() for b in rec["binds"])

    def test_the_artifact_is_PUBLISHED_into_the_run_tree(self, tmp_path, monkeypatch):
        """Private is not disposable: the evidence still has to land where the manifest points."""
        from quarry_recon import store
        seen = self._recorder(monkeypatch, tmp_path, out="chunks/a.js\n", err="boom\n")
        run = store.Run.create(tmp_path, "acme.com")
        (tmp_path / "x.js").write_text("x")
        cands, disp, res = crawl._jxscout_analyze(type("C", (), {"run": run})(), tmp_path / "x.js", 0)
        if "bwrap" not in seen[0]["argv"]:
            pytest.skip("bwrap not installed on this host")
        published = run.raw_path("crawl", "jxscout", "x.txt")
        assert (cands, disp) == (["chunks/a.js"], "success")
        assert published.read_text() == "chunks/a.js\n"
        assert run.raw_path("crawl", "jxscout", "x.stderr.txt").read_text() == "boom\n"
        assert res.raw_path == published, "the manifest must name the artifact that survived"

    def test_evidence_that_did_NOT_land_is_never_counted_ANALYSED(self, tmp_path, monkeypatch):
        """A failed publication keeps the candidates (suppressing real discovery over a disk fault would
        be worse) but never certifies the bundle: it stays owed, and retriable."""
        from quarry_recon import events, store
        seen = self._recorder(monkeypatch, tmp_path, out="chunks/a.js\n", publish=False)
        run = store.Run.create(tmp_path, "acme.com")
        events.configure(run.dir)
        try:
            art = tmp_path / "x.js"; art.write_text("x")
            cands, disp, res = crawl._jxscout_analyze(type("C", (), {"run": run})(), art, 0)
            if "bwrap" not in seen[0]["argv"]:
                pytest.skip("bwrap not installed on this host")
            assert (cands, disp) == (["chunks/a.js"], "unpublished")
            assert res.raw_path is None, "an artifact we could not prove landed may not be named"
            monkeypatch.setattr(crawl, "have", lambda _b: True)
            ctx = type("C", (), {"run": run, "scope": _Scope(), "echo": lambda *a, **k: None,
                                 "profile": type("P", (), {"js_chunk_brute": 0})()})()
            added = crawl._jxscout_chunks(ctx, type("L", (), {
                "items": lambda self=None: iter([("https://acme.com/js/main.js", art)])})())
            run.write_manifest(profile_summary={}, phases_run=["crawl"])
            cov = [c for c in run._run_summary()["coverage"]
                   if c["source_id"] == "crawl.jxscout_chunks"][0]
            assert added == 1, "the candidate is real; only its evidence copy failed"
            assert (cov["tested"], cov["omitted"]) == (0, 1) and "unpublished=1" in cov["reason"], cov
        finally:
            events.reset()

    @pytest.mark.integration          # spawns the REAL sandbox: the claim is about the namespace itself
    @pytest.mark.skipif(not __import__("shutil").which("bwrap"), reason="bwrap not installed")
    def test_the_evidence_TREE_is_absent_from_the_real_namespace(self, tmp_path, monkeypatch):
        import subprocess
        import tempfile
        from quarry_recon import store
        seen = self._recorder(monkeypatch, tmp_path)
        run = store.Run.create(tmp_path, "acme.com")
        (tmp_path / "x.js").write_text("x")
        crawl._jxscout_analyze(type("C", (), {"run": run})(), tmp_path / "x.js", 0)
        published = run.raw_path("crawl", "jxscout", "x.txt")
        assert published.exists() and published.read_text(), "it really is there, on the host"
        dead = seen[0]["binds"][0]
        assert not pathlib.Path(dead).exists(), "the first scratch does not outlive its invocation"
        # a LATER bundle, built exactly as the lane builds it, asks for the earlier one's evidence
        with tempfile.TemporaryDirectory(prefix="quarry-jxscout-") as later:
            (tmp_path / "y.js").write_text("y")
            cmd = crawl._jxscout_sandbox(["jxscout-chunks", str(tmp_path / "y.js"), "0"],
                                         pathlib.Path(later) / "out.txt", pathlib.Path(later) / "err.txt")
            probe = cmd[:cmd.index("sh")] + [
                "sh", "-c", f"ls -d {published} {published.parent} {run.dir} {dead}; "
                            f"echo rc=$?; : > {published} 2>&1 || echo 'write refused'"]
            done = subprocess.run(probe, capture_output=True, text=True, timeout=60)
            got = done.stdout + done.stderr
        assert str(published) not in got.split("rc=")[0], got[:300]
        assert got.count("No such file") >= 4, got[:300]        # every one of the four, absent
        assert dead not in got.split("rc=")[0], "a dead scratch must not reappear either"
        assert published.read_text(), "the earlier artifact is intact after a later bundle ran"


class TestGuessingIsEngagementPolicy:
    def test_the_default_NEVER_guesses(self):
        assert crawl.JXSCOUT_BRUTE_LIMIT == 0

    def test_UNBOUND_does_not_lift_it(self):
        """`--unbound` uses the work a run already HAS. A guessed chunk id is a new request for a path no
        bundle ever named, so no flag may turn it on."""
        assert policy.by_name("JXSCOUT_BRUTE_LIMIT") is None
        assert "quarry_recon.phases.crawl:JXSCOUT_BRUTE_LIMIT" in policy.EXCLUDED
        assert policy.EXCLUDED["quarry_recon.phases.crawl:JXSCOUT_BRUTE_LIMIT"][0] == "engagement"
        with settings.overrides(policy.unbound_overrides()):
            assert "JXSCOUT_BRUTE_LIMIT" not in policy.unbound_overrides()

    def test_the_profile_carries_it(self, tmp_path):
        from quarry_recon.config import TargetProfile
        prof = tmp_path / "t.yaml"
        prof.write_text("TARGET: acme\nAPEX_DOMAINS:\n  - acme.com\nMODES:\n  JS_CHUNK_BRUTE: 50\n")
        assert TargetProfile.load(prof).js_chunk_brute == 50

    def test_an_out_of_range_value_FAILS_LOUD(self, tmp_path):
        from quarry_recon.config import ProfileError, TargetProfile
        prof = tmp_path / "t.yaml"
        prof.write_text("TARGET: acme\nAPEX_DOMAINS:\n  - acme.com\nMODES:\n  JS_CHUNK_BRUTE: 999999\n")
        with pytest.raises(ProfileError, match="JS_CHUNK_BRUTE"):
            TargetProfile.load(prof)

    def test_the_ROUNDS_bound_is_registered_and_relaxable(self):
        b = policy.by_name("JXSCOUT_ROUNDS")
        assert b and b.relaxable and b.unbounded_value == 0 and b.consumer_honours_unbounded
        assert b.lane == "crawl.jxscout_chunks"


class TestTheKnobActuallyREACHESTheAnalyzer:
    """It was read through a `settings` helper that does not exist, so the fallback pinned it to 0 and
    `MODES.JS_CHUNK_BRUTE` had no effect at all — a knob an operator could set and never observe."""

    @staticmethod
    def _seen_limit(tmp_path, monkeypatch, brute):
        from quarry_recon import store
        from quarry_recon.runner import RunResult, Status
        _stub_shim(monkeypatch, tmp_path)
        seen = []

        def fake_contract(source_id, cmd, work_unit=None, timeout=None, env=None, **kw):
            seen.append(cmd)
            pathlib.Path(cmd[-1].split("> ", 1)[1].split(" 2> ")[0].strip("'")).write_text("")
            return RunResult(source_id, cmd, Status.SUCCESS, 0, 0.1, None, 0)

        monkeypatch.setattr(crawl, "run_contract", fake_contract)
        monkeypatch.setattr(crawl, "have", lambda _b: True)
        run = store.Run.create(tmp_path, "acme.com")
        art = tmp_path / "b.js"; art.write_text("x")
        ctx = type("C", (), {"run": run, "scope": _Scope(), "echo": lambda *a, **k: None,
                             "profile": type("P", (), {"js_chunk_brute": brute})()})()
        crawl._jxscout_chunks(ctx, type("L", (), {
            "items": lambda self=None: iter([("https://acme.com/js/main.js", art)])})())
        return " ".join(seen[0])

    @pytest.mark.parametrize("brute", [0, 1, 3000])
    def test_the_profile_value_is_what_the_analyzer_RECEIVES(self, tmp_path, monkeypatch, brute):
        joined = self._seen_limit(tmp_path, monkeypatch, brute)
        assert f"jxscout-chunks /" in joined and joined.rstrip("'").endswith(str(brute)) or \
            f" {brute} >" in joined, joined

    def test_the_DEFAULT_never_guesses(self, tmp_path, monkeypatch):
        assert " 0 >" in self._seen_limit(tmp_path, monkeypatch, 0)


class TestTheRoundBoundIsAREMAINDER:
    """Entities are run-scoped, so a traversal the bound cut short does NOT continue in a later run — the
    next run rediscovers the root and repeats the same rounds. Claiming resumable progress there would
    hide a chunk that is fetched and never analysed."""

    def test_a_cut_traversal_is_reported_as_an_unresolved_remainder(self, tmp_path, monkeypatch):
        from quarry_recon import events, store
        run = store.Run.create(tmp_path, "acme.com")
        events.configure(run.dir)
        try:
            monkeypatch.setattr(crawl, "_js_download", lambda ctx: (None, None))
            monkeypatch.setattr(crawl, "_jxscout_chunks", lambda ctx, led: 2)   # always still producing
            monkeypatch.setattr(crawl.policy, "limit", lambda name: 3 if name == "JXSCOUT_ROUNDS" else 0)
            ctx = type("C", (), {"run": run, "scope": _Scope(), "echo": lambda *a, **k: None,
                                 "profile": type("P", (), {"js_chunk_brute": 0})()})()
            # drive just the loop the phase runs
            rounds, owed, rnd = crawl.policy.limit("JXSCOUT_ROUNDS"), 0, 0
            while rounds <= 0 or rnd < rounds:
                rnd += 1
                owed = crawl._jxscout_chunks(ctx, None)
                if not owed:
                    break
            assert owed and rnd == 3, "the bound, not the fixed point, stopped it"
        finally:
            events.reset()

    def test_the_bound_does_not_CLAIM_resumability(self):
        b = policy.by_name("JXSCOUT_ROUNDS")
        assert "NOTHING carries" in b.persistence and "remainder" in b.persistence


class TestCoverageAccumulatesAcrossRounds:
    """Each round publishes under the same (lane, unit, measure) identity, and folding keeps the LATEST —
    so a killed bundle in round 1 disappeared the moment a clean round 2 was published."""

    def test_a_round_1_failure_SURVIVES_a_clean_round_2(self, tmp_path, monkeypatch):
        from quarry_recon import events, store
        run = store.Run.create(tmp_path, "acme.com")
        events.configure(run.dir)
        try:
            a1, a2 = tmp_path / "one.js", tmp_path / "two.js"
            a1.write_text("x"); a2.write_text("y")
            outcomes = {str(a1): ([], "killed", None), str(a2): (["chunks/c.js"], "success", None)}
            monkeypatch.setattr(crawl, "have", lambda _b: True)
            monkeypatch.setattr(crawl, "_jxscout_analyze",
                                lambda c, art, limit, timeout=60: outcomes[str(art)])
            ctx = type("C", (), {"run": run, "scope": _Scope(), "echo": lambda *a, **k: None,
                                 "profile": type("P", (), {"js_chunk_brute": 0})()})()
            crawl._jxscout_chunks(ctx, type("L", (), {
                "items": lambda self=None: iter([("https://acme.com/js/a.js", a1)])})())
            crawl._jxscout_chunks(ctx, type("L", (), {
                "items": lambda self=None: iter([("https://acme.com/js/a.js", a1),
                                                 ("https://acme.com/js/b.js", a2)])})())
            run.write_manifest(profile_summary={}, phases_run=["crawl"])
            cov = [c for c in run._run_summary()["coverage"]
                   if c["source_id"] == "crawl.jxscout_chunks"][0]
            assert "killed=1" in cov["reason"], f"round 1's kill was erased: {cov['reason']}"
            assert cov["omitted"] == 1 and cov["eligible"] == 2
        finally:
            events.reset()


class TestTheRemainingClaims:
    def test_the_CONSOLE_reports_the_same_shortfall_as_the_manifest(self, tmp_path, monkeypatch):
        """`attempted - analysed` counted only the bundle we tried, so a shared refusal over ten printed
        "1 not analysed" beside a manifest saying ten."""
        from quarry_recon import events, store
        run = store.Run.create(tmp_path, "acme.com")
        events.configure(run.dir)
        said = []
        try:
            arts = []
            for i in range(10):
                a = tmp_path / f"c{i}.js"; a.write_text("x"); arts.append((f"https://acme.com/{i}.js", a))
            monkeypatch.setattr(crawl, "have", lambda _b: True)
            monkeypatch.setattr(crawl, "_jxscout_analyze",
                                lambda c, art, limit, timeout=60: ([], "no-sandbox", None))
            ctx = type("C", (), {"run": run, "scope": _Scope(), "echo": said.append,
                                 "profile": type("P", (), {"js_chunk_brute": 0})()})()
            crawl._jxscout_chunks(ctx, type("L", (), {"items": lambda self=None: iter(arts)})())
            run.write_manifest(profile_summary={}, phases_run=["crawl"])
            cov = [c for c in run._run_summary()["coverage"]
                   if c["source_id"] == "crawl.jxscout_chunks"][0]
            assert "10 not analysed" in " ".join(said), said
            assert cov["omitted"] == 10
        finally:
            events.reset()

    def test_a_SHARED_refusal_belongs_to_every_bundle_it_stopped(self, tmp_path, monkeypatch):
        """With no sandbox the loop stops after the first bundle. Counting only that one reported nine of
        ten bundles as covered when NONE was analysed."""
        from quarry_recon import events, store
        run = store.Run.create(tmp_path, "acme.com")
        events.configure(run.dir)
        try:
            arts = []
            for i in range(10):
                a = tmp_path / f"b{i}.js"; a.write_text("x"); arts.append((f"https://acme.com/{i}.js", a))
            monkeypatch.setattr(crawl, "have", lambda _b: True)
            monkeypatch.setattr(crawl, "_jxscout_analyze",
                                lambda c, art, limit, timeout=60: ([], "no-sandbox", None))
            ctx = type("C", (), {"run": run, "scope": _Scope(), "echo": lambda *a, **k: None,
                                 "profile": type("P", (), {"js_chunk_brute": 0})()})()
            crawl._jxscout_chunks(ctx, type("L", (), {"items": lambda self=None: iter(arts)})())
            run.write_manifest(profile_summary={}, phases_run=["crawl"])
            cov = [c for c in run._run_summary()["coverage"]
                   if c["source_id"] == "crawl.jxscout_chunks"][0]
            assert cov["omitted"] == 10 and cov["tested"] == 0, cov
            assert "no-sandbox=10" in cov["reason"]
        finally:
            events.reset()

    def test_a_cut_traversal_reports_UNKNOWN_depth_not_one_more_round(self, tmp_path, monkeypatch):
        """Driven through the REAL loop. A round that was still producing proves another round is
        reachable and nothing about how many remain — a chain needing a hundred more looks exactly like
        one needing one."""
        from quarry_recon import events, store
        run = store.Run.create(tmp_path, "acme.com")
        events.configure(run.dir)
        try:
            monkeypatch.setattr(crawl.policy, "limit",
                                lambda n: 3 if n == "JXSCOUT_ROUNDS" else 0)
            monkeypatch.setattr(crawl, "_jxscout_chunks", lambda ctx, led: 2)   # never converges
            monkeypatch.setattr(crawl, "_js_download", lambda ctx: ("led", "dir"))
            ctx = type("C", (), {"run": run, "scope": _Scope(), "echo": lambda *a, **k: None,
                                 "profile": type("P", (), {"js_chunk_brute": 0})()})()
            crawl._jxscout_traverse(ctx, "led0", "dir0")
            run.write_manifest(profile_summary={}, phases_run=["crawl"])
            cov = [c for c in run._run_summary()["coverage"] if c["measure"] == "rounds"][0]
            assert not cov["valid"], "an unknown remainder must not carry an exact denominator"
            assert "UNKNOWN" in cov["reason"] and "JXSCOUT_ROUNDS=3" in cov["reason"]
        finally:
            events.reset()

    def test_a_traversal_that_CONVERGES_reports_no_remainder(self, tmp_path, monkeypatch):
        from quarry_recon import events, store
        run = store.Run.create(tmp_path, "acme.com")
        events.configure(run.dir)
        try:
            calls = {"n": 0}

            def chunks(ctx, led):
                calls["n"] += 1
                return 1 if calls["n"] == 1 else 0
            monkeypatch.setattr(crawl.policy, "limit", lambda n: 3 if n == "JXSCOUT_ROUNDS" else 0)
            monkeypatch.setattr(crawl, "_jxscout_chunks", chunks)
            monkeypatch.setattr(crawl, "_js_download", lambda ctx: ("led", "dir"))
            ctx = type("C", (), {"run": run, "scope": _Scope(), "echo": lambda *a, **k: None,
                                 "profile": type("P", (), {"js_chunk_brute": 0})()})()
            assert crawl._jxscout_traverse(ctx, "led0", "dir0") == ("led", "dir")
            run.write_manifest(profile_summary={}, phases_run=["crawl"])
            assert not [c for c in run._run_summary()["coverage"] if c["measure"] == "rounds"]
        finally:
            events.reset()

    @pytest.mark.parametrize("bad", ["50", 1.9, "true", [], 3.0])
    def test_the_PROPERTY_refuses_a_non_integer_too(self, bad):
        """Validation catches a bad profile on load; the property is what every consumer actually reads,
        and coercing there would let a value that never passed validation authorise requests."""
        prof = type("P", (), {"modes": {"JS_CHUNK_BRUTE": bad}})()
        from quarry_recon.config import TargetProfile
        assert TargetProfile.js_chunk_brute.fget(prof) == 0, bad

    @pytest.mark.parametrize("bad", ["50", 1.9, "true", [], 3.0])
    def test_a_non_INTEGER_brute_value_is_refused(self, tmp_path, bad):
        from quarry_recon.config import ProfileError, TargetProfile
        prof = tmp_path / "t.yaml"
        prof.write_text(f"TARGET: acme\nAPEX_DOMAINS:\n  - acme.com\nMODES:\n  JS_CHUNK_BRUTE: {bad!r}\n")
        with pytest.raises(ProfileError, match="JS_CHUNK_BRUTE"):
            TargetProfile.load(prof)

    def test_only_the_stderr_TAIL_is_ever_read(self, tmp_path, monkeypatch):
        """The file is bounded by `ulimit -f`; OUR memory is bounded only by reading the tail. A head
        marker reaching the note proves the whole file was read into this process."""
        from quarry_recon import store
        from quarry_recon.runner import RunResult, Status
        _stub_shim(monkeypatch, tmp_path)

        def fake_contract(source_id, cmd, work_unit=None, timeout=None, env=None, **kw):
            errp = pathlib.Path(cmd[-1].split(" 2> ")[1].strip("'"))
            pathlib.Path(cmd[-1].split("> ", 1)[1].split(" 2> ")[0].strip("'")).write_text("")
            errp.write_text("HEADMARKER" + "E" * 100_000 + "TAILMARKER")
            return RunResult(source_id, cmd, Status.FAILED, 1, 0.1, None, 0)
        monkeypatch.setattr(crawl, "run_contract", fake_contract)
        ctx = type("C", (), {"run": store.Run.create(tmp_path, "acme.com")})()
        _c, disp, res = crawl._jxscout_analyze(ctx, tmp_path / "x.js", 0)
        note = res.note or ""
        assert disp == "engine-error" and "TAILMARKER" in note
        assert "HEADMARKER" not in note, "the whole stderr was read into Quarry's memory"
        assert f"[stderr {crawl._JXSCOUT_STDERR_TAIL}B tail]" in note, \
            f"more than the tail was READ into memory: {note[:80]}"
        assert len(note) <= 600


class TestTheSupervisorCanSEEThisLane:
    """`--settle` learns what a lane still owes from REMAINDER events, not from prose. A lane that never
    emits one is UNKNOWN to it for ever — and this traversal genuinely owes work when the bound cuts it."""

    def _traverse(self, tmp_path, monkeypatch, *, owed_rounds, dispositions=None):
        from quarry_recon import events, store
        run = store.Run.create(tmp_path, "acme.com")
        events.configure(run.dir)
        calls = {"n": 0}

        def chunks(ctx, led):
            calls["n"] += 1
            d = dict(dispositions or {"success": 3})
            ctx._jxscout_stats = {"eligible": sum(d.values()), "attempted": sum(d.values()),
                                  "analysed": d.get("success", 0) + d.get("empty", 0),
                                  "dispositions": d}
            return 2 if calls["n"] <= owed_rounds else 0
        monkeypatch.setattr(crawl.policy, "limit", lambda n: 3 if n == "JXSCOUT_ROUNDS" else 0)
        monkeypatch.setattr(crawl, "_jxscout_chunks", chunks)
        monkeypatch.setattr(crawl, "_js_download", lambda ctx: ("led", "dir"))
        ctx = type("C", (), {"run": run, "scope": _Scope(), "echo": lambda *a, **k: None,
                             "profile": type("P", (), {"js_chunk_brute": 0})()})()
        crawl._jxscout_traverse(ctx, "led0", "dir0")
        run.write_manifest(profile_summary={}, phases_run=["crawl"])
        rows = {r["measure"]: r for r in run._run_summary()["remainders"]
                if r.get("lane") == "crawl.jxscout_chunks"}
        events.reset()
        return rows

    def test_a_cut_traversal_OWES_work(self, tmp_path, monkeypatch):
        row = self._traverse(tmp_path, monkeypatch, owed_rounds=99)["rounds"]
        assert row["retriable"]["now"] == 1
        assert row["model"] == "rerun_same_work"
        assert row["detail"]["exit"] == "bound" and row["detail"]["rounds_ran"] == 3

    def test_a_CONVERGED_traversal_clears_it(self, tmp_path, monkeypatch):
        """Emitting only on failure leaves the previous run's remainder standing; the supervisor would
        keep a campaign alive for work that is finished."""
        rows = self._traverse(tmp_path, monkeypatch, owed_rounds=1)
        row = rows["rounds"]
        assert row["retriable"] == {"now": 0, "cooldown": 0} and not any(row["terminal"].values())
        assert not any(rows["bundles"]["terminal"].values()), "a clean traversal owes no bundles either"
        assert row["detail"]["exit"] == "converged", \
            "the record must say WHY it ended — 'bound' on a converged run reads as work left undone"

    @pytest.mark.parametrize("disp,cause", [("engine-error", "unschedulable"),
                                            ("truncated", "unschedulable"),
                                            ("no-sandbox", "dependency"),
                                            ("missing-tool", "dependency")])
    def test_a_DETERMINISTIC_failure_is_terminal(self, tmp_path, monkeypatch, disp, cause):
        """The same bytes under the same policy give the same refusal, and a missing tool or sandbox is
        never fixed by repeating the run — so neither may keep a campaign alive."""
        rows = self._traverse(tmp_path, monkeypatch, owed_rounds=0,
                              dispositions={"success": 2, disp: 1})
        b = rows["bundles"]
        assert b["terminal"][cause] == 1 and b["retriable"] == {"now": 0, "cooldown": 0}, b
        assert b["detail"]["dispositions"] == {"success": 2, disp: 1}
        assert (b["detail"]["eligible"], b["detail"]["analysed"]) == (3, 2)

    @pytest.mark.parametrize("disp", ["timeout", "killed", "unreadable", "unpublished"])
    def test_a_TRANSIENT_failure_is_retriable_not_terminal(self, tmp_path, monkeypatch, disp):
        """Another child re-fetches that bundle and attempts it again — it may simply succeed. Calling it
        terminal forbade a recovery that genuinely works; the campaign's no-progress limit is what stops
        an endless retry, not a permanent verdict from this lane."""
        rows = self._traverse(tmp_path, monkeypatch, owed_rounds=0,
                              dispositions={"success": 2, disp: 1})
        b = rows["bundles"]
        assert b["retriable"]["now"] == 1 and not any(b["terminal"].values()), b
        assert b["model"] == "project_progress", "a retry must be able to keep the campaign alive"

    def test_the_two_UNITS_carry_different_models(self, tmp_path, monkeypatch):
        """One lane, two kinds of owed work: the traversal DEPTH can never be reached by repetition, but
        a failed bundle can. Forcing one model onto both had to misname one of them."""
        rows = self._traverse(tmp_path, monkeypatch, owed_rounds=99,
                              dispositions={"success": 1, "timeout": 1})
        assert rows["rounds"]["model"] == "rerun_same_work"
        assert rows["bundles"]["model"] == "project_progress"

    def test_a_MISSING_analyzer_never_reads_as_convergence(self, tmp_path, monkeypatch):
        """Nothing ran at all. `0 added` is the same number a clean fixed point produces, so without an
        explicit disposition a supervisor would certify a lane that never executed."""
        from quarry_recon import events, store
        run = store.Run.create(tmp_path, "acme.com")
        events.configure(run.dir)
        try:
            monkeypatch.setattr(crawl, "have", lambda _b: False)
            monkeypatch.setattr(crawl.policy, "limit", lambda n: 3 if n == "JXSCOUT_ROUNDS" else 0)
            monkeypatch.setattr(crawl, "_js_download", lambda ctx: ("led", "dir"))
            ctx = type("C", (), {"run": run, "scope": _Scope(), "echo": lambda *a, **k: None,
                                 "profile": type("P", (), {"js_chunk_brute": 0})()})()
            arts = [(f"https://acme.com/{i}.js", tmp_path / f"b{i}.js") for i in range(10)]
            for _u, a in arts:
                a.write_text("x")
            crawl._jxscout_traverse(ctx, type("L", (), {
                "items": lambda self=None: iter(arts)})(), "dir")
            run.write_manifest(profile_summary={}, phases_run=["crawl"])
            rows = {r["measure"]: r for r in run._run_summary()["remainders"]
                    if r["lane"] == "crawl.jxscout_chunks"}
            # the remainder is measured in BUNDLES: one missing binary leaves TEN of them owed
            assert rows["bundles"]["terminal"]["dependency"] == 10, rows["bundles"]
            assert rows["bundles"]["detail"]["eligible"] == 10
            cov = [c for c in run._run_summary()["coverage"]
                   if c["source_id"] == "crawl.jxscout_chunks" and c["measure"] == "bundles"][0]
            assert (cov["eligible"], cov["tested"], cov["omitted"]) == (10, 0, 10)
        finally:
            events.reset()

    def test_the_campaign_cannot_call_that_a_FIXED_POINT(self, tmp_path, monkeypatch):
        from quarry_recon import campaign
        rows = self._traverse(tmp_path, monkeypatch, owed_rounds=0,
                              dispositions={"success": 2, "engine-error": 1})
        summary = {"verdict": "complete_with_gaps", "faults": [], "provider_spend": [],
                   "remainders": list(rows.values())}
        absorbed = campaign.AbsorbResult(); absorbed.absorbed = True
        d = campaign.decide(summary, absorbed, expected_lanes=["crawl.jxscout_chunks"])
        assert d.stop == "terminal" and "unschedulable" in d.detail, d
        assert not d.success, "a lane that could not read a bundle has not finished"

    def test_repetition_can_NEVER_reach_it(self):
        """`rerun_same_work`: a later run rediscovers the root bundle and repeats rounds 1..N, so the
        remainder is `--unbound`'s business — a supervisor must not spawn children for it."""
        from quarry_recon import remainder
        assert remainder.LANE_MODEL["crawl.jxscout_chunks"] == "rerun_same_work"
        r = remainder.for_rounds("crawl.jxscout_chunks", stop="bound", rounds=3, ran=3, made=True)
        assert r.retriable == 0, "a rerun_same_work remainder may never keep a campaign alive"


class TestEitherStreamHittingTheCeiling:
    @staticmethod
    def _fill(monkeypatch, tmp_path, *, out_bytes=0, err_bytes=0, exit_code=0):
        from quarry_recon import store
        from quarry_recon.runner import RunResult, Status
        _stub_shim(monkeypatch, tmp_path)

        def fake_contract(source_id, cmd, work_unit=None, timeout=None, env=None, **kw):
            o = pathlib.Path(cmd[-1].split("> ", 1)[1].split(" 2> ")[0].strip("'"))
            e = pathlib.Path(cmd[-1].split(" 2> ")[1].strip("'"))
            o.write_text("a.js\n" * 3 if not out_bytes else "x" * out_bytes)
            e.write_text("x" * err_bytes)
            return RunResult(source_id, cmd, Status.SUCCESS if exit_code == 0 else Status.FAILED,
                             exit_code, 0.1, None, 0)
        monkeypatch.setattr(crawl, "run_contract", fake_contract)
        ctx = type("C", (), {"run": store.Run.create(tmp_path, "acme.com")})()
        return crawl._jxscout_analyze(ctx, tmp_path / "x.js", 0)

    def test_a_saturated_STDERR_is_not_a_clean_answer(self, tmp_path, monkeypatch):
        """node swallows an EFBIG write and exits 0 (measured), so a bundle that fills stderr would
        otherwise be classified success."""
        cands, disp, _ = self._fill(monkeypatch, tmp_path,
                                    err_bytes=crawl._JXSCOUT_OUTPUT_MB * 1024 * 1024)
        assert disp == "truncated"
        assert cands, "what stdout DID produce stays as partial evidence"

    def test_a_saturated_STDOUT_is_not_a_clean_answer(self, tmp_path, monkeypatch):
        _c, disp, _ = self._fill(monkeypatch, tmp_path,
                                 out_bytes=crawl._JXSCOUT_OUTPUT_MB * 1024 * 1024)
        assert disp == "truncated"

    def test_neither_saturated_is_a_normal_result(self, tmp_path, monkeypatch):
        cands, disp, _ = self._fill(monkeypatch, tmp_path, err_bytes=10)
        assert disp == "success" and len(cands) == 3
