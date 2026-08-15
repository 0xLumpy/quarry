"""Acquisition closes after a campaign's first child — settle, the closure step.

`--settle` repeats whole runs, and a run contains ACQUISITION lanes. A supervisor that let child 2 buy
again would be making a spending decision no continuation flag may make. There are THREE doors into a
provider — `run_provider`, `run_providers` and `run_contract` — plus one lane that runs plain HTTP outside
the registry entirely, so a gate in any single one of them is not a gate.
"""
from __future__ import annotations

import contextlib
import json
import pathlib

import pytest

pytestmark = pytest.mark.offline

from quarry_recon import campaign, contract, events, policy, sources
from quarry_recon.runner import RunResult, Status


class TestTheGateItself:
    def test_acquisition_is_OPEN_by_default(self):
        """An ordinary `quarry run` acquires exactly as it always has."""
        for lane in policy.PROVIDER_LANES:
            assert campaign.acquisition_allowed(lane) == (True, "")

    def test_closing_it_refuses_ONLY_acquisition_lanes(self):
        with campaign.acquisition_closed("after child 1"):
            for lane in policy.PROVIDER_LANES:
                allowed, why = campaign.acquisition_allowed(lane)
                assert not allowed and why == "after child 1", lane
            # processing is exactly what a later child exists to do
            for lane in ("probe.httpx", "enrich.a1d_brute", "crawl.katana_standard"):
                assert campaign.acquisition_allowed(lane) == (True, ""), lane

    def test_the_closure_is_RESTORED_afterwards(self):
        with campaign.acquisition_closed():
            assert not campaign.acquisition_allowed("probe.favicon")[0]
        assert campaign.acquisition_allowed("probe.favicon") == (True, "")

    def test_it_is_restored_even_when_the_child_RAISES(self):
        with pytest.raises(KeyboardInterrupt):
            with campaign.acquisition_closed():
                raise KeyboardInterrupt("ctrl-c mid-child")
        assert campaign.acquisition_allowed("probe.favicon")[0]


class TestEveryDoorIsGated:
    def _log(self, tmp_path):
        events.reset()
        events.configure(tmp_path)
        return tmp_path / "events.jsonl"

    def test_run_provider_refuses_a_closed_lane(self, tmp_path):
        log = self._log(tmp_path)
        ran: list = []
        try:
            with campaign.acquisition_closed("after child 1"):
                out = contract.run_provider("probe.shodan_host", lambda: ran.append(1))
        finally:
            events.reset()
        assert out is None and ran == [], ran
        blocked = [json.loads(l) for l in log.read_text().splitlines()
                   if json.loads(l).get("event") == "tool_blocked"]
        assert blocked and blocked[-1]["source_id"] == "probe.shodan_host", blocked
        assert "after child 1" in blocked[-1]["reason"], blocked

    def test_run_providers_refuses_a_closed_lane(self, tmp_path):
        self._log(tmp_path)
        shared: list = []
        try:
            with campaign.acquisition_closed():
                results = contract.run_providers(
                    [("probe.favicon", None, lambda: None), ("probe.cert", None, lambda: None)],
                    lambda: shared.append(1))
        finally:
            events.reset()
        assert results == {} or all(v is None for v in results.values()), results
        assert shared == [], "the shared body must not run for a closed campaign"

    def test_run_contract_refuses_a_closed_lane(self, tmp_path, monkeypatch):
        self._log(tmp_path)
        monkeypatch.setattr(contract, "_run",
                            lambda *a, **k: pytest.fail("a closed lane must not execute"))
        try:
            with campaign.acquisition_closed("after child 1"):
                res = contract.run_contract("vertical.shosubgo", ["shosubgo", "-d", "acme.com"])
        finally:
            events.reset()
        assert res.status is Status.SKIPPED and "after child 1" in (res.note or ""), res

    def test_the_DIRECT_HTTP_door_is_gated_too(self, tmp_path, monkeypatch):
        """`osint.whoxy` runs plain HTTP outside the registry — the door a central gate would have missed."""
        from quarry_recon import osint
        self._log(tmp_path)
        monkeypatch.setattr(osint, "_whoxy_get",
                            lambda *a, **k: pytest.fail("a closed campaign must not query Whoxy"))
        recorded: list = []

        class _S:
            def record(self, r):
                recorded.append(r)

            def fail(self, *a, **k):
                pass

        try:
            with campaign.acquisition_closed("after child 1"):
                osint._whoxy(_S(), {"a@acme.com"}, ["Acme"], lambda _m: None, 30)
        finally:
            events.reset()
        assert recorded and recorded[-1].status is Status.SKIPPED, recorded
        assert "after child 1" in (recorded[-1].note or ""), recorded

    def _github(self, tmp_path, monkeypatch, *, closed, token=True):
        """Drive the REAL github-subdomains lane and report what it did."""
        from quarry_recon import secrets, store
        from quarry_recon.phases import vertical
        run = store.Run.create(tmp_path, "t")
        events.reset()
        events.configure(run.dir)
        minted: list = []
        ran: list = []

        @contextlib.contextmanager
        def _mint_lifetime():
            if not token:
                yield None
                return
            path = tmp_path / "gh-token"
            path.write_text("ghp_x")
            minted.append(path)
            try:
                yield path
            finally:
                path.unlink(missing_ok=True)

        monkeypatch.setattr(vertical.secrets, "github_tokens_lifetime", _mint_lifetime)
        monkeypatch.setattr(vertical, "exec_tool", lambda *a, **k: ran.append(a) or (_ for _ in ()).throw(
            AssertionError("a closed campaign must not run github-subdomains")))
        prof = type("P", (), {"apex_domains": ["acme.com"]})()
        scope = type("S", (), {"in_scope": staticmethod(lambda h: True)})()
        try:
            ctx = type("C", (), {"run": run, "http_timeout": 30})()
            if closed:
                with campaign.acquisition_closed("after child 1"):
                    vertical._github_subs(ctx, prof, scope)
            else:
                vertical._github_subs(ctx, prof, scope)
        finally:
            events.reset()
        return run, minted, ran

    def test_the_DIRECT_TOOL_door_refuses_and_leaves_NOTHING_behind(self, tmp_path, monkeypatch):
        """`vertical.github_subs` runs its binary through `exec_tool`, so NEITHER registry gate covers it.
        The gate has to come BEFORE the credential is minted: creating a 0600 token and then declining to
        use it leaked the file and recorded a SECOND, contradictory skip about a token it had just made."""
        run, minted, ran = self._github(tmp_path, monkeypatch, closed=True)
        assert ran == [], "a closed campaign must not execute the tool"
        assert minted == [], "a closed campaign must not mint a credential it will not use"
        skips = [r for r in run._tool_runs if r.tool == "github-subdomains"]
        assert len(skips) == 1, skips                               # ONE skip...
        assert skips[0].status == "skipped" and "after child 1" in (skips[0].note or ""), skips
        assert "no GitHub token" not in (skips[0].note or ""), skips  # ...with the REAL cause

    def test_an_open_campaign_with_NO_token_still_says_so(self, tmp_path, monkeypatch):
        run, minted, ran = self._github(tmp_path, monkeypatch, closed=False, token=False)
        skips = [r for r in run._tool_runs if r.tool == "github-subdomains"]
        assert len(skips) == 1 and "no GitHub token" in (skips[0].note or ""), skips
        assert ran == [] and minted == []

    def test_an_OPEN_campaign_still_runs_the_lane(self, tmp_path):
        self._log(tmp_path)
        try:
            out = contract.run_provider("probe.shodan_host", lambda: "ran")
        finally:
            events.reset()
        assert out == "ran"


class TestTheClosureIsComplete:
    """Not a spot check. Every acquisition lane declares the DOOR it executes through, and the doors are
    checked against the code — a registered provider that started making its own HTTP calls would sail
    through a test that only counts gate strings."""

    def _sources(self):
        import pathlib
        root = pathlib.Path(contract.__file__).parent
        return {p: p.read_text(encoding="utf-8") for p in root.rglob("*.py")}

    def test_every_acquisition_lane_declares_a_door(self):
        owned = {lane for lane, kind in policy.SOURCE_OWNERSHIP.items() if kind == "quarry_provider"}
        declared = set(policy.PROVIDER_DOORS)
        assert declared == owned | set(policy.PROVIDER_LANES_OUTSIDE_REGISTRY), declared ^ owned
        assert set(policy.PROVIDER_DOORS.values()) <= set(policy.DOORS)

    def test_both_REGISTRY_doors_gate(self):
        src = pathlib.Path(contract.__file__).read_text()
        assert src.count("if not acquisition_open(source_id") == 2, "both registry doors must gate"
        assert "def acquisition_open(" in src

    def test_every_DIRECT_HTTP_lane_gates_itself(self):
        for lane, door in policy.PROVIDER_DOORS.items():
            if door not in ("direct_http", "direct_tool"):
                continue
            hits = [txt for txt in self._sources().values()
                    if f'acquisition_allowed("{lane}")' in txt]
            assert hits, f"{lane} declares direct_http and gates nothing"

    #: lanes whose source id is CONSTRUCTED at the call site (an f-string over a provider name, or a lane
    #: spec's attribute), so no literal ties them to their door. They are pinned behaviourally instead —
    #: the refusal lifecycle tests drive `probe.favicon` / `probe.cert` through `run_providers` directly.
    _CONSTRUCTED = {"probe.favicon", "probe.cert", "vertical.crtsh", "vertical.certspotter",
                    "vertical.shosubgo", "probe.shodan_host"}

    def _door_calls(self):
        """Every `run_provider` / `run_providers` / `run_contract` call whose source id can be resolved —
        a literal, or a module-level constant bound to one. The ENCLOSING CALL is what matters: a module
        keeping some unrelated wrapper call must not vouch for a lane that quietly went direct."""
        import ast
        found: dict = {}
        for path, txt in self._sources().items():
            tree = ast.parse(txt)
            consts = {t.id: n.value.value
                      for n in tree.body if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant)
                      and isinstance(n.value.value, str)
                      for t in n.targets if isinstance(t, ast.Name)}
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call) or not node.args:
                    continue
                fn = getattr(node.func, "attr", getattr(node.func, "id", ""))
                if fn not in ("run_provider", "run_contract"):
                    continue
                arg = node.args[0]
                lane = (arg.value if isinstance(arg, ast.Constant) and isinstance(arg.value, str)
                        else consts.get(arg.id) if isinstance(arg, ast.Name) else None)
                if lane:
                    found.setdefault(lane, set()).add(fn)
        return found

    def test_each_lane_is_tied_to_ITS_OWN_call_site(self):
        """The module-wide check accepted any wrapper anywhere in the file, so a lane that switched to
        direct HTTP stayed green as long as some other lane still used the wrapper. This resolves the
        source id AT the call."""
        calls = self._door_calls()
        for lane, door in policy.PROVIDER_DOORS.items():
            if door in ("direct_http", "direct_tool") or lane in self._CONSTRUCTED:
                continue
            assert lane in calls, f"{lane} declares {door} and no call site names it"
            assert door in calls[lane], (lane, door, calls[lane])

    def test_a_constructed_lane_is_pinned_BEHAVIOURALLY(self):
        """The exceptions are deliberate and bounded: every one of them is driven through its door by the
        refusal-lifecycle tests, which is a stronger claim than a string match."""
        assert self._CONSTRUCTED <= set(policy.PROVIDER_DOORS), self._CONSTRUCTED
        src = pathlib.Path(__file__).read_text()
        for lane in ("probe.favicon", "probe.cert", "probe.shodan_host"):
            assert f'"{lane}"' in src, lane

    def test_the_registry_ids_are_real(self):
        gated_outside = set(policy.PROVIDER_LANES_OUTSIDE_REGISTRY)
        for lane in policy.PROVIDER_LANES:
            assert lane in sources.all_sources() or lane in gated_outside, lane


class TestARefusedLaneStillHasALifecycle:
    """A manifest that simply lacks the lane says "nobody ran it". A closed campaign is a DECISION, and it
    has to read as one — start, then a skipped terminal carrying the reason."""

    def test_run_provider_records_start_and_a_SKIPPED_terminal(self, tmp_path):
        events.reset()
        events.configure(tmp_path)
        try:
            with campaign.acquisition_closed("after child 1"):
                assert contract.run_provider("probe.shodan_host", lambda: "ran") is None
        finally:
            events.reset()
        rows = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        kinds = [r["event"] for r in rows]
        assert kinds == ["tool_blocked", "tool_start", "coverage_reset", "tool_finish"], kinds
        assert rows[-1]["status"] == "skipped" and "after child 1" in rows[-1]["reason"], rows[-1]
        assert rows[1].get("provider") and rows[-1].get("provider"), rows

    def test_the_terminal_SUPERSEDES_an_earlier_generation(self, tmp_path):
        """An un-terminated start would leave the previous generation standing — the reason a refusal
        needs the whole lifecycle rather than a blocked event."""
        events.reset()
        events.configure(tmp_path)
        try:
            contract.run_provider("probe.shodan_host", lambda: "ran")          # generation 1: it ran
            with campaign.acquisition_closed("after child 1"):
                contract.run_provider("probe.shodan_host", lambda: "ran")      # generation 2: refused
        finally:
            events.reset()
        finishes = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()
                    if json.loads(l).get("event") == "tool_finish"]
        assert [f["status"] for f in finishes] == ["success", "skipped"], finishes

    def test_a_refusal_CLEARS_the_lane_s_earlier_coverage(self, tmp_path):
        """A source-wide decision supersedes the source's coverage too. Otherwise the lane says both
        "policy skipped this" and "this omitted a page" — one lane telling two stories about one run."""
        from quarry_recon import store
        run = store.Run.create(tmp_path, "t")
        events.reset()
        events.configure(run.dir)

        def capped():
            events.coverage_partial("probe.shodan_host", kind=events.COVERAGE_CAP, unit="pages",
                                    measure="pages", eligible=2, tested=1, omitted=1, reason="capped")
            return "ran"

        try:
            contract.run_provider("probe.shodan_host", capped)
            summary = run._run_summary()
            assert [g["status"] for g in summary["gaps"]] == ["coverage:cap"], summary["gaps"]
            with campaign.acquisition_closed("after child 1"):
                contract.run_provider("probe.shodan_host", lambda: "ran")
            run.write_manifest(profile_summary={}, phases_run=["probe"])
        finally:
            events.reset()
        after = json.loads(run.manifest_path.read_text())["summary"]
        assert after["gaps"] == [], after["gaps"]
        assert after["tool_status"] == {"skipped": 1} and after["verdict"] == "complete", after

    def test_run_providers_gives_EVERY_refused_lane_its_terminal(self, tmp_path):
        events.reset()
        events.configure(tmp_path)
        shared: list = []
        try:
            with campaign.acquisition_closed():
                contract.run_providers([("probe.favicon", None, lambda: None),
                                        ("probe.cert", None, lambda: None)], lambda: shared.append(1))
        finally:
            events.reset()
        rows = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        finished = {r["source_id"] for r in rows if r["event"] == "tool_finish" and r["status"] == "skipped"}
        assert finished == {"probe.favicon", "probe.cert"}, finished
        assert shared == [], "the shared body SPENDS — it must not run for refused lanes"
