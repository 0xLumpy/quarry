"""The `--unbound` registry must account for EVERY ceiling in `src/`, and describe its own truthfully.

A flag whose behaviour is a hand-maintained list rots on the next commit. These tests are the mechanism:
a new knob, a new module cap or a changed default fails here, before it can quietly fall outside
`--unbound`'s reach — or, worse, inside it. Accounting for a ceiling is not the same as OWNING it: the
registry is narrow (free-tool coverage/throughput bounds only) and everything else is an EXCLUSION with a
reason, so "not ours" is stated rather than forgotten.
"""
from __future__ import annotations

import ast
import importlib
import json
import pathlib
import pathlib

import pytest

from quarry_recon import policy

SRC = pathlib.Path(__file__).resolve().parent.parent / "src" / "quarry_recon"
#: a module-level constant whose name contains one of these tokens is a candidate CEILING
_TOKENS = {"CAP", "CAPS", "LIMIT", "LIMITS", "MAX", "MIN", "BUDGET", "RESERVE", "TARGETS", "WORKERS",
           "QUOTA", "BUCKETS", "BITS"}


def _modules():
    for f in sorted(SRC.rglob("*.py")):
        rel = f.relative_to(SRC.parent).with_suffix("")
        yield f, ".".join(rel.parts)


def _constants():
    """Every constant in `src/` whose NAME claims to be a ceiling — module level AND function-local.

    Walking only `tree.body` missed `SPA_CAP`, a hidden 10-host cut defined inside a function. Where a
    ceiling is WRITTEN says nothing about whether a flag owns it."""
    found = {}
    for path, mod in _modules():
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            targets = ([node.target] if isinstance(node, ast.AnnAssign)
                       else node.targets if isinstance(node, ast.Assign) else [])
            for t in targets:
                if (isinstance(t, ast.Name) and t.id.upper() == t.id       # CONSTANT-style names only
                        and _TOKENS & set(t.id.strip("_").split("_"))):
                    found.setdefault(f"{mod}:{t.id}", (path, node))
    return found


#: how a PERFORMANCE key can be read. `strict_int` / `budget_seconds` are the coverage-knob parsers;
#: `concurrency` and `raw` are how the provider page and reserve controls are read, and
#: `performance().get(...)` is the bare dict access behind the Shodan reserve.
_READERS = ("strict_int", "budget_seconds", "concurrency", "raw", "get")


def _knob_calls():
    """Every PERFORMANCE key read anywhere in `src/`, with the reader it was read through."""
    calls = {}
    for path, mod in _modules():
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call):
                continue
            fn = getattr(node.func, "attr", getattr(node.func, "id", ""))
            if fn not in _READERS or not node.args:
                continue
            if fn == "get":
                # only `settings.performance().get("KEY")`, never any other .get
                inner = getattr(node.func, "value", None)
                if not (isinstance(inner, ast.Call)
                        and getattr(inner.func, "attr", getattr(inner.func, "id", "")) == "performance"):
                    continue
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value.isupper():
                calls.setdefault(arg.value, (mod, fn))
    return calls


def _call_site_kwarg(key: str, arg: str):
    """The `default=` / `maximum=` a `strict_int` call site passes for this PERFORMANCE key, resolved
    through a module constant when it is one (`_SUBFINDER_DEFAULT_MIN`, `_NUCLEI_MHE_MAX`)."""
    for path, mod in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and node.args
                    and getattr(node.func, "attr", getattr(node.func, "id", "")) == "strict_int"):
                continue
            if not (isinstance(node.args[0], ast.Constant) and node.args[0].value == key):
                continue
            for kw in node.keywords:
                if kw.arg != arg:
                    continue
                if isinstance(kw.value, ast.Constant):
                    return kw.value.value
                if isinstance(kw.value, ast.Name):
                    return getattr(importlib.import_module(mod), kw.value.id)
    return None


class TestEveryBoundIsClassified:
    def test_every_PERFORMANCE_knob_is_registered_or_EXCLUDED(self):
        """A knob nobody classified is a knob `--unbound` silently ignores — or silently lifts."""
        missing = {k: where for k, where in _knob_calls().items()
                   if policy.knob(k) is None and k not in policy.EXCLUDED}
        assert not missing, missing

    def test_every_knob_reader_matches_its_call_site(self):
        """`budget_seconds` and `strict_int` mean different defaults and ranges."""
        wrong = {k: (policy.knob(k).reader, fn) for k, (_mod, fn) in _knob_calls().items()
                 if policy.knob(k) is not None and policy.knob(k).reader != fn}
        assert not wrong, wrong

    def test_the_scanner_SEES_the_ceilings_it_used_to_miss(self):
        """The scanner is the enforcement mechanism, so its blind spots are the registry's blind spots.
        These six were invisible: a function-local cut, and five provider controls read through
        `concurrency` / `raw` / `performance().get` rather than the coverage-knob parsers."""
        consts, knobs = _constants(), _knob_calls()
        assert "quarry_recon.phases.crawl:SPA_CAP" in consts, sorted(consts)
        for key in ("PROVIDER_MAX_PAGES", "SHODAN_MAX_PAGES", "SHODAN_CREDIT_RESERVE",
                    "WHOXY_PAGE_BUDGET", "WHOXY_CREDIT_RESERVE"):
            assert key in knobs, (key, sorted(knobs))

    def test_every_module_CEILING_is_registered_or_EXCLUDED(self):
        """A call-site scan cannot see `A1D_WORD_CAP` — it is a plain module constant. So the AST is walked
        for constants whose NAME claims to be a ceiling, and each is either a registered bound or an
        exclusion carrying its reason."""
        known = {b.const for b in policy.BOUNDS if b.const} | set(policy.EXCLUDED)
        missing = sorted(set(_constants()) - known)
        assert not missing, f"unclassified ceilings: {missing}"

    def test_every_EXCLUSION_states_a_KIND_and_a_reason(self):
        bad = {k: v for k, v in policy.EXCLUDED.items()
               if v[0] not in policy.EXCLUSION_KINDS or len(v[1]) < 10}
        assert not bad, bad

    def test_nothing_is_both_registered_and_excluded(self):
        both = {b.name for b in policy.BOUNDS} & set(policy.EXCLUDED)
        both |= {b.const for b in policy.BOUNDS if b.const} & set(policy.EXCLUDED)
        assert not both, both

    def test_the_registry_points_at_constants_that_EXIST(self):
        """The other direction: a renamed or deleted constant must not leave a bound describing nothing."""
        stale = []
        refs = ({b.const for b in policy.BOUNDS if b.const} | {k for k in policy.EXCLUDED if ":" in k})
        seen = set(_constants())          # function-local constants: the AST is the only witness
        for ref in sorted(refs):
            mod, _, name = ref.partition(":")
            if ref not in seen and not hasattr(importlib.import_module(mod), name):
                stale.append(ref)
        assert not stale, stale


class TestTheRegistryTellsTheTruth:
    @pytest.mark.parametrize("bound", policy.BOUNDS, ids=lambda b: b.name)
    def test_every_bound_records_the_LIVE_default(self, bound):
        """A default that drifts from the code makes every policy report a guess — and the knob entries
        used to be exempt, because their default lives at the CALL SITE rather than in a constant."""
        if bound.const is not None and bound.const_local:
            node = _constants()[bound.const][1]
            assert isinstance(node.value, ast.Constant), bound
            assert node.value.value == bound.default, (bound.name, node.value.value, bound.default)
            return
        if bound.const is not None:
            mod, _, name = bound.const.partition(":")
            live = getattr(importlib.import_module(mod), name)
            if isinstance(live, (list, tuple, set, frozenset, dict)):
                live = max(live.values()) if isinstance(live, dict) else len(live)
            assert int(live) == bound.default, (bound.name, live, bound.default)
            return
        if bound.reader == "budget_seconds":
            # `budget_seconds` fixes the default itself: 0 = process the whole eligible set
            assert bound.default == 0, bound
            return
        assert _call_site_kwarg(bound.name, "default") == bound.default, bound

    @pytest.mark.parametrize("bound", policy.BOUNDS, ids=lambda b: b.name)
    def test_the_parser_RANGE_matches_the_consumer(self, bound):
        """The registry resolves effective values itself, so its `maximum` must be the one the consumer
        parses with — otherwise the policy report and the lane can compute different numbers from the same
        config, and nothing would say so."""
        if bound.reader == "strict_int":
            assert bound.maximum == _call_site_kwarg(bound.name, "maximum"), bound
        else:
            # `budget_seconds` fixes its own range; a module constant has no parser at all
            assert bound.maximum is None, bound

    @pytest.mark.parametrize("bound", policy.BOUNDS, ids=lambda b: b.name)
    def test_the_classification_is_internally_consistent(self, bound):
        assert bound.identity in policy.IDENTITIES, bound
        assert bound.reader in policy.READERS, bound
        if bound.relaxable:
            # `--unbound` needs a value to set, and the value is per knob (subfinder's is 1440, not 0)
            assert bound.unbounded_value is not None, bound
        else:
            # silence is what made bypasses invisible: a bound we decline to lift SAYS why
            assert bound.held_reason, bound
            assert bound.unbounded_value is None, bound

    def test_NO_paid_provider_control_is_in_the_registry(self):
        """`--unbound` is about using what we HAVE, not buying more. Paid controls keep their own policy —
        enablement, balance, reserve, page budgets — and this flag may neither alter nor reinterpret it."""
        assert not [b for b in policy.BOUNDS if b.lane in policy.PROVIDER_LANES], policy.BOUNDS
        for key in ("SHODAN_HOST_BUDGET_S", "SHODAN_MAX_PAGES", "SHODAN_CREDIT_RESERVE",
                    "WHOXY_PAGE_BUDGET", "WHOXY_CREDIT_RESERVE", "PROVIDER_MAX_PAGES"):
            assert policy.knob(key) is None, key
            assert policy.EXCLUDED[key][0] == "provider", key
        # ...and the reason is OWNERSHIP, never an invented cost: this endpoint is measured FREE
        assert "ownership" in policy.EXCLUDED["SHODAN_HOST_BUDGET_S"][1]
        assert "spends" not in policy.EXCLUDED["SHODAN_HOST_BUDGET_S"][1]

    def test_every_PROVIDER_LANE_is_a_real_source_id(self):
        """A phantom lane protects nothing. `probe.shodan_search` was listed and does not exist, while
        `probe.favicon` and `probe.cert` — the two lanes that actually spend Shodan query credits — were
        missing, so the "no paid lane in the registry" guarantee was weaker than it read."""
        from quarry_recon import sources
        known = set(sources.all_sources())
        outside = set(policy.PROVIDER_LANES_OUTSIDE_REGISTRY)
        assert outside == {"osint.whoxy"}, outside      # EXACT, so `osint.typo` cannot slip through
        unknown = [lane for lane in policy.PROVIDER_LANES if lane not in known and lane not in outside]
        assert not unknown, unknown

    def test_EVERY_registered_source_is_classified(self):
        """The completeness mechanism, in the shape of the bound registry's: a hard-coded list cannot find
        what it omits — `vertical.certspotter` is Quarry's own HTTP with Quarry's token and Quarry's page
        bound, and it was missing. A new lane fails here until someone says which kind it is."""
        from quarry_recon import sources
        registered = set(sources.all_sources())
        classified = set(policy.SOURCE_OWNERSHIP)
        assert registered - classified == set(), sorted(registered - classified)
        assert classified - registered == set(), sorted(classified - registered)
        assert set(policy.SOURCE_OWNERSHIP.values()) <= set(policy.OWNERSHIP_KINDS)
        # ...and the two views agree in both directions
        provider = {k for k, v in policy.SOURCE_OWNERSHIP.items() if v == "quarry_provider"}
        assert provider == set(policy.PROVIDER_LANES) - set(policy.PROVIDER_LANES_OUTSIDE_REGISTRY)

    def test_every_BOUND_names_a_registered_lane(self):
        """A bound whose lane is a stale alias misattributes every policy line it prints, and cannot join
        with the planned-lane roster settle will need. Four were aliases: `crawl.sourcemap`, `probe.vhost`,
        `params.nuclei` and `vertical.permute`."""
        from quarry_recon import sources
        registered = set(sources.all_sources()) | set(policy.BOUND_LANES_OUTSIDE_REGISTRY)
        stale = sorted({b.lane for b in policy.BOUNDS} - registered)
        assert not stale, stale

    def test_the_out_of_registry_bound_lanes_are_EXACT(self):
        """An exception list is a hole in a completeness test, so it is enumerated and justified rather
        than matched by prefix — `osint.*` would admit any typo as a new exemption."""
        assert policy.BOUND_LANES_OUTSIDE_REGISTRY == ("osint.asrank", "osint.rdap")
        from quarry_recon import sources
        registered = set(sources.all_sources())
        for lane in policy.BOUND_LANES_OUTSIDE_REGISTRY:
            assert lane not in registered, f"{lane} IS registered — drop the exemption"
            assert lane.startswith("osint."), lane

    def test_an_ACTIVE_lane_is_never_classified_local(self):
        """Completeness cannot catch a category that is merely WRONG: both of these fetch over the network,
        under scope and rate guards, and were filed as local computation."""
        for lane in ("horizontal.csp", "crawl.sourcemaps"):
            assert policy.SOURCE_OWNERSHIP[lane] == "target_facing", lane

    def test_CERTSPOTTER_and_crtsh_are_ours(self):
        """Both are Quarry-implemented HTTP to a third-party CT service — certspotter with Quarry's own
        token and `PROVIDER_MAX_PAGES`. Free or keyless is not the test; who makes the call is."""
        for lane in ("vertical.certspotter", "vertical.crtsh"):
            assert policy.SOURCE_OWNERSHIP[lane] == "quarry_provider", lane
            assert lane in policy.PROVIDER_LANES, lane
        src = pathlib.Path(importlib.import_module("quarry_recon.phases.vertical").__file__).read_text()
        assert "api.certspotter.com" in src and "urllib.request.urlopen" in src

    def test_the_boundary_is_OWNERSHIP_not_keyed_ness(self):
        """Quarry owns the call, the key or the budget -> ours. An external tool reading its OWN provider
        configuration (`subfinder -all`) is outside Quarry's accounting model, and a `key` default can mean
        local dataset SETUP rather than a provider at all."""
        from quarry_recon import sources
        reg = sources.all_sources()
        # `key` is not the test: openintel is key-defaulted for a LOCAL DB and is not an acquisition lane
        assert str(reg["vertical.openintel"].get("reason", "")).startswith("setup (local DB")
        assert "vertical.openintel" not in policy.PROVIDER_LANES
        # ...and a keyed lane whose key WE supply to reach a provider is
        for lane in ("vertical.shosubgo", "vertical.github_subs"):
            assert str(reg[lane].get("default")) == "key" and lane in policy.PROVIDER_LANES, lane
        # every lane Quarry itself calls a provider from is listed
        for lane in ("probe.favicon", "probe.cert", "probe.shodan_host", "vertical.censys"):
            assert lane in policy.PROVIDER_LANES, lane
        # aggregators that read their own config are NOT ours to police
        assert "vertical.subfinder" not in policy.PROVIDER_LANES

    def test_RESOURCE_rate_parser_and_engagement_stay_OUT(self):
        """They are exclusions, not entries: lifting them buys coverage nothing and risks the host, the
        target, or an engagement decision that is not a machine-wide flag's to make."""
        for ref in ("quarry_recon.sweep:MAX_BATCH_WORDS", "quarry_recon.netguard:_MAX_WORKERS",
                    "quarry_recon.budget:_MAX_BUDGET_S", "quarry_recon.config:MAX_CONTENT_RECURSION",
                    "quarry_recon.evidence:MAX_FETCHES"):
            assert ref in policy.EXCLUDED, ref
            assert ref not in {b.const for b in policy.BOUNDS}, ref

    def test_the_A1d_word_cap_is_the_ONE_held_entry(self):
        """Lumpy's deferral, encoded where the flag will read it: `--unbound` must not land the strict `0`
        bypass ahead of the exact-label DNS boundary and the usefulness tiers it was gated on."""
        cap = policy.by_name("A1D_WORD_CAP")
        assert cap is not None and not cap.relaxable, cap
        assert "boundary" in cap.held_reason and "tiers" in cap.held_reason, cap
        assert policy.held() == (cap,), policy.held()      # the one printed exception in v1

    def test_every_EXCLUSION_KIND_is_actually_used(self):
        """A vocabulary nothing uses is a vocabulary nobody checks — `continuation` sat here claiming a
        loop `--settle` could not, in fact, continue."""
        used = {k for k, _ in policy.EXCLUDED.values()}
        assert used == set(policy.EXCLUSION_KINDS), set(policy.EXCLUSION_KINDS) - used

    def test_REPEATING_a_run_cannot_continue_a_run_scoped_loop(self, tmp_path):
        """The evidence behind `MAX_ITERS` being `--unbound`'s and not `--settle`'s: entities are
        RUN-scoped. A second run starts with an empty store, so it replays the permutation rounds from the
        beginning instead of continuing past the first run's last frontier — round four is unreachable by
        repetition, however many runs `--settle` creates."""
        from quarry_recon import store
        first = store.Run.create(tmp_path, "t")
        first.add("subdomain", {"host": "a.acme.com", "sources": ["x"]})
        assert sorted(first.values("subdomain")) == ["a.acme.com"]
        second = store.Run.create(tmp_path, "t")
        assert second.project_dir == first.project_dir and second.dir != first.dir
        assert second.values("subdomain") == [], second.values("subdomain")
        iters = policy.by_name("MAX_ITERS")
        assert iters is not None and iters.relaxable and iters.unbounded_value == 0, iters

    def test_names_are_unique(self):
        names = [b.name for b in policy.BOUNDS]
        assert len(names) == len(set(names)), sorted(n for n in names if names.count(n) > 1)

    def test_a_bound_the_consumer_cannot_yet_unbind_is_marked(self):
        """`consumer_honours_unbounded=False` is a promise NOT yet kept — the widening step's checklist,
        stated instead of assumed."""
        pending = [b.name for b in policy.relaxable() if not b.consumer_honours_unbounded]
        assert pending == [], pending          # step 4 taught the last three


class TestOverridesAreRunScoped:
    """flag-axis step 2: a flag is ONE run's instruction. `override()` alone is process-global and never
    restored, so an unbound child run would leave its bounds lifted for the next run in the same
    interpreter — exactly what a `--settle` supervisor will do."""

    def test_the_override_is_RESTORED_on_the_way_out(self):
        from quarry_recon import settings
        from quarry_recon.phases import vertical
        assert vertical.wildcard_zones_per_run() == 5
        with settings.overrides({"WILDCARD_ZONES_PER_RUN": 0}):
            assert vertical.wildcard_zones_per_run() == 0
        assert vertical.wildcard_zones_per_run() == 5

    def test_it_is_restored_even_when_the_run_RAISES(self):
        from quarry_recon import settings
        from quarry_recon.phases import vertical
        with pytest.raises(KeyboardInterrupt):
            with settings.overrides({"WILDCARD_ZONES_PER_RUN": 0}):
                raise KeyboardInterrupt("ctrl-c mid-run")
        assert vertical.wildcard_zones_per_run() == 5

    def test_an_OUTER_override_survives_an_inner_one(self):
        """Nesting restores the previous value, not "no overrides at all"."""
        from quarry_recon import settings
        from quarry_recon.phases import vertical
        try:
            with settings.overrides({"WILDCARD_ZONES_PER_RUN": 2}):
                with settings.overrides({"WILDCARD_ZONES_PER_RUN": 0}):
                    assert vertical.wildcard_zones_per_run() == 0
                assert vertical.wildcard_zones_per_run() == 2
        finally:
            settings.clear_overrides()
        assert vertical.wildcard_zones_per_run() == 5

    def test_a_SECOND_run_in_one_interpreter_starts_bounded(self, tmp_path, monkeypatch):
        """The supervisor case, through the real command: an unbound run must not lift the next one."""
        from click.testing import CliRunner
        from quarry_recon import cli as cli_mod
        from quarry_recon.phases import vertical
        seen: list = []

        def _boom(*a, **k):
            seen.append(vertical.wildcard_zones_per_run())
            raise SystemExit(0)

        monkeypatch.setattr(cli_mod, "_resolve_profile", _boom)
        CliRunner().invoke(cli_mod.cli, ["run", "-t", "acme", "--unbound"])
        CliRunner().invoke(cli_mod.cli, ["run", "-t", "acme"])
        assert seen == [0, 5], seen


class TestTheEffectivePolicyIsReportedAndPersisted:
    """flag-axis step 3: a run's ceilings are EVIDENCE, not shell history. The same table is printed at
    run start, stored in the manifest, and previewable without running anything."""

    def test_a_REJECTED_value_is_attributed_to_the_DEFAULT_and_named(self, monkeypatch):
        """Presence is not acceptance. A configured value the strict parser refuses must not leave the
        policy evidence naming an author for a number it did not choose."""
        from quarry_recon import policy, settings
        monkeypatch.setattr(settings, "performance",
                            lambda: {"SUBFINDER_MAX_TIME": "garbage", "WILDCARD_BUDGET_S": -1,
                                     "WILDCARD_ZONES_PER_RUN": True})
        rows = {r["name"]: r for r in policy.snapshot()}
        assert (rows["SUBFINDER_MAX_TIME"]["value"], rows["SUBFINDER_MAX_TIME"]["source"]) == (60, "default")
        assert rows["SUBFINDER_MAX_TIME"]["rejected"] == "str(7 chars)", rows["SUBFINDER_MAX_TIME"]
        assert rows["SUBFINDER_MAX_TIME"]["rejected_source"] == "config", rows["SUBFINDER_MAX_TIME"]
        budget = rows["WILDCARD_BUDGET_S"]
        assert (budget["value"], budget["source"], budget["rejected"]) == (0, "default", "-1")
        assert budget["rejected_source"] == "config", budget
        assert budget["unbounded"] is True          # 0 IS unbounded — but by the default, not by config
        zones = rows["WILDCARD_ZONES_PER_RUN"]
        assert (zones["value"], zones["source"], zones["rejected"]) == (5, "default", "True")
        lines = "\n".join(policy.render())
        for name in ("SUBFINDER_MAX_TIME", "WILDCARD_BUDGET_S", "WILDCARD_ZONES_PER_RUN"):
            assert f"{name} = " in lines and "REJECTED by the strict parser" in lines, lines
        assert "UNBOUNDED WILDCARD_BUDGET_S" not in lines, lines      # never "unbounded by config"

    def test_the_report_refuses_what_the_CONSUMER_would_refuse(self, monkeypatch):
        """An OVERSIZED value is the case where a wrong range hides: 5000 minutes is inside any generous
        ceiling and outside subfinder's real one, so a registry that parsed with its own maximum would
        report a bound the lane will never apply."""
        from quarry_recon import policy, settings
        monkeypatch.setattr(settings, "performance",
                            lambda: {"SUBFINDER_MAX_TIME": 5000, "WILDCARD_ZONES_PER_RUN": 20000})
        rows = {r["name"]: r for r in policy.snapshot()}
        assert (rows["SUBFINDER_MAX_TIME"]["value"], rows["SUBFINDER_MAX_TIME"]["rejected"]) == (60, "5000")
        assert (rows["WILDCARD_ZONES_PER_RUN"]["value"],
                rows["WILDCARD_ZONES_PER_RUN"]["rejected"]) == (5, "20000")
        # ...and the lane agrees, which is the whole point of sharing the range
        from quarry_recon.phases import vertical
        assert vertical._subfinder_budget_min(1800) == 60
        assert vertical.wildcard_zones_per_run() == 5

    def test_a_rejected_FLAG_value_is_attributed_the_same_way(self):
        from quarry_recon import policy, settings
        with settings.overrides({"WILDCARD_ZONES_PER_RUN": "nonsense"}):
            row = {r["name"]: r for r in policy.snapshot()}["WILDCARD_ZONES_PER_RUN"]
            line = [ln for ln in policy.render() if "WILDCARD_ZONES_PER_RUN" in ln][0]
        assert (row["value"], row["source"], row["rejected"]) == (5, "default", "str(8 chars)"), row
        # ...and a rejected FLAG is not described as a configured value
        assert row["rejected_source"] == "flag" and "the flag value" in line, (row, line)

    def test_a_value_names_WHO_set_it(self, monkeypatch):
        from quarry_recon import policy, settings
        monkeypatch.setattr(settings, "performance", lambda: {"SUBFINDER_MAX_TIME": 10})
        rows = {r["name"]: r for r in policy.snapshot()}
        assert (rows["SUBFINDER_MAX_TIME"]["value"], rows["SUBFINDER_MAX_TIME"]["source"]) == (10, "config")
        assert rows["WILDCARD_ZONES_PER_RUN"]["source"] == "default"
        with settings.overrides({"WILDCARD_ZONES_PER_RUN": 0}):
            rows = {r["name"]: r for r in policy.snapshot()}
            zones = rows["WILDCARD_ZONES_PER_RUN"]
            assert (zones["value"], zones["source"], zones["unbounded"]) == (0, "flag", True)

    def test_the_HELD_bound_is_always_rendered_with_its_reason(self, monkeypatch):
        """The one exception must never be summarised away — an invisible exception is a silent one."""
        from quarry_recon import policy
        lines = policy.render()
        held = [ln for ln in lines if ln.strip().startswith("HELD")]
        assert len(held) == 1 and "A1D_WORD_CAP" in held[0], lines
        assert "boundary" in held[0] and "tiers" in held[0], held[0]

    def test_a_bound_at_its_DEFAULT_is_summarised_not_listed(self):
        """The point of the print is what is DIFFERENT — plus every exception."""
        from quarry_recon import policy
        lines = policy.render()
        assert not [ln for ln in lines if "A1D_BUDGET_S" in ln], lines
        assert any("bound(s) at their default" in ln and "already unbounded" in ln for ln in lines), lines

    def test_the_PREVIEW_command_runs_nothing_and_shows_the_flag_s_effect(self, monkeypatch):
        from click.testing import CliRunner
        from quarry_recon import cli as cli_mod
        from quarry_recon.phases import vertical
        monkeypatch.setattr(cli_mod, "_resolve_profile",
                            lambda *a, **k: pytest.fail("the preview must not load a profile or run"))
        plain = CliRunner().invoke(cli_mod.cli, ["policy"])
        unbound = CliRunner().invoke(cli_mod.cli, ["policy", "--unbound"])
        assert plain.exit_code == 0 and unbound.exit_code == 0, (plain.output, unbound.output)
        assert "UNBOUNDED WILDCARD_ZONES_PER_RUN" not in plain.output, plain.output
        assert "UNBOUNDED WILDCARD_ZONES_PER_RUN" in unbound.output, unbound.output
        assert "HELD" in plain.output and "A1D_WORD_CAP" in plain.output, plain.output
        # ...and the preview's own overrides do not outlive it
        assert vertical.wildcard_zones_per_run() == 5

    def test_the_manifest_STORES_the_policy_it_ran_under(self, tmp_path):
        from quarry_recon import policy, store
        run = store.Run.create(tmp_path, "t")
        rows = policy.snapshot()
        run.write_manifest(profile_summary={}, phases_run=["vertical"], policy=rows)
        stored = json.loads(run.manifest_path.read_text())["policy"]
        assert stored == rows and len(stored) == len(policy.BOUNDS), stored
        held = [r for r in stored if not r["relaxable"]]
        assert [r["name"] for r in held] == ["A1D_WORD_CAP"] and held[0]["held_reason"], held


class TestARejectedValueIsNeverDISCLOSED:
    """A rejected value is diagnostic text that reaches the console, the event log and `manifest.json`. It
    may not be an unrestricted echo of whatever the config held: a knob whose value is a pasted token would
    publish it in three places at once."""

    SECRET = "SUPER-SECRET-KEY-abcdef0123456789"

    def test_the_SECRET_never_reaches_the_report_the_events_or_the_manifest(self, tmp_path, monkeypatch):
        from quarry_recon import events, policy, settings, store
        monkeypatch.setattr(settings, "performance", lambda: {"SUBFINDER_MAX_TIME": self.SECRET})
        rows = policy.snapshot()
        rendered = "\n".join(policy.render(rows))
        assert self.SECRET not in json.dumps(rows), rows
        assert self.SECRET not in rendered, rendered
        assert f"str({len(self.SECRET)} chars)" in rendered, rendered      # type and SIZE, never content

        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            events.emit("policy", "run", bounds=rows)
            run.write_manifest(profile_summary={}, phases_run=["vertical"], policy=rows)
            log = (run.dir / "events.jsonl").read_text()
            manifest = run.manifest_path.read_text()
        finally:
            events.reset()
        assert self.SECRET not in log, log
        assert self.SECRET not in manifest, manifest

    def test_a_CONFIGURED_credential_is_redacted_from_the_manifest_policy_block(self, tmp_path,
                                                                                monkeypatch):
        """Belt and braces: the rows are non-disclosing by construction, and the manifest sink redacts them
        again — a sink that trusts its input is how one leak becomes permanent."""
        from quarry_recon import secrets, store
        monkeypatch.setattr(secrets, "values", lambda: ["tok-live-42"])
        run = store.Run.create(tmp_path, "t")
        run.write_manifest(profile_summary={}, phases_run=["vertical"],
                           policy=[{"name": "X", "held_reason": "held because tok-live-42 said so"}])
        stored = json.loads(run.manifest_path.read_text())["policy"]
        assert stored == [{"name": "X", "held_reason": "held because *** said so"}], stored

    @pytest.mark.parametrize("raw,expect", [
        (5000, "5000"), (-1, "-1"), (True, "True"), (60.5, "60.5"),        # SHORT numbers describe themselves
        ("  42  ", "'42'"), ("-7", "'-7'"),                                 # numeric strings, same rule
        (10 ** 40, "int(41 digits; above maximum 1440)"),                   # a long number is DESCRIBED
        ("1" * 30, "str(30 digits; above maximum 1440)"),                    # ...in either form
        (-10 ** 12, "int(13 digits; below zero)"),
        ("garbage", "str(7 chars)"), ("", "str(0 chars)"),                  # opaque text: size only
        (["a", "b"], "list(2 item(s))"), ({"k": "v"}, "dict(1 key(s))"), (None, "NoneType"),
    ])
    def test_the_diagnostic_is_bounded_by_TYPE(self, raw, expect):
        from quarry_recon import settings
        assert settings._diagnostic(raw, maximum=1440) == expect

    @pytest.mark.parametrize("value,maximum,expect", [
        (-1, 1440, "below zero"), (5000, 1440, "above maximum 1440"),
        (999, None, "outside the accepted range"),          # no range to name: still no VALUE named
    ])
    def test_the_range_note_states_the_MISS_not_the_value(self, value, maximum, expect):
        from quarry_recon import settings
        note = settings._range_note(value, maximum)
        assert note == expect and str(value) not in note.replace(str(maximum or ""), ""), note

    # the raws are BUILT inside the test: pytest renders parametrised values into test ids, and rendering
    # a 5000-digit int is the very conversion CPython refuses
    @pytest.mark.parametrize("kind,expect", [
        ("str_pos", "str(5000 digits; above maximum 1440)"),       # int("9"*5000) RAISES
        ("str_neg", "str(5000 digits; below zero)"),
        ("int_pos", "int(5001 digits; above maximum 1440)"),       # even repr() of this RAISES
        ("int_neg", "int(5001 digits; below zero)"),
    ])
    def test_a_value_TOO_LONG_TO_CONVERT_is_still_described(self, kind, expect, monkeypatch):
        """CPython refuses int<->str conversion above 4300 digits, so the parser that exists to REFUSE a
        value could abort the run with it — and every run now reads every bound for the policy report. The
        length gate comes first, and the diagnostic describes an oversized int from its BIT LENGTH rather
        than building a string it cannot build."""
        from quarry_recon import policy, settings
        raw = {"str_pos": "9" * 5000, "str_neg": "-" + "9" * 5000,
               "int_pos": 10 ** 5000, "int_neg": -(10 ** 5000)}[kind]
        assert settings._diagnostic(raw, maximum=1440) == expect
        monkeypatch.setattr(settings, "performance", lambda: {"SUBFINDER_MAX_TIME": raw})
        # the consumer and the report agree, and neither raises
        from quarry_recon.phases import vertical
        assert vertical._subfinder_budget_min(1800) == 60
        row = {r["name"]: r for r in policy.snapshot()}["SUBFINDER_MAX_TIME"]
        assert (row["value"], row["source"], row["rejected"]) == (60, "default", expect), row
        assert len(policy.render()) < 40                            # the report stays BOUNDED

    def test_a_DISABLED_conversion_limit_does_not_mean_zero_digits(self, monkeypatch):
        """`sys.get_int_max_str_digits()` returns 0 when the interpreter DISABLED the limit. Reading that
        literally made every numeric setting fail its length gate — a configured "10" became the default."""
        import sys as _sys
        from quarry_recon import settings
        monkeypatch.setattr(_sys, "get_int_max_str_digits", lambda: 0, raising=False)
        assert settings._int_str_limit() == 4300
        monkeypatch.setattr(settings, "performance", lambda: {"SUBFINDER_MAX_TIME": "10"})
        assert settings.strict_int_with_source("SUBFINDER_MAX_TIME", default=60, maximum=1440) == (
            10, "config", None, None)

    @pytest.mark.parametrize("kind,expect", [
        ("zeros", 0),                    # "0" * 5000 IS zero — leading zeroes are representation
        ("zeros_then_30", 30),           # ...and they do not make a small number unconvertible
        ("nines", 60),                   # 5000 significant digits: genuinely refused, default kept
    ])
    def test_LEADING_ZEROES_are_representation_not_magnitude(self, kind, expect, monkeypatch):
        """Length alone does not establish range: `"0" * 5000` is numerically zero, and calling it "above
        maximum" claims a comparison nobody performed. SIGNIFICANT digits decide."""
        from quarry_recon import settings
        raw = {"zeros": "0" * 5000, "zeros_then_30": "0" * 5000 + "30", "nines": "9" * 5000}[kind]
        monkeypatch.setattr(settings, "performance", lambda: {"SUBFINDER_MAX_TIME": raw})
        value, source, rejected, _rs = settings.strict_int_with_source("SUBFINDER_MAX_TIME", default=60,
                                                                       maximum=1440)
        assert value == expect, (kind, value, rejected)
        assert (source == "default") == (kind == "nines"), (kind, source)
        if kind == "nines":
            assert rejected == "str(5000 digits; above maximum 1440)", rejected
        else:
            assert rejected is None, rejected

    def test_a_huge_value_through_a_FLAG_is_contained_too(self):
        from quarry_recon import policy, settings
        with settings.overrides({"WILDCARD_ZONES_PER_RUN": "9" * 9000}):
            row = {r["name"]: r for r in policy.snapshot()}["WILDCARD_ZONES_PER_RUN"]
            from quarry_recon.phases import vertical
            assert vertical.wildcard_zones_per_run() == 5
        assert row["rejected"] == "str(9000 digits; above maximum 10000)", row
        assert row["rejected_source"] == "flag" and row["value"] == 5, row

    @pytest.mark.parametrize("as_int", [False, True])
    def test_a_NUMERIC_credential_never_reaches_the_diagnostic(self, as_int, monkeypatch, tmp_path):
        """A credential of digits is the case both earlier attempts missed: an int bypassed the redactor
        entirely, and a numeric STRING was truncated to 24 characters BEFORE redaction — which defeats a
        redactor that matches the whole secret. Not one digit of it may survive, in either form."""
        from quarry_recon import events, policy, secrets, settings, store
        digits = "9081726354" * 4                       # a 40-digit credential
        monkeypatch.setattr(secrets, "values", lambda: [digits])
        monkeypatch.setattr(settings, "performance",
                            lambda: {"SUBFINDER_MAX_TIME": int(digits) if as_int else digits})
        rows = policy.snapshot()
        rendered = "\n".join(policy.render(rows))
        row = {r["name"]: r for r in rows}["SUBFINDER_MAX_TIME"]
        assert row["value"] == 60 and row["source"] == "default", row
        assert row["rejected"] == f"{'int' if as_int else 'str'}(40 digits; above maximum 1440)", row
        for probe in (digits, digits[:24], digits[:12]):
            assert probe not in rendered and probe not in json.dumps(rows), (probe, rendered)

        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            events.emit("policy", "run", bounds=rows)
            run.write_manifest(profile_summary={}, phases_run=["vertical"], policy=rows)
            sinks = (run.dir / "events.jsonl").read_text() + run.manifest_path.read_text()
        finally:
            events.reset()
        assert digits[:12] not in sinks, sinks


class TestUnboundIsDrivenByTheRegistry:
    """flag-axis step 4: `--unbound` has no list of its own. It applies the REGISTRY — every relaxable
    bound at its unbounded value — so a knob that is not registered is not lifted, a HELD one keeps its
    bound, and provider controls are not touched at all."""

    def test_it_lifts_EVERY_relaxable_bound_and_nothing_else(self):
        from quarry_recon import policy, settings
        applied = policy.unbound_overrides()
        assert set(applied) == {b.name for b in policy.relaxable()}, applied
        assert all(applied[b.name] == b.unbounded_value for b in policy.relaxable()), applied
        assert "A1D_WORD_CAP" not in applied                     # HELD by policy
        for key in ("SHODAN_HOST_BUDGET_S", "SHODAN_MAX_PAGES", "WHOXY_PAGE_BUDGET",
                    "PROVIDER_MAX_PAGES", "NUCLEI_BULK_SIZE", "ARJUN_TARGETS"):
            assert key not in applied, key                       # provider / rate: never ours
        with settings.overrides(applied):
            rows = {r["name"]: r for r in policy.snapshot()}
            for b in policy.relaxable():
                assert rows[b.name]["unbounded"] and rows[b.name]["source"] == "flag", rows[b.name]
            held = rows["A1D_WORD_CAP"]
            assert held["value"] == 2000 and held["source"] == "default", held

    def test_the_module_caps_are_read_through_the_registry(self, monkeypatch):
        """A module constant cannot be read by `settings`, so the consumer asks `policy.limit()` — the
        constant stays the DEFAULT and the flag layers on top."""
        from quarry_recon import policy, settings
        from quarry_recon.phases import vertical
        assert policy.limit("WILDCARD_WORD_CAP") == 5000
        monkeypatch.setattr(vertical, "WILDCARD_WORD_CAP", 25)   # the constant is still the default
        assert policy.limit("WILDCARD_WORD_CAP") == 25
        with settings.overrides(policy.unbound_overrides()):
            assert policy.limit("WILDCARD_WORD_CAP") == 0        # ...and `--unbound` wins over it

    def test_the_DIFFER_submits_the_whole_corpus_when_unbound(self, tmp_path, monkeypatch):
        """The behaviour the flag promises: with the spend bound lifted, one lifecycle submits every
        candidate it holds for the zone instead of leaving a remainder to rotate."""
        from quarry_recon import policy, settings, store
        from test_a1d_vocabulary import TestTheWildcardDifferHasItsOwnLifecycle as L
        words = tuple(f"w{i}" for i in range(9))
        monkeypatch.setattr(__import__("quarry_recon.phases.vertical", fromlist=["x"]),
                            "WILDCARD_WORD_CAP", 2)
        seen: list = []

        def tool(t_, cmd, raw_path=None, timeout=None, **k):
            from quarry_recon.runner import RunResult as _RR
            seen.extend(pathlib.Path(cmd[cmd.index("-l") + 1]).read_text().split())
            if raw_path is not None:
                raw_path.write_text("")
            return _RR(t_, cmd, crawl.Status.EMPTY, 0, 0.1, raw_path, 0)

        bounded = L._differ(L(), tmp_path / "a", monkeypatch, zones=("z.acme.com",), words=words,
                            rows=None, tool=tool)
        submitted_bounded = {c.split(".", 1)[0] for c in seen if not c.startswith("quarry-wc-")}
        seen.clear()
        with settings.overrides(policy.unbound_overrides()):
            L._differ(L(), tmp_path / "b", monkeypatch, zones=("z.acme.com",), words=words,
                      rows=None, tool=tool)
        submitted_unbound = {c.split(".", 1)[0] for c in seen if not c.startswith("quarry-wc-")}
        assert len(submitted_bounded) == 2, submitted_bounded          # the 2-per-zone spend
        assert submitted_unbound == set(words), submitted_unbound      # ...lifted: all nine, one run


class TestTheConsumersHonourTheirUnboundedValue:
    """A registry that says `consumer_honours_unbounded=True` is a promise about BEHAVIOUR."""

    def test_the_CLOUD_name_cap_probes_every_candidate_when_unbound(self, tmp_path, monkeypatch):
        from quarry_recon import cloud, events, policy, settings, store
        monkeypatch.setattr(cloud, "_check", lambda url: (False, None))     # nothing exists; no network
        probed: list = []
        monkeypatch.setattr(cloud, "_all_candidates", lambda prof: [f"n{i}" for i in range(300)])
        real = cloud._check
        monkeypatch.setattr(cloud, "_check", lambda url: (probed.append(url), (False, None))[1])
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        ctx = type("C", (), {"run": run, "profile": type("P", (), {"apex_domains": ["acme.com"]})()})()
        try:
            cloud._enumerate(ctx)
            bounded = len({u for u in probed})
            probed.clear()
            with settings.overrides(policy.unbound_overrides()):
                cloud._enumerate(ctx)
            unbound = len({u for u in probed})
        finally:
            events.reset()
        assert bounded == 120 * 2, bounded            # 120 names x 2 providers
        assert unbound == 300 * 2, unbound            # ...every candidate, both providers

    def test_the_SPA_cap_takes_every_app_like_host_when_unbound(self, monkeypatch):
        """The headless slice reads the policy, and 0 means every app-like host rather than a `[:0]` cut —
        the failure mode a naive "unbounded = 0" would produce."""
        from quarry_recon import policy, settings
        from quarry_recon.phases import crawl
        hosts = [f"https://app{i}.acme.com" for i in range(25)]
        assert policy.limit("SPA_CAP") == 10
        cap = policy.limit("SPA_CAP")
        assert (hosts if not cap else hosts[:cap]) == hosts[:10]
        with settings.overrides(policy.unbound_overrides()):
            cap = policy.limit("SPA_CAP")
            assert cap == 0 and (hosts if not cap else hosts[:cap]) == hosts
        # the lane reads the POLICY (not the constant) and slices with it — the headless pass itself is
        # driven end-to-end in the crawl suite, so what is pinned here is the policy wiring
        src = pathlib.Path(crawl.__file__).read_text()
        assert '_cap = policy.limit("SPA_CAP")' in src, "the lane must READ the policy"
        assert "spa = _spa_all if not _cap else _spa_all[:_cap]" in src, "...and slice with it"
        assert "_spa_all[:SPA_CAP]" not in src, src


class TestModuleBoundsAreFLAGOnly:
    """A module constant is not a PERFORMANCE knob: `config.yaml` has no say over it. One reader serving
    both let ordinary config change a module bound — and let the policy report claim the HELD `A1D_WORD_CAP`
    had moved to 0 while A1d went on brute-forcing with 2000."""

    @pytest.mark.parametrize("name,configured,expect", [
        ("MAX_ITERS", 0, 3), ("CLOUD_NAME_CAP", 1, 120), ("WILDCARD_WORD_CAP", 7, 5000),
        ("A1D_WORD_CAP", 0, 2000),
    ])
    def test_config_cannot_move_a_module_bound(self, name, configured, expect, monkeypatch):
        from quarry_recon import policy, settings
        monkeypatch.setattr(settings, "performance", lambda: {name: configured})
        assert policy.limit(name) == expect
        row = {r["name"]: r for r in policy.snapshot()}[name]
        assert (row["value"], row["source"]) == (expect, "default"), row

    def test_the_HELD_cap_the_lane_uses_is_the_one_the_report_shows(self, monkeypatch):
        """The worst shape of the same defect: a report that disagrees with the lane about a HELD bound."""
        from quarry_recon import policy, settings
        from quarry_recon.phases import enrich
        monkeypatch.setattr(settings, "performance", lambda: {"A1D_WORD_CAP": 0})
        with settings.overrides(policy.unbound_overrides()):        # even under `--unbound`
            row = {r["name"]: r for r in policy.snapshot()}["A1D_WORD_CAP"]
            assert (row["value"], row["source"]) == (2000, "default"), row
            assert row["value"] == enrich.A1D_WORD_CAP, (row, enrich.A1D_WORD_CAP)

    def test_a_FLAG_still_moves_a_module_bound(self):
        from quarry_recon import policy, settings
        with settings.overrides({"WILDCARD_WORD_CAP": 0}):
            assert policy.limit("WILDCARD_WORD_CAP") == 0
            row = {r["name"]: r for r in policy.snapshot()}["WILDCARD_WORD_CAP"]
            assert (row["value"], row["source"], row["unbounded"]) == (0, "flag", True), row
