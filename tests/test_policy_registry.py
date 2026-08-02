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
        assert pending == ["CLOUD_NAME_CAP", "SPA_CAP", "MAX_ITERS"], pending


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
