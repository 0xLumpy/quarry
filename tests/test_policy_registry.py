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


def _module_constants():
    """Every module-level constant in `src/` whose NAME claims to be a ceiling."""
    found = {}
    for path, mod in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            targets = ([node.target] if isinstance(node, ast.AnnAssign)
                       else node.targets if isinstance(node, ast.Assign) else [])
            for t in targets:
                if isinstance(t, ast.Name) and _TOKENS & set(t.id.upper().strip("_").split("_")):
                    found[f"{mod}:{t.id}"] = path
    return found


def _knob_calls():
    """Every `strict_int` / `budget_seconds` call site, by PERFORMANCE key."""
    calls = {}
    for path, mod in _modules():
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call):
                continue
            fn = getattr(node.func, "attr", getattr(node.func, "id", ""))
            if fn in ("strict_int", "budget_seconds") and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    calls.setdefault(arg.value, (mod, fn))
    return calls


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

    def test_every_module_CEILING_is_registered_or_EXCLUDED(self):
        """A call-site scan cannot see `A1D_WORD_CAP` — it is a plain module constant. So the AST is walked
        for constants whose NAME claims to be a ceiling, and each is either a registered bound or an
        exclusion carrying its reason."""
        known = {b.const for b in policy.BOUNDS if b.const} | set(policy.EXCLUDED)
        missing = sorted(set(_module_constants()) - known)
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
        refs = {b.const for b in policy.BOUNDS if b.const} | {
            k for k in policy.EXCLUDED if ":" in k}
        for ref in sorted(refs):
            mod, _, name = ref.partition(":")
            if not hasattr(importlib.import_module(mod), name):
                stale.append(ref)
        assert not stale, stale


class TestTheRegistryTellsTheTruth:
    @pytest.mark.parametrize("bound", policy.BOUNDS, ids=lambda b: b.name)
    def test_a_module_bound_records_the_LIVE_default(self, bound):
        """A default that drifts from the code makes every policy report a guess."""
        if bound.const is None:
            return
        mod, _, name = bound.const.partition(":")
        live = getattr(importlib.import_module(mod), name)
        if isinstance(live, (list, tuple, set, frozenset, dict)):
            live = max(live.values()) if isinstance(live, dict) else len(live)
        assert int(live) == bound.default, (bound.name, live, bound.default)

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
        assert not [b for b in policy.BOUNDS if b.lane in policy.PAID_LANES], policy.BOUNDS
        assert policy.knob("SHODAN_HOST_BUDGET_S") is None
        assert policy.EXCLUDED["SHODAN_HOST_BUDGET_S"][0] == "provider"

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

    def test_names_are_unique(self):
        names = [b.name for b in policy.BOUNDS]
        assert len(names) == len(set(names)), sorted(n for n in names if names.count(n) > 1)

    def test_a_bound_the_consumer_cannot_yet_unbind_is_marked(self):
        """`consumer_honours_unbounded=False` is a promise NOT yet kept — the widening step's checklist,
        stated instead of assumed."""
        pending = [b.name for b in policy.relaxable() if not b.consumer_honours_unbounded]
        assert pending == ["CLOUD_NAME_CAP"], pending
