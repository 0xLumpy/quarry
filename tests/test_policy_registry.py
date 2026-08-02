"""The bound registry must describe EVERY ceiling in `src/`, and describe it truthfully.

A flag whose behaviour is a hand-maintained list rots on the next commit. These tests are the mechanism
that keeps `policy.BOUNDS` honest: a new knob, a new module cap or a changed default fails here, before it
can quietly fall outside `--unbound`'s reach or inside it.
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
    def test_every_PERFORMANCE_knob_is_in_the_registry(self):
        """A knob nobody classified is a knob `--unbound` silently ignores — or silently lifts."""
        missing = {k: where for k, where in _knob_calls().items() if policy.knob(k) is None}
        assert not missing, missing

    def test_every_knob_reader_matches_its_call_site(self):
        """`budget_seconds` and `strict_int` mean different defaults and ranges."""
        wrong = {k: (policy.knob(k).reader, fn) for k, (_mod, fn) in _knob_calls().items()
                 if policy.knob(k) is not None and policy.knob(k).reader != fn}
        assert not wrong, wrong

    def test_every_module_CEILING_is_classified(self):
        """A call-site scan cannot see `A1D_WORD_CAP` — it is a plain module constant. So the AST is walked
        for constants whose NAME claims to be a ceiling, and each is either a registered bound or an
        explicitly reasoned non-bound."""
        known = {b.const for b in policy.BOUNDS if b.const} | set(policy.NOT_BOUNDS)
        missing = sorted(set(_module_constants()) - known)
        assert not missing, f"unclassified ceilings: {missing}"

    def test_the_registry_points_at_constants_that_EXIST(self):
        """The other direction: a renamed or deleted constant must not leave a bound describing nothing."""
        stale = []
        for ref in sorted({b.const for b in policy.BOUNDS if b.const} | set(policy.NOT_BOUNDS)):
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
        assert bound.axis in policy.AXES, bound
        assert bound.identity in policy.IDENTITIES, bound
        assert bound.reader in policy.READERS, bound
        if bound.relaxable:
            # `--unbound` needs a value to set, and the value is per knob (subfinder's is 1440, not 0)
            assert bound.unbounded_value is not None, bound
            assert bound.axis == "volume", bound          # only the volume axis is `--unbound`'s
        else:
            # silence is what made bypasses invisible: a bound we decline to lift SAYS why
            assert bound.held_reason, bound
            assert bound.unbounded_value is None, bound

    def test_MONEY_is_never_relaxed_by_unbound(self):
        """A paid ceiling is structurally a coverage bound, but relaxing it SPENDS. That belongs to a
        future `--spend-all`, and the separation is what keeps `--unbound` free."""
        assert not [b for b in policy.BOUNDS if b.axis == "money" and b.relaxable]

    def test_RESOURCE_is_never_relaxed_by_any_flag(self):
        """Blast radius, memory and sockets are not coverage: the scheduler reaches every chunk anyway."""
        assert not [b for b in policy.BOUNDS if b.axis == "resource" and b.relaxable]

    def test_the_A1d_word_cap_is_HELD_with_its_reason(self):
        """Lumpy's deferral, encoded where the flag will read it: `--unbound` must not land the strict `0`
        bypass ahead of the exact-label DNS boundary and the usefulness tiers it was gated on."""
        cap = policy.by_name("A1D_WORD_CAP")
        assert cap is not None and not cap.relaxable, cap
        assert "boundary" in cap.held_reason and "tiers" in cap.held_reason, cap
        assert cap in policy.held(), policy.held()

    def test_names_are_unique(self):
        names = [b.name for b in policy.BOUNDS]
        assert len(names) == len(set(names)), sorted(n for n in names if names.count(n) > 1)

    def test_a_bound_the_consumer_cannot_yet_unbind_is_marked(self):
        """`consumer_honours_unbounded=False` is a promise NOT yet kept — the widening step's checklist,
        stated instead of assumed."""
        pending = [b.name for b in policy.relaxable() if not b.consumer_honours_unbounded]
        assert pending == ["CLOUD_NAME_CAP"], pending
