"""C07 closure — the contract boundary is ENFORCED, not just available.

`run_contract`/`run_provider` are authoritative only if nothing can quietly bypass them. This module is the
ratchet:

1. Every direct `exec_tool(...)` (== runner.run) call in a phase must be on an EXPLICIT allowlist. A NEW bare
   call — a tool that skips the contract — fails this test until it either routes through the contract or is
   deliberately added here (a reviewed decision). The allowlist only ever shrinks as lanes migrate.
2. The registry is authoritative: removing a source_id makes the contract refuse it (fail loud), never a
   silent skip.
3. Every source executed under the contract emits exactly ONE terminal event (one stable lifecycle).

The allowlist entries are either chunked-lane internals that emit the contract vocabulary MANUALLY
(params.nuclei/dalfox, probe chunked scans) or lanes not yet migrated to `run_contract` (incremental per the
v0.3 plan). Contract-migrated single-shot lanes do NOT appear here — they call `run_contract`, not exec_tool.
"""
import ast
import collections
import importlib
import inspect
import json

import pytest

pytestmark = pytest.mark.offline

# module (phase stem) -> {tool: count} of APPROVED direct exec_tool calls. Frozen ratchet: the live scan must
# match EXACTLY. A new/removed direct call must update this map in the same change (a reviewed decision).
APPROVED_DIRECT = {
    "crawl":      {"js-beautify": 1, "jsluice": 1, "trufflehog": 1, "xnLinkFinder": 1},
    "dns":        {"dnsx": 2},
    "enrich":     {"dnsx": 2, "gowitness": 1, "nuclei": 1, "puredns": 1, "smap": 1},
    "horizontal": {"asnmap": 1, "caduceus": 1, "dnsx": 1, "mapcidr": 1, "tlsx": 1},
    "params":     {"arjun": 1, "dalfox": 1, "gf": 1, "nuclei": 2},
    "probe":      {"cdncheck": 1, "naabu": 2, "nuclei": 1, "smap": 1},
    "vertical":   {"alterx": 1, "dnsx": 1, "github-subdomains": 1, "httpx": 1, "openintel-subs": 1, "puredns": 2},
}

# EVERY phase module is scanned (a missed module is a blind spot). Kept in sync with src/quarry_recon/phases/.
PHASE_MODULES = [
    "_local_raw", "content", "crawl", "dns", "enrich", "horizontal", "origin", "params", "probe",
    "vertical",
]


def test_phase_module_list_is_complete():
    """The lint is only sound if it scans every phase module — guard against a new phase file slipping past."""
    import pathlib
    import quarry_recon.phases as pkg
    on_disk = {p.stem for p in pathlib.Path(pkg.__file__).parent.glob("*.py") if p.stem != "__init__"}
    assert on_disk == set(PHASE_MODULES), f"phase modules changed — update PHASE_MODULES: {on_disk ^ set(PHASE_MODULES)}"


def _runner_forms(module_stem):
    """(tree, run_aliases, module_aliases) for a phase module. `run_aliases` = every NAME bound directly to
    runner.run (`from ..runner import run as X`). `module_aliases` = every name bound to the runner MODULE
    (`from .. import runner`, `import quarry_recon.runner as Z`) so `<name>.run(...)` also reaches it. Resolving
    BOTH closes the escape hatch: a bare-name alias OR a module-qualified call, not just the literal `exec_tool`."""
    try:
        mod = importlib.import_module(f"quarry_recon.phases.{module_stem}")
    except ModuleNotFoundError:
        return None, set(), set()
    tree = ast.parse(inspect.getsource(mod))
    run_aliases, module_aliases = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[-1] == "runner":       # from [..]runner import run [as X]
                for a in node.names:
                    if a.name == "run":
                        run_aliases.add(a.asname or "run")
            for a in node.names:                                     # from .. import runner [as Y]
                if a.name == "runner":
                    module_aliases.add(a.asname or "runner")
        elif isinstance(node, ast.Import):                           # import quarry_recon.runner [as Z]
            for a in node.names:
                if a.name.split(".")[-1] == "runner":
                    module_aliases.add(a.asname or a.name.split(".")[0])
    return tree, run_aliases, module_aliases


def _direct_runner_calls(module_stem) -> dict:
    """{tool: count} of EVERY direct runner.run call in a phase — via a name alias OR a module-qualified
    `<runner>.run(...)`. Literal first arg is the tool, else <dynamic>."""
    tree, run_aliases, module_aliases = _runner_forms(module_stem)
    if tree is None:
        return {}
    c: collections.Counter = collections.Counter()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        hit = ((isinstance(f, ast.Name) and f.id in run_aliases) or
               (isinstance(f, ast.Attribute) and f.attr == "run"
                and isinstance(f.value, ast.Name) and f.value.id in module_aliases))
        if hit:
            tool = node.args[0].value if (node.args and isinstance(node.args[0], ast.Constant)) else "<dynamic>"
            c[tool] += 1
    return dict(c)


class TestNoUnapprovedDirectRunnerCalls:
    def test_direct_runner_calls_match_allowlist(self):
        live = {m: _direct_runner_calls(m) for m in PHASE_MODULES}
        live = {m: t for m, t in live.items() if t}          # drop modules with no direct calls
        # exact match — a NEW direct runner.run (any alias / module-qualified) bypassing the contract fails
        # until it moves onto run_contract or is deliberately added to APPROVED_DIRECT.
        assert live == APPROVED_DIRECT, (
            "contract boundary drift — reconcile APPROVED_DIRECT:\n"
            f"  added/changed: {json.dumps({m: t for m, t in live.items() if APPROVED_DIRECT.get(m) != t}, indent=2)}\n"
            f"  removed: {[m for m in APPROVED_DIRECT if m not in live]}")

    def test_exec_tool_is_the_only_permitted_runner_alias(self):
        # freeze the channel: runner.run may be imported ONLY as `exec_tool`, and NEVER reached module-qualified
        # (`from .. import runner; runner.run(...)`). This closes the alias/module-qualified escape hatch.
        for m in PHASE_MODULES:
            _, run_aliases, module_aliases = _runner_forms(m)
            assert run_aliases <= {"exec_tool"}, (
                f"{m}: runner.run imported under a non-'exec_tool' alias {run_aliases - {'exec_tool'}} "
                f"— use `run as exec_tool` or route through run_contract")
            qualified = sum(1 for node in ast.walk(_runner_forms(m)[0])
                            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                            and node.func.attr == "run" and isinstance(node.func.value, ast.Name)
                            and node.func.value.id in module_aliases)
            assert qualified == 0, f"{m}: module-qualified runner.run(...) call — forbidden (use exec_tool)"

    def test_no_dynamic_tool_in_direct_calls(self):
        # a direct runner call with a non-literal tool name can't be audited — none should exist
        for m in PHASE_MODULES:
            assert "<dynamic>" not in _direct_runner_calls(m), f"{m}: direct runner.run with a non-literal tool name"


class TestLintCatchesEscapeHatches:
    """The lint must recognize runner.run under ANY alias and module-qualified — not only the literal name
    `exec_tool`. These parse crafted phase-like sources through the same resolver the real tests use."""

    def _resolve(self, src, monkeypatch):
        # feed crafted source through the resolver by monkeypatching inspect.getsource + a fake module
        import types
        fake = types.ModuleType("quarry_recon.phases._probe_fake")
        monkeypatch.setitem(importlib.import_module("sys").modules, "quarry_recon.phases._probe_fake", fake)
        monkeypatch.setattr(inspect, "getsource", lambda m: src)
        return _direct_runner_calls("_probe_fake"), _runner_forms("_probe_fake")

    def test_aliased_import_is_detected(self, monkeypatch):
        src = "from ..runner import run as run_tool\ndef go():\n    run_tool('sneaky', ['sneaky'])\n"
        calls, (_, run_aliases, _) = self._resolve(src, monkeypatch)
        assert calls == {"sneaky": 1}                        # counted despite the non-exec_tool alias
        assert run_aliases == {"run_tool"}                   # ...and the alias-freeze test would reject it

    def test_module_qualified_call_is_detected(self, monkeypatch):
        src = "from .. import runner\ndef go():\n    runner.run('sneaky', ['sneaky'])\n"
        calls, (_, _, module_aliases) = self._resolve(src, monkeypatch)
        assert calls == {"sneaky": 1}                        # module-qualified runner.run(...) counted
        assert "runner" in module_aliases

    def test_import_module_as_alias_is_detected(self, monkeypatch):
        src = "import quarry_recon.runner as rmod\ndef go():\n    rmod.run('sneaky', ['x'])\n"
        calls, (_, _, module_aliases) = self._resolve(src, monkeypatch)
        assert calls == {"sneaky": 1} and "rmod" in module_aliases


class TestRegistryAuthoritative:
    def test_removing_a_source_makes_the_contract_refuse_it(self, tmp_path, monkeypatch):
        # registry-removal -> consumers UNAVAILABLE (fail loud), never a silent success.
        from quarry_recon import contract, events, sources
        events.reset(); events.configure(tmp_path)
        real_get = sources.get
        monkeypatch.setattr(sources, "get", lambda sid: None if sid == "vertical.subfinder" else real_get(sid))
        called = []
        monkeypatch.setattr(contract, "_run", lambda *a, **k: called.append(1))
        res = contract.run_contract("vertical.subfinder", ["subfinder"])
        from quarry_recon.runner import Status
        assert res.status == Status.SKIPPED and not called       # command NEVER handed to the runner
        evs = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        assert any(e["event"] == "tool_blocked" for e in evs)    # and it is LOUD (recorded), not silent
        events.reset()

    def test_provider_removal_also_refuses(self, tmp_path, monkeypatch):
        from quarry_recon import contract, events, sources
        events.reset(); events.configure(tmp_path)
        monkeypatch.setattr(sources, "get", lambda sid: None)
        called = []
        assert contract.run_provider("vertical.crtsh", lambda: called.append(1) or {"x"}) is None
        assert not called
        evs = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        assert any(e["event"] == "tool_blocked" for e in evs)
        assert not any(e["event"] == "tool_finish" for e in evs)
        events.reset()


class TestEventSourceIdsRegistered:
    """review-r2#2: every LITERAL source_id a phase/cloud module emits — through the contract (run_provider /
    run_contract) OR an events.* call — must exist in sources.yaml. This catches a lane emitting under an
    unregistered id (cloud's old `cloud.bucket_enum`, Shodan's unbracketed `probe.favicon`), which would run
    outside the authoritative registry. Dynamic (f-string/variable) ids are validated at runtime by the
    contract itself (unknown -> tool_blocked)."""
    EVENT_FNS = {"tool_start", "tool_finish", "tool_progress", "coverage_partial", "tool_blocked",
                 "ledger", "coverage_reset", "artifact_written"}
    CONTRACT_FNS = {"run_provider", "run_contract"}

    def _literal_source_ids(self):
        import pathlib
        import quarry_recon.phases as pkg
        files = list(pathlib.Path(pkg.__file__).parent.glob("*.py"))
        files.append(pathlib.Path(inspect.getsourcefile(importlib.import_module("quarry_recon.cloud"))))
        out = {}
        for f in files:
            if f.stem == "__init__":
                continue
            for node in ast.walk(ast.parse(f.read_text())):
                if not (isinstance(node, ast.Call) and node.args):
                    continue
                fn = (node.func.id if isinstance(node.func, ast.Name) and node.func.id in self.CONTRACT_FNS else
                      node.func.attr if isinstance(node.func, ast.Attribute) and node.func.attr in self.EVENT_FNS
                      else None)
                if fn and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    out.setdefault(node.args[0].value, set()).add(f.stem)
        return out

    def test_all_literal_event_source_ids_are_registered(self):
        from quarry_recon import sources
        reg = set(sources.all_sources())
        unregistered = {sid: sorted(mods) for sid, mods in self._literal_source_ids().items() if sid not in reg}
        assert not unregistered, f"event/contract source_ids not in sources.yaml: {unregistered}"


class TestOneStableLifecycle:
    def _events(self, tmp_path):
        p = tmp_path / "events.jsonl"
        return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []

    def test_single_shot_contract_emits_exactly_one_terminal(self, tmp_path, monkeypatch):
        from quarry_recon import contract, events
        from quarry_recon.runner import RunResult, Status
        events.reset(); events.configure(tmp_path)
        monkeypatch.setattr(contract, "_run",
                            lambda tool, cmd, **k: RunResult(tool, cmd, Status.SUCCESS, 0, 0.1, None, 3))
        contract.run_contract("vertical.subfinder", ["subfinder"])
        evs = self._events(tmp_path)
        assert sum(e["event"] == "tool_start" for e in evs) == 1
        assert sum(e["event"] == "tool_finish" for e in evs) == 1     # exactly one terminal
        events.reset()

    def test_provider_emits_exactly_one_terminal(self, tmp_path):
        from quarry_recon import contract, events
        events.reset(); events.configure(tmp_path)
        contract.run_provider("vertical.crtsh", lambda: {"a", "b"})
        evs = self._events(tmp_path)
        assert sum(e["event"] == "tool_start" for e in evs) == 1
        assert sum(e["event"] == "tool_finish" for e in evs) == 1
        events.reset()
