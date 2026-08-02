"""vertical.subfinder — honest classification of subfinder's native per-domain -max-time ceiling (a capped run
is PARTIAL, not clean SUCCESS; results always kept) AND per-APEX execution (the ceiling is per-domain, so a
single -dL batch would misclassify multi-apex runs). Pure/offline (run_contract is mocked)."""
import pytest

from quarry_recon import settings
from quarry_recon.phases import vertical
from quarry_recon.phases.vertical import (_run_subfinder, _subfinder_budget_min, _subfinder_reclassifier,
                                          _SUBFINDER_DEFAULT_MIN, _SUBFINDER_UNBOUNDED_MIN)
from quarry_recon.runner import RunResult, Status

pytestmark = pytest.mark.offline

_NOKEY = object()   # sentinel: PERFORMANCE has no SUBFINDER_MAX_TIME key at all


def _res(status, duration):
    return RunResult("subfinder", ["subfinder"], status, 0, duration, None, 100)


class TestSubfinderCeiling:
    _R = staticmethod(_subfinder_reclassifier(60))       # a 60-minute budget -> 3600s ceiling
    _S = 3600

    def test_early_completion_stays_success(self):
        assert self._R(_res(Status.SUCCESS, self._S - 120)).status == Status.SUCCESS

    def test_just_under_ceiling_stays_clean(self):
        # review-r2#P2: no tolerance below the ceiling — finishing just under means it finished on its own
        r = self._R(_res(Status.SUCCESS, self._S - 0.1))
        assert r.status == Status.SUCCESS and not r.note

    def test_exactly_at_ceiling_is_partial(self):
        assert self._R(_res(Status.SUCCESS, self._S)).status == Status.PARTIAL

    def test_over_ceiling_with_results_is_partial(self):
        r = self._R(_res(Status.SUCCESS, self._S + 5))
        assert r.status == Status.PARTIAL and "ceiling" in r.note and "capped" in r.note and "60m" in r.note

    def test_ceiling_with_zero_is_partial(self):
        assert self._R(_res(Status.EMPTY, self._S + 1)).status == Status.PARTIAL

    def test_nonclean_status_at_ceiling_unchanged(self):
        assert self._R(_res(Status.PARTIAL, self._S + 5)).status == Status.PARTIAL


class TestSubfinderBudget:
    # PERFORMANCE.SUBFINDER_MAX_TIME (minutes); Quarry's 0 = practically unbounded. Step 2 of the flag axis
    # SEPARATED it from `--timeout`: the outer kill decides waiting, this knob decides COLLECTION.
    # STRICT parse (review-r2#1): only an exact int / clean int-string in 0..1440; everything else -> 60.
    def _perf(self, monkeypatch, val):
        monkeypatch.setattr(settings, "performance",
                            lambda: {} if val is _NOKEY else {"SUBFINDER_MAX_TIME": val})

    @pytest.mark.parametrize("raw,expect", [
        (_NOKEY, 60), (None, 60), (60, 60), (30, 30), (1, 1),        # default / valid ints
        (1440, 1440),                                                 # max valid (24h, NOT the 0-sentinel)
        (0, _SUBFINDER_UNBOUNDED_MIN),                                # 0 -> practically unbounded
        (True, 60), (False, 60),                                      # bool rejected (not 1-min / not 24h)
        (-5, 60), (1441, 60), (99999, 60),                           # negative / oversized -> default
        (60.5, 60),                                                   # float -> default
        ("60", 60), ("30", 30), ("0", _SUBFINDER_UNBOUNDED_MIN),      # clean int strings accepted
        ("abc", 60), ("60.5", 60), ("-5", 60), ("  ", 60),           # garbage -> default
    ])
    def test_budget_parsing_is_strict_and_bounded(self, monkeypatch, raw, expect):
        self._perf(monkeypatch, raw)
        assert _subfinder_budget_min(1800) == expect                 # bounded outer, so the knob decides

    def test_the_OUTER_kill_no_longer_decides_the_COLLECTION_budget(self, monkeypatch):
        """flag-axis step 2: `--timeout 0` removes Quarry's outer process kill and NOTHING else. It used to
        force subfinder's -max-time to 1440m as well — an outer-kill flag deciding coverage, which also
        moved the resume key, so a run that only wanted no SIGKILL silently re-identified its work. How
        much subfinder may COLLECT is `SUBFINDER_MAX_TIME`'s answer, and `--unbound`'s to lift."""
        self._perf(monkeypatch, 30)
        assert _subfinder_budget_min(0) == 30                        # the knob decides, whatever the outer
        assert _subfinder_budget_min(1800) == 30
        self._perf(monkeypatch, _NOKEY)
        assert _subfinder_budget_min(0) == 60                        # ...including the default
        self._perf(monkeypatch, 0)
        assert _subfinder_budget_min(1800) == _SUBFINDER_UNBOUNDED_MIN   # only the KNOB unbinds it

    def test_never_zero_to_subfinder(self, monkeypatch):
        self._perf(monkeypatch, 0)
        assert _subfinder_budget_min(0) > 0                          # never 0 (subfinder would cancel)


class TestSubfinderPerApex:
    def _wire(self, monkeypatch, tmp_path, http_timeout, dur_for):
        calls, recorded, added = [], [], []

        def fake_rc(sid, cmd, *, work_unit=None, raw_path=None, reclassify=None, timeout=None, **k):
            apex = cmd[cmd.index("-d") + 1]
            raw_path.parent.mkdir(parents=True, exist_ok=True)
            raw_path.write_text(f"www.{apex}\n")                       # one in-scope host per apex
            res = RunResult("subfinder", cmd, Status.SUCCESS, 0, dur_for(apex), raw_path, 1)
            if reclassify:                                            # run_contract applies it before the terminal
                res = reclassify(res)
            calls.append({"cmd": cmd, "wu": work_unit, "raw": raw_path.name, "timeout": timeout, "status": res.status})
            return res
        monkeypatch.setattr(vertical, "run_contract", fake_rc)
        monkeypatch.setattr(settings, "performance", lambda: {})      # default 60m budget

        class _Run:
            def raw_path(self, ph, tl, nm):
                p = tmp_path / "raw" / ph / tl / nm; p.parent.mkdir(parents=True, exist_ok=True); return p
            def record(self, ph, r): recorded.append(r)
            def add(self, kind, e): added.append(e["host"]); return True
        prof = type("P", (), {"apex_domains": ["b.com", "a.com"]})()
        scope = type("S", (), {"in_scope": staticmethod(lambda h: True)})()
        ctx = type("C", (), {"run": _Run(), "http_timeout": http_timeout, "echo": staticmethod(lambda m: None)})()
        _run_subfinder(ctx, prof, scope)
        return calls, recorded, added

    def test_per_apex_wiring_classification_and_ingestion(self, monkeypatch, tmp_path):
        # bounded run (default 60m budget -> 3600s ceiling): a.com hits it, b.com finishes early
        calls, recorded, added = self._wire(monkeypatch, tmp_path, 1800,
                                            lambda a: 3601.0 if a == "a.com" else 12.0)
        assert [c["cmd"][c["cmd"].index("-d") + 1] for c in calls] == ["a.com", "b.com"]
        for c in calls:
            assert "-dL" not in c["cmd"]
            assert c["cmd"][c["cmd"].index("-max-time") + 1] == "60"   # effective budget minutes
            assert c["timeout"] == 60 * 60 + 60                        # outer backstop = budget + 60s
        assert calls[0]["wu"] != calls[1]["wu"]                       # per-apex work_units
        assert {c["raw"] for c in calls} == {"passive_a.com.txt", "passive_b.com.txt"}   # per-apex artifacts
        st = {c["cmd"][c["cmd"].index("-d") + 1]: c["status"] for c in calls}
        assert st == {"a.com": Status.PARTIAL, "b.com": Status.SUCCESS}   # capped vs honest finish
        assert set(added) == {"www.a.com", "www.b.com"} and len(recorded) == 2   # ingestion retained

    def test_unbounded_outer_removes_the_KILL_and_leaves_the_budget_alone(self, monkeypatch, tmp_path):
        # flag-axis step 2: `--timeout 0` -> outer subprocess timeout 0 (no kill), collection budget still
        # the configured one. The two axes are separate: waiting vs how much subfinder may collect.
        calls, _, _ = self._wire(monkeypatch, tmp_path, 0, lambda a: 12.0)
        for c in calls:
            assert c["cmd"][c["cmd"].index("-max-time") + 1] == "60"   # the default budget, untouched
            assert c["timeout"] == 0                                   # no outer kill under --timeout 0
        assert all(c["status"] == Status.SUCCESS for c in calls)      # 12s << 60m -> honest SUCCESS


class TestSubfinderProviderFP:
    # review-r3#2/r4: subfinder's EFFECTIVE config (both files, env-overridable + XDG) + the PDCP key are folded
    # into the resume work_unit, so a coverage change (new key / different config) can't be skipped as done.
    # Full sha256 (no entropy discarded), never a raw secret.
    def _clean(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HOME", str(tmp_path))
        for v in ("XDG_CONFIG_HOME", "SUBFINDER_PROVIDER_CONFIG", "SUBFINDER_CONFIG", "PDCP_API_KEY"):
            monkeypatch.delenv(v, raising=False)

    def test_changes_with_pdcp_key(self, monkeypatch, tmp_path):
        self._clean(monkeypatch, tmp_path)
        a = vertical._subfinder_provider_fp()
        monkeypatch.setenv("PDCP_API_KEY", "k1")
        assert vertical._subfinder_provider_fp() != a

    def test_changes_with_provider_config(self, monkeypatch, tmp_path):
        self._clean(monkeypatch, tmp_path)
        a = vertical._subfinder_provider_fp()
        cfg = tmp_path / ".config" / "subfinder"; cfg.mkdir(parents=True)
        (cfg / "provider-config.yaml").write_text("shodan: [xxx]\n")
        assert vertical._subfinder_provider_fp() != a

    def test_changes_with_main_config(self, monkeypatch, tmp_path):
        # config.yaml selects the source set -> coverage-affecting too (was previously ignored)
        self._clean(monkeypatch, tmp_path)
        a = vertical._subfinder_provider_fp()
        cfg = tmp_path / ".config" / "subfinder"; cfg.mkdir(parents=True)
        (cfg / "config.yaml").write_text("sources: [crtsh]\n")
        assert vertical._subfinder_provider_fp() != a

    def test_provider_config_env_override_honored(self, monkeypatch, tmp_path):
        self._clean(monkeypatch, tmp_path)
        override = tmp_path / "my-providers.yaml"; override.write_text("shodan: [k]\n")
        monkeypatch.setenv("SUBFINDER_PROVIDER_CONFIG", str(override))
        a = vertical._subfinder_provider_fp()
        override.write_text("shodan: [k]\ncensys: [x]\n")    # the OVERRIDE file drives the fp
        assert vertical._subfinder_provider_fp() != a

    def test_config_env_override_honored(self, monkeypatch, tmp_path):
        self._clean(monkeypatch, tmp_path)
        override = tmp_path / "my-config.yaml"; override.write_text("sources: [a]\n")
        monkeypatch.setenv("SUBFINDER_CONFIG", str(override))
        a = vertical._subfinder_provider_fp()
        override.write_text("sources: [a, b]\n")
        assert vertical._subfinder_provider_fp() != a

    def test_xdg_config_home_honored(self, monkeypatch, tmp_path):
        self._clean(monkeypatch, tmp_path)
        base = vertical._subfinder_provider_fp()             # ~/.config empty
        xdg = tmp_path / "xdg"; (xdg / "subfinder").mkdir(parents=True)
        (xdg / "subfinder" / "provider-config.yaml").write_text("k: [1]\n")
        monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
        assert vertical._subfinder_provider_fp() != base

    def test_is_not_raw_secret_and_retains_128_bits(self, monkeypatch, tmp_path):
        self._clean(monkeypatch, tmp_path)
        monkeypatch.setenv("PDCP_API_KEY", "SUPER-SECRET-KEY")
        fp = vertical._subfinder_provider_fp()
        assert "SUPER-SECRET-KEY" not in fp and len(fp) >= 32   # >= 128 bit, raw key never present
