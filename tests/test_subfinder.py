"""vertical.subfinder — honest classification of subfinder's native per-domain -max-time ceiling (a capped run
is PARTIAL, not clean SUCCESS; results always kept) AND per-APEX execution (the ceiling is per-domain, so a
single -dL batch would misclassify multi-apex runs). Pure/offline (run_contract is mocked)."""
import pytest

from quarry_recon.phases import vertical
from quarry_recon.phases.vertical import _run_subfinder, _subfinder_reclassify, _SUBFINDER_MAX_S
from quarry_recon.runner import RunResult, Status

pytestmark = pytest.mark.offline


def _res(status, duration):
    return RunResult("subfinder", ["subfinder"], status, 0, duration, None, 100)


class TestSubfinderCeiling:
    def test_early_completion_stays_success(self):
        assert _subfinder_reclassify(_res(Status.SUCCESS, _SUBFINDER_MAX_S - 120)).status == Status.SUCCESS

    def test_just_under_ceiling_stays_clean(self):
        # review-r2#P2: no tolerance below the ceiling — 599.9s means it finished on its own, an honest SUCCESS
        r = _subfinder_reclassify(_res(Status.SUCCESS, _SUBFINDER_MAX_S - 0.1))
        assert r.status == Status.SUCCESS and not r.note

    def test_exactly_at_ceiling_is_partial(self):
        assert _subfinder_reclassify(_res(Status.SUCCESS, _SUBFINDER_MAX_S)).status == Status.PARTIAL

    def test_ceiling_with_results_is_partial(self):
        r = _subfinder_reclassify(_res(Status.SUCCESS, _SUBFINDER_MAX_S + 0.19))  # the observed 600.19s
        assert r.status == Status.PARTIAL and "ceiling" in r.note and "capped" in r.note

    def test_ceiling_with_zero_is_partial(self):
        assert _subfinder_reclassify(_res(Status.EMPTY, _SUBFINDER_MAX_S + 1)).status == Status.PARTIAL

    def test_nonclean_status_at_ceiling_unchanged(self):
        # a real timeout/error (already non-clean) is never flipped — only clean SUCCESS/EMPTY reclassify
        assert _subfinder_reclassify(_res(Status.PARTIAL, _SUBFINDER_MAX_S + 5)).status == Status.PARTIAL


class TestSubfinderPerApex:
    def test_per_apex_wiring_classification_and_ingestion(self, monkeypatch, tmp_path):
        calls, recorded, added = [], [], []

        def fake_rc(sid, cmd, *, work_unit=None, raw_path=None, reclassify=None, timeout=None, **k):
            apex = cmd[cmd.index("-d") + 1]
            raw_path.parent.mkdir(parents=True, exist_ok=True)
            raw_path.write_text(f"www.{apex}\n")                       # one in-scope host per apex
            dur = 601.0 if apex == "a.com" else 12.0                   # a.com HITS the per-domain ceiling
            res = RunResult("subfinder", cmd, Status.SUCCESS, 0, dur, raw_path, 1)
            if reclassify:                                            # run_contract applies it before the terminal
                res = reclassify(res)
            calls.append({"cmd": cmd, "wu": work_unit, "raw": raw_path.name,
                          "timeout": timeout, "reclassify": reclassify, "status": res.status})
            return res
        monkeypatch.setattr(vertical, "run_contract", fake_rc)

        class _Run:
            def raw_path(self, ph, tl, nm):
                p = tmp_path / "raw" / ph / tl / nm; p.parent.mkdir(parents=True, exist_ok=True); return p
            def record(self, ph, r): recorded.append(r)
            def add(self, kind, e): added.append(e["host"]); return True
        prof = type("P", (), {"apex_domains": ["b.com", "a.com"]})()
        scope = type("S", (), {"in_scope": staticmethod(lambda h: True)})()
        ctx = type("C", (), {"run": _Run(), "http_timeout": 0, "echo": staticmethod(lambda m: None)})()

        _run_subfinder(ctx, prof, scope)

        # ONE subfinder call per apex, sorted, each single-domain (-d, never -dL) with the explicit 10m budget
        assert [c["cmd"][c["cmd"].index("-d") + 1] for c in calls] == ["a.com", "b.com"]
        for c in calls:
            assert "-dL" not in c["cmd"]
            assert c["cmd"][c["cmd"].index("-max-time") + 1] == "10"
            assert c["timeout"] == _SUBFINDER_MAX_S + 60               # outer backstop above the ceiling
            assert c["reclassify"] is _subfinder_reclassify
        assert calls[0]["wu"] != calls[1]["wu"]                       # per-apex work_units
        assert {c["raw"] for c in calls} == {"passive_a.com.txt", "passive_b.com.txt"}   # per-apex artifacts
        # per-apex classification: a.com (601s) -> PARTIAL, b.com (12s) -> honest SUCCESS
        st = {c["cmd"][c["cmd"].index("-d") + 1]: c["status"] for c in calls}
        assert st == {"a.com": Status.PARTIAL, "b.com": Status.SUCCESS}
        # ingestion RETAINED for BOTH apexes, including the capped one
        assert set(added) == {"www.a.com", "www.b.com"} and len(recorded) == 2


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
