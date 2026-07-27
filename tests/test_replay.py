"""Evidence-preservation + RoE regressions distilled from the OTC run (C16 / N02 / N05 / T0.1).

These lock behaviors that a live run got WRONG before the fixes: candidate shapes collapsed by
value not param-shape, and per-worker rate math that multiplied the engagement budget. Pure/hermetic.
"""
import pytest

from quarry_recon.phases import params

pytestmark = pytest.mark.offline


class TestDalfoxCanonicalization:
    """N02: collapse XSS/redirect candidates to unique (scheme,host,path,param-NAMES) shapes, one rep each
    — dalfox's reflected-XSS selection is shape-dependent, so scanning one URL per shape is set-equal."""

    def test_same_shape_different_values_collapse(self):
        reps, stats = params._canonicalize_candidates([
            "https://h/s?q=1", "https://h/s?q=2", "https://h/s?q=9999",
        ])
        assert len(reps) == 1 and stats["raw_candidates"] == 3 and stats["canonical_candidates"] == 1

    def test_scheme_and_path_are_distinct_shapes(self):
        # http vs https on the same host/path can be different services/redirect chains → must NOT collapse
        reps, _ = params._canonicalize_candidates(["http://h/s?q=1", "https://h/s?q=1"])
        assert len(reps) == 2

    def test_blank_redirect_param_is_a_real_sink(self):
        # ?next= / ?url= with a blank value is a distinct redirect/XSS sink parse_qs() would silently drop
        reps, _ = params._canonicalize_candidates(["https://h/go?next=", "https://h/go"])
        assert len(reps) == 2

    def test_param_name_set_not_order(self):
        reps, _ = params._canonicalize_candidates(["https://h/s?a=1&b=2", "https://h/s?b=9&a=8"])
        assert len(reps) == 1                                # same param-NAME set → one shape

    def test_reduction_percent_reported(self):
        _, stats = params._canonicalize_candidates(["https://h/s?q=1"] * 10 + ["https://h/x?p=1"])
        assert stats["canonical_candidates"] == 2 and stats["reduction_percent"] > 80


class TestRoERateControl:
    """v0.3.8: dalfox v3 has a REAL global --rate-limit (req/s, shared across workers AND targets) set directly
    to http_rl — this SUPERSEDES v2's per-host --delay ceil(1000/rl) model (and its per-target-limiter caveat).
    arjun uses its own global --rate-limit (keeps -t concurrency), not the per-thread -d."""

    class _Prof:
        def __init__(self, rl):
            self.http_rl = rl

    def test_dalfox_uses_global_rate_limit(self):
        cmd = params._dalfox_cmd("b", "o", self._Prof(3))
        assert cmd[cmd.index("--rate-limit") + 1] == "3"     # global rps cap == the RoE rate, no delay math
        assert "--delay" not in cmd                          # v2 per-host delay model retired

    def test_no_rate_no_rate_limit(self):
        # no RoE cap set → no pacing flag at all (tool default speed, bounded by governed concurrency)
        assert "--rate-limit" not in params._dalfox_cmd("b", "o", self._Prof(None))

    def test_dalfox_concurrency_is_2d_and_not_v2_hundred(self):
        # v3 concurrency is 2D (--workers per-target × --max-concurrent-targets); v2's -w 100 / --max-cpu are gone
        cmd = params._dalfox_cmd("b", "o", self._Prof(None))
        assert "--workers" in cmd and "--max-concurrent-targets" in cmd
        assert "-w" not in cmd and "--max-cpu" not in cmd

    def test_arjun_uses_global_rate_limit_not_per_thread_delay(self):
        # A2 moved the invocation from a batched `-i` in run() into the per-target _arjun_lane; the RoE
        # property is unchanged (global --rate-limit, never the thread-collapsing -d).
        import inspect
        assert hasattr(params, "_arjun_exec")          # fail LOUD if the worker is renamed away
        src = inspect.getsource(params._arjun_exec)
        assert '"--rate-limit", str(rate)' in src and '"-d"' not in src
        assert "if rate:" in src                       # applied only when the operator sets a rate

    def test_arjun_global_rate_is_partitioned_across_concurrent_targets(self):
        # --rate-limit is PER PROCESS, so the lane may run several targets at once ONLY if the operator's
        # global rate is split between them. Isolation is one process per target; it never implied serial.
        assert sum(params._arjun_rate_shares(10, 5)) == 10
        assert sum(params._arjun_rate_shares(7, 5)) == 7          # indivisible rate still sums exactly
        assert params._arjun_rate_shares(0, 5) == [0] * 5         # no cap -> no flag, full pool
        assert len(params._arjun_rate_shares(3, 5)) == 3          # rate below pool SHRINKS the pool
        assert all(s >= 1 for s in params._arjun_rate_shares(3, 5))   # 0 would mean UNLIMITED to arjun
