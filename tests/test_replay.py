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
    """T0.1 (source-verified): dalfox --delay is the per-host RoE period (file mode is sequential + the
    limiter is per-host mutex-serialized), set to ceil(1000/rl) so the payload rate never EXCEEDS rl;
    arjun uses its global --rate-limit (keeps -t concurrency), not the per-thread -d."""

    class _Prof:
        def __init__(self, rl):
            self.http_rl = rl

    def test_dalfox_delay_is_ceil_and_bounds_rate(self):
        cmd = params._dalfox_cmd("b", "o", self._Prof(3))
        delay = int(cmd[cmd.index("--delay") + 1])
        assert delay == -(-1000 // 3)                        # ceil(1000/3) = 334ms
        assert 1000.0 / delay <= 3 + 1e-9                    # host payload rate never exceeds http_rl

    def test_dalfox_delay_independent_of_workers(self):
        # -w does NOT multiply the per-host rate → the delay is NOT worker-scaled (the wrong model)
        cmd = params._dalfox_cmd("b", "o", self._Prof(10))
        w = int(cmd[cmd.index("-w") + 1])
        delay = int(cmd[cmd.index("--delay") + 1])
        assert delay == -(-1000 // 10) and delay != round(1000 * w / 10)

    def test_no_rate_no_delay(self):
        # no RoE cap set → no pacing at all (tool default speed)
        assert "--delay" not in params._dalfox_cmd("b", "o", self._Prof(None))

    def test_arjun_uses_global_rate_limit_not_per_thread_delay(self):
        import inspect
        src = inspect.getsource(params.run)
        assert 'aj_cmd += ["--rate-limit", str(prof.http_rl)]' in src and 'aj_cmd += ["-d"' not in src
