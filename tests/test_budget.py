"""budget.py — bounded, FAIR, resumable processing of a lane's FULL eligible input.

Replaces first-N input caps. The OTC 20260725 audit measured what those caps cost: a flat slice of a
store-ordered list let a few heavy hosts consume the whole budget, and WHICH hosts won depended on
discovery order, so the scanned set ROTATED between runs of the same target (influx1 JS 433/439 -> 0/439,
sourcemaps recovered 46 -> 5, normalized secrets 24 -> 3). These assert the three properties that fix it:
host fairness, an unbounded default, and a resumable content-bound remainder.
"""
import json

import pytest

from quarry_recon import budget, events, settings

pytestmark = pytest.mark.offline

_NOKEY = object()


class TestBudgetSeconds:
    def _perf(self, monkeypatch, val):
        monkeypatch.setattr(settings, "performance",
                            lambda: {} if val is _NOKEY else {"JS_FETCH_BUDGET_S": val})

    @pytest.mark.parametrize("raw,expect", [
        (_NOKEY, 0), (None, 0),                       # UNSET = UNBOUNDED. The whole point: no magic default.
        (0, 0), (1, 1), (3600, 3600),
        (True, 0), (False, 0),                        # bool is not a budget
        (-1, 0), (30.5, 0), ("abc", 0), ("  ", 0),   # garbage -> unbounded, never a tiny accidental budget
        ("600", 600), ("0", 0),
        (30 * 24 * 3600 + 1, 0),                      # beyond a month is a typo, not a policy
    ])
    def test_parse_defaults_to_unbounded(self, monkeypatch, raw, expect):
        self._perf(monkeypatch, raw)
        assert budget.budget_seconds("JS_FETCH_BUDGET_S") == expect

    def test_a_typo_can_never_shrink_coverage(self, monkeypatch):
        # the failure mode that matters: a bad value must not silently become a 1-second budget
        for bad in ("fast", "1e3", "-5", True, 1.5):
            self._perf(monkeypatch, bad)
            assert budget.Budget(budget.budget_seconds("JS_FETCH_BUDGET_S")).unbounded


class TestBudget:
    def test_zero_is_unbounded_and_never_exhausts(self):
        b = budget.Budget(0)
        assert b.unbounded and b.exhausted() is False

    def test_negative_is_clamped_to_unbounded(self):
        assert budget.Budget(-10).unbounded

    def test_a_positive_budget_exhausts(self, monkeypatch):
        t = [1000.0]
        monkeypatch.setattr(budget.time, "monotonic", lambda: t[0])
        b = budget.Budget(60)
        assert not b.exhausted()
        t[0] = 1059.9
        assert not b.exhausted()
        t[0] = 1060.0
        assert b.exhausted() and b.elapsed() == 60.0


class TestOrderFairly:
    def test_round_robin_across_hosts(self):
        items = ["a1", "a2", "a3", "b1", "c1", "c2"]
        out = budget.order_fairly(items, lambda s: s[0])
        assert out == ["a1", "b1", "c1", "a2", "c2", "a3"]

    def test_no_single_group_can_starve_the_others(self):
        """THE regression. The old flat slice gave a 2000-item budget entirely to one 825-URL host; every
        other host got nothing. Under a fair order, a budget of N >= number-of-hosts reaches every host."""
        items = [f"big{i}" for i in range(825)] + [f"small{i}" for i in range(3)]
        out = budget.order_fairly(items, lambda s: "big" if s.startswith("big") else "small")
        assert out[:2] == ["big0", "small0"]                   # interleaved from the very first pair
        first_10 = out[:10]
        assert sum(1 for x in first_10 if x.startswith("small")) == 3   # the small host is NOT starved

    def test_preserves_input_order_within_a_group(self):
        # discovery order carries signal — the crawler found it first for a reason
        items = ["a/z", "a/y", "a/x"]
        assert budget.order_fairly(items, lambda s: "a") == ["a/z", "a/y", "a/x"]

    def test_is_deterministic_and_lossless(self):
        items = [f"h{i % 7}/{i}" for i in range(200)]
        a = budget.order_fairly(items, lambda s: s.split("/")[0])
        b = budget.order_fairly(items, lambda s: s.split("/")[0])
        assert a == b                                          # reproducible coverage under a budget
        assert sorted(a) == sorted(items) and len(a) == len(items)   # nothing dropped, nothing duplicated

    def test_empty_input(self):
        assert budget.order_fairly([], lambda s: s) == []


class TestLedger:
    def _mk(self, tmp_path, name="a.js", body="x"):
        art = tmp_path / "files" / name
        art.parent.mkdir(parents=True, exist_ok=True)
        art.write_text(body)
        return art

    def test_records_and_resumes(self, tmp_path):
        art = self._mk(tmp_path)
        led = budget.Ledger(tmp_path / "s.json", lane="crawl.js_fetch")
        assert not led.has("http://h/a.js")
        led.record("http://h/a.js", art)
        led.save()
        again = budget.Ledger(tmp_path / "s.json", lane="crawl.js_fetch")
        assert again.has("http://h/a.js")

    def test_edited_artifact_is_not_trusted(self, tmp_path):
        art = self._mk(tmp_path)
        led = budget.Ledger(tmp_path / "s.json", lane="crawl.js_fetch")
        led.record("u", art); led.save()
        art.write_text("TAMPERED")                             # same path, new content
        assert not budget.Ledger(tmp_path / "s.json", lane="crawl.js_fetch").has("u")

    def test_missing_artifact_is_not_trusted(self, tmp_path):
        art = self._mk(tmp_path)
        led = budget.Ledger(tmp_path / "s.json", lane="crawl.js_fetch")
        led.record("u", art); led.save()
        art.unlink()
        assert not budget.Ledger(tmp_path / "s.json", lane="crawl.js_fetch").has("u")

    def test_entry_without_a_digest_fails_closed(self, tmp_path):
        art = self._mk(tmp_path)
        led = budget.Ledger(tmp_path / "s.json", lane="crawl.js_fetch")
        led.record("u", art); led.save()
        p = tmp_path / "s.json"
        st = json.loads(p.read_text()); st["digests"] = {}; p.write_text(json.dumps(st))
        assert not budget.Ledger(p, lane="crawl.js_fetch").has("u")   # unverifiable -> redo

    def test_foreign_lane_state_is_ignored(self, tmp_path):
        art = self._mk(tmp_path)
        led = budget.Ledger(tmp_path / "s.json", lane="crawl.js_fetch")
        led.record("u", art); led.save()
        assert not budget.Ledger(tmp_path / "s.json", lane="crawl.sourcemaps").has("u")

    def test_path_escape_is_rejected(self, tmp_path):
        p = tmp_path / "s.json"
        p.write_text(json.dumps({"lane": "l", "done": {"u": "../../etc/passwd"},
                                 "digests": {"../../etc/passwd": "x" * 64}}))
        assert not budget.Ledger(p, lane="l").has("u")

    @pytest.mark.parametrize("blob", ["", "not json", "[]", "null", '{"lane":"l"}',
                                      '{"lane":"l","done":[],"digests":{}}'])
    def test_garbled_state_starts_clean_without_raising(self, tmp_path, blob):
        p = tmp_path / "s.json"
        p.write_text(blob)
        assert budget.Ledger(p, lane="l").done == {}

    def test_a_growing_eligible_set_does_not_invalidate_prior_work(self, tmp_path):
        """Deliberately NOT nuclei's shape. nuclei keys state on a work_unit folding its whole host list,
        because its chunks are defined by that list. A fetch lane's eligible set GROWS every run (more
        crawling => more JS URLs), so a work-unit-gated map would invalidate on every growth and re-fetch
        everything. Per-ITEM keying means new items are simply remainder."""
        a1, a2 = self._mk(tmp_path, "1.js"), self._mk(tmp_path, "2.js")
        led = budget.Ledger(tmp_path / "s.json", lane="l")
        led.record("u1", a1); led.record("u2", a2); led.save()
        again = budget.Ledger(tmp_path / "s.json", lane="l")
        assert again.has("u1") and again.has("u2") and not again.has("u3_newly_discovered")


class TestCoverageReports:
    LANE = "crawl.js_fetch"

    def _gaps(self, tmp_path):
        from quarry_recon.store import Run
        st = Run.create(tmp_path, "t", run_id="r1")
        return st, [g for g in st._run_summary()["gaps"] if g["tool"] == self.LANE]

    def _fresh(self, tmp_path):
        from quarry_recon.store import Run
        events.reset()
        st = Run.create(tmp_path, "t", run_id="r1")
        events.configure(st.dir)
        return st

    def test_full_coverage_is_not_a_gap(self, tmp_path):
        st = self._fresh(tmp_path)
        budget.report_selection(self.LANE, measure="js_urls", eligible=500, attempted=500,
                                budget=budget.Budget(0), noun="JS URL")
        gaps = [g for g in st._run_summary()["gaps"] if g["tool"] == self.LANE]
        assert gaps == []                                      # unbounded default -> nothing omitted

    def test_budget_remainder_is_a_gap_naming_it_resumable(self, tmp_path):
        st = self._fresh(tmp_path)
        b = budget.Budget(60)
        budget.report_selection(self.LANE, measure="js_urls", eligible=5058, attempted=2000,
                                budget=b, noun="JS URL")
        gaps = [g for g in st._run_summary()["gaps"] if g["tool"] == self.LANE]
        assert len(gaps) == 1
        assert gaps[0]["status"] == f"coverage:{events.COVERAGE_CAP}"   # a ceiling that truncated input
        assert gaps[0]["omitted"] == 3058 and gaps[0]["eligible"] == 5058
        assert "RESUMABLE remainder" in gaps[0]["why"]

    def test_selection_and_outcome_are_separate_measures(self, tmp_path):
        """They have different causes and different fixes: selection loss is OURS (a budget), outcome loss is
        the TARGET's. Summing them would hide both. The outcome number was invisible before — OTC attempted
        2000 JS URLs and obtained 628, a 69% in-flight loss nobody could see."""
        st = self._fresh(tmp_path)
        b = budget.Budget(0)
        budget.report_selection(self.LANE, measure="js_urls", eligible=2000, attempted=2000, budget=b)
        budget.report_outcome(self.LANE, measure="js_fetched", attempted=2000, obtained=628,
                              classes={"http_403": 900, "not_contacted": 472})
        summ = st._run_summary()
        gaps = {g["measure"]: g for g in summ["gaps"] if g["tool"] == self.LANE}
        assert set(gaps) == {"js_fetched"}                     # selection fully covered -> no gap
        assert gaps["js_fetched"]["omitted"] == 1372
        assert gaps["js_fetched"]["status"] == f"coverage:{events.COVERAGE_TIMEOUT}"
        assert "http_403" in gaps["js_fetched"]["why"]         # the error classes are reported, not just a count
        # the two measures are aggregated separately — never one denominator
        measures = {c["measure"] for c in summ["coverage"] if c["source_id"] == self.LANE}
        assert measures == {"js_urls", "js_fetched"}

    def test_clean_outcome_is_not_a_gap(self, tmp_path):
        st = self._fresh(tmp_path)
        budget.report_outcome(self.LANE, measure="js_fetched", attempted=10, obtained=10)
        assert [g for g in st._run_summary()["gaps"] if g["tool"] == self.LANE] == []

    def test_a_later_unbounded_run_clears_a_prior_budget_gap(self, tmp_path):
        st = self._fresh(tmp_path)
        budget.report_selection(self.LANE, measure="js_urls", eligible=100, attempted=40,
                                budget=budget.Budget(30))
        assert [g for g in st._run_summary()["gaps"] if g["tool"] == self.LANE][0]["omitted"] == 60
        events.reset(); events.configure(st.dir)               # new generation, unbounded this time
        budget.report_selection(self.LANE, measure="js_urls", eligible=100, attempted=100,
                                budget=budget.Budget(0))
        assert [g for g in st._run_summary()["gaps"] if g["tool"] == self.LANE] == []
