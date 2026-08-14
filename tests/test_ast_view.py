"""Step 5 — the prioritised VIEW over `path_observation`.

A view, not a promotion: it ranks evidence that is already stored, creates no entity, and nothing is
fetched because a row matched. What it must get right is the definition (the measured conjunction, not
the tag), what it excludes and why, and that a row it leaves out is still there.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.offline

from quarry_recon import ast_obs


def _obs(key, tags, *, corroborated=(), n=1):
    return {"id": key, "value": key, "tags": list(tags), "sources": ["jxscout-ast"],
            "corroborated_by": list(corroborated), "sightings": [{"bundle": "b.js", "n": n}],
            "bundles": ["b.js"], "raw_ref": "raw/crawl/ast/x.json"}


class TestTheDefinition:
    def test_the_rule_is_the_CONJUNCTION_not_the_tag(self):
        """On one POAB bundle 214 of 254 api-shaped rows were also implausible
        (`/this.http.get("/portalapi/…`). The tag alone is a noise floor; the conjunction is what carried
        precision 0.90 on the unseen corpus."""
        assert ast_obs.high_priority(_obs("/api/users", ["api-shaped"]))
        assert not ast_obs.high_priority(_obs('/this.http.get("/api', ["api-shaped", "implausible"]))
        assert not ast_obs.high_priority(_obs("/some/path", []))

    @pytest.mark.parametrize("tag", sorted(ast_obs.EXCLUDED_TAGS))
    def test_the_excluded_classes_are_not_prioritised(self, tag):
        assert not ast_obs.high_priority(_obs("/api/thing", ["api-shaped", tag]))

    def test_an_excluded_row_is_still_EVIDENCE(self):
        """Exclusion is a ranking decision. The row stays in the store and in the artifact — the whole
        architecture rests on not deleting what a later pass might need."""
        rows = [_obs("/api/thing", ["api-shaped", "asset"]), _obs("/api/real", ["api-shaped"])]
        assert [r["id"] for r in ast_obs.priority_view(rows)] == ["/api/real"]
        assert len(rows) == 2, "the view filters a COPY; it does not consume the evidence"


class TestTheOrdering:
    def test_corroboration_orders_but_never_gates(self):
        """A path only this analyzer found is the interesting case — it must not sort itself out of
        sight, and it is never counted as something an incumbent contributed."""
        rows = [_obs("/api/alone", ["api-shaped"], n=1),
                _obs("/api/known", ["api-shaped"], corroborated=["katana"], n=1)]
        got = [r["id"] for r in ast_obs.priority_view(rows)]
        assert got == ["/api/known", "/api/alone"], "corroborated first"
        assert len(got) == 2, "and the uncorroborated one is still THERE"

    def test_more_sightings_rank_higher_then_stable_by_path(self):
        rows = [_obs("/api/b", ["api-shaped"], n=1), _obs("/api/a", ["api-shaped"], n=1),
                _obs("/api/c", ["api-shaped"], n=9)]
        assert [r["id"] for r in ast_obs.priority_view(rows)] == ["/api/c", "/api/a", "/api/b"]

    def test_a_malformed_row_cannot_break_the_view(self):
        rows = [_obs("/api/ok", ["api-shaped"]), {"id": "/x", "tags": None}, "not-a-record",
                {"id": "/y", "tags": ["api-shaped"], "sightings": "nope"}]
        assert [r["id"] for r in ast_obs.priority_view(rows)] == ["/api/ok", "/y"]


class TestWhatTheReportSays:
    @staticmethod
    def _run(tmp_path, rows):
        from quarry_recon import store
        run = store.Run.create(tmp_path, "acme.com")
        for r in rows:
            run.add("path_observation", r)
        return run

    def test_the_hotlist_names_it_evidence_and_bounds_the_display(self, tmp_path):
        from quarry_recon import triage
        from quarry_recon.config import ScopeMatcher
        rows = [_obs(f"/api/thing{i}", ["api-shaped"]) for i in range(20)]
        rows += [_obs("/assets/app.js", ["api-shaped", "asset"])]
        md = triage.build(self._run(tmp_path, rows), ScopeMatcher([], [], [], False))
        assert "## Path observations (21) — evidence, 20 prioritised" in md
        assert "NOT endpoints and NOT findings" in md
        assert "… 5 more prioritised — full list in normalized/path_observation.jsonl" in md, \
            "a bounded display must say it is bounded"
        assert "(1 further observation(s) kept as evidence, not prioritised)" in md

    def test_the_digest_queue_carries_impact_none_proven(self, tmp_path):
        from quarry_recon import triage
        from quarry_recon.config import ScopeMatcher
        run = self._run(tmp_path, [_obs("/api/x", ["api-shaped"], corroborated=["katana"], n=3)])
        d = triage.digest_json(run, ScopeMatcher([], [], [], False))
        q = d["queues"]["path_observations"]
        assert len(q) == 1
        assert "impact:none_proven" in q[0]["tags"] and "observation" in q[0]["tags"]
        assert "corroborated:katana" in q[0]["tags"] and "seen 3x" in q[0]["why"]
        assert q[0]["confidence"] == "candidate", "an observation is never a confirmed anything"

    def test_no_observations_means_no_section(self, tmp_path):
        from quarry_recon import triage
        from quarry_recon.config import ScopeMatcher
        md = triage.build(self._run(tmp_path, []), ScopeMatcher([], [], [], False))
        assert "Path observations" not in md


class TestCorroborationIsCurrentNotFrozen:
    """The record's `corroborated_by` is a snapshot from normalisation time; later lanes keep publishing.
    The view ranks on what the run knows NOW, without rewriting evidence that was true when written."""

    def test_a_fresh_map_beats_the_snapshot_for_ordering_and_display(self):
        rows = [_obs("/api/a", ["api-shaped"], n=5),
                _obs("/api/b", ["api-shaped"], n=1)]        # nobody corroborated it at write time
        fresh = {"/api/b": ["xnLinkFinder", "jsluice"]}
        assert [r["id"] for r in ast_obs.priority_view(rows, fresh)] == ["/api/b", "/api/a"]
        assert ast_obs.corroborators(rows[1], fresh) == ["xnLinkFinder", "jsluice"]
        assert rows[1]["corroborated_by"] == [], "the stored snapshot is not rewritten"

    def test_the_snapshot_and_the_fresh_map_are_UNIONED(self):
        """A RESUMED observation carries a snapshot from a run whose urls this store never held.
        Replacing it with the current map would lose evidence; corroboration only accumulates."""
        row = _obs("/api/a", ["api-shaped"], corroborated=["katana"])
        assert ast_obs.corroborators(row, {"/api/a": ["jsluice"]}) == ["katana", "jsluice"]
        assert ast_obs.corroborators(row, {}) == ["katana"]

    def test_without_a_fresh_map_the_snapshot_is_used(self):
        row = _obs("/api/a", ["api-shaped"], corroborated=["katana"])
        assert ast_obs.corroborators(row) == ["katana"]

    def test_the_report_uses_the_CURRENT_store(self, tmp_path):
        from quarry_recon import store, triage
        from quarry_recon.config import ScopeMatcher
        run = store.Run.create(tmp_path, "acme.com")
        run.add("path_observation", _obs("/api/late", ["api-shaped"]))     # written with no corroboration
        run.add("url", {"url": "https://acme.com/api/late", "sources": ["xnLinkFinder"]})   # …found later
        md = triage.build(run, ScopeMatcher([], [], [], False))
        assert "/api/late  ·  x1  ·  xnLinkFinder" in md, "the report must not say 'ast only' any more"
        q = triage.digest_json(run, ScopeMatcher([], [], [], False))["queues"]["path_observations"]
        assert "corroborated:xnLinkFinder" in q[0]["tags"]


class TestTheQueueIsCanonical:
    def test_it_is_present_even_with_no_observations(self, tmp_path):
        from quarry_recon import store, triage
        from quarry_recon.config import ScopeMatcher
        run = store.Run.create(tmp_path, "acme.com")
        d = triage.digest_json(run, ScopeMatcher([], [], [], False))
        assert d["queues"]["path_observations"] == [], "a canonical queue is always there, empty if unused"

    def test_it_is_present_when_observations_exist_but_none_are_prioritised(self, tmp_path):
        from quarry_recon import store, triage
        from quarry_recon.config import ScopeMatcher
        run = store.Run.create(tmp_path, "acme.com")
        run.add("path_observation", _obs("/assets/app.js", ["api-shaped", "asset"]))
        d = triage.digest_json(run, ScopeMatcher([], [], [], False))
        assert d["queues"]["path_observations"] == []
        assert "path_observations" in triage.CANONICAL_QUEUES

    def test_the_lane_runs_after_the_incumbent_miners(self):
        """Corroboration is frozen when the artifact is normalised, so the lane has to run after the
        tools it names — jsluice, xnLinkFinder and the sourcemap re-mine all publish late in the phase."""
        import inspect
        from quarry_recon.phases import crawl
        src = inspect.getsource(crawl.run)
        assert src.index("_xnl_lane(ctx, xnl_units)") < src.index("_ast_bundles(ctx"), \
            "the AST lane must come after xnLinkFinder"
        assert src.index("jsluice") < src.index("_ast_bundles(ctx")
