"""Step 6 — DOM sources and sinks as evidence.

The measurement behind this half: 2508 source/sink findings across the OTC corpus, and Quarry emitted
none of that class before. What must hold is that the roles come from the analyzer's OWN names, that a
source and a sink in one bundle is never presented as a flow, and that the informational families —
which outnumber the rest by two orders of magnitude — stay in the raw artifact rather than the store.
"""
from __future__ import annotations

import pytest

from quarry_recon import ast_obs


def _m(analyzer, value, tags=(), line=1, col=0):
    return {"analyzerName": analyzer, "value": value, "start": {"line": line, "column": col},
            "tags": {t: True for t in tags}}


def _norm(doc, bundle="b.js", digest="d" * 64):
    return ast_obs.sink_observations(doc, bundle=bundle, bundle_digest=digest,
                                     bundle_url="https://acme.com/b.js", artifact="/raw/x.json")


class TestTheRolesComeFromMeasuredNames:
    @pytest.mark.parametrize("analyzer,role", [
        ("inner-html", "sink"), ("dangerouslySetInnerHTML", "sink"), ("eval", "sink"),
        ("window-open", "sink"), ("postmessage", "sink"),
        ("location", "source"), ("url-search-params", "source"), ("onmessage", "source"),
        ("local-storage", "storage"), ("cookie", "storage"),
        ("add-event-listener", "channel"),
    ])
    def test_each_analyzer_has_its_role(self, analyzer, role):
        rows = _norm([_m(analyzer, "x()")])
        assert rows and rows[0]["role"] == role and role in rows[0]["tags"]

    def test_the_names_are_the_ANALYZERS_own(self):
        """MEASURED against real artifacts: it emits `dangerouslySetInnerHTML` and `regex`, not the file
        names those analyzers live in. Guessing produced a table that classified nothing."""
        assert "dangerouslySetInnerHTML" in ast_obs.SINK_ROLES
        assert "regex" in ast_obs.SINK_ROLES
        assert "react-dangerously-set-inner-html" not in ast_obs.SINK_ROLES

    def test_the_analyzers_own_tags_ride_along(self):
        """`cookie-read` vs `cookie-assignment` and `property-getItem` vs `property-setItem` are what say
        which DIRECTION a storage access is — this layer keeps them rather than deciding."""
        rows = _norm([_m("cookie", "document.cookie", ["cookie", "cookie-read"])])
        assert {"storage", "cookie", "cookie-read"} <= set(rows[0]["tags"])


class TestWhatIsNormalisedAndWhatStaysInTheArtifact:
    def test_informational_families_are_not_stored_as_entities(self):
        """`regex` and `hostname` were 13,953 of ~14,000 matches in two bundles. The raw artifact is the
        complete record and holds every one of them; a million rows of context nobody queries is not."""
        rows = _norm([_m("regex", "/x/", ["regex-pattern"]), _m("hostname", "acme.com"),
                      _m("inner-html", "el.innerHTML=e.data")])
        assert [r["analyzer"] for r in rows] == ["inner-html"]

    def test_path_analyzers_are_not_sinks(self):
        assert _norm([_m("robust-paths", "/api/x"), _m("fetch", "/api/y")]) == []

    def test_an_empty_or_whitespace_match_is_not_a_record(self):
        assert _norm([_m("inner-html", "   ")]) == []


class TestAggregationAndSafety:
    def test_the_same_construct_in_two_bundles_is_one_observation(self):
        a = _norm([_m("inner-html", "el.innerHTML=e.data")], bundle="a.js", digest="a" * 64)
        b = _norm([_m("inner-html", "el.innerHTML=e.data")], bundle="b.js", digest="b" * 64)
        assert a[0]["id"] == b[0]["id"], "a vendor bundle shipped twice is not two findings"

    def test_repeats_within_a_bundle_count_per_bundle(self):
        rows = _norm([_m("eval", "eval(x)"), _m("eval", "eval(x)"), _m("eval", "eval(x)")])
        assert len(rows) == 1 and rows[0]["sightings"][0]["n"] == 3

    def test_a_multiline_match_is_stored_on_one_line(self):
        """A record that breaks a report's markdown is a record nobody reads."""
        rows = _norm([_m("dangerouslySetInnerHTML", "{\n   dangerouslySetInnerHTML: {\n  __html: x\n}")])
        assert "\n" not in rows[0]["value"] and "dangerouslySetInnerHTML: {" in rows[0]["value"]

    def test_positions_are_validated_where_they_are_written(self):
        rows = _norm([_m("eval", "eval(x)", line=True, col={}),
                      _m("inner-html", "el.innerHTML=y", line=4, col=9)])
        sites = {r["analyzer"]: r["sites"][0] for r in rows}
        assert sites["eval"]["line"] is None and sites["eval"]["column"] is None
        assert sites["inner-html"]["line"] == 4 and sites["inner-html"]["column"] == 9


class TestTheReportNeverClaimsAFlow:
    @staticmethod
    def _run(tmp_path, rows):
        from quarry_recon import store
        run = store.Run.create(tmp_path, "acme.com")
        for r in rows:
            run.add("sink_observation", r)
        return run

    def test_the_hotlist_says_a_source_and_a_sink_are_not_a_flow(self, tmp_path):
        from quarry_recon import triage
        from quarry_recon.config import ScopeMatcher
        rows = _norm([_m("onmessage", "window.addEventListener('message',f)"),
                      _m("inner-html", "el.innerHTML=e.data")])
        md = triage.build(self._run(tmp_path, rows), ScopeMatcher([], [], [], False))
        assert "## DOM sources & sinks (2) — evidence, 2 data-flow" in md
        assert "is not a flow" in md
        assert "### SINK  (1)" in md and "### SOURCE  (1)" in md

    def test_the_digest_queue_is_canonical_and_non_actionable(self, tmp_path):
        from quarry_recon import triage
        from quarry_recon.config import ScopeMatcher
        from quarry_recon.triage import CANONICAL_QUEUES
        assert "sink_observations" in CANONICAL_QUEUES
        empty = triage.digest_json(self._run(tmp_path, []), ScopeMatcher([], [], [], False))
        assert empty["queues"]["sink_observations"] == []
        run = self._run(tmp_path, _norm([_m("eval", "eval(location.hash)")]))
        q = triage.digest_json(run, ScopeMatcher([], [], [], False))["queues"]["sink_observations"]
        assert len(q) == 1 and q[0]["confidence"] == "candidate"
        assert "impact:none_proven" in q[0]["tags"] and "dom" in q[0]["tags"]
        assert "not a flow" in q[0]["why"]

    def test_the_display_cap_is_disclosed(self, tmp_path):
        from quarry_recon import triage
        from quarry_recon.config import ScopeMatcher
        rows = _norm([_m("eval", f"eval(x{i})") for i in range(12)])
        md = triage.build(self._run(tmp_path, rows), ScopeMatcher([], [], [], False))
        assert "… 4 more — full list in normalized/sink_observation.jsonl" in md


class TestIdentityIsNotTheDisplay:
    def test_two_long_matches_sharing_a_prefix_stay_distinct(self):
        """Minified code is exactly the shape where the first 400 characters repeat. Hashing the
        truncation collapsed two distinct expressions into one observation."""
        shared = "x" * 500
        rows = _norm([_m("eval", f"eval({shared}A)"), _m("eval", f"eval({shared}B)")])
        assert len({r["id"] for r in rows}) == 2, "identity must come from the COMPLETE value"
        assert all(len(r["value"]) <= 400 and r["truncated"] for r in rows), "the PREVIEW is capped"
        assert all(r["value_len"] > 400 for r in rows), "and the record says how much was cut"

    def test_the_digest_queue_keeps_them_apart_too(self, tmp_path):
        """`_item` derives an id from the value it is shown; a 160-character display would merge two
        distinct records during queue dedup."""
        from quarry_recon import triage
        from quarry_recon.config import ScopeMatcher
        shared = "y" * 300
        rows = _norm([_m("eval", f"eval({shared}A)"), _m("eval", f"eval({shared}B)")])
        run = TestTheReportNeverClaimsAFlow._run(tmp_path, rows)
        q = triage.digest_json(run, ScopeMatcher([], [], [], False))["queues"]["sink_observations"]
        assert len(q) == 2, "two observations, two queue items"
        assert len({i["id"] for i in q}) == 2


class TestTheCountersMeanWhatTheySay:
    def test_a_sink_in_two_bundles_counts_once(self, tmp_path, monkeypatch):
        """The store and the report show one observation; a per-artifact sum reported two."""
        import json as _json
        from tests.test_ast_lane import TestTheWorkUnitMakesARerunSKIP, _bundle, _ctx, _ledger
        doc = [{"analyzerName": "eval", "value": "eval(x)", "start": {"line": 1, "column": 0}}]
        TestTheWorkUnitMakesARerunSKIP._fake(monkeypatch, tmp_path, out=_json.dumps(doc))
        from quarry_recon.phases import crawl as _crawl
        monkeypatch.setattr(_crawl, "have", lambda b: True)
        monkeypatch.setattr(_crawl.cgroup, "clear", lambda unit: None)
        monkeypatch.setattr(_crawl.cgroup, "stop", lambda unit, budget_s=30.0: True)
        ctx, run = _ctx(tmp_path)
        arts = [(f"https://acme.com/{i}.js", _bundle(tmp_path, f"{i}.js", size=100 + i)) for i in range(2)]
        _crawl._ast_bundles(ctx, _ledger(arts))
        assert len(list(run.read("sink_observation"))) == 1
        assert ctx._ast_stats["sinks"] == 1, "the counter counts observations, not bundle-sink pairs"

    def test_a_malformed_record_is_one_gap_not_a_crash(self, tmp_path, monkeypatch):
        import json as _json
        from tests.test_ast_lane import TestTheWorkUnitMakesARerunSKIP, _bundle, _ctx, _ledger
        from quarry_recon import ast_obs as _ao
        from quarry_recon.phases import crawl as _crawl
        TestTheWorkUnitMakesARerunSKIP._fake(monkeypatch, tmp_path,
                                             out=_json.dumps([{"analyzerName": "eval", "value": "x"}]))
        monkeypatch.setattr(_crawl, "have", lambda b: True)
        monkeypatch.setattr(_crawl.cgroup, "clear", lambda unit: None)
        monkeypatch.setattr(_crawl.cgroup, "stop", lambda unit, budget_s=30.0: True)
        monkeypatch.setattr(_ao, "sink_observations",
                            lambda *a, **k: (_ for _ in ()).throw(TypeError("broken record")))
        ctx, _run = _ctx(tmp_path)
        _crawl._ast_bundles(ctx, _ledger([("https://acme.com/b.js", _bundle(tmp_path))]))
        assert ctx._ast_stats["unnormalised"] == 1
        assert ctx._ast_stats["dispositions"].get("unreadable-artifact") == 1
