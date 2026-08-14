"""Structured child faults and provider spend — settle prerequisite D.

A campaign decides whether to keep going from a child's manifest, and it may not do that by matching prose:
`failures` does not separate a machinery break from an optional tool's failure, a REQUIRED missing tool
arrives in `gaps` instead, and no field carried spend at all. These are the machine-readable versions.
"""
from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.offline

from quarry_recon import events, store
from quarry_recon.runner import RunResult, Status


def _run(tmp_path):
    run = store.Run.create(tmp_path, "t")
    events.reset()
    events.configure(run.dir)
    return run


class TestChildFaults:
    def test_a_MACHINERY_failure_is_named_as_one(self, tmp_path):
        run = _run(tmp_path)
        try:
            run.record("probe", RunResult("httpx", ["httpx"], Status.FAILED, 1, 0.1, None, 0,
                                          note="the tool exploded"))
            run.write_manifest(profile_summary={}, phases_run=["probe"])
        finally:
            events.reset()
        faults = json.loads(run.manifest_path.read_text())["summary"]["faults"]
        # a typed Fault: the campaign reads the kind, and whether it challenges completeness, not prose
        assert faults == [{"kind": "machinery", "where": "httpx", "detail": "the tool exploded",
                           "challenges_completeness": True}], faults

    def test_an_OPTIONAL_tool_failing_is_not_machinery(self, tmp_path, monkeypatch):
        """Repeating a run is continuation; repeating a BROKEN run is not. An optional tool that failed is
        not the same claim, and the campaign has to be able to tell them apart without reading English."""
        from quarry_recon import registry
        real = registry.load_tools
        monkeypatch.setattr(registry, "load_tools",
                            lambda *a, **k: [t.__class__(**{**t.__dict__, "optional": True})
                                             if t.bin == "gowitness" else t for t in real()])
        run = _run(tmp_path)
        try:
            run.record("probe", RunResult("gowitness", ["gowitness"], Status.FAILED, 1, 0.1, None, 0,
                                          note="no chromium"))
            run.write_manifest(profile_summary={}, phases_run=["probe"])
        finally:
            events.reset()
        kinds = [f["kind"] for f in json.loads(run.manifest_path.read_text())["summary"]["faults"]]
        assert kinds == ["optional_tool_failed"], kinds

    def test_a_REQUIRED_missing_tool_is_its_own_fault(self, tmp_path):
        """It arrives in `gaps`, never in `failures` — so a campaign matching failures alone misses it."""
        run = _run(tmp_path)
        try:
            run.record("vertical", RunResult("subfinder", ["subfinder"], Status.SKIPPED, None, 0.0, None,
                                             0, note="subfinder not on path"))
            run.write_manifest(profile_summary={}, phases_run=["vertical"])
        finally:
            events.reset()
        summary = json.loads(run.manifest_path.read_text())["summary"]
        assert [f["kind"] for f in summary["faults"]] == ["required_tool_missing"], summary["faults"]
        assert summary["faults"][0]["where"] == "subfinder"

    def test_a_PHASE_EXCEPTION_is_a_fault(self, tmp_path):
        run = _run(tmp_path)
        try:
            run.notes.append("EXCEPTION in vertical: RuntimeError('boom')")
            run.write_manifest(profile_summary={}, phases_run=["vertical"])
        finally:
            events.reset()
        faults = json.loads(run.manifest_path.read_text())["summary"]["faults"]
        assert [f["kind"] for f in faults] == ["phase_exception"], faults

    def test_a_clean_child_has_NO_faults(self, tmp_path):
        run = _run(tmp_path)
        try:
            run.record("probe", RunResult("httpx", ["httpx"], Status.SUCCESS, 0, 0.1, None, 3))
            run.write_manifest(profile_summary={}, phases_run=["probe"])
        finally:
            events.reset()
        assert json.loads(run.manifest_path.read_text())["summary"]["faults"] == []


class TestProviderSpend:
    def test_spend_is_summed_per_lane_provider_and_MEASURE(self, tmp_path):
        """Pages and query credits are different currencies — `pages_bought` is not equivalent to charged
        requests, so nothing is summed across measures."""
        run = _run(tmp_path)
        try:
            events.spend("probe.favicon", provider="shodan", measure="pages", amount=3)
            events.spend("probe.favicon", provider="shodan", measure="pages", amount=2)
            events.spend("probe.favicon", provider="shodan", measure="query_credits", amount=5)
            events.spend("osint.whoxy", provider="whoxy", measure="pages", amount=1)
            run.write_manifest(profile_summary={}, phases_run=["probe"])
        finally:
            events.reset()
        rows = {(r["lane"], r["measure"]): r for r in
                json.loads(run.manifest_path.read_text())["summary"]["provider_spend"]}
        assert rows[("probe.favicon", "pages")]["amount"] == 5
        assert rows[("probe.favicon", "query_credits")]["amount"] == 5
        assert rows[("osint.whoxy", "pages")] == {"lane": "osint.whoxy", "provider": "whoxy",
                                                  "measure": "pages", "amount": 1, "unknown": 0}

    @pytest.mark.parametrize("amount", [None, -1, True, 1.5, "3"])
    def test_an_UNCOUNTABLE_amount_is_not_zero(self, tmp_path, amount):
        """The lane spent something nobody can count — reporting 0 would tell a campaign it was free."""
        run = _run(tmp_path)
        try:
            events.spend("probe.cert", provider="shodan", measure="pages", amount=amount)
            run.write_manifest(profile_summary={}, phases_run=["probe"])
        finally:
            events.reset()
        row = json.loads(run.manifest_path.read_text())["summary"]["provider_spend"][0]
        assert (row["amount"], row["unknown"]) == (0, 1), row

    @pytest.mark.parametrize("amount,kept", [(3, 3), (0, 0), (True, None), (1.0, None), ("3", None),
                                             (-1, None), (None, None)])
    def test_the_EVENT_itself_refuses_a_non_count(self, tmp_path, amount, kept):
        """Both ends guard it: the emitter drops what is not an exact non-negative int, and the fold counts
        what survives as unknown. A bool is not a count at either end."""
        run = _run(tmp_path)
        try:
            rec = events.spend("probe.cert", provider="shodan", measure="pages", amount=amount)
        finally:
            events.reset()
        assert rec.get("amount", None) == kept, (amount, rec)

    def test_a_child_that_bought_NOTHING_reports_nothing(self, tmp_path):
        run = _run(tmp_path)
        try:
            run.write_manifest(profile_summary={}, phases_run=["probe"])
        finally:
            events.reset()
        assert json.loads(run.manifest_path.read_text())["summary"]["provider_spend"] == []

    def test_the_shodan_pivot_lanes_REPORT_what_they_bought(self):
        """Wired at the site that knows: replayed pages cost nothing, bought pages are the bill."""
        import pathlib
        from quarry_recon.phases import probe
        src = pathlib.Path(probe.__file__).read_text()
        assert 'events.spend(spec.sid, provider="shodan", measure="pages", amount=int(o.pages_bought))' \
            in src

    def test_the_WHOXY_lane_reports_what_it_bought(self, tmp_path):
        """A Quarry-owned provider path with its own counters: a child could buy pages while its manifest
        reported no spend at all. Replayed pages are free, so only the bought ones are the bill."""
        from quarry_recon import osint, whoxy_page as wp
        run = _run(tmp_path)

        class _Session:
            def record(self, _r):
                pass

        try:
            out = wp.Outcome(anchors=2, pages_bought=4, pages_replayed=3, domains=9,
                             requests_issued=11)
            osint._whoxy_record(_Session(), out, wp.SpendPolicy(), [], lambda _m: None)
            run.write_manifest(profile_summary={}, phases_run=["osint"])
        finally:
            events.reset()
        rows = json.loads(run.manifest_path.read_text())["summary"]["provider_spend"]
        assert rows == [{"lane": "osint.whoxy", "provider": "whoxy", "measure": "pages",
                         "amount": 4, "unknown": 0}], rows      # bought only — never replayed or requests

    def test_a_whoxy_child_that_bought_NOTHING_reports_zero_not_silence(self, tmp_path):
        from quarry_recon import osint, whoxy_page as wp
        run = _run(tmp_path)

        class _Session:
            def record(self, _r):
                pass

        try:
            osint._whoxy_record(_Session(), wp.Outcome(anchors=1, pages_replayed=2), wp.SpendPolicy(),
                                [], lambda _m: None)
            run.write_manifest(profile_summary={}, phases_run=["osint"])
        finally:
            events.reset()
        rows = json.loads(run.manifest_path.read_text())["summary"]["provider_spend"]
        assert rows == [{"lane": "osint.whoxy", "provider": "whoxy", "measure": "pages",
                         "amount": 0, "unknown": 0}], rows
