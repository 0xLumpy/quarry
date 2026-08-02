"""Acquisition closes after a campaign's first child — settle, the closure step.

`--settle` repeats whole runs, and a run contains ACQUISITION lanes. A supervisor that let child 2 buy
again would be making a spending decision no continuation flag may make. There are THREE doors into a
provider — `run_provider`, `run_providers` and `run_contract` — plus one lane that runs plain HTTP outside
the registry entirely, so a gate in any single one of them is not a gate.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from quarry_recon import campaign, contract, events, policy, sources
from quarry_recon.runner import RunResult, Status


class TestTheGateItself:
    def test_acquisition_is_OPEN_by_default(self):
        """An ordinary `quarry run` acquires exactly as it always has."""
        for lane in policy.PROVIDER_LANES:
            assert campaign.acquisition_allowed(lane) == (True, "")

    def test_closing_it_refuses_ONLY_acquisition_lanes(self):
        with campaign.acquisition_closed("after child 1"):
            for lane in policy.PROVIDER_LANES:
                allowed, why = campaign.acquisition_allowed(lane)
                assert not allowed and why == "after child 1", lane
            # processing is exactly what a later child exists to do
            for lane in ("probe.httpx", "enrich.a1d_brute", "crawl.katana_standard"):
                assert campaign.acquisition_allowed(lane) == (True, ""), lane

    def test_the_closure_is_RESTORED_afterwards(self):
        with campaign.acquisition_closed():
            assert not campaign.acquisition_allowed("probe.favicon")[0]
        assert campaign.acquisition_allowed("probe.favicon") == (True, "")

    def test_it_is_restored_even_when_the_child_RAISES(self):
        with pytest.raises(KeyboardInterrupt):
            with campaign.acquisition_closed():
                raise KeyboardInterrupt("ctrl-c mid-child")
        assert campaign.acquisition_allowed("probe.favicon")[0]


class TestEveryDoorIsGated:
    def _log(self, tmp_path):
        events.reset()
        events.configure(tmp_path)
        return tmp_path / "events.jsonl"

    def test_run_provider_refuses_a_closed_lane(self, tmp_path):
        log = self._log(tmp_path)
        ran: list = []
        try:
            with campaign.acquisition_closed("after child 1"):
                out = contract.run_provider("probe.shodan_host", lambda: ran.append(1))
        finally:
            events.reset()
        assert out is None and ran == [], ran
        blocked = [json.loads(l) for l in log.read_text().splitlines()
                   if json.loads(l).get("event") == "tool_blocked"]
        assert blocked and blocked[-1]["source_id"] == "probe.shodan_host", blocked
        assert "after child 1" in blocked[-1]["reason"], blocked

    def test_run_providers_refuses_a_closed_lane(self, tmp_path):
        self._log(tmp_path)
        shared: list = []
        try:
            with campaign.acquisition_closed():
                results = contract.run_providers(
                    [("probe.favicon", None, lambda: None), ("probe.cert", None, lambda: None)],
                    lambda: shared.append(1))
        finally:
            events.reset()
        assert results == {} or all(v is None for v in results.values()), results
        assert shared == [], "the shared body must not run for a closed campaign"

    def test_run_contract_refuses_a_closed_lane(self, tmp_path, monkeypatch):
        self._log(tmp_path)
        monkeypatch.setattr(contract, "_run",
                            lambda *a, **k: pytest.fail("a closed lane must not execute"))
        try:
            with campaign.acquisition_closed("after child 1"):
                res = contract.run_contract("vertical.shosubgo", ["shosubgo", "-d", "acme.com"])
        finally:
            events.reset()
        assert res.status is Status.SKIPPED and "after child 1" in (res.note or ""), res

    def test_the_DIRECT_HTTP_door_is_gated_too(self, tmp_path, monkeypatch):
        """`osint.whoxy` runs plain HTTP outside the registry — the door a central gate would have missed."""
        from quarry_recon import osint
        self._log(tmp_path)
        monkeypatch.setattr(osint, "_whoxy_get",
                            lambda *a, **k: pytest.fail("a closed campaign must not query Whoxy"))
        recorded: list = []

        class _S:
            def record(self, r):
                recorded.append(r)

            def fail(self, *a, **k):
                pass

        try:
            with campaign.acquisition_closed("after child 1"):
                osint._whoxy(_S(), {"a@acme.com"}, ["Acme"], lambda _m: None, 30)
        finally:
            events.reset()
        assert recorded and recorded[-1].status is Status.SKIPPED, recorded
        assert "after child 1" in (recorded[-1].note or ""), recorded

    def test_an_OPEN_campaign_still_runs_the_lane(self, tmp_path):
        self._log(tmp_path)
        try:
            out = contract.run_provider("probe.shodan_host", lambda: "ran")
        finally:
            events.reset()
        assert out == "ran"


class TestTheClosureIsComplete:
    """Not a spot check. Every acquisition lane declares the DOOR it executes through, and the doors are
    checked against the code — a registered provider that started making its own HTTP calls would sail
    through a test that only counts gate strings."""

    def _sources(self):
        import pathlib
        root = pathlib.Path(contract.__file__).parent
        return {p: p.read_text(encoding="utf-8") for p in root.rglob("*.py")}

    def test_every_acquisition_lane_declares_a_door(self):
        owned = {lane for lane, kind in policy.SOURCE_OWNERSHIP.items() if kind == "quarry_provider"}
        declared = set(policy.PROVIDER_DOORS)
        assert declared == owned | set(policy.PROVIDER_LANES_OUTSIDE_REGISTRY), declared ^ owned
        assert set(policy.PROVIDER_DOORS.values()) <= set(policy.DOORS)

    def test_both_REGISTRY_doors_gate(self):
        src = pathlib.Path(contract.__file__).read_text()
        assert src.count("if not acquisition_open(source_id") == 2, "both registry doors must gate"
        assert "def acquisition_open(" in src

    def test_every_DIRECT_HTTP_lane_gates_itself(self):
        for lane, door in policy.PROVIDER_DOORS.items():
            if door != "direct_http":
                continue
            hits = [txt for txt in self._sources().values()
                    if f'acquisition_allowed("{lane}")' in txt]
            assert hits, f"{lane} declares direct_http and gates nothing"

    def test_a_lane_that_makes_its_OWN_http_must_declare_direct_http(self):
        """The invariant the string count could not carry: a module that opens sockets itself AND owns a
        registry-door lane has to route that lane through its declared door, or the closure misses it."""
        doors = {"run_provider": "run_provider(", "run_providers": "run_providers(",
                 "run_contract": "run_contract("}
        offenders = []
        for path, txt in self._sources().items():
            if "urllib.request.urlopen" not in txt:
                continue
            for lane, door in policy.PROVIDER_DOORS.items():
                # only a FULL lane id counts as a mention: a bare word like "cert" appears in prose and
                # in unrelated identifiers, and a false accusation is not an invariant
                if f'"{lane}"' not in txt or door == "direct_http":
                    continue
                if doors[door] not in txt:
                    offenders.append((path.name, lane, door))
        assert not offenders, offenders

    def test_the_registry_ids_are_real(self):
        gated_outside = set(policy.PROVIDER_LANES_OUTSIDE_REGISTRY)
        for lane in policy.PROVIDER_LANES:
            assert lane in sources.all_sources() or lane in gated_outside, lane


class TestARefusedLaneStillHasALifecycle:
    """A manifest that simply lacks the lane says "nobody ran it". A closed campaign is a DECISION, and it
    has to read as one — start, then a skipped terminal carrying the reason."""

    def test_run_provider_records_start_and_a_SKIPPED_terminal(self, tmp_path):
        events.reset()
        events.configure(tmp_path)
        try:
            with campaign.acquisition_closed("after child 1"):
                assert contract.run_provider("probe.shodan_host", lambda: "ran") is None
        finally:
            events.reset()
        rows = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        kinds = [r["event"] for r in rows]
        assert kinds == ["tool_blocked", "tool_start", "tool_finish"], kinds
        assert rows[-1]["status"] == "skipped" and "after child 1" in rows[-1]["reason"], rows[-1]
        assert rows[1].get("provider") and rows[-1].get("provider"), rows

    def test_the_terminal_SUPERSEDES_an_earlier_generation(self, tmp_path):
        """An un-terminated start would leave the previous generation standing — the reason a refusal
        needs the whole lifecycle rather than a blocked event."""
        events.reset()
        events.configure(tmp_path)
        try:
            contract.run_provider("probe.shodan_host", lambda: "ran")          # generation 1: it ran
            with campaign.acquisition_closed("after child 1"):
                contract.run_provider("probe.shodan_host", lambda: "ran")      # generation 2: refused
        finally:
            events.reset()
        finishes = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()
                    if json.loads(l).get("event") == "tool_finish"]
        assert [f["status"] for f in finishes] == ["success", "skipped"], finishes

    def test_run_providers_gives_EVERY_refused_lane_its_terminal(self, tmp_path):
        events.reset()
        events.configure(tmp_path)
        shared: list = []
        try:
            with campaign.acquisition_closed():
                contract.run_providers([("probe.favicon", None, lambda: None),
                                        ("probe.cert", None, lambda: None)], lambda: shared.append(1))
        finally:
            events.reset()
        rows = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        finished = {r["source_id"] for r in rows if r["event"] == "tool_finish" and r["status"] == "skipped"}
        assert finished == {"probe.favicon", "probe.cert"}, finished
        assert shared == [], "the shared body SPENDS — it must not run for refused lanes"
