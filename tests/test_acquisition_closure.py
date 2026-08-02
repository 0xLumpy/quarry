"""Acquisition closes after a campaign's first child — settle, the closure step.

`--settle` repeats whole runs, and a run contains ACQUISITION lanes. A supervisor that let child 2 buy
again would be making a spending decision no continuation flag may make. There are THREE doors into a
provider — `run_provider`, `run_providers` and `run_contract` — plus one lane that runs plain HTTP outside
the registry entirely, so a gate in any single one of them is not a gate.
"""
from __future__ import annotations

import json

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
    def test_every_acquisition_lane_reaches_a_gate(self):
        """Completeness, not a spot check: every `quarry_provider` lane must be reachable only through a
        gated door — the registry doors, or the one out-of-registry path that gates itself."""
        import pathlib
        gated_outside = {"osint.whoxy"}
        src = pathlib.Path(contract.__file__).read_text()
        assert src.count("if not acquisition_open(source_id):") == 2, "both registry doors must gate"
        osint_src = pathlib.Path(sources.__file__).parent.joinpath("osint.py").read_text()
        assert 'acquisition_allowed("osint.whoxy")' in osint_src
        for lane in policy.PROVIDER_LANES:
            assert lane in sources.all_sources() or lane in gated_outside, lane
