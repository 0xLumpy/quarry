"""The §5 measurement harness itself, driven against a stub provider.

A script that spends real money is not exempt from the rules it measures. Every defect pinned here was
found by running it offline BEFORE it was allowed near the API: it read a balance field that does not
exist, declared a page cap it never applied (`SHODAN_MAX_PAGES` defaults to 0 = UNBOUNDED), drove a
hand-built lane spec the coordinator would have crashed on after paying, and accepted an unreadable
balance as a zero-spend success.

Nothing here touches the network: `_read_shodan_balance`, `_shodan_count` and `_shodan_page` are
replaced, and `secrets.shodan` returns a stand-in.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from quarry_recon.phases import probe

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "measure-shodan-replay.py"


@pytest.fixture
def harness(monkeypatch, tmp_path):
    """The real script, loaded as a module, with a stub provider behind it.

    The script injects its page cap into the PROCESS-GLOBAL settings cache — correct for a one-shot
    program that exits, and a leak inside a shared interpreter: it silently re-bounded an unrelated
    "the default page policy is unbounded" test that happened to run after it. The cache is restored."""
    from quarry_recon import settings
    settings.load()
    saved = dict(settings._cache.get("PERFORMANCE") or {})
    spec = importlib.util.spec_from_file_location("measure_shodan_replay", SCRIPT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    state = {"pages": 0, "bal": 50, "raise_after": None}

    def balance(key, timeout=15, cooldown=None):
        return probe.ShodanBalance(remaining=state["bal"], allowance=100, reserve=0,
                                   spendable=state["bal"], may_spend=True, reason="ok")

    def page(key, facet, value, pg):
        state["pages"] += 1
        state["bal"] -= 1                                  # a search page costs ONE query credit
        if state["raise_after"] and state["pages"] >= state["raise_after"]:
            raise RuntimeError("provider exploded after the credit was spent")
        return ([{"ip_str": "203.0.113.9", "hostnames": [f"h.{value}.example"], "port": 443}], 3, None)

    monkeypatch.setattr(probe, "_read_shodan_balance", balance)
    monkeypatch.setattr(probe, "_shodan_count", lambda k, f, v: (3, b'{"total": 3}', None))
    monkeypatch.setattr(probe, "_shodan_page", page)
    monkeypatch.setattr(m.secrets, "shodan", lambda: "STUB")
    m.state = state
    m.run_in = lambda project, *extra: _main(m, monkeypatch, project, *extra)
    yield m
    settings._cache["PERFORMANCE"] = saved


def _main(m, monkeypatch, project: Path, *extra) -> int:
    monkeypatch.setattr(sys, "argv", ["measure-shodan-replay.py", "--project", str(project), *extra])
    return m.main()


def _report(project: Path) -> dict:
    return json.loads((project / "measurement.json").read_text())


class TestItMeasuresTheClaim:
    def test_A_buys_and_B_replays_for_free(self, harness, tmp_path):
        assert harness.run_in(tmp_path / "p", "--run") == 0
        v = _report(tmp_path / "p")["verdict"]
        assert v["replay_works"] and v["b_bought"] == 0 and v["b_replayed_fresh"] == 2
        assert v["b_credits_spent"] == 0 and v["b_emitted_spend"] == 0
        assert harness.state["pages"] == 2, "B must issue no paid request at all"

    def test_preflight_issues_nothing(self, harness, tmp_path):
        assert harness.run_in(tmp_path / "p", "--preflight") == 0
        assert harness.state["pages"] == 0


class TestItCannotPassWithoutProof:
    def test_an_unreadable_balance_is_not_a_zero_spend(self, harness, monkeypatch, tmp_path):
        """review#2: `None` means the claim was never measured. Accepting it reported the experiment's
        own blindness as a success."""
        real = probe._read_shodan_balance
        seen = {"n": 0}

        def blind(key, timeout=15, cooldown=None):
            seen["n"] += 1
            if seen["n"] > 4:                              # preflight + A's two reads, then go blind
                return probe.ShodanBalance(remaining=None, allowance=None, reserve=0, spendable=None,
                                           may_spend=True, reason="unreadable", read_error="transport")
            return real(key, timeout, cooldown)
        monkeypatch.setattr(probe, "_read_shodan_balance", blind)
        assert harness.run_in(tmp_path / "p", "--run") != 0

    @staticmethod
    def _silence_accounting(monkeypatch, on_call: int):
        """Let the lane run normally but skip the RESULT step — where `events.spend` is emitted — on one
        run only. Silencing both hides which of the two gates is doing the work."""
        real = probe._shodan_result
        seen = {"n": 0}

        def maybe(spec, vals, work):
            seen["n"] += 1
            return "accounting suppressed" if seen["n"] == on_call else real(spec, vals, work)
        monkeypatch.setattr(probe, "_shodan_result", maybe)

    def test_a_missing_spend_record_is_not_evidence_of_zero(self, harness, monkeypatch, tmp_path):
        """review#3: Quarry's OWN accounting has to say zero too, and a record that was never written
        says nothing."""
        monkeypatch.setattr(probe, "_shodan_result", lambda spec, vals, work: "nothing emitted")
        assert harness.run_in(tmp_path / "p", "--run") != 0

    def test_A_without_accounting_never_reaches_B(self, harness, monkeypatch, tmp_path):
        """The A gate's own job: a purchase Quarry did not book is not a proven starting point, even
        though the balance and the lane counter agree with each other."""
        self._silence_accounting(monkeypatch, on_call=1)
        assert harness.run_in(tmp_path / "p", "--run") == 1
        rep = _report(tmp_path / "p")
        assert "B" not in rep and harness._emitted_spend(rep["A"]) is None
        assert rep["A"]["credits_spent"] == 2, "the balance was readable; the BOOKS were not written"

    def test_B_without_accounting_is_not_a_pass(self, harness, monkeypatch, tmp_path):
        """The verdict's own job: B's balance can read a clean zero while Quarry wrote nothing at all,
        and a zero-spend claim resting on one unread side is unmeasured."""
        self._silence_accounting(monkeypatch, on_call=2)
        assert harness.run_in(tmp_path / "p", "--run") == 1
        v = _report(tmp_path / "p")["verdict"]
        assert v["b_credits_spent"] == 0 and v["b_emitted_spend"] is None
        assert v["replay_works"] is False

    def test_a_disagreement_between_the_two_accountings_stops_the_experiment(self, harness, monkeypatch,
                                                                              tmp_path):
        """The provider charging more than Quarry booked is exactly the case the experiment exists to
        catch. It must stop at A, not average the two numbers into a verdict."""
        real = probe._shodan_page

        def double_charge(key, facet, value, pg):
            out = real(key, facet, value, pg)
            harness.state["bal"] -= 1                       # a second credit Quarry never recorded
            return out
        monkeypatch.setattr(probe, "_shodan_page", double_charge)
        assert harness.run_in(tmp_path / "p", "--run") == 1
        rep = _report(tmp_path / "p")
        assert "B" not in rep, "B must not run on top of an unexplained charge"
        assert rep["A"]["credits_spent"] == 4 and harness._emitted_spend(rep["A"]) == 2

    def test_a_PARTIAL_replay_is_not_a_pass(self, harness, monkeypatch, tmp_path):
        """B replaying one of two pages spends nothing and proves nothing. The claim is that EVERY page
        A bought comes back for free — and the missing one here is a page the project paid for and can
        no longer show, which the lane now refuses to re-buy."""
        real = probe._shodan_result
        seen = {"n": 0}

        def damage_between_runs(spec, vals, work):
            out = real(spec, vals, work)
            seen["n"] += 1
            if seen["n"] == 1:                             # after A, before B
                from quarry_recon import budget, shodan_sched as S
                led = budget.Ledger(budget.state_path(S.state_dir(tmp_path / "p"), "probe.shodan",
                                                      f"v{S.SHODAN_WORK_SCHEMA}"), lane="probe.shodan")
                art = next(iter(dict(led.items()).values()))
                doc = json.loads(art.read_text()); doc["matches"] = []
                art.write_text(json.dumps(doc))
            return out
        monkeypatch.setattr(probe, "_shodan_result", damage_between_runs)
        assert harness.run_in(tmp_path / "p", "--run") == 1
        v = _report(tmp_path / "p")["verdict"]
        assert v["b_replayed_fresh"] == 1 and v["b_bought"] == 0 and v["replay_works"] is False
        lanes = _report(tmp_path / "p")["B"]["lanes"]
        assert sum(l["lost"] for l in lanes.values()) == 1
        assert sum(l["repair_refused"] for l in lanes.values()) == 1

    def test_the_two_accountings_must_agree(self, harness, tmp_path):
        assert harness.run_in(tmp_path / "p", "--run") == 0
        rep = _report(tmp_path / "p")
        assert rep["A"]["credits_spent"] == harness._emitted_spend(rep["A"]) == 2
        assert rep["verdict"]["balance_and_accounting_agree"] is True


class TestItStartsFromAProvenState:
    def test_a_project_that_already_owns_the_pages_is_refused(self, harness, tmp_path):
        """review#5: A would REPLAY instead of buying, and "B replayed what A bought" would be true of
        a purchase that never happened."""
        assert harness.run_in(tmp_path / "p", "--run") == 0
        before = harness.state["pages"]
        assert harness.run_in(tmp_path / "p", "--run") == 2, "abort, not a second experiment"
        assert harness.state["pages"] == before, "nothing may be requested by a refused run"

    def test_the_page_cap_is_read_back_through_the_lanes_own_accessor(self, harness, tmp_path):
        """`SHODAN_MAX_PAGES` defaults to 0 = UNBOUNDED and `settings.override()` does not reach
        `concurrency()`. A cap the lane never sees would page until the balance ran out."""
        from quarry_recon import settings
        facts = harness.preflight(tmp_path / "p")
        assert facts["max_pages"] == harness.MAX_PAGES == 1
        assert settings.concurrency("SHODAN_MAX_PAGES", 0) == 1

    def test_it_drives_the_registered_lane_not_a_stand_in(self, harness):
        """A spec carrying only `sid` satisfies the script and not the coordinator, which also reads
        `facet`, `source` and `note` — the AttributeError would land AFTER the pages were paid for."""
        assert harness.LANE in probe._SHODAN_LANES
        assert harness.LANE.facet and harness.LANE.source and harness.LANE.note

    def test_the_balance_fields_are_the_providers_own(self, harness, tmp_path):
        bal = harness._balance("STUB")
        assert isinstance(bal["remaining"], int) and "credits" not in bal


class TestAMustBeExactlyTheExperimentBeforeBRuns:
    def test_a_short_purchase_stops_before_B(self, harness, monkeypatch, tmp_path):
        """A buying ONE page instead of two is a different experiment: B would then replay one page and
        the report would still read like a clean pass."""
        real = probe._shodan_page
        seen = {"n": 0}

        def flaky(key, facet, value, pg):
            seen["n"] += 1
            if seen["n"] == 2:
                err = RuntimeError("second pivot refused"); err.error_class = "server"
                return ([], None, err)
            return real(key, facet, value, pg)
        monkeypatch.setattr(probe, "_shodan_page", flaky)
        assert harness.run_in(tmp_path / "p", "--run") == 1
        rep = _report(tmp_path / "p")
        assert "B" not in rep
        assert sum(l["pages_bought"] for l in rep["A"]["lanes"].values()) == 1

    def test_a_failure_after_a_COMPLETE_purchase_still_stops_before_B(self, harness, monkeypatch,
                                                                     tmp_path):
        """Every count can agree and the lane still end in an unknown state. The exception is its own
        stop condition, not something the arithmetic happens to catch."""
        real = probe._shodan_result

        def boom(spec, vals, work):
            out = real(spec, vals, work)                    # the books ARE written…
            raise RuntimeError("failed after the accounting was emitted")   # …and then it breaks
        monkeypatch.setattr(probe, "_shodan_result", boom)
        assert harness.run_in(tmp_path / "p", "--run") == 1
        rep = _report(tmp_path / "p")
        assert "B" not in rep, "an unexplained failure must stop the experiment on its own"
        a = rep["A"]
        assert a["credits_spent"] == 2 and harness._emitted_spend(a) == 2, "the counts AGREED"
        assert a["exception"]["type"] == "RuntimeError"


class TestAPaidFailureStillLeavesARecord:
    def test_a_RAISING_balance_read_still_leaves_the_record(self, harness, monkeypatch, tmp_path):
        """review#2: `_balance` was the first statement in the `finally`, so a raise there skipped
        `save()` and destroyed the record of a run that had already spent."""
        # armed only once the LANE has finished, so the raise lands on the harness's own after-read
        # rather than on one of the coordinator's internal reads.
        real_bal, real_res, armed = probe._read_shodan_balance, probe._shodan_result, {"yes": False}

        def arm(spec, vals, work):
            out = real_res(spec, vals, work)
            armed["yes"] = True
            return out

        def maybe_explode(key, timeout=15, cooldown=None):
            if armed["yes"]:
                raise OSError("the balance endpoint went away")
            return real_bal(key, timeout, cooldown)
        monkeypatch.setattr(probe, "_shodan_result", arm)
        monkeypatch.setattr(probe, "_read_shodan_balance", maybe_explode)
        assert harness.run_in(tmp_path / "p", "--run") == 1
        rep = _report(tmp_path / "p")
        assert "B" not in rep
        a = rep["A"]
        assert a["balance_after"]["read_error"] == "OSError" and a["credits_spent"] is None
        assert a["balance_before"]["remaining"] == 50, "what WAS known is preserved"
        assert harness._emitted_spend(a) == 2, "Quarry's own books survive an unreadable provider"
        assert any("balance_after unreadable" in e for e in a["errors"])

    def test_each_run_publishes_its_manifest(self, harness, tmp_path):
        """review#3: the docstring promised manifests nothing wrote."""
        assert harness.run_in(tmp_path / "p", "--run") == 0
        rep = _report(tmp_path / "p")
        for label in ("A", "B"):
            man = Path(rep[label]["manifest"])
            assert man.is_file() and json.loads(man.read_text())["run_id"] == rep[label]["run_id"]


class TestItRefusesAnUntrustedStore:
    def test_a_corrupt_ownership_index_aborts_before_anything_is_requested(self, harness, tmp_path):
        """review#1: a corrupt index reads as an empty one, so the experiment would "prove" replay by
        buying everything a second time."""
        assert harness.run_in(tmp_path / "p", "--run") == 0
        before = harness.state["pages"]
        from quarry_recon import budget, shodan_sched as S
        path = budget.state_path(S.state_dir(tmp_path / "p"), "probe.shodan",
                                 f"v{S.SHODAN_WORK_SCHEMA}")
        path.write_text("{ not a ledger")
        assert harness.run_in(tmp_path / "p", "--run") == 2
        assert harness.state["pages"] == before, "nothing may be requested against a store we cannot read"


class TestARepurchaseNeedsMoreThanACleanLookingSlate:
    def test_an_exception_after_a_purchase_is_persisted_and_stops_B(self, harness, tmp_path):
        """review#4: the old version propagated before writing anything — the credit was spent and the
        experiment had no record of it."""
        harness.state["raise_after"] = 1
        assert harness.run_in(tmp_path / "p", "--run") == 1
        rep = _report(tmp_path / "p")
        assert "B" not in rep, "B must not start after an unexplained paid failure"
        a = rep["A"]
        assert a["exception"] and a["exception"]["type"] and a["exception"]["traceback"]
        assert a["credits_spent"] == 1, "the balance delta proves a credit left the account"
        assert a["run_id"] and a["balance_before"] and a["balance_after"]
        assert a["provider_spend"] is not None, "Quarry's own books are kept even on the failing run"
