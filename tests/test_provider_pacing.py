"""Rate coordination belongs to the provider ACCOUNT, not to one lane's object.

review (Lumpy, 2026-08-05): every `_ProviderCooldown()` started at `last = 0`, so the first request of
each lifecycle was unpaced against whatever ran a moment before it — the paid pivot coordinator, the
free `/host/count` sizing, the `/api-info` balance read and the free `shodan_host` lane are ONE account
being throttled, and two Quarry processes had entirely independent clocks. "One request per second" was
true of an object, never of the account.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from quarry_recon import pace
from quarry_recon.phases import probe


class TestTheAccountIsTheBoundary:
    def test_the_same_credential_shares_one_key_across_lanes_and_runs(self):
        a = pace.account("shodan", "SECRET-KEY")
        b = pace.account("shodan", "SECRET-KEY")
        assert a == b, "two lifecycles on one credential must queue behind the same boundary"
        assert a != pace.account("shodan", "OTHER-KEY")

    def test_providers_do_not_share_a_clock(self):
        """Whoxy, Censys and crt.sh have their own accounts and rate policies. One clock across
        providers would be the same mistake in the other direction."""
        key = "SECRET-KEY"
        keys = {pace.account(p, key) for p in ("shodan", "whoxy", "censys", "certspotter")}
        assert len(keys) == 4

    def test_an_unauthenticated_provider_coordinates_by_endpoint(self):
        assert pace.account("crt.sh") == "crt.sh:anonymous"

    def test_the_CREDENTIAL_never_appears_in_the_key_or_on_disk(self, tmp_path, monkeypatch):
        secret = "SUPER-SECRET-KEY-VALUE"
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        key = pace.account("shodan", secret)
        assert secret not in key and secret not in str(pace._state_path(key))
        pace.wait(key, 0.0)
        blob = "".join(p.read_text() for p in tmp_path.rglob("*.json"))
        assert secret not in blob and secret not in "".join(str(p) for p in tmp_path.rglob("*"))
        assert len(key.split(":")[1]) == 16, "a truncated digest, not the credential"


class TestPacingIsSharedNotPerObject:
    def test_a_SECOND_lifecycle_is_paced_behind_the_first(self, tmp_path, monkeypatch):
        """The defect, directly: two objects, one account. The second must not start unpaced."""
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        key = pace.account("shodan", "K")
        assert pace.wait(key, 1.05) == 0.0, "the first request waits for nothing"
        waited = pace.wait(key, 1.05)                 # a DIFFERENT lifecycle, same account
        assert 0.5 < waited <= 1.1, waited

    def test_two_cooldown_OBJECTS_share_the_boundary(self, tmp_path, monkeypatch):
        """The defect as the lane experiences it: two `_ProviderCooldown` objects, one credential."""
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        monkeypatch.setattr(probe, "_SHODAN_MIN_INTERVAL_S", 1.05)
        asked: list = []
        real_wait = pace.wait
        monkeypatch.setattr(probe.pace, "wait",
                            lambda key, interval, **kw: asked.append((key, interval)) or 0.0)
        monkeypatch.setattr(probe._time, "sleep", lambda s: None)
        probe._ProviderCooldown("K").wait()           # the paid pivot lane
        probe._ProviderCooldown("K").wait()           # …and the free host lane, moments later
        assert len(asked) == 2, "every request consults the account boundary"
        assert asked[0][0] == asked[1][0] == pace.account("shodan", "K"), asked
        assert asked[0][1] == 1.05, "…with the shipped interval, not a per-object one"
        del real_wait

    def test_a_different_credential_is_NOT_paced_behind_it(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        pace.wait(pace.account("shodan", "K1"), 1.05)
        assert pace.wait(pace.account("shodan", "K2"), 1.05) == 0.0

    def test_the_stamp_is_written_BEFORE_the_request(self, tmp_path, monkeypatch):
        """A process that dies mid-request must still leave the account paced."""
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        key = pace.account("shodan", "K")
        pace.wait(key, 0.0)
        doc = json.loads(pace._state_path(key).read_text())
        assert doc["last"] > 0 and doc["last"] <= time.time()


class TestAPenaltyOutlivesTheProcessThatEarnedIt:
    def test_a_429_is_persisted_for_the_account(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        key = pace.account("shodan", "K")
        pace.note_penalty(key, time.time() + 300)
        doc = json.loads(pace._state_path(key).read_text())
        assert doc["until"] > time.time() + 200

    def test_the_next_lifecycle_honours_it(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        slept: list = []
        monkeypatch.setattr(pace.time, "sleep", lambda s: slept.append(s))
        key = pace.account("shodan", "K")
        pace.note_penalty(key, time.time() + 120)
        pace.wait(key, 1.05)
        assert slept and slept[0] > 100, "the provider's own slowdown outranks the interval"

    def test_a_penalty_recorded_by_the_lane_reaches_the_account(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        err = Exception("429")
        err.headers = {"Retry-After": "90"}
        c = probe._ProviderCooldown("K")
        c.note(err)
        doc = json.loads(pace._state_path(c.account).read_text())
        assert doc["until"] > time.time() + 60


class TestABoundaryRefusesRatherThanFailsOpen:
    """review#2 (Lumpy): the first version proceeded UNPACED whenever the slot was held, the state was
    malformed or a write failed — it stopped coordinating exactly when coordination mattered, and two
    processes could burst together. A fail-open pacer is advisory telemetry, not a boundary.

    Refusing costs no evidence: replay is untouched and the pages we did not buy are still there."""

    def test_a_held_slot_REFUSES_instead_of_proceeding(self, tmp_path, monkeypatch):
        from quarry_recon import budget
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        monkeypatch.setattr(pace, "LOCK_WAIT_S", 0.1)
        key = pace.account("shodan", "K")
        lock = pace._state_path(key).with_suffix(".lock")
        lock.parent.mkdir(parents=True, exist_ok=True)
        started = time.perf_counter()
        with budget.state_lock(lock):                    # another process holds the slot
            with pytest.raises(pace.PaceBusy):
                pace.wait(key, 1.05)
        assert time.perf_counter() - started < 5.0, "the WAIT is bounded; the boundary is not abandoned"

    def test_malformed_state_refuses(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        key = pace.account("shodan", "K")
        pace._state_path(key).parent.mkdir(parents=True, exist_ok=True)
        pace._state_path(key).write_text("{ half a write")
        with pytest.raises(pace.PaceBusy):
            pace.wait(key, 1.05)

    def test_a_non_object_state_refuses(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        key = pace.account("shodan", "K")
        pace._state_path(key).parent.mkdir(parents=True, exist_ok=True)
        pace._state_path(key).write_text("[]")
        with pytest.raises(pace.PaceBusy):
            pace.wait(key, 1.05)

    def test_an_unusable_state_directory_refuses(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path / "nope" / "\0bad")
        with pytest.raises(pace.PaceBusy):
            pace.wait(pace.account("shodan", "K"), 1.05)

    def test_a_failed_write_refuses(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        key = pace.account("shodan", "K")

        def boom(self, *a, **k):
            raise OSError("disk full")
        monkeypatch.setattr(Path, "write_text", boom)
        with pytest.raises(pace.PaceBusy):
            pace.wait(key, 0.0)

    def test_the_state_is_published_ATOMICALLY(self, tmp_path, monkeypatch):
        """`write_text` can leave a fragment behind, which the next process would read as "no pacing
        history" — the very failure this module exists to prevent."""
        import inspect
        src = inspect.getsource(pace._publish)
        assert "os.replace" in src and ".tmp" in src
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        key = pace.account("shodan", "K")
        pace.wait(key, 0.0)
        assert not list(tmp_path.glob("*.tmp")), "no fragment is left behind"

    def test_a_MISSING_state_is_a_first_request_not_a_refusal(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        assert pace.wait(pace.account("shodan", "NEW"), 1.05) == 0.0

    def test_recording_a_penalty_never_raises(self, tmp_path, monkeypatch):
        """The request already happened and the 429 is in hand — the caller is on a failure path. What
        is lost is SHARING the penalty, which the next `wait()` refuses over anyway."""
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        key = pace.account("shodan", "K")
        pace._state_path(key).parent.mkdir(parents=True, exist_ok=True)
        pace._state_path(key).write_text("{ broken")
        pace.note_penalty(key, time.time() + 60)          # must not raise


class TestAnUnusableStampWaitsTheInterval:
    """review#3 (Lumpy): `_stamp` returned 0.0 for an unusable value, so `last + interval` landed near
    the Unix epoch and the request went out IMMEDIATELY — the opposite of the documented behaviour."""

    @pytest.mark.parametrize("bad", [float("inf"), float("nan"), "soon", None, True])
    def test_an_unusable_last_stamp_waits_a_FULL_interval(self, tmp_path, monkeypatch, bad):
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        key = pace.account("shodan", "K")
        pace._state_path(key).parent.mkdir(parents=True, exist_ok=True)
        pace._state_path(key).write_text(json.dumps({"last": bad}))
        slept: list = []
        monkeypatch.setattr(pace.time, "sleep", lambda s: slept.append(s))
        pace.wait(key, 1.05)
        assert slept and 1.0 <= slept[0] <= 1.1, (bad, slept)

    def test_a_FUTURE_stamp_waits_one_interval_not_the_difference(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        key = pace.account("shodan", "K")
        pace._state_path(key).parent.mkdir(parents=True, exist_ok=True)
        pace._state_path(key).write_text(json.dumps({"last": time.time() + 10_000}))
        slept: list = []
        monkeypatch.setattr(pace.time, "sleep", lambda s: slept.append(s))
        pace.wait(key, 1.05)
        assert slept and 1.0 <= slept[0] <= 1.1, slept


class TestTheLaneReportsARefusalAsAGap:
    def test_a_refused_search_is_a_classified_error_not_a_crash(self, monkeypatch, tmp_path):
        from quarry_recon import contract
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path / "x" / "\0bad")
        c = probe._ProviderCooldown("K")
        with pytest.raises(pace.PaceBusy):
            c.wait()
        e = pace.PaceBusy("slot held")
        e.error_class = contract.PROVIDER_PACE_BUSY
        assert contract.provider_error_class(e) == "pace_busy"
        assert not contract.is_provider_limit("pace_busy"), "ours, not a provider limit"
        assert "pace_busy" in contract.PROVIDER_CLASSES
