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


class TestPolitenessNeverBecomesAHang:
    def test_an_unusable_state_directory_does_not_stop_a_run(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path / "nope" / "\0bad")
        assert pace.wait(pace.account("shodan", "K"), 1.05) == 0.0
        pace.note_penalty(pace.account("shodan", "K"), time.time() + 10)   # must not raise

    def test_a_FUTURE_timestamp_is_not_trusted(self, tmp_path, monkeypatch):
        """A clock that ran backwards must not let the next request through unpaced… nor stall it for
        the difference: an unusable stamp means wait the interval, no more."""
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        key = pace.account("shodan", "K")
        pace._state_path(key).parent.mkdir(parents=True, exist_ok=True)
        pace._state_path(key).write_text(json.dumps({"last": time.time() + 10_000}))
        slept: list = []
        monkeypatch.setattr(pace.time, "sleep", lambda s: slept.append(s))
        pace.wait(key, 1.05)
        assert slept == [] or slept[0] <= 1.1, slept

    def test_a_held_slot_does_not_park_the_run_forever(self, tmp_path, monkeypatch):
        from quarry_recon import budget
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        monkeypatch.setattr(pace, "LOCK_WAIT_S", 0.1)
        key = pace.account("shodan", "K")
        path = pace._state_path(key).with_suffix(".lock")
        path.parent.mkdir(parents=True, exist_ok=True)
        started = time.perf_counter()
        with budget.state_lock(path):                 # another process holds the slot
            pace.wait(key, 1.05)
        assert time.perf_counter() - started < 5.0, "a busy slot must not stall the run"
