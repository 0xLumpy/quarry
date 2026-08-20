"""The acquisition byte/disk governor: bound a hostile/paid body, keep the bounded partial, record a
typed truncation, admit BEFORE contact, and hold the cumulative caps under concurrency and across runs.
Byte ceilings default OFF; the always-on host guard is the free-space reserve (fail-closed).
"""
from __future__ import annotations

import contextlib
import io
import json
import threading
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest

from quarry_recon import budget, contract, fetch, settings, shodan_sched
from quarry_recon.phases import probe

pytestmark = pytest.mark.offline


def _patch_provider(monkeypatch, opener):
    """Route a legacy request fake through the pinned provider wrapper seam."""
    def request(url, *, data=None, method="GET", headers=None):
        return urllib.request.Request(url, data=data, method=method, headers=headers or {})

    @contextlib.contextmanager
    def response_for(req, timeout):
        owner = opener(req, timeout=timeout)
        response = owner.__enter__() if hasattr(owner, "__enter__") else owner
        try:
            yield response
        finally:
            if hasattr(owner, "__exit__"):
                owner.__exit__(None, None, None)
            elif hasattr(response, "close"):
                response.close()

    @contextlib.contextmanager
    def fake_walk(ctx, url, origin_host=None, *, timeout=20, data=None, method="GET",
                  headers=None, max_redirects=5, source_id="native-http", **_kwargs):
        req = request(url, data=data, method=method, headers=headers)
        with response_for(req, timeout) as response:
            yield response, url, getattr(response, "status", 200), True

    def scoped_get(ctx, url, origin_host=None, *, max_body=2 * 1024 * 1024, timeout=20,
                   data=None, method="GET", headers=None, response_headers=None, **_kwargs):
        req = request(url, data=data, method=method, headers=headers)
        with response_for(req, timeout) as response:
            if response_headers is not None:
                response_headers.update(getattr(response, "headers", {}) or {})
            return response.read(max_body + 1), url, getattr(response, "status", 200)

    def scoped_get_file(ctx, url, dest, origin_host=None, *, timeout=20, data=None,
                        method="GET", headers=None, max_redirects=0, chunk=1024 * 1024,
                        deadline_s=300.0, policy=None, governor=None, source_id="native-http",
                        response_headers=None, metadata_url=None):
        from quarry_recon import fetch
        result = fetch._scoped_get_file_legacy(
            ctx, url, dest, origin_host, timeout=timeout, data=data, method=method,
            headers=headers, max_redirects=max_redirects, chunk=chunk, deadline_s=deadline_s,
            policy=policy, governor=governor, source_id=source_id,
            response_headers=response_headers, metadata_url=metadata_url,
        )
        receipt = Path(dest).with_name(Path(dest).name + fetch._RECEIPT_SUFFIX)
        if receipt.exists():
            doc = json.loads(receipt.read_text())
            doc.setdefault("kind", "acquisition")
            receipt.write_text(json.dumps(doc))
        acquisition, _final, _status = result
        if acquisition is not None and not acquisition.complete and acquisition.truncation is not None:
            raise contract.AcquisitionTruncated(
                acquisition.error or "acquisition truncated",
                bytes_written=acquisition.bytes, partial=acquisition.partial,
                limit_kind=acquisition.truncation.kind, limit_bytes=acquisition.truncation.limit,
            )
        return result

    monkeypatch.setattr(fetch, "_walk", fake_walk)
    monkeypatch.setattr(fetch, "scoped_public_provider_get", scoped_get)
    monkeypatch.setattr(fetch, "scoped_public_provider_get_file", scoped_get_file)


@pytest.fixture(autouse=True)
def _isolate_shared_governor():
    contract.reset_shared_governor()
    yield
    contract.reset_shared_governor()


class _Infinite(io.RawIOBase):
    """A socket that never ends: `read(n)` always yields n bytes, with a safety ceiling."""

    def __init__(self, byte: bytes = b"x", *, safety: int = 64 * 1024 * 1024):
        self._byte = byte
        self._served = 0
        self._safety = safety

    def read(self, n=-1):
        n = 1 if n is None or n < 0 else n
        self._served += n
        if self._served > self._safety:
            raise AssertionError("governor never stopped an infinite response")
        return self._byte * n

    def close(self):
        pass


class _CM:
    def __init__(self, r):
        self.r = r

    def __enter__(self):
        return self.r

    def __exit__(self, *a):
        return False


def _ctx():
    return SimpleNamespace(profile=SimpleNamespace(http_rl=0),
                           scope=SimpleNamespace(active_allowed=lambda h: True))


def _reachable_infinite(monkeypatch):
    monkeypatch.setattr(fetch.netguard, "contact_state",
                        lambda h, block_private=False: ("contact", None, None))
    monkeypatch.setattr(fetch, "_open_no_follow",
                        lambda req, timeout, opener=None: (200, {}, _Infinite()))


class TestResponseByteCeiling:
    def test_stops_at_the_boundary_and_keeps_the_partial(self, tmp_path):
        gov = contract.DiskGovernor(response_max=4096, reserve_bytes=0)
        dest = tmp_path / "a.bin"
        with pytest.raises(contract.AcquisitionTruncated) as ei:
            contract.stream_to_file(_Infinite(), dest, chunk=1000, governor=gov)
        e = ei.value
        assert e.bytes_written == 4096 and e.limit_kind == contract.LAYER_RESPONSE and e.limit_bytes == 4096
        part = dest.with_name(dest.name + ".part")
        assert part.exists() and part.stat().st_size == 4096
        assert not dest.exists()

    def test_a_truncation_is_an_incomplete_acquisition(self):
        assert issubclass(contract.AcquisitionTruncated, contract.IncompleteAcquisition)


class TestFreeSpaceReserve:
    def test_stops_before_consuming_into_the_reserve(self, tmp_path):
        free = {"bytes": 5000}

        class _Filling(_Infinite):
            def read(self, n=-1):
                buf = super().read(n)
                free["bytes"] -= len(buf)
                return buf

        gov = contract.DiskGovernor(reserve_bytes=4000, free_fn=lambda p: free["bytes"])
        dest = tmp_path / "b.bin"
        with pytest.raises(contract.AcquisitionTruncated) as ei:
            contract.stream_to_file(_Filling(), dest, chunk=200, governor=gov)
        assert ei.value.limit_kind == contract.LAYER_RESERVE
        assert free["bytes"] >= 4000
        part = dest.with_name(dest.name + ".part")
        assert part.exists() and part.stat().st_size == ei.value.bytes_written > 0

    def test_an_uninspectable_free_probe_FAILS_CLOSED(self, tmp_path):
        gov = contract.DiskGovernor(reserve_bytes=4000, free_fn=lambda p: None)
        dest = tmp_path / "c.bin"
        with pytest.raises(contract.AcquisitionTruncated) as ei:
            contract.stream_to_file(io.BytesIO(b"z" * 2048), dest, chunk=256, governor=gov)
        assert ei.value.limit_kind == contract.LAYER_RESERVE and ei.value.bytes_written == 0
        assert not dest.exists()

    def test_a_disabled_reserve_never_trips_on_an_unknown_probe(self, tmp_path):
        gov = contract.DiskGovernor(reserve_bytes=0, free_fn=lambda p: None)
        dest = tmp_path / "c0.bin"
        n, _sha = contract.stream_to_file(io.BytesIO(b"z" * 2048), dest, chunk=256, governor=gov)
        assert n == 2048 and dest.read_bytes() == b"z" * 2048


class TestUnboundedIsTheDefaultForBytes:
    def test_a_normal_body_is_kept_whole_when_ceilings_are_off(self, tmp_path):
        gov = contract.DiskGovernor(reserve_bytes=0)
        assert gov.response_max == 0 and gov.run_max == 0 and gov.project_max == 0
        dest = tmp_path / "d.bin"
        body = b"k" * (5 * 1024 * 1024)
        n, _sha = contract.stream_to_file(io.BytesIO(body), dest, chunk=1024 * 1024, governor=gov)
        assert n == len(body) and dest.read_bytes() == body


class TestCumulativeRunProjectBudgets:
    def test_a_run_ceiling_binds_across_two_acquisitions_with_the_partial_accounted(self, tmp_path):
        gov = contract.DiskGovernor(run_max=100, reserve_bytes=0)
        first = tmp_path / "one.bin"
        n1, _sha = contract.stream_to_file(io.BytesIO(b"x" * 70), first, chunk=1000, governor=gov)
        assert n1 == 70 and gov.run_streamed == 70
        second = tmp_path / "two.bin"
        with pytest.raises(contract.AcquisitionTruncated) as ei:
            contract.stream_to_file(_Infinite(), second, chunk=1000, governor=gov)
        assert ei.value.limit_kind == contract.LAYER_RUN and ei.value.bytes_written == 30
        part2 = second.with_name(second.name + ".part")
        assert first.stat().st_size + part2.stat().st_size == 100, "cumulative cap stops the run — not 140"
        assert gov.run_streamed == 100

    def test_a_response_under_the_run_cap_is_kept_whole_across_chunks(self, tmp_path):
        # the in-flight bytes must not be charged twice: 80B under 100B keeps 80, never truncates at 60
        gov = contract.DiskGovernor(run_max=100, reserve_bytes=0)
        dest = tmp_path / "whole.bin"
        n, _sha = contract.stream_to_file(io.BytesIO(b"x" * 80), dest, chunk=50, governor=gov)
        assert n == 80 and dest.read_bytes() == b"x" * 80
        assert gov.run_streamed == 80

    def test_the_default_governor_is_process_shared_within_a_run(self, monkeypatch):
        monkeypatch.setattr(contract, "_current_scope", lambda: ("run-A", None))
        contract.reset_shared_governor()
        assert contract.default_governor() is contract.default_governor()

    def test_concurrent_first_callers_share_one_governor(self, monkeypatch):
        monkeypatch.setattr(contract, "_current_scope", lambda: ("run-A", None))
        contract.reset_shared_governor()
        seen: list = []
        ts = [threading.Thread(target=lambda: seen.append(contract.default_governor())) for _ in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        assert len({id(g) for g in seen}) == 1, "concurrent first callers must share ONE governor"


class TestRunScopeIsPerRun:
    def test_a_new_run_does_not_inherit_the_previous_runs_allowance(self, monkeypatch):
        scope = {"key": "run-A", "state": None}
        monkeypatch.setattr(contract, "_current_scope", lambda: (scope["key"], scope["state"]))
        contract.reset_shared_governor()
        a = contract.default_governor()
        a.run_streamed = 55                       # this run used bytes
        scope["key"] = "run-B"                    # a settled child / next run
        b = contract.default_governor()
        assert b is not a and b.run_streamed == 0, "the run scope resets per run"


class TestProjectScopeIsDurableAcrossRestarts:
    def test_the_project_ceiling_survives_a_simulated_restart(self, tmp_path):
        state = tmp_path / "acquire-project-bytes.json"
        gov1 = contract.DiskGovernor(project_max=100, reserve_bytes=0, project_state=state)
        contract.stream_to_file(io.BytesIO(b"y" * 40), tmp_path / "p1.bin", chunk=1000, governor=gov1)
        assert json.loads(state.read_text())["bytes"] == 40, "project bytes are flushed durably"
        # a fresh process: a new governor over the same project loads the durable total
        gov2 = contract.DiskGovernor(project_max=100, reserve_bytes=0, project_state=state)
        assert gov2.project_streamed == 40
        with pytest.raises(contract.AcquisitionTruncated) as ei:
            contract.stream_to_file(_Infinite(), tmp_path / "p2.bin", chunk=1000, governor=gov2)
        assert ei.value.limit_kind == contract.LAYER_PROJECT and ei.value.bytes_written == 60
        assert json.loads(state.read_text())["bytes"] == 100

    def test_the_default_governor_wires_the_durable_project_state(self, tmp_path, monkeypatch):
        state = tmp_path / "state" / "acquire-project-bytes.json"
        monkeypatch.setattr(contract, "_current_scope", lambda: ("run-A", state))
        contract.reset_shared_governor()
        assert contract.default_governor().project_state == state


class TestConcurrentAdmitIsSerialized:
    def test_two_concurrent_streams_cannot_both_pass_the_cumulative_cap(self, tmp_path):
        gov = contract.DiskGovernor(run_max=100, reserve_bytes=0)
        start = threading.Barrier(2)

        def one(name):
            start.wait()
            try:
                contract.stream_to_file(io.BytesIO(b"x" * 80), tmp_path / name, chunk=1024, governor=gov)
            except contract.AcquisitionTruncated:
                pass

        ts = [threading.Thread(target=one, args=(f"c{i}.bin",)) for i in range(2)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()

        on_disk = sum(p.stat().st_size for p in tmp_path.iterdir())
        assert on_disk == 100, f"two 80B streams must not retain 160B under a 100B cap (got {on_disk})"
        assert gov.run_streamed == 100


class TestAdmitBeforeContact:
    def test_an_exhausted_budget_never_contacts_and_leaves_no_receipt(self, tmp_path, monkeypatch):
        monkeypatch.setattr(fetch.netguard, "contact_state",
                            lambda h, block_private=False: ("contact", None, None))
        monkeypatch.setattr(fetch, "_open_no_follow",
                            lambda *a, **k: pytest.fail("an exhausted budget must not contact the host"))
        gov = contract.DiskGovernor(run_max=10, run_streamed=10, reserve_bytes=0)   # already spent
        dest = tmp_path / "x.bin"
        acq, _final, status = fetch.scoped_get_file(_ctx(), "https://t/x", dest, "t", governor=gov)
        assert acq.contacted is False and acq.disposition == "budget-exhausted" and status == 0
        assert not dest.exists() and not dest.with_name(dest.name + ".part").exists()
        assert not dest.with_name(dest.name + fetch._RECEIPT_SUFFIX).exists(), "no receipt without contact"

    def test_a_misconfigured_budget_never_contacts(self, tmp_path, monkeypatch):
        monkeypatch.setattr(fetch.netguard, "contact_state",
                            lambda h, block_private=False: ("contact", None, None))
        monkeypatch.setattr(fetch, "_open_no_follow",
                            lambda *a, **k: pytest.fail("an invalid budget must not contact the host"))
        def _raise():
            raise ValueError("ACQUIRE_RUN_MAX_BYTES=-5 is not a usable byte ceiling")
        monkeypatch.setattr(contract, "default_governor", _raise)
        acq, _f, status = fetch.scoped_get_file(_ctx(), "https://t/x", tmp_path / "y.bin", "t")
        assert acq.contacted is False and acq.disposition == "budget-invalid" and status == 0

    def test_a_paid_shodan_open_is_refused_before_spending(self, tmp_path, monkeypatch):
        _patch_provider(monkeypatch,
                            lambda *a, **k: pytest.fail("an exhausted budget must not open the paid request"))
        monkeypatch.setattr(probe, "default_governor",
                            lambda: contract.DiskGovernor(run_max=5, run_streamed=5, reserve_bytes=0))
        with pytest.raises(contract.AcquisitionBudgetExhausted):
            probe._shodan_page("K", "ssl", "acme.com", 1, sink=tmp_path / "raw" / "p.json")

    def test_the_scheduler_treats_a_budget_refusal_as_no_spend(self, tmp_path):
        lane = "probe.favicon"
        led = budget.Ledger(budget.state_path(tmp_path, lane, "fp0"), lane=lane)
        calls: list = []

        def refusing_search(pivot, page):
            calls.append((pivot.value, page))
            raise contract.AcquisitionBudgetExhausted(contract.LAYER_RUN)

        attempts = tmp_path / "attempts"
        attempts.mkdir()
        res = shodan_sched.run_work(None,
                                    states=[shodan_sched.PivotState(shodan_sched.Pivot(lane, "f", "a"))],
                                    balance=_Bal(), search=refusing_search, ingest=lambda *a, **k: 0,
                                    ledger=led, attempt_dir=attempts)
        o = res.lanes[lane]
        assert o.budget_refused == 1 and o.pages_bought == 0
        assert shodan_sched.read_acquisition(led, shodan_sched.Pivot(lane, "f", "a"), 1) is None


class TestMalformedCeilingIsRejected:
    def test_a_negative_run_ceiling_is_refused_not_run_unbounded(self):
        with settings.overrides({"ACQUIRE_RUN_MAX_BYTES": -5}):
            contract.reset_shared_governor()
            with pytest.raises(ValueError):
                contract.default_governor()

    def test_a_garbled_reserve_is_refused(self):
        with settings.overrides({"ACQUIRE_FREE_RESERVE_BYTES": "not-a-number"}):
            contract.reset_shared_governor()
            with pytest.raises(ValueError):
                contract.default_governor()


class TestScopedGetFileRecordsTheRemainder:
    def test_partial_kept_receipt_carries_typed_truncation_no_retry(self, tmp_path, monkeypatch):
        _reachable_infinite(monkeypatch)
        gov = contract.DiskGovernor(response_max=8192, reserve_bytes=0)
        dest = tmp_path / "e.bin"
        acq, _final, status = fetch.scoped_get_file(_ctx(), "https://t/x", dest, "t", governor=gov)
        assert status == 200 and acq is not None
        assert acq.complete is False and acq.contacted is True and acq.disposition == "incomplete"
        assert acq.truncation == contract.Truncation(contract.LAYER_RESPONSE, 8192)
        part = Path(acq.partial)
        assert part.exists() and part.stat().st_size == 8192
        rec = json.loads(dest.with_name(dest.name + fetch._RECEIPT_SUFFIX).read_text())
        assert rec["complete"] is False and rec["bytes"] == 8192
        assert rec["truncation"] == {"kind": contract.LAYER_RESPONSE, "limit": 8192}

    def test_a_replay_re_requests_nothing_and_rebuilds_the_typed_truncation(self, tmp_path, monkeypatch):
        _reachable_infinite(monkeypatch)
        gov = contract.DiskGovernor(response_max=4096, reserve_bytes=0)
        dest = tmp_path / "f.bin"
        fetch.scoped_get_file(_ctx(), "https://t/x", dest, "t", governor=gov)
        monkeypatch.setattr(fetch, "_open_no_follow",
                            lambda *a, **k: pytest.fail("a truncated acquisition must not re-request"))
        again, _f, _s = fetch.scoped_get_file(_ctx(), "https://t/x", dest, "t", governor=gov)
        assert again.contacted is False and again.disposition == "replayed-incomplete"
        assert again.bytes == 4096
        assert again.truncation == contract.Truncation(contract.LAYER_RESPONSE, 4096)

    def test_an_incomplete_acquisition_carries_the_partials_digest(self, tmp_path, monkeypatch):
        import hashlib
        _reachable_infinite(monkeypatch)
        gov = contract.DiskGovernor(response_max=4096, reserve_bytes=0)
        dest = tmp_path / "g.bin"
        acq, _f, _s = fetch.scoped_get_file(_ctx(), "https://t/x", dest, "t", governor=gov)
        assert acq.complete is False and acq.bytes == 4096
        expected = hashlib.sha256(b"x" * 4096).hexdigest()
        assert acq.sha256 == expected, "the retained partial's digest is carried, not an empty string"
        rec = json.loads(dest.with_name(dest.name + fetch._RECEIPT_SUFFIX).read_text())
        assert rec["digest"] == acq.sha256


class TestReceiptTruncationIsTyped:
    def test_the_typed_record_round_trips(self):
        t = contract.Truncation(contract.LAYER_RUN, 123)
        assert contract.Truncation.from_receipt(t.as_receipt()) == t

    def test_a_malformed_typed_record_is_rejected(self):
        with pytest.raises(ValueError):
            contract.Truncation("not-a-layer", 1)
        with pytest.raises(ValueError):
            contract.Truncation(contract.LAYER_RUN, -1)
        with pytest.raises(ValueError):
            contract.Truncation.from_receipt({"kind": contract.LAYER_RUN, "limit": 1, "extra": 2})

    def _valid_receipt(self, **over):
        rec = {"ident": "a" * 64, "url": "https://t/x", "method": "GET", "final": "https://t/x",
               "status": 200, "bytes": 10, "digest": "b" * 64, "complete": False,
               "truncation": {"kind": contract.LAYER_RESPONSE, "limit": 10}}
        rec.update(over)
        return rec

    def test_a_malformed_truncation_field_in_a_receipt_is_refused(self, tmp_path):
        rec_path = tmp_path / "r.acq.json"
        rec_path.write_text(json.dumps(self._valid_receipt(truncation={"kind": "bogus", "limit": 10})))
        with pytest.raises(fetch.AcquisitionRefused) as ei:
            fetch._read_receipt(rec_path)
        assert ei.value.disposition == "receipt-damaged"

    def test_a_complete_receipt_with_a_truncation_is_contradictory_and_refused(self, tmp_path):
        rec_path = tmp_path / "bad.acq.json"
        rec_path.write_text(json.dumps(self._valid_receipt(complete=True)))
        with pytest.raises(fetch.AcquisitionRefused) as ei:
            fetch._read_receipt(rec_path)
        assert ei.value.disposition == "receipt-damaged"

    def test_a_well_formed_truncation_receipt_validates(self, tmp_path):
        rec_path = tmp_path / "ok.acq.json"
        rec_path.write_text(json.dumps(self._valid_receipt()))
        doc = fetch._read_receipt(rec_path)
        assert contract.Truncation.from_receipt(doc["truncation"]).limit == 10


class TestPaidShodanTruncationOwnership:
    def test_probe_reports_the_partial_bytes_not_zero(self, tmp_path, monkeypatch):
        _patch_provider(monkeypatch, lambda req, timeout=20: _CM(_Infinite()))
        monkeypatch.setattr(probe, "default_governor",
                            lambda: contract.DiskGovernor(response_max=4096, reserve_bytes=0))
        sink = tmp_path / "raw" / "page.json"
        rows, total, err = probe._shodan_page("K", "ssl", "acme.com", 1, sink=sink)
        assert rows == [] and total is None and err is not None
        assert getattr(err, "error_class", None) == "truncated"
        assert err.raw_bytes == 4096, "the retained partial's real byte count, not zero"
        assert err.raw_path is not None and Path(err.raw_path).is_file()
        assert Path(err.raw_path).stat().st_size == 4096

    def test_a_truncated_paid_page_carries_its_sha256(self, tmp_path, monkeypatch):
        import hashlib
        _patch_provider(monkeypatch, lambda req, timeout=20: _CM(_Infinite()))
        monkeypatch.setattr(probe, "default_governor",
                            lambda: contract.DiskGovernor(response_max=4096, reserve_bytes=0))
        _rows, _total, err = probe._shodan_page("K", "ssl", "acme.com", 1, sink=tmp_path / "raw" / "p.json")
        assert err.raw_bytes == 4096
        assert err.raw_digest == hashlib.sha256(b"x" * 4096).hexdigest(), "the paid partial exports its real digest"

    def test_an_incomplete_error_body_carries_its_sha256(self, tmp_path, monkeypatch):
        import hashlib
        import urllib.error

        def _raise_http(req, timeout=20):
            raise urllib.error.HTTPError("https://api.shodan.io/x", 500, "server error", {},
                                         io.BytesIO(b"E" * 100000))
        _patch_provider(monkeypatch, _raise_http)
        monkeypatch.setattr(probe, "default_governor",
                            lambda: contract.DiskGovernor(response_max=4096, reserve_bytes=0))
        _rows, _total, err = probe._shodan_page("K", "ssl", "acme.com", 1, sink=tmp_path / "raw" / "p.json")
        assert err.raw_bytes == 4096
        assert err.raw_digest == hashlib.sha256(b"E" * 4096).hexdigest(), "an incomplete error body carries its digest"

    def test_a_paid_publish_failure_reports_the_evidence_not_zeros(self, tmp_path, monkeypatch):
        import hashlib
        _patch_provider(monkeypatch, lambda req, timeout=20: _CM(io.BytesIO(b"P" * 24)))
        monkeypatch.setattr(probe, "default_governor", lambda: contract.DiskGovernor(reserve_bytes=0))
        monkeypatch.setattr(contract._os, "replace", lambda src, dst: (_ for _ in ()).throw(OSError("no")))
        _rows, _total, err = probe._shodan_page("K", "ssl", "acme.com", 1, sink=tmp_path / "raw" / "p.json")
        assert err is not None and err.raw_bytes == 24
        assert err.raw_digest == hashlib.sha256(b"P" * 24).hexdigest()
        assert err.raw_path is not None and Path(err.raw_path).exists(), "the retained evidence path is reported"

    def test_a_truncated_paid_page_is_owned_so_replay_never_rebuys(self, tmp_path):
        lane = "probe.favicon"
        led = budget.Ledger(budget.state_path(tmp_path, lane, "fp0"), lane=lane)

        part = tmp_path / "kept.json.part"
        part.write_bytes(b"x" * 512)
        trunc = contract.AcquisitionTruncated("stopped at policy", bytes_written=512, partial=part,
                                              limit_kind=contract.LAYER_RESPONSE, limit_bytes=512)
        trunc.error_class = "truncated"
        trunc.raw_path, trunc.raw_bytes, trunc.raw_digest = part, 512, None

        first: list = []

        def _search_first(pivot, page):
            first.append((pivot.value, page))
            return [], None, trunc

        attempts = tmp_path / "attempts"
        attempts.mkdir()
        shodan_sched.run_work(None, states=[shodan_sched.PivotState(shodan_sched.Pivot(lane, "f", "a"))],
                              balance=_Bal(), search=_search_first, ingest=lambda *a, **k: 0,
                              ledger=led, attempt_dir=attempts)
        assert first == [("a", 1)]
        assert shodan_sched.read_acquisition(led, shodan_sched.Pivot(lane, "f", "a"), 1) is not None

        second: list = []

        def _search_again(pivot, page):
            second.append((pivot.value, page))
            return [], None, trunc

        attempts2 = tmp_path / "attempts2"
        attempts2.mkdir()
        shodan_sched.run_work(None, states=[shodan_sched.PivotState(shodan_sched.Pivot(lane, "f", "a"))],
                              balance=_Bal(), search=_search_again, ingest=lambda *a, **k: 0,
                              ledger=led, attempt_dir=attempts2)
        assert second == [], "an owned truncated page is never re-purchased"


class TestReserveIsAtomic:
    def test_two_grants_before_commit_cannot_oversubscribe_the_run_cap(self, tmp_path):
        gov = contract.DiskGovernor(run_max=100, reserve_bytes=0)
        g1, _l1 = gov.take(tmp_path, 0, 80)
        g2, _l2 = gov.take(tmp_path, 0, 80)     # the first grant is reserved though not yet committed
        assert (g1, g2) == (80, 20), "a concurrent grant cannot exceed the run cap"

    def test_two_grants_before_commit_cannot_oversubscribe_the_reserve(self, tmp_path):
        gov = contract.DiskGovernor(reserve_bytes=50, free_fn=lambda p: 100)   # 50 bytes of room
        g1, l1 = gov.take(tmp_path, 0, 80)
        g2, _l2 = gov.take(tmp_path, 0, 80)
        assert (g1, g2) == (50, 0) and l1 == contract.LAYER_RESERVE

    def test_a_short_write_charges_actual_persisted_bytes_not_granted(self, tmp_path):
        gov = contract.DiskGovernor(run_max=100, reserve_bytes=0)
        granted, _l = gov.take(tmp_path, 0, 40)
        assert granted == 40
        gov.commit(10)                          # only 10 of the 40 reached disk
        gov.settle(granted_total=40, written=10)
        assert gov.run_streamed == 10 and gov._inflight == 0


class _WrapSink:
    """Wraps a real file handle, delegating flush/fileno/context so `_write_and_measure` sees the true
    on-disk size, but letting `write` lie about how many bytes it stored."""

    def __init__(self, fh, writer):
        self.fh = fh
        self._writer = writer

    def write(self, data):
        return self._writer(self.fh, data)

    def flush(self):
        self.fh.flush()

    def fileno(self):
        return self.fh.fileno()

    def __enter__(self):
        self.fh.__enter__()
        return self

    def __exit__(self, *a):
        return self.fh.__exit__(*a)


def _inject_sink(monkeypatch, writer):
    """Patch the `.part` opener to wrap the real (O_NOFOLLOW) handle with a writer that can lie."""
    real = contract._open_part_wb
    monkeypatch.setattr(contract, "_open_part_wb", lambda p: _WrapSink(real(p), writer))


class TestDurableByteAccounting:
    def test_ondisk_size_reports_the_real_file_size(self, tmp_path):
        p = tmp_path / "u.bin"
        with open(p, "wb") as fh:
            fh.write(b"abcd"); fh.flush()
            assert contract._ondisk_size(fh) == 4

    def test_a_buffered_write_that_lands_fewer_bytes_charges_the_actual(self, tmp_path, monkeypatch):
        # OVERCHARGE case: write() returns the input length (buffered) but only 6 bytes reach disk
        def _store_six(fh, data):
            fh.write(bytes(data[:6]))
            return len(data)                          # lies: claims all, stored 6
        _inject_sink(monkeypatch, _store_six)
        gov = contract.DiskGovernor(reserve_bytes=0)
        dest = tmp_path / "over.bin"
        with pytest.raises(contract.IncompleteAcquisition) as ei:
            contract.stream_to_file(io.BytesIO(b"y" * 20), dest, chunk=1000, governor=gov)
        part = dest.with_name(dest.name + ".part")
        assert ei.value.bytes_written == 6 and part.read_bytes() == b"y" * 6
        assert gov.run_streamed == part.stat().st_size == 6, "charge reflects bytes on disk, not the write() return"
        assert gov._inflight == 0

    def test_a_write_that_underreports_still_charges_what_landed(self, tmp_path, monkeypatch):
        # UNDERCHARGE case: write() returns 0 but all 25 bytes reach disk
        def _store_all_report_zero(fh, data):
            fh.write(data)
            return 0                                  # lies: claims nothing, stored all
        _inject_sink(monkeypatch, _store_all_report_zero)
        gov = contract.DiskGovernor(reserve_bytes=0)
        dest = tmp_path / "under.bin"
        n, _sha = contract.stream_to_file(io.BytesIO(b"z" * 25), dest, chunk=1000, governor=gov)
        assert n == 25 and dest.read_bytes() == b"z" * 25
        assert gov.run_streamed == dest.stat().st_size == 25, "0 bytes reported must not undercharge 25 retained"
        assert gov._inflight == 0

    def test_the_run_cap_binds_on_durable_bytes_not_the_write_return(self, tmp_path, monkeypatch):
        # a buffered writer that stores everything: the cap must still bind on what is on disk
        gov = contract.DiskGovernor(run_max=100, reserve_bytes=0)
        contract.stream_to_file(io.BytesIO(b"a" * 70), tmp_path / "a.bin", chunk=1000, governor=gov)
        with pytest.raises(contract.AcquisitionTruncated) as ei:
            contract.stream_to_file(_Infinite(), tmp_path / "b.bin", chunk=1000, governor=gov)
        assert ei.value.bytes_written == 30 and gov.run_streamed == 100

    def test_a_flush_failure_keeps_the_retained_bytes_charged(self, tmp_path, monkeypatch):
        # the reservation must NOT be fully refunded when bytes landed on disk before the flush failed
        def _land_then_fail(fh, data):
            fh.write(data)
            fh.flush()                                # the 20 bytes reach disk...
            raise OSError("flush failed")             # ...then the flush raises
        _inject_sink(monkeypatch, _land_then_fail)
        state = tmp_path / "state" / "acquire-project-bytes.json"
        state.parent.mkdir(parents=True)
        gov = contract.DiskGovernor(run_max=100, project_max=100, reserve_bytes=0, project_state=state)
        dest = tmp_path / "ff.bin"
        with pytest.raises(contract.IncompleteAcquisition):
            contract.stream_to_file(io.BytesIO(b"y" * 20), dest, chunk=1000, governor=gov)
        part = dest.with_name(dest.name + ".part")
        assert part.stat().st_size == 20, "the flushed bytes are on disk"
        assert gov.run_streamed == 20 and gov._inflight == 0, "the retained bytes stay charged, not refunded to 0"
        assert json.loads(state.read_text())["bytes"] == 20, "the project counter keeps the retained bytes too"

    def test_bytes_flushed_during_close_are_charged(self, tmp_path, monkeypatch):
        # the mid-stream write path raises with the bytes still BUFFERED; the file's close-flush lands them
        # AFTER the last measure, and they must be charged, not lost
        def _buffer_then_raise(fh, data):
            fh.write(data)                            # buffered in the real writer, not yet on disk
            raise OSError("failed before flush")
        _inject_sink(monkeypatch, _buffer_then_raise)
        state = tmp_path / "state" / "acquire-project-bytes.json"
        state.parent.mkdir(parents=True)
        gov = contract.DiskGovernor(run_max=100, project_max=100, reserve_bytes=0, project_state=state)
        dest = tmp_path / "cf.bin"
        with pytest.raises(contract.IncompleteAcquisition) as ei:
            contract.stream_to_file(io.BytesIO(b"y" * 20), dest, chunk=1000, governor=gov)
        part = dest.with_name(dest.name + ".part")
        assert part.stat().st_size == 20, "the close-flush landed the 20 bytes"
        assert gov.run_streamed == 20 and gov._inflight == 0, "close-flush bytes are charged, not lost to 0"
        assert json.loads(state.read_text())["bytes"] == 20, "the project counter reflects the final on-disk size"
        assert ei.value.bytes_written == 20, "the exception's count matches the charged/retained bytes"


class TestProjectCounterDurability:
    def test_store_fsyncs_the_temp_file_and_the_parent_dir(self, tmp_path, monkeypatch):
        state = tmp_path / "state" / "acquire-project-bytes.json"
        state.parent.mkdir(parents=True)
        synced: list = []
        real_fsync = contract._os.fsync
        monkeypatch.setattr(contract._os, "fsync", lambda fd: synced.append(fd) or real_fsync(fd))
        contract._store_project_bytes(state, 4242)
        assert len(synced) >= 2, "the temp file AND the parent dir are fsync'd before the reservation is trusted"
        assert json.loads(state.read_text())["bytes"] == 4242
        assert not state.with_name(state.name + ".tmp").exists(), "no torn temp left behind"

    def test_a_short_counter_write_still_writes_the_whole_file(self, tmp_path, monkeypatch):
        state = tmp_path / "state" / "acquire-project-bytes.json"
        state.parent.mkdir(parents=True)
        real_write = contract._os.write
        calls = {"n": 0}

        def _short_first(fd, data):
            calls["n"] += 1
            if calls["n"] == 1:
                return real_write(fd, data[:3])       # a short write: only 3 bytes this call
            return real_write(fd, data)
        monkeypatch.setattr(contract._os, "write", _short_first)
        contract._store_project_bytes(state, 4242)
        assert json.loads(state.read_text())["bytes"] == 4242, "the write-all loop completes the JSON, not a torn file"


class TestPreExistingPartAndPublishFailure:
    def test_a_planted_part_directory_charges_nothing(self, tmp_path):
        gov = contract.DiskGovernor(reserve_bytes=0)
        dest = tmp_path / "d.bin"
        dest.with_name(dest.name + ".part").mkdir()       # a planted directory where the .part would go
        with pytest.raises(contract.IncompleteAcquisition):
            contract.stream_to_file(io.BytesIO(b"y" * 4096), dest, chunk=1000, governor=gov)
        assert gov.run_streamed == 0 and gov._inflight == 0, "a .part this call did not open charges nothing"

    def test_a_leftover_part_is_truncated_and_charges_only_new_bytes(self, tmp_path):
        gov = contract.DiskGovernor(reserve_bytes=0)
        dest = tmp_path / "d.bin"
        dest.with_name(dest.name + ".part").write_bytes(b"OLD" * 2000)   # 6000 leftover bytes
        n, _sha = contract.stream_to_file(io.BytesIO(b"y" * 100), dest, chunk=1000, governor=gov)
        assert n == 100 and dest.read_bytes() == b"y" * 100
        assert gov.run_streamed == 100, "the leftover is truncated; only this call's bytes are charged"

    def test_a_planted_part_symlink_is_refused_and_target_untouched(self, tmp_path):
        gov = contract.DiskGovernor(reserve_bytes=0)
        dest = tmp_path / "d.bin"
        external = tmp_path / "external.txt"
        external.write_bytes(b"IMPORTANT" * 10)
        dest.with_name(dest.name + ".part").symlink_to(external)         # planted symlink where .part would go
        with pytest.raises(contract.IncompleteAcquisition):
            contract.stream_to_file(io.BytesIO(b"y" * 100), dest, chunk=1000, governor=gov)
        assert external.read_bytes() == b"IMPORTANT" * 10, "the symlink target is NOT truncated/overwritten"
        assert not dest.exists(), "nothing is published through the symlink"
        assert gov.run_streamed == 0 and gov._inflight == 0, "a refused open charges nothing"

    def test_a_publish_failure_raises_typed_with_the_evidence(self, tmp_path, monkeypatch):
        import hashlib
        monkeypatch.setattr(contract._os, "replace", lambda src, dst: (_ for _ in ()).throw(OSError("no")))
        gov = contract.DiskGovernor(reserve_bytes=0)
        dest = tmp_path / "p.bin"
        with pytest.raises(contract.IncompleteAcquisition) as ei:
            contract.stream_to_file(io.BytesIO(b"z" * 24), dest, chunk=1000, governor=gov)
        part = dest.with_name(dest.name + ".part")
        assert ei.value.bytes_written == 24 and Path(ei.value.partial) == part
        assert part.read_bytes() == b"z" * 24, "the whole body stays retained in .part"
        assert hashlib.sha256(part.read_bytes()).hexdigest() == hashlib.sha256(b"z" * 24).hexdigest()
        assert gov.run_streamed == 24, "the acquired bytes stay charged"


class TestProjectCeilingAcrossProcesses:
    def test_a_second_process_sees_the_first_processs_reservation(self, tmp_path):
        state = tmp_path / "state" / "acquire-project-bytes.json"
        a = contract.DiskGovernor(project_max=100, reserve_bytes=0, project_state=state)
        b = contract.DiskGovernor(project_max=100, reserve_bytes=0, project_state=state)
        assert a._reserve_project(60) == 60
        assert b._reserve_project(80) == 40, "process B may only take what A left of the durable counter"
        assert json.loads(state.read_text())["bytes"] == 100

    def test_a_held_project_lock_makes_the_other_process_fail_closed(self, tmp_path):
        state = tmp_path / "state" / "acquire-project-bytes.json"
        state.parent.mkdir(parents=True, exist_ok=True)
        gov = contract.DiskGovernor(project_max=100, reserve_bytes=0, project_state=state)
        lockpath = state.with_name(state.name + ".lock")
        with budget.state_lock(lockpath):       # another process holds the reservation lock
            assert gov._reserve_project(50) is None
            assert gov.take(tmp_path, 0, 50) == (0, contract.LAYER_PROJECT), "contended durable state refuses"

    def test_an_unreadable_durable_counter_refuses(self, tmp_path):
        state = tmp_path / "state" / "acquire-project-bytes.json"
        state.parent.mkdir(parents=True, exist_ok=True)
        state.write_text("{ not valid json")
        gov = contract.DiskGovernor(project_max=100, reserve_bytes=0, project_state=state)
        assert gov.admit(tmp_path) == contract.LAYER_PROJECT
        assert gov.take(tmp_path, 0, 50) == (0, contract.LAYER_PROJECT)

    def test_a_persistence_failure_refuses_rather_than_reporting_false_clean(self, tmp_path, monkeypatch):
        state = tmp_path / "state" / "acquire-project-bytes.json"
        gov = contract.DiskGovernor(project_max=100, reserve_bytes=0, project_state=state)

        def _boom(*a, **k):
            raise OSError("disk full")
        monkeypatch.setattr(contract, "_store_project_bytes", _boom)
        assert gov.take(tmp_path, 0, 50) == (0, contract.LAYER_PROJECT), "a failed persist is not a false-clean"


class _Bal:
    """Only the balance fields the coordinator consumes; no reserve, unknown spendable = run it."""

    def __init__(self, spendable=None, may_spend=True, reserve=0):
        self.spendable = spendable
        self.may_spend = may_spend
        self.reason = "test"
        self.stop_kind = ""
        self.read_error = None
        self.reserve = reserve
