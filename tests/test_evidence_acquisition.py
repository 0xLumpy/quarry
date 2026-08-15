"""Acquisition is not interpretation (review#21, Lumpy, 2026-08-06).

`evidence.MAX_BODY = 2 MiB` dropped an over-cap response ENTIRELY — not truncated, not saved, not
reported — while `evidence_fetches` still counted it completed. The request had already been made and
the bytes had already crossed the wire, so the cap prevented no cost; it only converted a fetched body
into no evidence at all. `_DEEP_MAX_BODY` was worse: it refused to save a heap dump, the single most
secret-dense artifact recon can obtain, and suggested raising a number and paying for the request again.

These pin the replacement, in Lumpy's own acceptance terms:

  * a body far past the old cap is stored COMPLETE, in ONE fetch;
  * declining to parse preserves the whole artifact and RECORDS the deferral;
  * an interrupted transport keeps the partial bytes, reports a gap, and never retries;
  * reprocessing reads the stored artifact and makes ZERO further requests.
"""
from __future__ import annotations

import io
import json
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.offline

from quarry_recon import contract, events, evidence, fetch


class _Resp(io.BytesIO):
    """A response that behaves like a socket: `read(n)` returns AT MOST n bytes.

    A fake that returns the whole body on every `read()` pins the BUFFERED shape and hides every
    streaming defect — that exact fake cost a round on the Shodan side."""

    status = 200
    headers: dict = {}

    def close(self):                    # urllib responses are closed by the walker
        pass


def _ctx(tmp_path, added=None):
    """`read` is backed by the same list `add` writes to — the store is what a NEW lifecycle sees, so a
    fake that only records writes cannot exercise a repair across contexts (review#29)."""
    added = [] if added is None else added
    run = SimpleNamespace(
        raw_path=lambda ph, sub, nm: (tmp_path / ph / sub).joinpath(nm)
        if (tmp_path / ph / sub).mkdir(parents=True, exist_ok=True) or True else None,
        add=lambda kind, rec: (added.append((kind, rec)), True)[1],
        read=lambda kind: [r for k, r in added if k == kind])
    run.read_folded = lambda kind: SimpleNamespace(
        records={r.get("id", i): r for i, (k, r) in enumerate(added) if k == kind},
        status="valid", dropped=0, reason="")
    return SimpleNamespace(run=run, profile=SimpleNamespace(http_rl=0), scope=SimpleNamespace(
        in_scope=lambda h: True, is_oos=lambda h: False, active_allowed=lambda h: True)), added


def _reachable(monkeypatch):
    """`t` is not a real host, and the netguard resolves for real. Contact state is asserted on its own
    (below); these tests are about what happens to the BODY once contact is allowed."""
    monkeypatch.setattr(fetch.netguard, "contact_state",
                        lambda h, block_private=False: ("contact", None, None))


def _serve(monkeypatch, body: bytes, status: int = 200, calls=None):
    """Drive the REAL walker + streamer: only the socket is faked."""
    _reachable(monkeypatch)

    def _open(req, timeout, opener=None):
        if calls is not None:
            calls.append(req.full_url)
        return status, {}, _Resp(body)
    monkeypatch.setattr(fetch, "_open_no_follow", _open)


def ctx_of(tmp_path):
    return _ctx(tmp_path)[0]


def _transitions(specs, key="k"):
    """VALID transition rows — the shared resolver validates id and fingerprint exactly as the lane
    does, so a report fixture built by hand has to be real (review#32)."""
    out = []
    for state, seq, value, klass in specs:
        r = {"id": f"ownership:{key}:{seq}", "klass": klass, "state_key": key, "state": state,
             "state_seq": seq, "value": value, "note": f"{state} at {seq}"}
        r["state_fp"] = evidence._material(state, r)
        out.append(r)
    return out


def receipt(url="https://t/a", *, complete=False, body=b"", digest=None, **kw):
    """A VALID acquisition receipt. Every integrity field is required now (review#24), so a fixture
    that omits one is testing `receipt-damaged`, not the state it meant to."""
    import hashlib as _h
    doc = {"ident": fetch.acquisition_identity(url), "url": url, "method": "GET",
           "complete": complete, "bytes": len(body),
           "digest": digest if digest is not None else _h.sha256(body).hexdigest()}
    doc.update(kw)
    return json.dumps(doc)


BIG = b"x" * (3 * 1024 * 1024) + b"AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"      # 3 MiB, past the old 2 MiB cap


class TestABodyPastTheOldCapIsKeptWhole:
    def test_stored_complete_in_one_fetch(self, tmp_path, monkeypatch):
        calls: list = []
        _serve(monkeypatch, BIG, calls=calls)
        ctx, added = _ctx(tmp_path)
        res = evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch", subdir="exposed")
        assert res["ok"] and res["bytes"] == len(BIG)
        assert len(calls) == 1, f"the body must not be fetched twice: {calls}"
        from pathlib import Path
        assert Path(res["dest"]).read_bytes() == BIG, "stored WHOLE, byte for byte"

    def test_the_secret_past_the_old_cap_is_actually_found(self, tmp_path, monkeypatch):
        """The point of keeping it. Under `MAX_BODY` this body was discarded and this key never existed."""
        _serve(monkeypatch, BIG)
        ctx, added = _ctx(tmp_path)
        evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch", subdir="exposed")
        secs = [r for k, r in added if k == "secret"]
        assert secs and secs[0]["value"] == "AKIAIOSFODNN7EXAMPLE", added

    def test_memory_is_the_bound_not_the_bytes(self, tmp_path, monkeypatch):
        """`STREAM_CHUNK` is what is held in RAM; the artifact size is not bounded by it."""
        seen: list = []

        class _Watched(_Resp):
            def read(self, n=-1):
                seen.append(n)
                return super().read(n)

        def _open(req, timeout, opener=None):
            return 200, {}, _Watched(BIG)
        _reachable(monkeypatch)
        monkeypatch.setattr(fetch, "_open_no_follow", _open)
        ctx, _ = _ctx(tmp_path)
        res = evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch", subdir="exposed")
        assert res["bytes"] == len(BIG)
        assert seen and max(seen) == evidence.STREAM_CHUNK, seen[:5]
        assert len(seen) >= 4, "a 3 MiB body must arrive in several 1 MiB reads, not one"


class TestDecliningToParsePreservesEverything:
    def test_the_artifact_is_complete_and_the_deferral_is_recorded(self, tmp_path, monkeypatch):
        events.reset(); events.configure(tmp_path)
        monkeypatch.setattr(evidence, "MAX_PARSE", 1024)          # refuse to hold 3 MiB as text
        _serve(monkeypatch, BIG)
        ctx, added = _ctx(tmp_path)
        res = evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch", subdir="exposed")
        from pathlib import Path
        assert res["ok"] and res.get("deferred") and Path(res["dest"]).read_bytes() == BIG
        rec = [r for k, r in added if k == "review" and r.get("klass") == "deferred-interpretation"]
        assert rec, added
        assert rec[0]["bytes"] == len(BIG) and rec[0]["raw_ref"] == res["dest"]
        assert "Nothing was discarded" in rec[0]["note"]
        evs = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()]
        cov = [e for e in evs if e.get("measure") == "evidence_interpretation"]
        assert cov and cov[-1]["omitted"] == 1 and "acquired complete" in cov[-1]["reason"], cov
        events.reset()

    def test_reprocessing_reads_the_ARTIFACT_and_contacts_nobody(self, tmp_path, monkeypatch):
        """Lumpy's last acceptance test: the deferred body is re-runnable without a second request."""
        monkeypatch.setattr(evidence, "MAX_PARSE", 1024)
        calls: list = []
        _serve(monkeypatch, BIG, calls=calls)
        ctx, added = _ctx(tmp_path)
        res = evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch", subdir="exposed")
        assert len(calls) == 1 and not [r for k, r in added if k == "secret"]
        monkeypatch.setattr(fetch, "_open_no_follow",
                            lambda *a, **k: pytest.fail("reprocessing contacted the target"))
        n = evidence._mine_file(ctx, res["dest"], "https://t/.env", "t", "exposed-fetch")
        assert n == 1 and len(calls) == 1
        assert [r for k, r in added if k == "secret"][0]["value"] == "AKIAIOSFODNN7EXAMPLE"


class TestEveryLaneDefersRatherThanDropping:
    """`_text_of` is the shared decision, so every lane that reads a body through it must behave the
    same way: the artifact is kept and the deferral is recorded. A lane that quietly `continue`s on a
    large document loses every endpoint, schema or link it declared."""

    def test_a_large_openapi_document_is_kept_and_recorded(self, tmp_path, monkeypatch):
        events.reset(); events.configure(tmp_path)
        monkeypatch.setattr(evidence, "MAX_PARSE", 512)
        doc = b'{"paths": {"/a": {"get": {}}}, "pad": "' + b"p" * 4096 + b'"}'
        _serve(monkeypatch, doc)
        ctx, added = _ctx(tmp_path)
        assert evidence.parse_openapi(ctx, ["https://t/openapi.json"]) == 0
        rec = [r for k, r in added if k == "review" and r.get("klass") == "api-doc"]
        assert rec and rec[0]["bytes"] == len(doc), added
        from pathlib import Path
        assert Path(rec[0]["raw_ref"]).read_bytes() == doc, "the spec is stored WHOLE"
        events.reset()

    def test_a_large_graphql_schema_is_kept_and_recorded(self, tmp_path, monkeypatch):
        events.reset(); events.configure(tmp_path)
        monkeypatch.setattr(evidence, "MAX_PARSE", 512)
        body = b'{"data": {"__schema": {"pad": "' + b"p" * 4096 + b'"}}}'
        _serve(monkeypatch, body)
        ctx, added = _ctx(tmp_path)
        evidence.probe_graphql(ctx, ["https://t/graphql"])
        rec = [r for k, r in added if k == "review" and r.get("klass") == "graphql"]
        assert rec and "too large to parse in process" in rec[0]["note"], added
        from pathlib import Path
        assert Path(rec[0]["raw_ref"]).read_bytes() == body
        evs = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()]
        assert [e for e in evs if e.get("measure") == "evidence_interpretation"]
        events.reset()

    def test_a_large_actuator_index_is_kept_and_recorded(self, tmp_path, monkeypatch):
        events.reset(); events.configure(tmp_path)
        monkeypatch.setattr(evidence, "MAX_PARSE", 512)
        _serve(monkeypatch, b'{"_links": {"heapdump": {}}, "pad": "' + b"p" * 4096 + b'"}')
        ctx, added = _ctx(tmp_path)
        assert evidence._actuator_index_links(ctx, "https://t/actuator", "t") == set()
        rec = [r for k, r in added if k == "review" and r.get("klass") == "actuator"]
        assert rec and "actuator index fetched WHOLE" in rec[0]["note"], added
        events.reset()


class TestAnInterruptedTransportKeepsWhatArrived:
    class _Breaks(_Resp):
        def read(self, n=-1):
            buf = super().read(n)
            if not buf:
                raise OSError("connection reset mid-body")
            return buf

    def test_partial_bytes_are_kept_and_the_gap_is_reported(self, tmp_path, monkeypatch):
        def _open(req, timeout, opener=None):
            return 200, {}, self._Breaks(b"AWS_KEY=AKIAIOSFODNN7EXAMPLE\n" + b"y" * 4096)
        _reachable(monkeypatch)
        monkeypatch.setattr(fetch, "_open_no_follow", _open)
        ctx, added = _ctx(tmp_path)
        res = evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch", subdir="exposed")
        assert res["error"] == "incomplete" and not res["ok"]
        from pathlib import Path
        part = Path(res["partial"])
        assert part.exists() and part.read_bytes().startswith(b"AWS_KEY="), "what arrived is KEPT"
        assert res["bytes"] == part.stat().st_size

    def test_a_PARTIAL_body_is_never_interpreted_as_a_whole_one(self, tmp_path, monkeypatch):
        """A truncated document parses — badly. Half an OpenAPI spec is not a smaller spec, it is a
        different one, and endpoints "declared" by the surviving half are a claim the evidence does not
        support. The bytes stay; the interpretation does not happen."""
        doc = b'{"paths": {"/real": {"get": {}}, "/cut": ' + b"z" * 8192
        _reachable(monkeypatch)
        monkeypatch.setattr(fetch, "_open_no_follow",
                            lambda req, timeout, opener=None: (200, {}, self._Breaks(doc)))
        ctx, added = _ctx(tmp_path)
        assert evidence.parse_openapi(ctx, ["https://t/openapi.json"]) == 0
        assert not [r for k, r in added if k == "endpoint"], "no endpoint from a truncated spec"
        assert evidence._text_of(fetch.Acquisition(tmp_path, 10, "s", False)) is None

    def test_nothing_retries_it(self, tmp_path, monkeypatch):
        calls: list = []

        def _open(req, timeout, opener=None):
            calls.append(req.full_url)
            return 200, {}, self._Breaks(b"z" * 4096)
        _reachable(monkeypatch)
        monkeypatch.setattr(fetch, "_open_no_follow", _open)
        ctx, _ = _ctx(tmp_path)
        evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch", subdir="exposed")
        assert len(calls) == 1, f"an incomplete acquisition must not be re-requested: {calls}"

    def test_the_deadline_is_TIME_not_size(self, tmp_path, monkeypatch):
        """A socket that never reaches EOF would otherwise stream forever. The bound is the clock."""
        class _Endless(_Resp):
            def read(self, n=-1):
                return b"a" * (n if n and n > 0 else 1024)

        def _open(req, timeout, opener=None):
            return 200, {}, _Endless(b"")
        _reachable(monkeypatch)
        monkeypatch.setattr(fetch, "_open_no_follow", _open)
        monkeypatch.setattr(evidence, "STREAM_DEADLINE_S", 0.05)
        ctx, _ = _ctx(tmp_path)
        res = evidence.fetch_and_extract(ctx, "https://t/big", source="exposed-fetch", subdir="exposed")
        assert res["error"] == "incomplete" and res["bytes"] > 0
        assert "still receiving" in (res.get("partial") or "") or res["partial"], res


class TestTheWindowMinerSeesTheWholeFile:
    """A heap dump is gigabytes of binary with ASCII credentials in it. The bound moved to the WINDOW:
    memory is one window, evidence is the whole file."""

    def test_a_secret_beyond_the_first_window_is_found(self, tmp_path, monkeypatch):
        monkeypatch.setattr(evidence, "_DEEP_SCAN_WINDOW", 4096)
        monkeypatch.setattr(evidence, "_DEEP_SCAN_OVERLAP", 64)
        f = tmp_path / "heap.bin"
        f.write_bytes(b"\x00" * 20000 + b"AWS_KEY=AKIAIOSFODNN7EXAMPLE\n" + b"\x00" * 20000)
        ctx, added = _ctx(tmp_path)
        assert evidence._mine_file(ctx, f, "https://t/actuator/heapdump", "t", "deep-evidence") == 1
        assert [r for k, r in added if k == "secret"][0]["value"] == "AKIAIOSFODNN7EXAMPLE"

    def test_a_secret_ON_a_window_boundary_survives(self, tmp_path, monkeypatch):
        """Why the overlap exists: a token cut in half by the read boundary matches nothing."""
        monkeypatch.setattr(evidence, "_DEEP_SCAN_WINDOW", 4096)
        monkeypatch.setattr(evidence, "_DEEP_SCAN_OVERLAP", 64)
        sec = b"AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
        f = tmp_path / "heap.bin"
        f.write_bytes(b"\x00" * (4096 - 10) + sec + b"\x00" * 4096)     # straddles the first boundary
        ctx, added = _ctx(tmp_path)
        assert evidence._mine_file(ctx, f, "https://t/actuator/heapdump", "t", "deep-evidence") == 1

    def test_the_overlap_does_not_publish_the_same_value_twice(self, tmp_path, monkeypatch):
        monkeypatch.setattr(evidence, "_DEEP_SCAN_WINDOW", 4096)
        monkeypatch.setattr(evidence, "_DEEP_SCAN_OVERLAP", 512)
        sec = b"AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
        f = tmp_path / "heap.bin"
        f.write_bytes(b"\x00" * (4096 - 100) + sec + b"\x00" * 4096)    # inside the re-read overlap
        ctx, added = _ctx(tmp_path)
        assert evidence._mine_file(ctx, f, "https://t/x", "t", "deep-evidence") == 1
        assert len([r for k, r in added if k == "secret"]) == 1, added


class TestSizeNoLongerDecidesAFinding:
    def test_a_large_debug_dashboard_is_still_EXPOSED(self, tmp_path, monkeypatch):
        """`status == 200 and len(data) <= MAX_BODY` made a big body read as NOT exposed — the finding
        disappearing, dressed up as a guard."""
        _serve(monkeypatch, BIG)
        ctx, added = _ctx(tmp_path)
        n = evidence.probe_framework_endpoints(ctx, [{"url": "https://t/debug", "framework": "werkzeug",
                                             "note": "console"}])
        assert n == 1
        rec = [r for k, r in added if k == "review" and r.get("klass") == "debug"][0]
        assert "EXPOSED (200)" in rec["note"] and "secret(s) mined" in rec["note"]

    def test_a_large_actuator_env_is_still_EXPOSED_and_mined(self, tmp_path, monkeypatch):
        _serve(monkeypatch, b'{"_links":{}}')
        ctx, added = _ctx(tmp_path)
        monkeypatch.setattr(evidence, "ACTUATOR_SENSITIVE", ("env",))
        _serve(monkeypatch, BIG)
        evidence.probe_actuator(ctx, ["https://t/actuator"])
        rec = [r for k, r in added if k == "review" and r.get("klass") == "actuator"][0]
        assert "env" in rec["note"] and "EXPOSED" in rec["note"], rec
        assert [r for k, r in added if k == "secret"], "the credential in the large body is published"


class TestTheSSTIProbeCannotFalselyReadSAFE:
    def test_a_huge_response_is_recorded_as_unclassified_not_silently_safe(self, tmp_path, monkeypatch):
        events.reset(); events.configure(tmp_path)
        _serve(monkeypatch, b"q" * 8192)
        monkeypatch.setattr(evidence, "_ssti_hit", lambda p: None)
        ctx, _ = _ctx(tmp_path)
        assert evidence.probe_ssti(ctx, ["https://t/p?a=1"]) == 0
        evs = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()]
        cov = [e for e in evs if e.get("measure") == "ssti_params"]
        assert cov and cov[-1]["tested"] == 0 and cov[-1]["omitted"] == 1
        assert "could not be classified" in cov[-1]["reason"], cov[-1]["reason"]
        events.reset()

    def test_the_marker_check_walks_the_whole_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(evidence, "_DEEP_SCAN_WINDOW", 1024)
        f = tmp_path / "r.http"
        f.write_bytes(b"n" * 5000 + evidence._SSTI_EXPECT.encode() + b"n" * 5000)
        assert evidence._ssti_hit(f) is True
        f.write_bytes(b"n" * 5000 + evidence._SSTI_LITERAL.encode() + b"n" * 5000)
        assert evidence._ssti_hit(f) is False, "the expression came back unevaluated"
        assert evidence._ssti_hit(tmp_path / "missing") is None, "unreadable is NOT 'safe'"

    def test_a_non_hit_response_is_not_left_behind_as_evidence(self, tmp_path, monkeypatch):
        _serve(monkeypatch, b"nothing evaluated here")
        ctx, _ = _ctx(tmp_path)
        evidence.probe_ssti(ctx, ["https://t/p?a=1"])
        assert not list((tmp_path / "params" / "ssti").glob("*.http")), "a miss is not evidence"


class TestTheStreamingPrimitiveKeepsTheGuards:
    """The hop walker was lifted out of `scoped_get` so both body policies share it. Two copies of a
    scope check is how one of them stops matching the other."""

    def test_an_off_scope_redirect_is_never_contacted_and_writes_nothing(self, tmp_path, monkeypatch):
        seen: list = []

        def _open(req, timeout, opener=None):
            seen.append(req.full_url)
            return 302, {"Location": "https://evil.test/x"}, None
        _reachable(monkeypatch)
        monkeypatch.setattr(fetch, "_open_no_follow", _open)
        ctx, _ = _ctx(tmp_path)
        ctx.scope.active_allowed = lambda h: h == "t"
        dest = tmp_path / "out.bin"
        acq, final, status = fetch.scoped_get_file(ctx, "https://t/a", dest)
        assert acq is None and final == "https://evil.test/x"
        assert seen == ["https://t/a"], "the off-scope hop must never be requested"
        assert not dest.exists()

    def test_the_scan_box_guard_still_applies(self, tmp_path, monkeypatch):
        monkeypatch.setattr(fetch.netguard, "contact_state", lambda h, block_private=False: ("deny", "self", None))
        monkeypatch.setattr(fetch, "_open_no_follow",
                            lambda *a, **k: pytest.fail("the scan box was contacted"))
        ctx, _ = _ctx(tmp_path)
        acq, _final, status = fetch.scoped_get_file(ctx, "https://127.0.0.1/x", tmp_path / "o.bin")
        assert acq is None and status == 0

    def test_the_memory_reader_still_behaves_exactly_as_before(self, tmp_path, monkeypatch):
        """`scoped_get` keeps its contract for every caller that has not moved."""
        _serve(monkeypatch, b"abcdef")
        ctx, _ = _ctx(tmp_path)
        data, final, status = fetch.scoped_get(ctx, "https://t/a", max_body=3)
        assert data == b"abcd" and status == 200, "max_body+1 bytes, for the caller to judge"

    def test_a_redirect_LOOP_publishes_an_empty_artifact_not_an_off_scope_signal(self, tmp_path, monkeypatch):
        _reachable(monkeypatch)
        monkeypatch.setattr(fetch, "_open_no_follow",
                            lambda req, timeout, opener=None: (302, {"Location": "https://t/a"}, None))
        ctx, _ = _ctx(tmp_path)
        dest = tmp_path / "loop.bin"
        acq, _final, status = fetch.scoped_get_file(ctx, "https://t/a", dest)
        assert acq is not None and acq.complete and acq.bytes == 0, "a loop is not off-scope"
        assert dest.read_bytes() == b""


class TestTheAcquisitionContractIsShared:
    def test_it_reuses_the_paid_side_streamer(self, tmp_path, monkeypatch):
        """One streaming implementation, not two. The paid side already got this right after the Shodan
        4 MiB defect; the target side had no reason to invent a second one."""
        called: list = []
        real = contract.stream_to_file
        monkeypatch.setattr(contract, "stream_to_file",
                            lambda *a, **k: (called.append(k), real(*a, **k))[1])
        _serve(monkeypatch, b"hello")
        ctx, _ = _ctx(tmp_path)
        evidence.fetch_and_extract(ctx, "https://t/x", source="exposed-fetch", subdir="exposed")
        assert called and called[0]["chunk"] == evidence.STREAM_CHUNK


class TestAnUnclassifiedMatchIsKeptNotDropped:
    """review#21 (Lumpy): "classification changes placement, never retention".

    A candidate a DETECTOR matched and a RULE declined used to produce no entity at all — the bytes were
    in the raw artifact and an operator found them by reading it. Three rules decline on purpose, and
    each has a good reason; none of them is a reason to forget the value."""

    BODY = (b"DB_HOST=db.internal.example\n"
            b"MAILER_DSN=smtp://svc:S3cr3tPass@mail.example\n"
            b"LOG_LEVEL=verbose\n"
            b"AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

    def test_the_classified_one_still_goes_to_the_secret_queue(self, tmp_path, monkeypatch):
        _serve(monkeypatch, self.BODY)
        ctx, added = _ctx(tmp_path)
        evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch", subdir="exposed")
        assert [r["value"] for k, r in added if k == "secret"] == ["AKIAIOSFODNN7EXAMPLE"]

    def test_the_declined_ones_are_kept_WHOLE_as_observations(self, tmp_path, monkeypatch):
        _serve(monkeypatch, self.BODY)
        ctx, added = _ctx(tmp_path)
        res = evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch", subdir="exposed")
        obs = {r["key"]: r for k, r in added if k == "review" and r.get("klass") == "unclassified"}
        assert set(obs) == {"DB_HOST", "MAILER_DSN", "LOG_LEVEL"}, obs
        assert res["unclassified"] == 3
        assert obs["MAILER_DSN"]["value"] == "smtp://svc:S3cr3tPass@mail.example", "COMPLETE, not masked"
        assert obs["MAILER_DSN"]["line"] == 2 and obs["MAILER_DSN"]["raw_ref"] == res["dest"]

    def test_it_makes_no_secrecy_claim(self, tmp_path, monkeypatch):
        _serve(monkeypatch, self.BODY)
        ctx, added = _ctx(tmp_path)
        evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch", subdir="exposed")
        obs = [r for k, r in added if k == "review" and r.get("klass") == "unclassified"]
        assert all(o["klass"] == "unclassified" for o in obs)
        assert all("No secrecy or impact claim" in o["note"] for o in obs)
        assert all(o["reason"] for o in obs), "why it was not promoted travels with it"

    def test_shape_decides_ORDER_not_retention(self, tmp_path, monkeypatch):
        _serve(monkeypatch, self.BODY)
        ctx, added = _ctx(tmp_path)
        evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch", subdir="exposed")
        obs = {r["key"]: r["interest"] for k, r in added if k == "review"
               and r.get("klass") == "unclassified"}
        assert obs["MAILER_DSN"] == "high" and obs["LOG_LEVEL"] == "low"
        assert "LOG_LEVEL" in obs, "low interest is still RETAINED"

    def test_a_SHORT_value_is_low_however_varied_it_looks(self):
        """Length is its own axis: four character classes in five characters is a formatting quirk, not
        a credential. Without the length floor, `aB3!` outranks a 40-character random string."""
        assert evidence._shape_interest("aB3!x") == "low"
        assert evidence._shape_interest("aB3!x" * 4) == "high"
        assert evidence._shape_interest("https://cdn.example/app.js") == "low", "a plain URL is config"
        assert evidence._shape_interest("https://u:p@cdn.example/x") == "high", "credentials in a URL"

    def test_a_bare_json_key_with_no_context_is_observed(self, tmp_path, monkeypatch):
        _serve(monkeypatch, b'{"cache": {"key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}')
        ctx, added = _ctx(tmp_path)
        evidence.fetch_and_extract(ctx, "https://t/app.json", source="exposed-fetch", subdir="exposed")
        obs = [r for k, r in added if k == "review" and r.get("klass") == "unclassified"]
        assert obs and "no signing or symmetric context" in obs[0]["reason"]
        assert not [r for k, r in added if k == "secret"], "still not promoted to a secret"

    def test_a_password_without_connection_string_structure_is_observed(self, tmp_path, monkeypatch):
        _serve(monkeypatch, b"password=hunter22xyz;mode=fast;\n")
        ctx, added = _ctx(tmp_path)
        evidence.fetch_and_extract(ctx, "https://t/notes.txt", source="exposed-fetch", subdir="exposed")
        obs = [r for k, r in added if k == "review" and r.get("klass") == "unclassified"]
        assert obs and obs[0]["value"] == "hunter22xyz"
        assert "without connection-string structure" in obs[0]["reason"]

    def test_the_sink_is_OPTIONAL_so_the_rules_live_in_one_place(self):
        """`mine()` behaves identically when no list is passed — there is no second scanner restating
        the same rules and drifting from them."""
        body = self.BODY.decode()
        assert evidence.mine(body, source_path="/x/.env") == \
            evidence.mine(body, source_path="/x/.env", rejected=[])

    def test_a_heap_dump_observation_is_not_republished_per_window(self, tmp_path, monkeypatch):
        monkeypatch.setattr(evidence, "_DEEP_SCAN_WINDOW", 4096)
        monkeypatch.setattr(evidence, "_DEEP_SCAN_OVERLAP", 512)
        f = tmp_path / "heap.bin"
        f.write_bytes(b"\x00" * (4096 - 60) + b"\nMAILER_DSN=smtp://svc:S3cr3tPass@mail.example\n"
                      + b"\x00" * 4096)
        ctx, added = _ctx(tmp_path)
        evidence._mine_file(ctx, f, "https://t/actuator/heapdump", "t", "deep-evidence")
        obs = [r for k, r in added if k == "review" and r.get("klass") == "unclassified"]
        assert len(obs) == 1, obs

    def test_an_observation_never_suppresses_a_LATER_classified_value(self, tmp_path, monkeypatch):
        """The two dedupe sets are separate on purpose. Sharing one would let the same string, seen
        first under a boring key, swallow the promotion it gets from a rule later in the file."""
        monkeypatch.setattr(evidence, "_DEEP_SCAN_WINDOW", 4096)
        monkeypatch.setattr(evidence, "_DEEP_SCAN_OVERLAP", 64)
        val = b"Zk3Rm9QpX7bV2sLd4NwY8tHc6uJe0A"          # no provider token rule matches this
        f = tmp_path / "heap.bin"
        f.write_bytes(b"\nBUILD_TAG=" + val + b"\n" + b"\x00" * 8192
                      + b'\n{"app_password": "' + val + b'"}\n')
        ctx, added = _ctx(tmp_path)
        assert evidence._mine_file(ctx, f, "https://t/x", "t", "deep-evidence") == 1, \
            "the later, CLASSIFIED sighting must still be published"
        assert [r["value"] for k, r in added if k == "secret"] == [val.decode()]
        assert [r["key"] for k, r in added if k == "review" and r.get("klass") == "unclassified"] \
            == ["BUILD_TAG"]


class TestTheReportShowsTheInterestingOnesFirst:
    """The display is bounded (15 rows) and the queue is not. Which 15 an operator sees is therefore the
    whole value of the ranking — and `sorted(set(...))` would order them alphabetically, i.e. by nothing."""

    @staticmethod
    def _report(rows):
        from quarry_recon import triage
        run = SimpleNamespace(
            read=lambda kind: rows if kind == "review" else [],
            values=lambda kind: [], count=lambda kind: 0, path=None,
            target="t.example", run_id="r1")
        scope = SimpleNamespace(in_scope=lambda h: True, is_oos=lambda h: False,
                                active_allowed=lambda h: True, roots=[], oos=[])
        return triage.build(run, scope)

    def _rows(self, n_low=30):
        # the boring rows sort BEFORE the interesting one alphabetically, so an alphabetical order
        # would bury it past the 15 shown. That is the whole point of ranking by shape.
        rows = [{"klass": "unclassified", "value": f"aaa-boring-{i:02d}", "key": f"AOPT{i:02d}",
                 "reason": "key is not secret-shaped", "interest": "low"} for i in range(n_low)]
        rows.append({"klass": "unclassified", "value": "smtp://svc:S3cr3tPass@mail.example",
                     "key": "MAILER_DSN", "reason": "key is not secret-shaped", "interest": "high"})
        return rows

    def test_a_high_interest_row_is_shown_even_behind_30_boring_ones(self):
        from quarry_recon import triage
        out = self._report(self._rows())
        expected = triage.markdown_value("MAILER_DSN = smtp://svc:S3cr3tPass@mail.example"
                                         "   [high: key is not secret-shaped]")
        assert expected in out, out[-2000:]

    def test_the_value_is_shown_COMPLETE_with_why_it_was_not_promoted(self):
        from quarry_recon import triage
        out = self._report(self._rows())
        assert triage.markdown_value("[high: key is not secret-shaped]") in out
        assert "S3cr3tPass" in out, "the operator reads the finding, not a mask"

    def test_the_held_back_rows_are_ANNOUNCED_not_silently_cut(self):
        out = self._report(self._rows())
        assert "more — full list in normalized/review.jsonl" in out


class TestTheOverlapBoundsWhatCanSurviveABoundary:
    """Found while writing the gate check: with an 8-byte overlap a 20-character AWS key matched
    NOWHERE — every window that touched it held only a fragment. The overlap is not a tuning knob, it
    is the longest value the scan can still see across a boundary."""

    KEY = b"AKIAIOSFODNN7EXAMPLE"

    def _mine(self, tmp_path, window, overlap, monkeypatch):
        monkeypatch.setattr(evidence, "_DEEP_SCAN_WINDOW", window)
        monkeypatch.setattr(evidence, "_DEEP_SCAN_OVERLAP", overlap)
        f = tmp_path / "h.bin"
        f.write_bytes(b"." * (window - 8) + self.KEY + b"." * window)   # straddles the first boundary
        ctx, added = _ctx(tmp_path)
        return evidence._mine_file(ctx, f, "https://t/x", "t", "deep-evidence")

    def test_an_overlap_LONGER_than_the_value_finds_it(self, tmp_path, monkeypatch):
        assert self._mine(tmp_path, 24, 20, monkeypatch) == 1

    def test_an_overlap_SHORTER_than_the_value_cannot(self, tmp_path, monkeypatch):
        assert self._mine(tmp_path, 24, 4, monkeypatch) == 0, \
            "documented consequence, not a surprise — the shipped overlap is 64 KiB"

    def test_the_shipped_overlap_is_far_above_any_pattern_here(self):
        assert evidence._DEEP_SCAN_OVERLAP >= 4096
        assert evidence._DEEP_SCAN_OVERLAP < evidence._DEEP_SCAN_WINDOW, \
            "an overlap at or above the window re-reads everything forever"


class TestAnIncompleteAcquisitionIsNotAResult:
    """review#22 (Lumpy). Four ways an interrupted body was still allowed to look like an answer."""

    class _Breaks(_Resp):
        def read(self, n=-1):
            buf = super().read(n)
            if not buf:
                raise OSError("connection reset mid-body")
            return buf

    def _broken(self, monkeypatch, body, calls=None):
        _reachable(monkeypatch)

        def _open(req, timeout, opener=None):
            if calls is not None:
                calls.append(req.full_url)
            return 200, {}, self._Breaks(body)
        monkeypatch.setattr(fetch, "_open_no_follow", _open)

    def test_a_SECOND_call_does_not_re_request_it(self, tmp_path, monkeypatch):
        """"nothing retries it" was true of one call and false of the lane: the same URL reached from
        two candidate lists walked straight back to the network. The `.part` file is the receipt."""
        calls: list = []
        self._broken(monkeypatch, b"AWS_KEY=AKIAIOSFODNN7EXAMPLE\n" + b"y" * 4096, calls)
        ctx, _ = _ctx(tmp_path)
        first = evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch",
                                           subdir="exposed")
        assert first["error"] == "incomplete", "the FIRST one really did break mid-transport"
        for _ in range(2):
            res = evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch",
                                             subdir="exposed")
            assert res["error"] == "refused", "the ones after it made no request at all"
        assert len(calls) == 1, f"the URL was requested {len(calls)} times: {calls}"
        assert "NOT re-requested" in res["reason"], res
        assert res["contacted"] is False and res["disposition"] == "replayed-incomplete"
        assert res["attempted"] is False, "a replayed receipt is not an attempt at the target"

    def test_removing_the_part_file_lets_an_operator_try_again(self, tmp_path, monkeypatch):
        calls: list = []
        self._broken(monkeypatch, b"z" * 4096, calls)
        ctx, _ = _ctx(tmp_path)
        r1 = evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch", subdir="exposed")
        from pathlib import Path
        part = Path(r1["partial"])
        part.unlink()
        for r in part.parent.glob("*" + fetch._RECEIPT_SUFFIX):
            r.unlink()
        evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch", subdir="exposed")
        assert len(calls) == 2, "the decision to retry is the operator's, and it works"

    def test_it_is_NOT_counted_as_a_readable_response(self, tmp_path, monkeypatch):
        events.reset(); events.configure(tmp_path)
        self._broken(monkeypatch, b"AWS_KEY=AKIAIOSFODNN7EXAMPLE\n" + b"y" * 4096)
        ctx, added = _ctx(tmp_path)
        evidence.fetch_exposed(ctx, ["https://t/.env"])
        evs = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()]
        cov = [e for e in evs if e.get("measure") == "evidence_fetches"][-1]
        assert cov["eligible"] == 1 and cov["tested"] == 0 and cov["omitted"] == 1, cov
        assert "attempted without a readable response" in cov["reason"]
        events.reset()

    def test_and_it_does_not_DISAPPEAR(self, tmp_path, monkeypatch):
        """It used to be counted as completed and then skipped, so nothing was written anywhere: an
        interrupted fetch and a resource we never looked at read identically."""
        self._broken(monkeypatch, b"AWS_KEY=AKIAIOSFODNN7EXAMPLE\n" + b"y" * 4096)
        ctx, added = _ctx(tmp_path)
        evidence.fetch_exposed(ctx, ["https://t/.env"])
        rows = [r for k, r in added if k == "review" and "INCOMPLETE" in r.get("note", "")]
        assert rows, added
        from pathlib import Path
        assert Path(rows[0]["raw_ref"]).read_bytes().startswith(b"AWS_KEY=")

    def test_an_incomplete_openapi_document_is_recorded_not_skipped(self, tmp_path, monkeypatch):
        self._broken(monkeypatch, b'{"paths": {"/a": {"get": {}}}' + b" " * 4096)
        ctx, added = _ctx(tmp_path)
        assert evidence.parse_openapi(ctx, ["https://t/openapi.json"]) == 0
        rows = [r for k, r in added if k == "review" and r.get("klass") == "api-doc"]
        assert rows and "INCOMPLETE" in rows[0]["note"], added
        assert not [r for k, r in added if k == "endpoint"]

    def test_an_incomplete_actuator_index_is_recorded_not_skipped(self, tmp_path, monkeypatch):
        self._broken(monkeypatch, b'{"_links": {"heapdump": {}}' + b" " * 4096)
        ctx, added = _ctx(tmp_path)
        assert evidence._actuator_index_links(ctx, "https://t/actuator", "t") == set()
        rows = [r for k, r in added if k == "review" and "INCOMPLETE" in r.get("note", "")]
        assert rows and "under-reported" in rows[0]["note"], added

    def test_a_PARTIAL_ssti_response_is_never_a_finding(self, tmp_path, monkeypatch):
        """The computed value can be in the prefix that arrived while the unevaluated literal — which
        would have settled it as reflection only — is in the suffix that never did."""
        events.reset(); events.configure(tmp_path)
        self._broken(monkeypatch, b"out: 7006652 ... and later the literal {{1234*5678}}" + b"z" * 8192)
        ctx, added = _ctx(tmp_path)
        assert evidence.probe_ssti(ctx, ["https://t/p?a=1"]) == 0
        assert not [r for k, r in added if k == "finding"], added
        evs = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()]
        cov = [e for e in evs if e.get("measure") == "ssti_params"]
        assert cov and cov[-1]["tested"] == 0 and "could not be classified" in cov[-1]["reason"]
        events.reset()


class TestNoSILENTMembershipCapsAreLeft:
    def test_every_openapi_path_becomes_an_endpoint(self, tmp_path, monkeypatch):
        """`_OPENAPI_MAX_PATHS = 2000` kept the first 2000 paths of an already-parsed document and
        dropped the rest, unrecorded and unresumable — registered as a memory guard it never was."""
        assert not hasattr(evidence, "_OPENAPI_MAX_PATHS"), "the cap is gone, not renamed"
        doc = {"openapi": "3.0.0", "servers": [{"url": "https://t/v1"}],
               "paths": {f"/p{i}": {"get": {}} for i in range(2500)}}
        _serve(monkeypatch, json.dumps(doc).encode())
        ctx, added = _ctx(tmp_path)
        assert evidence.parse_openapi(ctx, ["https://t/openapi.json"]) == 2500
        assert len([r for k, r in added if k == "endpoint"]) == 2500

    def test_the_ssti_param_bound_stays_but_NAMES_what_it_skipped(self, tmp_path, monkeypatch):
        """This one is real request pressure — one probe per parameter against a live target — so the
        bound is right. Silence about the remainder was not."""
        events.reset(); events.configure(tmp_path)
        _serve(monkeypatch, b"nothing")
        ctx, _ = _ctx(tmp_path)
        url = "https://t/p?" + "&".join(f"a{i}=1" for i in range(14))
        evidence.probe_ssti(ctx, [url])
        evs = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()]
        cov = {e["unit"].rsplit("#", 1)[1]: e for e in evs if e.get("measure") == "ssti_params"}
        # the buckets are DISJOINT and sum to the whole query string
        assert sum(e["eligible"] for e in cov.values()) == 14
        cap = cov["policy-cap"]
        assert cap["kind"] == "cap" and cap["eligible"] == 4 and cap["tested"] == 0
        for i, name in enumerate(("a10", "a11", "a12", "a13"), start=10):
            assert f"{name}[{i}] (beyond SSTI_MAX_PARAMS=10" in cap["reason"], cap["reason"]
        assert cov["unreachable"]["tested"] == 10, "the ten we probed all answered"
        events.reset()


class TestProvenanceIsMEASUREDOrAbsent:
    def test_a_rejected_connection_string_carries_its_REAL_line(self, tmp_path, monkeypatch):
        body = b"one\ntwo\nthree\npassword=hunter22xyz;mode=fast;\n"
        _serve(monkeypatch, body)
        ctx, added = _ctx(tmp_path)
        evidence.fetch_and_extract(ctx, "https://t/n.txt", source="exposed-fetch", subdir="exposed")
        obs = [r for k, r in added if k == "review" and r.get("klass") == "unclassified"][0]
        assert obs["line"] == 4, obs

    def test_a_STRUCTURAL_reject_carries_its_json_path_and_no_line(self, tmp_path, monkeypatch):
        """`text.find(val)` reported the FIRST occurrence: the same string under `"name"` on line 2 and
        the rejected `"key"` on line 4 pointed an operator at line 2, a different field entirely. A
        structural finding gets structural provenance."""
        _serve(monkeypatch, b'{\n "name": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",\n "cache": {\n'
                            b'  "key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n }\n}')
        ctx, added = _ctx(tmp_path)
        evidence.fetch_and_extract(ctx, "https://t/a.json", source="exposed-fetch", subdir="exposed")
        obs = [r for k, r in added if k == "review" and r.get("klass") == "unclassified"][0]
        assert "line" not in obs, obs
        assert "[at cache.key]" in obs["reason"], obs

    def test_a_structural_reject_is_never_given_a_line(self):
        """Line 1 is a claim; so is the line of some other field that happens to hold the same string."""
        rejected = [("bare `key` field with no signing or symmetric context", "key", "abc", None)]
        evidence.mine('{"other": "abc"}', source_path="/x/a.json", rejected=rejected)
        assert rejected[0][3] is None, "a text search must not manufacture a position"
        ctx = SimpleNamespace(run=SimpleNamespace(add=lambda k, r: (rows.append(r), True)[1]))
        rows: list = []
        evidence.publish_unclassified(ctx, rejected, url="https://t/a", dest=None,
                                      source="exposed-fetch")
        assert "line" not in rows[0], rows[0]


class TestTheReceiptIsBoundToTheREQUEST:
    """review#22 (Lumpy): existence of a `.part` file is not identity. Callers named artifacts with
    `md5(url)[:8]` — 32 bits — and `https://t/item/46327` and `https://t/item/69781` really do collide
    at `af1f2617`. One URL's failed acquisition would then speak for another URL entirely."""

    def test_the_old_artifact_name_collided_and_the_new_one_does_not(self):
        import hashlib
        a, b = "https://t/item/46327", "https://t/item/69781"
        assert hashlib.md5(a.encode()).hexdigest()[:8] == hashlib.md5(b.encode()).hexdigest()[:8]
        assert evidence._artifact_id(a) != evidence._artifact_id(b)
        assert len(evidence._artifact_id(a)) >= 24

    def test_identity_covers_url_method_body_and_policy(self):
        i = fetch.acquisition_identity
        base = i("https://t/x")
        assert i("https://t/x") == base
        assert i("https://t/y") != base
        assert i("https://t/x", method="POST") != base
        assert i("https://t/x", data=b"{}") != base
        assert i("https://t/x", data=b"{}") != i("https://t/x", data=b"[]")
        assert i("https://t/x", policy="introspection") != base

    def test_a_DIFFERENT_request_at_the_same_path_refuses_instead_of_mixing(self, tmp_path, monkeypatch):
        """The last line of defence if a path is ever reused: never silently overwrite, never fetch
        under an ambiguous name, and never let the other request's failure answer for this one."""
        _reachable(monkeypatch)
        dest = tmp_path / "shared.bin"
        (tmp_path / ("shared.bin" + fetch._RECEIPT_SUFFIX)).write_text(
            receipt("https://t/other", body=b"someone", status=200, error="reset"))
        monkeypatch.setattr(fetch, "_open_no_follow",
                            lambda *a, **k: pytest.fail("fetched under an ambiguous artifact name"))
        acq, _final, _status = fetch.scoped_get_file(ctx_of(tmp_path), "https://t/mine", dest)
        assert acq.disposition == "path-collision" and acq.contacted is False
        assert "https://t/other" in acq.error

    def test_a_replay_reports_the_ORIGINAL_response_line(self, tmp_path, monkeypatch):
        """Several lanes branch on status before they look at completeness. A synthetic 0 made them
        treat a replayed incomplete as 'no answer' and drop the disposition."""
        import hashlib as _h
        _reachable(monkeypatch)
        dest = tmp_path / "a.bin"
        body = b"twelve bytes"                     # the partial must EXIST and match — see the
        (tmp_path / "a.bin.part").write_bytes(body)   # reconciliation tests below
        (tmp_path / ("a.bin" + fetch._RECEIPT_SUFFIX)).write_text(
            receipt(body=body, final="https://t/final", status=200, error="reset"))
        monkeypatch.setattr(fetch, "_open_no_follow",
                            lambda *a, **k: pytest.fail("a replay must not contact the target"))
        acq, final, status = fetch.scoped_get_file(ctx_of(tmp_path), "https://t/a", dest)
        assert (final, status) == ("https://t/final", 200)
        assert acq.status == 200 and acq.final == "https://t/final"
        assert acq.disposition == "replayed-incomplete" and acq.contacted is False and acq.bytes == 12

    def test_a_replay_is_not_an_ATTEMPT(self, tmp_path, monkeypatch):
        events.reset(); events.configure(tmp_path)
        _reachable(monkeypatch)
        ctx, _ = _ctx(tmp_path)
        dest = ctx.run.raw_path("params", "exposed", "t-" + evidence._artifact_id("https://t/.env"))
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.with_name(dest.name + fetch._RECEIPT_SUFFIX).write_text(json.dumps(
            {"ident": fetch.acquisition_identity("https://t/.env"), "url": "https://t/.env",
             "status": 200, "bytes": 4, "error": "reset"}))
        monkeypatch.setattr(fetch, "_open_no_follow",
                            lambda *a, **k: pytest.fail("a replay must not contact the target"))
        evidence.fetch_exposed(ctx, ["https://t/.env"])
        evs = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()]
        cov = [e for e in evs if e.get("measure") == "evidence_fetches"][-1]
        assert cov["eligible"] == 0 and cov["tested"] == 0, "a replay is not in this denominator at all"
        assert "attempted without a readable response" not in cov["reason"], \
            "zero network contact must not read as an attempt"
        own = [e for e in evs if e.get("measure") == "evidence_ownership"]
        assert own and own[-1]["kind"] == "ownership", "it is counted HERE instead"
        events.reset()

    def test_a_transport_failure_IS_still_an_attempt(self, tmp_path, monkeypatch):
        """The other direction, and the older review it must not undo: a refused connection happened
        after contact was made."""
        _reachable(monkeypatch)
        monkeypatch.setattr(fetch, "_open_no_follow",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("refused")))
        ctx, _ = _ctx(tmp_path)
        res = evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch", subdir="exposed")
        assert res["attempted"] is True and res["error"] == "OSError"


class TestTruncationReachesTheVERDICT:
    """A review row is operator-facing and does not make a run incomplete. Without a coverage record the
    verdict could certify coverage over an artifact that was truncated."""

    class _Breaks(_Resp):
        def read(self, n=-1):
            buf = super().read(n)
            if not buf:
                raise OSError("connection reset mid-body")
            return buf

    def _broken(self, monkeypatch, body):
        _reachable(monkeypatch)
        monkeypatch.setattr(fetch, "_open_no_follow",
                            lambda req, timeout, opener=None: (200, {}, self._Breaks(body)))

    def _gaps(self, tmp_path, measure):
        evs = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()]
        return [e for e in evs if e.get("measure") == measure]

    def test_an_incomplete_openapi_document_emits_a_GATING_coverage_gap(self, tmp_path, monkeypatch):
        events.reset(); events.configure(tmp_path)
        self._broken(monkeypatch, b'{"paths": {"/a": {"get": {}}}' + b" " * 4096)
        ctx, _ = _ctx(tmp_path)
        evidence.parse_openapi(ctx, ["https://t/openapi.json"])
        cov = self._gaps(tmp_path, "api_documents")
        assert cov and cov[-1]["omitted"] == 1
        assert cov[-1]["kind"] not in ("sample", "provider"), "sample/provider are the SOFT kinds"
        events.reset()

    def test_an_incomplete_actuator_index_emits_a_GATING_coverage_gap(self, tmp_path, monkeypatch):
        events.reset(); events.configure(tmp_path)
        self._broken(monkeypatch, b'{"_links": {"heapdump": {}}' + b" " * 4096)
        ctx, _ = _ctx(tmp_path)
        evidence._actuator_index_links(ctx, "https://t/actuator", "t")
        cov = self._gaps(tmp_path, "actuator_index")
        assert cov and cov[-1]["omitted"] == 1 and cov[-1]["kind"] not in ("sample", "provider")
        events.reset()

    def test_a_deferred_interpretation_is_a_GAP_not_a_soft_limit(self, tmp_path, monkeypatch):
        """Nobody CHOSE this subset and the run really did not extract from that artifact. Keeping it
        makes the omission recoverable, not clean."""
        events.reset(); events.configure(tmp_path)
        monkeypatch.setattr(evidence, "MAX_PARSE", 1024)
        _serve(monkeypatch, BIG)
        ctx, _ = _ctx(tmp_path)
        evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch", subdir="exposed")
        cov = self._gaps(tmp_path, "evidence_interpretation")
        assert cov and cov[-1]["kind"] not in ("sample", "provider"), cov
        events.reset()


class TestSSTICoverageIsMEASURED:
    def test_probes_that_never_CONTACTED_are_not_reported_as_tested(self, tmp_path, monkeypatch):
        """It published `tested=10` before the loop: with every probe failing before contact, the run
        made zero requests and still claimed ten."""
        events.reset(); events.configure(tmp_path)
        _reachable(monkeypatch)
        monkeypatch.setattr(fetch, "_open_no_follow",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("refused")))
        ctx, _ = _ctx(tmp_path)
        url = "https://t/p?" + "&".join(f"a{i}=1" for i in range(12))
        assert evidence.probe_ssti(ctx, [url]) == 0
        rows = {e["unit"].rsplit("#", 1)[1]: e for e in
                (json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines())
                if e.get("measure") == "ssti_params"}
        assert sum(e["eligible"] for e in rows.values()) == 12
        assert rows["unreachable"]["tested"] == 0 and rows["unreachable"]["omitted"] == 10
        assert rows["unreachable"]["kind"] == "timeout", "a failed request is not a ceiling"
        assert "request failed (OSError)" in rows["unreachable"]["reason"]
        assert rows["policy-cap"]["kind"] == "cap" and rows["policy-cap"]["omitted"] == 2
        events.reset()

    def test_a_confirmation_leaves_the_REST_in_the_remainder(self, tmp_path, monkeypatch):
        """The loop breaks on the first confirmation. Those parameters were not tested and must not be
        counted as if they were."""
        events.reset(); events.configure(tmp_path)
        _serve(monkeypatch, b"out: 7006652")
        ctx, _ = _ctx(tmp_path)
        url = "https://t/p?" + "&".join(f"a{i}=1" for i in range(6))
        assert evidence.probe_ssti(ctx, [url]) == 1
        rows = {e["unit"].rsplit("#", 1)[1]: e for e in
                (json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines())
                if e.get("measure") == "ssti_params"}
        assert rows["unreachable"]["tested"] == 1, "one parameter was classified"
        stop = rows["policy-stop"]
        assert stop["eligible"] == 5 and stop["omitted"] == 5 and stop["tested"] == 0
        assert "a confirmation on an earlier parameter" in stop["reason"]
        events.reset()

    def test_a_REPEATED_parameter_name_is_two_occurrences_not_one(self, tmp_path, monkeypatch):
        """`?a=1&a=2` is ordinary and it raised `KeyError: 'a'` — the map was keyed by NAME, so the
        second occurrence deleted a key the first had already removed. The index is what distinguishes
        them, and it is what an operator needs to know WHICH `a` was probed."""
        events.reset(); events.configure(tmp_path)
        _serve(monkeypatch, b"nothing")
        ctx, _ = _ctx(tmp_path)
        assert evidence.probe_ssti(ctx, ["https://t/p?a=1&a=2"]) == 0
        rows = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()
                if json.loads(x).get("measure") == "ssti_params"]
        assert len(rows) == 1 and rows[0]["eligible"] == 2 and rows[0]["tested"] == 2
        events.reset()

    def test_a_mixed_outcome_counts_every_RESOLVED_one(self, tmp_path, monkeypatch):
        """One answered 404 plus one failed request reported `eligible=2, tested=0, omitted=1` — the
        answered occurrence vanished from both sides of the triple."""
        events.reset(); events.configure(tmp_path)
        _reachable(monkeypatch)
        seen = {"n": 0}

        def _open(req, timeout, opener=None):
            seen["n"] += 1
            if seen["n"] == 1:
                return 404, {}, _Resp(b"nope")
            raise OSError("refused")
        monkeypatch.setattr(fetch, "_open_no_follow", _open)
        ctx, _ = _ctx(tmp_path)
        evidence.probe_ssti(ctx, ["https://t/p?a=1&b=2"])
        rows = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()
                if json.loads(x).get("measure") == "ssti_params"]
        assert len(rows) == 1, rows
        assert (rows[0]["eligible"], rows[0]["tested"], rows[0]["omitted"]) == (2, 1, 1), rows[0]
        assert rows[0]["kind"] == "timeout", "a failed request is not a ceiling"
        events.reset()

    def test_a_non_200_is_an_ANSWER_not_a_gap(self, tmp_path, monkeypatch):
        events.reset(); events.configure(tmp_path)
        _serve(monkeypatch, b"nope", status=404)
        ctx, _ = _ctx(tmp_path)
        evidence.probe_ssti(ctx, ["https://t/p?a=1&b=2"])
        log = tmp_path / "events.jsonl"
        rows = [json.loads(x) for x in log.read_text().splitlines()] if log.exists() else []
        cov = [e for e in rows if e.get("measure") == "ssti_params"]
        assert len(cov) == 1 and cov[0]["omitted"] == 0 and cov[0]["tested"] == 2, cov
        assert "none" in cov[0]["reason"], "every parameter was resolved: the app did not render it"
        events.reset()


class TestTheReceiptStateIsRECONCILED:
    """review#23 (Lumpy): the receipt and the partial are ONE state and must be read as one. Every
    combination other than "neither exists" means a prior acquisition happened or cannot be ruled out —
    and collapsing any of them into "absent" fails OPEN, recreating the automatic retry after a crash."""

    def _no_network(self, monkeypatch):
        _reachable(monkeypatch)
        monkeypatch.setattr(fetch, "_open_no_follow",
                            lambda *a, **k: pytest.fail("a refused state must not reach the network"))

    def _get(self, tmp_path, monkeypatch, url="https://t/a", dest_name="a.bin"):
        return fetch.scoped_get_file(ctx_of(tmp_path), url, tmp_path / dest_name)

    def test_an_ORPHAN_partial_refuses(self, tmp_path, monkeypatch):
        """A crash between the partial write and the receipt write. Whose bytes those are is unprovable."""
        self._no_network(monkeypatch)
        (tmp_path / "a.bin.part").write_bytes(b"half")
        acq, _f, _s = self._get(tmp_path, monkeypatch)
        assert acq.disposition == "orphan-partial" and acq.contacted is False

    def test_a_DAMAGED_receipt_refuses(self, tmp_path, monkeypatch):
        self._no_network(monkeypatch)
        (tmp_path / ("a.bin" + fetch._RECEIPT_SUFFIX)).write_text("{ torn")
        acq, _f, _s = self._get(tmp_path, monkeypatch)
        assert acq.disposition == "receipt-damaged" and acq.contacted is False

    def test_a_receipt_without_an_IDENTITY_refuses(self, tmp_path, monkeypatch):
        self._no_network(monkeypatch)
        (tmp_path / ("a.bin" + fetch._RECEIPT_SUFFIX)).write_text(json.dumps({"url": "https://t/a"}))
        acq, _f, _s = self._get(tmp_path, monkeypatch)
        assert acq.disposition == "receipt-damaged"

    def test_a_receipt_with_a_NON_INTEGER_byte_count_refuses_without_raising(self, tmp_path, monkeypatch):
        """It used to raise, and the caller's `except Exception` counted that as a network attempt."""
        self._no_network(monkeypatch)
        (tmp_path / "a.bin.part").write_bytes(b"half")
        (tmp_path / ("a.bin" + fetch._RECEIPT_SUFFIX)).write_text(json.dumps(
            {"ident": fetch.acquisition_identity("https://t/a"), "bytes": "lots", "url": "https://t/a",
             "method": "GET", "complete": False, "digest": "a" * 64}))
        acq, _f, _s = self._get(tmp_path, monkeypatch)
        assert acq.disposition == "receipt-damaged" and acq.contacted is False

    def test_a_receipt_whose_PARTIAL_is_gone_is_evidence_lost(self, tmp_path, monkeypatch):
        """It reported `replayed-incomplete, bytes=123, partial=None` — a claim about evidence it could
        not show."""
        self._no_network(monkeypatch)
        (tmp_path / ("a.bin" + fetch._RECEIPT_SUFFIX)).write_text(
            receipt(body=b"x" * 123))
        acq, _f, _s = self._get(tmp_path, monkeypatch)
        assert acq.disposition == "evidence-lost" and acq.partial is None

    def test_a_MODIFIED_partial_is_not_replayed_as_intact(self, tmp_path, monkeypatch):
        self._no_network(monkeypatch)
        part = tmp_path / "a.bin.part"
        part.write_bytes(b"half")
        (tmp_path / ("a.bin" + fetch._RECEIPT_SUFFIX)).write_text(
            receipt(body=b"half", digest="0" * 64))
        acq, _f, _s = self._get(tmp_path, monkeypatch)
        assert acq.disposition == "evidence-modified"

    def test_a_symlinked_partial_is_refused(self, tmp_path, monkeypatch):
        self._no_network(monkeypatch)
        real = tmp_path / "elsewhere"; real.write_bytes(b"half")
        (tmp_path / "a.bin.part").symlink_to(real)
        (tmp_path / ("a.bin" + fetch._RECEIPT_SUFFIX)).write_text(receipt(body=b"half"))
        acq, _f, _s = self._get(tmp_path, monkeypatch)
        assert acq.disposition == "evidence-modified"

    def test_an_intact_pair_replays_with_a_verified_digest(self, tmp_path, monkeypatch):
        self._no_network(monkeypatch)
        part = tmp_path / "a.bin.part"; part.write_bytes(b"half")
        (tmp_path / ("a.bin" + fetch._RECEIPT_SUFFIX)).write_text(
            receipt(body=b"half", status=200, final="https://t/final", error="reset"))
        acq, final, status = self._get(tmp_path, monkeypatch)
        assert acq.disposition == "replayed-incomplete" and acq.partial == part
        assert (final, status) == ("https://t/final", 200) and acq.bytes == 4

    def test_a_receipt_write_FAILURE_leaves_a_fail_CLOSED_state(self, tmp_path, monkeypatch):
        """Suppressing it left a partial with no receipt. That is now `orphan-partial`, which refuses —
        and the failure itself is reported rather than swallowed."""
        class _Breaks(_Resp):
            def read(self, n=-1):
                buf = super().read(n)
                if not buf:
                    raise OSError("reset")
                return buf
        _reachable(monkeypatch)
        monkeypatch.setattr(fetch, "_open_no_follow",
                            lambda req, timeout, opener=None: (200, {}, _Breaks(b"half" * 8)))
        monkeypatch.setattr(fetch, "_publish_receipt",
                            lambda *a, **k: "; the acquisition RECEIPT could not be written (disk full)")
        acq, _f, _s = fetch.scoped_get_file(ctx_of(tmp_path), "https://t/a", tmp_path / "a.bin")
        assert "RECEIPT could not be written" in acq.error
        monkeypatch.setattr(fetch, "_open_no_follow",
                            lambda *a, **k: pytest.fail("an unrecorded partial must not be re-requested"))
        again, _f2, _s2 = fetch.scoped_get_file(ctx_of(tmp_path), "https://t/a", tmp_path / "a.bin")
        assert again.disposition == "orphan-partial"


class TestASuccessfulArtifactIsOwnedToo:
    """review#23 (Lumpy): only incomplete acquisitions carried a receipt, so another method, body or
    policy for the same URL could overwrite a completed artifact even though `acquisition_identity()`
    says they are different work."""

    def test_a_DIFFERENT_request_cannot_overwrite_a_completed_artifact(self, tmp_path, monkeypatch):
        _serve(monkeypatch, b"the original body")
        dest = tmp_path / "a.bin"
        acq, _f, _s = fetch.scoped_get_file(ctx_of(tmp_path), "https://t/a", dest)
        assert acq.complete and dest.read_bytes() == b"the original body"
        _reachable(monkeypatch)
        monkeypatch.setattr(fetch, "_open_no_follow",
                            lambda *a, **k: pytest.fail("fetched over another request's artifact"))
        other, _f2, _s2 = fetch.scoped_get_file(ctx_of(tmp_path), "https://t/a", dest,
                                                method="POST", data=b"{}")
        assert other.disposition == "path-collision" and other.contacted is False
        assert dest.read_bytes() == b"the original body", "untouched"

    def test_the_SAME_request_replays_the_artifact_instead_of_re_fetching(self, tmp_path, monkeypatch):
        calls: list = []
        _serve(monkeypatch, b"body", calls=calls)
        dest = tmp_path / "a.bin"
        for _ in range(3):
            acq, _f, _s = fetch.scoped_get_file(ctx_of(tmp_path), "https://t/a", dest)
        assert len(calls) == 1, calls
        assert acq.complete and acq.disposition == "replayed-complete" and acq.contacted is False
        assert acq.path == dest

    def test_a_completed_artifact_MODIFIED_under_us_refuses(self, tmp_path, monkeypatch):
        _serve(monkeypatch, b"body")
        dest = tmp_path / "a.bin"
        fetch.scoped_get_file(ctx_of(tmp_path), "https://t/a", dest)
        dest.write_bytes(b"tampered")
        _reachable(monkeypatch)
        monkeypatch.setattr(fetch, "_open_no_follow",
                            lambda *a, **k: pytest.fail("silently re-fetched over modified evidence"))
        acq, _f, _s = fetch.scoped_get_file(ctx_of(tmp_path), "https://t/a", dest)
        assert acq.disposition == "evidence-modified"

    def test_a_discarded_probe_response_takes_its_receipt_with_it(self, tmp_path, monkeypatch):
        """The SSTI lane deletes non-hit responses. Leaving the receipt behind would make the next call
        refuse with `evidence-lost` over a file we deleted on purpose."""
        _serve(monkeypatch, b"nothing evaluated")
        ctx, _ = _ctx(tmp_path)
        evidence.probe_ssti(ctx, ["https://t/p?a=1"])
        left = list((tmp_path / "params" / "ssti").glob("*"))
        assert not left, left


class TestStructuralProvenanceTravelsWithPROMOTEDFindings:
    def test_a_promoted_HS256_key_reports_its_PATH_not_a_searched_line(self, tmp_path, monkeypatch):
        """The same value under `"name"` on line 2 and the promoted `"key"` on line 5 sent an operator
        to line 2 — a different field entirely."""
        body = (b'{\n "name": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",\n "auth": {\n  "jwt": {\n'
                b'   "key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "alg": "HS256"\n  }\n }\n}')
        _serve(monkeypatch, body)
        ctx, added = _ctx(tmp_path)
        evidence.fetch_and_extract(ctx, "https://t/a.json", source="exposed-fetch", subdir="exposed")
        sec = [r for k, r in added if k == "secret"][0]
        assert sec["json_path"] == "auth.jwt.key" and "line" not in sec, sec

    def test_a_signing_OBSERVATION_carries_its_path_too(self, tmp_path, monkeypatch):
        _serve(monkeypatch, b'{"jwks": {"kid": "k1", "key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}')
        ctx, added = _ctx(tmp_path)
        evidence.fetch_and_extract(ctx, "https://t/a.json", source="exposed-fetch", subdir="exposed")
        obs = [r for k, r in added if k == "review" and r.get("klass") == "signing-key"][0]
        assert obs["json_path"] == "jwks.key" and "line" not in obs, obs

    def test_the_path_is_the_WHOLE_chain_including_list_indices(self):
        doc = {"a": {"b": [{"c": {"key": "x" * 30, "alg": "HS256"}}]}}
        got = list(evidence._json_key_findings(doc))
        assert got and got[0][2] == "a.b.[0].c.key", got

    def test_a_TEXT_matched_finding_still_reports_its_line(self, tmp_path, monkeypatch):
        """Only structural findings lose the line — a regex match knows exactly where it matched."""
        _serve(monkeypatch, b"one\ntwo\nAWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
        ctx, added = _ctx(tmp_path)
        evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch", subdir="exposed")
        sec = [r for k, r in added if k == "secret"][0]
        assert sec["line"] == 3 and "json_path" not in sec, sec


class TestOwnershipIsTHREEFilesNotTwo:
    """review#24 (Lumpy). `_reconcile` looked at the receipt and the partial; a completed artifact with
    neither was read as a clean slate and OVERWRITTEN by a fresh request."""

    def test_an_existing_artifact_with_no_receipt_is_not_overwritten(self, tmp_path, monkeypatch):
        dest = tmp_path / "a.bin"
        dest.write_bytes(b"PAID-EVIDENCE")
        _reachable(monkeypatch)
        monkeypatch.setattr(fetch, "_open_no_follow",
                            lambda *a, **k: pytest.fail("fetched over evidence already on disk"))
        acq, _f, _s = fetch.scoped_get_file(ctx_of(tmp_path), "https://t/a", dest)
        assert acq.disposition == "orphan-complete" and acq.contacted is False
        assert dest.read_bytes() == b"PAID-EVIDENCE"

    def test_an_unrecorded_success_SAYS_it_is_unrecorded(self, tmp_path, monkeypatch):
        _serve(monkeypatch, b"body")
        monkeypatch.setattr(fetch, "_publish_receipt", lambda *a, **k: "; RECEIPT could not be written")
        acq, _f, _s = fetch.scoped_get_file(ctx_of(tmp_path), "https://t/a", tmp_path / "a.bin")
        assert acq.complete is True, "the body IS whole; lying about that would be worse"
        assert acq.disposition == "complete-unowned" and "RECEIPT could not be written" in acq.error

    def test_an_EMPTY_published_body_is_owned_the_same_way(self, tmp_path, monkeypatch):
        """The redirect-loop path publishes an empty artifact through its own return, so it needs the
        same ownership treatment — otherwise one branch records nothing and the next call refuses a
        file this branch wrote."""
        _reachable(monkeypatch)
        monkeypatch.setattr(fetch, "_open_no_follow",
                            lambda req, timeout, opener=None: (302, {"Location": "https://t/a"}, None))
        dest = tmp_path / "loop.bin"
        acq, _f, _s = fetch.scoped_get_file(ctx_of(tmp_path), "https://t/a", dest)
        assert acq.complete and acq.bytes == 0 and acq.disposition == "complete"
        rec = json.loads((tmp_path / ("loop.bin" + fetch._RECEIPT_SUFFIX)).read_text())
        assert rec["complete"] is True and rec["bytes"] == 0 and len(rec["digest"]) == 64
        # …and with the receipt write failing, it says so rather than looking recorded
        monkeypatch.setattr(fetch, "_publish_receipt", lambda *a, **k: "; RECEIPT could not be written")
        d2 = tmp_path / "loop2.bin"
        acq2, _f2, _s2 = fetch.scoped_get_file(ctx_of(tmp_path), "https://t/b", d2)
        assert acq2.complete and acq2.disposition == "complete-unowned"

    def test_the_lane_carries_that_note_to_its_caller(self, tmp_path, monkeypatch):
        _serve(monkeypatch, b"body")
        monkeypatch.setattr(fetch, "_publish_receipt", lambda *a, **k: "; RECEIPT could not be written")
        ctx, _ = _ctx(tmp_path)
        res = evidence.fetch_and_extract(ctx, "https://t/x", source="exposed-fetch", subdir="exposed")
        assert res["ok"] and res["disposition"] == "complete-unowned"
        assert "RECEIPT could not be written" in res["reason"]


class TestTheReceiptSchemaIsMANDATORY:
    """An optional digest is not an integrity check."""

    def _refused(self, tmp_path, monkeypatch, doc, *, artifact=b"body"):
        _reachable(monkeypatch)
        dest = tmp_path / "a.bin"
        dest.write_bytes(artifact)
        (tmp_path / ("a.bin" + fetch._RECEIPT_SUFFIX)).write_text(json.dumps(doc))
        monkeypatch.setattr(fetch, "_open_no_follow",
                            lambda *a, **k: pytest.fail("acted on an unverifiable receipt"))
        return fetch.scoped_get_file(ctx_of(tmp_path), "https://t/a", dest)[0]

    def test_a_receipt_without_a_digest_is_damaged(self, tmp_path, monkeypatch):
        """The reproduction: identity + complete + byte count and no digest replayed same-length
        MODIFIED content as if it were the evidence we acquired."""
        acq = self._refused(tmp_path, monkeypatch,
                            {"ident": fetch.acquisition_identity("https://t/a"), "complete": True,
                             "bytes": 4, "url": "https://t/a", "method": "GET"})
        assert acq.disposition == "receipt-damaged" and "digest" in acq.error

    def test_a_short_or_non_hex_digest_is_damaged(self, tmp_path, monkeypatch):
        for bad in ("abc", "z" * 64, "A" * 64):
            acq = self._refused(tmp_path, monkeypatch,
                                {"ident": fetch.acquisition_identity("https://t/a"), "complete": True,
                                 "bytes": 4, "digest": bad, "url": "https://t/a", "method": "GET"})
            assert acq.disposition == "receipt-damaged", bad

    def test_complete_must_be_an_actual_BOOL(self, tmp_path, monkeypatch):
        for truthy in (1, "yes", [1]):
            acq = self._refused(tmp_path, monkeypatch,
                                {"ident": fetch.acquisition_identity("https://t/a"), "url": "https://t/a",
                                 "method": "GET", "complete": truthy, "bytes": 4, "digest": "a" * 64})
            assert acq.disposition == "receipt-damaged", truthy

    def test_an_identity_that_is_not_a_digest_is_damaged(self, tmp_path, monkeypatch):
        acq = self._refused(tmp_path, monkeypatch,
                            {"ident": "someone-elses", "complete": True, "bytes": 4,
                             "url": "https://t/a", "method": "GET", "digest": "a" * 64})
        assert acq.disposition == "receipt-damaged"

    def test_same_length_MODIFIED_content_is_caught(self, tmp_path, monkeypatch):
        _serve(monkeypatch, b"body")
        dest = tmp_path / "a.bin"
        fetch.scoped_get_file(ctx_of(tmp_path), "https://t/a", dest)
        dest.write_bytes(b"ydob")                      # same length, different bytes
        _reachable(monkeypatch)
        monkeypatch.setattr(fetch, "_open_no_follow",
                            lambda *a, **k: pytest.fail("re-fetched over modified evidence"))
        acq, _f, _s = fetch.scoped_get_file(ctx_of(tmp_path), "https://t/a", dest)
        assert acq.disposition == "evidence-modified"


class TestCompleteEvidenceGetsTheSameFileChecks:
    def test_a_symlinked_COMPLETE_artifact_is_refused(self, tmp_path, monkeypatch):
        """The partial branch had `lstat` + `S_ISREG`; the complete branch did not, so a symlink to
        matching external bytes replayed as our own acquisition."""
        import hashlib as _h
        external = tmp_path / "elsewhere"; external.write_bytes(b"body")
        dest = tmp_path / "a.bin"
        dest.symlink_to(external)
        (tmp_path / ("a.bin" + fetch._RECEIPT_SUFFIX)).write_text(json.dumps(
            {"ident": fetch.acquisition_identity("https://t/a"), "complete": True, "bytes": 4,
             "digest": _h.sha256(b"body").hexdigest(), "url": "https://t/a", "method": "GET"}))
        _reachable(monkeypatch)
        monkeypatch.setattr(fetch, "_open_no_follow",
                            lambda *a, **k: pytest.fail("acted on a symlinked artifact"))
        acq, _f, _s = fetch.scoped_get_file(ctx_of(tmp_path), "https://t/a", dest)
        assert acq.disposition == "evidence-modified"

    def test_a_verified_replay_KEEPS_the_digest_it_checked(self, tmp_path, monkeypatch):
        """It was hardcoded to "", so replayed evidence had weaker provenance than the original."""
        import hashlib as _h
        _serve(monkeypatch, b"body")
        dest = tmp_path / "a.bin"
        first, _f, _s = fetch.scoped_get_file(ctx_of(tmp_path), "https://t/a", dest)
        again, _f2, _s2 = fetch.scoped_get_file(ctx_of(tmp_path), "https://t/a", dest)
        assert again.sha256 == first.sha256 == _h.sha256(b"body").hexdigest()
        assert again.disposition == "replayed-complete"


class TestUninspectableOwnershipIsNotContact:
    def test_an_unreadable_state_directory_refuses_without_claiming_an_attempt(self, tmp_path,
                                                                              monkeypatch):
        """`exists()`/`stat()`/`_digest_file()` errors escaped as ordinary exceptions, and the lane's
        blanket `except` reported `attempted=True` for a run that never touched the target."""
        _reachable(monkeypatch)
        monkeypatch.setattr(fetch, "_open_no_follow",
                            lambda *a, **k: pytest.fail("contacted the target"))
        real_lstat = fetch.Path.lstat

        def _boom(self, *a, **k):
            if self.name.startswith("t-"):
                raise PermissionError("permission denied")
            return real_lstat(self, *a, **k)
        monkeypatch.setattr(fetch.Path, "lstat", _boom)
        ctx, _ = _ctx(tmp_path)
        res = evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch", subdir="exposed")
        assert res["attempted"] is False, "nothing was requested"
        assert res["disposition"] == "ownership-uninspectable"


class TestSigningContextSurvivesAnArray:
    def test_a_signing_config_inside_a_LIST_still_classifies(self):
        assert evidence.mine('{"Jwt": {"key": "' + "a" * 30 + '"}}',
                             source_path="/x/a.json")[0][0] == "signing-key"
        got = evidence.mine('{"Jwt": [{"key": "' + "a" * 30 + '"}]}', source_path="/x/a.json")
        assert got and got[0][0] == "signing-key", got
        assert got[0][2] == "Jwt.[0].key", "and the path still names the index"

    def test_a_non_signing_ancestor_still_does_not_classify(self):
        got = evidence.mine('{"cache": [{"key": "' + "a" * 30 + '"}]}', source_path="/x/a.json")
        assert not got, got


class TestUnrecordedOwnershipReachesTheOUTPUT:
    """review#25 (Lumpy): `complete-unowned` lived only in a result dict the caller discarded. The
    evidence is readable and `ok` stays True — but the run cannot prove it owns it and the path is
    refused from here on, and that belongs in the verdict, not in a variable."""

    def _unowned(self, tmp_path, monkeypatch):
        events.reset(); events.configure(tmp_path)
        _serve(monkeypatch, b"AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
        monkeypatch.setattr(fetch, "_publish_receipt", lambda *a, **k: "; RECEIPT could not be written")
        ctx, added = _ctx(tmp_path)
        res = evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch",
                                         subdir="exposed")
        return res, added

    def test_the_evidence_is_still_readable_and_still_mined(self, tmp_path, monkeypatch):
        res, added = self._unowned(tmp_path, monkeypatch)
        assert res["ok"] is True and res["secrets"] == 1
        assert [r for k, r in added if k == "secret"], "the finding is not withheld"

    def test_a_GATING_coverage_record_says_the_ownership_is_unrecorded(self, tmp_path, monkeypatch):
        self._unowned(tmp_path, monkeypatch)
        evs = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()]
        cov = [e for e in evs if e.get("measure") == "evidence_durability"]
        assert cov and cov[-1]["omitted"] == 1 and cov[-1]["kind"] not in ("sample", "provider")
        assert "RECEIPT could not be written" in cov[-1]["reason"]
        events.reset()

    def test_and_an_operator_row_says_what_to_do_about_it(self, tmp_path, monkeypatch):
        _res, added = self._unowned(tmp_path, monkeypatch)
        row = [r for k, r in added if k == evidence.OWNERSHIP_ENTITY and r.get("klass") == "unowned-artifact"]
        assert row and "REFUSED rather than re-fetched" in row[0]["note"], added
        events.reset()


class TestARefusalIsNotABrokenTransport:
    def test_the_row_does_not_claim_a_partial_that_does_not_exist(self, tmp_path, monkeypatch):
        """`orphan-complete` became `error="incomplete", partial=None`, and the operator was told the
        partial body was KEPT at `None`."""
        events.reset(); events.configure(tmp_path)
        _reachable(monkeypatch)
        ctx, added = _ctx(tmp_path)
        dest = ctx.run.raw_path("params", "exposed", "t-" + evidence._artifact_id("https://t/.env"))
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"PAID-EVIDENCE")
        self.dest = dest
        monkeypatch.setattr(fetch, "_open_no_follow",
                            lambda *a, **k: pytest.fail("a refusal must not reach the network"))
        evidence.fetch_exposed(ctx, ["https://t/.env"])
        row = [r for k, r in added if k == evidence.OWNERSHIP_ENTITY and r.get("klass") == "acquisition-refused"]
        assert row, added
        assert row[0]["disposition"] == "orphan-complete"
        assert "Nothing was requested" in row[0]["note"]
        assert "no partial body for this one" in row[0]["note"]
        # …but the file that CAUSED the refusal is named: it is what the operator has to resolve
        assert row[0]["state_paths"] and row[0]["state_paths"][0].endswith(dest.name)
        assert row[0]["raw_ref"] == row[0]["state_paths"][0]
        assert len([r for k, r in added if k == "review" and "INCOMPLETE" in r.get("note", "")]) == 0, \
            "one refusal, one row — the lane must not restate what `acquire` already published"
        events.reset()

    def test_it_is_counted_under_OWNERSHIP_not_under_the_timeout_path(self, tmp_path, monkeypatch):
        events.reset(); events.configure(tmp_path)
        _reachable(monkeypatch)
        ctx, _ = _ctx(tmp_path)
        dest = ctx.run.raw_path("params", "exposed", "t-" + evidence._artifact_id("https://t/.env"))
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"PAID-EVIDENCE")
        monkeypatch.setattr(fetch, "_open_no_follow", lambda *a, **k: pytest.fail("contacted"))
        evidence.fetch_exposed(ctx, ["https://t/.env"])
        evs = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()]
        own = [e for e in evs if e.get("measure") == "evidence_ownership"]
        assert own and own[-1]["omitted"] == 1 and own[-1]["kind"] == "ownership"
        assert "nothing was requested" in own[-1]["reason"]
        # DISJOINT: the same refusal must not also be counted as a resource we asked for and could not read
        fetches = [e for e in evs if e.get("measure") == "evidence_fetches"]
        assert fetches and fetches[-1]["eligible"] == 0 and fetches[-1]["omitted"] == 0, fetches[-1]
        events.reset()

    def test_a_real_transport_break_still_reports_its_partial(self, tmp_path, monkeypatch):
        """The other side of the split, so neither disposition borrows the other's words."""
        class _Breaks(_Resp):
            def read(self, n=-1):
                buf = super().read(n)
                if not buf:
                    raise OSError("reset")
                return buf
        _reachable(monkeypatch)
        monkeypatch.setattr(fetch, "_open_no_follow",
                            lambda req, timeout, opener=None: (200, {}, _Breaks(b"AWS_KEY=x" * 512)))
        ctx, added = _ctx(tmp_path)
        evidence.fetch_exposed(ctx, ["https://t/.env"])
        row = [r for k, r in added if k == "review" and "INCOMPLETE" in r.get("note", "")][0]
        assert "the partial body is KEPT at" in row["note"] and row["raw_ref"]


class TestContradictoryStatesAreRefused:
    def test_a_complete_receipt_with_an_unexplained_partial(self, tmp_path, monkeypatch):
        _serve(monkeypatch, b"body")
        dest = tmp_path / "a.bin"
        fetch.scoped_get_file(ctx_of(tmp_path), "https://t/a", dest)
        (tmp_path / "a.bin.part").write_bytes(b"where did this come from")
        _reachable(monkeypatch)
        monkeypatch.setattr(fetch, "_open_no_follow", lambda *a, **k: pytest.fail("contacted"))
        acq, _f, _s = fetch.scoped_get_file(ctx_of(tmp_path), "https://t/a", dest)
        assert acq.disposition == "ownership-conflict" and acq.contacted is False

    def test_a_partial_receipt_with_an_unexplained_complete_artifact(self, tmp_path, monkeypatch):
        _reachable(monkeypatch)
        (tmp_path / "a.bin.part").write_bytes(b"half")
        (tmp_path / "a.bin").write_bytes(b"whole?")
        (tmp_path / ("a.bin" + fetch._RECEIPT_SUFFIX)).write_text(receipt(body=b"half"))
        monkeypatch.setattr(fetch, "_open_no_follow", lambda *a, **k: pytest.fail("contacted"))
        acq, _f, _s = fetch.scoped_get_file(ctx_of(tmp_path), "https://t/a", tmp_path / "a.bin")
        assert acq.disposition == "ownership-conflict"


class TestTheRECEIPTIsAlsoEvidence:
    def test_a_symlinked_receipt_is_refused(self, tmp_path, monkeypatch):
        """`_exists` used `lstat`, but the read went through `read_text`, which follows. A receipt
        pointed at an external valid document replayed as our own ownership record."""
        _reachable(monkeypatch)
        elsewhere = tmp_path / "elsewhere.json"
        elsewhere.write_text(receipt(body=b"body", complete=True))
        dest = tmp_path / "a.bin"
        dest.write_bytes(b"body")
        (tmp_path / ("a.bin" + fetch._RECEIPT_SUFFIX)).symlink_to(elsewhere)
        monkeypatch.setattr(fetch, "_open_no_follow", lambda *a, **k: pytest.fail("contacted"))
        acq, _f, _s = fetch.scoped_get_file(ctx_of(tmp_path), "https://t/a", dest)
        assert acq.disposition == "evidence-modified" and "symlink" in acq.error


    def test_a_receipt_that_is_a_DIRECTORY_is_refused(self, tmp_path, monkeypatch):
        """O_NOFOLLOW handles a symlink; everything else that is not a regular file is caught by the
        `S_ISREG` check behind it."""
        _reachable(monkeypatch)
        dest = tmp_path / "a.bin"; dest.write_bytes(b"body")
        (tmp_path / ("a.bin" + fetch._RECEIPT_SUFFIX)).mkdir()
        monkeypatch.setattr(fetch, "_open_no_follow", lambda *a, **k: pytest.fail("contacted"))
        acq, _f, _s = fetch.scoped_get_file(ctx_of(tmp_path), "https://t/a", dest)
        assert acq.disposition == "evidence-modified" and "not a regular file" in acq.error

    def test_a_FIFO_receipt_does_not_HANG_the_scan(self, tmp_path, monkeypatch):
        """Opening a named pipe read-only blocks until a writer appears. A run must not stop forever on
        one someone left in the run tree."""
        import os as _os
        _reachable(monkeypatch)
        dest = tmp_path / "a.bin"; dest.write_bytes(b"body")
        _os.mkfifo(tmp_path / ("a.bin" + fetch._RECEIPT_SUFFIX))
        monkeypatch.setattr(fetch, "_open_no_follow", lambda *a, **k: pytest.fail("contacted"))
        acq, _f, _s = fetch.scoped_get_file(ctx_of(tmp_path), "https://t/a", dest)
        assert acq.disposition == "evidence-modified"


class TestEVERYConsumedReceiptFieldIsTyped:
    def _refuse(self, tmp_path, monkeypatch, **over):
        _reachable(monkeypatch)
        dest = tmp_path / "a.bin"; dest.write_bytes(b"body")
        doc = json.loads(receipt(body=b"body", complete=True))
        doc.update(over)
        (tmp_path / ("a.bin" + fetch._RECEIPT_SUFFIX)).write_text(json.dumps(doc))
        monkeypatch.setattr(fetch, "_open_no_follow", lambda *a, **k: pytest.fail("contacted"))
        return fetch.scoped_get_file(ctx_of(tmp_path), "https://t/a", dest)[0]

    def test_a_non_string_final_is_damaged_not_a_TypeError_later(self, tmp_path, monkeypatch):
        """It passed reconciliation and then raised `TypeError: unhashable type: 'list'` in the middle
        of interpretation — a receipt field crashing a lane three layers away."""
        acq = self._refuse(tmp_path, monkeypatch, final=["not-a-url"])
        assert acq.disposition == "receipt-damaged" and "final" in acq.error

    def test_a_non_integer_status_is_damaged(self, tmp_path, monkeypatch):
        for bad in ("200", 999, True, [200]):
            acq = self._refuse(tmp_path, monkeypatch, status=bad)
            assert acq.disposition == "receipt-damaged", bad

    def test_url_and_method_must_be_strings(self, tmp_path, monkeypatch):
        assert self._refuse(tmp_path, monkeypatch, url=None).disposition == "receipt-damaged"
        assert self._refuse(tmp_path, monkeypatch, method=7).disposition == "receipt-damaged"

    def test_a_non_string_error_is_damaged(self, tmp_path, monkeypatch):
        assert self._refuse(tmp_path, monkeypatch, error={"a": 1}).disposition == "receipt-damaged"

    def test_the_optional_fields_may_be_ABSENT(self, tmp_path, monkeypatch):
        """Absent is fine; wrong type is not. A complete acquisition has no `error`."""
        _serve(monkeypatch, b"body")
        dest = tmp_path / "a.bin"
        fetch.scoped_get_file(ctx_of(tmp_path), "https://t/a", dest)
        rec = json.loads((tmp_path / ("a.bin" + fetch._RECEIPT_SUFFIX)).read_text())
        assert "error" not in rec
        again, _f, _s = fetch.scoped_get_file(ctx_of(tmp_path), "https://t/a", dest)
        assert again.disposition == "replayed-complete"


class TestEVERYLaneReportsItsAcquisitionState:
    """review#26 (Lumpy): the durability and refusal reporting were wired into `fetch_and_extract`
    only, so the six lanes that called the primitive directly kept the old behaviour. Per-lane wiring
    of a SHARED mechanism is six chances to miss one — this drives every production entry point."""

    LANES = ("graphql", "openapi", "actuator-index", "deep", "framework", "exposed")

    @staticmethod
    def _run(lane, ctx):
        if lane == "graphql":
            return evidence.probe_graphql(ctx, ["https://t/graphql"])
        if lane == "openapi":
            return evidence.parse_openapi(ctx, ["https://t/openapi.json"])
        if lane == "actuator-index":
            return evidence._actuator_index_links(ctx, "https://t/actuator", "t")
        if lane == "deep":
            return evidence._deep_download(ctx, "https://t/actuator/heapdump", "t", "heapdump")
        if lane == "framework":
            return evidence.probe_framework_endpoints(
                ctx, [{"url": "https://t/debug", "framework": "werkzeug", "note": "console"}])
        return evidence.fetch_exposed(ctx, ["https://t/.env"])

    @pytest.mark.parametrize("lane", LANES)
    def test_an_unrecorded_receipt_is_reported_by_every_lane(self, lane, tmp_path, monkeypatch):
        events.reset(); events.configure(tmp_path)
        _serve(monkeypatch, b'{"data": {"__schema": {}}, "paths": {}, "_links": {}}')
        monkeypatch.setattr(fetch, "_publish_receipt", lambda *a, **k: "; RECEIPT could not be written")
        ctx, added = _ctx(tmp_path)
        ctx.profile = SimpleNamespace(http_rl=0, deep_evidence=True)
        self._run(lane, ctx)
        evs = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()]
        cov = [e for e in evs if e.get("measure") == "evidence_durability"]
        assert cov, f"{lane} reported no durability gap: {evs}"
        assert cov[-1]["kind"] == "ownership" and cov[-1]["omitted"] == 1
        assert [r for k, r in added if k == evidence.OWNERSHIP_ENTITY and r.get("klass") == "unowned-artifact"], lane
        events.reset()

    @pytest.mark.parametrize("lane", LANES)
    def test_an_ownership_REFUSAL_is_reported_by_every_lane(self, lane, tmp_path, monkeypatch):
        """An orphan artifact: nothing is requested, and no lane may describe that as a transport
        failure or an incomplete document."""
        events.reset(); events.configure(tmp_path)
        _reachable(monkeypatch)
        ctx, added = _ctx(tmp_path)
        ctx.profile = SimpleNamespace(http_rl=0, deep_evidence=True)
        for sub, name in (("graphql", f"t-{evidence._artifact_id('https://t/graphql')}.json"),
                          ("openapi", f"t-{evidence._artifact_id('https://t/openapi.json')}.json"),
                          ("actuator", f"t-index-{evidence._artifact_id('https://t/actuator')}.json"),
                          ("actuator", f"t-heapdump-"
                                       f"{evidence._artifact_id('https://t/actuator/heapdump')}.bin"),
                          ("framework", f"t-{evidence._artifact_id('https://t/debug')}"),
                          ("exposed", f"t-{evidence._artifact_id('https://t/.env')}")):
            d = ctx.run.raw_path("params", sub, name)
            d.parent.mkdir(parents=True, exist_ok=True)
            d.write_bytes(b"EVIDENCE ALREADY HERE")
        monkeypatch.setattr(fetch, "_open_no_follow",
                            lambda *a, **k: pytest.fail(f"{lane} contacted the target despite a refusal"))
        self._run(lane, ctx)
        evs = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()]
        own = [e for e in evs if e.get("measure") == "evidence_ownership"]
        assert own, f"{lane} reported no ownership gap: {evs}"
        assert own[-1]["kind"] == "ownership" and "nothing was requested" in own[-1]["reason"]
        rows = [r for k, r in added if k == evidence.OWNERSHIP_ENTITY and r.get("klass") == "acquisition-refused"]
        assert rows and rows[0]["disposition"] == "orphan-complete", (lane, added)
        # …and the lane adds nothing of its own: no transport story, no "exposed", no document row
        assert [r["klass"] for k, r in added if k in ("review", evidence.OWNERSHIP_ENTITY)] == ["acquisition-refused"], (lane, added)
        events.reset()

    @pytest.mark.parametrize("lane", LANES)
    def test_a_REPLAYED_INCOMPLETE_is_not_a_transport_break_either(self, lane, tmp_path, monkeypatch):
        """The refusal that still carries a 200: lanes branching on status before completeness reach
        their transport handling with it, so `orphan-complete` (status 0) alone does not prove them."""
        events.reset(); events.configure(tmp_path)
        _reachable(monkeypatch)
        ctx, added = _ctx(tmp_path)
        ctx.profile = SimpleNamespace(http_rl=0, deep_evidence=True)
        body = b"half a body"
        for sub, name in (("graphql", f"t-{evidence._artifact_id('https://t/graphql')}.json"),
                          ("openapi", f"t-{evidence._artifact_id('https://t/openapi.json')}.json"),
                          ("actuator", f"t-index-{evidence._artifact_id('https://t/actuator')}.json"),
                          ("actuator", f"t-heapdump-"
                                       f"{evidence._artifact_id('https://t/actuator/heapdump')}.bin"),
                          ("framework", f"t-{evidence._artifact_id('https://t/debug')}"),
                          ("exposed", f"t-{evidence._artifact_id('https://t/.env')}")):
            d = ctx.run.raw_path("params", sub, name)
            d.parent.mkdir(parents=True, exist_ok=True)
            url = {"graphql": "https://t/graphql", "openapi": "https://t/openapi.json",
                   "actuator": "https://t/actuator", "framework": "https://t/debug",
                   "exposed": "https://t/.env"}[sub]
            if name.startswith("t-heapdump"):
                url = "https://t/actuator/heapdump"
            kw = {"policy": "graphql-introspection", "method": "POST"} if sub == "graphql" else {}
            import hashlib as _h
            d.with_name(d.name + ".part").write_bytes(body)
            d.with_name(d.name + fetch._RECEIPT_SUFFIX).write_text(json.dumps(
                {"ident": fetch.acquisition_identity(url, data=(evidence._GQL_INTROSPECTION.encode()
                                                                if sub == "graphql" else None), **kw),
                 "url": url, "method": kw.get("method", "GET"), "complete": False, "bytes": len(body),
                 "digest": _h.sha256(body).hexdigest(), "status": 200, "error": "reset"}))
        monkeypatch.setattr(fetch, "_open_no_follow",
                            lambda *a, **k: pytest.fail(f"{lane} contacted the target despite a refusal"))
        self._run(lane, ctx)
        # assert on the ROW KIND, not on a word in free text: `tmp_path` is named after the test, so
        # a substring check for "INCOMPLETE" matched the temp directory in the note and failed on a
        # correct result. The klass is the fact; the prose is not.
        # the invariant, stated as a WHOLE: on a refusal the lane adds NOTHING of its own. Matching a
        # phrase in free text is what let two lanes keep their old transport wording with different
        # words (and `tmp_path` carries the test name, so substrings find themselves).
        rows = [r for k, r in added if k in ("review", evidence.OWNERSHIP_ENTITY)]
        assert [r["klass"] for r in rows] == ["acquisition-refused"], f"{lane}: {rows}"
        events.reset()


class TestTheCoverageCAUSEIsHonest:
    def test_ownership_failures_are_not_labelled_as_a_CAP(self, tmp_path, monkeypatch):
        """`cap` means a hard ceiling truncated eligible input. A receipt that could not be written is
        an internal storage failure — it gates either way, but the operator-facing cause was false."""
        events.reset(); events.configure(tmp_path)
        _serve(monkeypatch, b"body")
        monkeypatch.setattr(fetch, "_publish_receipt", lambda *a, **k: "; RECEIPT could not be written")
        ctx, _ = _ctx(tmp_path)
        evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch", subdir="exposed")
        cov = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()
               if json.loads(x).get("measure") == "evidence_durability"][-1]
        assert cov["kind"] == events.COVERAGE_OWNERSHIP != events.COVERAGE_CAP
        assert cov["kind"] not in ("sample", "provider"), "and it still GATES"
        events.reset()

    def test_a_new_refusal_disposition_needs_no_LIST_update(self, tmp_path, monkeypatch):
        """Classification reads `contacted`, which the result already carries. A hand-maintained set of
        disposition names would silently turn a newly added refusal back into 'incomplete transport'."""
        _reachable(monkeypatch)
        monkeypatch.setattr(fetch, "_reconcile", lambda *a, **k: (_ for _ in ()).throw(
            fetch.AcquisitionRefused("some-future-disposition", "a state we invented after the fact")))
        monkeypatch.setattr(fetch, "_open_no_follow", lambda *a, **k: pytest.fail("contacted"))
        ctx, added = _ctx(tmp_path)
        res = evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch", subdir="exposed")
        assert res["error"] == "refused" and res["attempted"] is False
        assert [r for k, r in added if k == evidence.OWNERSHIP_ENTITY and r.get("klass") == "acquisition-refused"]


class TestTheRECEIPTWriteCannotBeHijacked:
    def test_a_planted_temp_path_cannot_be_followed(self, tmp_path, monkeypatch):
        """The temp name was `<receipt>.tmp` and written with `write_text`, which follows a symlink:
        planting it made Quarry overwrite an external file, move the symlink into place, and report
        success — claiming ownership it did not have."""
        outside = tmp_path / "outside.txt"
        outside.write_text("DO NOT TOUCH")
        dest = tmp_path / "a.bin"
        (tmp_path / ("a.bin" + fetch._RECEIPT_SUFFIX + ".tmp")).symlink_to(outside)
        _serve(monkeypatch, b"body")
        acq, _f, _s = fetch.scoped_get_file(ctx_of(tmp_path), "https://t/a", dest)
        assert outside.read_text() == "DO NOT TOUCH", "an external file was overwritten"
        assert acq.complete and acq.disposition == "complete"
        rec = tmp_path / ("a.bin" + fetch._RECEIPT_SUFFIX)
        assert rec.is_file() and not rec.is_symlink(), "the receipt is a real file, not a planted link"

    def test_the_temp_name_is_unique_and_the_flags_are_SAFE(self, tmp_path, monkeypatch):
        """Asserted AFTER the calls, never inside the patched `open`: `_publish_receipt` swallows
        exceptions into its failure text, so an assertion raised in there would be reported as a
        receipt-write failure and the test would pass while the flags were wrong."""
        seen = []
        real_open = fetch.os.open

        def _watch(path, flags, *a, **k):
            if str(path).endswith(".tmp"):
                seen.append((str(path), flags))
            return real_open(path, flags, *a, **k)
        monkeypatch.setattr(fetch.os, "open", _watch)
        _serve(monkeypatch, b"body")
        for i in range(3):
            fetch.scoped_get_file(ctx_of(tmp_path), f"https://t/{i}", tmp_path / f"{i}.bin")
        names = [n for n, _f in seen]
        assert len(names) == len(set(names)) == 3, seen
        for n, flags in seen:
            assert flags & fetch.os.O_EXCL, f"{n} can be pre-planted"
            assert flags & fetch.os.O_NOFOLLOW, f"{n} would follow a symlink"


class TestTheActuatorSUBPATHSRefuseToo:
    """The index and the sensitive sub-paths are separate acquisitions. Driving `_actuator_index_links`
    alone never reaches the loop that probes `/actuator/env` — so it kept the old handling, and a
    refused sub-path was reported as an EXPOSED endpoint."""

    def _plant(self, ctx, url, sub, name):
        d = ctx.run.raw_path("params", sub, name)
        d.parent.mkdir(parents=True, exist_ok=True)
        d.write_bytes(b"EVIDENCE ALREADY HERE")
        return d

    def test_a_refused_subpath_is_not_reported_as_exposed(self, tmp_path, monkeypatch):
        events.reset(); events.configure(tmp_path)
        # the index answers over the network; only the sub-path already has an artifact on disk
        _serve(monkeypatch, b'{"_links": {"env": {"href": "x"}}}')
        ctx, added = _ctx(tmp_path)
        monkeypatch.setattr(evidence, "ACTUATOR_SENSITIVE", ("env",))
        self._plant(ctx, "https://t/actuator/env", "actuator",
                    f"t-env-{evidence._artifact_id('https://t/actuator/env')}")
        evidence.probe_actuator(ctx, ["https://t/actuator"])
        base = [r for k, r in added if k == "review" and str(r.get("id", "")).startswith("actuator:")]
        assert base and "benign" in base[0]["note"], base
        assert "env" not in base[0]["note"], "a refusal is not evidence that the endpoint is exposed"
        refused = [r for k, r in added if k == evidence.OWNERSHIP_ENTITY and r.get("klass") == "acquisition-refused"]
        assert refused and refused[0]["disposition"] == "orphan-complete", added
        evs = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()]
        assert [e for e in evs if e.get("measure") == "evidence_ownership"], evs
        events.reset()

    def test_a_REPLAYED_INCOMPLETE_subpath_is_not_reported_as_exposed(self, tmp_path, monkeypatch):
        """The refusal that carries a real 200. `orphan-complete` alone does not prove this branch —
        it has no status, so the lane's `status != 200` check hides the missing guard."""
        import hashlib as _h
        events.reset(); events.configure(tmp_path)
        _serve(monkeypatch, b'{"_links": {"env": {"href": "x"}}}')
        ctx, added = _ctx(tmp_path)
        monkeypatch.setattr(evidence, "ACTUATOR_SENSITIVE", ("env",))
        url = "https://t/actuator/env"
        d = ctx.run.raw_path("params", "actuator", f"t-env-{evidence._artifact_id(url)}")
        d.parent.mkdir(parents=True, exist_ok=True)
        body = b"DB_PASSWORD=hunter2super\n"
        d.with_name(d.name + ".part").write_bytes(body)
        d.with_name(d.name + fetch._RECEIPT_SUFFIX).write_text(json.dumps(
            {"ident": fetch.acquisition_identity(url), "url": url, "method": "GET", "complete": False,
             "bytes": len(body), "digest": _h.sha256(body).hexdigest(), "status": 200,
             "error": "reset"}))
        evidence.probe_actuator(ctx, ["https://t/actuator"])
        base = [r for k, r in added if k == "review" and str(r.get("id", "")).startswith("actuator:")][0]
        assert "benign" in base["note"] and "env" not in base["note"], base
        assert not [r for k, r in added if k == "secret"], "the partial was not acquired THIS run"
        assert [r for k, r in added if k == evidence.OWNERSHIP_ENTITY and r.get("klass") == "acquisition-refused"]
        events.reset()

    def test_and_nothing_is_mined_out_of_the_unowned_artifact(self, tmp_path, monkeypatch):
        events.reset(); events.configure(tmp_path)
        _serve(monkeypatch, b'{"_links": {"env": {"href": "x"}}}')
        ctx, added = _ctx(tmp_path)
        monkeypatch.setattr(evidence, "ACTUATOR_SENSITIVE", ("env",))
        d = self._plant(ctx, "https://t/actuator/env", "actuator",
                        f"t-env-{evidence._artifact_id('https://t/actuator/env')}")
        d.write_bytes(b"DB_PASSWORD=hunter2super\n")     # a secret we did NOT acquire this run
        evidence.probe_actuator(ctx, ["https://t/actuator"])
        assert not [r for k, r in added if k == "secret"], \
            "an artifact whose ownership we cannot prove must not be mined as this run's finding"
        events.reset()


class TestAVerifiedReplayIsEVIDENCE:
    """review#27 (Lumpy), and a regression I introduced: `replayed-complete` has `contacted=False`, so
    six lanes gating on `not acq.contacted` threw away the verified artifact. That state is exactly
    what a crash between receipt publication and interpretation leaves behind — refusing it discards
    the recovery the mechanism exists to provide. NO CONTACT and NO USABLE EVIDENCE are different."""

    def test_graphql_interprets_the_replayed_schema_without_a_request(self, tmp_path, monkeypatch):
        calls: list = []
        _serve(monkeypatch, b'{"data": {"__schema": {"queryType": {"name": "Q"}}}}', calls=calls)
        ctx, added = _ctx(tmp_path)
        assert evidence.probe_graphql(ctx, ["https://t/graphql"]) == 1
        first = len([r for k, r in added if k == "review"])
        monkeypatch.setattr(fetch, "_open_no_follow",
                            lambda *a, **k: pytest.fail("a verified replay must not re-request"))
        assert evidence.probe_graphql(ctx, ["https://t/graphql"]) == 1, \
            "the second lifecycle must reach the same conclusion from the stored artifact"
        assert len(calls) == 1
        assert len([r for k, r in added if k == "review"]) == first * 2

    def test_the_exposed_lane_still_mines_a_replayed_body(self, tmp_path, monkeypatch):
        _serve(monkeypatch, b"AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
        ctx, added = _ctx(tmp_path)
        evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch", subdir="exposed")
        monkeypatch.setattr(fetch, "_open_no_follow", lambda *a, **k: pytest.fail("re-requested"))
        res = evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch",
                                         subdir="exposed")
        assert res["ok"] and res["disposition"] == "replayed-complete" and res["secrets"] == 1

    def test_openapi_rebuilds_its_endpoints_from_the_stored_document(self, tmp_path, monkeypatch):
        doc = json.dumps({"openapi": "3.0.0", "servers": [{"url": "https://t/v1"}],
                          "paths": {"/a": {"get": {}}}}).encode()
        _serve(monkeypatch, doc)
        ctx, added = _ctx(tmp_path)
        assert evidence.parse_openapi(ctx, ["https://t/openapi.json"]) == 1
        monkeypatch.setattr(fetch, "_open_no_follow", lambda *a, **k: pytest.fail("re-requested"))
        assert evidence.parse_openapi(ctx, ["https://t/openapi.json"]) == 1

    def test_the_actuator_index_is_read_back_from_the_artifact(self, tmp_path, monkeypatch):
        _serve(monkeypatch, b'{"_links": {"heapdump": {}, "env": {}}}')
        ctx, _ = _ctx(tmp_path)
        assert evidence._actuator_index_links(ctx, "https://t/actuator", "t") == {"heapdump", "env"}
        monkeypatch.setattr(fetch, "_open_no_follow", lambda *a, **k: pytest.fail("re-requested"))
        assert evidence._actuator_index_links(ctx, "https://t/actuator", "t") == {"heapdump", "env"}

    def test_a_replayed_deep_dump_is_still_mined(self, tmp_path, monkeypatch):
        _serve(monkeypatch, b"\x00blob AKIAIOSFODNN7EXAMPLE trailing")
        ctx, added = _ctx(tmp_path)
        assert evidence._deep_download(ctx, "https://t/actuator/heapdump", "t", "heapdump") is True
        monkeypatch.setattr(fetch, "_open_no_follow", lambda *a, **k: pytest.fail("re-requested"))
        assert evidence._deep_download(ctx, "https://t/actuator/heapdump", "t", "heapdump") is True
        assert [r for k, r in added if k == "secret"]

    def test_a_replayed_framework_hit_is_still_EXPOSED(self, tmp_path, monkeypatch):
        _serve(monkeypatch, b"Werkzeug Debugger")
        ctx, added = _ctx(tmp_path)
        cand = [{"url": "https://t/debug", "framework": "werkzeug", "note": "console"}]
        assert evidence.probe_framework_endpoints(ctx, cand) == 1
        monkeypatch.setattr(fetch, "_open_no_follow", lambda *a, **k: pytest.fail("re-requested"))
        assert evidence.probe_framework_endpoints(ctx, cand) == 1

    def test_a_replayed_actuator_subpath_is_still_EXPOSED(self, tmp_path, monkeypatch):
        _serve(monkeypatch, b'{"_links": {"env": {}}}')
        ctx, added = _ctx(tmp_path)
        monkeypatch.setattr(evidence, "ACTUATOR_SENSITIVE", ("env",))
        assert evidence.probe_actuator(ctx, ["https://t/actuator"]) == 1
        monkeypatch.setattr(fetch, "_open_no_follow", lambda *a, **k: pytest.fail("re-requested"))
        assert evidence.probe_actuator(ctx, ["https://t/actuator"]) == 1

    def test_and_a_replay_is_NOT_reported_as_an_ownership_gap(self, tmp_path, monkeypatch):
        events.reset(); events.configure(tmp_path)
        _serve(monkeypatch, b"body")
        ctx, added = _ctx(tmp_path)
        for _ in range(2):
            evidence.fetch_and_extract(ctx, "https://t/x", source="exposed-fetch", subdir="exposed")
        evs = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()]
        own = [e for e in evs if e.get("measure") == "evidence_ownership"]
        # BOTH lifecycles state their ownership: the replay is a healthy outcome in its own right, not
        # an absence. Only asserting "no gaps" passed while the replay reported nothing at all.
        assert len(own) == 2 and all(e["omitted"] == 0 and e["tested"] == 1 for e in own), own
        assert not [r for k, r in added if k == evidence.OWNERSHIP_ENTITY and r.get("klass") == "acquisition-refused"]
        events.reset()


class TestAnOwnershipGapCanBeCLEARED:
    def test_repairing_the_state_emits_a_healthy_record_on_the_SAME_unit(self, tmp_path, monkeypatch):
        """A gap was emitted when ownership withheld a URL and NOTHING when the operator fixed it, so
        reconciliation — latest record per (source, unit) — left the old gap standing forever."""
        events.reset(); events.configure(tmp_path)
        _reachable(monkeypatch)
        ctx, _ = _ctx(tmp_path)
        dest = ctx.run.raw_path("params", "exposed", "t-" + evidence._artifact_id("https://t/.env"))
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"ORPHAN")
        monkeypatch.setattr(fetch, "_open_no_follow", lambda *a, **k: pytest.fail("contacted"))
        evidence.fetch_exposed(ctx, ["https://t/.env"])
        gaps = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()
                if json.loads(x).get("measure") == "evidence_ownership"]
        assert gaps and gaps[-1]["omitted"] == 1
        unit = gaps[-1]["unit"]

        dest.unlink()                                  # the operator resolves it
        _serve(monkeypatch, b"body")
        evidence.fetch_exposed(ctx, ["https://t/.env"])
        after = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()
                 if json.loads(x).get("measure") == "evidence_ownership"]
        assert after[-1]["unit"] == unit, "the healthy record must land on the SAME unit"
        assert after[-1]["omitted"] == 0 and after[-1]["tested"] == 1
        events.reset()

    def test_a_repaired_durability_failure_clears_too(self, tmp_path, monkeypatch):
        events.reset(); events.configure(tmp_path)
        _serve(monkeypatch, b"body")
        monkeypatch.setattr(fetch, "_publish_receipt", lambda *a, **k: "; RECEIPT could not be written")
        ctx, _ = _ctx(tmp_path)
        evidence.fetch_and_extract(ctx, "https://t/x", source="exposed-fetch", subdir="exposed")
        rows = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()
                if json.loads(x).get("measure") == "evidence_durability"]
        assert rows and rows[-1]["omitted"] == 1
        unit = rows[-1]["unit"]

        monkeypatch.undo()                             # the disk recovers; the run is repeated
        _serve(monkeypatch, b"body")
        for p in (tmp_path / "params" / "exposed").glob("*"):
            p.unlink()
        evidence.fetch_and_extract(ctx, "https://t/x", source="exposed-fetch", subdir="exposed")
        rows = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()
                if json.loads(x).get("measure") == "evidence_durability"]
        assert rows[-1]["unit"] == unit and rows[-1]["omitted"] == 0
        events.reset()


class TestTheDenominatorArithmeticIsRIGHT:
    def test_a_refusal_is_removed_from_ELIGIBLE_only(self, tmp_path, monkeypatch):
        """`attempted` never counted the refusal, so subtracting it again produced
        `eligible=0, tested=0, omitted=0` with the reason "1 never requested"."""
        events.reset(); events.configure(tmp_path)
        _serve(monkeypatch, b"ok")
        ctx, _ = _ctx(tmp_path)
        orphan = ctx.run.raw_path("params", "exposed", "t-" + evidence._artifact_id("https://t/a"))
        orphan.parent.mkdir(parents=True, exist_ok=True)
        orphan.write_bytes(b"ORPHAN")
        evidence.fetch_exposed(ctx, ["https://t/a", "https://t/b", "https://t/c"])
        cov = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()
               if json.loads(x).get("measure") == "evidence_fetches"][-1]
        assert (cov["eligible"], cov["tested"], cov["omitted"]) == (2, 2, 0), cov
        assert "never requested" not in cov["reason"], cov["reason"]
        events.reset()


class TestOwnershipEvidenceIsAttributedToITSLane:
    def test_a_framework_refusal_is_not_openapi(self, tmp_path, monkeypatch):
        events.reset(); events.configure(tmp_path)
        _reachable(monkeypatch)
        ctx, added = _ctx(tmp_path)
        d = ctx.run.raw_path("params", "framework", f"t-{evidence._artifact_id('https://t/debug')}")
        d.parent.mkdir(parents=True, exist_ok=True)
        d.write_bytes(b"ORPHAN")
        monkeypatch.setattr(fetch, "_open_no_follow", lambda *a, **k: pytest.fail("contacted"))
        evidence.probe_framework_endpoints(
            ctx, [{"url": "https://t/debug", "framework": "werkzeug", "note": "console"}])
        evs = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()]
        own = [e for e in evs if e.get("measure") == "evidence_ownership"]
        assert own and own[-1].get("source_id") == "framework-probe", own
        assert not [e for e in own if e.get("source_id") == "openapi"], "not the openapi lane's unit"
        row = [r for k, r in added if k == evidence.OWNERSHIP_ENTITY and r.get("klass") == "acquisition-refused"][0]
        assert row["sources"] == ["framework-probe"], row
        events.reset()


class TestAnUnrecordedPARTIALIsNotDurablyOwned:
    """review#28 (Lumpy): the incomplete branch kept `disposition="incomplete"` even when the receipt
    write failed, so the caller certified `ownership receipt in place` — while the next lifecycle would
    meet an `orphan-partial` and refuse. Two facts, both true: the transport broke AND we cannot prove
    what we hold."""

    class _Breaks(_Resp):
        def read(self, n=-1):
            buf = super().read(n)
            if not buf:
                raise OSError("reset")
            return buf

    def _run(self, tmp_path, monkeypatch, *, receipt_fails=True):
        events.reset(); events.configure(tmp_path)
        _reachable(monkeypatch)
        monkeypatch.setattr(fetch, "_open_no_follow",
                            lambda req, timeout, opener=None: (200, {}, self._Breaks(b"half" * 64)))
        if receipt_fails:
            monkeypatch.setattr(fetch, "_publish_receipt",
                                lambda *a, **k: "; RECEIPT could not be written")
        ctx, added = _ctx(tmp_path)
        res = evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch",
                                         subdir="exposed")
        evs = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()]
        return res, added, evs

    def test_the_disposition_says_the_ownership_failed_too(self, tmp_path, monkeypatch):
        res, _added, _evs = self._run(tmp_path, monkeypatch)
        assert res["disposition"] == "incomplete-unowned" and res["error"] == "incomplete"

    def test_it_is_NOT_certified_as_owned(self, tmp_path, monkeypatch):
        _res, _added, evs = self._run(tmp_path, monkeypatch)
        healthy = [e for e in evs if e.get("measure") in ("evidence_ownership", "evidence_durability")
                   and e.get("omitted") == 0]
        assert not healthy, f"an unrecorded partial was certified as durably owned: {healthy}"

    def test_a_durability_GAP_is_emitted_and_POINTS_AT_the_partial(self, tmp_path, monkeypatch):
        """The bytes of an incomplete acquisition are at `<dest>.part`. Publishing `dest` sent the
        operator to a path that does not exist — the same defect as "KEPT at None" (review#29)."""
        res, added, evs = self._run(tmp_path, monkeypatch)
        gap = [e for e in evs if e.get("measure") == "evidence_durability"]
        assert gap and gap[-1]["omitted"] == 1 and gap[-1]["kind"] == "ownership"
        assert "PARTIAL" in gap[-1]["reason"], gap[-1]["reason"]
        row = [r for k, r in added if k == evidence.OWNERSHIP_ENTITY and r.get("klass") == "unowned-artifact"][0]
        assert "PARTIALLY" in row["note"]
        from pathlib import Path
        assert row["raw_ref"] == res["partial"] and row["raw_ref"].endswith(".part"), row
        assert Path(row["raw_ref"]).exists(), "raw_ref must resolve to the bytes we actually kept"
        assert row["state_paths"] == [row["raw_ref"]]
        assert row["raw_ref"] in gap[-1]["reason"]

    def test_a_recorded_partial_keeps_the_plain_disposition(self, tmp_path, monkeypatch):
        """When the receipt DID land, ownership is genuinely recorded — the body being incomplete is a
        transport fact the lane reports separately. So the durability record is HEALTHY here, and that
        is the difference the disposition has to carry."""
        res, _added, evs = self._run(tmp_path, monkeypatch, receipt_fails=False)
        assert res["disposition"] == "incomplete"
        dur = [e for e in evs if e.get("measure") == "evidence_durability"]
        assert dur and all(e["omitted"] == 0 for e in dur), dur

    def test_the_next_lifecycle_agrees_with_what_we_reported(self, tmp_path, monkeypatch):
        """The point of the whole thing: what we said happened must match what the state says next."""
        self._run(tmp_path, monkeypatch)
        monkeypatch.undo()
        _reachable(monkeypatch)
        monkeypatch.setattr(fetch, "_open_no_follow",
                            lambda *a, **k: pytest.fail("an unrecorded partial must not be re-fetched"))
        ctx, _added = _ctx(tmp_path)
        res = evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch",
                                         subdir="exposed")
        assert res["disposition"] == "orphan-partial" and res["error"] == "refused"
        events.reset()


class TestTheRefusalROWCannotRaise:
    def test_an_unreadable_state_directory_does_not_become_an_attempt(self, tmp_path, monkeypatch):
        """`_reconcile` turns inspection failure into a no-contact result; `_refused` then walked the
        same paths with unguarded `exists()` and put the exception back."""
        _reachable(monkeypatch)
        monkeypatch.setattr(fetch, "_open_no_follow", lambda *a, **k: pytest.fail("contacted"))
        real = fetch.Path.lstat

        def _boom(self, *a, **k):
            if self.name.startswith("t-"):
                raise PermissionError("permission denied")
            return real(self, *a, **k)
        monkeypatch.setattr(fetch.Path, "lstat", _boom)
        monkeypatch.setattr(evidence.Path, "lstat", _boom)
        ctx, added = _ctx(tmp_path)
        res = evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch",
                                         subdir="exposed")
        assert res["attempted"] is False and res["disposition"] == "ownership-uninspectable"
        row = [r for k, r in added if k == evidence.OWNERSHIP_ENTITY and r.get("klass") == "acquisition-refused"][0]
        assert row["state_paths"] == [], "unreadable is not 'present'"

    def test_a_DANGLING_symlink_counts_as_state(self, tmp_path, monkeypatch):
        """`exists()` follows and answers False for one; the file is very much there."""
        _reachable(monkeypatch)
        ctx, added = _ctx(tmp_path)
        dest = ctx.run.raw_path("params", "exposed", "t-" + evidence._artifact_id("https://t/.env"))
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.with_name(dest.name + ".part").symlink_to(tmp_path / "gone")
        monkeypatch.setattr(fetch, "_open_no_follow", lambda *a, **k: pytest.fail("contacted"))
        evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch", subdir="exposed")
        row = [r for k, r in added if k == evidence.OWNERSHIP_ENTITY and r.get("klass") == "acquisition-refused"][0]
        assert any(p.endswith(".part") for p in row["state_paths"]), row


class TestAReplayIsNotAnUnrequestedCandidate:
    def test_the_fetch_reason_says_REPLAYED_not_never_requested(self, tmp_path, monkeypatch):
        events.reset(); events.configure(tmp_path)
        _serve(monkeypatch, b"body")
        ctx, _ = _ctx(tmp_path)
        evidence.fetch_exposed(ctx, ["https://t/a"])
        monkeypatch.setattr(fetch, "_open_no_follow", lambda *a, **k: pytest.fail("re-requested"))
        evidence.fetch_exposed(ctx, ["https://t/a"])
        cov = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()
               if json.loads(x).get("measure") == "evidence_fetches"][-1]
        assert (cov["eligible"], cov["tested"], cov["omitted"]) == (1, 1, 0), cov
        assert "replayed from verified evidence" in cov["reason"], cov["reason"]
        assert "never requested" not in cov["reason"], cov["reason"]
        events.reset()


class TestOwnershipHasALIFECYCLE:
    """review#29 (Lumpy): open -> resolved -> reopened. A mutable `resolved` boolean on a merged review
    entity cannot express that — the store never overwrites a non-empty scalar, so once True it was True
    for ever and a reopened refusal still rendered `[RESOLVED]`. Transitions are append-only rows and
    the CURRENT state is the latest one."""

    @staticmethod
    def _states(added, key=None):
        rows = [r for k, r in added if k == evidence.OWNERSHIP_ENTITY and r.get("state_key")]
        return [(r["state_seq"], r["state"]) for r in sorted(rows, key=lambda x: x["state_seq"])]

    def _orphan(self, ctx, url="https://t/.env"):
        d = ctx.run.raw_path("params", "exposed", "t-" + evidence._artifact_id(url))
        d.parent.mkdir(parents=True, exist_ok=True)
        d.write_bytes(b"ORPHAN")
        return d

    def test_open_then_resolved(self, tmp_path, monkeypatch):
        _reachable(monkeypatch)
        ctx, added = _ctx(tmp_path)
        dest = self._orphan(ctx)
        monkeypatch.setattr(fetch, "_open_no_follow", lambda *a, **k: pytest.fail("contacted"))
        evidence.fetch_exposed(ctx, ["https://t/.env"])
        assert self._states(added) == [(1, "refused")]
        dest.unlink()
        _serve(monkeypatch, b"body")
        evidence.fetch_exposed(ctx, ["https://t/.env"])
        assert self._states(added) == [(1, "refused"), (2, "ok")]

    def test_and_REOPENED(self, tmp_path, monkeypatch):
        """The case the boolean could not represent at all."""
        _reachable(monkeypatch)
        ctx, added = _ctx(tmp_path)
        dest = self._orphan(ctx)
        monkeypatch.setattr(fetch, "_open_no_follow", lambda *a, **k: pytest.fail("contacted"))
        evidence.fetch_exposed(ctx, ["https://t/.env"])
        dest.unlink()
        _serve(monkeypatch, b"body")
        evidence.fetch_exposed(ctx, ["https://t/.env"])
        # …and the artifact is tampered with afterwards
        dest.write_bytes(b"TAMPERED-DIFFERENT-LENGTH")
        _reachable(monkeypatch)
        monkeypatch.setattr(fetch, "_open_no_follow", lambda *a, **k: pytest.fail("contacted"))
        evidence.fetch_exposed(ctx, ["https://t/.env"])
        assert self._states(added) == [(1, "refused"), (2, "ok"), (3, "refused")]

    def test_a_repair_in_a_NEW_LIFECYCLE_still_resolves_it(self, tmp_path, monkeypatch):
        """The operator workflow: the failure is in one process and the repair in the next. A per-`ctx`
        set started empty and never resolved the persisted row."""
        _reachable(monkeypatch)
        shared: list = []
        ctx_a, _ = _ctx(tmp_path, shared)
        dest = self._orphan(ctx_a)
        monkeypatch.setattr(fetch, "_open_no_follow", lambda *a, **k: pytest.fail("contacted"))
        evidence.fetch_exposed(ctx_a, ["https://t/.env"])
        assert self._states(shared) == [(1, "refused")]

        dest.unlink()
        _serve(monkeypatch, b"body")
        ctx_b, _ = _ctx(tmp_path, shared)          # a DIFFERENT context over the same store
        evidence.fetch_exposed(ctx_b, ["https://t/.env"])
        assert self._states(shared) == [(1, "refused"), (2, "ok")], shared

    def test_a_steady_stream_of_healthy_replays_does_not_grow_the_log(self, tmp_path, monkeypatch):
        _serve(monkeypatch, b"body")
        ctx, added = _ctx(tmp_path)
        for _ in range(4):
            evidence.fetch_and_extract(ctx, "https://t/x", source="exposed-fetch", subdir="exposed")
        assert self._states(added) == [], "nothing was ever wrong; there is nothing to record"

    def test_a_repeated_REFUSAL_appends_one_transition_not_one_per_call(self, tmp_path, monkeypatch):
        """The state has not changed, so there is nothing to record. Without the no-op guard an
        unresolved orphan writes a row on every lane pass — and the log is read on every acquisition,
        so it degrades quadratically as well as lying about how many times it happened."""
        _reachable(monkeypatch)
        ctx, added = _ctx(tmp_path)
        self._orphan(ctx)
        monkeypatch.setattr(fetch, "_open_no_follow", lambda *a, **k: pytest.fail("contacted"))
        for _ in range(5):
            evidence.fetch_exposed(ctx, ["https://t/.env"])
        assert self._states(added) == [(1, "refused")], added

    def test_the_report_shows_only_the_LATEST_transition(self, tmp_path, monkeypatch):
        from quarry_recon import triage
        rows = _transitions([("refused", 1, "https://t/.env", "acquisition-refused"),
                             ("ok", 2, "/raw/a.bin", "ownership-resolved")])
        run = SimpleNamespace(read=lambda kind: rows if kind == evidence.OWNERSHIP_ENTITY else [],
                              read_folded=lambda kind: SimpleNamespace(
                                  records={r["id"]: r for r in rows}
                                  if kind == evidence.OWNERSHIP_ENTITY else {},
                                  status="valid", dropped=0, reason=""),
                              values=lambda kind: [], count=lambda kind: 0, path=None,
                              target="t", run_id="r1")
        scope = SimpleNamespace(in_scope=lambda h: True, is_oos=lambda h: False,
                                active_allowed=lambda h: True, roots=[], oos=[])
        out = triage.build(run, scope)
        assert triage.markdown_value("[RESOLVED] /raw/a.bin") in out, out[-1500:]
        assert triage.markdown_value("https://t/.env") not in out, \
            "the superseded transition is history, not current state"

    def test_and_a_REOPENED_one_is_shown_as_a_live_problem_again(self):
        from quarry_recon import triage
        rows = _transitions([("refused", 1, "x", "acquisition-refused"),
                             ("ok", 2, "x", "ownership-resolved"),
                             ("refused", 3, "https://t/again", "acquisition-refused")])
        run = SimpleNamespace(read=lambda kind: rows if kind == evidence.OWNERSHIP_ENTITY else [],
                              read_folded=lambda kind: SimpleNamespace(
                                  records={r["id"]: r for r in rows}
                                  if kind == evidence.OWNERSHIP_ENTITY else {},
                                  status="valid", dropped=0, reason=""),
                              values=lambda kind: [], count=lambda kind: 0, path=None,
                              target="t", run_id="r1")
        scope = SimpleNamespace(in_scope=lambda h: True, is_oos=lambda h: False,
                                active_allowed=lambda h: True, roots=[], oos=[])
        out = triage.build(run, scope)
        assert triage.markdown_value("https://t/again") in out
        assert triage.markdown_value("[RESOLVED]") not in out, out[-1500:]

    def test_an_ordinary_replay_does_NOT_invent_a_resolution(self, tmp_path, monkeypatch):
        """A resolution for a path that was never refused is a history that did not happen."""
        _serve(monkeypatch, b"body")
        ctx, added = _ctx(tmp_path)
        for _ in range(2):
            evidence.fetch_and_extract(ctx, "https://t/x", source="exposed-fetch", subdir="exposed")
        assert not [r for k, r in added if r.get("state") == "ok"], added


class TestAChangedRefusalIsANewTransition:
    """review#30 (Lumpy): the no-op guard compared only `state`. `orphan-complete` becoming
    `ownership-conflict` is a different cause, different evidence and a different action — and the row
    kept telling the operator to remove the wrong file."""

    def _states(self, added):
        rows = [r for k, r in added if k == evidence.OWNERSHIP_ENTITY and r.get("state_key")]
        return [(r["state_seq"], r["state"], r.get("disposition")) for r in
                sorted(rows, key=lambda x: x["state_seq"])]

    def test_a_different_refusal_CAUSE_is_recorded(self, tmp_path, monkeypatch):
        _reachable(monkeypatch)
        ctx, added = _ctx(tmp_path)
        dest = ctx.run.raw_path("params", "exposed", "t-" + evidence._artifact_id("https://t/.env"))
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"ORPHAN")
        monkeypatch.setattr(fetch, "_open_no_follow", lambda *a, **k: pytest.fail("contacted"))
        evidence.fetch_exposed(ctx, ["https://t/.env"])
        assert self._states(added) == [(1, "refused", "orphan-complete")]

        # the state on disk CHANGES: now there is a receipt describing a complete acquisition AND a
        # stray partial beside it — a conflict, not an orphan
        import hashlib as _h
        dest.with_name(dest.name + ".part").write_bytes(b"stray")
        dest.with_name(dest.name + fetch._RECEIPT_SUFFIX).write_text(json.dumps(
            {"ident": fetch.acquisition_identity("https://t/.env"), "url": "https://t/.env",
             "method": "GET", "complete": True, "bytes": 6,
             "digest": _h.sha256(b"ORPHAN").hexdigest()}))
        evidence.fetch_exposed(ctx, ["https://t/.env"])
        assert self._states(added) == [(1, "refused", "orphan-complete"),
                                       (2, "refused", "ownership-conflict")], added

    def test_an_IDENTICAL_refusal_is_still_a_no_op(self, tmp_path, monkeypatch):
        _reachable(monkeypatch)
        ctx, added = _ctx(tmp_path)
        d = ctx.run.raw_path("params", "exposed", "t-" + evidence._artifact_id("https://t/.env"))
        d.parent.mkdir(parents=True, exist_ok=True)
        d.write_bytes(b"ORPHAN")
        monkeypatch.setattr(fetch, "_open_no_follow", lambda *a, **k: pytest.fail("contacted"))
        for _ in range(4):
            evidence.fetch_exposed(ctx, ["https://t/.env"])
        assert len(self._states(added)) == 1


class TestResolutionPointsAtTheEvidenceThatEXISTS:
    class _Breaks(_Resp):
        def read(self, n=-1):
            buf = super().read(n)
            if not buf:
                raise OSError("reset")
            return buf

    def test_an_owned_PARTIAL_resolves_against_its_part_file(self, tmp_path, monkeypatch):
        """The receipt landed, so the ownership problem really is resolved — but the bytes are at
        `<dest>.part`, and `dest` does not exist."""
        _reachable(monkeypatch)
        ctx, added = _ctx(tmp_path)
        dest = ctx.run.raw_path("params", "exposed", "t-" + evidence._artifact_id("https://t/.env"))
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"ORPHAN")                     # open the problem first
        monkeypatch.setattr(fetch, "_open_no_follow", lambda *a, **k: pytest.fail("contacted"))
        evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch", subdir="exposed")
        assert [r for k, r in added if r.get("state") == "refused"]

        dest.unlink()                                   # the operator clears it; the next fetch breaks
        monkeypatch.undo()
        _reachable(monkeypatch)
        monkeypatch.setattr(fetch, "_open_no_follow",
                            lambda req, timeout, opener=None: (200, {}, self._Breaks(b"half" * 32)))
        res = evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch",
                                         subdir="exposed")
        assert res["disposition"] == "incomplete", "the receipt landed; only the body did not"
        ok = [r for k, r in added if r.get("state") == "ok"][0]
        from pathlib import Path
        assert ok["raw_ref"].endswith(".part") and Path(ok["raw_ref"]).exists(), ok
        assert ok["value"] == ok["raw_ref"] and ok["state_paths"] == [ok["raw_ref"]]


class TestACorruptTransitionLogIsHANDLED:
    """These rows come off disk. An arbitrary `state`, a string `state_seq` or a missing key is INPUT."""

    def _ctx_with(self, tmp_path, rows):
        ctx, added = _ctx(tmp_path)
        for r in rows:
            added.append((evidence.OWNERSHIP_ENTITY, r))    # transitions have their OWN log
        return ctx, added

    def test_a_non_integer_sequence_does_not_raise(self, tmp_path, monkeypatch):
        events.reset(); events.configure(tmp_path)
        _serve(monkeypatch, b"body")
        key = evidence._state_key("exposed-fetch",
                                  tmp_path / "params" / "exposed" /
                                  ("t-" + evidence._artifact_id("https://t/.env")))
        ctx, added = self._ctx_with(tmp_path, [{"id": "ownership:x:1", "state_key": key,
                                                "state": "refused", "state_seq": "not-an-int"}])
        res = evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch",
                                         subdir="exposed")
        assert res["ok"], "a corrupt history must not break the lane"
        events.reset()

    def test_the_corruption_is_REPORTED_as_an_unknown_lifecycle(self, tmp_path, monkeypatch):
        events.reset(); events.configure(tmp_path)
        _serve(monkeypatch, b"body")
        ctx, _ = self._ctx_with(tmp_path, [{"id": "ownership:x:1", "state_key": "k",
                                            "state": "refused", "state_seq": "1"},
                                           {"id": "ownership:y:1", "state_key": "k2",
                                            "state": "invented", "state_seq": 1}])
        evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch", subdir="exposed")
        evs = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()]
        bad = [e for e in evs if e.get("measure") == "ownership_state"]
        assert bad and bad[-1]["kind"] == "unknown", evs
        assert "2 ownership transition row(s) are malformed" in bad[-1]["reason"]
        events.reset()

    def test_duplicate_sequences_are_only_reachable_through_a_MERGED_conflict(self, tmp_path):
        """Validation ties the id to `ownership:{key}:{seq}`, so two rows with the same key+seq must
        share an id — which means the store MERGES them and the conflict lands in `_alt`. That is why
        this case can only be exercised through the real store (`TestThroughTheREALStore`), and why a
        fake that keys records by id cannot show it at all."""
        r1 = {"id": "ownership:k:1", "state_key": "k", "state": "ok", "state_seq": 1}
        r2 = {"id": "ownership:k:1", "state_key": "k", "state": "refused", "state_seq": 1}
        for r in (r1, r2):
            r["state_fp"] = evidence._material(r["state"], r)
        assert evidence._valid_transition(r1) and evidence._valid_transition(r2)
        assert r1["id"] == r2["id"], "same key+seq -> same id -> one canonical key in the store"

    def test_an_ambiguous_key_is_never_RESOLVED_by_a_later_success(self, tmp_path, monkeypatch):
        """"unknown" is not "refused": a resolution would claim to have fixed something we cannot even
        read the state of."""
        events.reset(); events.configure(tmp_path)
        _serve(monkeypatch, b"body")
        ctx, added = _ctx(tmp_path)
        dest = ctx.run.raw_path("params", "exposed", "t-" + evidence._artifact_id("https://t/.env"))
        dest.parent.mkdir(parents=True, exist_ok=True)
        key = evidence._state_key("exposed-fetch", dest)
        for st in ("refused", "ok"):
            r = {"id": f"ownership:{key}:1", "state_key": key, "state": st, "state_seq": 1}
            r["state_fp"] = evidence._material(st, r)
            added.append((evidence.OWNERSHIP_ENTITY, r))
        evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch", subdir="exposed")
        published = [r for k, r in added if r.get("state_key") == key and r.get("state_seq", 0) > 1]
        assert not published, published
        events.reset()

    def test_an_unknown_state_can_never_be_PUBLISHED(self, tmp_path):
        ctx, _ = _ctx(tmp_path)
        with pytest.raises(ValueError):
            evidence._publish_state(ctx, "k", "invented", klass="x", value="v", source="s")


class TestTheTransitionLogIsTRUST_AWARE:
    """review#31 (Lumpy): three ways the log stops being authoritative, all of which used to read as
    'nothing ever happened'."""

    @staticmethod
    def _state_events(tmp_path):
        log = tmp_path / "events.jsonl"
        rows = [json.loads(x) for x in log.read_text().splitlines()] if log.exists() else []
        return [e for e in rows if e.get("measure") == "ownership_state"]

    def test_an_UNREADABLE_log_is_a_gap_not_an_empty_history(self, tmp_path, monkeypatch):
        events.reset(); events.configure(tmp_path)
        _serve(monkeypatch, b"body")
        ctx, _ = _ctx(tmp_path)
        def _boom(kind):
            raise PermissionError("permission denied")
        ctx.run.read_folded = _boom
        ctx.run.read = _boom
        evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch", subdir="exposed")
        ev = self._state_events(tmp_path)
        assert ev and ev[-1]["kind"] == "unknown" and "could not be read" in ev[-1]["reason"], ev
        events.reset()

    def test_a_DEGRADED_fold_is_a_gap_even_though_read_returns_rows(self, tmp_path, monkeypatch):
        """`Run.read()` drops bad JSON while folding and throws the status away, so the corruption was
        gone before `_valid_transition` could ever count it."""
        events.reset(); events.configure(tmp_path)
        _serve(monkeypatch, b"body")
        ctx, _ = _ctx(tmp_path)
        ctx.run.read_folded = lambda kind: SimpleNamespace(
            records={}, status="degraded", dropped=3, reason="invalid JSON")
        evidence.fetch_and_extract(ctx, "https://t/.env", source="exposed-fetch", subdir="exposed")
        ev = self._state_events(tmp_path)
        assert ev and ev[-1]["kind"] == "unknown"
        assert "degraded" in ev[-1]["reason"] and "3 row(s) dropped" in ev[-1]["reason"], ev
        events.reset()

    def test_the_store_exposes_that_status_at_all(self, tmp_path):
        """The reader can only be trust-aware if the store hands the trust over."""
        from quarry_recon import store
        run = store.Run.create(tmp_path, "t.example")
        run.add("review", {"id": "a", "klass": "x", "value": "v"})
        folded = run.read_folded("review")
        assert folded.status in ("valid", "absent") and folded.dropped == 0
        assert [r["id"] for r in folded.records.values()] == ["a"]
        assert len(run.read("review")) == 1, "and the plain read is unchanged"

    def test_a_degraded_review_log_is_visible_through_the_real_store(self, tmp_path):
        from quarry_recon import store
        run = store.Run.create(tmp_path, "t.example")
        run.add("review", {"id": "a", "klass": "x", "value": "v"})
        p = run._entity_file("review")
        p.write_text(p.read_text() + "{not json\n")
        run._records.clear(); run._folded.clear()      # re-read the SAME run dir, not a new one
        folded = run.read_folded("review")
        assert folded.status == "degraded" and folded.dropped == 1, folded

    def test_a_REPAIRED_log_clears_the_unknown(self, tmp_path, monkeypatch):
        """Reconciliation keeps the latest record per (source, unit). With no healthy counterpart the
        first corruption gated every later run for ever."""
        events.reset(); events.configure(tmp_path)
        _serve(monkeypatch, b"body")
        ctx, added = _ctx(tmp_path)
        added.append((evidence.OWNERSHIP_ENTITY, {"id": "ownership:k:1", "state_key": "k",
                                                  "state": "refused", "state_seq": "not-an-int"}))
        evidence.fetch_and_extract(ctx, "https://t/a", source="exposed-fetch", subdir="exposed")
        ev = self._state_events(tmp_path)
        assert ev and ev[-1]["kind"] == "unknown"
        unit = ev[-1]["unit"]

        added[:] = [(k, r) for k, r in added if r.get("state_seq") != "not-an-int"]   # repaired
        ctx2, _ = _ctx(tmp_path, added)
        evidence.fetch_and_extract(ctx2, "https://t/b", source="exposed-fetch", subdir="exposed")
        ev = self._state_events(tmp_path)
        assert ev[-1]["unit"] == unit, "the healthy record must land on the SAME unit"
        assert ev[-1]["kind"] == "ownership" and ev[-1]["omitted"] == 0, ev[-1]
        events.reset()


class TestTheMaterialFingerprintIsUNAMBIGUOUS:
    def test_delimiters_in_values_cannot_forge_a_collision(self):
        """review#31's exact pair: `|`-joined fields and `,`-joined paths collided."""
        a = evidence._material("refused", {"disposition": "a|b", "raw_ref": "c",
                                           "state_paths": ["/one,two", "/three"]})
        b = evidence._material("refused", {"disposition": "a", "raw_ref": "b|c",
                                           "state_paths": ["/one", "two,/three"]})
        assert a != b

    def test_it_is_a_FULL_sha256(self):
        fp = evidence._material("ok", {"disposition": "x"})
        assert len(fp) == 64 and int(fp, 16) >= 0

    def test_the_same_material_state_still_fingerprints_the_same(self):
        f = {"disposition": "orphan-complete", "raw_ref": "/raw/a", "state_paths": ["/raw/a"]}
        assert evidence._material("refused", f) == evidence._material("refused", dict(f))

    def test_a_row_whose_fingerprint_does_not_match_its_fields_is_rejected(self, tmp_path, monkeypatch):
        """A rewritten row is not evidence of the transition it describes."""
        events.reset(); events.configure(tmp_path)
        _serve(monkeypatch, b"body")
        ctx, added = _ctx(tmp_path)
        added.append((evidence.OWNERSHIP_ENTITY,
                      {"id": "ownership:k:1", "state_key": "k", "state": "ok", "state_seq": 1,
                       "state_fp": "0" * 64, "disposition": "x"}))
        evidence.fetch_and_extract(ctx, "https://t/a", source="exposed-fetch", subdir="exposed")
        # the row is DROPPED, and a dropped row makes the whole log non-authoritative — the missing
        # transition could have been the newest one for any key (review#32)
        assert evidence._ownership_state(ctx, "k") == "unknown"
        ev = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()
              if json.loads(x).get("measure") == "ownership_state"]
        assert ev and ev[-1]["kind"] == "unknown" and "malformed" in ev[-1]["reason"]
        events.reset()

    def test_an_id_that_disagrees_with_its_key_and_seq_is_rejected(self, tmp_path, monkeypatch):
        events.reset(); events.configure(tmp_path)
        _serve(monkeypatch, b"body")
        ctx, added = _ctx(tmp_path)
        row = {"id": "ownership:SOMEONE-ELSE:9", "state_key": "k", "state": "ok", "state_seq": 1}
        row["state_fp"] = evidence._material("ok", row)
        added.append((evidence.OWNERSHIP_ENTITY, row))
        evidence.fetch_and_extract(ctx, "https://t/a", source="exposed-fetch", subdir="exposed")
        assert evidence._ownership_state(ctx, "k") == "unknown"
        events.reset()


class TestThroughTheREALStore:
    """review#32 (Lumpy): the list-backed fake preserves raw observations; the production store MERGES
    them by canonical key. Two transitions with the same (key, seq) share an id, so the real fold turned
    them into ONE row with the loser parked in `_alt` — and the duplicate detection never fired. Tests
    that only drive the fake cannot see that."""

    @staticmethod
    def _run(tmp_path):
        from quarry_recon import store
        return store.Run.create(tmp_path, "t.example")

    @staticmethod
    def _reopen(run):
        run._records.clear(); run._folded.clear()      # same run dir, read from disk again
        return run

    def _row(self, key, seq, state, **kw):
        r = {"id": f"ownership:{key}:{seq}", "klass": "acquisition-refused", "state_key": key,
             "state": state, "state_seq": seq, "value": "v", **kw}
        r["state_fp"] = evidence._material(state, r)
        return r

    def test_two_transitions_sharing_an_id_are_AMBIGUOUS_not_merged_into_a_winner(self, tmp_path):
        events.reset(); events.configure(tmp_path)
        run = self._run(tmp_path)
        run.add(evidence.OWNERSHIP_ENTITY, self._row("k", 1, "ok"))
        run.add(evidence.OWNERSHIP_ENTITY, self._row("k", 1, "refused"))
        ctx = SimpleNamespace(run=self._reopen(run))
        folded = ctx.run.read_folded(evidence.OWNERSHIP_ENTITY)
        assert len(folded.records) == 1, "the production store really does merge them"
        assert evidence._ownership_state(ctx, "k") == "unknown", \
            "a merged conflict on a transition field is the same ambiguity by another route"
        ev = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()
              if json.loads(x).get("measure") == "ownership_state"]
        assert ev and ev[-1]["kind"] == "unknown", ev
        events.reset()

    def test_a_clean_lifecycle_survives_close_and_reopen(self, tmp_path):
        events.reset(); events.configure(tmp_path)
        run = self._run(tmp_path)
        run.add(evidence.OWNERSHIP_ENTITY, self._row("k", 1, "refused"))
        ctx = SimpleNamespace(run=self._reopen(run))
        assert evidence._ownership_state(ctx, "k") == "refused"
        run.add(evidence.OWNERSHIP_ENTITY, self._row("k", 2, "ok"))
        ctx2 = SimpleNamespace(run=self._reopen(run))
        assert evidence._ownership_state(ctx2, "k") == "ok"
        rows, ok = evidence.current_ownership_rows(ctx2.run)
        assert ok and [r["state"] for r in rows] == ["ok"]
        events.reset()

    def test_a_degraded_log_makes_EVERY_key_unknown(self, tmp_path):
        """A dropped row could have been a newer refusal for the very key whose surviving `ok` we are
        about to call current."""
        events.reset(); events.configure(tmp_path)
        run = self._run(tmp_path)
        run.add(evidence.OWNERSHIP_ENTITY, self._row("k", 1, "ok"))
        f = run._entity_file(evidence.OWNERSHIP_ENTITY)
        f.write_text(f.read_text() + "{not json\n")
        ctx = SimpleNamespace(run=self._reopen(run))
        assert evidence._ownership_state(ctx, "k") == "unknown"
        rows, authoritative = evidence.current_ownership_rows(ctx.run)
        assert authoritative is False and all(r["undecidable"] for r in rows), rows
        events.reset()

    def test_a_non_authoritative_log_is_READ_ONLY(self, tmp_path, monkeypatch):
        """Appending onto a sequence we know is incomplete manufactures a history."""
        events.reset(); events.configure(tmp_path)
        run = self._run(tmp_path)
        run.add(evidence.OWNERSHIP_ENTITY, self._row("k", 1, "ok"))
        f = run._entity_file(evidence.OWNERSHIP_ENTITY)
        f.write_text(f.read_text() + "{not json\n")
        ctx = SimpleNamespace(run=self._reopen(run))
        assert evidence._publish_state(ctx, "k2", "refused", klass="acquisition-refused",
                                       value="v", source="s") is False
        assert not [r for r in ctx.run.read(evidence.OWNERSHIP_ENTITY) if r.get("state_key") == "k2"]
        events.reset()

    def test_the_report_says_UNDECIDABLE_instead_of_showing_a_state(self, tmp_path):
        from quarry_recon import triage
        events.reset(); events.configure(tmp_path)
        run = self._run(tmp_path)
        run.add(evidence.OWNERSHIP_ENTITY, self._row("k", 1, "ok", value="/raw/a.bin"))
        f = run._entity_file(evidence.OWNERSHIP_ENTITY)
        f.write_text(f.read_text() + "{not json\n")
        self._reopen(run)
        scope = SimpleNamespace(in_scope=lambda h: True, is_oos=lambda h: False,
                                active_allowed=lambda h: True, roots=[], oos=[])
        out = triage.build(run, scope)
        assert triage.markdown_value("[STATE UNKNOWN] /raw/a.bin") in out, out[-1500:]
        assert triage.markdown_value("[RESOLVED]") not in out, \
            "the lane refuses to act on this log; the report must not"
        events.reset()

    def test_the_lane_and_the_report_agree_on_a_healthy_log(self, tmp_path, monkeypatch):
        from quarry_recon import triage
        events.reset(); events.configure(tmp_path)
        run = self._run(tmp_path)
        run.add(evidence.OWNERSHIP_ENTITY, self._row("k", 1, "refused", value="https://t/x"))
        run.add(evidence.OWNERSHIP_ENTITY, self._row("k", 2, "ok", value="/raw/x"))
        self._reopen(run)
        ctx = SimpleNamespace(run=run)
        assert evidence._ownership_state(ctx, "k") == "ok"
        scope = SimpleNamespace(in_scope=lambda h: True, is_oos=lambda h: False,
                                active_allowed=lambda h: True, roots=[], oos=[])
        out = triage.build(run, scope)
        assert triage.markdown_value("[RESOLVED] /raw/x") in out
        assert triage.markdown_value("https://t/x") not in out, out[-1500:]
        events.reset()


class TestALostOwnershipLogIsVISIBLE:
    """review#33 (Lumpy): when NO transition survives there is no row to hang a per-path warning on,
    so the report said nothing at all — while the lane was refusing to record new refusals into that
    same log. The warning has to be section-level for exactly that case."""

    @staticmethod
    def _wrecked_run(tmp_path):
        from quarry_recon import store
        run = store.Run.create(tmp_path, "t.example")
        run.add(evidence.OWNERSHIP_ENTITY, {"id": "ownership:k:1", "klass": "acquisition-refused",
                                            "state_key": "k", "state": "refused", "state_seq": 1,
                                            "state_fp": "0" * 64, "value": "v"})
        f = run._entity_file(evidence.OWNERSHIP_ENTITY)
        f.write_text("{not json\n")                 # nothing readable at all
        run._records.clear(); run._folded.clear()
        return run

    @staticmethod
    def _report(run):
        from quarry_recon import triage
        scope = SimpleNamespace(in_scope=lambda h: True, is_oos=lambda h: False,
                                active_allowed=lambda h: True, roots=[], oos=[])
        return triage.build(run, scope)

    def test_the_report_says_so_even_with_ZERO_surviving_rows(self, tmp_path):
        events.reset(); events.configure(tmp_path)
        run = self._wrecked_run(tmp_path)
        rows, ok = evidence.current_ownership_rows(run)
        assert rows == [] and ok is False, (rows, ok)
        out = self._report(run)
        assert "Acquisition-ownership log NOT AUTHORITATIVE" in out, out[-1500:]
        assert "no path's current acquisition state is known" in out
        events.reset()

    def test_it_says_what_is_and_is_not_affected(self, tmp_path):
        events.reset(); events.configure(tmp_path)
        out = self._report(self._wrecked_run(tmp_path))
        assert "raw artifacts, findings and the other review queues are unaffected" in out
        assert "ownership_state" in out, "and points at the coverage record with the cause"
        assert "ownership_transition.jsonl" in out, "and names the log that is actually damaged"
        events.reset()

    def test_a_healthy_log_carries_no_such_warning(self, tmp_path):
        from quarry_recon import store
        events.reset(); events.configure(tmp_path)
        run = store.Run.create(tmp_path, "t.example")
        run.add("review", {"id": "a", "klass": "exposure", "value": "v"})
        out = self._report(run)
        assert "NOT AUTHORITATIVE" not in out
        events.reset()


class TestAnAmbiguousKeyIsREAD_ONLY:
    def _row(self, key, seq, state, **kw):
        r = {"id": f"ownership:{key}:{seq}", "klass": "acquisition-refused", "state_key": key,
             "state": state, "state_seq": seq, "value": "v", **kw}
        r["state_fp"] = evidence._material(state, r)
        return r

    def test_repeated_refusals_do_not_grow_an_undecidable_key(self, tmp_path):
        """The no-op guard is by definition useless here — the "current" state is undecidable — so the
        key grew a row on every refusal while still reporting `unknown`."""
        from quarry_recon import store
        events.reset(); events.configure(tmp_path)
        run = store.Run.create(tmp_path, "t.example")
        run.add(evidence.OWNERSHIP_ENTITY, self._row("k", 1, "ok"))
        run.add(evidence.OWNERSHIP_ENTITY, self._row("k", 1, "refused"))     # same id -> merged conflict -> ambiguous
        run._records.clear(); run._folded.clear()
        ctx = SimpleNamespace(run=run)
        assert evidence._ownership_state(ctx, "k") == "unknown"
        for _ in range(4):
            assert evidence._publish_state(ctx, "k", "refused", klass="acquisition-refused",
                                           value="v", source="s") is False
        seqs = sorted(r["state_seq"] for r in run.read(evidence.OWNERSHIP_ENTITY)
                      if r.get("state_key") == "k")
        assert seqs == [1], seqs
        events.reset()

    def test_ANOTHER_key_is_still_writable(self, tmp_path):
        """Ambiguity is per path: one undecidable key does not freeze the rest of the log."""
        from quarry_recon import store
        events.reset(); events.configure(tmp_path)
        run = store.Run.create(tmp_path, "t.example")
        run.add(evidence.OWNERSHIP_ENTITY, self._row("k", 1, "ok"))
        run.add(evidence.OWNERSHIP_ENTITY, self._row("k", 1, "refused"))
        run._records.clear(); run._folded.clear()
        ctx = SimpleNamespace(run=run)
        assert evidence._publish_state(ctx, "other", "refused", klass="acquisition-refused",
                                       value="v", source="s") is True
        assert evidence._ownership_state(ctx, "other") == "refused"
        events.reset()


class TestTheOwnershipLogIsISOLATED:
    """review#34 (Lumpy): the transitions shared `normalized/review.jsonl` with unclassified matches,
    source maps, debug endpoints and API documents. One unreadable line anywhere in that file froze
    ownership globally — and the report could not know whether the dropped row had been a transition or
    a finding, so "artifacts and findings are unaffected" was an overclaim."""

    @staticmethod
    def _run(tmp_path):
        from quarry_recon import store
        return store.Run.create(tmp_path, "t.example")

    def _row(self, key, seq, state):
        r = {"id": f"ownership:{key}:{seq}", "klass": "acquisition-refused", "state_key": key,
             "state": state, "state_seq": seq, "value": "v"}
        r["state_fp"] = evidence._material(state, r)
        return r

    def test_transitions_are_written_to_their_own_file(self, tmp_path, monkeypatch):
        _reachable(monkeypatch)
        run = self._run(tmp_path)
        ctx = SimpleNamespace(run=run, profile=SimpleNamespace(http_rl=0), scope=SimpleNamespace(
            in_scope=lambda h: True, is_oos=lambda h: False, active_allowed=lambda h: True))
        dest = run.raw_path("params", "exposed", "t-" + evidence._artifact_id("https://t/.env"))
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"ORPHAN")
        monkeypatch.setattr(fetch, "_open_no_follow", lambda *a, **k: pytest.fail("contacted"))
        evidence.fetch_exposed(ctx, ["https://t/.env"])
        assert run._entity_file(evidence.OWNERSHIP_ENTITY).name == "ownership_transition.jsonl"
        assert [r["state"] for r in run.read(evidence.OWNERSHIP_ENTITY)] == ["refused"]
        assert not [r for r in run.read("review") if r.get("state_key")], \
            "no transition leaked into the shared review queue"

    def test_a_CORRUPT_review_log_does_not_freeze_ownership(self, tmp_path):
        """The isolation that makes the operator-facing statement true."""
        events.reset(); events.configure(tmp_path)
        run = self._run(tmp_path)
        run.add("review", {"id": "unclassified:x", "klass": "unclassified", "value": "v"})
        run.add(evidence.OWNERSHIP_ENTITY, self._row("k", 1, "refused"))
        f = run._entity_file("review")
        f.write_text(f.read_text() + "{not json\n")
        run._records.clear(); run._folded.clear()
        ctx = SimpleNamespace(run=run)
        assert evidence._ownership_state(ctx, "k") == "refused", "ownership is unaffected"
        assert evidence._publish_state(ctx, "k", "ok", klass="ownership-resolved", value="v",
                                       source="s") is True, "and still writable"
        events.reset()

    def test_a_CORRUPT_ownership_log_does_not_hide_the_review_queues(self, tmp_path):
        """…and the other direction, which is what the warning promises."""
        from quarry_recon import triage
        events.reset(); events.configure(tmp_path)
        run = self._run(tmp_path)
        run.add("review", {"id": "unclassified:x", "klass": "unclassified", "value": "MAILER_DSN",
                           "key": "MAILER_DSN", "reason": "key is not secret-shaped",
                           "interest": "high"})
        run.add(evidence.OWNERSHIP_ENTITY, self._row("k", 1, "refused"))
        f = run._entity_file(evidence.OWNERSHIP_ENTITY)
        f.write_text("{not json\n")
        run._records.clear(); run._folded.clear()
        scope = SimpleNamespace(in_scope=lambda h: True, is_oos=lambda h: False,
                                active_allowed=lambda h: True, roots=[], oos=[])
        out = triage.build(run, scope)
        assert "NOT AUTHORITATIVE" in out
        assert triage.markdown_value("MAILER_DSN") in out, \
            "the review evidence really is unaffected — as the warning says"
        assert "ownership_transition.jsonl" in out, "and the warning names the log that is damaged"
        events.reset()
