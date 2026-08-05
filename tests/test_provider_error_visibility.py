"""What a provider REFUSAL tells the operator, and who Quarry says it is when it asks.

Both pinned here because one measurement produced both: on 2026-08-05 the Shodan pivot lane sized two
pivots correctly against the free `/host/count` endpoint and then could not buy a single page. The
terminal said `HTTPError: HTTP Error 403: Forbidden`. The body — already captured on the exception and
surfaced nowhere — was Cloudflare's `<title>Just a moment...</title>`, served because we asked with a
`Mozilla/5.0` User-Agent. The same key, query and encoding succeeded with an ordinary client identifier.
"""
from __future__ import annotations

import io
import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from quarry_recon import contract
from quarry_recon.phases import probe

CF_HTML = ('<!DOCTYPE html><html lang="en-US"><head><title>Just a moment...</title>'
           '<meta http-equiv="Content-Type" content="text/html; charset=UTF-8"></head>'
           '<body><div id="challenge">Enable JavaScript and cookies to continue</div></body></html>')


def _http_error(code: int, body: bytes, url: str = "https://api.shodan.io/shodan/host/search"):
    return urllib.error.HTTPError(url, code, "Forbidden", {}, io.BytesIO(body))


class TestARefusalSaysWhatTheProviderSaid:
    def test_an_HTML_interstitial_is_summarised_by_its_title(self):
        e = _http_error(403, CF_HTML.encode())
        contract.capture_error_body(e, provider="shodan")
        assert contract.error_detail(e) == "Just a moment..."

    def test_a_JSON_error_body_still_wins(self):
        e = _http_error(401, json.dumps({"error": "Invalid API key"}).encode())
        contract.capture_error_body(e, provider="shodan")
        assert contract.error_detail(e) == "Invalid API key"

    def test_a_body_with_no_markup_is_collapsed_to_one_line(self):
        e = _http_error(429, b"  rate limit\n\n   exceeded, retry later  ")
        contract.capture_error_body(e, provider="shodan")
        assert contract.error_detail(e) == "rate limit exceeded, retry later"

    def test_an_empty_body_yields_nothing_rather_than_noise(self):
        e = _http_error(500, b"   ")
        contract.capture_error_body(e, provider="shodan")
        assert contract.error_detail(e) is None
        assert contract.error_detail(RuntimeError("no body at all")) is None

    def test_a_long_body_is_truncated(self):
        e = _http_error(400, ("x" * 5000).encode())
        contract.capture_error_body(e, provider="shodan")
        detail = contract.error_detail(e)
        assert len(detail) <= contract._DETAIL_CHARS + 1 and detail.endswith("…")

    def test_our_OWN_credential_is_redacted_out_of_it(self, monkeypatch):
        """An error body can echo the request that carried our key. Every prose channel goes through the
        same sink; a new one that trusts its input is how one leak becomes permanent."""
        monkeypatch.setattr("quarry_recon.secrets.values", lambda: ["SUPERSECRETKEY"])
        e = _http_error(403, b"denied for key=SUPERSECRETKEY on this plan")
        contract.capture_error_body(e, provider="shodan")
        detail = contract.error_detail(e)
        assert "SUPERSECRETKEY" not in detail and "***" in detail

    def test_the_TERMINAL_carries_the_detail_not_just_the_status(self, tmp_path):
        """The whole point: a status code is what happened, the body is why. This is the string an
        operator actually reads."""
        from quarry_recon import events
        events.reset()
        events.configure(tmp_path)

        def refused():
            e = _http_error(403, CF_HTML.encode())
            contract.capture_error_body(e, provider="shodan")
            raise e

        contract.run_provider("probe.favicon", refused)
        evs = [json.loads(line) for line in (tmp_path / "events.jsonl").read_text().splitlines()]
        term = [e for e in evs if e.get("event") == "tool_finish" and e.get("source_id") == "probe.favicon"]
        assert term, "the lane must still record a terminal"
        reason = term[-1].get("reason") or ""
        assert "403" in reason and "Just a moment" in reason, reason
        events.reset()


class TestQuarryIdentifiesItselfToShodan:
    """A browser User-Agent without a browser's TLS and headers is what a bot filter looks for. This is an
    API we identify ourselves to, not a target we blend into — and the free `shodan_host` lane was already
    sending `quarry-recon` while the PAID path pretended to be Firefox."""

    @staticmethod
    def _capture(monkeypatch) -> list:
        seen = []

        def fake_urlopen(req, timeout=None):
            seen.append(dict(getattr(req, "headers", {}) or {}))
            raise urllib.error.URLError("no network in this test")
        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        return seen

    def test_it_is_not_a_browser(self):
        assert probe.SHODAN_UA == "quarry-recon"
        assert "Mozilla" not in probe.SHODAN_UA

    @pytest.mark.parametrize("call", [
        lambda: probe._shodan_page("K", "http.favicon.hash", "1", 1, sink=Path("/tmp/x.json")),
        lambda: probe._shodan_count("K", "http.favicon.hash", "1"),
        lambda: probe._read_shodan_balance("K", timeout=1),
    ])
    def test_every_shodan_endpoint_asks_as_quarry(self, monkeypatch, call):
        seen = self._capture(monkeypatch)
        call()
        assert seen, "the call must actually have issued a request"
        for headers in seen:
            ua = next((v for k, v in headers.items() if k.lower() == "user-agent"), None)
            # the LITERAL, not `probe.SHODAN_UA`: comparing the sent header to the constant that
            # produced it passes for any value, including the browser string that caused the outage.
            assert ua == "quarry-recon", f"asked as {ua!r}"
            assert "Mozilla" not in (ua or "")

    def test_no_shodan_call_is_left_on_the_browser_identity(self):
        """A single call left behind is where the next challenge lands. Checked per FUNCTION rather than
        over a slice of the module, so an unrelated target-facing call cannot make this pass or fail."""
        import inspect
        for fn in (probe._shodan_page, probe._shodan_count, probe._read_shodan_balance,
                   probe._shodan_host_get):
            src = inspect.getsource(fn)
            assert "Mozilla" not in src, f"{fn.__name__} still asks as a browser"
            assert "User-Agent" not in src or "SHODAN_UA" in src, f"{fn.__name__} sets its own identity"


class TestOurOwnCeilingIsNotTheProvidersFault:
    """MEASURED 2026-08-05, twice, two credits: a 4 MiB read cap truncated Shodan's page mid-string and
    the fragment went to `json.loads`, so the run reported `JSONDecodeError` — Quarry calling its own
    constant a provider defect. The first fix raised the cap to 64 MiB, which is the same mistake with a
    bigger number. A PAID response now has no byte ceiling at all: it is streamed to disk and kept whole.
    What remains bounded is MEMORY (what we will parse in one process) and the FREE endpoints, whose
    responses can be re-read for nothing."""

    class _Response:
        """A STREAM: hands out the body in chunks, then EOF. A fake that returns the whole body on every
        `read()` spins forever against a chunked reader — and pins the buffered shape we removed."""

        def __init__(self, payload: bytes):
            self._payload = payload

        def read(self, n=None):
            if n is None:
                out, self._payload = self._payload, b""
                return out
            out, self._payload = self._payload[:n], self._payload[n:]
            return out

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def _serve(self, monkeypatch, payload: bytes):
        monkeypatch.setattr(urllib.request, "urlopen",
                            lambda req, timeout=None: self._Response(payload))

    def test_a_PAID_page_has_no_byte_ceiling_at_all(self):
        """"If we are already paying, I want to get EVERYTHING I pay for" — the credit is spent before
        any cap can help, so a cap only converts money into incomplete evidence."""
        import inspect
        src = inspect.getsource(probe._shodan_page)
        assert "SHODAN_READ_LIMIT" not in src, "a paid response must not be capped"
        assert "stream_to_file" in src, "it must be streamed to disk, not buffered in memory"

    def test_a_large_page_arrives_WHOLE_and_is_kept(self, monkeypatch, tmp_path):
        big = {"total": 3, "matches": [{"hostnames": [f"h{i}.example"], "pad": "x" * 4096}
                                       for i in range(300)]}
        payload = json.dumps(big).encode()
        assert len(payload) > 1024 * 1024, "the fixture must exceed one streaming chunk"
        self._serve(monkeypatch, payload)
        sink = tmp_path / "page.json"
        rows, total, err = probe._shodan_page("K", "http.favicon.hash", "1", 1, sink=sink)
        assert err is None and total == 3 and len(rows) == 300
        assert sink.read_bytes() == payload, "the artifact IS the response, byte for byte"

    def test_the_artifact_is_published_atomically(self, monkeypatch, tmp_path):
        self._serve(monkeypatch, json.dumps({"total": 1, "matches": []}).encode())
        sink = tmp_path / "page.json"
        probe._shodan_page("K", "http.favicon.hash", "1", 1, sink=sink)
        assert sink.is_file() and not list(tmp_path.glob("*.part")), "no half-written artifact remains"

    def test_a_broken_transport_reports_an_INCOMPLETE_PAID_acquisition(self, monkeypatch, tmp_path):
        """The credit is gone and the bytes are partial. That is its own outcome — not a parse failure,
        and never something to retry automatically."""
        class _Dies:
            def __init__(self):
                self._sent = False

            def read(self, n=None):
                if self._sent:
                    raise OSError("connection reset mid-body")
                self._sent = True
                return b'{"total": 1, "matches": [' + b"x" * 1000

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=None: _Dies())
        sink = tmp_path / "page.json"
        _rows, _total, err = probe._shodan_page("K", "http.favicon.hash", "1", 1, sink=sink)
        assert isinstance(err, contract.IncompleteAcquisition)
        assert contract.provider_error_class(err) == "incomplete"
        assert err.bytes_written > 0 and Path(err.partial).is_file(), "what DID arrive is kept"
        assert not sink.is_file(), "an incomplete body must never be published as the page"

    def test_a_page_too_large_to_PARSE_is_still_acquired_and_kept(self, monkeypatch, tmp_path):
        """The memory bound stops us reading it into RAM; it does not throw the purchase away."""
        monkeypatch.setattr(probe, "SHODAN_PARSE_LIMIT", 256)
        payload = json.dumps({"total": 1, "matches": [{"hostnames": ["a.example"], "pad": "y" * 4096}]})
        self._serve(monkeypatch, payload.encode())
        sink = tmp_path / "page.json"
        rows, total, err = probe._shodan_page("K", "http.favicon.hash", "1", 1, sink=sink)
        assert rows == [] and total is None and err is not None
        assert contract.provider_error_class(err) == contract.PROVIDER_OVERSIZE
        assert "KEPT" in str(err) and "SHODAN_PARSE_LIMIT" in str(err)
        assert sink.read_text() == payload, "the bytes we paid for are on disk, complete"
        assert getattr(err, "raw_path", None) and getattr(err, "raw_bytes", 0) == len(payload)

    def test_a_FREE_endpoint_keeps_its_memory_bound(self, monkeypatch):
        """Nothing was bought, so re-reading costs nothing and a memory bound is honest there."""
        monkeypatch.setattr(probe, "SHODAN_READ_LIMIT", 64)
        self._serve(monkeypatch, b"z" * 5000)
        total, _raw, err = probe._shodan_count("K", "http.favicon.hash", "1")
        assert total is None and contract.provider_error_class(err) == contract.PROVIDER_OVERSIZE

    def test_oversize_is_a_DEFECT_not_a_provider_limit(self):
        assert contract.PROVIDER_OVERSIZE in contract.PROVIDER_CLASSES
        assert not contract.is_provider_limit(contract.PROVIDER_OVERSIZE)
        assert not contract.is_provider_limit("incomplete")


class TestEveryProviderReadSharesTheBound:
    """The Shodan cap was not a Shodan problem: `vertical.py` read censys, crt.sh and certspotter through
    bare 8 MiB caps with the same shape, and crt.sh answers a busy apex with a very large array. One
    helper, so the next provider added cannot reinvent the silent truncation."""

    class _Big:
        def read(self, n=None):
            if getattr(self, '_eof', False):
                return b''                      # STREAM: the body once, then EOF
            self._eof = True
            return b"x" * (n or 1)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def test_no_provider_read_is_a_bare_slice_any_more(self):
        import inspect
        from quarry_recon.phases import vertical
        for mod in (vertical, probe):
            src = inspect.getsource(mod)
            assert "r.read(8 * 1024 * 1024)" not in src
            assert "r.read(4 * 1024 * 1024)" not in src, f"{mod.__name__} still truncates in place"

    def test_each_source_declares_its_own_named_bound(self):
        from quarry_recon.phases import vertical
        for const in ("CENSYS_READ_LIMIT", "CRTSH_READ_LIMIT", "CERTSPOTTER_READ_LIMIT"):
            assert getattr(vertical, const) >= 32 * 1024 * 1024

    def test_the_message_names_the_constant_that_stopped_us(self):
        with pytest.raises(contract.ResponseTooLarge) as caught:
            contract.read_bounded(self._Big(), 10, provider="crt.sh", bound="CRTSH_READ_LIMIT")
        msg = str(caught.value)
        assert "crt.sh" in msg and "CRTSH_READ_LIMIT" in msg and "10 bytes" in msg

    def test_a_sub_megabyte_bound_is_not_reported_as_zero(self):
        with pytest.raises(contract.ResponseTooLarge) as caught:
            contract.read_bounded(self._Big(), 4096, provider="p")
        assert "4 KiB" in str(caught.value)

    def test_the_bytes_read_are_carried_for_preservation(self):
        with pytest.raises(contract.ResponseTooLarge) as caught:
            contract.read_bounded(self._Big(), 64, provider="p")
        assert len(caught.value.body_bytes) == 65
