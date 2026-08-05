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
        lambda: probe._shodan_page("K", "http.favicon.hash", "1", 1),
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
    """MEASURED 2026-08-05, twice, with two credits spent on it: a 4 MiB read cap truncated Shodan's page
    mid-string and the fragment went straight to `json.loads`, so the run reported

        JSONDecodeError: Unterminated string starting at: line 1 column 4194270 (char 4194269)

    4194304 is 4 MiB. Quarry called its own constant a provider defect, and every artifact agreed with
    it. A search page carries up to 100 banners with base64 favicon and certificate blobs; the cap was
    the wrong order of magnitude, and the misattribution was the more expensive half."""

    class _Response:
        def __init__(self, payload: bytes):
            self._payload = payload

        def read(self, n=None):
            return self._payload[:n] if n else self._payload

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def _serve(self, monkeypatch, payload: bytes):
        monkeypatch.setattr(urllib.request, "urlopen",
                            lambda req, timeout=None: self._Response(payload))

    def test_the_cap_is_large_enough_for_a_real_page(self):
        assert probe.SHODAN_READ_LIMIT >= 32 * 1024 * 1024, "4 MiB truncated ordinary favicon pages"

    def test_an_oversize_response_is_classed_as_OURS_not_as_a_parse_failure(self, monkeypatch):
        monkeypatch.setattr(probe, "SHODAN_READ_LIMIT", 512)
        self._serve(monkeypatch, b'{"total": 5, "matches": [' + b'"x" ' * 500 + b']}')
        rows, total, err = probe._shodan_page("K", "http.favicon.hash", "1", 1)
        assert rows == [] and total is None and err is not None
        assert contract.provider_error_class(err) == contract.PROVIDER_OVERSIZE
        assert contract.provider_error_class(err) != contract.PROVIDER_PARSE
        assert "read cap" in str(err) and "SHODAN_READ_LIMIT" in str(err)

    def test_it_says_nothing_was_dropped_silently(self, monkeypatch):
        monkeypatch.setattr(probe, "SHODAN_READ_LIMIT", 64)
        self._serve(monkeypatch, b"x" * 5000)
        _rows, _total, err = probe._shodan_page("K", "http.favicon.hash", "1", 1)
        assert "NOT parsed" in str(err), "a truncated page must never look like an empty one"

    def test_what_we_DID_read_travels_with_the_error(self, monkeypatch):
        monkeypatch.setattr(probe, "SHODAN_READ_LIMIT", 100)
        self._serve(monkeypatch, b"y" * 5000)
        _rows, _total, err = probe._shodan_page("K", "http.favicon.hash", "1", 1)
        assert getattr(err, "body_bytes", None), "a paid response's bytes are evidence"
        assert err.body_bytes.startswith(b"yyy")

    def test_a_page_that_FITS_is_unaffected(self, monkeypatch):
        monkeypatch.setattr(probe, "SHODAN_READ_LIMIT", 4096)
        self._serve(monkeypatch, json.dumps(
            {"total": 2, "matches": [{"ip_str": "203.0.113.1", "hostnames": ["a.example"]}]}).encode())
        rows, total, err = probe._shodan_page("K", "http.favicon.hash", "1", 1)
        assert err is None and total == 2 and len(rows) == 1

    def test_the_count_endpoint_reads_through_the_same_bound(self, monkeypatch):
        monkeypatch.setattr(probe, "SHODAN_READ_LIMIT", 32)
        self._serve(monkeypatch, b'{"total": 12345678901234567890}' * 10)
        total, _raw, err = probe._shodan_count("K", "http.favicon.hash", "1")
        assert total is None and err is not None
        assert contract.provider_error_class(err) == contract.PROVIDER_OVERSIZE

    def test_oversize_is_a_DEFECT_not_a_provider_limit(self):
        """It is our constant, so it must read as a gap to be fixed — never as an external boundary that
        makes an incomplete run look complete_with_limits."""
        assert contract.PROVIDER_OVERSIZE in contract.PROVIDER_CLASSES
        assert not contract.is_provider_limit(contract.PROVIDER_OVERSIZE)


class TestEveryProviderReadSharesTheBound:
    """The Shodan cap was not a Shodan problem: `vertical.py` read censys, crt.sh and certspotter through
    bare 8 MiB caps with the same shape, and crt.sh answers a busy apex with a very large array. One
    helper, so the next provider added cannot reinvent the silent truncation."""

    class _Big:
        def read(self, n=None):
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
