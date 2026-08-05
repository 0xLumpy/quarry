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
