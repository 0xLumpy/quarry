"""C06 — in-process provider error CLASSES.

A FAILED provider terminal must say WHY (auth vs quota vs transport vs parse vs server), so a consumer can
tell a real failure from 'nothing found' and pick retry/backoff. classify_provider_error maps the raised
exception; run_provider tags the terminal's error_class. A clean/empty result carries NO error_class.
"""
import json
import socket
import urllib.error

import pytest

from quarry_recon import contract, events
from quarry_recon.contract import classify_provider_error

pytestmark = pytest.mark.offline


@pytest.fixture(autouse=True)
def _events(tmp_path):
    events.reset(); events.configure(tmp_path)
    yield
    events.reset()


def _terminal(tmp_path):
    evs = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
    return [e for e in evs if e["event"] == "tool_finish"][0]


def _http(code):
    return urllib.error.HTTPError("http://x", code, "msg", {}, None)


class TestClassifier:
    @pytest.mark.parametrize("exc,cls", [
        (_http(401), "auth"), (_http(403), "auth"),
        (_http(429), "quota"),
        (_http(500), "server"), (_http(503), "server"),
        (_http(418), "http"),
        (urllib.error.URLError("dns boom"), "transport"),
        (socket.timeout("slow"), "transport"),
        (TimeoutError("slow"), "transport"),
        (ConnectionResetError("reset"), "transport"),
        (json.JSONDecodeError("bad", "doc", 0), "parse"),
        (ValueError("schema drift"), "parse"),
        (RuntimeError("weird"), "error"),
    ])
    def test_maps_exception_to_class(self, exc, cls):
        assert classify_provider_error(exc) == cls

    def test_httperror_precedence_over_oserror(self):
        # HTTPError is an OSError subclass — must classify by HTTP code, not fall through to transport
        assert classify_provider_error(_http(403)) == "auth"


class TestRunProviderTagsErrorClass:
    def test_auth_failure_tagged(self, tmp_path):
        def boom():
            raise _http(403)
        assert contract.run_provider("vertical.crtsh", boom) is None
        t = _terminal(tmp_path)
        assert t["status"] == "failed" and t["error_class"] == "auth"

    def test_quota_failure_tagged(self, tmp_path):
        def boom():
            raise _http(429)
        contract.run_provider("vertical.crtsh", boom)
        assert _terminal(tmp_path)["error_class"] == "quota"

    def test_transport_failure_tagged(self, tmp_path):
        def boom():
            raise urllib.error.URLError("connection refused")
        contract.run_provider("vertical.crtsh", boom)
        assert _terminal(tmp_path)["error_class"] == "transport"

    def test_parse_failure_tagged(self, tmp_path):
        def boom():
            raise ValueError("non-list JSON root")
        contract.run_provider("vertical.crtsh", boom)
        assert _terminal(tmp_path)["error_class"] == "parse"

    def test_success_has_no_error_class(self, tmp_path):
        contract.run_provider("vertical.crtsh", lambda: {"a", "b"})
        assert "error_class" not in _terminal(tmp_path)         # None fields are dropped by emit

    def test_empty_has_no_error_class(self, tmp_path):
        contract.run_provider("vertical.crtsh", lambda: set())
        t = _terminal(tmp_path)
        assert t["status"] == "empty" and "error_class" not in t
