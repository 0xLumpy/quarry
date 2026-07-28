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
        # B0: 401 (bad key) and 403 (plan/entitlement) are DIFFERENT operator actions; 429 is a RATE
        # LIMIT, not spent credits. Quota is proven from a body/balance and can never come from a code.
        (_http(401), "auth"), (_http(403), "forbidden"),
        (_http(429), "rate_limit"),
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
        assert classify_provider_error(_http(403)) == "forbidden"

    def test_no_http_status_can_produce_quota(self):
        """Quota is an account-balance fact, provable only from a provider body or balance endpoint.
        Whoxy reports a spent account inside an HTTP 200, so no status code implies it."""
        codes = [200, 400, 401, 402, 403, 404, 418, 429, 500, 503]
        assert all(classify_provider_error(_http(c)) != "quota" for c in codes)


class TestRunProviderTagsErrorClass:
    def test_auth_failure_tagged(self, tmp_path):
        def boom():
            raise _http(401)
        assert contract.run_provider("vertical.crtsh", boom) is None
        t = _terminal(tmp_path)
        assert t["status"] == "failed" and t["error_class"] == "auth"

    def test_forbidden_failure_tagged(self, tmp_path):
        """A 403 is NEUTRAL: a WAF, an IP allow-list and a plan limit all produce it, so it stays a plain
        failure. Only provider EVIDENCE may promote it to the `entitlement` LIMIT."""
        def boom():
            raise _http(403)
        assert contract.run_provider("vertical.crtsh", boom) is None
        assert _terminal(tmp_path)["error_class"] == "forbidden"

    def test_rate_limit_failure_tagged(self, tmp_path):
        def boom():
            raise _http(429)
        contract.run_provider("vertical.crtsh", boom)
        assert _terminal(tmp_path)["error_class"] == "rate_limit"

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


def _all(tmp_path, event):
    evs = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
    return [e for e in evs if e["event"] == event]


class TestSharedLaneBracket:
    """`run_providers` brackets SEVERAL lanes around one shared body — the shape a coordinator that
    spends a single credit budget across lanes needs. Every lane must start before the body runs and
    finish afterwards, whatever the body does."""

    def _entries(self, *sids):
        return [(sid, f"wu-{sid}", lambda s=sid: {f"h.{s}"}) for sid in sids]

    def test_every_lane_starts_before_the_shared_body(self, tmp_path):
        order = []
        contract.run_providers(self._entries("vertical.crtsh", "vertical.certspotter"),
                               lambda: order.append("shared"))
        starts = _all(tmp_path, "tool_start")
        assert len(starts) == 2 and len(_all(tmp_path, "tool_finish")) == 2
        assert order == ["shared"]

    def test_CANCELLATION_in_the_shared_body_still_finishes_EVERY_lane(self, tmp_path):
        """review-B1.4r4#1: `_provider_terminal` re-raises cancellation past its own finally, so the
        first lane's re-raise ended the loop and left every later lane permanently started."""
        def cancel():
            raise KeyboardInterrupt("ctrl-c mid-spend")

        with pytest.raises(KeyboardInterrupt):
            contract.run_providers(self._entries("vertical.crtsh", "vertical.certspotter"), cancel)
        fins = {e["source_id"] for e in _all(tmp_path, "tool_finish")}
        assert fins == {"vertical.crtsh", "vertical.certspotter"}, fins
        assert all(e["status"] == "failed" for e in _all(tmp_path, "tool_finish"))

    def test_CANCELLATION_in_the_FIRST_finalizer_still_finishes_the_rest(self, tmp_path):
        """The half the shared-body test cannot see: the cancellation arrives lane by lane."""
        def boom():
            raise SystemExit("cancelled while finalizing")

        entries = [("vertical.crtsh", "wu-a", boom),
                   ("vertical.certspotter", "wu-b", lambda: {"h.ok"})]
        with pytest.raises(SystemExit):
            contract.run_providers(entries, lambda: None)
        fins = {e["source_id"]: e for e in _all(tmp_path, "tool_finish")}
        assert set(fins) == {"vertical.crtsh", "vertical.certspotter"}, fins
        assert fins["vertical.certspotter"]["status"] == "success", fins["vertical.certspotter"]

    def test_an_ORDINARY_shared_failure_stays_inside_the_best_effort_contract(self, tmp_path):
        """review-B1.4r4#4: this caught BaseException and always re-raised, so an ordinary failure in
        shared setup aborted the surrounding PHASE — while single-lane `run_provider` records FAILED and
        returns None. Best-effort is the provider contract; only cancellation propagates."""
        def broken():
            raise RuntimeError("shared setup exploded")

        out = contract.run_providers(self._entries("vertical.crtsh", "vertical.certspotter"), broken)
        assert out == {"vertical.crtsh": None, "vertical.certspotter": None}
        fins = _all(tmp_path, "tool_finish")
        assert len(fins) == 2 and all(e["status"] == "failed" for e in fins), fins
        assert all(e.get("error_class") for e in fins), fins

    def test_an_unknown_source_id_is_blocked_and_never_finalized(self, tmp_path):
        out = contract.run_providers(self._entries("vertical.crtsh", "not.a.source"), lambda: None)
        assert set(out) == {"vertical.crtsh"}
        assert [e["source_id"] for e in _all(tmp_path, "tool_blocked")] == ["not.a.source"]


class TestPartialPrecedence:
    """review-B1.4r5#1: `limited` meant different things in the two partial branches, and where it was
    read it OUTRANKED a real failure. One precedence, applied identically to both."""

    def _term(self, tmp_path, result):
        contract.run_provider("vertical.crtsh", lambda: result)
        return _terminal(tmp_path)

    def test_limited_without_partial_can_never_be_SUCCESS(self, tmp_path):
        """A limit IS incompleteness. `limited=True, partial=False` silently reported a complete run."""
        r = contract.ProviderResult({"h.acme.com"}, limited=True)
        assert r.partial is True and r.partial_kind == "degraded"
        assert self._term(tmp_path, r)["status"] == "limited"

    def test_limited_does_not_inherit_the_PAGINATION_default(self, tmp_path):
        """`partial_kind` defaulted to "pagination", so a bare limited result fabricated a cursor reason
        it had no basis for — the case Whoxy pagination would have walked straight into."""
        t = self._term(tmp_path, contract.ProviderResult({"h.acme.com"}, partial=True, limited=True))
        assert t["status"] == "limited", t
        assert "TRUNCATED at None" not in (t.get("reason") or ""), t["reason"]

    def test_a_real_failure_OUTRANKS_a_limit_flag(self, tmp_path):
        """Gaps dominate limits: an operator bound alongside a transport failure is still degraded."""
        t = self._term(tmp_path, contract.ProviderResult(
            {"h.acme.com"}, partial=True, partial_kind="degraded", limited=True,
            error_class="transport"))
        assert t["status"] == "partial" and t["error_class"] == "transport", t

    def test_a_real_failure_outranks_a_limit_in_the_PAGINATION_branch_too(self, tmp_path):
        t = self._term(tmp_path, contract.ProviderResult(
            {"h.acme.com"}, partial=True, partial_kind="pagination", limited=True,
            error_class="transport", pages=2, cursor="c"))
        assert t["status"] == "partial" and t["error_class"] == "transport", t

    def test_a_PROVEN_provider_limit_still_wins_in_both_branches(self, tmp_path):
        for kind in ("pagination", "degraded"):
            t = self._term(tmp_path, contract.ProviderResult(
                {"h.acme.com"}, partial=True, partial_kind=kind, error_class="quota", pages=1))
            assert t["status"] == "limited", (kind, t)
            events.reset(); events.configure(tmp_path)

    def _cov(self, tmp_path, measure):
        return [e for e in _all(tmp_path, "coverage_partial") if e["measure"] == measure]

    def test_an_EXPLICIT_pagination_limit_is_LIMITED_too(self, tmp_path):
        """The branch the default-kind test can no longer reach: a paginating provider whose truncation
        was OUR deliberate bound, not a failure and not the provider refusing us."""
        t = self._term(tmp_path, contract.ProviderResult(
            {"h.acme.com"}, partial=True, partial_kind="pagination", limited=True, pages=2,
            cursor="next"))
        assert t["status"] == "limited" and t.get("error_class") is None, t
        # review-B1.4r6#1: the COVERAGE kind must say the same thing the terminal does. Derived from the
        # status, every limited outcome claimed the PROVIDER refused us.
        assert self._cov(tmp_path, "pagination")[0]["kind"] == "sample", self._cov(tmp_path, "pagination")

    def test_pagination_coverage_names_the_RIGHT_cause_in_every_case(self, tmp_path):
        """One precedence, asserted end to end: failure > provider limit > operator bound > our cap."""
        cases = [
            (dict(error_class="transport"), "timeout"),      # a later page was LOST
            (dict(error_class="quota"), "provider"),         # the provider refused us
            (dict(limited=True), "sample"),                  # WE stopped on purpose
            (dict(), "cap"),                                 # our configured ceiling
            (dict(limited=True, error_class="transport"), "timeout"),   # gaps dominate bounds
            (dict(limited=True, error_class="quota"), "provider"),      # proven beats deliberate
        ]
        for kwargs, want in cases:
            events.reset(); events.configure(tmp_path)
            (tmp_path / "events.jsonl").write_text("")
            self._term(tmp_path, contract.ProviderResult(
                {"h.acme.com"}, partial=True, partial_kind="pagination", pages=2, cursor="n", **kwargs))
            got = self._cov(tmp_path, "pagination")[0]["kind"]
            assert got == want, f"{kwargs} -> {got}, expected {want}"

    def test_an_ordinary_truncation_is_still_PARTIAL(self, tmp_path):
        """The control: incomplete, nothing broke, nobody refused — our own cap."""
        t = self._term(tmp_path, contract.ProviderResult({"h.acme.com"}, partial=True, pages=3,
                                                         cursor="next"))
        assert t["status"] == "partial" and t.get("error_class") is None, t
