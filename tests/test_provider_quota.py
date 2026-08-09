"""B0 — shared provider-outcome taxonomy + Whoxy status-envelope parsing.

Provider quota exhaustion is not a Quarry error and not a defect, but it IS incomplete coverage: it must
read as an external LIMIT, never as a failure and never as a clean zero.

The Whoxy payloads below are MEASURED against the live API (2026-07-27), not invented — including the
detail that makes the whole class of bug possible: Whoxy reports a spent account inside an HTTP **200**.
"""
import pathlib
import json
import urllib.error

import pytest

import pathlib

from quarry_recon import contract, osint, secrets, settings, whoxy_page
from quarry_recon.contract import (PROVIDER_ENTITLEMENT, PROVIDER_FORBIDDEN, PROVIDER_QUOTA,
                                   PROVIDER_RATE_LIMIT, ProviderBodyError, classify_provider_error,
                                   classify_provider_reason, is_provider_limit, whoxy_envelope,
                                   whoxy_reverse_page, whoxy_reverse_rows)
from quarry_recon.runner import Status

pytestmark = pytest.mark.offline


@pytest.fixture(autouse=True)
def _never_touch_the_real_spend_lock(tmp_path, monkeypatch):
    """The Whoxy spend lock is installation-wide — the operator's own `~/.config/quarry`."""
    monkeypatch.setattr(whoxy_page, "SPEND_LOCK", tmp_path / "install-spend.lock")

# ── MEASURED Whoxy payloads (all HTTP 200) ────────────────────────────────────────────────────────
WHOXY_EXHAUSTED = '{"status": 0, "status_reason": "Zero Account Balance"}'
WHOXY_BALANCE = ('{"status": 1, "live_whois_balance": 0, "whois_history_balance": 0, '
                 '"reverse_whois_balance": 0}')
# schema-shaped from Whoxy's published reverse-whois JSON schema (total_results + search_result), NOT one
# of the two live-measured payloads above — flagged so nobody mistakes it for ground truth.
# review-B1.6r5#1: every reverse-whois response owes the ENDPOINT and REQUEST binding, not just the
# compact empty one — so the shared fixture carries them, and callers pass what they asked for.
WHOXY_ANCHOR = ("company", "Acme")
WHOXY_OK = ('{"status": 1, "api_query": "reverse_whois", "search_identifier": {"company": "Acme"}, '
            '"total_results": 2, "current_page": 1, "total_pages": 1, '
            '"search_result": [{"domain_name": "a.com"}, {"domain_name": "b.com"}]}')


def _bound(doc, param="company", value="Acme"):
    """Add the binding a real response always carries, so a fixture tests the shape under scrutiny
    rather than the absence of a field."""
    out = dict(doc)
    out.setdefault("api_query", "reverse_whois")
    out.setdefault("search_identifier", {param: value})
    return out


# MEASURED 2026-07-27 — a genuine reverse-whois NO-MATCH, verbatim from the live API (HTTP 200). Note what
# is ABSENT: no `search_result`, no `current_page`, no `total_pages`. The reverse-whois balance was 200
# before and after this query, so THIS no-match consumed no credit (recorded as an observation about this
# call — NOT a general claim that Whoxy queries are free).
WHOXY_NO_MATCH = ('{"status": 1, "api_query": "reverse_whois", '
                  '"search_identifier": {"company": "quarry-contract-no-match-1785160485"}, '
                  '"total_results": 0, "api_execution_time": 0.01}')

# NOT MEASURED: a synthetic UNRECOGNISED failure reason, used only to exercise the generic-error path.
# (Whoxy's genuine no-match body IS now measured — see WHOXY_NO_MATCH above.)
WHOXY_UNKNOWN_FAILURE = '{"status": 0, "status_reason": "Synthetic Unrecognised Failure"}'


def _http(code):
    return urllib.error.HTTPError("http://x", code, "msg", {}, None)


class TestTaxonomy:
    def test_401_and_403_are_different_actions(self):
        """A bad key and a refused request need different operator responses; one label loses that."""
        assert classify_provider_error(_http(401)) != classify_provider_error(_http(403))

    def test_403_is_forbidden_not_entitlement(self):
        """A WAF, an IP allow-list, a permission error and a malformed request all return 403. Calling
        any of them 'entitlement' would let a real defect pass the run as an expected plan limit."""
        assert classify_provider_error(_http(403)) == PROVIDER_FORBIDDEN
        assert not is_provider_limit(classify_provider_error(_http(403)))

    def test_no_status_code_can_produce_a_limit(self):
        """Both LIMIT classes are claims that need provider evidence — a code can never establish one."""
        codes = [200, 400, 401, 402, 403, 404, 409, 418, 429, 451, 500, 502, 503]
        assert all(not is_provider_limit(classify_provider_error(_http(c))) for c in codes)

    def test_429_is_a_rate_limit_not_spent_credits(self):
        """Being told to slow down says nothing about the balance — the credits may be fully intact."""
        assert classify_provider_error(_http(429)) == PROVIDER_RATE_LIMIT

    def test_quota_is_never_derived_from_a_status_code(self):
        codes = [200, 400, 401, 402, 403, 404, 409, 418, 429, 500, 502, 503]
        assert all(classify_provider_error(_http(c)) != PROVIDER_QUOTA for c in codes)

    def test_limits_are_separable_from_failures(self):
        assert is_provider_limit(PROVIDER_QUOTA) and is_provider_limit(PROVIDER_ENTITLEMENT)
        for cls in ("auth", "forbidden", "rate_limit", "transport", "server", "parse", "http", "error"):
            assert not is_provider_limit(cls)


class TestWhoxyEnvelope:
    def test_success_envelope_passes_through(self):
        assert whoxy_envelope(json.loads(WHOXY_OK))["total_results"] == 2

    def test_balance_envelope_is_a_success(self):
        """`account=balance` is free and reports THREE independent service balances."""
        doc = whoxy_envelope(json.loads(WHOXY_BALANCE))
        assert doc["reverse_whois_balance"] == 0 and doc["live_whois_balance"] == 0

    def test_exhausted_account_raises_quota_not_empty(self):
        with pytest.raises(ProviderBodyError) as e:
            whoxy_envelope(json.loads(WHOXY_EXHAUSTED))
        assert e.value.error_class == PROVIDER_QUOTA
        assert e.value.reason == "Zero Account Balance"          # verbatim, never paraphrased

    def test_unknown_failure_reason_is_an_error_not_a_limit(self):
        """Fail-closed in the direction that keeps problems visible: calling an unrecognised failure a
        'limit' would let a real defect pass as an expected boundary."""
        with pytest.raises(ProviderBodyError) as e:
            whoxy_envelope({"status": 0, "status_reason": "Invalid API Key"})
        assert e.value.error_class == "error" and e.value.reason == "Invalid API Key"
        assert not is_provider_limit(e.value.error_class)

    def test_missing_reason_still_fails_loudly(self):
        with pytest.raises(ProviderBodyError) as e:
            whoxy_envelope({"status": 0})
        assert "status=0" in e.value.reason

    def test_non_object_body_is_a_parse_failure(self):
        with pytest.raises(ProviderBodyError) as e:
            whoxy_envelope([1, 2, 3])
        assert e.value.error_class == "parse"

    @pytest.mark.parametrize("status", [True, 1.0, "1", None])
    def test_success_status_must_be_an_exact_int(self, status):
        """`True == 1` in Python, so a bool sailed through as success. So did a float and a string."""
        with pytest.raises(ProviderBodyError) as e:
            whoxy_envelope({"status": status, "search_result": []})
        assert e.value.error_class == "parse"


class TestWhoxyRequestBinding:
    """review-B1.6r5#1: the endpoint and request binding lived on the COMPACT empty shape only, so a
    PAGED body could arrive answering a different question — or no identifiable question — and its rows
    became confident domain results. The live lane calls this parser directly, so the enforcement has to
    be here, where every caller gets it."""

    def _page(self, **over):
        doc = {"status": 1, "api_query": "reverse_whois", "search_identifier": {"company": "Acme"},
               "total_results": 1, "current_page": 1, "total_pages": 1,
               "search_result": [{"domain_name": "a.com"}]}
        doc.update(over)
        for k, v in list(over.items()):
            if v is None:
                doc.pop(k, None)
        return doc

    @pytest.mark.parametrize("over", [
        {"api_query": None},                            # no endpoint at all
        {"api_query": "account_balance"},               # a DIFFERENT endpoint's answer
        {"api_query": "whois_history"},
        {"search_identifier": None},                    # nothing tying it to a question
        {"search_identifier": {"company": "Other Co"}},  # someone ELSE's answer
        {"search_identifier": {"company": "Acme", "email": "x@y.z"}},   # extra keys
        {"search_identifier": {"email": "Acme"}},       # right value, wrong param
    ])
    def test_a_PAGED_body_that_is_not_our_answer_is_rejected(self, over):
        with pytest.raises(ProviderBodyError) as e:
            whoxy_reverse_page(whoxy_envelope(self._page(**over)), page=1,
                               param="company", value="Acme")
        assert e.value.error_class == "parse", e.value.reason

    def test_our_own_answer_is_accepted(self):
        rows, total, truncated = whoxy_reverse_page(whoxy_envelope(self._page()), page=1,
                                                    param="company", value="Acme")
        assert rows == ["a.com"] and total == 1 and truncated is False

    @pytest.mark.parametrize("param,value", [(None, "Acme"), ("company", None), ("nickname", "Acme"),
                                             ("company", ""), ("company", 5)])
    def test_a_caller_that_cannot_state_its_request_gets_nothing(self, param, value):
        """A response can only be bound to a question the caller actually names."""
        with pytest.raises(ProviderBodyError):
            whoxy_reverse_page(whoxy_envelope(self._page()), page=1, param=param, value=value)


class TestWhoxyTotalResults:
    """MEASURED 2026-07-29: Whoxy varies the TYPE of `total_results` by value — int `0` on a no-match,
    the string `"39766"` on a non-empty answer. The int-only check fail-closed on every query that
    actually found something, which B0 never saw because it had only ever measured the empty case."""

    def test_the_MEASURED_string_form_is_accepted(self):
        assert contract.whoxy_total("39766") == 39766
        assert contract.whoxy_total(0) == 0 and contract.whoxy_total(39766) == 39766

    @pytest.mark.parametrize("bad", [
        True, False,                      # bool is an int subclass; `True` is not a count
        -1, "-1", "+1",                   # signed
        " 39766", "39766\n", "39 766",    # whitespace / separators
        "0039766", "007",                 # non-canonical: one value, one spelling
        "", "abc", "3.9e4", "39766.0",    # not a decimal integer at all
        "٣٩", "³⁹",                       # Unicode digits — `str.isdigit()` accepts these
        None, [], {}, 3.0,
    ])
    def test_anything_NOT_a_canonical_decimal_is_unusable(self, bad):
        assert contract.whoxy_total(bad) is None, bad

    def test_the_STRING_zero_is_an_UNMEASURED_shape(self):
        """review-B1.6r1#1: what was measured is exact — an EMPTY answer carries the INTEGER 0, a
        non-empty one carries a string. Accepting `"0"` would send an unmeasured body down the
        zero-result path and produce a clean EMPTY from a shape we have never seen."""
        assert contract.whoxy_total(0) == 0            # the measured empty
        assert contract.whoxy_total("0") is None       # never measured; not a licence to invent one
        assert contract.whoxy_total("00") is None

    @pytest.mark.parametrize("doc", [
        # the compact shape, which would otherwise have been read as "this query found nothing"
        {"status": 1, "api_query": "reverse_whois",
         "search_identifier": {"company": "Acme"}, "total_results": "0"},
        # and the paged shape, which reaches the cardinality check itself
        {"status": 1, "api_query": "reverse_whois", "search_identifier": {"company": "Acme"},
         "total_results": "0", "current_page": 1, "total_pages": 1, "search_result": []},
    ])
    def test_a_string_zero_body_fails_CLOSED_rather_than_reading_as_empty(self, doc):
        """The property, not the wording: a `"0"` body must never come back as a clean empty result."""
        with pytest.raises(contract.ProviderBodyError) as e:
            contract.whoxy_reverse_page(contract.whoxy_envelope(doc), page=1,
                                        param="company", value="Acme")
        assert e.value.error_class == contract.PROVIDER_PARSE, e.value.error_class

    @pytest.mark.parametrize("n", [16, 4301, 5000])
    def test_an_OVERLONG_digit_string_returns_None_and_never_RAISES(self, n):
        """review-B1.6r1#2: CPython refuses to convert an over-long decimal string, so a long run of
        digits passed the character check and then made `int()` raise — breaking the one promise this
        function makes, that unusable input comes back as None."""
        assert contract.whoxy_total("1" * n) is None

    def test_the_bound_is_generous_enough_for_any_real_count(self):
        assert contract.whoxy_total("1" * 15) == int("1" * 15)

    def test_a_REAL_measured_page_parses(self):
        """The live body that production used to reject, as a fixture."""
        doc = {"status": 1, "api_query": "reverse_whois",
               "search_identifier": {"company": "Deutsche Telekom AG"},
               "total_results": "39766", "total_pages": 398, "current_page": 1,
               "search_result": [{"domain_name": f"d{i}.example.com"} for i in range(100)]}
        rows, total, truncated = contract.whoxy_reverse_page(
            contract.whoxy_envelope(doc), page=1, param="company", value="Deutsche Telekom AG")
        assert len(rows) == 100 and total == 39766 and truncated is True

    def test_a_garbled_total_still_fails_CLOSED(self):
        doc = {"status": 1, "api_query": "reverse_whois",
               "search_identifier": {"company": "Acme"}, "total_results": "3 9766",
               "total_pages": 1, "current_page": 1,
               "search_result": [{"domain_name": "a.example.com"}]}
        with pytest.raises(contract.ProviderBodyError) as e:
            contract.whoxy_reverse_page(contract.whoxy_envelope(doc), page=1,
                                        param="company", value="Acme")
        assert "no usable total_results" in e.value.reason and "'3 9766'" in e.value.reason


class TestWhoxyResultSchema:
    def test_bodiless_success_is_schema_drift_not_an_empty_answer(self):
        """`{"status": 1}` alone used to read as a confident empty result. The documented success body
        carries `search_result`; a body without it is drift, and drift must never look like 'no matches'."""
        with pytest.raises(ProviderBodyError) as e:
            whoxy_reverse_rows(whoxy_envelope({"status": 1}))
        assert e.value.error_class == "parse"

    def test_valid_rows_are_normalised(self):
        rows = whoxy_reverse_rows(json.loads(WHOXY_OK))
        assert rows == ["a.com", "b.com"]

    def test_documented_alternate_shape_is_accepted(self):
        assert whoxy_reverse_rows({"status": 1, "domainsList": ["A.com"]}) == ["a.com"]

    @pytest.mark.parametrize("rows", [
        [None], ["a.com"], [{"domain_name": None}], [{"domain_name": ""}],
        [{"domain_name": "not-a-domain"}], [{"no_domain": "x"}],
        # review-B0r2#6: "contains a dot" admitted all of these as APEX CANDIDATES
        [{"domain_name": "a..b"}], [{"domain_name": "../evil.com"}],
        [{"domain_name": "http://evil.com"}], [{"domain_name": "ev il.com"}],
        [{"domain_name": "a.com/../../etc"}],
    ])
    def test_malformed_rows_raise_instead_of_becoming_candidates(self, rows):
        """A `None` domain used to become a candidate; a non-dict row raised deep inside the caller; a
        path- or URL-shaped value is a traversal primitive the moment anything derives a filename."""
        with pytest.raises(ProviderBodyError) as e:
            whoxy_reverse_rows({"status": 1, "search_result": rows})
        assert e.value.error_class == "parse"

    def test_pagination_shortfall_is_surfaced(self):
        """`total_results` is the provider's own count: a page holding fewer rows is PAGINATED, and
        reporting the page as the whole answer silently loses the rest."""
        doc = {"status": 1, "total_results": 50, "current_page": 1, "total_pages": 1,
               "search_result": [{"domain_name": "a.com"}]}
        rows, total, truncated = whoxy_reverse_page(_bound(doc), param="company", value="Acme")
        assert rows == ["a.com"] and total == 50 and truncated is True

    def test_complete_page_is_not_flagged_truncated(self):
        rows, total, truncated = whoxy_reverse_page(json.loads(WHOXY_OK), param="company", value="Acme")
        assert len(rows) == 2 and total == 2 and truncated is False

    # MEASURED 2026-07-29: `"12"` was in this list, asserting that a decimal STRING is unusable — and
    # a canonical decimal string is exactly what Whoxy sends for every non-empty answer. The case was
    # written from the documented schema, so it pinned the bug rather than catching it. Non-canonical
    # strings are still unusable and are covered by TestWhoxyTotalResults.
    @pytest.mark.parametrize("total", [None, " 12", "-1", -1, True, 1.5])
    def test_unusable_cardinality_fails_closed(self, total):
        """review-B0r2#4: 'no cardinality claim' let a drifted body finish CLEAN — the same fail-open
        shape as the original false empty, one level up. The documented success schema carries
        total_results, so its absence or corruption is drift, not a complete answer."""
        doc = {"status": 1, "current_page": 1, "total_pages": 1,
               "search_result": [{"domain_name": "a.com"}]}
        if total is not None:
            doc["total_results"] = total
        with pytest.raises(ProviderBodyError) as e:
            whoxy_reverse_page(_bound(doc), param="company", value="Acme")
        assert e.value.error_class == "parse"

    def test_absent_total_fails_even_with_zero_rows(self):
        """Pins the absence guard INDEPENDENTLY: with rows present, the total<rows check would mask it,
        so a mutation deleting this guard still passed. An empty page with no cardinality is still drift."""
        with pytest.raises(ProviderBodyError) as e:
            whoxy_reverse_page(_bound({"status": 1, "current_page": 1, "total_pages": 1,
                                       "search_result": []}), param="company", value="Acme")
        assert e.value.error_class == "parse"

    def test_total_smaller_than_rows_is_incoherent(self):
        with pytest.raises(ProviderBodyError) as e:
            whoxy_reverse_page(_bound({"status": 1, "total_results": 1, "current_page": 1,
                                       "total_pages": 1,
                                       "search_result": [{"domain_name": "a.com"},
                                                         {"domain_name": "b.com"}]}),
                               param="company", value="Acme")
        assert e.value.error_class == "parse"

    @pytest.mark.parametrize("page,pages", [(0, 2), (2, 1), ("1", 2), (1, 0), (True, 2), (None, 1),
                                            (1, None)])
    def test_incoherent_or_missing_page_position_fails_closed(self, page, pages):
        """review-B0r3#4: validated-only-if-present let a body missing BOTH fields through unchecked."""
        doc = {"status": 1, "total_results": 1, "search_result": [{"domain_name": "a.com"}]}
        if page is not None:
            doc["current_page"] = page
        if pages is not None:
            doc["total_pages"] = pages
        with pytest.raises(ProviderBodyError) as e:
            whoxy_reverse_page(_bound(doc), param="company", value="Acme")
        assert e.value.error_class == "parse"

    def test_a_response_for_a_different_page_is_rejected(self):
        """Accepting page 2 for a page-1 request silently attributes one slice of the answer to another."""
        doc = {"status": 1, "total_results": 200, "current_page": 2, "total_pages": 2,
               "search_result": [{"domain_name": "a.com"}]}
        with pytest.raises(ProviderBodyError) as e:
            whoxy_reverse_page(_bound(doc), page=1, param="company", value="Acme")
        assert e.value.error_class == "parse"
        rows, _total, truncated = whoxy_reverse_page(_bound(doc), page=2, param="company", value="Acme")     # correct request -> accepted
        assert rows == ["a.com"] and truncated is True

    def test_multiple_pages_is_truncated_even_when_the_count_fits(self):
        """`total_pages > 1` is itself a shortfall claim — the count alone can agree while pages remain."""
        doc = {"status": 1, "total_results": 1, "current_page": 1, "total_pages": 3,
               "search_result": [{"domain_name": "a.com"}]}
        _rows, _total, truncated = whoxy_reverse_page(_bound(doc), param="company", value="Acme")
        assert truncated is True

    def test_genuinely_empty_page_is_accepted(self):
        rows, total, truncated = whoxy_reverse_page(
            _bound({"status": 1, "total_results": 0, "current_page": 1, "total_pages": 1,
                    "search_result": []}), param="company", value="Acme")
        assert rows == [] and total == 0 and truncated is False

    def test_reason_matching_is_exact_not_substring(self):
        assert classify_provider_reason("whoxy", "Zero Account Balance") == PROVIDER_QUOTA
        assert classify_provider_reason("whoxy", "  zero   account balance  ") == PROVIDER_QUOTA
        # a substring test cannot tell a message from its own NEGATION
        assert classify_provider_reason("whoxy", "Non-zero Account Balance") == "error"
        assert classify_provider_reason("whoxy", "Zero Account Balance Restored") == "error"
        assert classify_provider_reason("whoxy", "Domain Not Found") == "error"
        assert classify_provider_reason("shodan", "Zero Account Balance") == "error"   # per-provider


# ── the false-empty regression ────────────────────────────────────────────────────────────────────
class _Sess:
    def __init__(self, tmp_path):
        self.dir = tmp_path
        # B1.6b: page ownership is DURABLE and lives beside the timestamped sessions, so the lane needs
        # the project root as well as this session's directory.
        self.project_dir = tmp_path / "project"
        self.cands = []
        self.recorded = []

    def raw_path(self, source, name):
        p = self.dir / "raw" / source
        p.mkdir(parents=True, exist_ok=True)
        return p / name

    def candidate(self, value, ctype, source, hint, reason, raw_ref=None, manual_followup=None):
        self.cands.append(value)

    def record(self, result):
        self.recorded.append(result)


def _echo_request(body, url):
    """Stamp `api_query` + `search_identifier` onto a scripted body from the URL that asked for it,
    unless the fixture set them deliberately."""
    import urllib.parse as _up
    try:
        doc = json.loads(body)
    except Exception:
        return body
    if not isinstance(doc, dict) or doc.get("status") != 1:
        return body                      # a failure envelope carries no identity, and the real one
                                         # does not add one — leave it exactly as scripted
    q = _up.parse_qs(_up.urlsplit(url).query)
    for param in ("company", "email"):
        if param in q:
            doc["api_query"] = "reverse_whois"
            doc["search_identifier"] = {param: q[param][0]}   # ALWAYS the question actually asked
            break
    return json.dumps(doc)


def _whoxy_provider(monkeypatch, respond, *, balance=200, calls=None):
    """THE lane double. B1.6b: production fetches EXACT BYTES via `_whoxy_get(url) -> (bytes, error)`,
    and reads a FREE `account=balance` before any paid page. Patching `_http` no longer reaches the lane
    at all, so every lane test goes through one endpoint-aware provider instead of its own stub.

    `respond(url) -> bytes | (bytes, error) | Exception` answers a reverse-whois request."""
    calls = calls if calls is not None else []

    def get(url, timeout=None):
        calls.append(url)
        if "account=balance" in url:
            return json.dumps({"status": 1, "reverse_whois_balance": balance}).encode(), None
        out = respond(url)
        if isinstance(out, BaseException):
            from quarry_recon.contract import capture_error_body, provider_error_class
            capture_error_body(out, provider="whoxy")
            try:
                out.error_class = provider_error_class(out)
            except Exception:
                pass
            return getattr(out, "body_bytes", b"") or b"", out
        if isinstance(out, tuple):
            return out
        return (out.encode() if isinstance(out, str) else out), None

    monkeypatch.setattr(secrets, "whoxy", lambda: "KEY")
    monkeypatch.setattr(osint.secrets, "whoxy", lambda: "KEY")
    monkeypatch.setattr(osint, "_whoxy_get", get)
    monkeypatch.setattr(settings, "performance", dict)
    return calls


def _paid(calls):
    """Paid requests only — the balance read is free and is not a query."""
    return [c for c in calls if "account=balance" not in c]


def _drive(tmp_path, monkeypatch, bodies):
    """Run _whoxy with a scripted sequence of HTTP bodies."""
    monkeypatch.setattr(secrets, "whoxy", lambda: "KEY")
    seq = list(bodies)
    calls = []

    def fake_http(url, timeout=None, **kw):
        calls.append(url)
        if "account=balance" in url:                 # FREE, and answered before any paid page
            return json.dumps({"status": 1, "reverse_whois_balance": 200}).encode()
        body = seq.pop(0) if seq else '{"status": 1}'
        # review-B1.6r5#1: a real reverse-whois response ECHOES the question it answers, and every
        # response now owes that binding. A fixture that always claimed one fixed anchor would be
        # testing a body the provider never sends — so the fake echoes the URL it was actually given.
        return _echo_request(body, url).encode()

    # B1.6b: the lane fetches EXACT BYTES through `_whoxy_get`, so the double returns bytes and an
    # error slot rather than decoded text.
    monkeypatch.setattr(osint, "_whoxy_get",
                        lambda url, timeout=None: (fake_http(url, timeout), None))
    monkeypatch.setattr(osint, "_http", lambda url, timeout=None, **kw: fake_http(url, timeout).decode())
    s = _Sess(tmp_path)
    echoed = []
    osint._whoxy(s, {"a@x.com", "b@x.com"}, ["Acme Inc"], echoed.append, 30)
    # the FREE balance read is not a query — tests count paid requests.
    return s, [c for c in calls if "account=balance" not in c], echoed


def _outcome(s):
    return s.recorded[0].meta


def test_exhausted_account_is_not_reported_as_zero_domains(tmp_path, monkeypatch):
    """THE BUG: the results key is absent from a failure body, so reading it directly turned a spent
    account into `whoxy[...]: 0 domains` — no error, no event, coverage silently lost."""
    s, _calls, echoed = _drive(tmp_path, monkeypatch, [WHOXY_EXHAUSTED])
    assert not any("0 domains" in m for m in echoed)
    assert any("Zero Account Balance" in m for m in echoed)
    # review-B0r3#1: LIMITED, not PARTIAL — "degraded" would assert something went wrong here.
    assert s.recorded and s.recorded[0].status == Status.LIMITED
    assert _outcome(s)["error_class"] == PROVIDER_QUOTA and _outcome(s)["provider_limit"] is True


def test_attempted_is_not_the_same_number_as_completed(tmp_path, monkeypatch):
    """review-B0#6: exhaustion on the FIRST call still SENT that request. Reporting `0/3 sent` and
    `3 not sent` describes four queries for a three-query lane."""
    s, calls, _echoed = _drive(tmp_path, monkeypatch, [WHOXY_EXHAUSTED])
    o = _outcome(s)
    assert len(calls) == 1
    assert (o["eligible"], o["attempted"], o["completed"], o["not_sent"]) == (3, 1, 0, 2)


def test_exhaustion_stops_further_queries_and_reports_the_remainder(tmp_path, monkeypatch):
    """Once credits are gone every further call just fails: stop cleanly, and make the unsent queries
    visible rather than burning them into noise."""
    s, calls, echoed = _drive(tmp_path, monkeypatch, [WHOXY_EXHAUSTED, WHOXY_OK, WHOXY_OK])
    assert len(calls) == 1
    # B1.6b: the unsent anchors are reported as `not_sent` and named in `unopened`, and the echo carries
    # the provider's own words rather than a count of what we skipped.
    assert _outcome(s)["not_sent"] == 2
    assert len(_outcome(s)["unopened"]) == 2
    assert any("Zero Account Balance" in m for m in echoed), echoed


def test_evidence_before_exhaustion_is_kept(tmp_path, monkeypatch):
    """A limit must never discard what was already earned."""
    s, calls, _echoed = _drive(tmp_path, monkeypatch, [WHOXY_OK, WHOXY_EXHAUSTED, WHOXY_OK])
    assert len(calls) == 2
    assert set(s.cands) == {"a.com", "b.com"}                 # first query's candidates survive
    o = _outcome(s)
    assert s.recorded[0].status == Status.LIMITED
    assert (o["attempted"], o["completed"], o["not_sent"]) == (2, 1, 1)


def test_a_clean_run_records_success(tmp_path, monkeypatch):
    s, calls, _echoed = _drive(tmp_path, monkeypatch, [WHOXY_OK, WHOXY_OK, WHOXY_OK])
    assert len(calls) == 3
    assert s.recorded and s.recorded[0].status == Status.SUCCESS
    assert _outcome(s)["completed"] == 3 and _outcome(s)["failed"] == 0


def test_mixed_failures_are_partial_not_success(tmp_path, monkeypatch):
    """review-B0#2: one failed query among two successes recorded a flat SUCCESS — the failure vanished.
    (The previous version of this test asserted exactly that, locking the defect in.)"""
    s, calls, _echoed = _drive(tmp_path, monkeypatch,
                               [WHOXY_UNKNOWN_FAILURE, WHOXY_OK, WHOXY_OK])
    assert len(calls) == 3                                    # a per-query failure does NOT stop the lane
    assert s.recorded[0].status == Status.PARTIAL
    o = _outcome(s)
    assert (o["attempted"], o["completed"], o["failed"]) == (3, 2, 1)


def test_all_queries_failing_is_a_failure_lifecycle(tmp_path, monkeypatch):
    """review-B0#2: three failed queries produced NO manifest record at all — the lane looked as if it
    had never run."""
    bad = WHOXY_UNKNOWN_FAILURE
    s, calls, _echoed = _drive(tmp_path, monkeypatch, [bad, bad, bad])
    assert len(calls) == 3
    assert s.recorded and s.recorded[0].status == Status.FAILED
    assert _outcome(s)["completed"] == 0 and _outcome(s)["failed"] == 3


def test_transport_failures_also_count(tmp_path, monkeypatch):
    """An HTTP/transport error is a failed query too — it must not vanish into an echo."""
    monkeypatch.setattr(secrets, "whoxy", lambda: "KEY")

    _whoxy_provider(monkeypatch, lambda url: urllib.error.URLError("connection refused"))
    s = _Sess(tmp_path)
    osint._whoxy(s, {"a@x.com"}, [], lambda m: None, 30)
    assert s.recorded[0].status == Status.FAILED and _outcome(s)["failed"] == 1


def test_no_anchors_is_an_explicit_skip(tmp_path, monkeypatch):
    """A lane with nothing to pivot on must still say so — silence is indistinguishable from 'not run'."""
    monkeypatch.setattr(secrets, "whoxy", lambda: "KEY")
    s = _Sess(tmp_path)
    osint._whoxy(s, set(), [], lambda m: None, 30)
    assert s.recorded and s.recorded[0].status == Status.SKIPPED


def test_every_anchor_is_queued_no_first_n_cap(tmp_path, monkeypatch):
    """review-B0#4: `[:5]` on each list was the hidden membership cap this migration removes. Ranking
    decides ORDER; the provider's balance decides how many are attempted."""
    _whoxy_provider(monkeypatch, lambda url: _echo_request(WHOXY_OK, url))
    s = _Sess(tmp_path)
    emails = {f"e{i}@x.com" for i in range(9)}
    orgs = [f"Org {i}" for i in range(7)]
    osint._whoxy(s, emails, orgs, lambda m: None, 30)
    assert _outcome(s)["eligible"] == 16 and _outcome(s)["attempted"] == 16


def test_neither_anchor_KIND_can_starve_the_other(tmp_path, monkeypatch):
    """B1.6b: ordering was strict emails-first. One credit buys one PAGE now, so the paginator orders
    page-tier-first and round-robins between the two anchor KINDS inside a tier — fifty company anchors
    cannot spend the account before a single registrant email is opened. Every anchor still gets its
    page 1 before any anchor gets a page 2, which is the property the old ordering was reaching for."""
    calls = _whoxy_provider(monkeypatch, lambda url: _echo_request(WHOXY_OK, url))
    osint._whoxy(_Sess(tmp_path), {f"e{i}@x.com" for i in range(4)}, ["Org"], lambda m: None, 30)
    seen = ["email" if "email=" in c else "company" for c in _paid(calls)]
    assert seen[:2] == ["company", "email"], seen        # alternating, not four emails first
    assert seen.count("company") == 1 and seen.count("email") == 4


def test_truncated_page_is_not_a_clean_success(tmp_path, monkeypatch):
    """review-B0r2#2: the shortfall was detected, printed, and then recorded as SUCCESS — so the manifest
    said the answer was complete while the echo said otherwise. Whoxy pages at 100 results and charges a
    credit per page, so FETCHING the rest is credit-budget work (B1); until then it must read incomplete."""
    doc = ('{"status": 1, "total_results": 50, "current_page": 1, "total_pages": 1, '
           '"search_result": [{"domain_name": "a.com"}]}')
    s, _calls, _echoed = _drive(tmp_path, monkeypatch, [doc, WHOXY_OK, WHOXY_OK])
    # B1.6b: a body claiming 50 results on one page and returning ONE row is not a truncated success —
    # it CONTRADICTS ITSELF. It is retryable evidence, never an owned page, so the run reports a real
    # failure rather than a page budget we did not impose.
    assert s.recorded[0].status == Status.PARTIAL
    o = _outcome(s)
    assert o["failed"] >= 1 and o["coverage_incomplete"] is True
    assert s.recorded[0].meta["error_class"] == "parse"


def test_distinct_anchors_never_share_a_raw_evidence_file(tmp_path, monkeypatch):
    """review-B0r2#3: a lossy 40-char slug collided, so the later response OVERWROTE the earlier one while
    the earlier candidates kept pointing at that same raw_ref — provenance naming the wrong evidence."""
    _whoxy_provider(monkeypatch, lambda url: _echo_request(WHOXY_OK, url))
    s = _Sess(tmp_path)
    osint._whoxy(s, set(), ["Acme Inc", "Acme-Inc", "Acme  Inc"], lambda m: None, 30)
    # B1.6b: pages live in the DURABLE project state, named by the per-page identity, so they survive
    # the timestamped session that bought them.
    written = [q for q in (whoxy_page.state_dir(s.project_dir) / "pages").rglob("*.json")
               if q.name != ".quarry-write-probe"]
    assert len(written) == 3, f"anchors collided onto {len(written)} file(s)"


def test_a_provider_limit_is_not_a_failed_execution(tmp_path, monkeypatch):
    """review-B0r2#1: the terminal status must not say `failed` for depletion — hiding it later during
    verdict folding left events.jsonl and tool_status.failed still reporting a failure."""
    from quarry_recon import events
    from quarry_recon.store import Run
    run = Run.create(tmp_path, "t")
    events.reset()
    events.configure(run.dir)
    try:
        contract.run_provider("vertical.censys",
                              lambda: (_ for _ in ()).throw(
                                  ProviderBodyError(PROVIDER_QUOTA, "Zero Account Balance", "censys")),
                              work_unit="wu-a")
        run.write_manifest({}, ["vertical"])
        summary = json.loads(run.manifest_path.read_text())["summary"]
        terminals = [json.loads(l) for l in (run.dir / "events.jsonl").read_text().splitlines()
                     if '"tool_finish"' in l]
    finally:
        events.reset()
    # neither FAILED nor DEGRADED: a limit must not inflate any trouble counter (r3#1)
    assert terminals and terminals[-1]["status"] == "limited"
    assert terminals[-1]["error_class"] == PROVIDER_QUOTA
    assert summary["tools_failed"] == 0
    assert summary["tool_status"].get("failed", 0) == 0
    assert summary["tool_status"].get("partial", 0) == 0
    assert summary["verdict"] == "complete_with_limits"


def test_missing_key_is_an_explicit_skip_not_a_gap(tmp_path, monkeypatch):
    """An unconfigured OPTIONAL provider is SKIPPED — it must not make every ordinary run incomplete."""
    monkeypatch.setattr(secrets, "whoxy", lambda: "")
    s = _Sess(tmp_path)
    osint._whoxy(s, {"a@x.com"}, [], lambda m: None, 30)
    assert s.recorded and s.recorded[0].status == Status.SKIPPED


def _summary_with_terminal(tmp_path, error_class, status):
    """Drive a REAL provider terminal through run_provider and read the REAL verdict from the manifest —
    no hand-built event dicts, so the test exercises the wiring rather than describing it."""
    from quarry_recon import events
    from quarry_recon.store import Run
    run = Run.create(tmp_path, "t")
    events.reset()
    events.configure(run.dir)
    try:
        if status == "partial":
            contract.run_provider(
                "vertical.censys",
                lambda: contract.ProviderResult({"a.acme.com"}, partial=True, partial_kind="degraded",
                                                error_class=error_class, partial_reason="credits spent"),
                work_unit="wu-a")
        else:
            contract.run_provider(
                "vertical.censys",
                lambda: (_ for _ in ()).throw(ProviderBodyError(error_class, "credits spent", "censys")),
                work_unit="wu-a")
        run.write_manifest({}, ["vertical"])
        return json.loads(run.manifest_path.read_text())["summary"]
    finally:
        events.reset()


class TestVerdictWiring:
    """review-B0#3: the taxonomy described semantics the verdict could not deliver — PROVIDER_LIMITS and
    is_provider_limit() had no production consumer, so a quota terminal still became a gap or a failure."""

    def test_provider_limit_yields_complete_with_limits(self, tmp_path):
        s = _summary_with_terminal(tmp_path, PROVIDER_QUOTA, "partial")
        assert s["verdict"] == "complete_with_limits"
        assert s["provider_limits"] and not s["gaps"] and not s["failures"]

    def test_entitlement_is_also_a_limit(self, tmp_path):
        s = _summary_with_terminal(tmp_path, PROVIDER_ENTITLEMENT, "failed")
        assert s["verdict"] == "complete_with_limits" and not s["failures"]

    def test_forbidden_is_still_a_failure(self, tmp_path):
        """The whole reason 403 stopped being 'entitlement': a WAF must not read as an expected limit."""
        s = _summary_with_terminal(tmp_path, PROVIDER_FORBIDDEN, "failed")
        assert s["verdict"] == "complete_with_gaps" and s["failures"]

    def test_rate_limit_is_still_a_failure(self, tmp_path):
        s = _summary_with_terminal(tmp_path, PROVIDER_RATE_LIMIT, "failed")
        assert s["verdict"] == "complete_with_gaps" and s["failures"]

    def test_a_limit_does_not_mask_a_real_gap(self, tmp_path):
        """Gaps DOMINATE: a limit may only lift an otherwise-clean run, never soften a broken one."""
        from quarry_recon import events
        from quarry_recon.store import Run
        run = Run.create(tmp_path, "t")
        events.reset()
        events.configure(run.dir)
        try:
            contract.run_provider("vertical.censys",
                                  lambda: (_ for _ in ()).throw(
                                      ProviderBodyError(PROVIDER_QUOTA, "spent", "censys")),
                                  work_unit="wu-a")
            contract.run_provider("vertical.crtsh",
                                  lambda: (_ for _ in ()).throw(_http(500)), work_unit="wu-b")
            run.write_manifest({}, ["vertical"])
            s = json.loads(run.manifest_path.read_text())["summary"]
        finally:
            events.reset()
        assert s["verdict"] == "complete_with_gaps"
        assert s["provider_limits"] and s["failures"]


class TestOsintSessionVerdict:
    """review-B0r2#5: the structured limit had no standalone consumer — the OSINT path has no events
    pipeline, so without a session verdict it lived in a per-tool block nothing ever read."""

    def _session(self, tmp_path):
        from quarry_recon.osint import OsintSession
        return OsintSession(tmp_path, "t")

    def test_a_provider_limit_makes_the_session_limited(self, tmp_path, monkeypatch):
        s = self._session(tmp_path)
        _whoxy_provider(monkeypatch, lambda url: WHOXY_EXHAUSTED)
        osint._whoxy(s, {"a@x.com"}, [], lambda m: None, 30)
        out = s.outcome()
        assert out["verdict"] == "complete_with_limits"
        assert out["provider_limits"] and out["provider_limits"][0]["error_class"] == PROVIDER_QUOTA
        assert not out["gaps"]

    def test_a_clean_session_is_complete(self, tmp_path, monkeypatch):
        s = self._session(tmp_path)
        # the response must echo the question actually asked — a fixed identity would be a body the
        # provider never sends (review-B1.6r5#1).
        _whoxy_provider(monkeypatch, lambda url: _echo_request(WHOXY_OK, url))
        osint._whoxy(s, {"a@x.com"}, [], lambda m: None, 30)
        assert s.outcome()["verdict"] == "complete"

    def test_a_failure_is_a_gap_not_a_limit(self, tmp_path, monkeypatch):
        s = self._session(tmp_path)
        _whoxy_provider(monkeypatch, lambda url: WHOXY_UNKNOWN_FAILURE)
        osint._whoxy(s, {"a@x.com"}, [], lambda m: None, 30)
        out = s.outcome()
        assert out["verdict"] == "complete_with_gaps" and out["gaps"] and not out["provider_limits"]

    def test_the_verdict_reaches_the_manifest(self, tmp_path, monkeypatch):
        s = self._session(tmp_path)
        _whoxy_provider(monkeypatch, lambda url: WHOXY_EXHAUSTED)
        osint._whoxy(s, {"a@x.com"}, [], lambda m: None, 30)
        prof = type("P", (), {"target": "t", "apex_domains": ["acme.com"], "asn": [], "org_names": [],
                              "brands": [], "path": None})()
        s.finalize(prof)
        mf = json.loads((s.dir / "manifest.json").read_text())
        assert mf["summary"]["verdict"] == "complete_with_limits"


class TestLimitsNeverMaskGaps:
    """review-B0r3#2/#3: a limit and a gap are independent facts, and the session verdict must see every
    lane — not just the one that happens to carry custom metadata."""

    def test_a_failed_query_plus_exhaustion_reports_BOTH(self, tmp_path, monkeypatch):
        """The if/elif recorded only the limit, so a genuine failure vanished behind an expected boundary."""
        s, calls, _echoed = _drive(tmp_path, monkeypatch, [WHOXY_UNKNOWN_FAILURE, WHOXY_EXHAUSTED])
        assert len(calls) == 2
        out = s.outcome() if hasattr(s, "outcome") else None
        o = _outcome(s)
        assert o["provider_limit"] is True and o["failed"] == 1

    def test_session_verdict_is_gaps_when_both_are_present(self, tmp_path, monkeypatch):
        from quarry_recon.osint import OsintSession
        s = OsintSession(tmp_path, "t")
        seq = [WHOXY_UNKNOWN_FAILURE, WHOXY_EXHAUSTED]
        _whoxy_provider(monkeypatch, lambda url: seq.pop(0))
        osint._whoxy(s, {"a@x.com", "b@x.com"}, [], lambda m: None, 30)
        out = s.outcome()
        assert out["verdict"] == "complete_with_gaps"      # a real gap DOMINATES the expected limit
        assert out["provider_limits"] and out["gaps"]      # and BOTH facts survive

    def test_a_native_lane_failure_reaches_the_verdict(self, tmp_path, monkeypatch):
        """`_azmap` / whois / dmarc / rdap only ECHOED their exceptions — a session where they all blew up
        still produced a clean verdict, while the CLI called it the whole-session outcome."""
        from quarry_recon.osint import OsintSession
        s = OsintSession(tmp_path, "t")
        s.note_failure("azmap", "acme.com: boom")
        out = s.outcome()
        assert out["verdict"] == "complete_with_gaps" and out["gaps"][0]["tool"] == "azmap"

    def test_native_lane_exceptions_are_recorded_not_only_echoed(self, tmp_path, monkeypatch):
        from quarry_recon.osint import OsintSession
        s = OsintSession(tmp_path, "t")

        def boom(url, timeout=None, **kw):
            raise urllib.error.URLError("dns dead")

        monkeypatch.setattr(osint, "_http", boom)
        osint._azmap(s, "acme.com", lambda m: None, 30)
        assert s.outcome()["verdict"] == "complete_with_gaps"

    def test_a_degraded_tool_run_is_a_gap(self, tmp_path):
        """Any recorded PARTIAL/TIMED_OUT/BLOCKED lane counts, not just ones carrying our metadata."""
        from quarry_recon.osint import OsintSession
        from quarry_recon.runner import RunResult
        s = OsintSession(tmp_path, "t")
        s.record(RunResult("asnmap", ["asnmap"], Status.TIMED_OUT, None, 0.0, None, 0, note="slow"))
        assert s.outcome()["verdict"] == "complete_with_gaps"

    def test_a_limited_lane_alone_is_not_a_gap(self, tmp_path):
        from quarry_recon.osint import OsintSession
        from quarry_recon.runner import RunResult
        s = OsintSession(tmp_path, "t")
        s.record(RunResult("whoxy", ["whoxy"], Status.LIMITED, None, 0.0, None, 0, note="spent",
                           meta={"provider_limit": True, "error_class": PROVIDER_QUOTA}))
        out = s.outcome()
        assert out["verdict"] == "complete_with_limits" and not out["gaps"]


class TestUnreadableTruthIsNotGreen:
    """review-B0r3#5: a missing/corrupt manifest must read `unknown`, never clean green."""

    def _verdict(self, d):
        from quarry_recon.cli import _osint_verdict
        return _osint_verdict(d)[1]

    def test_missing_manifest_is_unknown(self, tmp_path):
        assert self._verdict(tmp_path) == "unknown"

    @pytest.mark.parametrize("body", ["", "{", "null", "[]", '{"summary": null}', '{"summary": []}',
                                      '{"summary": {}}'])
    def test_corrupt_or_empty_manifest_is_unknown(self, tmp_path, body):
        (tmp_path / "manifest.json").write_text(body)
        assert self._verdict(tmp_path) == "unknown"

    def test_a_real_verdict_is_read_through(self, tmp_path):
        (tmp_path / "manifest.json").write_text(json.dumps(
            {"summary": {"verdict": "complete_with_limits", "provider_limits": [], "gaps": []}}))
        assert self._verdict(tmp_path) == "complete_with_limits"


def test_evidence_filename_carries_the_full_digest(tmp_path, monkeypatch):
    """A truncated identity is a smaller collision space for no benefit — Quarry's other durable
    identities are full sha256 (the A1 lesson: an 8-hex service id let two URLs collide)."""
    _whoxy_provider(monkeypatch, lambda url: _echo_request(WHOXY_OK, url))
    s = _Sess(tmp_path)
    osint._whoxy(s, {"a@x.com"}, [], lambda m: None, 30)
    # B1.6b: the identity is the per-PAGE key `(schema, param, value, page)` — still a full sha256, and
    # now the same identity the ledger owns the page under, so evidence and ownership cannot diverge.
    want = whoxy_page.item_key(whoxy_page.Anchor("email", "a@x.com"), 1)
    names = [q.name for q in (whoxy_page.state_dir(s.project_dir) / "pages").rglob("*.json")]
    assert names and any(want in n for n in names), names
    assert len(want) == 64, "a truncated identity is a smaller collision space for no benefit"


class TestLaterPageLimit:
    """review-B0r4#1: the PAGINATION branch ran before any limit check, so spent credits on page 3 became
    a degraded PARTIAL *and* a COVERAGE_CAP — Quarry claiming its own ceiling truncated the input."""

    def _run(self, tmp_path, error_class):
        from quarry_recon import events
        from quarry_recon.store import Run
        run = Run.create(tmp_path, "t")
        events.reset()
        events.configure(run.dir)
        try:
            contract.run_provider(
                "vertical.censys",
                lambda: contract.ProviderResult({"a.acme.com"}, partial=True, partial_kind="pagination",
                                                pages=3, cursor="tok", error_class=error_class),
                work_unit="wu-a")
            run.write_manifest({}, ["vertical"])
            summary = json.loads(run.manifest_path.read_text())["summary"]
            evts = [json.loads(l) for l in (run.dir / "events.jsonl").read_text().splitlines()]
        finally:
            events.reset()
        return summary, evts

    @pytest.mark.parametrize("cls", [PROVIDER_QUOTA, PROVIDER_ENTITLEMENT])
    def test_later_page_limit_is_limited_not_a_cap(self, tmp_path, cls):
        summary, evts = self._run(tmp_path, cls)
        terminal = [e for e in evts if e.get("event") == "tool_finish"][-1]
        assert terminal["status"] == "limited"
        cov = [e for e in evts if e.get("event") == "coverage_partial" and e.get("measure") == "pagination"]
        assert cov and cov[-1]["kind"] == "provider"          # the PROVIDER's boundary, not ours
        assert summary["verdict"] == "complete_with_limits"
        assert summary["tools_failed"] == 0
        assert summary["tool_status"].get("partial", 0) == 0

    @pytest.mark.parametrize("cls", [PROVIDER_RATE_LIMIT, "transport", "server"])
    def test_a_later_page_failure_is_lost_in_flight_not_our_cap(self, tmp_path, cls):
        """review-B0r5#2: every non-limit truncation was labelled `cap`, blaming Quarry's own max_pages
        ceiling for a page the target rate-limited or broke on. Still a gap — but the attribution is what
        tuning (and the future AI interface) reads."""
        summary, evts = self._run(tmp_path, cls)
        terminal = [e for e in evts if e.get("event") == "tool_finish"][-1]
        assert terminal["status"] == "partial"
        cov = [e for e in evts if e.get("event") == "coverage_partial" and e.get("measure") == "pagination"]
        assert cov and cov[-1]["kind"] == "timeout"
        assert summary["verdict"] == "complete_with_gaps"

    def test_our_own_page_ceiling_is_still_a_cap(self, tmp_path):
        """A configured max_pages ceiling IS Quarry's cap — that attribution must survive."""
        summary, evts = self._run(tmp_path, None)          # truncated with no provider error
        cov = [e for e in evts if e.get("event") == "coverage_partial" and e.get("measure") == "pagination"]
        assert cov and cov[-1]["kind"] == "cap"
        assert summary["verdict"] == "complete_with_gaps"


class TestStatusPredicateAudit:
    """review-B0r4#3: generic predicates were written before LIMITED existed."""

    def test_limited_counts_as_ok(self):
        from quarry_recon.runner import RunResult
        r = RunResult("t", ["t"], Status.LIMITED, None, 0.0, None, 0)
        assert r.ok is True

    def test_limited_counts_as_a_run_that_happened(self):
        from quarry_recon import checkpoint
        import inspect
        src = inspect.getsource(checkpoint)
        assert "Status.LIMITED.value" in src

    def test_artifact_reclassification_never_rewrites_a_limit(self):
        """Folding LIMITED into the clean/degraded matrix would either launder it into SUCCESS (losing
        the limit) or demote it to a degraded PARTIAL (inventing a defect)."""
        from quarry_recon.runner import RunResult, reclassify_from_artifact
        for n in (0, 5, None):
            r = RunResult("t", ["t"], Status.LIMITED, None, 0.0, None, 0)
            assert reclassify_from_artifact(r, n, label="t").status == Status.LIMITED


class TestNativeLaneOutcomes:
    """review-B0r4#2: exception handlers are not outcome checks — a nonzero exit raises nothing."""

    def _sess(self, tmp_path):
        from quarry_recon.osint import OsintSession
        return OsintSession(tmp_path, "t")

    def test_whois_nonzero_exit_is_a_gap(self, tmp_path, monkeypatch):
        import subprocess as sp
        monkeypatch.setattr(sp, "run",
                            lambda *a, **k: sp.CompletedProcess(a[0], 2, stdout="", stderr="no whois"))
        s = self._sess(tmp_path)
        osint._whois(s, "acme.com", lambda m: None, 30)
        assert s.outcome()["verdict"] == "complete_with_gaps"

    def test_dig_nonzero_exit_is_a_gap(self, tmp_path, monkeypatch):
        import subprocess as sp
        monkeypatch.setattr(sp, "run",
                            lambda *a, **k: sp.CompletedProcess(a[0], 9, stdout="", stderr=""))
        s = self._sess(tmp_path)
        osint._dmarc(s, "acme.com", lambda m: None, 30)
        assert s.outcome()["verdict"] == "complete_with_gaps"

    def test_a_clean_subprocess_is_not_a_gap(self, tmp_path, monkeypatch):
        import subprocess as sp
        monkeypatch.setattr(sp, "run",
                            lambda *a, **k: sp.CompletedProcess(a[0], 0, stdout="", stderr=""))
        s = self._sess(tmp_path)
        osint._dmarc(s, "acme.com", lambda m: None, 30)
        assert s.outcome()["verdict"] == "complete"

    def test_unresolvable_apex_is_a_gap_not_a_silent_continue(self, tmp_path, monkeypatch):
        import socket
        monkeypatch.setattr(socket, "getaddrinfo",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("nxdomain")))
        s = self._sess(tmp_path)
        prof = type("P", (), {"apex_domains": ["acme.com"]})()
        osint._rdap(s, prof, lambda m: None, 30)
        assert s.outcome()["verdict"] == "complete_with_gaps"

    def test_a_v6_ONLY_apex_is_not_invisible(self, tmp_path, monkeypatch):
        """`gethostbyname_ex` is IPv4-only, so a v6-only apex resolved to nothing, contributed no
        netblock, and was recorded as a resolve failure it never had."""
        import socket
        monkeypatch.setattr(socket, "getaddrinfo", lambda host, _p, family, *a, **k:
                            [] if family == socket.AF_INET
                            else [(family, None, None, "", ("2606:4700::1111", 0, 0, 0))])
        s = self._sess(tmp_path)
        prof = type("P", (), {"apex_domains": ["acme.com"]})()
        assert osint._rdap_addresses(prof, s) == {"acme.com": ["2606:4700::1111"]}
        assert s.outcome()["gaps"] == []


class TestGenerationsMoveTogether:
    """review-B0r5#1: the TERMINAL generation and the COVERAGE generation were independent, so a stale
    `coverage:cap` from a previous session outlived the run that superseded it."""

    def _session(self, tmp_path, fn):
        from quarry_recon import events
        from quarry_recon.store import Run
        run = Run.create(tmp_path, "t")
        events.reset()
        events.configure(run.dir)
        try:
            contract.run_provider("vertical.censys", fn, work_unit="wu-a")
            run.write_manifest({}, ["vertical"])
            return json.loads(run.manifest_path.read_text())["summary"], run
        finally:
            events.reset()

    def test_a_stale_cap_does_not_survive_a_later_quota_run(self, tmp_path):
        """Session 1 truncates at our page ceiling (a cap gap). Session 2 hits spent credits on page 1,
        so it emits NO pagination counter at all — nothing would have superseded the old cap, and the
        honest `complete_with_limits` was dragged back to `complete_with_gaps`."""
        from quarry_recon import events
        from quarry_recon.store import Run
        run = Run.create(tmp_path, "t")
        events.reset()
        events.configure(run.dir)
        try:
            # session 1: our own max_pages ceiling -> coverage:cap
            contract.run_provider("vertical.censys",
                                  lambda: contract.ProviderResult({"a.acme.com"}, partial=True,
                                                                  partial_kind="pagination", pages=5),
                                  work_unit="wu-a")
            first = Run(run.dir).summary() if hasattr(Run, "summary") else None
            # session 2: a NEW session for the same source, stopped by spent credits on page 1
            events.reset()
            events.configure(run.dir)
            contract.run_provider("vertical.censys",
                                  lambda: (_ for _ in ()).throw(
                                      ProviderBodyError(PROVIDER_QUOTA, "Zero Account Balance", "censys")),
                                  work_unit="wu-a")
            run.write_manifest({}, ["vertical"])
            summary = json.loads(run.manifest_path.read_text())["summary"]
        finally:
            events.reset()
        assert summary["verdict"] == "complete_with_limits", summary.get("gaps")
        assert not summary["gaps"]
        assert summary["provider_limits"]

    def test_a_rerun_that_is_clean_clears_the_prior_gap(self, tmp_path):
        from quarry_recon import events
        from quarry_recon.store import Run
        run = Run.create(tmp_path, "t")
        events.reset()
        events.configure(run.dir)
        try:
            contract.run_provider("vertical.censys",
                                  lambda: contract.ProviderResult({"a.acme.com"}, partial=True,
                                                                  partial_kind="pagination", pages=5),
                                  work_unit="wu-a")
            events.reset()
            events.configure(run.dir)
            contract.run_provider("vertical.censys",
                                  lambda: contract.ProviderResult({"a.acme.com"}, pages=1),
                                  work_unit="wu-a")
            run.write_manifest({}, ["vertical"])
            summary = json.loads(run.manifest_path.read_text())["summary"]
        finally:
            events.reset()
        assert summary["verdict"] == "complete" and not summary["gaps"]


def _no_match_body(param, value):
    """The MEASURED compact no-match shape, echoing the identity of the query that produced it."""
    return json.dumps({"status": 1, "api_query": "reverse_whois",
                       "search_identifier": {param: value},
                       "total_results": 0, "api_execution_time": 0.01})


class TestMeasuredNoMatch:
    """The measured zero-result contract. B0 required search_result + both page fields and so rejected a
    real, correct answer as schema drift: "nobody matched" is a COMPLETE answer, not an unreadable one."""

    def test_the_measured_payload_is_a_clean_empty(self):
        doc = whoxy_envelope(json.loads(WHOXY_NO_MATCH))
        rows, total, truncated = whoxy_reverse_page(
            doc, page=1, param="company", value="quarry-contract-no-match-1785160485")
        assert rows == [] and total == 0 and truncated is False

    def test_the_compact_shape_must_answer_OUR_query(self):
        """It carries no rows, so its own echo of the request is the only thing tying it to our question.
        Without this, a response to a different anchor counted as 'this query found nothing'."""
        doc = json.loads(_no_match_body("company", "Acme Inc"))
        assert whoxy_reverse_page(doc, param="company", value="Acme Inc") == ([], 0, False)
        for bad_param, bad_value in (("company", "Other Corp"), ("email", "Acme Inc")):
            with pytest.raises(ProviderBodyError) as e:
                whoxy_reverse_page(doc, param=bad_param, value=bad_value)
            assert e.value.error_class == "parse"

    def test_a_bare_zero_body_is_not_the_measured_shape(self):
        """`{"status":1,"total_results":0}` says nothing about WHICH question it answers."""
        with pytest.raises(ProviderBodyError) as e:
            whoxy_reverse_page({"status": 1, "total_results": 0}, param="company", value="Acme")
        assert e.value.error_class == "parse"

    def test_another_endpoints_answer_is_rejected(self):
        """An `account=balance` reply is a zero-result-shaped body for a completely different question."""
        with pytest.raises(ProviderBodyError) as e:
            whoxy_reverse_page({"status": 1, "api_query": "account_balance", "total_results": 0},
                               param="company", value="Acme")
        assert e.value.error_class == "parse"

    @pytest.mark.parametrize("extra", [
        {"current_page": 1},                                  # paging without a carrier
        {"total_pages": 1},                                   # half-present pagination
        {"search_result": []},                                # carrier without paging
        {"domainsList": []},
        {"search_result": [], "current_page": 1},             # still half
        {"search_result": [], "total_pages": 1},
    ])
    def test_hybrid_shapes_fail_closed(self, extra):
        """Neither the measured compact shape nor a fully paged empty — fail closed rather than guess
        which half to trust."""
        doc = {"status": 1, "api_query": "reverse_whois",
               "search_identifier": {"company": "Acme"}, "total_results": 0, **extra}
        with pytest.raises(ProviderBodyError) as e:
            whoxy_reverse_page(doc, param="company", value="Acme")
        assert e.value.error_class == "parse"

    def test_zero_with_a_populated_domainsList_is_contradictory(self):
        """The alternate carrier gets the same contradiction check as search_result."""
        with pytest.raises(ProviderBodyError) as e:
            whoxy_reverse_page({"status": 1, "api_query": "reverse_whois", "total_results": 0,
                                "domainsList": ["a.com"]}, param="company", value="Acme")
        assert e.value.error_class == "parse"

    def test_api_query_is_checked_independently(self):
        """Pins the api_query guard ALONE: with a matching search_identifier the identity check would
        mask its removal, so a mutation deleting it still passed."""
        doc = {"status": 1, "api_query": "account_balance",
               "search_identifier": {"company": "Acme"}, "total_results": 0}
        with pytest.raises(ProviderBodyError) as e:
            whoxy_reverse_page(doc, param="company", value="Acme")
        assert e.value.error_class == "parse" and "reverse_whois" in e.value.reason

    def test_a_populated_domainsList_cannot_ride_in_on_the_paged_shape(self):
        """The contradiction check must cover BOTH carriers: with pagination present, an unchecked
        domainsList made a body holding rows return as a clean EMPTY — rows silently discarded."""
        doc = {"status": 1, "total_results": 0, "domainsList": ["a.com"],
               "current_page": 1, "total_pages": 1}
        with pytest.raises(ProviderBodyError) as e:
            whoxy_reverse_page(_bound(doc), page=1, param="company", value="Acme")
        assert e.value.error_class == "parse" and "domainsList" in e.value.reason

    def test_the_lane_rejects_an_answer_to_a_different_anchor(self, tmp_path, monkeypatch):
        """End-to-end proof that the lane actually PASSES the request identity down: a provider echoing
        someone else's query must not count as 'this anchor found nothing'."""
        _whoxy_provider(monkeypatch, lambda url: _no_match_body("company", "Someone Else"))
        s = _Sess(tmp_path)
        osint._whoxy(s, {"a@x.com"}, [], lambda m: None, 30)
        assert s.recorded[0].status == Status.FAILED
        assert s.recorded[0].meta["failed"] == 1 and s.recorded[0].meta["completed"] == 0

    @pytest.mark.parametrize("nulled", ["search_result", "domainsList", "current_page", "total_pages"])
    def test_an_explicit_null_field_is_not_an_absent_field(self, nulled):
        """review-B0r7#1: `doc.get()` cannot tell a missing key from an explicit null, so a body carrying
        `"search_result": null` looked exactly like the measured compact shape and became a clean EMPTY.
        A present-but-null key is MALFORMED presence, not absence."""
        doc = {"status": 1, "api_query": "reverse_whois", "search_identifier": {"company": "Acme"},
               "total_results": 0, nulled: None}
        with pytest.raises(ProviderBodyError) as e:
            whoxy_reverse_page(doc, param="company", value="Acme")
        assert e.value.error_class == "parse"

    def test_a_null_carrier_cannot_ride_in_on_the_paged_shape(self):
        """With both pagination fields present, a NULL carrier would otherwise reach shape B."""
        doc = {"status": 1, "total_results": 0, "search_result": None,
               "current_page": 1, "total_pages": 1}
        with pytest.raises(ProviderBodyError) as e:
            whoxy_reverse_page(_bound(doc), page=1, param="company", value="Acme")
        assert e.value.error_class == "parse" and "not a list" in e.value.reason

    def test_OMITTING_the_request_identity_is_a_CALLER_defect(self):
        """review-B1.6r6: `param`/`value` defaulted to None while being mandatory in effect, so a caller
        that simply forgot them got a ProviderBodyError — Quarry blaming the PROVIDER for a defect in its
        own call. They are required keyword arguments, so forgetting them fails immediately and locally."""
        doc = json.loads(_no_match_body("company", "Acme"))
        for bad in ({}, {"param": "company"}, {"value": "Acme"}):
            with pytest.raises(TypeError):
                whoxy_reverse_page(doc, **bad)

    def test_an_UNUSABLE_request_identity_is_still_a_parse_failure(self):
        """review-B0r7#2: a caller that names its request badly cannot be given a free clean empty —
        the compact shape has no rows, so the echo IS the evidence."""
        doc = json.loads(_no_match_body("company", "Acme"))
        for bad in ({"param": "org", "value": "Acme"},           # not a supported anchor kind
                    {"param": "company", "value": ""},           # empty value proves nothing
                    {"param": "company", "value": "   "},
                    {"param": "company", "value": 7}):
            with pytest.raises(ProviderBodyError) as e:
                whoxy_reverse_page(doc, **bad)
            assert e.value.error_class == "parse"
            # assert the REASON, not just that something raised: the exactness check below would also
            # reject these, masking the removal of this guard entirely (it survived a mutation doing
            # exactly that). A test aimed at one term must prove that term is what fired.
            assert "cannot be bound to a request" in e.value.reason, e.value.reason

    def test_the_identity_echo_must_match_EXACTLY(self):
        """An identifier that ALSO names another anchor is not an answer to our question alone."""
        doc = {"status": 1, "api_query": "reverse_whois", "total_results": 0,
               "search_identifier": {"company": "Acme", "email": "someone-else@example.com"}}
        with pytest.raises(ProviderBodyError) as e:
            whoxy_reverse_page(doc, param="company", value="Acme")
        assert e.value.error_class == "parse"

    @pytest.mark.parametrize("ident", [None, {}, [], "company=Acme", {"company": None}])
    def test_a_missing_or_malformed_identifier_is_rejected(self, ident):
        doc = {"status": 1, "api_query": "reverse_whois", "total_results": 0}
        if ident is not None:
            doc["search_identifier"] = ident
        with pytest.raises(ProviderBodyError) as e:
            whoxy_reverse_page(doc, param="company", value="Acme")
        assert e.value.error_class == "parse"

    @pytest.mark.parametrize("page", [0, 2, True, "1", 1.0, None])
    def test_the_compact_shape_can_only_answer_page_one(self, page):
        """review-B0r8: it carries no page identity, so it proves nothing about a later page. Once B1
        paginates, accepting it for page 2 would complete a page that was never received."""
        doc = json.loads(_no_match_body("company", "Acme"))
        with pytest.raises(ProviderBodyError) as e:
            whoxy_reverse_page(doc, param="company", value="Acme", page=page)
        assert e.value.error_class == "parse" and "no page identity" in e.value.reason

    def test_the_compact_shape_is_accepted_for_page_one(self):
        doc = json.loads(_no_match_body("company", "Acme"))
        assert whoxy_reverse_page(doc, param="company", value="Acme", page=1) == ([], 0, False)

    def test_a_fully_paged_empty_is_still_accepted(self):
        doc = {"status": 1, "total_results": 0, "current_page": 1, "total_pages": 1, "search_result": []}
        assert whoxy_reverse_page(_bound(doc), page=1, param="company", value="Acme") == ([], 0, False)

    def test_end_to_end_no_match_produces_no_failure_limit_or_gap(self, tmp_path, monkeypatch):
        from quarry_recon.osint import OsintSession
        import urllib.parse as _up
        s = OsintSession(tmp_path, "t")
        def echoing_no_match(url):
            """Answer each query with ITS OWN identity. The previous version returned one company body
            for two email queries and a different company query, and counted all three complete — the
            test itself asserting that a mismatched answer is fine."""
            q = _up.parse_qs(_up.urlsplit(url).query)
            param = "email" if "email" in q else "company"
            return _no_match_body(param, q[param][0])

        _whoxy_provider(monkeypatch, echoing_no_match)
        echoed = []
        osint._whoxy(s, {"a@x.com", "b@x.com"}, ["Acme Inc"], echoed.append, 30)
        out = s.outcome()
        assert out["verdict"] == "complete"
        assert not out["gaps"] and not out["provider_limits"]
        run = s._tool_runs[0]
        assert run["status"] == "success"
        assert run["outcome"]["completed"] == 3 and run["outcome"]["failed"] == 0
        # B1.6b: `truncated_pages` is always present and carries the remainder — a clean no-match has
        # none. The property is unchanged: nothing was left behind.
        assert run["outcome"]["truncated_pages"] == 0 and run["outcome"]["pages_left"] == 0
        assert run["outcome"]["unopened_anchors"] == 0
        assert any("0 domain(s)" in m for m in echoed)         # an honest zero, not a suppressed one

    @pytest.mark.parametrize("total", [False, True, "0", None, -0.0])
    def test_only_an_exact_integer_zero_takes_the_empty_path(self, total):
        """`False == 0` in Python, and a string/float/missing value is drift — none of them may unlock the
        relaxed shape, or the narrow exception becomes a hole."""
        doc = {"status": 1, "api_query": "reverse_whois"}
        if total is not None:
            doc["total_results"] = total
        with pytest.raises(ProviderBodyError) as e:
            whoxy_reverse_page(_bound(doc), param="company", value="Acme")
        assert e.value.error_class == "parse"

    def test_zero_with_rows_is_still_contradictory(self):
        with pytest.raises(ProviderBodyError) as e:
            whoxy_reverse_page({"status": 1, "total_results": 0,
                                "search_result": [{"domain_name": "a.com"}]},
                param="company", value="Acme")
        assert e.value.error_class == "parse"

    def test_zero_with_a_non_list_result_is_still_drift(self):
        with pytest.raises(ProviderBodyError) as e:
            whoxy_reverse_page({"status": 1, "total_results": 0, "search_result": "nope"},
                param="company", value="Acme")
        assert e.value.error_class == "parse"

    def test_zero_claiming_multiple_pages_is_contradictory(self):
        with pytest.raises(ProviderBodyError) as e:
            whoxy_reverse_page({"status": 1, "total_results": 0, "current_page": 1, "total_pages": 4},
                param="company", value="Acme")
        assert e.value.error_class == "parse"

    @pytest.mark.parametrize("cur,pages", [(0, 1), ("1", 1), (True, 1), (1, 0)])
    def test_zero_with_an_invalid_page_position_still_fails(self, cur, pages):
        with pytest.raises(ProviderBodyError) as e:
            whoxy_reverse_page({"status": 1, "total_results": 0, "current_page": cur,
                                "total_pages": pages},
                param="company", value="Acme")
        assert e.value.error_class == "parse"

    def test_zero_for_the_wrong_page_is_rejected(self):
        with pytest.raises(ProviderBodyError) as e:
            whoxy_reverse_page({"status": 1, "total_results": 0, "current_page": 2, "total_pages": 1},
                               page=1,
                param="company", value="Acme")
        assert e.value.error_class == "parse"

    def test_a_non_empty_answer_still_owes_the_full_contract(self):
        """The relaxation applies ONLY to the zero case: any real result keeps the strict schema."""
        with pytest.raises(ProviderBodyError):
            whoxy_reverse_page({"status": 1, "total_results": 2,
                                "search_result": [{"domain_name": "a.com"}, {"domain_name": "b.com"}]},
                param="company", value="Acme")
        rows, total, truncated = whoxy_reverse_page(json.loads(WHOXY_OK), param="company", value="Acme")
        assert rows == ["a.com", "b.com"] and total == 2 and truncated is False


# ── B1.1 — a Shodan error body refines an ambiguous status code ───────────────────────────────────
# MEASURED 2026-07-28 by depleting a real account. Both are HTTP 401; only the body differs.
SHODAN_QUOTA_BODY = ('{"error": "Insufficient query credits, please upgrade your API plan or wait for '
                     'the monthly limit to reset"}')
SHODAN_AUTH_BODY = ("<html>\n <head>\n  <title>401 Unauthorized</title>\n </head>\n <body>\n"
                    "  <h1>401 Unauthorized</h1>\n  This server could not verify that you are "
                    "authorized to access the document you requested.<br/><br/>\n </body>\n</html>")


def _http_err(code, body):
    """An HTTPError carrying a real readable body, like urllib produces."""
    import io
    return urllib.error.HTTPError("http://x", code, "msg", {}, io.BytesIO(body.encode()))


class _Body:
    """A minimal urlopen context manager."""

    def __init__(self, payload):
        self._payload = payload.encode() if isinstance(payload, str) else payload

    def read(self, n=None):
        if getattr(self, '_eof', False):
            return b''                      # STREAM: the body once, then EOF
        self._eof = True
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _with_balance(responder, *, credits=100, allowance=100, count_total=10):
    """Answer `/api-info` from a HEALTHY balance and send everything else to `responder`.

    B1.4: the lane reads the credit balance before it schedules any paid page, so a responder that
    answers EVERY url would have the balance read consume the first scripted error. `/api-info` is free
    and keeps working at a zero balance (measured), so a fixture where it fails alongside the search is
    testing a state Shodan does not produce. Tests that want a depleted ACCOUNT say so with `credits=0`;
    tests that want a failing SEARCH leave the balance healthy.

    B1.5: `/shodan/host/count` is answered here too. It is FREE and keeps working at a zero balance, so a
    fixture that routed it to the scenario's responder would have sizing consume the scripted errors that
    the PAID search is supposed to receive."""
    def route(req, timeout=20):
        url = getattr(req, "full_url", req)
        if "host/count" in str(url):
            return _Body(json.dumps({"total": count_total}))
        if "api-info" in str(url):
            return _Body(json.dumps({"query_credits": credits, "scan_credits": 0,
                                     "usage_limits": {"query_credits": allowance}}))
        return responder(req, timeout=timeout)
    return route


class TestShodanBodyRefinedClassification:
    """Shodan returns 401 for a bad key AND for spent credits. A status-only taxonomy would send the
    operator to re-key a credential that was never wrong, and report a failure where the truth is a
    LIMIT."""

    def test_the_two_401s_are_told_apart_by_body(self):
        quota = contract.capture_error_body(_http_err(401, SHODAN_QUOTA_BODY), provider="shodan")
        auth = contract.capture_error_body(_http_err(401, SHODAN_AUTH_BODY), provider="shodan")
        assert quota.error_class == PROVIDER_QUOTA
        assert auth.error_class == "auth"
        assert is_provider_limit(quota.error_class) and not is_provider_limit(auth.error_class)

    def test_an_html_body_yields_NO_reason_at_all(self):
        """Pins the parser directly. Asserting only `error_class != "parse"` was too weak: a mutation
        returning a junk reason string still landed on `auth` via the unknown-reason fallback, so the
        guard's removal was invisible. A non-JSON body must produce NO signal, not a bogus one."""
        e = contract.capture_error_body(_http_err(401, SHODAN_AUTH_BODY), provider="shodan")
        assert contract.error_body_reason(e) is None
        assert e.error_class != "parse"

    def test_the_measured_phrase_is_registered_for_shodan(self):
        """The exhaustion phrase must be bound to THIS provider — the reason table is per-provider so one
        provider's wording can never classify another's."""
        measured = ("Insufficient query credits, please upgrade your API plan or wait for the monthly "
                    "limit to reset")
        assert classify_provider_reason("shodan", measured) == PROVIDER_QUOTA
        assert classify_provider_reason("whoxy", measured) == "error"

    def test_an_unrecognised_json_reason_falls_back_to_the_status_class(self):
        """Never invent a limit from an unknown reason: an unknown failure must stay visible."""
        e = contract.capture_error_body(_http_err(401, '{"error": "Some New Message"}'), provider="shodan")
        assert e.error_class == "auth" and not is_provider_limit(e.error_class)

    @pytest.mark.parametrize("body", ["", "   ", "not json", "[]", "null", '{"error": null}',
                                      '{"error": ""}', '{"nope": "x"}', '{"error": 7}'])
    def test_a_bodyless_or_shapeless_error_uses_the_status_class(self, body):
        e = contract.capture_error_body(_http_err(401, body), provider="shodan")
        assert e.error_class == "auth"

    def test_the_reason_match_is_exact_for_shodan_too(self):
        near = '{"error": "Insufficient scan credits, please upgrade your API plan"}'
        e = contract.capture_error_body(_http_err(401, near), provider="shodan")
        assert e.error_class == "auth"          # NOT the measured query-credit phrase

    def test_other_status_codes_still_classify_normally(self):
        for code, want in ((429, PROVIDER_RATE_LIMIT), (403, PROVIDER_FORBIDDEN), (500, "server")):
            e = contract.capture_error_body(_http_err(code, "irrelevant"), provider="shodan")
            assert e.error_class == want

    def test_a_quota_body_on_another_code_is_still_quota(self):
        """The reason is the proof; the code is not. If Shodan ever moves it to 403, it stays a LIMIT."""
        e = contract.capture_error_body(_http_err(403, SHODAN_QUOTA_BODY), provider="shodan")
        assert e.error_class == PROVIDER_QUOTA

    def test_the_body_is_read_once_and_survives_propagation(self):
        """An HTTPError wraps a live socket: read late and the body may be gone. Capturing at the raise
        site must make the class available to a caller far downstream — AFTER the stream is closed."""
        e = _http_err(401, SHODAN_QUOTA_BODY)
        contract.capture_error_body(e, provider="shodan")
        assert contract.provider_error_class(e) == PROVIDER_QUOTA
        assert contract.error_body_reason(e).startswith("Insufficient query credits")

    def test_the_response_stream_is_closed(self):
        """review-B1.1#3: an HTTPError holds a LIVE response. A lane failing on every pivot would leak one
        connection per failure."""
        e = _http_err(401, SHODAN_QUOTA_BODY)
        contract.capture_error_body(e, provider="shodan")
        assert e.fp is None or e.fp.closed, "response stream left open"

    def test_capture_is_idempotent(self):
        """A second capture must not try to re-read a closed stream and must not change the verdict."""
        e = contract.capture_error_body(_http_err(401, SHODAN_QUOTA_BODY), provider="shodan")
        first = e.body_text
        contract.capture_error_body(e, provider="shodan")
        assert e.body_text == first and e.error_class == PROVIDER_QUOTA

    def test_an_uncaptured_error_falls_back_to_the_generic_mapping(self):
        assert contract.provider_error_class(_http_err(401, SHODAN_QUOTA_BODY)) == "auth"

    def test_capture_is_harmless_for_non_http_errors(self):
        e = contract.capture_error_body(urllib.error.URLError("dns dead"), provider="shodan")
        assert contract.provider_error_class(e) == "transport"

    def test_a_quota_terminal_is_LIMITED_not_failed(self, tmp_path):
        """End to end: the whole point is that a depleted Shodan account reads as complete_with_limits."""
        from quarry_recon import events
        from quarry_recon.store import Run
        run = Run.create(tmp_path, "t")
        events.reset()
        events.configure(run.dir)
        try:
            def boom():
                raise contract.capture_error_body(_http_err(401, SHODAN_QUOTA_BODY), provider="shodan")
            contract.run_provider("probe.favicon", boom, work_unit="wu-a")
            run.write_manifest({}, ["probe"])
            summary = json.loads(run.manifest_path.read_text())["summary"]
        finally:
            events.reset()
        assert summary["verdict"] == "complete_with_limits"
        assert summary["tools_failed"] == 0 and summary["tool_status"].get("failed", 0) == 0
        assert summary["provider_limits"]


class TestShodanPivotUsesTheProvenClass:
    def test_the_pivot_lane_captures_the_body_at_the_raise_site(self):
        import inspect
        from quarry_recon.phases import probe
        src = inspect.getsource(probe._shodan_page)
        assert 'capture_error_body(e, provider="shodan")' in src
        # The capture must happen BEFORE the error leaves the adapter, or the body is gone by then
        # (an HTTPError wraps a live socket). B1.4: the adapter RETURNS the classified error instead of
        # raising, so anchor on the return that hands it to the coordinator.
        assert src.index("capture_error_body") < src.index("return [], None, _classified(e)")

    def test_the_pivot_counts_the_proven_class(self):
        import inspect
        from quarry_recon.phases import probe
        # B1.4: classification is the ADAPTER's job now — every exception leaves it carrying a class the
        # coordinator can act on, so the pivot never re-derives one.
        src = inspect.getsource(probe._classified)
        assert "provider_error_class(e)" in src and "classify_provider_error(" not in src
        # the lane BODY moved under a project lock wrapper; the classification claim is about the body
        piv = inspect.getsource(probe._shodan_work_locked)
        assert "provider_error_class(err)" in piv and "classify_provider_error(" not in piv


class TestRealShodanLaneUnderQuota:
    """The regression that was MISSING, and whose absence let the P1 through: the earlier 'end-to-end'
    test raised a pre-classified exception directly, bypassing `_shodan_search` and `_shodan_pivot` — the
    two functions that actually decide whether a quota becomes a limit or a gap."""

    def _ctx(self, tmp_path, run):
        class _Scope:
            passive_only = False

            def in_scope(self, h):
                return bool(h) and h.endswith("acme.com")

            def is_oos(self, h):
                return not self.in_scope(h)

            def active_allowed(self, h):
                return True

        return type("C", (), {"run": run, "scope": _Scope(), "http_timeout": 20,
                              "echo": staticmethod(lambda m: None)})()

    def _drive(self, tmp_path, monkeypatch, responder, values=("abc", "def"), with_dir=False,
               route_balance=True, credits=100):
        """Run the REAL pivot through a faked urlopen and read the REAL verdict from the manifest."""
        import urllib.request
        from quarry_recon import events
        from quarry_recon.phases import probe
        from quarry_recon.store import Run
        run = Run.create(tmp_path, "t")
        events.reset()
        events.configure(run.dir)
        # route_balance=False lets a test refuse the BALANCE read itself, which the wrapper would
        # otherwise answer — the failure mode that made this test pass for the wrong reason.
        monkeypatch.setattr(urllib.request, "urlopen",
                            _with_balance(responder, credits=credits) if route_balance else responder)
        ctx = self._ctx(tmp_path, run)
        try:
            contract.run_provider("probe.favicon", lambda: probe._shodan_pivot(
                ctx, "KEY", values, "http.favicon.hash", "favicon-shodan", "probe.favicon", "seen {}"),
                work_unit="wu-a")
            run.write_manifest({}, ["probe"])
            s = json.loads(run.manifest_path.read_text())["summary"]
            return (s, run.dir) if with_dir else s
        finally:
            events.reset()

    def _quota_urlopen(self, *a, **kw):
        raise _http_err(401, SHODAN_QUOTA_BODY)

    def test_a_depleted_account_is_a_LIMIT_not_a_gap(self, tmp_path, monkeypatch):
        """The P1: every first-page failure was emitted as COVERAGE_TIMEOUT (a gap) including a proven
        quota, so a depleted account produced BOTH a limit and a gap — and gaps dominate."""
        s = self._drive(tmp_path, monkeypatch, self._quota_urlopen)
        assert s["verdict"] == "complete_with_limits", (s["gaps"], s["failures"])
        assert not s["gaps"] and not s["failures"]
        assert s["provider_limits"]
        assert s["tools_failed"] == 0 and s["tool_status"].get("failed", 0) == 0

    def test_a_real_failure_is_still_a_gap(self, tmp_path, monkeypatch):
        """The control: the limit path must not swallow genuine breakage."""
        def boom(*a, **kw):
            raise _http_err(500, "upstream exploded")
        s = self._drive(tmp_path, monkeypatch, boom)
        assert s["verdict"] == "complete_with_gaps"
        assert s["failures"] or s["gaps"]

    def test_an_html_401_is_an_auth_FAILURE_not_a_limit(self, tmp_path, monkeypatch):
        def bad_key(*a, **kw):
            raise _http_err(401, SHODAN_AUTH_BODY)
        s = self._drive(tmp_path, monkeypatch, bad_key)
        assert s["verdict"] == "complete_with_gaps"
        assert not s["provider_limits"]

    def test_quota_plus_a_real_failure_keeps_BOTH_and_ends_in_gaps(self, tmp_path, monkeypatch):
        """review#2: the outcome used to depend on which pivot happened to be last. The limit must stay
        visible, and a genuine failure must still dominate the verdict."""
        # B1.4: the failure comes FIRST, because a proven limit stops purchasing and anything scripted
        # behind it is never requested (see test_a_limit_STOPS_the_run_... for that half).
        seq = [_http_err(500, "boom"), _http_err(401, SHODAN_QUOTA_BODY)]

        def mixed(*a, **kw):
            raise seq.pop(0) if seq else _http_err(500, "boom")
        s = self._drive(tmp_path, monkeypatch, mixed)
        assert s["verdict"] == "complete_with_gaps"
        limited = [c for c in s["coverage"]
                   if any(k == "provider" for k in (c.get("by_kind") or {}))]
        assert limited, "the provider limit vanished behind the failure"

    def test_a_ZERO_BALANCE_stops_before_any_request_and_still_reads_as_LIMITED(self, tmp_path,
                                                                                monkeypatch):
        """B1.4: when /api-info proves there are no credits, the coordinator issues NOTHING — so there is
        no exception to raise, and a bare empty set would read as a clean EMPTY: the lane silently doing
        nothing on a depleted account. The proven stop is carried in the result instead."""
        calls = []

        def counted(req, timeout=20):
            calls.append(str(getattr(req, "full_url", req)))
            raise AssertionError("a paid search was issued at a zero balance")

        term = self._drive_terminal(tmp_path, monkeypatch, counted, credits=0)
        assert calls == [], f"spent on a proven-empty account: {calls}"
        assert term["status"] == "limited" and term["error_class"] == PROVIDER_QUOTA

    def test_a_balance_read_REFUSED_by_the_provider_is_not_a_gap(self, tmp_path, monkeypatch):
        """B1.4: /api-info is read before any page, and its failure was counted as a failure whatever the
        cause — so a depleted account emitted a gap from the balance probe while its pivots correctly
        reported a limit. A refusal the provider PROVED is a limit in every channel, including this one."""
        def refused(*a, **kw):
            raise _http_err(401, SHODAN_QUOTA_BODY)                 # /api-info itself is refused

        s, run_dir = self._drive(tmp_path, monkeypatch, refused, with_dir=True, route_balance=False)
        fails = [json.loads(l) for l in (run_dir / "events.jsonl").read_text().splitlines()
                 if '"shodan_failures"' in l]
        assert fails and fails[-1]["omitted"] == 0, f"the refused balance read became a gap: {fails}"
        assert s["verdict"] == "complete_with_limits", (s["gaps"], s["failures"])

    def test_an_operator_reserve_ALONE_folds_as_complete_with_limits(self, tmp_path, monkeypatch):
        """review-B1.4r7#1, end to end through the real lane: our own reserve withholds every credit, so
        nothing is queried and nothing goes wrong. The run is INCOMPLETE and CLEAN."""
        from quarry_recon.phases import probe
        monkeypatch.setattr(probe, "_shodan_reserve_setting", lambda: (10, True))

        def never(*a, **kw):
            raise AssertionError("a credit was spent past the reserve")

        s = self._drive(tmp_path, monkeypatch, never, credits=10)
        assert s["verdict"] == "complete_with_limits", (s["gaps"], s["failures"])
        assert not s["gaps"] and not s["failures"]
        # OUR bound, filed as ours — never as the provider refusing us (review-B1.4r8#2)
        assert s["operator_limits"] and not s["provider_limits"], s
        assert {x["origin"] for x in s["operator_limits"]} == {"operator"}

    def test_a_reserve_PLUS_a_broken_balance_read_still_ends_in_gaps(self, tmp_path, monkeypatch):
        """The real gap dominates. `unknown_with_reserve` is our own caution — a soft limit — but the
        transport failure that made the balance unknown is a genuine gap, and BOTH must survive."""
        from quarry_recon.phases import probe
        monkeypatch.setattr(probe, "_shodan_reserve_setting", lambda: (10, True))

        def dead(*a, **kw):
            raise urllib.error.URLError("connection refused")

        s = self._drive(tmp_path, monkeypatch, dead, route_balance=False)
        assert s["verdict"] == "complete_with_gaps", (s["gaps"], s["failures"])
        assert s["gaps"] or s["failures"], s

    def test_a_BAD_KEY_produces_a_CLASSIFIED_FAILED_terminal_not_a_ghost_empty(self, tmp_path,
                                                                               monkeypatch):
        """review-B1.4r2#3: only quota/entitlement were carried into the result, so an auth stop fell
        through to `return found` — an EMPTY terminal with no class and produced.host=0, while coverage
        said "gap". The verdict was right and `failed_tools` was a lie. `stop_is_limit` already draws
        exactly the line: an expected boundary is a limit, a credential that does not work is a DEFECT."""
        def bad_key(*a, **kw):
            raise _http_err(401, SHODAN_AUTH_BODY)                  # /api-info: HTML 401 = auth

        term = self._drive_terminal(tmp_path, monkeypatch, bad_key, route_balance=False)
        assert term["status"] == "failed", term
        assert term["error_class"] == "auth", term

    def test_a_BAD_KEY_is_never_dressed_up_as_a_provider_limit(self, tmp_path, monkeypatch):
        """The control for the balance-stop terminal: `stop_kind` covers our OWN stops too (a bad
        credential, an operator reserve), and only the provider's own boundary may be reported as its
        boundary. A credential that does not work is a defect in our setup, and must stay a gap."""
        def bad_key(*a, **kw):
            raise _http_err(401, SHODAN_AUTH_BODY)                  # /api-info: HTML 401 = auth

        s, run_dir = self._drive(tmp_path, monkeypatch, bad_key, with_dir=True, route_balance=False)
        assert s["verdict"] == "complete_with_gaps", (s["gaps"], s["failures"])
        assert not s["provider_limits"], "a bad key was reported as the provider limiting us"
        fails = [json.loads(l) for l in (run_dir / "events.jsonl").read_text().splitlines()
                 if '"shodan_failures"' in l]
        assert fails and fails[-1]["omitted"] >= 1, "the auth failure did not read as a gap"

    def _terminal(self, run_dir):
        return [json.loads(l) for l in (run_dir / "events.jsonl").read_text().splitlines()
                if '"tool_finish"' in l][-1]

    def _drive_terminal(self, tmp_path, monkeypatch, responder, values=("abc", "def"), with_dir=False,
                        credits=100, route_balance=True):
        """Same as _drive but hands back the TERMINAL event — the verdict alone cannot see which
        exception was raised, because the coverage gap is emitted before the raise either way."""
        import urllib.request
        from quarry_recon import events
        from quarry_recon.phases import probe
        from quarry_recon.store import Run
        run = Run.create(tmp_path, "t")
        events.reset()
        events.configure(run.dir)
        monkeypatch.setattr(urllib.request, "urlopen",
                            _with_balance(responder, credits=credits) if route_balance else responder)
        ctx = self._ctx(tmp_path, run)
        try:
            contract.run_provider("probe.favicon", lambda: probe._shodan_pivot(
                ctx, "KEY", values, "http.favicon.hash", "favicon-shodan", "probe.favicon", "seen {}"),
                work_unit="wu-a")
            return (self._terminal(run.dir), run.dir) if with_dir else self._terminal(run.dir)
        finally:
            events.reset()

    def test_a_real_failure_outranks_a_limit_that_did_not_stop_the_run(self, tmp_path, monkeypatch):
        """review#2: with everything failing and no evidence, the lane raises ONE exception — and it used
        to be simply the LAST one, so a quota arriving after a 500 turned a broken run into a mere limit.
        The verdict cannot catch this (the gap is emitted before the raise), so assert the TERMINAL.

        B1.4 narrows WHEN both can be observed: a proven provider limit now STOPS purchasing, so a
        failure that would have happened after it never happens (see the companion test below). With the
        failure FIRST, both are real and the failure must still win."""
        seq = [_http_err(500, "boom"), _http_err(401, SHODAN_QUOTA_BODY)]

        def mixed(*a, **kw):
            raise seq.pop(0) if seq else _http_err(500, "boom")
        term = self._drive_terminal(tmp_path, monkeypatch, mixed)
        assert term["status"] == "failed", term
        assert term["error_class"] != PROVIDER_QUOTA

    def test_a_limit_STOPS_the_run_so_later_pivots_are_a_counted_remainder(self, tmp_path, monkeypatch):
        """B1.4, the deliberate behaviour change: once the provider proves there are no credits, further
        requests cannot succeed, so the coordinator stops. A pivot that would have failed afterwards is
        never attempted — reporting it as a failure would be inventing an observation. Nothing is hidden:
        the unattempted pivots are an explicit, resumable remainder."""
        seq = [_http_err(401, SHODAN_QUOTA_BODY), _http_err(500, "boom")]

        def mixed(*a, **kw):
            raise seq.pop(0) if seq else _http_err(500, "boom")
        term, run_dir = self._drive_terminal(tmp_path, monkeypatch, mixed,
                                             values=("abc", "def", "ghi"), with_dir=True)
        assert term["status"] == "limited" and term["error_class"] == PROVIDER_QUOTA
        unq = [json.loads(l) for l in (run_dir / "events.jsonl").read_text().splitlines()
               if '"shodan_pivots_unqueried"' in l]
        assert unq and unq[-1]["omitted"] == 2, f"the unbought pivots were not reported: {unq}"

    def test_only_limits_and_no_evidence_still_reads_as_LIMITED(self, tmp_path, monkeypatch):
        """The control for the rule above: with NO real failure, the limit is the honest terminal."""
        term = self._drive_terminal(tmp_path, monkeypatch, self._quota_urlopen)
        assert term["status"] == "limited" and term["error_class"] == PROVIDER_QUOTA

    def test_mixed_errors_WITH_evidence_report_the_failure_class(self, tmp_path, monkeypatch):
        """When some pivot succeeded the lane returns a degraded PARTIAL instead of raising, and the
        dominant class is chosen there. Picking it from the combined pool let a single transport error be
        relabelled a provider limit (or the reverse) purely on counts."""
        import io
        ok_body = json.dumps({"total": 1, "matches": [{"hostnames": ["a.acme.com"]}]}).encode()

        class _Resp:
            """A STREAM: the body once, then EOF. A fake that answers every `read()` with the whole body
            never terminates a chunked reader — it hung the suite when the paid page started streaming."""

            def __init__(self):
                self._left = ok_body

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n=None):
                out, self._left = (self._left, b"") if n is None else (self._left[:n], self._left[n:])
                return out

        # B1.4: the limit can no longer OUTNUMBER the failure — the first provider limit stops
        # purchasing, so at most one is ever recorded per run. The property under test is unchanged
        # (failures pick the dominant class, limits only fill in when there are none); what changed is
        # that the failure must be observed BEFORE the limit, because nothing is bought after it.
        seq = ["ok", "fail", "quota", "quota"]

        def mixed(*a, **kw):
            k = seq.pop(0) if seq else "fail"
            if k == "ok":
                return _Resp()
            raise _http_err(401, SHODAN_QUOTA_BODY) if k == "quota" else _http_err(500, "boom")

        term = self._drive_terminal(tmp_path, monkeypatch, mixed, values=("a", "b", "c", "d"))
        assert term["status"] == "partial"       # a real failure -> degraded, NOT merely limited
        assert term["error_class"] != PROVIDER_QUOTA, "a real failure was relabelled as a limit"
        assert not is_provider_limit(term["error_class"])


class TestLaterPagePositionAccounting:
    """review-B1.1r2: position and cause are INDEPENDENT facts, and collapsing them let a later-page quota
    cancel an unrelated first-page transport failure. The existing TestLaterPageLimit cannot see any of
    this — it hands `run_provider` a prebuilt ProviderResult and never enters the Shodan lane."""

    def _cov(self, run_dir, measure):
        out = []
        for line in (run_dir / "events.jsonl").read_text().splitlines():
            e = json.loads(line)
            if e.get("event") == "coverage_partial" and e.get("measure") == measure:
                out.append(e)
        return out

    def _drive(self, tmp_path, monkeypatch, responder, values, max_pages=3):
        import urllib.request
        from quarry_recon import events
        from quarry_recon.phases import probe
        from quarry_recon.store import Run

        class _Scope:
            passive_only = False

            def in_scope(self, h):
                return bool(h) and h.endswith("acme.com")

            def is_oos(self, h):
                return not self.in_scope(h)

            def active_allowed(self, h):
                return True

        run = Run.create(tmp_path, "t")
        events.reset()
        events.configure(run.dir)
        # SHODAN_MAX_PAGES is read as a SPENDING control (settings.raw), not a worker count:
        # `0` must reach the lane as 0 = unbounded, which `concurrency()` would floor to 1.
        monkeypatch.setattr(probe.settings, "raw", lambda k, d=None: max_pages)
        routed = _with_balance(responder)
        monkeypatch.setattr(urllib.request, "urlopen", routed)
        monkeypatch.setattr(probe.urllib.request, "urlopen", routed)
        ctx = type("C", (), {"run": run, "scope": _Scope(), "http_timeout": 20,
                             "echo": staticmethod(lambda m: None)})()
        try:
            contract.run_provider("probe.favicon", lambda: probe._shodan_pivot(
                ctx, "KEY", values, "http.favicon.hash", "favicon-shodan", "probe.favicon", "seen {}"),
                work_unit="wu-a")
            run.write_manifest({}, ["probe"])
            return json.loads(run.manifest_path.read_text())["summary"], run.dir
        finally:
            events.reset()

    def _full_page(self):
        from quarry_recon.phases import probe
        return json.dumps({"total": 500, "matches": [{"hostnames": [f"h{i}.acme.com"]}
                                                     for i in range(probe._SHODAN_PAGE)]}).encode()

    class _Resp:
        def __init__(self, body):
            self._b = body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n=None):
            out, self._b = ((self._b, b'') if n is None
                            else (self._b[:n], self._b[n:]))   # STREAM, then EOF
            return out

    def test_page_one_evidence_then_page_two_quota_is_a_LIMIT(self, tmp_path, monkeypatch):
        """Page-1 data is kept and the later quota is a soft limit — NOT Quarry's page cap, and not a gap."""
        body = self._full_page()

        def paged(req, timeout=20):
            if "page=1" in req.full_url:
                return self._Resp(body)
            raise _http_err(401, SHODAN_QUOTA_BODY)

        s, d = self._drive(tmp_path, monkeypatch, paged, ("hX",))
        assert self._cov(d, "shodan_results_limited")[0]["omitted"] == 1     # the later LIMIT
        # B1.4: our page budget is now counted in PAGES, not pivots — a finer denominator for the same
        # fact. max_pages=3 of a 5-page pivot withholds 2, and the quota is not one of them.
        assert self._cov(d, "shodan_pages_withheld")[0]["omitted"] == 2      # NOT the quota
        assert self._cov(d, "shodan_results_failed")[0]["omitted"] == 0      # NOT a failure
        # B1.4: our own page cap withheld pages 4-5 of this 5-page pivot, and a cap is a GAP (Lumpy:
        # "SHODAN_MAX_PAGES=1 is still a cap"). Both facts are true at once — the provider limited us on
        # page 2 AND we never asked for pages past 3 — so the verdict carries the gap and the LIMIT stays
        # visible in its own measure.
        assert s["verdict"] == "complete_with_gaps", (s["gaps"], s["failures"])
        assert any(h.endswith("acme.com") for h in
                   [x["host"] for x in (json.loads(l) for l in
                    (d / "normalized" / "subdomain.jsonl").read_text().splitlines())])

    def test_a_later_limit_cannot_erase_a_first_page_failure(self, tmp_path, monkeypatch):
        """THE defect: `first_page_failures - limited_pivots` mixed positions, so a page-2 quota on one
        pivot cancelled a page-1 transport failure on ANOTHER."""
        body = self._full_page()

        def mixed(req, timeout=20):
            if "hDEAD" in req.full_url:
                raise urllib.error.URLError("connection refused")        # first-page FAILURE
            if "page=1" in req.full_url:
                return self._Resp(body)
            raise _http_err(401, SHODAN_QUOTA_BODY)                      # later-page LIMIT

        s, d = self._drive(tmp_path, monkeypatch, mixed, ("hDEAD", "hOK"))
        assert self._cov(d, "shodan_pivots")[0]["omitted"] == 1, "the first-page failure was erased"
        assert self._cov(d, "shodan_pivots_limited")[0]["omitted"] == 0   # the limit was at a LATER page
        assert self._cov(d, "shodan_results_limited")[0]["omitted"] == 1
        assert s["verdict"] == "complete_with_gaps"                       # a real failure still dominates

    def test_our_own_page_budget_is_still_our_cap(self, tmp_path, monkeypatch):
        """The control: when nothing errors and we simply stop paging, that IS Quarry's cap."""
        body = self._full_page()

        def one_page(req, timeout=20):
            return self._Resp(body)

        s, d = self._drive(tmp_path, monkeypatch, one_page, ("hX",), max_pages=1)
        withheld = self._cov(d, "shodan_pages_withheld")[0]
        assert withheld["omitted"] == 4                                   # ours: 4 of 5 pages
        # review-B1 (Lumpy): "SHODAN_MAX_PAGES=1 is still a cap" — a soft SAMPLE would let a run that
        # never looked past page 1 call itself complete.
        assert withheld["kind"] == "cap"
        assert self._cov(d, "shodan_results_failed")[0]["omitted"] == 0
        assert self._cov(d, "shodan_results_limited")[0]["omitted"] == 0

    def test_each_measure_carries_the_RIGHT_KIND(self, tmp_path, monkeypatch):
        """Counts alone are not enough: `cap`, `timeout` and `provider` are all gaps-or-limits with
        different MEANINGS, and two of them read as gaps — so mislabelling one is invisible in the verdict
        (a mutation relabelling a later-page failure as OUR cap passed every count assertion)."""
        body = self._full_page()

        def mixed(req, timeout=20):
            if "hSPENT" in req.full_url:
                raise _http_err(401, SHODAN_QUOTA_BODY)
            if "hDEAD" in req.full_url:
                raise urllib.error.URLError("refused")
            if "page=1" in req.full_url:
                return self._Resp(body)
            raise _http_err(500, "boom")

        _s, d = self._drive(tmp_path, monkeypatch, mixed, ("hSPENT", "hDEAD", "hOK"))
        kinds = {m: self._cov(d, m)[0]["kind"] for m in
                 ("shodan_pivots", "shodan_pivots_limited", "shodan_pages_withheld",
                  "shodan_results_failed", "shodan_results_limited")}
        assert kinds == {
            "shodan_pivots": "timeout",            # first-page FAILURE — the target's cost
            "shodan_pivots_limited": "provider",   # first-page LIMIT — the provider's boundary
            "shodan_pages_withheld": "cap",        # OUR page budget — the only one that is ours
            "shodan_results_failed": "timeout",    # later-page FAILURE
            "shodan_results_limited": "provider",  # later-page LIMIT
        }, kinds

    def test_each_reason_names_only_ITS_OWN_position(self, tmp_path, monkeypatch):
        """review-B1.1r3: counts and kinds were right while the PROSE lied — one combined class counter
        made the first-page reason report classes that only ever happened on page 2 of another pivot."""
        body = self._full_page()

        def mixed(req, timeout=20):
            if "hDEAD" in req.full_url:
                raise urllib.error.URLError("refused")               # FIRST-page failure: transport
            if "page=1" in req.full_url:
                return self._Resp(body)
            raise _http_err(401, SHODAN_QUOTA_BODY)                  # LATER-page limit: quota

        _s, d = self._drive(tmp_path, monkeypatch, mixed, ("hDEAD", "hOK"))
        first_fail = self._cov(d, "shodan_pivots")[0]["reason"]
        later_limit = self._cov(d, "shodan_results_limited")[0]["reason"]
        assert "transport" in first_fail and "quota" not in first_fail, first_fail
        assert "quota" in later_limit and "transport" not in later_limit, later_limit

    def test_a_later_FAILURE_class_never_leaks_into_the_first_page_reason(self, tmp_path, monkeypatch):
        """The sharper case: when the later problem is a FAILURE (not a limit) it lands in the same
        fail-class pool as the first-page one, so a combined counter is invisible unless the two classes
        DIFFER. transport (first page) vs server (later page)."""
        body = self._full_page()

        def mixed(req, timeout=20):
            if "hDEAD" in req.full_url:
                raise urllib.error.URLError("refused")               # FIRST page: transport
            if "page=1" in req.full_url:
                return self._Resp(body)
            raise _http_err(500, "boom")                             # LATER page: server

        _s, d = self._drive(tmp_path, monkeypatch, mixed, ("hDEAD", "hOK"))
        first_fail = self._cov(d, "shodan_pivots")[0]["reason"]
        later_fail = self._cov(d, "shodan_results_failed")[0]["reason"]
        assert "transport" in first_fail and "server" not in first_fail, first_fail
        assert "server" in later_fail and "transport" not in later_fail, later_fail

    def test_a_first_page_limit_stops_the_run_and_the_rest_is_a_REMAINDER(self, tmp_path, monkeypatch):
        """The mirror case, re-derived for B1.4. It used to assert that a first-page LIMIT could not
        erase a LATER-page failure. That combination is now unreachable, and for a structural reason
        worth stating: the coordinator schedules PAGE TIER first, so every pivot's page 1 is attempted
        before any pivot's page 2 — a first-page limit therefore always precedes any later page, and
        stops purchasing. So the property to protect is no longer "both are counted" but "what we never
        bought is COUNTED, not silently dropped"."""
        body = self._full_page()

        def mixed(req, timeout=20):
            if "hSPENT" in req.full_url:
                raise _http_err(401, SHODAN_QUOTA_BODY)                  # first-page LIMIT
            if "page=1" in req.full_url:
                return self._Resp(body)
            raise _http_err(500, "boom")                                 # never reached

        s, d = self._drive(tmp_path, monkeypatch, mixed, ("hSPENT", "hOK"))
        assert self._cov(d, "shodan_pivots_limited")[0]["omitted"] == 1   # first-page limit
        assert self._cov(d, "shodan_pivots")[0]["omitted"] == 0           # no first-page failure
        assert self._cov(d, "shodan_results_failed")[0]["omitted"] == 0   # it never happened
        # the pages we did not buy are visible as a remainder rather than vanishing with the run
        left = self._cov(d, "shodan_pages_left")[0]
        assert left["omitted"] >= 1, left
        assert s["verdict"] == "complete_with_gaps"


class TestBalanceReasonMatchesTheGate:
    """review-B1.5r3#4: the reason told every operator that "free operations continue" — which stopped
    being true once a REFUSED CREDENTIAL began blocking free /host/count sizing too. Operator-visible
    telemetry that contradicts the behaviour is worse than none."""

    def _reason(self, cls):
        from quarry_recon.phases import probe
        return probe._blocked_read(probe.shodan_balance(None), cls).reason

    def test_a_refused_key_does_NOT_claim_free_operations_continue(self):
        for cls in ("auth", "forbidden"):
            why = self._reason(cls)
            assert "free operations continue" not in why, (cls, why)
            assert "the key itself was refused" in why, (cls, why)

    def test_a_refused_SPEND_still_says_free_operations_continue(self):
        for cls in ("quota", "entitlement"):
            why = self._reason(cls)
            assert "free operations continue" in why, (cls, why)


class TestThePageCeilingIsASpendingControl:
    """`SHODAN_MAX_PAGES: 0` documents "no page ceiling — the credit balance is the bound", and it is
    also the default. It was read through `settings.concurrency()`, whose `max(1, …)` floor is right
    for a worker pool and wrong here: an operator who wrote the documented `0` got ONE page
    (Lumpy, 2026-08-08). The direction matters — it silently bought less than asked on a paid pivot,
    so nothing looked broken.
    """

    @pytest.mark.parametrize("raw,expect", [
        (None, (0, True)), ("", (0, True)), ("   ", (0, True)),   # ABSENT is 0, and 0 is fine
        (0, (0, True)), (3, (3, True)), (1, (1, True)),
        (True, (0, False)), (False, (0, False)),   # bool is an int subclass; True is not one page
        ("3", (0, False)), (2.0, (0, False)), (-1, (0, False)), ([], (0, False)), ("all", (0, False)),
    ])
    def test_only_an_exact_non_negative_int_is_a_ceiling(self, raw, expect):
        from quarry_recon.phases.probe import _page_ceiling
        assert _page_ceiling(raw) == expect

    def test_an_unusable_ceiling_REFUSES_rather_than_removing_the_bound(self):
        """The failure direction that matters: a malformed value must not read as "no ceiling" and let a
        pivot page until the balance runs out. Same contract the credit reserve already had — a broken
        cost guard is not the absence of a guard."""
        from quarry_recon.phases import probe
        pages, valid = probe._page_ceiling("all")
        assert (pages, valid) == (0, False), "an unusable value must be flagged, not silently unbounded"

    def test_the_balance_refuses_to_spend_on_an_unusable_ceiling(self, monkeypatch):
        from quarry_recon.phases import probe
        monkeypatch.setattr(probe.settings, "performance", lambda: {})
        monkeypatch.setattr(probe.settings, "raw", lambda k, d=None: "all")
        bal = probe.shodan_balance({"query_credits": 500})
        assert bal.spendable == 0 and not bal.may_spend
        assert bal.stop_kind == probe.SHODAN_PAGE_CEILING_INVALID
        assert not bal.stop_is_limit, "our own broken knob is a GAP to fix, not an expected limit"

    def test_a_usable_ceiling_still_spends(self, monkeypatch):
        from quarry_recon.phases import probe
        monkeypatch.setattr(probe.settings, "performance", lambda: {})
        monkeypatch.setattr(probe.settings, "raw", lambda k, d=None: 3)
        bal = probe.shodan_balance({"query_credits": 500})
        assert bal.may_spend and bal.stop_kind != probe.SHODAN_PAGE_CEILING_INVALID

    def test_the_knob_is_read_through_the_spending_reader(self):
        """Structural, from the AST: `settings.concurrency` floors at 1 and swallows a malformed value
        into a default — both wrong for a cost guard, which is why `settings.raw` exists. Asserted at
        the CALL SITE so the defect cannot come back by editing one word."""
        import ast
        import pathlib

        from quarry_recon.phases import probe

        tree = ast.parse(pathlib.Path(probe.__file__).read_text())
        readers = set()
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and node.args
                    and isinstance(node.args[0], ast.Constant)
                    and node.args[0].value == "SHODAN_MAX_PAGES"):
                readers.add(getattr(node.func, "attr", None) or getattr(node.func, "id", None))
        assert readers == {"raw"}, f"SHODAN_MAX_PAGES is read through {sorted(readers)}"


class TestAPaidResponseIsKeptWhole:
    """Two truncations survived the acquisition rewrite. A refused paid response is still a paid
    response: the credit is spent, so the bytes are evidence whatever our contract said about them.
    """

    def test_a_large_refused_body_is_stored_WHOLE_beside_its_document(self, tmp_path):
        import json

        from quarry_recon import shodan_sched as S

        big = b"A" * (S.REJECTED_INLINE_LIMIT + 4096)
        pivot = S.Pivot("probe.favicon", "http.favicon.hash", "12345")
        art = S.publish_rejected(tmp_path, pivot, 1, reason="parse: nope", body=big)
        assert art is not None
        doc = json.loads(art.read_text())
        assert doc["body_bytes"] == len(big)
        assert "body_b64" not in doc, "a body too large to inline must not be inlined at all"
        side = pathlib.Path(doc["raw_ref"])
        assert side.read_bytes() == big, "the paid bytes are kept whole, not sliced"

    def test_the_large_body_is_published_ATOMICALLY(self, tmp_path, monkeypatch):
        """A crash mid-write must not leave a partial artifact at the name the document points at, so
        the bytes go through the same content-verified primitive every other paid artifact uses."""
        from quarry_recon import budget, shodan_sched as S

        seen = {}

        def _publish(dest, data, *, digest):
            seen["dest"], seen["len"], seen["digest"] = dest, len(data), digest
            return budget.publish_bytes(dest, data, digest=digest)

        monkeypatch.setattr(S.budget, "publish_bytes", _publish)
        big = b"B" * (S.REJECTED_INLINE_LIMIT + 1)
        pivot = S.Pivot("probe.cert", "ssl.cert.fingerprint", "abc")
        S.publish_rejected(tmp_path, pivot, 2, reason="parse", body=big)
        assert seen.get("len") == len(big), "the side artifact must go through publish_bytes"

    def test_a_body_the_store_refuses_is_reported_not_claimed(self, tmp_path, monkeypatch):
        import json

        from quarry_recon import shodan_sched as S

        monkeypatch.setattr(S.budget, "publish_bytes", lambda *a, **k: False)
        big = b"C" * (S.REJECTED_INLINE_LIMIT + 1)
        art = S.publish_rejected(tmp_path, S.Pivot("probe.cert", "f", "v"), 3, reason="parse", body=big)
        doc = json.loads(art.read_text())
        assert doc.get("body_kept") is False and "raw_ref" not in doc

    def test_a_small_refused_body_still_rides_inside_the_document(self, tmp_path):
        import base64
        import json

        from quarry_recon import shodan_sched as S

        small = b"{\"error\": \"nope\"}"
        pivot = S.Pivot("probe.favicon", "http.favicon.hash", "12345")
        doc = json.loads(S.publish_rejected(tmp_path, pivot, 1, reason="parse", body=small).read_text())
        assert base64.b64decode(doc["body_b64"]) == small and doc["body_bytes"] == len(small)

    @staticmethod
    def _lane(tmp_path):
        from quarry_recon import shodan_sched as S

        class _Ledger:
            def record(self, *a, **k):
                return True

            def add_evidence(self, *a, **k):
                return True

        pivot = S.Pivot("probe.favicon", "http.favicon.hash", "12345")
        return S, _Ledger(), S.PivotState(pivot=pivot), S.LaneOutcome(lane="probe.favicon"), S.WorkResult()

    def test_a_lost_receipt_on_a_READABLE_page_is_reported(self, tmp_path, monkeypatch):
        """The page's own completion journals fine, so nothing else notices — but the receipt is the
        proof we BOUGHT it, and without it the next run pays again."""
        S, ledger, st, o, res = self._lane(tmp_path)
        monkeypatch.setattr(S, "commit_acquisition", lambda *a, **k: False)
        ok = S._commit_page(st, o, res, page=1, matches=[], total=0, ledger=ledger,
                            attempt_dir=tmp_path, ingest=lambda *a, **k: 0)
        assert ok is True, "the page is still ours"
        assert res.records_journaled is False, "a lost receipt must reach the durability verdict"

    def test_the_rejected_branch_commits_ONE_receipt_after_an_earlier_failure(self, tmp_path, monkeypatch):
        """Driven, not inspected: `records_journaled` starts False, and the receipt must still be
        committed exactly once — a skipped one leaves the page bought, unrecorded, and bought again."""
        from quarry_recon import shodan_sched as S

        pivot = S.Pivot("probe.favicon", "http.favicon.hash", "77")
        attempt = tmp_path / "attempt"
        (attempt / "raw").mkdir(parents=True)

        def _search(pv, page):
            # the bytes appear DURING the purchase, as the real lane streams them — writing them up
            # front would make the ownership scan refuse acquisition before any of this ran.
            (attempt / "raw" / f"{S.item_key(pv, page)}.json").write_bytes(b'{"total": 1}')
            return "not a list", 1, None

        calls = []
        monkeypatch.setattr(S, "commit_acquisition",
                            lambda *a, **k: (calls.append(k.get("state")), False)[1])

        class _Ledger:
            path = attempt / "ledger.json"

            def has(self, *a, **k):
                return False

            def items(self):
                return {}

            def record(self, *a, **k):
                return True

            def save(self):
                return True

            def checkpoint(self):
                return True

        bal = type("B", (), {"may_spend": True, "spendable": 5, "stop_kind": "",
                             "remaining": 5, "reserve": 0, "reason": ""})()
        st = S.PivotState(pivot=pivot, total=1)
        res = S.run_work(None, states=[st], balance=bal,
                         search=_search,
                         ingest=lambda *a, **k: 0, ledger=_Ledger(), attempt_dir=attempt,
                         is_limit=lambda c: False, should_stop=lambda c: True)
        assert calls == [S.ACQ_UNPARSED], f"one receipt for the rejected page, got {calls}"
        assert res.records_journaled is False

    def test_the_receipt_is_committed_even_after_an_EARLIER_failure(self):
        """A rejected page's receipt is its only ownership record. Folding the call into
        `records_journaled and commit_acquisition(...)` skips it entirely once an earlier record has
        already set the flag False — so the page ends up bought, unrecorded, and bought again."""
        import ast
        import inspect

        from quarry_recon import shodan_sched as S

        tree = ast.parse(pathlib.Path(inspect.getfile(S)).read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.BoolOp) or not isinstance(node.op, ast.And):
                continue
            calls = [v for v in node.values
                     if isinstance(v, ast.Call)
                     and getattr(v.func, "id", getattr(v.func, "attr", None)) == "commit_acquisition"]
            assert not calls, ("commit_acquisition must be called before its result is folded, "
                               f"not inside an `and` (line {node.lineno})")

    def test_a_kept_receipt_leaves_the_verdict_clean(self, tmp_path, monkeypatch):
        S, ledger, st, o, res = self._lane(tmp_path)
        monkeypatch.setattr(S, "commit_acquisition", lambda *a, **k: True)
        S._commit_page(st, o, res, page=1, matches=[], total=0, ledger=ledger,
                       attempt_dir=tmp_path, ingest=lambda *a, **k: 0)
        assert res.records_journaled is True


class TestAPaidErrorResponseIsKeptWhole:
    """`urlopen` RAISES on any 4xx/5xx, so the streaming path never runs for an error — and the
    classifier reads a bounded head and closes the socket. Without streaming the error body first, that
    head is the only copy of a response we were charged for.
    """

    @staticmethod
    def _raise_http_error(body: bytes):
        import io
        import urllib.error

        def _open(req, timeout=20):
            raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, io.BytesIO(body))
        return _open

    def test_the_whole_error_body_reaches_disk(self, tmp_path, monkeypatch):
        from quarry_recon.phases import probe

        body = b"X" * 716_800
        monkeypatch.setattr(probe.urllib.request, "urlopen", self._raise_http_error(body))
        sink = tmp_path / "page.json"
        rows, total, err = probe._shodan_page("K", "http.favicon.hash", "1", 1, sink=sink)
        assert (rows, total) == ([], None) and err is not None
        kept = pathlib.Path(err.raw_path)
        assert kept.stat().st_size == len(body), f"kept {kept.stat().st_size} of {len(body)} paid bytes"
        assert not sink.exists(), "an ordinary error is not a page we bought — it must not land in the"
        assert kept.name.endswith(".error"), kept.name

    def test_the_failure_still_carries_the_artifact(self, tmp_path, monkeypatch):
        from quarry_recon.phases import probe

        body = b'{"error": "Insufficient query credits"}'
        monkeypatch.setattr(probe.urllib.request, "urlopen", self._raise_http_error(body))
        sink = tmp_path / "page.json"
        _rows, _total, err = probe._shodan_page("K", "http.favicon.hash", "1", 1, sink=sink)
        assert pathlib.Path(err.raw_path).read_bytes() == body
        assert err.error_class in ("quota", "auth"), err.error_class


class TestAnErrorResponseIsNotAnOrphan:
    """An ordinary 429 or 500 is not a page we bought. If its body lands at the acquisition name, the
    next lifecycle reads an unowned paid response and refuses acquisition for that page for ever — a
    transient failure turned permanent.
    """

    def test_the_error_body_is_invisible_to_the_ownership_scan(self, tmp_path, monkeypatch):
        import io
        import urllib.error

        from quarry_recon import shodan_sched as S
        from quarry_recon.phases import probe

        pivot = S.Pivot("probe.favicon", "http.favicon.hash", "999")
        attempt = tmp_path / "attempt"
        (attempt / "raw").mkdir(parents=True)
        sink = attempt / "raw" / f"{S.item_key(pivot, 1)}.json"

        def _open(req, timeout=20):
            raise urllib.error.HTTPError(req.full_url, 429, "Too Many", {}, io.BytesIO(b"slow down"))

        monkeypatch.setattr(probe.urllib.request, "urlopen", _open)
        probe._shodan_page("K", pivot.facet, pivot.value, 1, sink=sink)

        class _Ledger:
            def items(self):
                return {}

        view = S.ownership_view(attempt, _Ledger())
        assert view.error == "", f"the scan itself failed: {view.error}"
        assert view.orphans == {}, f"a transient error became an orphan: {view.orphans}"

    def test_an_INTERRUPTED_error_stream_keeps_its_partial(self, tmp_path, monkeypatch):
        """Driven through the REAL streamer, so the fields are the ones `stream_to_file` actually sets.
        The partial bytes are ours and the class must say so — the status code's class would send an
        operator looking at the provider instead of at a broken transfer."""
        import urllib.error

        from quarry_recon.contract import IncompleteAcquisition
        from quarry_recon.phases import probe

        closed = []

        class _Truncated(urllib.error.HTTPError):
            """Seven bytes, then the transport dies — what a real interrupted body looks like."""

            def read(self, n=-1):
                if not closed:                       # first chunk lands, second raises
                    closed.append("read")
                    return b"partial"
                raise ConnectionResetError("transport broke mid-body")

            def close(self):
                closed.append("closed")

        def _open(req, timeout=20):
            return _Truncated(req.full_url, 500, "Server Error", {}, None)

        monkeypatch.setattr(probe.urllib.request, "urlopen",
                            lambda req, timeout=20: (_ for _ in ()).throw(_open(req)))
        _rows, _total, err = probe._shodan_page("K", "http.favicon.hash", "1", 1,
                                                sink=tmp_path / "page.json")
        assert isinstance(err, IncompleteAcquisition), type(err).__name__
        assert err.raw_bytes == 7, f"reported {err.raw_bytes} of 7 partial bytes"
        assert pathlib.Path(err.raw_path).read_bytes() == b"partial"
        assert "closed" in closed, "the ORIGINAL response must be closed, not the carrier"

    def test_a_streamed_error_response_is_closed(self, tmp_path, monkeypatch):
        import io
        import urllib.error

        from quarry_recon.phases import probe

        closed = []

        class _Err(urllib.error.HTTPError):
            def close(self):
                closed.append(True)
                super().close()

        def _open(req, timeout=20):
            raise _Err(req.full_url, 401, "Unauthorized", {}, io.BytesIO(b"nope"))

        monkeypatch.setattr(probe.urllib.request, "urlopen", _open)
        probe._shodan_page("K", "http.favicon.hash", "1", 1, sink=tmp_path / "page.json")
        assert closed, ("the response must be closed by the lane: stamping `body_text` makes "
                        "`capture_error_body` skip its own read, and its close with it")
