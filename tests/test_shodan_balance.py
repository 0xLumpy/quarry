"""B1.2 — the Shodan credit-balance contract.

`/api-info` is FREE and works at a ZERO balance (MEASURED 2026-07-28), so remaining credits are a fact we
read rather than guess. The coordinator (B1.3) consumes this contract; it must not re-invent the
semantics, which is why every edge is pinned here first.

Live shape, measured:
    {"plan": "dev", "query_credits": 85, "scan_credits": 100, "monitored_ips": 0,
     "unlocked": true, "usage_limits": {"scan_credits": 100, "query_credits": 100, "monitored_ips": 16}}
"""
import json
import pathlib

import pytest

from quarry_recon import events, secrets
from quarry_recon.phases import probe
from quarry_recon.phases.probe import (SHODAN_AUTH_REFUSED, SHODAN_ENTITLEMENT, SHODAN_FORBIDDEN,
                                       SHODAN_OPERATOR_RESERVE, SHODAN_PROVIDER_EXHAUSTED,
                                       SHODAN_RESERVE_INVALID, SHODAN_UNKNOWN_WITH_RESERVE,
                                       ShodanBalance, shodan_balance)

pytestmark = pytest.mark.offline

MEASURED = {"plan": "dev", "query_credits": 85, "scan_credits": 100, "monitored_ips": 0,
            "unlocked": True, "usage_limits": {"scan_credits": 100, "query_credits": 100,
                                               "monitored_ips": 16}}


class TestSpendableArithmetic:
    def test_spendable_is_remaining_minus_reserve(self):
        b = shodan_balance(MEASURED, reserve=10)
        assert (b.remaining, b.reserve, b.spendable) == (85, 10, 75)

    def test_spendable_never_goes_negative(self):
        b = shodan_balance({"query_credits": 5}, reserve=100)
        assert b.spendable == 0 and b.remaining == 5      # remaining is NOT clamped — it is a fact

    def test_the_four_facts_stay_distinct(self):
        """`remaining` and `spendable` answer different questions; collapsing them would let an operator
        reserve read as an empty account."""
        b = shodan_balance(MEASURED, reserve=25)
        assert b.remaining == 85 and b.allowance == 100 and b.reserve == 25 and b.spendable == 60

    def test_a_zero_reserve_spends_everything(self):
        assert shodan_balance(MEASURED, reserve=0).spendable == 85


class TestStrictValidation:
    @pytest.mark.parametrize("value", [True, False, 12.0, "85", None, [], {}, -2, -0.0])
    def test_only_an_exact_non_negative_int_is_a_balance(self, value):
        b = shodan_balance({"query_credits": value}, reserve=0)
        assert b.remaining is None and not b.known

    @pytest.mark.parametrize("doc", [None, [], "nope", 7, {"nope": 1}, {"query_credits": None}])
    def test_a_malformed_body_is_UNKNOWN_not_zero(self, doc):
        """'We could not look' and 'there is nothing left' are different facts with different
        consequences — defaulting to 0 would fabricate an exhausted account."""
        b = shodan_balance(doc, reserve=0)
        assert b.remaining is None and b.spendable is None and b.may_spend is True

    def test_a_malformed_allowance_does_not_invalidate_the_balance(self):
        b = shodan_balance({"query_credits": 85, "usage_limits": {"query_credits": "100"}}, reserve=0)
        assert b.remaining == 85 and b.allowance is None

    @pytest.mark.parametrize("limits", [None, [], "x", {"query_credits": True}])
    def test_allowance_is_optional_context(self, limits):
        b = shodan_balance({"query_credits": 85, "usage_limits": limits}, reserve=0)
        assert b.remaining == 85 and b.allowance is None and b.may_spend


class TestUnknownBalanceAndReserve:
    def test_unknown_with_no_reserve_may_still_spend(self):
        """Exhaustion is a clean, self-announcing outcome (401 + the measured body), so spending until
        the provider refuses costs only what it costs."""
        b = shodan_balance(None, reserve=0)
        assert b.may_spend is True and b.spendable is None      # None = unknown-but-permitted, NOT zero

    def test_unknown_with_a_reserve_must_not_spend(self):
        """Without a balance we cannot know where the reserve begins, so ANY spend risks eating credits
        the operator withheld."""
        b = shodan_balance(None, reserve=1)
        assert b.may_spend is False and b.spendable == 0
        assert b.stop_kind == SHODAN_UNKNOWN_WITH_RESERVE
        assert "cannot tell where the reserve begins" in b.reason

    def test_the_unknown_reason_states_which_case_it_is(self):
        assert "no reserve" in shodan_balance(None, reserve=0).reason


class TestOperatorLimitVsExhaustion:
    def test_a_balance_at_the_reserve_is_an_OPERATOR_limit(self):
        """The provider would still serve us; reporting this as quota would blame Shodan for our policy."""
        b = shodan_balance({"query_credits": 10}, reserve=10)
        assert b.may_spend is False and b.spendable == 0
        assert "OPERATOR limit" in b.reason and "exhaustion" in b.reason

    def test_a_genuinely_empty_account_is_NOT_called_a_reserve(self):
        """review-B1.2#1: every spendable==0 case claimed "reserve withholds them". With reserve 0 that
        is simply false — the provider balance is exhausted, and blaming our own config for it sends the
        operator to change a setting that had nothing to do with it."""
        b = shodan_balance({"query_credits": 0}, reserve=0)
        assert b.known and b.remaining == 0 and b.may_spend is False
        assert b.stop_kind == SHODAN_PROVIDER_EXHAUSTED
        assert "EXHAUSTED" in b.reason and "OPERATOR" not in b.reason

    def test_the_two_zero_cases_are_distinguishable_without_reading_prose(self):
        empty = shodan_balance({"query_credits": 0}, reserve=0)
        held = shodan_balance({"query_credits": 10}, reserve=10)
        assert empty.stop_kind != held.stop_kind
        assert held.stop_kind == SHODAN_OPERATOR_RESERVE

    def test_a_reserve_is_named_as_not_the_cause_when_the_account_is_empty(self):
        b = shodan_balance({"query_credits": 0}, reserve=25)
        assert b.stop_kind == SHODAN_PROVIDER_EXHAUSTED and "not the cause" in b.reason

    def test_below_the_reserve_still_reports_the_real_remaining(self):
        b = shodan_balance({"query_credits": 3}, reserve=10)
        assert b.remaining == 3 and b.spendable == 0


class TestReserveKnob:
    def test_the_default_reserve_is_zero(self, monkeypatch):
        """Patched `performance()`, which is what production actually reads. The previous version patched
        `settings.strict_int` — a function this code no longer calls — so the default could have changed
        to anything and the test would still have passed."""
        monkeypatch.setattr(probe.settings, "performance", lambda: {})
        b = shodan_balance(MEASURED)
        assert b.reserve == 0 and b.may_spend is True and b.spendable == 85

    def test_the_knob_is_exposed_in_the_config_template(self):
        """A knob that exists only in code cannot be set by the operator whose spending it governs."""
        from quarry_recon import registry  # noqa: F401  (package import for the data path)
        import quarry_recon
        tpl = (pathlib.Path(quarry_recon.__file__).parent / "data" / "config.template.yaml").read_text()
        assert "SHODAN_CREDIT_RESERVE:" in tpl

    @pytest.mark.parametrize("raw", [True, False, -5, "abc", 3.5, "12.5", 10 ** 9, [], {}])
    def test_an_INVALID_reserve_blocks_spending_instead_of_failing_open(self, monkeypatch, raw):
        """review-B1.2#2: falling back to 0 silently DISABLED the operator's cost guard — failing open on
        a control whose entire purpose is to withhold spending. Absent means 0; present-but-broken means
        stop and say so."""
        monkeypatch.setattr(probe.settings, "performance", lambda: {"SHODAN_CREDIT_RESERVE": raw})
        b = shodan_balance(MEASURED)
        assert b.may_spend is False and b.stop_kind == SHODAN_RESERVE_INVALID
        assert "cost guard" in b.reason

    @pytest.mark.parametrize("raw", [None, "", "   "])
    def test_an_ABSENT_reserve_is_zero_and_fine(self, monkeypatch, raw):
        monkeypatch.setattr(probe.settings, "performance", lambda: {"SHODAN_CREDIT_RESERVE": raw})
        b = shodan_balance(MEASURED)
        assert b.reserve == 0 and b.may_spend is True and not b.stop_kind

    @pytest.mark.parametrize("raw,want", [(10, 10), ("10", 10), (0, 0), ("0", 0)])
    def test_a_valid_reserve_is_honoured(self, monkeypatch, raw, want):
        monkeypatch.setattr(probe.settings, "performance", lambda: {"SHODAN_CREDIT_RESERVE": raw})
        assert shodan_balance(MEASURED).reserve == want

    @pytest.mark.parametrize("bad", [True, 12.9, "abc", -1, None if False else "5x"])
    def test_a_caller_passed_reserve_is_strict_too(self, bad):
        """The direct path was `max(0, int(reserve))`: True became 1, 12.9 became 12, "abc" RAISED."""
        b = shodan_balance(MEASURED, reserve=bad)
        assert b.may_spend is False and b.stop_kind == SHODAN_RESERVE_INVALID


class TestNoSecretLeaks:
    def test_the_key_never_reaches_the_reason(self, monkeypatch):
        monkeypatch.setattr(probe.urllib.request, "urlopen",
                            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom KEY-123456")))
        monkeypatch.setattr(secrets, "load", lambda: {"shodan": "KEY-123456"})
        b = probe._read_shodan_balance("KEY-123456")
        assert "KEY-123456" not in (b.reason or "")
        assert b.remaining is None                                   # a failed read is UNKNOWN

    def test_the_emitted_ledger_carries_no_key(self, tmp_path, monkeypatch):
        monkeypatch.setattr(secrets, "load", lambda: {"shodan": "KEY-123456"})
        events.reset()
        events.configure(tmp_path)
        try:
            probe._emit_shodan_balance("probe.favicon",
                                       shodan_balance(MEASURED, reserve=5))
            body = (tmp_path / "events.jsonl").read_text()
        finally:
            events.reset()
        assert "KEY-123456" not in body
        rec = [json.loads(l) for l in body.splitlines() if '"balance"' in l][-1]
        assert rec["balance"]["remaining"] == 85 and rec["balance"]["spendable"] == 80

    def test_a_secret_in_the_reason_is_scrubbed_before_emission(self, tmp_path, monkeypatch):
        """A key in ANY field must never reach disk. The scrubbing is the EVENT SINK's job (events.py
        `_redact` walks every field), not this lane's — an extra redact in the emitter was unfalsifiable,
        since the sink already made it pass. This test targets the property, wherever it is enforced."""
        monkeypatch.setattr(secrets, "load", lambda: {"shodan": "KEY-123456"})
        leaky = ShodanBalance(remaining=85, allowance=100, reserve=0, spendable=85, may_spend=True,
                              reason="upstream said: https://api.shodan.io/api-info?key=KEY-123456")
        events.reset()
        events.configure(tmp_path)
        try:
            probe._emit_shodan_balance("probe.favicon", leaky)
            body = (tmp_path / "events.jsonl").read_text()
        finally:
            events.reset()
        assert "KEY-123456" not in body, "the API key reached telemetry"


class TestLifecycleEmission:
    """review-B1.2#4 — SCOPE NOTE. `_emit_shodan_balance` appends a ledger event, but `views._fold_events`
    keeps only `produced`/`consumed` from a ledger and the manifest ignores the rest, so NOTHING consumes
    the balance yet. These tests therefore assert only what is true today: the event is EMITTED every
    lifecycle with honest nulls. The "a later lifecycle supersedes the earlier numbers" claim is deferred
    to B1.3, which adds the reconciling consumer — asserting it now would test the JSONL line order, not
    the behaviour anyone relies on."""
    def _emit(self, tmp_path, bal):
        events.reset()
        events.configure(tmp_path)
        try:
            probe._emit_shodan_balance("probe.favicon", bal)
            return [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()
                    if '"balance"' in l]
        finally:
            events.reset()

    def test_the_balance_is_emitted_every_lifecycle(self, tmp_path):
        """Including the UNKNOWN case — otherwise a run that could not read the balance leaves the
        PREVIOUS run's numbers standing as current."""
        recs = self._emit(tmp_path, shodan_balance(None, reserve=0))
        assert recs and recs[-1]["balance"]["known"] is False
        assert recs[-1]["balance"]["remaining"] is None              # never defaulted to 0

    def test_unknown_is_null_not_zero(self, tmp_path):
        recs = self._emit(tmp_path, shodan_balance(None, reserve=0))
        b = recs[-1]["balance"]
        assert b["remaining"] is None and b["allowance"] is None and b["spendable"] is None

    def test_every_emission_is_recorded_in_order(self, tmp_path):
        """What is actually true today: each lifecycle appends its own record. Which one a CONSUMER
        should believe is B1.3's question, and there is no consumer to ask yet."""
        monkeypatch_free = {"SHODAN_CREDIT_RESERVE": None}
        events.reset()
        events.configure(tmp_path)
        try:
            probe._emit_shodan_balance("probe.favicon", shodan_balance({"query_credits": 85}, reserve=0))
            probe._emit_shodan_balance("probe.favicon", shodan_balance({"query_credits": 12}, reserve=0))
            recs = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()
                    if '"balance"' in l]
        finally:
            events.reset()
        assert [r["balance"]["remaining"] for r in recs] == [85, 12]
        assert monkeypatch_free  # keep the intent explicit: no reconciliation is asserted here


class TestLiveRead:
    def test_a_successful_read_settles_the_contract(self, monkeypatch):
        class _R:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n=None):
                return json.dumps(MEASURED).encode()

        monkeypatch.setattr(probe.urllib.request, "urlopen", lambda *a, **k: _R())
        monkeypatch.setattr(probe.settings, "performance", lambda: {})
        b = probe._read_shodan_balance("KEY")
        assert b.remaining == 85 and b.allowance == 100 and b.spendable == 85

    def test_a_failed_read_is_unknown_not_a_crash(self, monkeypatch):
        monkeypatch.setattr(probe.urllib.request, "urlopen",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("dns dead")))
        b = probe._read_shodan_balance("KEY")
        assert isinstance(b, ShodanBalance) and not b.known


class TestAllowanceVsRemaining:
    """`usage_limits.query_credits == -1` is Shodan's DOCUMENTED unlimited-plan sentinel. The TOP-LEVEL
    `query_credits` has no such documented sentinel — and I had them share a parser, so `-1` there
    disabled the reserve entirely. That is fail-OPEN on a spending control, from a response shape I
    invented rather than measured."""

    def test_an_unlimited_ALLOWANCE_does_not_discard_a_finite_balance(self):
        b = shodan_balance({"query_credits": 5, "usage_limits": {"query_credits": -1}}, reserve=0)
        assert b.remaining == 5 and b.spendable == 5
        assert b.allowance_unlimited is True

    def test_the_documented_shodan_example_parses_correctly(self):
        """Shodan's own /api-info example: a FINITE balance next to an unlimited plan allowance."""
        b = shodan_balance({"query_credits": 100000, "usage_limits": {"query_credits": -1}}, reserve=0)
        assert (b.remaining, b.spendable, b.allowance_unlimited) == (100000, 100000, True)

    def test_an_unlimited_allowance_still_respects_a_reserve(self):
        b = shodan_balance({"query_credits": 10, "usage_limits": {"query_credits": -1}}, reserve=10)
        assert b.may_spend is False and b.stop_kind == SHODAN_OPERATOR_RESERVE

    @pytest.mark.parametrize("v", [-1, -2, "unlimited", True])
    def test_an_UNPROVEN_sentinel_in_the_remaining_field_is_schema_drift(self, v):
        """Not "unlimited" — unknown. Guessing here would silently switch the cost guard off."""
        b = shodan_balance({"query_credits": v}, reserve=0)
        assert b.remaining is None and not b.known

    def test_an_unproven_remaining_sentinel_blocks_when_a_reserve_is_set(self):
        b = shodan_balance({"query_credits": -1}, reserve=10)
        assert b.may_spend is False and b.stop_kind == SHODAN_UNKNOWN_WITH_RESERVE

    @pytest.mark.parametrize("v", [-2, "x", True, 1.5])
    def test_a_malformed_allowance_is_not_unlimited(self, v):
        b = shodan_balance({"query_credits": 85, "usage_limits": {"query_credits": v}}, reserve=0)
        assert b.allowance_unlimited is False and b.remaining == 85


class TestStopKindIsNotAlwaysALimit:
    """review-B1.2r3#2: one `read_refused` token held auth, generic forbidden AND entitlement, so a BAD
    KEY would have softened into complete_with_limits beside a genuinely exhausted account."""

    @pytest.mark.parametrize("kind,is_limit", [
        (SHODAN_PROVIDER_EXHAUSTED, True),      # the account ran out — expected
        (SHODAN_ENTITLEMENT, True),             # the plan cannot — expected
        (SHODAN_OPERATOR_RESERVE, True),        # we withheld them — our choice
        (SHODAN_UNKNOWN_WITH_RESERVE, True),    # our caution stopped us
        (SHODAN_AUTH_REFUSED, False),           # the credential is broken — FIX it
        (SHODAN_FORBIDDEN, False),              # refused, reason unproven — FIX or prove it
        (SHODAN_RESERVE_INVALID, False),        # our config is broken — FIX it
    ])
    def test_the_verdict_class_of_every_stop(self, kind, is_limit):
        b = ShodanBalance(None, None, 0, 0, False, "", stop_kind=kind)
        assert b.stop_is_limit is is_limit

    def test_no_stop_kind_is_not_a_limit(self):
        assert shodan_balance(MEASURED, reserve=0).stop_is_limit is False


class TestReadOutcomeSurvives:
    """review-B1.2#3: with a reserve configured no paid request follows, so a BAD KEY produced no other
    signal anywhere — it hid permanently behind 'balance unknown; reserve protected'."""

    def _read(self, monkeypatch, exc):
        monkeypatch.setattr(probe.settings, "performance", lambda: {"SHODAN_CREDIT_RESERVE": 10})
        monkeypatch.setattr(probe.urllib.request, "urlopen",
                            lambda *a, **k: (_ for _ in ()).throw(exc))
        return probe._read_shodan_balance("KEY")

    def test_a_bad_key_is_visible_as_auth(self, monkeypatch):
        import io
        import urllib.error
        html = b"<html><head><title>401 Unauthorized</title></head><body></body></html>"
        b = self._read(monkeypatch, urllib.error.HTTPError("u", 401, "m", {}, io.BytesIO(html)))
        assert b.read_error == "auth" and not b.known and b.may_spend is False

    def test_an_exhausted_account_reads_as_quota_even_here(self, monkeypatch):
        import io
        import urllib.error
        body = ('{"error": "Insufficient query credits, please upgrade your API plan or wait for the '
                'monthly limit to reset"}').encode()
        b = self._read(monkeypatch, urllib.error.HTTPError("u", 401, "m", {}, io.BytesIO(body)))
        assert b.read_error == "quota"

    def test_a_transport_failure_is_not_the_same_as_a_bad_key(self, monkeypatch):
        import urllib.error
        b = self._read(monkeypatch, urllib.error.URLError("dns dead"))
        assert b.read_error == "transport"

    def test_a_malformed_body_is_a_parse_error_not_a_transport_one(self, monkeypatch):
        class _R:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n=None):
                return b"<html>not json</html>"

        monkeypatch.setattr(probe.settings, "performance", lambda: {})
        monkeypatch.setattr(probe.urllib.request, "urlopen", lambda *a, **k: _R())
        b = probe._read_shodan_balance("KEY")
        assert b.read_error == "parse" and not b.known

    def test_a_successful_read_carries_no_error(self, monkeypatch):
        class _R:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n=None):
                return json.dumps(MEASURED).encode()

        monkeypatch.setattr(probe.settings, "performance", lambda: {})
        monkeypatch.setattr(probe.urllib.request, "urlopen", lambda *a, **k: _R())
        assert probe._read_shodan_balance("KEY").read_error is None

    def test_the_read_error_reaches_telemetry(self, tmp_path, monkeypatch):
        import io
        import urllib.error
        html = b"<html><title>401 Unauthorized</title></html>"
        b = self._read(monkeypatch, urllib.error.HTTPError("u", 401, "m", {}, io.BytesIO(html)))
        events.reset()
        events.configure(tmp_path)
        try:
            probe._emit_shodan_balance("probe.favicon", b)
            rec = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()
                   if '"balance"' in l][-1]
        finally:
            events.reset()
        assert rec["balance"]["read_error"] == "auth"
        # a PROVEN refusal outranks "unknown + reserve": the read itself settled it
        assert rec["balance"]["stop_kind"] == SHODAN_AUTH_REFUSED
        assert rec["balance"]["stop_is_limit"] is False
        assert rec["balance"]["may_spend"] is False


class TestProvenRefusalBlocksSpending:
    """review-B1.2r2#2: `replace(shodan_balance(None), read_error=...)` left `may_spend=True` with reserve
    0, so /api-info could PROVE a bad key or an exhausted account and the coordinator would still have
    spent credits against it. The error was recorded and then ignored by the only field anyone acts on."""

    def _read(self, monkeypatch, exc, reserve=None):
        monkeypatch.setattr(probe.settings, "performance",
                            lambda: {} if reserve is None else {"SHODAN_CREDIT_RESERVE": reserve})
        monkeypatch.setattr(probe.urllib.request, "urlopen",
                            lambda *a, **k: (_ for _ in ()).throw(exc))
        return probe._read_shodan_balance("KEY")

    def _http(self, code, body):
        import io
        import urllib.error
        return urllib.error.HTTPError("u", code, "m", {}, io.BytesIO(body))

    QUOTA = (b'{"error": "Insufficient query credits, please upgrade your API plan or wait for the '
             b'monthly limit to reset"}')
    HTML = b"<html><head><title>401 Unauthorized</title></head><body></body></html>"

    def test_a_proven_bad_key_blocks_paid_work_even_with_no_reserve(self, monkeypatch):
        b = self._read(monkeypatch, self._http(401, self.HTML))
        assert b.read_error == "auth" and b.may_spend is False and b.spendable == 0
        # a broken credential is a DEFECT to fix, not an expected boundary
        assert b.stop_kind == SHODAN_AUTH_REFUSED and b.stop_is_limit is False

    def test_a_proven_quota_blocks_and_carries_the_provider_token(self, monkeypatch):
        b = self._read(monkeypatch, self._http(401, self.QUOTA))
        assert b.read_error == "quota" and b.may_spend is False
        assert b.stop_kind == SHODAN_PROVIDER_EXHAUSTED and b.stop_is_limit is True

    def test_auth_and_quota_are_not_the_same_verdict(self, monkeypatch):
        """Both are HTTP 401 from Shodan. One is a defect to fix, the other an expected boundary — and
        collapsing them is exactly what B0 exists to prevent."""
        auth = self._read(monkeypatch, self._http(401, self.HTML))
        quota = self._read(monkeypatch, self._http(401, self.QUOTA))
        assert auth.stop_kind != quota.stop_kind
        assert auth.stop_is_limit is False and quota.stop_is_limit is True

    def test_a_forbidden_read_blocks_too(self, monkeypatch):
        b = self._read(monkeypatch, self._http(403, b"nope"))
        assert b.may_spend is False and b.stop_kind == SHODAN_FORBIDDEN
        assert b.stop_is_limit is False              # unproven refusal is a gap, not a soft limit

    @pytest.mark.parametrize("exc_kind", ["transport", "server"])
    def test_an_INCONCLUSIVE_failure_keeps_the_unknown_fallback(self, monkeypatch, exc_kind):
        """transport/5xx say nothing about the account, so with reserve 0 the run may still spend until
        the provider itself refuses — that fallback is the whole reason unknown+reserve-0 exists."""
        import urllib.error
        exc = (urllib.error.URLError("dns") if exc_kind == "transport"
               else self._http(503, b"unavailable"))
        b = self._read(monkeypatch, exc)
        assert b.read_error == exc_kind and b.may_spend is True

    @pytest.mark.parametrize("body", ['{"query_credits": "85"}', '{"query_credits": -2}', "{}",
                                      '{"usage_limits": {"query_credits": 100}}'])
    def test_decoded_but_invalid_is_a_parse_error_not_a_healthy_read(self, monkeypatch, body):
        """review-B1.2r2#3: decoding is not validating. A well-formed body with no usable `query_credits`
        was reported as a SUCCESSFUL read of an unknown balance — a broken response looking healthy."""
        class _R:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n=None):
                return body.encode()

        monkeypatch.setattr(probe.settings, "performance", lambda: {})
        monkeypatch.setattr(probe.urllib.request, "urlopen", lambda *a, **k: _R())
        b = probe._read_shodan_balance("KEY")
        assert b.read_error == "parse" and not b.known

    def test_a_malformed_usage_limits_is_still_non_fatal(self, monkeypatch):
        """`usage_limits` is CONTEXT. A broken one must not invalidate a perfectly good balance."""
        class _R:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n=None):
                return b'{"query_credits": 85, "usage_limits": "broken"}'

        monkeypatch.setattr(probe.settings, "performance", lambda: {})
        monkeypatch.setattr(probe.urllib.request, "urlopen", lambda *a, **k: _R())
        b = probe._read_shodan_balance("KEY")
        assert b.read_error is None and b.remaining == 85 and b.may_spend is True


class TestAReadFailureIsNotMaskedByTheReserve:
    """Carried into B1.3 (Lumpy): a transport/parse failure WITH a reserve configured must keep BOTH
    facts — the operator limit stopped us, AND the read genuinely failed. The stop is the reason no
    search runs; the read_error is a real gap that must still dominate reconciliation. If the reserve
    silently absorbed the failure, a permanently broken /api-info would look like ordinary caution."""

    def _read(self, monkeypatch, exc, reserve=10):
        monkeypatch.setattr(probe.settings, "performance",
                            lambda: {"SHODAN_CREDIT_RESERVE": reserve})
        monkeypatch.setattr(probe.urllib.request, "urlopen",
                            lambda *a, **k: (_ for _ in ()).throw(exc))
        return probe._read_shodan_balance("KEY")

    def test_transport_failure_plus_reserve_carries_both(self, monkeypatch):
        import urllib.error
        b = self._read(monkeypatch, urllib.error.URLError("dns dead"))
        assert b.read_error == "transport"                       # the REAL failure survives
        assert b.stop_kind == SHODAN_UNKNOWN_WITH_RESERVE        # and why no paid search runs
        assert b.may_spend is False

    def test_parse_failure_plus_reserve_carries_both(self, monkeypatch):
        class _R:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n=None):
                return b"<html>not json</html>"

        monkeypatch.setattr(probe.settings, "performance", lambda: {"SHODAN_CREDIT_RESERVE": 10})
        monkeypatch.setattr(probe.urllib.request, "urlopen", lambda *a, **k: _R())
        b = probe._read_shodan_balance("KEY")
        assert b.read_error == "parse" and b.stop_kind == SHODAN_UNKNOWN_WITH_RESERVE

    def test_the_stop_being_a_LIMIT_does_not_erase_the_gap(self, monkeypatch):
        """`unknown_with_reserve` IS a soft limit — but a failed read alongside it is not, and B1.3 must
        reconcile the gap rather than let the limit soften the run."""
        import urllib.error
        b = self._read(monkeypatch, urllib.error.URLError("dns dead"))
        assert b.stop_is_limit is True                           # the STOP is expected
        assert b.read_error is not None                          # the READ is not — both are true

    def test_both_facts_reach_telemetry(self, monkeypatch, tmp_path):
        import urllib.error
        b = self._read(monkeypatch, urllib.error.URLError("dns dead"))
        events.reset()
        events.configure(tmp_path)
        try:
            probe._emit_shodan_balance("probe.favicon", b)
            rec = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()
                   if '"balance"' in l][-1]
        finally:
            events.reset()
        assert rec["balance"]["read_error"] == "transport"
        assert rec["balance"]["stop_kind"] == SHODAN_UNKNOWN_WITH_RESERVE

    def test_without_a_reserve_the_same_failure_still_permits_spending(self, monkeypatch):
        """The control: the reserve is what stops us, not the failed read — transport says nothing about
        the account, so with no reserve the run may still spend until the provider refuses."""
        import urllib.error
        b = self._read(monkeypatch, urllib.error.URLError("dns dead"), reserve=0)
        assert b.read_error == "transport" and b.may_spend is True and not b.stop_kind
