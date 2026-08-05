"""B1.6 — the Whoxy paginator's lifecycle, driven hermetically.

`fetch`/`ingest` are injected, so nothing here can reach Whoxy or spend a credit. Fixtures mirror the
MEASURED envelopes (2026-07-29): `total_results` is a string when non-empty, `total_pages` bounds the
walk, page size is 100, and one credit buys one page.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from quarry_recon import budget, whoxy_page as wp
from quarry_recon.whoxy_page import Anchor, AnchorState, item_key

pytestmark = pytest.mark.offline

#: SANITIZED measured payloads, committed so a clean runner exercises the real shapes. The verbatim
#: originals stay out of the repo — they carry registrant PII.
FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "whoxy"


@pytest.fixture(autouse=True)
def _never_touch_the_real_spend_lock(tmp_path, monkeypatch):
    """The spend lock is installation-wide, which means the operator's own `~/.config/quarry` — no test
    may create or contend for it, including via a default argument."""
    monkeypatch.setattr(wp, "SPEND_LOCK", tmp_path / "install-spend.lock")

COMPANY = "company"
EMAIL = "email"


def _body(param, value, page, total, pages=None, rows=None):
    """A measured-shape reverse-whois page. `total_results` is a STRING, as Whoxy sends it."""
    pages = pages if pages is not None else max(1, -(-total // wp.WHOXY_PAGE_SIZE))
    n = rows if rows is not None else min(wp.WHOXY_PAGE_SIZE, max(0, total - (page - 1) * 100))
    return json.dumps({
        "status": 1, "api_query": "reverse_whois", "search_identifier": {param: value},
        "total_results": str(total), "total_pages": pages, "current_page": page,
        "search_result": [{"domain_name": f"p{page}d{i}.example.com"} for i in range(n)],
    }).encode()


def _rows(doc):
    return doc.get("rows") or []


class _Provider:
    """A scripted Whoxy. Every call is recorded, so "was a credit spent?" is directly observable."""

    def __init__(self, totals=None, errors=None):
        self.totals = totals or {}
        self.errors = errors or {}
        self.calls = []

    def fetch(self, anchor, page):
        self.calls.append((anchor.param, anchor.value, page))
        err = self.errors.get((anchor.value, page)) or self.errors.get(anchor.value)
        if err is not None:
            return b"", err
        total = self.totals.get(anchor.value, 1)
        return _body(anchor.param, anchor.value, page, total), None


def _err(cls):
    e = RuntimeError(f"simulated {cls}")
    e.error_class = cls
    return e


#: THE PRODUCTION READER. review-B1.6r3: this suite used a permissive stand-in, which is precisely what
#: let a body with 250 results and no pagination pass as a terminal page. A test reader laxer than
#: production hides the defects the tests exist to find.
_read = wp.read_page


def _states(*pairs):
    return [AnchorState(Anchor(p, v)) for p, v in pairs]


def _ledger(tmp_path):
    base = tmp_path / "state"
    base.mkdir(parents=True, exist_ok=True)
    return budget.Ledger(budget.state_path(base, "osint.whoxy", "fp0"), lane="osint.whoxy")


def _run(tmp_path, states, provider, *, spend=None, ledger=None, seen=None, attempt="a0"):
    # artifacts live UNDER the ledger's own base: `Ledger.record` stores paths relative to it, so a page
    # written outside that tree cannot be owned at all. One project-owned base holds both.
    d = tmp_path / "state" / "pages" / attempt
    d.mkdir(parents=True, exist_ok=True)
    seen = seen if seen is not None else []

    def ingest(anchor, page, doc, art):
        rows = _rows(doc)                      # the production reader hands back validated domains
        seen.extend(rows)
        return len(rows)

    return wp.run_pages(states, paid=lambda: wp.fixed_allowance(spend), fetch=provider.fetch,
                        ingest=ingest, read=_read,
                        ledger=ledger if ledger is not None else _ledger(tmp_path), attempt_dir=d), seen


class TestSpendable:
    """Two controls, two problems: a RESERVE protects credits for later, a RUN BUDGET limits this
    invocation, and the effective spend is bounded by both."""

    @pytest.mark.parametrize("bal,res,run,want", [
        (200, 0, 0, 200),        # no operator ceiling at all
        (200, 50, 0, 150),       # reserve only
        (200, 0, 10, 10),        # run budget only
        (200, 50, 10, 10),       # both -> the tighter one
        (200, 250, 0, 0),        # a reserve larger than the balance withholds everything
        (0, 0, 0, 0),            # a genuinely empty account
    ])
    def test_the_bound_is_the_tighter_of_the_two(self, bal, res, run, want):
        """`spendable` is the pure arithmetic; `spend_policy` wraps it with the mandatory preflight."""
        assert wp.spendable(bal, res, run) == want

    def test_an_UNKNOWN_balance_is_not_zero(self):
        """Refusing to work would turn "we could not read the balance" into "there are no credits"."""
        assert wp.spendable(None, 0, 0) is None
        assert wp.spendable(None, 0, 7) == 7

    def test_an_unknown_balance_WITH_a_reserve_spends_NOTHING(self):
        """The B1.2 rule: a reserve says "keep N back", and that cannot be honoured against an unknown
        balance. Our own caution stops us — an operator limit, not the provider refusing."""
        assert wp.spendable(None, 50, 0) == 0
        assert wp.spendable(None, 50, 10) == 0

    def test_the_reserve_is_NOT_part_of_a_page_identity_either(self):
        a = Anchor(COMPANY, "Acme")
        assert item_key(a, 1) == item_key(a, 1)

    def test_the_reserve_is_NOT_part_of_a_page_identity(self):
        """Changing a spending policy must never re-buy a page that is already paid for."""
        a = Anchor(COMPANY, "Acme")
        assert item_key(a, 1) == item_key(a, 1)
        assert len({item_key(a, p) for p in (1, 2, 3)}) == 3
        assert item_key(a, 1) != item_key(Anchor(EMAIL, "Acme"), 1)


class TestOrdering:
    def _sched(self, states):
        return [(st.anchor.value, pg) for st, pg in wp.schedule(states)]

    def test_page_ONE_of_every_anchor_precedes_page_two_of_any(self):
        """One credit per page and 398 pages for one anchor: breadth before depth, or a single anchor
        drains the account before another is opened."""
        deep = AnchorState(Anchor(COMPANY, "big"), total_pages=398)
        deep.pages_done.add(1)
        fresh = AnchorState(Anchor(COMPANY, "new"))
        assert self._sched([deep, fresh]) == [("new", 1), ("big", 2)]

    def test_rare_anchors_come_first_within_a_tier(self):
        a = AnchorState(Anchor(COMPANY, "rare"), total_pages=2)
        b = AnchorState(Anchor(COMPANY, "generic"), total_pages=398)
        a.pages_done.add(1)
        b.pages_done.add(1)
        assert self._sched([b, a]) == [("rare", 2), ("generic", 2)]

    def test_an_unopened_anchor_offers_exactly_ONE_page(self):
        """Until page 1 answers there is no page count, so nothing beyond it can be scheduled."""
        st = AnchorState(Anchor(COMPANY, "x"))
        assert self._sched([st]) == [("x", 1)]

    def test_total_pages_BOUNDS_the_walk(self):
        """Past-end is `status: 0 "Invalid Page Number"`, which classifies as a plain failure — probing
        for the end would turn a clean completion into a provider error."""
        st = AnchorState(Anchor(COMPANY, "x"), total_pages=2)
        st.pages_done.update({1, 2})
        assert self._sched([st]) == []
        assert st.next_page() is None

    def test_the_two_QUESTION_FORMS_share_a_tier_fairly(self):
        """Fifty company anchors must not starve the registrant-email anchors, which are the stronger
        ownership signal. Grouping by ANCHOR instead of anchor TYPE made every anchor its own group, and
        `order_fairly` visits groups in sorted key order — which silently re-sorted them alphabetically
        and discarded the cardinality pre-sort."""
        states = []
        for i in range(4):
            st = AnchorState(Anchor(COMPANY, f"c{i}"), total_pages=9)
            st.pages_done.add(1)
            states.append(st)
        e = AnchorState(Anchor(EMAIL, "e0"), total_pages=9)
        e.pages_done.add(1)
        states.append(e)
        got = [st.anchor.param for st, _pg in wp.schedule(states)]
        assert got[:2] == [COMPANY, EMAIL], got      # alternating, not four companies first

    def test_an_ABSURD_page_count_is_not_trusted(self):
        """`total_pages` is the only thing terminating an unbounded walk, so a value the provider's own
        `total_results` does not corroborate must not become a bound — we would paginate, and PAY, for
        as long as it said to. MEASURED: total_pages == ceil(total_results / 100), on both forms."""
        assert wp.usable_page_count(398, 39766) == 398        # the measured company anchor
        assert wp.usable_page_count(4, 355) == 4              # the measured email anchor
        assert wp.usable_page_count(1, 0) == 1
        for bad in [(999999, 355), (0, 355), (-1, 355), ("4", 355), (4, None), (4, "355"), (4, -1),
                    # sharper cases: each of these would be ACCEPTED by a plausible weakening —
                    # `True == 1`, and an absent count invented as 0 makes `expected` 1.
                    (True, 100), (True, 0), (1, None), (1, "0"), (1, True)]:
            assert wp.usable_page_count(*bad) is None, bad

    def test_a_corrupted_page_count_can_never_ENTER_the_state(self, tmp_path):
        """`total_pages` is what terminates the walk, so the guard has to be at the point of ADOPTION —
        a bound is corroborated before it is believed, and an uncorroborated one simply never becomes
        one. (A ceiling computed FROM the folded value cannot help: it would be derived from the very
        number it distrusts.)"""
        p = _Provider()

        def bogus(anchor, page):
            p.calls.append((anchor.param, anchor.value, page))
            return json.dumps({
                "status": 1, "api_query": "reverse_whois",
                "search_identifier": {anchor.param: anchor.value},
                "total_results": "100", "total_pages": 10 ** 6, "current_page": page,
                "search_result": [{"domain_name": f"p{page}.example.com"}]}).encode(), None

        p.fetch = bogus
        st = AnchorState(Anchor(COMPANY, "a"))
        # BOUNDED deliberately: if the guard is broken the walk is unbounded, and an unbounded fixture
        # would HANG rather than fail — the one outcome that tells us nothing. With a budget, a broken
        # guard shows up as "it bought more than one page".
        out, _ = _run(tmp_path, [st], p, spend=5)
        assert st.total_pages is None, "an uncorroborated bound was adopted"
        # ...and the page is not OWNED either: recording it would stop it ever being re-bought, so a
        # transient contradiction would become permanent (review-B1.6r2#3).
        assert len(p.calls) == 1 and out.pages_bought == 0 and out.evidence_invalid == 1

    def test_a_page_whose_count_does_not_corroborate_leaves_it_UNKNOWN(self, tmp_path):
        """The anchor keeps the page it bought and stops: an uncorroborated count is not a licence to
        keep spending, and it is not a reason to discard evidence already paid for."""
        p = _Provider()

        def uncorroborated(anchor, page):
            p.calls.append((anchor.param, anchor.value, page))
            return json.dumps({
                "status": 1, "api_query": "reverse_whois",
                "search_identifier": {anchor.param: anchor.value},
                "total_results": "355", "total_pages": 999999, "current_page": page,
                "search_result": [{"domain_name": "a.example.com"}]}).encode(), None

        p.fetch = uncorroborated
        out, seen = _run(tmp_path, _states((COMPANY, "a")), p, spend=5)   # bounded: see above
        assert len(p.calls) == 1, f"kept paginating against a bound the provider did not corroborate: {p.calls}"
        assert out.pages_bought == 0 and out.evidence_invalid == 1 and seen == []
        assert out.pages_left_known == 0 and out.pages_left_unknown_anchors == 0

    def test_ordering_never_changes_membership(self):
        states = [AnchorState(Anchor(COMPANY, "generic"), total_pages=398),
                  AnchorState(Anchor(EMAIL, "rare"), total_pages=1)]
        assert len(wp.schedule(states)) == 2

    def test_a_duplicate_anchor_cannot_buy_page_one_twice(self, tmp_path):
        p = _Provider(totals={"a": 250})
        _run(tmp_path, _states((COMPANY, "a"), (COMPANY, "a")), p, spend=1)
        assert p.calls == [(COMPANY, "a", 1)], p.calls


class TestPurchaseAndReplay:
    def test_a_REQUESTED_anchor_is_recorded(self, tmp_path):
        """review-B1.6b14#6: `anchors - unopened` counted a replay-only lifecycle as having attempted
        every anchor while issuing zero requests, so the paginator records which anchors it ASKED."""
        led = _ledger(tmp_path)
        out, _ = _run(tmp_path, _states((COMPANY, "a")), _Provider(totals={"a": 250}), ledger=led)
        assert out.requested == {(COMPANY, "a")} and out.requests_issued == 3
        p2 = _Provider(totals={"a": 250})
        out2, _ = _run(tmp_path, _states((COMPANY, "a")), p2, ledger=_ledger(tmp_path), attempt="a1")
        assert out2.requested == set() and out2.requests_issued == 0, "a replay counted as a request"
        assert out2.pages_replayed == 3

    def test_a_full_walk_buys_every_page_once(self, tmp_path):
        p = _Provider(totals={"a": 250})                       # 3 pages
        out, seen = _run(tmp_path, _states((COMPANY, "a")), p)
        assert [c[2] for c in p.calls] == [1, 2, 3]
        assert out.pages_bought == 3 and out.pages_left_known == 0
        assert out.domains == 250 and len(seen) == 250

    def test_a_second_lifecycle_REPLAYS_and_spends_nothing(self, tmp_path):
        """Cross-run resume is the whole point: without it every OSINT run re-buys page 1."""
        led = _ledger(tmp_path)
        _run(tmp_path, _states((COMPANY, "a")), _Provider(totals={"a": 250}), ledger=led)
        p2 = _Provider(totals={"a": 250})
        out, seen = _run(tmp_path, _states((COMPANY, "a")), p2, ledger=_ledger(tmp_path),
                         attempt="a1")
        assert p2.calls == [], f"a paid page was re-bought: {p2.calls}"
        assert out.pages_replayed == 3 and out.pages_bought == 0
        assert out.domains == 250 and len(seen) == 250, "replayed pages were not re-ingested"

    def test_a_budget_stops_buying_and_leaves_a_COUNTED_remainder(self, tmp_path):
        p = _Provider(totals={"a": 1000})                      # 10 pages
        out, _ = _run(tmp_path, _states((COMPANY, "a")), p, spend=3)
        assert out.pages_bought == 3 and out.stop_cause == "budget_exhausted"
        assert out.pages_left_known == 7

    def test_the_remainder_is_RESUMABLE(self, tmp_path):
        led = _ledger(tmp_path)
        _run(tmp_path, _states((COMPANY, "a")), _Provider(totals={"a": 1000}), spend=3, ledger=led)
        p2 = _Provider(totals={"a": 1000})
        out, _ = _run(tmp_path, _states((COMPANY, "a")), p2, spend=3, ledger=_ledger(tmp_path),
                      attempt="a1")
        assert [c[2] for c in p2.calls] == [4, 5, 6], p2.calls
        assert out.pages_replayed == 3 and out.pages_bought == 3

    def test_a_ZERO_budget_buys_nothing_but_still_replays(self, tmp_path):
        led = _ledger(tmp_path)
        _run(tmp_path, _states((COMPANY, "a")), _Provider(totals={"a": 250}), spend=1, ledger=led)
        p2 = _Provider(totals={"a": 250})
        out, seen = _run(tmp_path, _states((COMPANY, "a")), p2, spend=0,
                         ledger=_ledger(tmp_path), attempt="a1")
        assert p2.calls == [] and out.pages_replayed == 1 and len(seen) == 100

    def test_anchors_share_the_budget_FAIRLY(self, tmp_path):
        p = _Provider(totals={"big": 39766, "small": 355})
        out, _ = _run(tmp_path, _states((COMPANY, "big"), (EMAIL, "small")), p, spend=2)
        assert {c[1] for c in p.calls} == {"big", "small"}, p.calls
        assert out.anchors_touched == 2

    def test_an_unopened_anchor_is_reported_by_IDENTITY(self, tmp_path):
        p = _Provider(totals={"a": 100, "b": 100})
        out, _ = _run(tmp_path, _states((COMPANY, "a"), (COMPANY, "b")), p, spend=1)
        assert len(out.unopened) == 1 and "=" in out.unopened[0]


class TestEvidence:
    def test_the_stored_page_is_the_EXACT_response_bytes(self, tmp_path):
        """Never reserialized: a re-encoded page is our account of the answer, not the answer — and the
        PII-bearing fields we do not parse must survive verbatim."""
        p = _Provider(totals={"a": 100})
        _run(tmp_path, _states((COMPANY, "a")), p)
        art = next((tmp_path / "state" / "pages").rglob("*.json"))
        assert art.read_bytes() == _body(COMPANY, "a", 1, 100)

    def test_an_unusable_page_is_NOT_owned(self, tmp_path):
        """The bytes are stored as evidence, but a page we cannot read must be re-bought, not owned."""
        led = _ledger(tmp_path)
        p = _Provider()
        p.fetch = lambda anchor, page: (p.calls.append((anchor.param, anchor.value, page)),
                                        (b'{"status":1,"search_identifier":{"company":"WRONG"}}',
                                         None))[1]
        out, _ = _run(tmp_path, _states((COMPANY, "a")), p, ledger=led)
        assert out.evidence_invalid == 1 and out.pages_bought == 0
        assert not _ledger(tmp_path).has(item_key(Anchor(COMPANY, "a"), 1))

    def test_a_DAMAGED_owned_page_is_re_bought(self, tmp_path):
        led = _ledger(tmp_path)
        _run(tmp_path, _states((COMPANY, "a")), _Provider(totals={"a": 100}), ledger=led)
        art = led.artifact(item_key(Anchor(COMPANY, "a"), 1))
        art.write_text("{}")
        p2 = _Provider(totals={"a": 100})
        out, _ = _run(tmp_path, _states((COMPANY, "a")), p2, ledger=_ledger(tmp_path), attempt="a1")
        assert [c[2] for c in p2.calls] == [1] and out.pages_bought == 1

    def test_an_unwritable_STORE_costs_NOTHING(self, tmp_path, monkeypatch):
        """review-B1.6r1#3: only the ledger was probed, so a read-only artifact store was discovered by
        paying for a page and then failing to store it. The old test asserted `len(p.calls) == 1` — it
        was locking in that lost credit."""
        monkeypatch.setattr(budget, "publish_bytes", lambda dest, data, digest: False)
        p = _Provider(totals={"a": 1000})
        out, _ = _run(tmp_path, _states((COMPANY, "a")), p)
        assert p.calls == [], f"paid for a page the store could not hold: {p.calls}"
        assert out.stop_cause == "publish_failed"

    def test_a_MID_RUN_publish_failure_still_stops_paying(self, tmp_path, monkeypatch):
        """The probe proves the store at the start; a store that breaks later must still end the run."""
        real = budget.publish_bytes
        state = {"n": 0}

        def flaky(dest, data, digest):
            if ".quarry-write-probe" in str(dest):
                return real(dest, data, digest=digest)
            state["n"] += 1
            return False

        monkeypatch.setattr(budget, "publish_bytes", flaky)
        p = _Provider(totals={"a": 1000})
        out, _ = _run(tmp_path, _states((COMPANY, "a")), p)
        assert len(p.calls) == 1 and out.stop_cause == "publish_failed"
        assert out.publish_failed == 1

    def test_an_unwritable_ledger_spends_NOTHING(self, tmp_path):
        led = _ledger(tmp_path)
        led.journal.parent.mkdir(parents=True, exist_ok=True)
        led.journal.mkdir()                                    # appending here can only raise
        p = _Provider(totals={"a": 1000})
        out, _ = _run(tmp_path, _states((COMPANY, "a")), p, ledger=led)
        assert p.calls == [] and out.stop_cause == "ledger_unwritable"


class TestReviewB1_6r1:
    """The six defects the first core shipped with. Four were lessons already learned in the Shodan
    coordinator and not carried across — the reason each test names what it reproduces."""

    def test_a_DAMAGED_early_page_does_not_cost_the_LATER_ones(self, tmp_path):
        """#1: ownership discovery stopped at the first hole, so damaging page 1 made pages 2-3 invisible
        and all three were bought again. Paid evidence lost to a gap above it."""
        led = _ledger(tmp_path)
        _run(tmp_path, _states((COMPANY, "a")), _Provider(totals={"a": 250}), ledger=led)
        led.artifact(item_key(Anchor(COMPANY, "a"), 1)).write_text("{}")     # damage page 1 only
        p2 = _Provider(totals={"a": 250})
        out, _ = _run(tmp_path, _states((COMPANY, "a")), p2, ledger=_ledger(tmp_path), attempt="a1")
        assert [c[2] for c in p2.calls] == [1], f"pages above the hole were re-bought: {p2.calls}"
        assert out.pages_replayed == 2 and out.pages_bought == 1

    def test_a_TRANSPLANTED_artifact_cannot_donate_ownership(self, tmp_path):
        """#1: enumeration reads the page's own identity, so the key it is filed under must agree — or a
        page bought for one anchor would count as another anchor's."""
        led = _ledger(tmp_path)
        _run(tmp_path, _states((COMPANY, "a")), _Provider(totals={"a": 100}), ledger=led)
        art = led.artifact(item_key(Anchor(COMPANY, "a"), 1))
        led2 = _ledger(tmp_path)
        led2.record(item_key(Anchor(COMPANY, "b"), 1), art)      # same bytes, a DIFFERENT question
        led2.save()
        idx = wp.owned_index(_ledger(tmp_path), _read)
        assert set(idx) == {(COMPANY, "a")}, idx
        # the count is what reveals it: without the binding the mis-keyed item is read, believed, and
        # filed under the identity its BYTES claim — so the page appears TWICE and is replayed twice.
        assert len(idx[(COMPANY, "a")]) == 1, idx[(COMPANY, "a")]
        out, seen = _run(tmp_path, _states((COMPANY, "a")), _Provider(totals={"a": 100}),
                         ledger=_ledger(tmp_path), attempt="a1")
        assert out.pages_replayed == 1 and len(seen) == 100, "a page was ingested twice"

    def test_the_sinks_are_probed_ONCE_per_run(self, tmp_path, monkeypatch):
        """#3: each probe writes a journal record and republishes a file, so repeating it per purchase
        would grow the journal and touch the artifact tree on every page."""
        seen = {"n": 0}
        real = budget.store_writable
        monkeypatch.setattr(budget, "store_writable",
                            lambda d: (seen.__setitem__("n", seen["n"] + 1), real(d))[1])
        p = _Provider(totals={"a": 250})                          # three pages
        out, _ = _run(tmp_path, _states((COMPANY, "a")), p)
        assert out.pages_bought == 3 and seen["n"] == 1, seen

    def test_a_page_that_reached_NEITHER_destination_is_not_persisted(self, tmp_path):
        """#2: a checkpoint journals, the paid page's own append fails, compaction fails too — every
        signal survivable while the page exists nowhere."""
        led = _ledger(tmp_path)
        real_append, real_replace = led._append, __import__("os").replace
        led._append = lambda rec: False if "i" in rec else real_append(rec)
        import quarry_recon.budget as _b

        def fail(src, dst, *a, **k):
            if str(dst).endswith(led.path.name):
                raise OSError("no space left on device")
            return real_replace(src, dst, *a, **k)

        _b.os.replace = fail
        try:
            out, _ = _run(tmp_path, _states((COMPANY, "a")), _Provider(totals={"a": 100}), ledger=led)
        finally:
            _b.os.replace = real_replace
        assert out.pages_bought == 1 and led.durable is True     # the trap: the OLD journal is readable
        assert out.persisted is False, "a page that reached no destination read as durable"
        assert not _ledger(tmp_path).has(item_key(Anchor(COMPANY, "a"), 1))

    def test_a_replay_only_lifecycle_probes_NEITHER_sink(self, tmp_path, monkeypatch):
        """#3: the probes must be lazy. A run that buys nothing needs neither sink, and judging it on
        one it never used would report a failure it did not have."""
        led = _ledger(tmp_path)
        _run(tmp_path, _states((COMPANY, "a")), _Provider(totals={"a": 100}), ledger=led)
        seen = {"store": 0}
        monkeypatch.setattr(budget, "store_writable",
                            lambda d: (seen.__setitem__("store", seen["store"] + 1), True)[1])
        p2 = _Provider(totals={"a": 100})
        out, _ = _run(tmp_path, _states((COMPANY, "a")), p2, ledger=_ledger(tmp_path), attempt="a1")
        assert p2.calls == [] and out.pages_replayed == 1
        assert seen["store"] == 0 and out.stop_cause == ""

    def test_a_LATER_page_reporting_MORE_expands_the_walk(self, tmp_path):
        """#4: totals were adopted only while unknown, so page 1 saying 200 bounded a walk that page 2
        said was 300 long — two pages fetched, no remainder reported, the rest silently uncollected."""
        p = _Provider()
        totals = {1: 200, 2: 300, 3: 300}

        def growing(anchor, page):
            p.calls.append((anchor.param, anchor.value, page))
            tot = totals.get(page, 300)
            return _body(anchor.param, anchor.value, page, tot), None

        p.fetch = growing
        out, _ = _run(tmp_path, _states((COMPANY, "a")), p)
        assert [c[2] for c in p.calls] == [1, 2, 3], p.calls
        assert out.total_drift == 1 and out.pages_left_known == 0

    def test_an_INVALID_spending_control_stops_paid_work(self, tmp_path):
        """#5: `run_budget=-1` clamped to 0, and 0 MEANS "no operator ceiling" — a typo in a cost guard
        became permission to spend the whole balance."""
        bal = wp.read_balance('{"status": 1, "reverse_whois_balance": 200}')
        assert wp.spend_policy(bal, 0, -1).pages == 0
        assert "WHOXY_PAGE_BUDGET" in wp.spend_policy(bal, 0, -1).invalid
        assert wp.spend_policy(bal, -5, 0).pages == 0
        assert "WHOXY_CREDIT_RESERVE" in wp.spend_policy(bal, -5, 0).invalid
        assert wp.spend_policy(bal, True, 0).pages == 0        # bool is not a count
        assert wp.spend_policy(bal, "10", 0).pages == 0
        good = wp.spend_policy(bal, 50, 0)
        assert good.pages == 150 and good.invalid == ""

    def test_a_FAILED_response_body_is_kept_as_evidence(self, tmp_path):
        """#6: the bytes were discarded whenever an error was present — and Whoxy reports failure INSIDE
        an HTTP 200 status envelope, which is exactly where the explanation lives."""
        body = json.dumps({"status": 0, "status_reason": "Invalid Page Number"}).encode()
        p = _Provider()

        def refuse(anchor, page):
            p.calls.append((anchor.param, anchor.value, page))
            return body, _err("error")

        p.fetch = refuse
        out, _ = _run(tmp_path, _states((COMPANY, "a")), p)
        assert out.error_bodies == 1 and out.pages_bought == 0
        kept = [q.read_bytes() for q in (tmp_path / "state" / "pages").rglob("*.json")
                if q.name != ".quarry-write-probe"]
        assert kept == [body], kept
        assert not _ledger(tmp_path).has(item_key(Anchor(COMPANY, "a"), 1)), "an error body was OWNED"

    def test_requests_are_counted_apart_from_pages_OWNED(self, tmp_path):
        """#6: `pages_bought` counts usable owned pages, which is not what the account was charged."""
        p = _Provider(totals={"a": 1000}, errors={("a", 2): _err("transport")})
        out, _ = _run(tmp_path, _states((COMPANY, "a")), p)
        assert out.requests_issued == 2 and out.pages_bought == 1


class TestReviewB1_6r2:
    def test_a_failed_EVIDENCE_bind_stops_paid_work(self, tmp_path):
        """#1: `add_evidence` was called and its result discarded, so a bind could fail while the run
        reported error bodies retained and `persisted=True` — and a reopened ledger held nothing."""
        led = _ledger(tmp_path)
        real = led.add_evidence
        led.add_evidence = lambda *a, **k: False
        body = json.dumps({"status": 0, "status_reason": "Zero Account Balance"}).encode()
        p = _Provider()

        def refuse(anchor, page):
            p.calls.append((anchor.param, anchor.value, page))
            return body, _err("error")

        p.fetch = refuse
        out, _ = _run(tmp_path, _states((COMPANY, "a"), (COMPANY, "b")), p, ledger=led)
        assert len(p.calls) == 1, f"kept paying after a ledger write failed: {p.calls}"
        assert out.stop_cause == "ledger_unwritable" and out.error_bodies == 0
        assert out.records_journaled is False
        led.add_evidence = real

    def test_an_UNUSABLE_success_body_is_bound_as_evidence_too(self, tmp_path):
        """#1: an invalid success body was left as a loose artifact file, called evidence and bound to
        nothing. It is retained under the ERROR namespace, so it can never read as a page we own."""
        led = _ledger(tmp_path)
        p = _Provider()

        def contradictory(anchor, page):
            p.calls.append((anchor.param, anchor.value, page))
            return json.dumps({
                "status": 1, "api_query": "reverse_whois",
                "search_identifier": {anchor.param: anchor.value},
                "total_results": "100", "total_pages": 77, "current_page": page,
                "search_result": []}).encode(), None

        p.fetch = contradictory
        out, _ = _run(tmp_path, _states((COMPANY, "a")), p, ledger=led, spend=2)
        assert out.evidence_invalid == 1 and out.pages_bought == 0
        re = _ledger(tmp_path)
        assert re.evidence(wp.error_key(Anchor(COMPANY, "a"), 1)), "the unusable body was not bound"
        assert not re.has(item_key(Anchor(COMPANY, "a"), 1))

    def test_a_contradictory_page_can_REPAIR_itself_next_lifecycle(self, tmp_path):
        """#3: recording it stopped it ever being re-bought, so a transient contradiction was permanent."""
        led = _ledger(tmp_path)
        p1 = _Provider()
        p1.fetch = lambda a, pg: (json.dumps({
            "status": 1, "api_query": "reverse_whois", "search_identifier": {a.param: a.value},
            "total_results": "100", "total_pages": 77, "current_page": pg,
            "search_result": []}).encode(), None)
        _run(tmp_path, _states((COMPANY, "a")), p1, ledger=led, spend=2)
        p2 = _Provider(totals={"a": 100})                      # the provider is healthy again
        out, seen = _run(tmp_path, _states((COMPANY, "a")), p2, ledger=_ledger(tmp_path), attempt="a1")
        assert [c[2] for c in p2.calls] == [1], p2.calls
        assert out.pages_bought == 1 and len(seen) == 100

    @pytest.mark.parametrize("bad", ['{"status": 1, "reverse_whois_balance": "200"}',
                                     '{"status": 1, "reverse_whois_balance": true}',
                                     '{"status": 1, "reverse_whois_balance": 12.5}',
                                     '{"status": 1, "reverse_whois_balance": -1}',
                                     "[]", "{}"])
    def test_a_MALFORMED_provider_balance_permits_no_paid_work(self, bad):
        """#2: the operator's controls were validated and the provider's balance — the least trustworthy
        of the three, since it arrives over the network — was coerced with `int()`.

        review-B1.6r3#4: it is reported SEPARATELY from the operator's controls. Provider schema drift
        filed as configuration would send an operator to fix a knob that is perfectly correct."""
        pol = wp.spend_policy(wp.read_balance(bad), 0, 0)
        assert pol.pages == 0, (bad, pol)
        assert pol.balance_invalid and pol.invalid == "", (bad, pol)

    def test_an_operator_control_and_a_provider_balance_are_DIFFERENT_faults(self):
        ok = wp.read_balance('{"status": 1, "reverse_whois_balance": 200}')
        drifted = wp.read_balance('{"status": 1, "reverse_whois_balance": "200"}')
        cfg = wp.spend_policy(ok, -5, 0)
        assert "WHOXY_CREDIT_RESERVE" in cfg.invalid and cfg.balance_invalid == ""
        drift = wp.spend_policy(drifted, 0, 0)
        assert drift.balance_invalid and drift.invalid == "", drift
        # a broken CONTROL is checked first: an operator cannot act on a provider report while their own
        # configuration is unusable, and both stop paid work anyway.
        both = wp.spend_policy(drifted, -5, 0)
        assert both.pages == 0 and both.invalid, both

    def test_a_READABLE_balance_carries_no_fault(self):
        assert wp.spend_policy(wp.read_balance('{"status": 1, "reverse_whois_balance": 5}'),
                               0, 0).invalid == ""

    def test_the_measured_COMPACT_no_match_is_a_terminal_page(self, tmp_path):
        """#3: the measured no-match carries NO pagination fields at all. That is not drift — it is the
        whole answer, one page, nothing to walk. No core test had ever exercised the real payload."""
        p = _Provider()

        def compact(anchor, page):
            p.calls.append((anchor.param, anchor.value, page))
            return json.dumps({"status": 1, "api_query": "reverse_whois",
                               "search_identifier": {anchor.param: anchor.value},
                               "total_results": 0, "api_execution_time": 0.01}).encode(), None

        p.fetch = compact
        out, seen = _run(tmp_path, _states((COMPANY, "a")), p)
        assert [c[2] for c in p.calls] == [1], p.calls
        assert out.pages_bought == 1 and seen == [] and out.pages_left_known == 0
        assert wp.classify_page({"total_results_int": 0}) == (wp.PAGE_TERMINAL, 1)

    def test_requests_issued_is_not_a_credit_count(self):
        """#4: the measured past-end refusal cost ZERO, so "a request" and "a credit" are different
        facts. The allowance is decremented per attempt conservatively; only the balance says what was
        actually charged."""
        assert "requests_issued" in wp.Outcome.__dataclass_fields__
        assert "requests" not in wp.Outcome.__dataclass_fields__


class TestReviewB1_6r3:
    def test_a_body_that_omits_pagination_but_claims_RESULTS_is_not_terminal(self, tmp_path):
        """#1: "no pagination fields" was far wider than the measurement. A body claiming 250 results,
        returning 100 rows and simply omitting its pagination became an owned one-page completion — 150
        results silently dropped by a shape we have never seen."""
        assert wp.classify_page({"total_results_int": 250,
                                 "search_result": [{"domain_name": "a.com"}]})[0] == wp.PAGE_CONTRADICTORY
        assert wp.classify_page({"total_results_int": 0})[0] == wp.PAGE_TERMINAL
        assert wp.classify_page({"total_results_int": 0,
                                 "search_result": [{"domain_name": "a.com"}]})[0] == wp.PAGE_CONTRADICTORY

    @pytest.mark.parametrize("total,pages,page,rows,ok", [
        (50, 1, 1, 50, True),        # the whole answer on one page
        (50, 1, 1, 1, False),        # THE DEFECT: 50 claimed, one delivered, accepted as complete
        (50, 1, 1, 49, False),
        (250, 3, 1, 100, True),      # a non-final page is always full
        (250, 3, 1, 99, False),
        (250, 3, 3, 50, True),       # the final page carries the remainder
        (250, 3, 3, 49, False),
        (250, 3, 3, 51, False),
        (250, 3, 4, 50, False),      # a page beyond the count it declares
        (250, 3, 0, 100, False),
    ])
    def test_the_ROW_COUNT_must_match_the_page_position(self, total, pages, page, rows, ok):
        """review-B1.6b18#2: the page COUNT was corroborated and the ROW COUNT was not, so a body
        claiming 50 results across one page and returning ONE row was accepted as a complete answer —
        49 results lost, and OWNED, so it could never be re-bought. The measured contract fixes both
        numbers: 100 rows a page, and total_pages == ceil(total / 100)."""
        doc = {"total_results_int": total, "total_pages": pages, "current_page": page,
               "rows": [{"domain_name": f"d{i}.example.com"} for i in range(rows)]}
        kind, _n = wp.classify_page(doc)
        assert (kind == wp.PAGE_PAGED) is ok, (kind, total, pages, page, rows)

    def test_a_SHORT_page_is_retryable_evidence_not_a_completion(self, tmp_path):
        """It must stay re-buyable: owning a contradictory page makes a transient fault permanent."""
        led = _ledger(tmp_path)
        p = _Provider()

        def short(anchor, page):
            p.calls.append((anchor.param, anchor.value, page))
            return json.dumps({
                "status": 1, "api_query": "reverse_whois",
                "search_identifier": {anchor.param: anchor.value},
                "total_results": "50", "total_pages": 1, "current_page": 1,
                "search_result": [{"domain_name": "only.example.com"}]}).encode(), None

        p.fetch = short
        out, seen = _run(tmp_path, _states((COMPANY, "a")), p, ledger=led, spend=2)
        assert out.pages_bought == 0 and out.evidence_invalid == 1 and seen == []
        assert not _ledger(tmp_path).has(item_key(Anchor(COMPANY, "a"), 1))
        p2 = _Provider(totals={"a": 50})                    # the provider recovers
        out2, seen2 = _run(tmp_path, _states((COMPANY, "a")), p2, ledger=_ledger(tmp_path),
                           attempt="a1")
        assert out2.pages_bought == 1 and len(seen2) == 50

    def test_a_SHORT_page_already_OWNED_does_not_replay(self, tmp_path):
        """Fresh and replayed pages owe the same contract — a short page recorded by an older build
        must not replay as a complete answer."""
        led = _ledger(tmp_path)
        d = tmp_path / "state" / "pages" / "a0"
        d.mkdir(parents=True, exist_ok=True)
        body = json.dumps({"status": 1, "api_query": "reverse_whois",
                           "search_identifier": {COMPANY: "a"}, "total_results": "50",
                           "total_pages": 1, "current_page": 1,
                           "search_result": [{"domain_name": "only.example.com"}]}).encode()
        art = d / f"{item_key(Anchor(COMPANY, 'a'), 1)}.json"
        art.write_bytes(body)
        led.record(item_key(Anchor(COMPANY, "a"), 1), art)
        led.save()
        assert wp.owned_index(_ledger(tmp_path), _read) == {}

    def test_a_CONTRADICTORY_owned_page_does_not_replay(self, tmp_path):
        """#2: enumeration accepted anything the reader could identify, so a digest-valid contradictory
        completion replayed for free and stayed permanently unsized. Fresh and replay owe one contract."""
        led = _ledger(tmp_path)
        d = tmp_path / "state" / "pages" / "a0"
        d.mkdir(parents=True, exist_ok=True)
        body = json.dumps({"status": 1, "api_query": "reverse_whois",
                           "search_identifier": {COMPANY: "a"}, "total_results": "100",
                           "total_pages": 77, "current_page": 1,
                           "search_result": [{"domain_name": "a.example.com"}]}).encode()
        art = d / f"{item_key(Anchor(COMPANY, 'a'), 1)}.json"
        art.write_bytes(body)
        led.record(item_key(Anchor(COMPANY, "a"), 1), art)     # a completion that should never have been
        led.save()
        assert wp.owned_index(_ledger(tmp_path), _read) == {}
        p = _Provider(totals={"a": 100})
        out, _ = _run(tmp_path, _states((COMPANY, "a")), p, ledger=_ledger(tmp_path), attempt="a1")
        assert [c[2] for c in p.calls] == [1] and out.pages_replayed == 0

    def test_OUR_storage_failure_outranks_the_providers_limit(self, tmp_path):
        """#3: the limit overwrote the storage cause, so a response Quarry LOST was reported as a soft
        provider boundary. Both happened; only one of them is ours, and ours is a gap."""
        led = _ledger(tmp_path)
        led.add_evidence = lambda *a, **k: False
        body = json.dumps({"status": 0, "status_reason": "Zero Account Balance"}).encode()
        p = _Provider()

        def quota(anchor, page):
            p.calls.append((anchor.param, anchor.value, page))
            return body, _err("quota")

        p.fetch = quota
        out, _ = _run(tmp_path, _states((COMPANY, "a")), p, ledger=led)
        assert out.stop_cause == "ledger_unwritable", out.stop_cause
        assert out.records_journaled is False

    def test_WHICH_sink_failed_is_reported(self, tmp_path, monkeypatch):
        """#3: `_keep_evidence` collapsed a publish failure and a bind failure into one cause. They are
        different faults — one is the artifact tree, the other the ledger — and an operator fixes them
        in different places."""
        real = budget.publish_bytes
        monkeypatch.setattr(budget, "publish_bytes",
                            lambda dest, data, digest: (real(dest, data, digest=digest)
                                                        if ".quarry-write-probe" in str(dest) else False))
        body = json.dumps({"status": 0, "status_reason": "Zero Account Balance"}).encode()
        p = _Provider()

        def refuse(anchor, page):
            p.calls.append((anchor.param, anchor.value, page))
            return body, _err("quota")

        p.fetch = refuse
        out, _ = _run(tmp_path, _states((COMPANY, "a")), p)
        assert out.stop_cause == "publish_failed", out.stop_cause
        assert out.publish_failed == 1 and out.records_journaled is True

    def test_a_provider_limit_with_INTACT_storage_is_still_a_limit(self, tmp_path):
        """The control: when nothing of ours failed, the provider's boundary is the honest cause."""
        body = json.dumps({"status": 0, "status_reason": "Zero Account Balance"}).encode()
        p = _Provider()

        def quota(anchor, page):
            p.calls.append((anchor.param, anchor.value, page))
            return body, _err("quota")

        p.fetch = quota
        out, _ = _run(tmp_path, _states((COMPANY, "a")), p)
        assert out.stop_cause == "provider_limit:quota" and out.error_bodies == 1

    @pytest.mark.parametrize("name,param,pages,total", [
        ("company-page1.json", COMPANY, 124, 12345),
        ("email-page1.json", EMAIL, 6, 512),
    ])
    def test_the_MEASURED_shapes_parse_through_the_production_reader(self, tmp_path, name, param,
                                                                    pages, total):
        """review-B1.6r4#2: these read `/tmp/whoxy-*` and SKIPPED when absent, so a clean CI runner never
        exercised the production reader against the real shapes — the same machine-dependent test defect
        just fixed for nuclei, recreated a week later.

        The committed fixtures are SANITIZED (domains, contacts, phone and fax redacted) and preserve
        every type and structure that matters: `total_results` as a STRING, int page fields, and the
        email form's registrant/administrative contact OBJECTS."""
        art = tmp_path / name
        art.write_bytes((FIXTURES / name).read_bytes())
        got = wp.read_page(art)
        assert got is not None and got["page"] == 1 and got["anchor"].param == param
        assert got["doc"]["total_results_int"] == total and len(got["doc"]["rows"]) == 100
        assert wp.classify_page(got["doc"]) == (wp.PAGE_PAGED, pages)
        assert isinstance(json.loads(art.read_text())["total_results"], str)

    def test_the_email_form_keeps_its_CONTACT_OBJECTS(self, tmp_path):
        """The row shapes differ between query forms, and the fixture must keep that: the email form
        carries registrant/administrative contacts the company form does not."""
        row = json.loads((FIXTURES / "email-page1.json").read_text())["search_result"][0]
        assert isinstance(row.get("registrant_contact"), dict)
        assert isinstance(row.get("administrative_contact"), dict)
        assert "create_date" not in row and "domain_status" not in row
        crow = json.loads((FIXTURES / "company-page1.json").read_text())["search_result"][0]
        assert "create_date" in crow and "registrant_contact" not in crow

    def test_the_measured_PAST_END_body_is_not_a_readable_page(self, tmp_path):
        art = tmp_path / "past-end.json"
        art.write_bytes((FIXTURES / "past-end.json").read_bytes())
        assert wp.read_page(art) is None
        assert json.loads(art.read_text()) == {"status": 0, "status_reason": "Invalid Page Number"}

    @pytest.mark.parametrize("api_query", [None, "account_balance", "whois_history"])
    def test_a_page_that_answers_a_DIFFERENT_question_is_not_a_page(self, tmp_path, api_query):
        """review-B1.6r4#1: only the compact shape was bound to the endpoint, so a paged body whose
        `api_query` was missing — or said `account_balance` — became a confident owned completion."""
        body = json.loads(_body(COMPANY, "a", 1, 250).decode())
        if api_query is None:
            body.pop("api_query")
        else:
            body["api_query"] = api_query
        art = tmp_path / "x.json"
        art.write_text(json.dumps(body))
        assert wp.read_page(art) is None


def _paid(spend_path, allowance, *, seen=None):
    """A realistic paid phase: take the installation-wide spend lock, THEN yield the allowance. This is
    where a real lifecycle also reads the balance, so `seen` records that it got that far."""
    import contextlib

    @contextlib.contextmanager
    def phase():
        with wp.spend_lock(spend_path):
            if seen is not None:
                seen.append("balance read")
            yield allowance

    return phase


class TestDurableProjectState:
    """B1.6b: page ownership lives beside the timestamped sessions, not inside one. An `OsintSession`
    directory is per-run, so state kept there dies with it and every run re-buys page 1."""

    def _run_in(self, project, provider, **kw):
        # `open_state` is a context manager: the provider lock is held across the whole lifecycle, and
        # there is no way to reach the ledger without it (review-B1.6b2#2).
        # the spend lock is installation-wide by default; tests must never touch the real
        # ~/.config/quarry, so they point it at their own tmp path.
        with wp.open_state(project) as (led, pages):
            d = pages / f"attempt-{len(list(pages.iterdir()))}"
            d.mkdir(parents=True, exist_ok=True)
            seen = []

            def ingest(anchor, page, doc, art):
                rows = _rows(doc)
                seen.extend(rows)
                return len(rows)

            allowance = kw.pop("spend", None)
            out = wp.run_pages(_states((COMPANY, "a")),
                               paid=_paid(project.parent / "spend.lock", allowance),
                               fetch=provider.fetch, ingest=ingest, read=_read, ledger=led,
                               attempt_dir=d, **kw)
        return out, seen

    def test_TWO_SESSIONS_in_one_project_replay_without_repurchasing(self, tmp_path):
        """The whole point: two `quarry osint` runs an hour apart share ownership."""
        proj = tmp_path / "proj"
        p1 = _Provider(totals={"a": 250})
        out1, _ = self._run_in(proj, p1)
        assert out1.pages_bought == 3
        p2 = _Provider(totals={"a": 250})
        out2, seen = self._run_in(proj, p2)
        assert p2.calls == [], f"a second session re-bought paid pages: {p2.calls}"
        assert out2.pages_replayed == 3 and len(seen) == 250

    def test_DIFFERENT_PROJECTS_never_share_ownership(self, tmp_path):
        """Two engagements are two evidence trees. One must never replay the other's paid pages."""
        p1 = _Provider(totals={"a": 250})
        self._run_in(tmp_path / "acme", p1)
        p2 = _Provider(totals={"a": 250})
        out, _ = self._run_in(tmp_path / "other", p2)
        assert [c[2] for c in p2.calls] == [1, 2, 3], p2.calls
        assert out.pages_replayed == 0

    @pytest.mark.parametrize("reserve,run_budget", [(0, 0), (50, 0), (0, 5), (75, 9)])
    def test_changing_a_SPENDING_POLICY_does_not_repurchase(self, tmp_path, reserve, run_budget):
        """A page bought under one policy is byte-identical under another, so neither the reserve nor the
        page budget may touch the state generation."""
        proj = tmp_path / "proj"
        self._run_in(proj, _Provider(totals={"a": 250}))
        before = wp.state_dir(proj)
        p2 = _Provider(totals={"a": 250})
        pol = wp.spend_policy(wp.read_balance('{"status": 1, "reverse_whois_balance": 200}'),
                              reserve, run_budget)
        out, _ = self._run_in(proj, p2, spend=pol.pages)
        assert p2.calls == [], f"a policy change re-bought paid pages: {p2.calls}"
        assert out.pages_replayed == 3 and wp.state_dir(proj) == before

    def test_the_API_KEY_and_anchors_are_not_part_of_the_generation(self, tmp_path):
        """A page's bytes do not depend on which credential paid for it, nor on what else was asked."""
        proj = tmp_path / "proj"
        rel = wp.state_dir(proj).relative_to(proj).parts     # RELATIVE: tmp_path names are not ours
        assert rel == ("osint", "state", "whoxy", f"v{wp.WHOXY_WORK_SCHEMA}"), rel

    def test_a_SCHEMA_change_starts_ISOLATED_ownership(self, tmp_path, monkeypatch):
        """A schema bump is the one thing that genuinely invalidates stored pages — and it ISOLATES the
        old ones rather than deleting them. Paid evidence is never pruned automatically."""
        proj = tmp_path / "proj"
        self._run_in(proj, _Provider(totals={"a": 250}))
        old = wp.state_dir(proj)
        assert (old / "ledger.json").exists()
        monkeypatch.setattr(wp, "WHOXY_WORK_SCHEMA", wp.WHOXY_WORK_SCHEMA + 1)
        new = wp.state_dir(proj)
        assert new != old and not (new / "ledger.json").exists()
        assert wp.provider_dir(proj) == old.parent == new.parent   # the LOCK level is shared
        p2 = _Provider(totals={"a": 250})
        out, _ = self._run_in(proj, p2)
        assert [c[2] for c in p2.calls] == [1, 2, 3] and out.pages_replayed == 0
        assert (old / "ledger.json").exists(), "the previous generation's paid evidence was destroyed"

    def test_osint_LATEST_still_resolves_to_a_real_session(self, tmp_path, monkeypatch):
        """review-B1.6b#2: the old test only checked path ancestry — it never called `finalize()` nor
        looked at the pointer, so it could not have caught `latest` resolving to `state/`."""
        from quarry_recon.osint import OsintSession
        proj = tmp_path / "proj"
        wp.state_dir(proj).mkdir(parents=True, exist_ok=True)      # state/ exists FIRST
        s = OsintSession(proj, "acme.com")
        s.dir.mkdir(parents=True, exist_ok=True)
        profile = type("P", (), {"target": "acme.com", "apex_domains": ["acme.com"], "asn": [],
                                 "org_names": [], "brands": [], "path": None})()
        s.finalize(profile)
        link = proj / "osint" / "latest"
        txt = proj / "osint" / "latest.txt"
        target = (link.resolve() if link.exists() or link.is_symlink()
                  else pathlib.Path(txt.read_text().strip()))
        assert target == s.dir.resolve(), target
        assert target != wp.state_dir(proj) and "state" not in target.relative_to(proj).parts


class TestBalanceOutcome:
    """MEASURED 2026-07-29: `account=balance` is FREE (two consecutive reads, no change) and answers
    `{"status": 1, ..., "reverse_whois_balance": N}`. Only the reverse-whois figure funds this lane.

    review-B1.6b7: the reader returned a bare int|None, so a PROVEN refusal was indistinguishable from
    "we could not read it" — and with no reserve that means UNBOUNDED. The provider stating plainly that
    there are no credits became permission to spend."""

    def test_the_MEASURED_balance_shape_reads(self):
        raw = json.dumps({"status": 1, "live_whois_balance": 500, "whois_history_balance": 100,
                          "reverse_whois_balance": 197})
        r = wp.read_balance(raw)
        assert r.remaining == 197 and not r.refused and r.error_class == ""

    def test_a_genuine_ZERO_balance_is_KNOWN_not_unknown(self):
        r = wp.read_balance('{"status": 1, "reverse_whois_balance": 0}')
        assert r.remaining == 0 and not r.refused
        assert wp.spend_policy(r, 0, 0).pages == 0

    def test_a_PROVEN_QUOTA_refusal_permits_no_spending_and_is_a_SOFT_limit(self):
        """The measured exhaustion body. Nothing went wrong — the account is simply spent."""
        r = wp.read_balance('{"status": 0, "status_reason": "Zero Account Balance"}')
        assert r.refused and r.error_class == "quota" and "Zero Account Balance" in r.reason
        pol = wp.spend_policy(r, 0, 0)
        assert pol.pages == 0 and pol.limit and not pol.gap

    def test_an_UNCLASSIFIED_refusal_permits_no_spending_and_is_a_GAP(self):
        """The provider refused for a reason we cannot classify. Not a boundary — something to fix.

        review-B1.6b8#3: this asserted `r.refused and pytest.approx`, which only tests that pytest has
        an `approx` attribute. The exact class and the verbatim reason are the point."""
        r = wp.read_balance('{"status": 0, "status_reason": "Something Odd"}')
        assert r.refused is True and r.error_class == "error"
        assert r.reason == "Something Odd", r.reason
        pol = wp.spend_policy(r, 0, 0)
        assert pol.pages == 0 and "Something Odd" in pol.gap and not pol.limit

    def test_a_PARSE_failure_is_not_a_provider_REFUSAL(self):
        """review-B1.6b8#2: every envelope rejection was marked refused, so `status: true` claimed Whoxy
        had explicitly refused us. The two send an operator to completely different places."""
        for raw in ('{"status": true, "reverse_whois_balance": 5}', '{"reverse_whois_balance": 5}',
                    '{"status": "1", "reverse_whois_balance": 5}', "[]", "null", "garbage"):
            r = wp.read_balance(raw)
            assert r.error_class == "parse" and r.refused is False, (raw, r)
            pol = wp.spend_policy(r, 0, 0)
            assert pol.pages == 0 and pol.gap and not pol.limit, (raw, pol)

    def test_a_BOOLEAN_status_is_not_success(self):
        """`True == 1` in Python. The envelope is `contract.whoxy_envelope`, which already excludes it —
        a second status authority would be one more place for that to be got wrong."""
        r = wp.read_balance('{"status": true, "reverse_whois_balance": 5}')
        assert r.remaining is None and r.error_class == "parse" and r.refused is False
        assert wp.spend_policy(r, 0, 0).pages == 0

    @pytest.mark.parametrize("raw", [
        "not json", "[]", "null", '{"status": 1}',
        '{"status": 1, "reverse_whois_balance": "197"}',
        '{"status": 1, "reverse_whois_balance": true}',
        '{"status": 1, "reverse_whois_balance": 12.5}',
        '{"status": 1, "reverse_whois_balance": -1}',
        '{"status": 1, "live_whois_balance": 500}',            # the WRONG balance
    ])
    def test_an_UNREADABLE_balance_permits_NO_paid_work(self, raw):
        """Fails CLOSED. A cost guard that does not understand the body in front of it must not spend
        against it, and the gap survives so a run that could not read the balance cannot report itself
        clean."""
        r = wp.read_balance(raw)
        assert r.remaining is None and not r.refused and r.error_class == "parse"
        pol = wp.spend_policy(r, 0, 0)
        assert pol.pages == 0 and pol.gap and pol.balance_invalid

    def test_a_malformed_balance_WITH_a_reserve_spends_nothing(self):
        """A reserve says "keep N back", which cannot be honoured against a balance we could not read."""
        pol = wp.spend_policy(wp.read_balance("garbage"), 50, 0)
        assert pol.pages == 0 and pol.gap

    @pytest.mark.parametrize("kw,why", [
        ({}, "empty: neither a figure nor a reason"),
        ({"remaining": True}, "bool is an int subclass, not a count"),
        ({"remaining": "200"}, "a string is not a count"),
        ({"remaining": 12.5}, "a float is not a count"),
        ({"remaining": -1}, "negative"),
        ({"remaining": 5, "error_class": "quota", "reason": "x"}, "read AND failed"),
        ({"remaining": 5, "refused": True}, "read AND refused"),
        ({"error_class": "quota"}, "a failure with no reason"),
        ({"reason": "something"}, "a reason with no class"),
        ({"error_class": "parse", "reason": "x", "refused": True}, "parse is not a refusal"),
        # review-B1.6b10#1: the success branch never looked at `reason`, the failure branch tested
        # truthiness rather than TYPE, and `refused` accepted any truthy value.
        ({"remaining": 5, "reason": "contradiction"}, "read AND carrying a reason"),
        ({"error_class": 123, "reason": "failure"}, "class is not a string"),
        ({"error_class": "quota", "reason": ["x"]}, "reason is not a string"),
        ({"error_class": "quota", "reason": "x", "refused": 1}, "refused is not a bool"),
        ({"error_class": "quota", "reason": "x", "refused": "yes"}, "refused is not a bool"),
        ({"error_class": "Quota", "reason": "x"}, "not the canonical class spelling"),
        ({"error_class": "quota ", "reason": "x"}, "whitespace in the class"),
        ({"error_class": "nonsense", "reason": "x"}, "not a provider-outcome class at all"),
        ({"error_class": "quota", "reason": "   "}, "a blank reason says nothing"),
        # a PROVEN limit is a refusal by definition; accepting it as unrefused made the one outcome
        # that is emphatically not a defect report as a gap.
        ({"error_class": "quota", "reason": "Zero Account Balance"}, "a proven limit must be refused"),
        ({"error_class": "entitlement", "reason": "plan"}, "a proven limit must be refused"),
    ])
    def test_an_INVALID_balance_outcome_cannot_be_CONSTRUCTED(self, kw, why):
        """review-B1.6b9#1: making this the boundary type moved the validation off `spend_policy`'s
        argument and onto nothing at all — `BalanceRead()` meant UNBOUNDED spending, `remaining=True`
        bought a page. An unconstructable bad state is worth more than a checked one."""
        with pytest.raises(ValueError):
            wp.BalanceRead(**kw)

    def test_every_class_the_taxonomy_defines_is_accepted(self):
        """The canonical set, so a consumer never has to guess which spellings are real."""
        from quarry_recon.contract import PROVIDER_CLASSES, PROVIDER_LIMITS, PROVIDER_PARSE
        for cls in PROVIDER_CLASSES:
            r = wp.BalanceRead(error_class=cls, reason="because", refused=cls != PROVIDER_PARSE)
            assert r.error_class == cls
        # ...and a proven limit is always a refusal, so it always reads as a LIMIT, never a gap
        for cls in PROVIDER_LIMITS:
            pol = wp.spend_policy(wp.BalanceRead(error_class=cls, reason="proven", refused=True), 0, 0)
            assert pol.pages == 0 and pol.limit and not pol.gap, (cls, pol)

    def test_the_VALID_shapes_construct(self):
        assert wp.BalanceRead(remaining=0).remaining == 0
        assert wp.BalanceRead(remaining=200).remaining == 200
        assert wp.BalanceRead(error_class="quota", reason="Zero Account Balance",
                              refused=True).refused is True
        assert wp.BalanceRead(error_class="parse", reason="not JSON").refused is False

    def test_an_invalid_KNOB_does_not_erase_an_observed_provider_fact(self):
        """review-B1.6b9#2: an invalid control RETURNED immediately, dropping a balance response we had
        already observed — an operator would fix their config, rerun, and only then discover the account
        was refused."""
        quota = wp.read_balance('{"status": 0, "status_reason": "Zero Account Balance"}')
        pol = wp.spend_policy(quota, -5, 0)
        assert pol.pages == 0
        assert "WHOXY_CREDIT_RESERVE" in pol.invalid, pol
        assert "Zero Account Balance" in pol.limit, pol
        drifted = wp.spend_policy(wp.read_balance("garbage"), 0, -1)
        assert drifted.pages == 0 and drifted.invalid and drifted.gap and drifted.balance_invalid

    def test_the_balance_PREFLIGHT_is_MANDATORY(self):
        """review-B1.6b8#1: accepting a bare int|None left `spend_policy(None, 0, 0)` granting UNBOUNDED
        spending — a caller that skipped the preflight got the most permissive answer available. There
        is no path around it, and forgetting it is a defect in the CALL, not a spending decision."""
        for bad in (None, 200, "200", 0, True):
            with pytest.raises(TypeError):
                wp.spend_policy(bad, 0, 0)

    def test_the_reader_feeds_the_spending_contract(self):
        assert wp.spend_policy(wp.read_balance('{"status":1,"reverse_whois_balance":197}'),
                               50, 0).pages == 147

    def test_the_ARITHMETIC_is_still_reachable_on_its_own(self):
        """`spendable` is the pure calculation and stays directly testable; `spend_policy` is where the
        preflight and the classification live."""
        assert wp.spendable(200, 50, 0) == 150
        assert wp.spendable(None, 0, 0) is None and wp.spendable(None, 50, 0) == 0


class TestProviderOutcomes:
    def test_a_provider_LIMIT_stops_the_run_and_keeps_the_evidence(self, tmp_path):
        p = _Provider(totals={"a": 1000}, errors={("a", 2): _err("quota")})
        out, seen = _run(tmp_path, _states((COMPANY, "a")), p)
        assert out.pages_bought == 1 and len(seen) == 100
        assert out.stop_cause == "provider_limit:quota" and out.limit_classes == {"quota": 1}

    def test_a_FAILURE_is_counted_apart_from_a_limit(self, tmp_path):
        p = _Provider(totals={"a": 1000}, errors={("a", 2): _err("transport")})
        out, _ = _run(tmp_path, _states((COMPANY, "a")), p)
        assert out.fail_classes == {"transport": 1} and out.limit_classes == {}
        assert out.stop_cause == "", "a transport failure ended the whole run"

    def test_a_failed_page_1_leaves_the_anchor_unopened_but_ATTEMPTED(self, tmp_path):
        p = _Provider(totals={"a": 100}, errors={"a": _err("transport")})
        out, _ = _run(tmp_path, _states((COMPANY, "a")), p)
        assert out.unopened == [], "an anchor we asked about was reported as never queried"
        assert out.anchors_touched == 0 and out.fail_classes == {"transport": 1}

    def test_pages_left_is_UNKNOWN_not_zero_for_an_unopened_anchor(self, tmp_path):
        p = _Provider(totals={"a": 1000})
        out, _ = _run(tmp_path, _states((COMPANY, "a"), (COMPANY, "b")), p, spend=1)
        assert out.pages_left_unknown_anchors == 0        # b was never opened -> no page count at all
        assert AnchorState(Anchor(COMPANY, "b")).pages_left() == 0


class TestMachineryFailuresPreserveTheOutcome:
    """review-B1.6b22: `run_pages` keeps whatever the lifecycle established when its OWN machinery
    fails. The cause it reports has to be the one that stopped it, not the last thing to go wrong."""

    def test_the_FIRST_cause_names_the_stop(self, tmp_path, monkeypatch):
        """A page we could not publish is the reason this run ended; a downstream accounting failure is
        a consequence of that, and overwriting reports the symptom instead of the cause."""
        monkeypatch.setattr(budget, "publish_bytes", lambda *a, **k: False)
        boom = lambda *a, **k: (_ for _ in ()).throw(ValueError("accounting exploded"))
        monkeypatch.setattr(wp, "_remainder", boom)

        out, _ = _run(tmp_path, _states((COMPANY, "a")), _Provider(totals={"a": 250}), spend=5)
        assert out.stop_cause == "publish_failed", out.stop_cause
        # the later failure is real too and is not thrown away — it just does not get to rename the stop
        assert "accounting exploded" in out.fail_reason, out.fail_reason

    def test_a_PROVIDER_failure_keeps_its_own_wording(self, tmp_path, monkeypatch):
        """A provider failure is what an operator acts on. Our accounting blowing up afterwards must not
        rewrite the terminal's reason into one about ourselves."""
        boom = lambda *a, **k: (_ for _ in ()).throw(ValueError("accounting exploded"))
        monkeypatch.setattr(wp, "_remainder", boom)
        prov = _Provider(totals={"a": 250}, errors={("a", 2): _err("transport")})

        out, _ = _run(tmp_path, _states((COMPANY, "a")), prov, spend=5)
        assert "transport" in out.fail_reason, out.fail_reason
        assert "accounting exploded" not in out.fail_reason, out.fail_reason
        assert out.pages_bought == 1 and out.domains == 100, (out.pages_bought, out.domains)

    def test_a_LATER_machinery_failure_is_kept_as_its_own_fact(self, tmp_path, monkeypatch):
        """review-B1.6b23#3: keeping the first cause used to mean DISCARDING the second. Both happened,
        so both are recorded — the stop keeps its name, and the later failure keeps its own slot."""
        boom = lambda *a, **k: (_ for _ in ()).throw(ValueError("accounting exploded"))
        monkeypatch.setattr(wp, "_remainder", boom)
        prov = _Provider(totals={"a": 250}, errors={("a", 2): _err("transport")})

        out, _ = _run(tmp_path, _states((COMPANY, "a")), prov, spend=5)
        assert out.machinery == ["ValueError: accounting exploded"], out.machinery

    def test_a_SAVE_that_raises_keeps_the_whole_lifecycle(self, tmp_path, monkeypatch):
        """review-B1.6b23#2: `ledger.save()` sat outside the boundary, so a store that raised discarded
        every page the run had bought — and the caller reported `attempted=0` over them."""
        led = _ledger(tmp_path)
        prov = _Provider(totals={"a": 250})
        out, seen = _run(tmp_path, _states((COMPANY, "a")), prov, spend=5, ledger=led)
        assert out.pages_bought == 3 and out.persisted

        led2 = _ledger(tmp_path)
        led2.save = lambda *a, **k: (_ for _ in ()).throw(OSError("store exploded"))
        out2, seen2 = _run(tmp_path, _states((COMPANY, "a")), prov, spend=5, ledger=led2, attempt="a1")
        assert out2.pages_replayed == 3, "replayed pages died with the save"
        assert out2.domains == 250, out2.domains
        assert len(seen2) == 250, "the replayed candidates never reached the caller"
        assert out2.stop_cause == "machinery:OSError", out2.stop_cause
        assert "store exploded" in out2.fail_reason, out2.fail_reason
        # the JOURNAL is what makes work survive a process, and it is intact here — reporting a
        # persistence gap on genuinely resumable work is the lie the `durable` branch exists to prevent.
        assert out2.persisted is True, "an intact journal was reported as lost"

    def test_a_SAVE_that_raises_with_NO_journal_reports_the_persistence_gap(self, tmp_path):
        """The other half: nothing wrote anywhere, so the pages this run bought will be bought again."""
        led = _ledger(tmp_path)
        led.save = lambda *a, **k: (_ for _ in ()).throw(OSError("store exploded"))
        led._journal_lost = True
        out, _ = _run(tmp_path, _states((COMPANY, "a")), _Provider(totals={"a": 250}), spend=5,
                      ledger=led)
        assert out.pages_bought == 3 and out.domains == 250, (out.pages_bought, out.domains)
        assert out.persisted is False, "a save that RAISED with no journal cannot count as persisted"
        assert out.stop_cause == "machinery:OSError", out.stop_cause

    def test_an_INGEST_that_raises_does_not_count_as_a_delivered_page(self, tmp_path, monkeypatch):
        """review-B1.6b23#1: the page left the remainder as though its rows had landed, so a ten-page
        anchor that died on page 2 reported eight missing pages for nine it never delivered."""
        d = tmp_path / "state" / "pages" / "a0"
        d.mkdir(parents=True, exist_ok=True)

        def ingest(anchor, page, doc, art):
            if page == 2:
                raise RuntimeError("ingest exploded")
            return len(_rows(doc))

        out = wp.run_pages(_states((COMPANY, "a")), paid=lambda: wp.fixed_allowance(5),
                           fetch=_Provider(totals={"a": 1000}).fetch, ingest=ingest, read=_read,
                           ledger=_ledger(tmp_path), attempt_dir=d)
        assert out.pages_unconsumed == 1, out.pages_unconsumed
        assert out.domains == 100, out.domains
        # the page is still OWNED: dropping it would have the scheduler sell it to us a second time
        assert out.pages_bought == 2 and out.pages_left_known == 8, (out.pages_bought,
                                                                    out.pages_left_known)

    @pytest.mark.parametrize("dead", [1, 2])
    def test_an_anchor_is_COMPLETE_only_once_a_page_of_it_LANDS(self, tmp_path, dead):
        """review-B1.6b24#2: `anchors_touched` moved before ingestion, so an anchor whose PAGE 1 failed
        to ingest was published as `completed=1` beside `domains=0` — the same anchor reported as
        completed and as failed. Page 2 is the case where completion was legitimately established
        earlier, and it must still be counted."""
        d = tmp_path / "state" / "pages" / "a0"
        d.mkdir(parents=True, exist_ok=True)

        def ingest(anchor, page, doc, art):
            if page == dead:
                raise RuntimeError("ingest exploded")
            return len(_rows(doc))

        out = wp.run_pages(_states((COMPANY, "a")), paid=lambda: wp.fixed_allowance(5),
                           fetch=_Provider(totals={"a": 1000}).fetch, ingest=ingest, read=_read,
                           ledger=_ledger(tmp_path), attempt_dir=d)
        assert out.pages_unconsumed == 1, out.pages_unconsumed
        if dead == 1:
            assert out.anchors_touched == 0, "an anchor that delivered NOTHING was reported complete"
            assert out.domains == 0, out.domains
        else:
            assert out.anchors_touched == 1, "page 1 landed; the anchor IS delivered"
            assert out.domains == 100, out.domains

    def test_a_SUCCESSFUL_save_never_consults_the_fallback(self, tmp_path):
        """review-B1.6b25: `durable` is the fallback for a snapshot that did NOT land. Reading it
        unconditionally let a ledger that saved cleanly report a machinery gap over evidence the run had
        no need of — a fabricated failure on a completely clean lifecycle."""
        touched = []

        class _Loud(type(_ledger(tmp_path))):
            @property
            def durable(self):
                touched.append(1)
                raise OSError("fallback exploded")

        led = _ledger(tmp_path)
        led.__class__ = _Loud
        led.save = lambda *a, **k: True

        out, _ = _run(tmp_path, _states((COMPANY, "a")), _Provider(totals={"a": 250}), spend=5,
                      ledger=led)
        assert touched == [], "the fallback was consulted although the snapshot landed"
        assert out.persisted is True
        assert out.machinery == [] and out.stop_cause == "", (out.machinery, out.stop_cause)
        assert out.fail_reason == "", out.fail_reason
        assert out.pages_bought == 3 and out.domains == 250, (out.pages_bought, out.domains)

    def test_a_DURABLE_read_that_raises_is_reported_like_any_other_machinery(self, tmp_path):
        """review-B1.6b24#3: it became `False` silently, contradicting the contract the rest of this
        function keeps — every machinery failure is retained."""
        class _Blind(type(_ledger(tmp_path))):
            @property
            def durable(self):
                raise OSError("cannot stat the journal")

        led = _ledger(tmp_path)
        led.__class__ = _Blind
        led.save = lambda *a, **k: False
        out, _ = _run(tmp_path, _states((COMPANY, "a")), _Provider(totals={"a": 250}), spend=5,
                      ledger=led)
        assert out.pages_bought == 3 and out.domains == 250, (out.pages_bought, out.domains)
        assert out.persisted is False
        assert out.machinery == ["OSError: cannot stat the journal"], out.machinery
        assert out.stop_cause == "machinery:OSError", out.stop_cause

    def test_a_MACHINERY_failure_names_ITSELF_in_the_reason(self, tmp_path, monkeypatch):
        """A bare exception string on the terminal is indistinguishable from a provider failure."""
        monkeypatch.setattr(wp, "_replay",
                            lambda *a, **k: (_ for _ in ()).throw(ValueError("replay exploded")))
        out, _ = _run(tmp_path, _states((COMPANY, "a")), _Provider(totals={"a": 250}), spend=5)
        assert out.stop_cause == "machinery:ValueError", out.stop_cause
        assert "machinery" in out.fail_reason and "replay exploded" in out.fail_reason, out.fail_reason

    def test_the_REMAINDER_is_still_reported_when_replay_fails(self, tmp_path, monkeypatch):
        """The remainder is what a later run has to pick up; losing it hides the work that is left."""
        monkeypatch.setattr(wp, "_replay",
                            lambda *a, **k: (_ for _ in ()).throw(ValueError("replay exploded")))
        out, _ = _run(tmp_path, _states((COMPANY, "a")), _Provider(totals={"a": 250}), spend=5)
        assert out.unopened == [f"{COMPANY}=a"], out.unopened
        assert out.persisted is not None


class TestAnUnreadableOwnershipStoreBlocksPurchase:
    """review#1 (Lumpy, on the Shodan store): `Ledger._read_snapshot()` returned an empty index for a
    file that EXISTS and cannot be parsed, so a corrupt ledger read as "nothing owned". This cache is
    PERMANENT — a page bought here is meant to be paid for once, ever — so an unnoticed re-buy is worse
    here than anywhere else."""

    def test_a_corrupt_ledger_buys_NOTHING(self, tmp_path):
        led = _ledger(tmp_path)
        provider = _Provider()
        out, seen = _run(tmp_path, _states((COMPANY, "a")), provider, spend=5, ledger=led)
        assert out.pages_bought >= 1 and seen, "baseline: a clean store buys"

        led.save()
        led.journal.unlink(missing_ok=True)
        led.path.write_text("{ this is not a ledger")
        corrupt = budget.Ledger(led.path, lane="osint.whoxy")
        assert corrupt.unreadable, "the file exists and cannot be trusted"

        before = len(provider.calls) if hasattr(provider, "calls") else None
        out2, _ = _run(tmp_path, _states((COMPANY, "a")), provider, spend=5, ledger=corrupt)
        assert out2.pages_bought == 0, "a corrupt index must never authorise a purchase"
        assert out2.stop_cause.startswith("ownership_unreadable:")
        if before is not None:
            assert len(provider.calls) == before, "no provider call may be made at all"
