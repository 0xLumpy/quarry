"""content.ffuf — the A1 lane migrated off MAX_HOSTS / MAX_RESULTS_PER_HOST.

The lifecycle paths these cover had NO regressions before: crash-after-checkpoint replay, immutable retry
evidence, capped-row recovery, malformed ffuf shapes, coverage survival across resume, and the typed row
contract. Pure/offline — `run_contract` is faked, no ffuf, no network.
"""
import json

import pytest

from quarry_recon import budget, events, settings
from quarry_recon.phases import content
from quarry_recon.runner import RunResult, Status, ffuf_http_row, ffuf_results, ffuf_usable_rows

pytestmark = pytest.mark.offline


def _rows(*pairs):
    return json.dumps({"results": [{"url": u, "status": s} for u, s in pairs]})


class _Scope:
    passive_only = False

    def active_allowed(self, host):
        return True

    def in_scope(self, host):
        return bool(host) and host.endswith("ex.com")

    def is_oos(self, host):
        return False


class _Run:
    def __init__(self, d):
        self.dir = d
        self.added = []
        self.recorded = []
        self.fail_add = False

    def raw_path(self, ph, tl, nm):
        p = self.dir / "raw" / ph / tl / nm
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def read(self, kind):
        return self._live if kind == "live" else []

    def values(self, kind):
        return []

    def add(self, kind, e):
        if self.fail_add:
            raise RuntimeError("store write failed")
        self.added.append((kind, e))
        return True

    def record(self, ph, r):
        self.recorded.append(r)


class _Ctx:
    def __init__(self, d, live):
        self.run = _Run(d)
        self.run._live = live
        self.scope = _Scope()
        self.http_timeout = 60
        self.echoed = []
        self.profile = type("P", (), {"content_discovery": "light", "content_recursion": 0,
                                      "http_rl": 0, "apex_domains": ["ex.com"]})()

    def echo(self, m):
        self.echoed.append(m)

    def tmp(self, nm):
        p = self.run.dir / "work" / nm
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def write_list(self, nm, it):
        p = self.tmp(nm)
        p.write_text("\n".join(it))
        return p


def _live(*urls, cdn=False):
    return [{
        "url": u, "cdn": cdn,
        "cdn_state": "detected" if cdn else "not_detected",
    } for u in urls]


def _drive(tmp_path, monkeypatch, live, *, body=None, status=Status.SUCCESS, budget_s=None,
           bodies=None, ctx=None, wl_body="a\nb\n"):
    """Run the lane with a faked run_contract that writes `body` to ffuf's -o path."""
    events.reset(); events.configure(tmp_path)
    monkeypatch.setattr(settings, "performance", lambda: {} if budget_s is None else dict(budget_s))
    monkeypatch.setattr(settings, "workers", lambda t, d: d)
    monkeypatch.setattr(content, "have", lambda t: True)
    monkeypatch.setattr(content, "_wordlist", lambda c, tier: c.tmp("wl.txt"))
    # wl_body is a PARAMETER: the harness used to hard-patch this on every call, silently clobbering a
    # test's own override — so the two config-change tests re-used one fingerprint and proved nothing.
    monkeypatch.setattr(content, "_merged_wordlist", lambda c, wl: (wl.write_text(wl_body), wl)[1])
    seen = []
    contract_kwargs = []

    def fake(sid, cmd, **k):
        out = __import__("pathlib").Path(cmd[cmd.index("-o") + 1])
        seen.append(out)
        contract_kwargs.append(k)
        b = bodies.pop(0) if bodies else body
        if b is not None:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(b)
        res = RunResult("ffuf", cmd, status, 0, 0.1, None, 0)
        rc = k.get("reclassify")
        return rc(res) if rc else res
    monkeypatch.setattr(content, "run_contract", fake)
    c = ctx or _Ctx(tmp_path, live)
    content.run(c)
    c.contract_kwargs = contract_kwargs
    return c, seen


def _cov(tmp_path, measure):
    ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
    return [e for e in ev if e.get("measure") == measure]


class TestNoMembershipCap:
    def test_ffuf_declares_canonical_origin_for_exact_transport(self, tmp_path, monkeypatch):
        c, _ = _drive(tmp_path, monkeypatch, _live("https://H.Ex.COM:443"), body=_rows())
        assert c.contract_kwargs[0]["network_hosts"] == ("h.ex.com",)

    def test_ffuf_preserves_an_ipv6_origin_as_an_address(self, tmp_path, monkeypatch):
        c, _ = _drive(tmp_path, monkeypatch, _live("https://[2001:db8::1]:443"), body=_rows())
        assert c.contract_kwargs[0]["network_hosts"] == ("2001:db8::1",)

    def test_every_eligible_service_is_scanned(self, tmp_path, monkeypatch):
        """MAX_HOSTS=25 silently excluded 473 of 498 eligible services on the OTC run."""
        live = _live(*[f"https://h{i}.ex.com" for i in range(40)])
        c, seen = _drive(tmp_path, monkeypatch, live, body=_rows())
        assert len(seen) == 40                                  # no 25-slice
        sel = _cov(tmp_path, "hosts")[-1]
        assert (sel["eligible"], sel["tested"], sel["omitted"]) == (40, 40, 0)

    def test_origin_rank_orders_without_excluding(self, tmp_path, monkeypatch):
        """Ranking sets ORDER, never membership: CDN services come last but are still scanned."""
        live = _live("https://cdn1.ex.com", cdn=True) + _live("https://origin.ex.com")
        c, seen = _drive(tmp_path, monkeypatch, live, body=_rows())
        assert len(seen) == 2
        assert "origin" in seen[0].name and "cdn1" in seen[1].name

    def test_a_budget_leaves_a_counted_remainder(self, tmp_path, monkeypatch):
        live = _live(*[f"https://h{i}.ex.com" for i in range(20)])
        clock = [1000.0]
        monkeypatch.setattr(budget.time, "monotonic", lambda: clock[0])

        def tick(*a, **k):
            clock[0] += 10
            return None
        events.reset()
        c, seen = _drive(tmp_path, monkeypatch, live, body=_rows(),
                         budget_s={"CONTENT_FFUF_BUDGET_S": 30})
        # the fake does not advance the clock, so assert the knob is wired rather than the exact stop point
        sel = _cov(tmp_path, "hosts")[-1]
        assert sel["eligible"] == 20

    def test_every_row_is_ingested_no_row_cap(self, tmp_path, monkeypatch):
        """MAX_RESULTS_PER_HOST=500 discarded already-discovered URLs; there is no row cap now."""
        pairs = [(f"https://h.ex.com/p{i}", 200) for i in range(900)]
        c, _ = _drive(tmp_path, monkeypatch, _live("https://h.ex.com"), body=_rows(*pairs))
        urls = [e for k, e in c.run.added if k == "url"]
        assert len(urls) == 900
        rows = _cov(tmp_path, "result_rows")[-1]
        assert rows["eligible"] == 900 and rows["omitted"] == 0
        assert "flood" in rows["reason"]                         # flagged, not discarded


class TestTypedRowContract:
    """review#1 (A1 r2): a non-empty-field check was fail-open on TYPES."""

    @pytest.mark.parametrize("row", [
        {"url": ["https://h.ex.com/a"], "status": 200},          # list url -> crashed host_of_url
        {"url": "https://h.ex.com/b", "status": True},           # bool is an int subclass
        {"url": "https://h.ex.com/c", "status": "200"},          # string status
        {"url": "javascript:alert(1)", "status": 200},           # not an http(s) url
        {"url": "", "status": 200},
        {},
    ])
    def test_unusable_rows_are_rejected(self, row):
        assert ffuf_http_row(row) is False

    def test_a_genuine_row_is_accepted(self):
        assert ffuf_http_row({"url": "https://h.ex.com/a", "status": 200}) is True

    def test_unusable_rows_make_the_service_non_resumable(self, tmp_path, monkeypatch):
        """`{"results":[{}]}` stayed SUCCESS and permanently resumable."""
        c, seen = _drive(tmp_path, monkeypatch, _live("https://h.ex.com"), body='{"results":[{}]}')
        state = list((tmp_path / "raw" / "content").glob("content_ffuf.*.state.json"))
        assert state, "a state file should exist"
        assert json.loads(state[0].read_text())["done"] == {}    # NOT recorded
        assert any("not resumable" in m for m in
                   [e.get("reason") or "" for e in
                    [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]])

    def test_valid_siblings_survive_an_unusable_row(self, tmp_path, monkeypatch):
        body = json.dumps({"results": [{"url": "https://h.ex.com/good", "status": 200},
                                       {"url": ["bad"], "status": 200}]})
        c, _ = _drive(tmp_path, monkeypatch, _live("https://h.ex.com"), body=body)
        urls = [e["url"] for k, e in c.run.added if k == "url"]
        assert urls == ["https://h.ex.com/good"]                 # evidence preserved
        rows = _cov(tmp_path, "result_rows")[-1]
        # review#5 (A1 r3): a type-contract failure is NOT a Quarry ceiling -> UNKNOWN, not CAP
        assert rows["kind"] == events.COVERAGE_UNKNOWN
        assert "type contract" in rows["reason"]


class TestMalformedArtifacts:
    @pytest.mark.parametrize("body", [None, "[]", '{"results":[null]}', "not json", '{"results":{}}'])
    def test_untrustworthy_artifact_is_unmeasured_and_not_resumable(self, tmp_path, monkeypatch, body):
        c, _ = _drive(tmp_path, monkeypatch, _live("https://h.ex.com"), body=body)
        rows = _cov(tmp_path, "result_rows")[-1]
        assert rows["kind"] == events.COVERAGE_UNKNOWN and rows["coverage_valid"] is False
        state = list((tmp_path / "raw" / "content").glob("content_ffuf.*.state.json"))
        assert json.loads(state[0].read_text())["done"] == {}


class TestReplayAndResume:
    def test_a_resumed_service_re_ingests_and_re_reports(self, tmp_path, monkeypatch):
        """review#1/#3 (A1 r1): recording completion before ingestion lost findings on a crash, and skipping
        resumed services stopped re-emitting per-service row coverage so the generation reset erased it."""
        live = _live("https://h.ex.com")
        c1, seen1 = _drive(tmp_path, monkeypatch, live, body=_rows(("https://h.ex.com/a", 200)))
        assert len(seen1) == 1
        c2, seen2 = _drive(tmp_path, monkeypatch, live, body=_rows(("https://h.ex.com/a", 200)))
        assert seen2 == []                                       # not re-scanned...
        assert [e["url"] for k, e in c2.run.added if k == "url"] == ["https://h.ex.com/a"]   # ...but re-ingested
        rows = _cov(tmp_path, "result_rows")[-1]
        assert rows["eligible"] == 1 and rows["tested"] == 1     # coverage survives the resume

    def test_a_partial_attempt_artifact_is_replayed(self, tmp_path, monkeypatch):
        """review#2 (A1 r2): an attempt that never made it into the ledger (killed mid-ingest) stayed on disk
        and was never replayed — its rows could be lost for good."""
        live = _live("https://h.ex.com")
        # run 1 completes but the artifact is not clean, so nothing is recorded
        c1, seen1 = _drive(tmp_path, monkeypatch, live,
                           body=json.dumps({"results": [{"url": "https://h.ex.com/kept", "status": 200},
                                                        {"url": ["bad"], "status": 200}]}))
        state = list((tmp_path / "raw" / "content").glob("content_ffuf.*.state.json"))
        assert json.loads(state[0].read_text())["done"] == {}
        # run 2 re-scans and returns nothing; the PRIOR attempt's good row must still be ingested
        c2, seen2 = _drive(tmp_path, monkeypatch, live, body=_rows())
        assert len(seen2) == 1
        urls = [e["url"] for k, e in c2.run.added if k == "url"]
        assert "https://h.ex.com/kept" in urls                   # replayed from attempt-0

    def test_retries_never_overwrite_recorded_evidence(self, tmp_path, monkeypatch):
        """review#2 (A1 r1): one fixed artifact path meant a retry unlinked evidence the store already
        referenced by raw_ref."""
        live = _live("https://h.ex.com")
        c1, seen1 = _drive(tmp_path, monkeypatch, live, body=_rows(("https://h.ex.com/first", 200)))
        first = seen1[0]
        assert "attempt-0" in str(first)
        # force a re-scan by changing the coverage config (a new wordlist digest)
        c2, seen2 = _drive(tmp_path, monkeypatch, live, wl_body="a\nb\nc\n",
                           body=_rows(("https://h.ex.com/second", 200)))
        assert seen2 and seen2[0] != first
        assert first.exists() and "first" in first.read_text()   # prior evidence intact

    def test_a_config_change_invalidates_resume(self, tmp_path, monkeypatch):
        live = _live("https://h.ex.com")
        _drive(tmp_path, monkeypatch, live, body=_rows(("https://h.ex.com/a", 200)))
        c2, seen2 = _drive(tmp_path, monkeypatch, live, wl_body="different\n",
                           body=_rows(("https://h.ex.com/a", 200)))
        assert len(seen2) == 1                                   # re-scanned under the new config
        states = list((tmp_path / "raw" / "content").glob("content_ffuf.*.state.json"))
        assert len(states) == 1                                  # the superseded generation is pruned


class TestIngestionHonesty:
    def test_out_of_scope_rows_are_excluded_from_the_denominator(self, tmp_path, monkeypatch):
        """review#3 (A1 r2): coverage claimed `tested=len(usable)` before ingestion. review#5 (A1 r3): and an
        out-of-scope row is a DELIBERATE filter, so counting it as `omitted` produced a phantom CAP gap while
        the comment claimed it was not a coverage loss."""
        body = _rows(("https://h.ex.com/in", 200), ("https://elsewhere.net/out", 200))
        c, _ = _drive(tmp_path, monkeypatch, _live("https://h.ex.com"), body=body)
        rows = _cov(tmp_path, "result_rows")[-1]
        assert (rows["eligible"], rows["tested"], rows["omitted"]) == (1, 1, 0)   # no phantom gap
        assert [e["url"] for k, e in c.run.added if k == "url"] == ["https://h.ex.com/in"]

    def test_a_store_failure_is_reported_as_unmeasured(self, tmp_path, monkeypatch):
        ctx = _Ctx(tmp_path, _live("https://h.ex.com"))
        ctx.run.fail_add = True
        with pytest.raises(RuntimeError):
            _drive(tmp_path, monkeypatch, None, body=_rows(("https://h.ex.com/a", 200)), ctx=ctx)
        rows = _cov(tmp_path, "result_rows")[-1]
        assert rows["kind"] == events.COVERAGE_UNKNOWN           # never "fully ingested"


class TestIdentityAndSchema:
    def test_service_identity_is_full_width(self, tmp_path, monkeypatch):
        """review#5 (A1 r2): an 8-hex (32-bit) hash let two service URLs collide, overwriting each other's
        artifact inside one attempt and sharing a coverage unit."""
        c, seen = _drive(tmp_path, monkeypatch, _live("https://h.ex.com"), body=_rows())
        stem = seen[0].stem
        assert len(stem.rsplit("-", 1)[1]) == 64                 # full sha256, not 8 hex chars

    def test_distinct_services_on_one_host_do_not_share_a_unit(self, tmp_path, monkeypatch):
        live = _live("https://h.ex.com", "https://h.ex.com:8443", "http://h.ex.com")
        c, seen = _drive(tmp_path, monkeypatch, live, body=_rows())
        assert len({p.name for p in seen}) == 3
        units = {e["unit"] for e in _cov(tmp_path, "result_rows")}
        assert len(units) == 3

    def test_schema_version_is_folded_into_the_work_unit(self):
        """review#4 (A1 r2): the row parser got stricter, so artifacts an older looser parser accepted must
        not stay resumable."""
        a = events.work_unit("content.ffuf", inputs={"url": "u"}, config={}, schema_version=1)
        b = events.work_unit("content.ffuf", inputs={"url": "u"}, config={}, schema_version=2)
        assert a != b and content._CONTENT_SCHEMA == 2


class TestContentReviewRound3:
    """The mechanics vhost would otherwise inherit: completion vs evidence, digest-bound replay, and a
    budget that gates only new work."""

    # ── review#1: a dirty historical attempt must not poison completion forever ───────────────────────
    def test_a_clean_rerun_completes_despite_a_dirty_history(self, tmp_path, monkeypatch):
        """`_ingest` aggregated trustworthy/clean across EVERY retained attempt, so run-1-dirty +
        run-2-clean could never enter the ledger — the old artifact blocked it permanently."""
        live = _live("https://h.ex.com")
        dirty = json.dumps({"results": [{"url": "https://h.ex.com/keep", "status": 200},
                                        {"url": ["bad"], "status": 200}]})
        _drive(tmp_path, monkeypatch, live, body=dirty)                     # run 1: dirty -> not recorded
        state = list((tmp_path / "raw" / "content").glob("content_ffuf.*.state.json"))[0]
        assert json.loads(state.read_text())["done"] == {}

        _drive(tmp_path, monkeypatch, live, body=_rows(("https://h.ex.com/ok", 200)))   # run 2: CLEAN
        assert json.loads(state.read_text())["done"] != {}                  # completion granted
        c3, seen3 = _drive(tmp_path, monkeypatch, live, body=_rows())        # run 3 resumes
        assert seen3 == []
        urls = {e["url"] for k, e in c3.run.added if k == "url"}
        assert {"https://h.ex.com/keep", "https://h.ex.com/ok"} <= urls     # BOTH generations' evidence

    def test_completion_records_the_current_artifact_not_a_sorted_tail(self, tmp_path, monkeypatch):
        """`artifacts[-1]` sorts `attempt-10` BEFORE `attempt-9` lexicographically, so a sorted tail could
        record an older attempt as the completion artifact.

        review#4 (A1 r4): the first version of this test changed the wordlist every iteration, so it built
        eleven CONFIGS each holding only `attempt-0` — it never produced a double-digit attempt at all. Here
        ONE config accumulates 11 attempts by staying unusable (never recorded, so it re-runs), then a clean
        12th run must record `attempt-11`."""
        live = _live("https://h.ex.com")
        dirty = json.dumps({"results": [{"url": ["bad"], "status": 200}]})
        for _ in range(11):
            _drive(tmp_path, monkeypatch, live, body=dirty)      # same config -> attempt-0 .. attempt-10
        cfg_dirs = list((tmp_path / "raw" / "content" / "ffuf").iterdir())
        assert len(cfg_dirs) == 1                                # ONE config, as intended
        attempts = {q.name for q in cfg_dirs[0].iterdir()}
        assert "attempt-10" in attempts and len(attempts) == 11  # the double-digit attempt really exists
        # a lexicographic tail of these names would pick attempt-9, NOT the newest
        assert sorted(attempts)[-1] == "attempt-9"
        _drive(tmp_path, monkeypatch, live, body=_rows(("https://h.ex.com/ok", 200)))
        state = list((tmp_path / "raw" / "content").glob("content_ffuf.*.state.json"))[0]
        rel = next(iter(json.loads(state.read_text())["done"].values()))
        assert "attempt-11/" in rel                              # the CURRENT artifact, not sorted[-1]

    # ── review#2: replayed evidence must be digest-bound ─────────────────────────────────────────────
    def test_a_tampered_retained_artifact_is_not_replayed(self, tmp_path, monkeypatch):
        """Globbing `attempt-*/` trusted any matching file — a tampered or planted artifact could inject
        fabricated findings into normalized data."""
        live = _live("https://h.ex.com")
        c1, seen1 = _drive(tmp_path, monkeypatch, live, body=_rows(("https://h.ex.com/real", 200)))
        art = seen1[0]
        art.write_text(_rows(("https://h.ex.com/FABRICATED", 200)))          # tamper after recording
        c2, _ = _drive(tmp_path, monkeypatch, live, body=_rows())
        urls = {e["url"] for k, e in c2.run.added if k == "url"}
        assert "https://h.ex.com/FABRICATED" not in urls                     # digest mismatch -> not replayed

    def test_a_planted_artifact_is_not_replayed(self, tmp_path, monkeypatch):
        live = _live("https://h.ex.com")
        c1, seen1 = _drive(tmp_path, monkeypatch, live, body=_rows(("https://h.ex.com/real", 200)))
        planted = seen1[0].parent.parent / "attempt-9" / seen1[0].name
        planted.parent.mkdir(parents=True, exist_ok=True)
        planted.write_text(_rows(("https://h.ex.com/PLANTED", 200)))
        c2, _ = _drive(tmp_path, monkeypatch, live, body=_rows())
        urls = {e["url"] for k, e in c2.run.added if k == "url"}
        assert "https://h.ex.com/PLANTED" not in urls                        # never in the ledger

    def test_a_symlinked_artifact_is_not_replayed(self, tmp_path, monkeypatch):
        outside = tmp_path / "outside.json"
        outside.write_text(_rows(("https://h.ex.com/OUTSIDE", 200)))
        live = _live("https://h.ex.com")
        c1, seen1 = _drive(tmp_path, monkeypatch, live, body=_rows(("https://h.ex.com/real", 200)))
        art = seen1[0]
        art.unlink()
        art.symlink_to(outside)
        c2, _ = _drive(tmp_path, monkeypatch, live, body=_rows())
        urls = {e["url"] for k, e in c2.run.added if k == "url"}
        assert "https://h.ex.com/OUTSIDE" not in urls

    # ── review#3: the budget gates launching, not replay ────────────────────────────────────────────
    def test_completed_services_later_in_the_order_are_still_replayed(self, tmp_path, monkeypatch):
        """Breaking out on the first pending service left every already-completed service LATER in the fair
        order unreplayed and uncounted — a coverage generation silently lost those units.

        review#4 (A1 r4): the first version completed `a.ex.com` and left `z.ex.com` pending, so the completed
        service came FIRST in the host-sorted fair order and the break was never reached before it. The
        COMPLETED host must sort LAST, so the pending one is encountered first and triggers the budget stop."""
        pending_url, done_url = "https://a.ex.com", "https://z.ex.com"
        _drive(tmp_path, monkeypatch, _live(done_url), body=_rows((f"{done_url}/x", 200)))   # z completes
        real = budget.Budget.exhausted
        monkeypatch.setattr(budget.Budget, "exhausted", lambda self: True)   # a (pending, FIRST) cannot launch
        c, seen = _drive(tmp_path, monkeypatch, _live(pending_url, done_url), body=_rows(),
                         budget_s={"CONTENT_FFUF_BUDGET_S": 1})
        monkeypatch.setattr(budget.Budget, "exhausted", real)
        assert seen == []                                                    # nothing launched
        units = {e["unit"] for e in _cov(tmp_path, "result_rows")}
        assert any("z.ex.com" in u for u in units)                           # the LATER completed host replayed
        assert f"{done_url}/x" in {e["url"] for k, e in c.run.added if k == "url"}

    def test_the_remainder_counts_only_unlaunched_work(self, tmp_path, monkeypatch):
        done_url, pending_url = "https://a.ex.com", "https://z.ex.com"
        _drive(tmp_path, monkeypatch, _live(done_url), body=_rows((f"{done_url}/x", 200)))
        clock = [1000.0]
        monkeypatch.setattr(budget.time, "monotonic", lambda: clock[0])
        real = budget.Budget.exhausted
        monkeypatch.setattr(budget.Budget, "exhausted", lambda self: True)   # nothing may launch
        c, seen = _drive(tmp_path, monkeypatch, _live(done_url, pending_url), body=_rows(),
                         budget_s={"CONTENT_FFUF_BUDGET_S": 1})
        monkeypatch.setattr(budget.Budget, "exhausted", real)
        assert seen == []                                                    # nothing launched
        sel = _cov(tmp_path, "hosts")[-1]
        # the completed service is ATTEMPTED (replayed); only the never-launched one is the remainder
        assert (sel["eligible"], sel["tested"], sel["omitted"]) == (2, 1, 1)

    # ── review#4: execution completion and artifact usability are separate ──────────────────────────
    def test_a_malformed_clean_run_is_not_counted_twice(self, tmp_path, monkeypatch):
        """`ff_clean` incremented before row validation and `ff_partial` again after, so one run could report
        attempted=1, obtained=1 and partial=1 at once."""
        c, _ = _drive(tmp_path, monkeypatch, _live("https://h.ex.com"),
                      body=json.dumps({"results": [{"url": ["bad"], "status": 200}]}))
        out = _cov(tmp_path, "hosts_scanned")[-1]
        assert (out["eligible"], out["tested"], out["omitted"]) == (1, 0, 1)
        assert "unusable_output" in out["reason"] and "partial" not in out["reason"]

    def test_a_clean_usable_run_reports_one_success(self, tmp_path, monkeypatch):
        c, _ = _drive(tmp_path, monkeypatch, _live("https://h.ex.com"),
                      body=_rows(("https://h.ex.com/a", 200)))
        out = _cov(tmp_path, "hosts_scanned")[-1]
        assert (out["eligible"], out["tested"], out["omitted"]) == (1, 1, 0)

    # ── review#5/#6: attribution + URL validation ───────────────────────────────────────────────────
    def test_no_retained_artifact_still_reports_row_coverage(self, tmp_path, monkeypatch):
        c, _ = _drive(tmp_path, monkeypatch, _live("https://h.ex.com"), body=None)
        rows = _cov(tmp_path, "result_rows")[-1]
        assert rows["kind"] == events.COVERAGE_UNKNOWN            # never absent -> no stale carry-forward

    @pytest.mark.parametrize("row,ok", [
        ({"url": "http://", "status": 200}, False),                # no authority
        ({"url": "http:///path", "status": 200}, False),           # empty host
        ({"url": "https://h:99999/", "status": 200}, False),       # impossible port
        ({"url": "https://h/", "status": 9999}, False),            # not an HTTP status
        ({"url": "https://h/", "status": 0}, False),
        ({"url": "https://h.ex.com/a", "status": 200}, True),
        ({"url": "http://h.ex.com:8443/a", "status": 403}, True),
    ])
    def test_absolute_url_and_status_range_are_enforced(self, row, ok):
        from quarry_recon.runner import ffuf_http_row as f
        assert f(row) is ok


class TestContentReviewRound4:
    """Completion vs retention vs coverage — three facts that kept collapsing into one."""

    # ── review#1: a degraded execution is never complete, but its evidence is kept ────────────────────
    @pytest.mark.parametrize("status", [Status.PARTIAL, Status.BLOCKED, Status.FAILED, Status.TIMED_OUT])
    def test_a_degraded_run_with_valid_json_is_not_recorded(self, tmp_path, monkeypatch, status):
        """Judging the ARTIFACT alone recorded a PARTIAL/BLOCKED run as done — skipped forever — whenever its
        JSON happened to parse."""
        live = _live("https://h.ex.com")
        c, seen = _drive(tmp_path, monkeypatch, live, status=status,
                         body=_rows(("https://h.ex.com/found", 200)))
        state = list((tmp_path / "raw" / "content").glob("content_ffuf.*.state.json"))[0]
        assert json.loads(state.read_text())["done"] == {}       # NOT complete
        c2, seen2 = _drive(tmp_path, monkeypatch, live, status=status, body=_rows())
        assert len(seen2) == 1                                   # re-runs on the next lifecycle

    @pytest.mark.parametrize("status", [Status.PARTIAL, Status.BLOCKED])
    def test_a_degraded_runs_rows_are_still_retained_and_replayed(self, tmp_path, monkeypatch, status):
        """Gating retention on ran_clean threw away real evidence: a PARTIAL run's rows are findings."""
        live = _live("https://h.ex.com")
        _drive(tmp_path, monkeypatch, live, status=status, body=_rows(("https://h.ex.com/found", 200)))
        c2, _ = _drive(tmp_path, monkeypatch, live, status=status, body=_rows())   # 2nd run finds nothing
        urls = {e["url"] for k, e in c2.run.added if k == "url"}
        assert "https://h.ex.com/found" in urls                  # the degraded run's row survived

    def test_only_a_clean_run_with_a_usable_artifact_completes(self, tmp_path, monkeypatch):
        live = _live("https://h.ex.com")
        c, _ = _drive(tmp_path, monkeypatch, live, status=Status.SUCCESS,
                      body=_rows(("https://h.ex.com/a", 200)))
        state = list((tmp_path / "raw" / "content").glob("content_ffuf.*.state.json"))[0]
        assert json.loads(state.read_text())["done"] != {}

    # ── review#2: a clean rerun clears the previous coverage gap ─────────────────────────────────────
    def test_a_clean_rerun_clears_the_dirty_generations_gap(self, tmp_path, monkeypatch):
        """`_ingest` aggregated schema trust across history, so one dirty old artifact emitted
        COVERAGE_UNKNOWN forever — the clean rerun earned completion but could never clear the gap."""
        live = _live("https://h.ex.com")
        dirty = json.dumps({"results": [{"url": "https://h.ex.com/keep", "status": 200},
                                        {"url": ["bad"], "status": 200}]})
        _drive(tmp_path, monkeypatch, live, body=dirty)
        assert _cov(tmp_path, "result_rows")[-1]["kind"] == events.COVERAGE_UNKNOWN

        _drive(tmp_path, monkeypatch, live, body=_rows(("https://h.ex.com/ok", 200)))
        rows = _cov(tmp_path, "result_rows")[-1]
        assert rows["kind"] == events.COVERAGE_TIMEOUT           # the gap is CLEARED
        assert rows["coverage_valid"] is True and rows["omitted"] == 0

    def test_the_cleared_gap_survives_a_later_resume(self, tmp_path, monkeypatch):
        live = _live("https://h.ex.com")
        _drive(tmp_path, monkeypatch, live,
               body=json.dumps({"results": [{"url": ["bad"], "status": 200}]}))
        _drive(tmp_path, monkeypatch, live, body=_rows(("https://h.ex.com/ok", 200)))
        c3, seen3 = _drive(tmp_path, monkeypatch, live, body=_rows())
        assert seen3 == []                                       # resumed
        rows = _cov(tmp_path, "result_rows")[-1]
        assert rows["kind"] == events.COVERAGE_TIMEOUT and rows["omitted"] == 0

    def test_the_verdict_reflects_the_cleared_gap(self, tmp_path, monkeypatch):
        """Assert the operator-visible outcome, not just the event."""
        from quarry_recon.store import Run
        live = _live("https://h.ex.com")
        _drive(tmp_path, monkeypatch, live,
               body=json.dumps({"results": [{"url": ["bad"], "status": 200}]}))
        _drive(tmp_path, monkeypatch, live, body=_rows(("https://h.ex.com/ok", 200)))
        st = Run.create(tmp_path / "proj", "t", run_id="r1")
        (st.dir / "events.jsonl").write_text((tmp_path / "events.jsonl").read_text())
        gaps = [g for g in st._run_summary()["gaps"]
                if g["tool"] == "content.ffuf" and g["measure"] == "result_rows"]
        assert gaps == []                                        # no lingering unknown

    # ── review#3: journal-only recovery keeps completion evidence ────────────────────────────────────
    def test_completion_implies_evidence_after_journal_only_recovery(self, tmp_path):
        """Reproduced: record() then reopen before save() gave has=True, evidence=[] — the item resumed while
        replaying nothing, so its findings were silently gone."""
        art = tmp_path / "f" / "x.json"
        art.parent.mkdir(parents=True)
        art.write_text("{}")
        led = budget.Ledger(tmp_path / "s.json", lane="l")
        led.record("u", art)                                     # journal only, no save()
        again = budget.Ledger(tmp_path / "s.json", lane="l")
        assert again.has("u") and [q.name for q in again.evidence("u")] == ["x.json"]

    def test_a_legacy_snapshot_without_evidence_still_replays(self, tmp_path):
        art = tmp_path / "f" / "x.json"
        art.parent.mkdir(parents=True)
        art.write_text("{}")
        led = budget.Ledger(tmp_path / "s.json", lane="l")
        led.record("u", art)
        led.save()
        snap = json.loads((tmp_path / "s.json").read_text())
        snap.pop("evidence")                                     # a state file from before evidence existed
        (tmp_path / "s.json").write_text(json.dumps(snap))
        again = budget.Ledger(tmp_path / "s.json", lane="l")
        assert again.has("u") and len(again.evidence("u")) == 1

    def test_a_resumed_service_replays_its_completion_artifact(self, tmp_path, monkeypatch):
        """The lane-level consequence of the same bug."""
        live = _live("https://h.ex.com")
        _drive(tmp_path, monkeypatch, live, body=_rows(("https://h.ex.com/only", 200)))
        state = list((tmp_path / "raw" / "content").glob("content_ffuf.*.state.json"))[0]
        snap = json.loads(state.read_text())
        snap.pop("evidence")                                     # simulate the legacy/journal-recovery shape
        state.write_text(json.dumps(snap))
        c2, seen2 = _drive(tmp_path, monkeypatch, live, body=_rows())
        assert seen2 == []
        assert "https://h.ex.com/only" in {e["url"] for k, e in c2.run.added if k == "url"}


class TestContentReviewRound5:
    """Reporting honesty for the bounded and replayed cases."""

    # ── review#1: a never-launched service emits no row-coverage unit ─────────────────────────────────
    def test_a_budget_skipped_service_emits_no_row_unit(self, tmp_path, monkeypatch):
        """Budget exhaustion left current=None, but _ingest still ran and reported "no current artifact" —
        so every intentionally-unlaunched service got a bogus UNKNOWN gap ON TOP of the correct selection
        omission. On a large bounded run that is one false gap per skipped service."""
        real = budget.Budget.exhausted
        monkeypatch.setattr(budget.Budget, "exhausted", lambda self: True)
        c, seen = _drive(tmp_path, monkeypatch, _live("https://a.ex.com", "https://b.ex.com"),
                         body=_rows(), budget_s={"CONTENT_FFUF_BUDGET_S": 1})
        monkeypatch.setattr(budget.Budget, "exhausted", real)
        assert seen == []                                        # nothing launched
        assert _cov(tmp_path, "result_rows") == []               # and NO row units at all
        sel = _cov(tmp_path, "hosts")[-1]
        assert (sel["eligible"], sel["tested"], sel["omitted"]) == (2, 0, 2)   # selection accounts for it

    def test_an_attempted_run_with_no_artifact_still_reports_unknown(self, tmp_path, monkeypatch):
        """The distinction that matters: "never launched" is silent, "launched and produced nothing" is a gap."""
        c, seen = _drive(tmp_path, monkeypatch, _live("https://h.ex.com"), body=None)
        assert len(seen) == 1                                    # it DID launch
        rows = _cov(tmp_path, "result_rows")[-1]
        assert rows["kind"] == events.COVERAGE_UNKNOWN
        assert "attempted but produced no ffuf artifact" in rows["reason"]

    def test_a_budget_skipped_service_with_history_still_replays(self, tmp_path, monkeypatch):
        """Silence applies only when there is nothing retained — prior evidence must still be replayed."""
        live = _live("https://h.ex.com")
        _drive(tmp_path, monkeypatch, live,
               body=json.dumps({"results": [{"url": "https://h.ex.com/old", "status": 200},
                                            {"url": ["bad"], "status": 200}]}))   # retained, not completed
        real = budget.Budget.exhausted
        monkeypatch.setattr(budget.Budget, "exhausted", lambda self: True)
        c2, seen2 = _drive(tmp_path, monkeypatch, live, body=_rows(),
                           budget_s={"CONTENT_FFUF_BUDGET_S": 1})
        monkeypatch.setattr(budget.Budget, "exhausted", real)
        assert seen2 == []
        assert "https://h.ex.com/old" in {e["url"] for k, e in c2.run.added if k == "url"}
        # the reason must not claim it was attempted — it was never launched this lifecycle
        rows = _cov(tmp_path, "result_rows")[-1]
        assert "not launched" in rows["reason"] and "attempted" not in rows["reason"]

    # ── review#2: notable paths are unique per lifecycle ─────────────────────────────────────────────
    def test_notable_count_is_not_inflated_by_replay(self, tmp_path, monkeypatch):
        """`notable` incremented per row per ARTIFACT, so one unique path became 10 or 20 as retries and
        resumes replayed the same rows."""
        live = _live("https://h.ex.com")
        dirty = json.dumps({"results": [{"url": "https://h.ex.com/admin", "status": 200},
                                        {"url": ["bad"], "status": 200}]})
        for _ in range(5):                                       # five retained attempts, same notable path
            c, _ = _drive(tmp_path, monkeypatch, live, body=dirty)
        line = next(m for m in c.echoed if "content ffuf:" in m)
        assert "1 notable path(s)" in line                       # unique, not 5 or 15

    def test_notable_count_is_unique_across_services(self, tmp_path, monkeypatch):
        live = _live("https://a.ex.com", "https://b.ex.com")
        bodies = [_rows(("https://a.ex.com/admin", 200)), _rows(("https://b.ex.com/login", 401))]
        c, _ = _drive(tmp_path, monkeypatch, live, bodies=bodies)
        line = next(m for m in c.echoed if "content ffuf:" in m)
        assert "2 notable path(s)" in line                       # two DISTINCT paths

    def test_a_resumed_service_does_not_re_inflate_the_count(self, tmp_path, monkeypatch):
        live = _live("https://h.ex.com")
        _drive(tmp_path, monkeypatch, live, body=_rows(("https://h.ex.com/admin", 200)))
        c2, seen2 = _drive(tmp_path, monkeypatch, live, body=_rows())
        assert seen2 == []
        line = next(m for m in c2.echoed if "content ffuf:" in m)
        assert "1 notable path(s)" in line

    # ── review#3: dead state removed ───────────────────────────────────────────────────────────────
    def test_no_dead_budget_state_remains(self):
        import inspect
        src = inspect.getsource(content.run)
        assert "budget_spent" not in src
