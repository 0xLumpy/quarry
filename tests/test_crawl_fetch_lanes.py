"""crawl.js_fetch and crawl.sourcemaps — the first two lanes migrated off input-set caps.

These are the lanes the OTC 20260725 audit indicted. `js_urls = eligible[:2000]` and
`sorted(map_urls)[:100]` dropped 60% and 92% of eligible input, chose WHICH input by discovery /
alphabetical order, and so rotated the scanned set between runs of the same target: influx1 JS
433/439 -> 0/439, recovered sourcemaps 46 -> 5, normalized secrets 24 -> 3.

Both now process the FULL eligible set in host-fair order under an UNBOUNDED-by-default throughput budget,
with a resumable content-bound ledger for any remainder. Pure/offline — fetch.scoped_get is faked, no
network, no tools.
"""
import json
import pathlib

import pytest

from quarry_recon import budget, events, settings
from quarry_recon.phases import crawl

pytestmark = pytest.mark.offline


class _Scope:
    def __init__(self, allowed=True):
        self.allowed = allowed
        self.passive_only = False

    def active_allowed(self, host):
        return self.allowed

    def in_scope(self, host):
        return True

    def is_oos(self, host):
        return False


class _Run:
    def __init__(self, d):
        self.dir = d
        self._vals = {}
        self.added = []

    def raw_path(self, ph, tl, nm):
        p = self.dir / "raw" / ph / tl / nm
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def values(self, kind):
        return list(self._vals.get(kind, []))

    def add(self, kind, e):
        self.added.append((kind, e))
        return True

    def read(self, kind):
        return []

    def record(self, *a, **k):
        pass


class _Ctx:
    def __init__(self, d, js_urls, allowed=True):
        self.run = _Run(d)
        self.run._vals["js_url"] = js_urls
        self.scope = _Scope(allowed)
        self.http_timeout = 30
        self.echoed = []
        self.profile = type("P", (), {"apex_domains": ["ex.com"], "http_rl": 0})()

    def echo(self, m):
        self.echoed.append(m)

    def write_list(self, nm, it):
        p = self.run.dir / "work" / nm
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("\n".join(it))
        return p


def _urls(spec):
    """spec: {host: count} -> flat list in HOST-BLOCK order, i.e. the pathological input the old flat cap
    was fed (all of host A, then all of host B ...)."""
    out = []
    for host, n in spec.items():
        out += [f"https://{host}/{i}.js" for i in range(n)]
    return out


class _Fetcher:
    """Fake scoped_get. Records call order so we can assert WHICH items a bounded run reached."""

    def __init__(self, *, body=b"x" * 200, fail_hosts=(), status_for=None, unique=True):
        self.calls = []
        self.body = body
        self.fail_hosts = set(fail_hosts)
        self.status_for = status_for or {}
        # `unique` appends the URL so two JS bodies never collide in the content-dedup set. It must be OFF
        # for sourcemap bodies — appending to a JSON document makes it unparseable.
        self.unique = unique

    def __call__(self, ctx, url, origin_host=None, *, max_body=None, **k):
        self.calls.append(url)
        from quarry_recon import normalize
        host = normalize.host_of_url(url)
        if host in self.fail_hosts:
            return None, url, 0                       # not contacted (off-scope redirect / guard)
        st = self.status_for.get(url, 200)
        if st != 200:
            return b"", url, st
        return (self.body + url.encode() if self.unique else self.body), url, 200


def _run_crawl_js(tmp_path, monkeypatch, ctx, fetcher, *, budget_s=None):
    """Drive ONLY the JS-download + sourcemap portion by stubbing out everything around it."""
    events.reset(); events.configure(tmp_path)
    monkeypatch.setattr(settings, "performance",
                        lambda: {} if budget_s is None else dict(budget_s))
    monkeypatch.setattr(crawl.fetch, "scoped_get", fetcher)
    monkeypatch.setattr(crawl, "have", lambda t: False)        # no external tools in these tests
    return ctx


class TestJsFetchFairness:
    """The cap lottery, killed."""

    def _fetch_all(self, tmp_path, monkeypatch, spec, **kw):
        ctx = _Ctx(tmp_path, _urls(spec))
        f = _Fetcher(**kw)
        _run_crawl_js(tmp_path, monkeypatch, ctx, f)
        led, raw = crawl._js_download(ctx)                     # the extracted lane
        return ctx, f

    def test_every_eligible_url_is_fetched_when_unbounded(self, tmp_path, monkeypatch):
        ctx, f = self._fetch_all(tmp_path, monkeypatch, {"a.ex.com": 30, "b.ex.com": 5})
        assert len(f.calls) == 35                              # the WHOLE set — no 2000-style slice
        assert len(list((tmp_path / "raw" / "crawl" / "js_files").glob("*.js"))) == 35

    def test_order_is_host_fair_not_host_blocked(self, tmp_path, monkeypatch):
        """Input arrives as one host's whole block then the next. The old code fetched it in that order, so a
        budget drained the first host. The fair order must interleave from the first pair."""
        ctx, f = self._fetch_all(tmp_path, monkeypatch, {"big.ex.com": 50, "small.ex.com": 2})
        from quarry_recon import normalize
        hosts = [normalize.host_of_url(u) for u in f.calls[:4]]
        assert hosts == ["big.ex.com", "small.ex.com", "big.ex.com", "small.ex.com"]

    def test_a_bounded_run_reaches_every_host(self, tmp_path, monkeypatch):
        """THE regression, end to end: with a budget that stops after a handful of items, the small host must
        still be represented. Under the old flat order it got nothing."""
        ctx = _Ctx(tmp_path, _urls({"big.ex.com": 825, "small.ex.com": 3}))
        f = _Fetcher()
        _run_crawl_js(tmp_path, monkeypatch, ctx, f, budget_s={"JS_FETCH_BUDGET_S": 60})
        clock = [1000.0]
        monkeypatch.setattr(budget.time, "monotonic", lambda: clock[0])
        real = f.__call__

        def ticking(*a, **k):                                  # each fetch costs 10s of the 60s budget
            clock[0] += 10
            return real(*a, **k)
        monkeypatch.setattr(crawl.fetch, "scoped_get", ticking)
        crawl._js_download(ctx)
        from quarry_recon import normalize
        reached = {normalize.host_of_url(u) for u in f.calls}
        assert reached == {"big.ex.com", "small.ex.com"}        # the budget did not starve the small host
        assert len(f.calls) < 828                               # ...and it really did stop short

    def test_remainder_is_reported_as_a_resumable_gap(self, tmp_path, monkeypatch):
        ctx = _Ctx(tmp_path, _urls({"a.ex.com": 40}))
        f = _Fetcher()
        _run_crawl_js(tmp_path, monkeypatch, ctx, f, budget_s={"JS_FETCH_BUDGET_S": 30})
        clock = [1000.0]
        monkeypatch.setattr(budget.time, "monotonic", lambda: clock[0])
        real = f.__call__

        def ticking(*a, **k):
            clock[0] += 10
            return real(*a, **k)
        monkeypatch.setattr(crawl.fetch, "scoped_get", ticking)
        crawl._js_download(ctx)
        cov = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        sel = [e for e in cov if e.get("measure") == "js_urls"][-1]
        assert sel["eligible"] == 40 and sel["omitted"] > 0
        assert sel["kind"] == events.COVERAGE_CAP and "RESUMABLE" in sel["reason"]
        assert any("left by budget" in m for m in ctx.echoed)

    def test_passive_mode_reports_zero_eligible_not_a_phantom(self, tmp_path, monkeypatch):
        ctx = _Ctx(tmp_path, _urls({"a.ex.com": 10}), allowed=False)
        f = _Fetcher()
        _run_crawl_js(tmp_path, monkeypatch, ctx, f)
        crawl._js_download(ctx)
        assert f.calls == []
        cov = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        sel = [e for e in cov if e.get("measure") == "js_urls"][-1]
        assert sel["eligible"] == 0 and sel["omitted"] == 0


class TestJsFetchOutcome:
    def test_in_flight_loss_is_measured_separately(self, tmp_path, monkeypatch):
        """The number nobody could see: OTC attempted 2000 and obtained 628. Selection and outcome are
        different facts with different causes, so they get different measures."""
        urls = _urls({"ok.ex.com": 5, "dead.ex.com": 5})
        ctx = _Ctx(tmp_path, urls)
        f = _Fetcher(fail_hosts={"dead.ex.com"})
        _run_crawl_js(tmp_path, monkeypatch, ctx, f)
        crawl._js_download(ctx)
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        sel = [e for e in ev if e.get("measure") == "js_urls"][-1]
        out = [e for e in ev if e.get("measure") == "js_fetched"][-1]
        assert (sel["eligible"], sel["tested"], sel["omitted"]) == (10, 10, 0)   # we reached everything
        assert (out["eligible"], out["tested"], out["omitted"]) == (10, 5, 5)    # half was lost in flight
        assert out["kind"] == events.COVERAGE_TIMEOUT and "not_contacted" in out["reason"]

    def test_http_failure_classes_are_named(self, tmp_path, monkeypatch):
        urls = _urls({"a.ex.com": 3})
        ctx = _Ctx(tmp_path, urls)
        f = _Fetcher(status_for={urls[0]: 403, urls[1]: 404})
        _run_crawl_js(tmp_path, monkeypatch, ctx, f)
        crawl._js_download(ctx)
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        out = [e for e in ev if e.get("measure") == "js_fetched"][-1]
        assert "http_403" in out["reason"] and "http_404" in out["reason"]

    def test_size_guard_is_a_per_item_bound_not_a_cap(self, tmp_path, monkeypatch):
        """A 15 MB ceiling on ONE file is legitimate: it bounds that item's cost, not which items run."""
        urls = _urls({"a.ex.com": 2})
        ctx = _Ctx(tmp_path, urls)
        f = _Fetcher(body=b"z" * (16 * 1024 * 1024))
        _run_crawl_js(tmp_path, monkeypatch, ctx, f)
        crawl._js_download(ctx)
        assert len(f.calls) == 2                                # BOTH still attempted
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        out = [e for e in ev if e.get("measure") == "js_fetched"][-1]
        assert out["omitted"] == 2 and "size_guard" in out["reason"]


class TestJsFetchResume:
    def test_a_second_run_does_not_refetch_completed_urls(self, tmp_path, monkeypatch):
        urls = _urls({"a.ex.com": 6})
        ctx = _Ctx(tmp_path, urls)
        f1 = _Fetcher()
        _run_crawl_js(tmp_path, monkeypatch, ctx, f1)
        crawl._js_download(ctx)
        assert len(f1.calls) == 6

        ctx2 = _Ctx(tmp_path, urls)
        f2 = _Fetcher()
        _run_crawl_js(tmp_path, monkeypatch, ctx2, f2)
        crawl._js_download(ctx2)
        assert f2.calls == []                                   # all six resumed from the ledger

    def test_state_lives_outside_the_scanned_js_dir(self, tmp_path, monkeypatch):
        """js_files/ is walked by gitleaks/trufflehog and mined by xnLinkFinder. A ledger inside it would
        inject its own recorded URLs into the URL corpus and hand its sha256 digests to the secret scanners
        as high-entropy strings."""
        ctx = _Ctx(tmp_path, _urls({"a.ex.com": 2}))
        f = _Fetcher()
        _run_crawl_js(tmp_path, monkeypatch, ctx, f)
        crawl._js_download(ctx)
        js_dir = tmp_path / "raw" / "crawl" / "js_files"
        assert (js_dir.parent / "js_fetch.state.json").is_file()
        assert list(js_dir.glob("*.json")) == []                 # nothing but .js inside the scanned dir

    def test_a_growing_url_set_keeps_prior_work(self, tmp_path, monkeypatch):
        first = _urls({"a.ex.com": 3})
        ctx = _Ctx(tmp_path, first)
        _run_crawl_js(tmp_path, monkeypatch, ctx, _Fetcher())
        crawl._js_download(ctx)

        grown = first + _urls({"b.ex.com": 2})                   # crawl found more JS since
        ctx2 = _Ctx(tmp_path, grown)
        f2 = _Fetcher()
        _run_crawl_js(tmp_path, monkeypatch, ctx2, f2)
        crawl._js_download(ctx2)
        assert len(f2.calls) == 2                                # ONLY the new ones — not a full re-fetch
        from quarry_recon import normalize
        assert {normalize.host_of_url(u) for u in f2.calls} == {"b.ex.com"}

    def test_a_tampered_artifact_is_refetched(self, tmp_path, monkeypatch):
        urls = _urls({"a.ex.com": 2})
        ctx = _Ctx(tmp_path, urls)
        _run_crawl_js(tmp_path, monkeypatch, ctx, _Fetcher())
        crawl._js_download(ctx)
        js_dir = tmp_path / "raw" / "crawl" / "js_files"
        victim = sorted(js_dir.glob("*.js"))[0]
        victim.write_text("TAMPERED")
        ctx2 = _Ctx(tmp_path, urls)
        f2 = _Fetcher()
        _run_crawl_js(tmp_path, monkeypatch, ctx2, f2)
        crawl._js_download(ctx2)
        assert len(f2.calls) == 1                                # exactly the tampered one


def _map_body(name="app.ts", content="const token = 'x'"):
    return json.dumps({"version": 3, "sources": [name], "sourcesContent": [content]}).encode()


class TestSourcemapLane:
    """`sorted(map_urls)[:100]` was the cap lottery at its worst: sorting CLUSTERS by host, so one
    alphabetically-early host consumed all 100 fetch slots. Measured on two OTC runs of the same target —
    influx1 took 85 slots and yielded 46 recovered maps; next run dependencytrack took 74 and yielded 5,
    and report-sourcemap.json came back empty because the map holding the secret was never fetched."""

    class _TwoPhase:
        """One fake for both hops: a `.js` request returns a body whose sourceMappingURL is relative to THAT
        url; a `.map` request returns the sourcemap JSON. `js_body` forces every JS to share one body, which
        is how the content-dedup case is reproduced."""

        def __init__(self, map_body, *, js_body=None, fail_hosts=()):
            self.calls = []
            self.map_calls = []
            self.map_body = map_body
            self.js_body = js_body
            self.fail_hosts = set(fail_hosts)

        def __call__(self, ctx, url, origin_host=None, **k):
            from quarry_recon import normalize
            if url.endswith(".map"):
                self.calls.append(url)
                self.map_calls.append(url)
                if normalize.host_of_url(url) in self.fail_hosts:
                    return None, url, 0
                return self.map_body, url, 200
            if self.js_body is not None:
                return self.js_body, url, 200                # identical across urls -> content dedup
            name = url.rsplit("/", 1)[1]
            return (f"//# sourceMappingURL={name}.map\n".encode() + b"x" * 200 + url.encode()), url, 200

    def _setup(self, tmp_path, monkeypatch, spec, *, budget_s=None, body=None, js_body=None, fail_hosts=()):
        """Fetch JS, then drive the sourcemap lane off the resulting ledger."""
        ctx = _Ctx(tmp_path, _urls(spec))
        f = self._TwoPhase(body if body is not None else _map_body(), js_body=js_body,
                           fail_hosts=fail_hosts)
        _run_crawl_js(tmp_path, monkeypatch, ctx, f, budget_s=budget_s)
        led, raw = crawl._js_download(ctx)
        f.calls.clear()                                      # count only the sourcemap hops from here
        return ctx, led, f

    def test_every_referenced_map_is_fetched_when_unbounded(self, tmp_path, monkeypatch):
        ctx, led, f = self._setup(tmp_path, monkeypatch, {"a.ex.com": 8, "b.ex.com": 4})
        crawl._sourcemap_recover(ctx, led)
        # the explicit `sourceMappingURL=0.js.map` ref and the conventional `<url>.map` fallback resolve to
        # the SAME url and dedupe in the candidate set -> one candidate per JS
        assert len(f.calls) == 12                                # the WHOLE set, no 100-slice
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        sel = [e for e in ev if e.get("measure") == "sourcemaps"][-1]
        assert sel["omitted"] == 0 and sel["eligible"] == 12

    def test_fetch_order_is_host_fair_not_alphabetical_clustering(self, tmp_path, monkeypatch):
        """THE defect: alphabetical order groups every URL of one host together."""
        ctx, led, f = self._setup(tmp_path, monkeypatch, {"aaa.ex.com": 20, "zzz.ex.com": 2})
        crawl._sourcemap_recover(ctx, led)
        from quarry_recon import normalize
        first_hosts = [normalize.host_of_url(u) for u in f.calls[:4]]
        assert "zzz.ex.com" in first_hosts                        # the late-sorting host is reached immediately
        assert first_hosts[0] == "aaa.ex.com" and first_hosts[1] == "zzz.ex.com"

    def test_recovered_sources_are_written(self, tmp_path, monkeypatch):
        ctx, led, f = self._setup(tmp_path, monkeypatch, {"a.ex.com": 2},
                                               body=_map_body("secret.ts", "const k = 'leak'"))
        recov = crawl._sourcemap_recover(ctx, led)
        files = [p for p in recov.rglob("*") if p.is_file()]
        assert files and any("leak" in p.read_text() for p in files)

    def test_selection_and_outcome_are_separate(self, tmp_path, monkeypatch):
        ctx, led, f = self._setup(tmp_path, monkeypatch, {"ok.ex.com": 2, "dead.ex.com": 2})
        f.fail_hosts = {"dead.ex.com"}
        crawl._sourcemap_recover(ctx, led)
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        sel = [e for e in ev if e.get("measure") == "sourcemaps"][-1]
        out = [e for e in ev if e.get("measure") == "sourcemaps_fetched"][-1]
        assert sel["omitted"] == 0                               # reached all of them
        assert out["eligible"] == 4 and out["omitted"] == 2       # half lost in flight
        assert out["kind"] == events.COVERAGE_TIMEOUT

    def test_a_second_run_resumes_from_the_cache(self, tmp_path, monkeypatch):
        ctx, led, f1 = self._setup(tmp_path, monkeypatch, {"a.ex.com": 3})
        crawl._sourcemap_recover(ctx, led)
        assert len(f1.calls) == 3

        ctx2, led2, f2 = self._setup(tmp_path, monkeypatch, {"a.ex.com": 3})
        crawl._sourcemap_recover(ctx2, led2)
        assert f2.calls == []                                    # every map came from the ledger + cache

    def test_no_js_emits_zero_for_every_measure(self, tmp_path, monkeypatch):
        """A prior generation's OUTCOME units must be superseded too — emitting only the selection zero would
        leave the old in-flight-loss and recovery numbers standing with nothing to replace them."""
        ctx = _Ctx(tmp_path, [])
        _run_crawl_js(tmp_path, monkeypatch, ctx, _Fetcher())
        crawl._sourcemap_recover(ctx, budget.Ledger(tmp_path / "empty.json", lane="crawl.js_fetch"))
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        measures = {e.get("measure") for e in ev if e.get("event") == "coverage_partial"}
        assert measures == {"sourcemaps", "sourcemaps_fetched", "sourcemaps_valid",
                            "sourcemaps_extracted", "sourcemaps_published", "js_inspected"}
        for m in measures - {"sourcemaps_published"}:
            assert [e for e in ev if e.get("measure") == m][-1]["eligible"] == 0
        # publication is ONE operation, measured 1/0 even when the generation is empty (review#1 r5) — sizing
        # it by subdir count made an empty generation that FAILED to publish report no gap at all
        pub = [e for e in ev if e.get("measure") == "sourcemaps_published"][-1]
        assert (pub["eligible"], pub["tested"], pub["omitted"]) == (1, 1, 0)

    def test_state_and_cache_stay_out_of_the_scanned_recovered_dir(self, tmp_path, monkeypatch):
        ctx, led, f = self._setup(tmp_path, monkeypatch, {"a.ex.com": 1})
        recov = crawl._sourcemap_recover(ctx, led)
        sm = tmp_path / "raw" / "crawl" / "sourcemaps"
        assert (sm.parent / "sourcemap_fetch.state.json").is_file()   # beside sourcemaps/, not inside recovered/
        assert (sm / "fetched").is_dir()
        assert not any(p.name.endswith(".state.json") for p in recov.rglob("*"))
        assert not any(p.name.endswith(".map") for p in recov.rglob("*"))


class TestTemplateDefects:
    """One regression per defect found reviewing the first two migrated lanes. Each of these passed the
    original tests — they simply were not exercised, which is why the review gate exists."""

    # ── review#1: beautification must not invalidate the resume ledger ────────────────────────────────
    def test_beautification_does_not_invalidate_the_ledger(self, tmp_path, monkeypatch):
        """js-beautify REPLACES its target. When it ran on the raw artifacts the ledger had digest-bound,
        every later run saw a mismatch and re-fetched the whole lane — the ledger did nothing during a normal
        full run. Raw artifacts are now immutable and beautification works on derived copies."""
        ctx = _Ctx(tmp_path, _urls({"a.ex.com": 4}))
        f1 = _Fetcher()
        _run_crawl_js(tmp_path, monkeypatch, ctx, f1)
        led, raw_dir = crawl._js_download(ctx)
        assert len(f1.calls) == 4

        pub = crawl._js_publish_derived(ctx, led, raw_dir)
        derived = sorted(pub.glob("*.js"))
        assert len(derived) == 4 and pub != raw_dir
        for d in derived:                                    # simulate the reformat inside the published tree
            d.write_text("/* beautified */\n" + d.read_text())
        raw_before = {p.name: p.read_bytes() for p in raw_dir.glob("*.js")}

        ctx2 = _Ctx(tmp_path, _urls({"a.ex.com": 4}))
        f2 = _Fetcher()
        _run_crawl_js(tmp_path, monkeypatch, ctx2, f2)
        crawl._js_download(ctx2)
        assert f2.calls == []                                 # NOTHING re-fetched
        assert {p.name: p.read_bytes() for p in raw_dir.glob("*.js")} == raw_before   # raw untouched

    # ── review#2: interruption / torn write must not discard completed work ───────────────────────────
    def test_interruption_keeps_completions_already_made(self, tmp_path, monkeypatch):
        ctx = _Ctx(tmp_path, _urls({"a.ex.com": 10}))
        f = _Fetcher()
        _run_crawl_js(tmp_path, monkeypatch, ctx, f)
        n = [0]
        real = f.__call__

        def boom(*a, **k):
            n[0] += 1
            if n[0] > 4:
                raise KeyboardInterrupt("operator hit ctrl-c")
            return real(*a, **k)
        monkeypatch.setattr(crawl.fetch, "scoped_get", boom)
        with pytest.raises(KeyboardInterrupt):
            crawl._js_download(ctx)

        ctx2 = _Ctx(tmp_path, _urls({"a.ex.com": 10}))
        f2 = _Fetcher()
        _run_crawl_js(tmp_path, monkeypatch, ctx2, f2)
        crawl._js_download(ctx2)
        assert len(f2.calls) == 6                             # the 4 completed before the interrupt were kept

    def test_save_is_atomic(self, tmp_path, monkeypatch):
        """A torn state write loads as nothing and fails closed into a full redo. save() must go through a
        temp file and os.replace, so a crash mid-write leaves the PREVIOUS state intact."""
        art = tmp_path / "f" / "a.js"
        art.parent.mkdir(parents=True)
        art.write_text("x")
        led = budget.Ledger(tmp_path / "s.json", lane="l")
        led.record("u1", art)
        led.save()
        good = (tmp_path / "s.json").read_text()

        seen = {}
        real_replace = budget.os.replace

        def fail_replace(src, dst):
            seen["src"] = src
            raise OSError("crash between write and rename")
        monkeypatch.setattr(budget.os, "replace", fail_replace)
        led.record("u2", art)
        # review#3 (r7): the contract is "returns success, never raises" — callers only handle a returned
        # False, so a raising save() bypassed the state_persisted gap and surfaced from the lane body instead.
        assert led.save() is False
        monkeypatch.setattr(budget.os, "replace", real_replace)
        assert (tmp_path / "s.json").read_text() == good      # previous state survived, not truncated
        assert budget.Ledger(tmp_path / "s.json", lane="l").has("u1")

    def test_every_record_is_durable_without_a_save(self, tmp_path):
        """review#5: persistence is an APPEND-ONLY journal, not a periodic full rewrite. Re-serializing the
        whole map every N records was quadratic (151k items would serialize ~456M cumulative entries). Each
        record costs one appended line, and it is durable IMMEDIATELY — no checkpoint window to lose."""
        art = tmp_path / "f" / "a.js"
        art.parent.mkdir(parents=True)
        art.write_text("x")
        led = budget.Ledger(tmp_path / "s.json", lane="l")
        for i in range(40):
            led.record(f"u{i}", art)                          # no explicit save() at all
        assert not (tmp_path / "s.json").exists()              # no snapshot yet...
        assert led.journal.is_file()                           # ...but the journal has every completion
        assert len(budget.Ledger(tmp_path / "s.json", lane="l").done) == 40

    def test_save_compacts_and_drops_the_journal(self, tmp_path):
        art = tmp_path / "f" / "a.js"
        art.parent.mkdir(parents=True)
        art.write_text("x")
        led = budget.Ledger(tmp_path / "s.json", lane="l")
        for i in range(5):
            led.record(f"u{i}", art)
        led.save()
        assert (tmp_path / "s.json").is_file() and not led.journal.exists()
        assert len(budget.Ledger(tmp_path / "s.json", lane="l").done) == 5

    def test_a_torn_journal_line_loses_only_that_entry(self, tmp_path):
        art = tmp_path / "f" / "a.js"
        art.parent.mkdir(parents=True)
        art.write_text("x")
        led = budget.Ledger(tmp_path / "s.json", lane="l")
        led.record("u1", art)
        led.record("u2", art)
        with led.journal.open("a") as fh:
            fh.write('{"i": "u3", "r": "f/a.js"')              # killed mid-append
        again = budget.Ledger(tmp_path / "s.json", lane="l")
        assert again.has("u1") and again.has("u2") and not again.has("u3")

    def test_a_shared_artifact_is_hashed_once_not_once_per_item(self, tmp_path, monkeypatch):
        """review#5: loading rehashed the artifact once per URL. A body served at 400 URLs meant 400 hashes
        of the same file."""
        art = tmp_path / "f" / "a.js"
        art.parent.mkdir(parents=True)
        art.write_text("x")
        led = budget.Ledger(tmp_path / "s.json", lane="l")
        for i in range(50):
            led.record(f"u{i}", art)                          # 50 items, ONE artifact
        led.save()
        n = [0]
        real = budget.events.file_digest
        monkeypatch.setattr(budget.events, "file_digest", lambda p: (n.__setitem__(0, n[0] + 1), real(p))[1])
        assert len(budget.Ledger(tmp_path / "s.json", lane="l").done) == 50
        assert n[0] == 1

    # ── review#3: content dedup must not lose a URL's own sourcemap ───────────────────────────────────
    def test_duplicate_bodies_both_get_entries_and_resolve_their_own_map(self, tmp_path, monkeypatch):
        """Two origins serving the SAME bundle with a relative sourceMappingURL. The old code content-deduped
        the second body away, leaving it with no artifact and no entry — so only one origin's map was ever
        discovered, and the duplicate was re-fetched on every resume."""
        urls = ["https://a.ex.com/app.js", "https://b.ex.com/app.js"]
        ctx = _Ctx(tmp_path, urls)
        shared = b"//# sourceMappingURL=app.js.map\n" + b"y" * 200

        class _F:
            def __init__(self):
                self.calls = []

            def __call__(self, c, url, **k):
                self.calls.append(url)
                if url.endswith(".map"):
                    return _map_body(), url, 200
                return shared, url, 200                       # byte-identical for BOTH origins
        f = _F()
        _run_crawl_js(tmp_path, monkeypatch, ctx, f)
        led, raw_dir = crawl._js_download(ctx)
        assert len(list(raw_dir.glob("*.js"))) == 1            # one artifact (content-addressed)
        assert led.has(urls[0]) and led.has(urls[1])           # ...but BOTH urls recorded
        assert led.artifact(urls[0]) == led.artifact(urls[1])  # ...pointing at the shared file

        f.calls.clear()
        crawl._sourcemap_recover(ctx, led)
        assert sorted(f.calls) == ["https://a.ex.com/app.js.map",
                                   "https://b.ex.com/app.js.map"]   # BOTH origins' maps resolved

        ctx2 = _Ctx(tmp_path, urls)                            # and neither url is re-fetched on resume
        f2 = _F()
        _run_crawl_js(tmp_path, monkeypatch, ctx2, f2)
        crawl._js_download(ctx2)
        assert f2.calls == []

    # ── review#4: the ledger verifies the artifact the caller actually uses ───────────────────────────
    def test_entry_bound_to_another_items_artifact_is_still_verified(self, tmp_path):
        """A state entry can name any artifact. What must never happen is trusting the entry while the file
        the caller reads goes unverified — so `artifact()` IS the caller's path, and it is digest-checked."""
        a = tmp_path / "f" / "a.js"
        a.parent.mkdir(parents=True)
        a.write_text("A")
        led = budget.Ledger(tmp_path / "s.json", lane="l")
        led.record("url_b", a)                                 # B legitimately bound to A's file (dedup)
        led.save()
        again = budget.Ledger(tmp_path / "s.json", lane="l")
        assert again.artifact("url_b") == a                    # one lookup, and it IS the verified file
        a.write_text("MUTATED")
        assert not budget.Ledger(tmp_path / "s.json", lane="l").has("url_b")   # mutation invalidates B too

    def test_symlink_escape_is_rejected(self, tmp_path):
        outside = tmp_path / "outside.js"
        outside.write_text("secret")
        base = tmp_path / "lane"
        base.mkdir()
        link = base / "link.js"
        link.symlink_to(outside)
        led = budget.Ledger(base / "s.json", lane="l")
        led.record("u", link)
        led.save()
        # a lexical `..` check cannot see through a symlink; resolved containment can
        assert not budget.Ledger(base / "s.json", lane="l").has("u")

    # ── review#5: fairness over PENDING work only ────────────────────────────────────────────────────
    def test_resume_fairness_ignores_completed_history(self, tmp_path, monkeypatch):
        """A host with a long completed history must not push its NEW remainder behind other hosts. Ordering
        the whole eligible set interleaved its done items through the sequence, so a bounded run could be
        consumed before reaching the part that still needed fetching."""
        old = _urls({"big.ex.com": 40})
        ctx = _Ctx(tmp_path, old)
        _run_crawl_js(tmp_path, monkeypatch, ctx, _Fetcher())
        crawl._js_download(ctx)                                # 40 completions for big.ex.com

        grown = old + ["https://big.ex.com/new.js"] + _urls({"other.ex.com": 5})
        ctx2 = _Ctx(tmp_path, grown)
        f2 = _Fetcher()
        _run_crawl_js(tmp_path, monkeypatch, ctx2, f2)
        crawl._js_download(ctx2)
        # only the 6 pending items ran, and big's single new URL is in the FIRST pair — not behind other.'s 5
        assert len(f2.calls) == 6
        assert "https://big.ex.com/new.js" in f2.calls[:2]

    def test_resumed_items_are_counted_in_coverage(self, tmp_path, monkeypatch):
        ctx = _Ctx(tmp_path, _urls({"a.ex.com": 3}))
        _run_crawl_js(tmp_path, monkeypatch, ctx, _Fetcher())
        crawl._js_download(ctx)
        ctx2 = _Ctx(tmp_path, _urls({"a.ex.com": 3}))
        _run_crawl_js(tmp_path, monkeypatch, ctx2, _Fetcher())
        crawl._js_download(ctx2)
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        sel = [e for e in ev if e.get("measure") == "js_urls"][-1]
        out = [e for e in ev if e.get("measure") == "js_fetched"][-1]
        assert sel["tested"] == 3 and sel["omitted"] == 0      # a resumed run still reports FULL coverage
        assert out["tested"] == 3 and out["omitted"] == 0
        assert any("resumed" in m for m in ctx2.echoed)

    # ── review#6: a 200 is not a sourcemap ───────────────────────────────────────────────────────────
    def test_unparseable_map_is_not_reported_as_recovered(self, tmp_path, monkeypatch):
        """A WAF HTML page served with 200 used to count as fully obtained, so the verdict could report
        complete sourcemap coverage having recovered nothing."""
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 3},
                               body=b"<html>Access Denied</html>")
        recov = crawl._sourcemap_recover(ctx, led)
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        fetched = [e for e in ev if e.get("measure") == "sourcemaps_fetched"][-1]
        rec = [e for e in ev if e.get("measure") == "sourcemaps_valid"][-1]
        assert fetched["omitted"] == 0                         # the fetch genuinely succeeded...
        assert rec["eligible"] == 3 and rec["tested"] == 0
        assert rec["omitted"] == 3 and "not_json" in rec["reason"]      # ...but nothing was usable
        assert [p for p in recov.rglob("*") if p.is_file()] == []

    def test_valid_map_without_sources_content_is_not_a_gap(self, tmp_path, monkeypatch):
        """review#4: `sourcesContent` is OPTIONAL in a valid source map. Treating its absence as failed
        recovery would mark most production maps degraded. Validity is the measure; recovered-source count is
        output, reported on the ledger event."""
        t = TestSourcemapLane()
        body = json.dumps({"version": 3, "sources": ["a.ts"], "sourcesContent": [None]}).encode()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 2}, body=body)
        crawl._sourcemap_recover(ctx, led)
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        val = [e for e in ev if e.get("measure") == "sourcemaps_valid"][-1]
        assert val["omitted"] == 0 and val["tested"] == 2       # valid maps, no gap
        led_ev = [e for e in ev if e.get("event") == "ledger"][-1]
        assert led_ev["produced"]["recovered_sources"] == 0     # ...and zero recovered is OUTPUT, not a gap

    def test_a_map_with_no_sources_content_key_at_all_is_valid(self, tmp_path, monkeypatch):
        t = TestSourcemapLane()
        body = json.dumps({"version": 3, "sources": ["a.ts"], "mappings": ";;"}).encode()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 1}, body=body)
        crawl._sourcemap_recover(ctx, led)
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        val = [e for e in ev if e.get("measure") == "sourcemaps_valid"][-1]
        assert val["omitted"] == 0


class TestTemplateDefectsRound2:
    """Second review round on the same two lanes. Same pattern as round 1: every one of these passed the
    then-current tests, because none of them was exercised."""

    # ── review#1: only VALIDATED evidence may reach a scanner ─────────────────────────────────────────
    def test_a_rejected_orphan_never_reaches_the_miners(self, tmp_path, monkeypatch):
        """The ledger correctly rejects a tampered artifact — but the derived tree was mirrored from
        `raw_dir/*.js` wholesale, so the rejected file still went to gitleaks and xnLinkFinder."""
        ctx = _Ctx(tmp_path, _urls({"a.ex.com": 3}))
        _run_crawl_js(tmp_path, monkeypatch, ctx, _Fetcher())
        led, raw_dir = crawl._js_download(ctx)
        victim = sorted(raw_dir.glob("*.js"))[0]
        victim.write_text("TAMPERED")                          # content no longer matches its own name

        ctx2 = _Ctx(tmp_path, _urls({"a.ex.com": 3}))
        f2 = _Fetcher()
        _run_crawl_js(tmp_path, monkeypatch, ctx2, f2)
        led2, raw2 = crawl._js_download(ctx2)
        pub = crawl._js_publish_derived(ctx2, led2, raw2)
        derived = sorted(pub.glob("*.js"))
        assert all("TAMPERED" not in d.read_text() for d in derived)
        assert {d.name for d in derived} == {a.name for a in led2.artifacts()}   # tree == evidence, exactly

    def test_recovered_subdir_is_rebuilt_when_a_map_changes(self, tmp_path, monkeypatch):
        """A map whose cached body is invalidated gets re-fetched — and `recovered/` was append-only, so the
        PREVIOUS extraction stayed on disk as live scanner input alongside the new one."""
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 1},
                               body=_map_body("old.ts", "OLD CONTENT"))
        recov = crawl._sourcemap_recover(ctx, led)
        assert any("OLD CONTENT" in p.read_text() for p in recov.rglob("*") if p.is_file())

        # invalidate the cached .map so the lane must re-fetch it, and serve different content this time
        for cached in (tmp_path / "raw" / "crawl" / "sourcemaps" / "fetched").glob("*.map"):
            cached.write_text("tampered")
        ctx2, led2, f2 = t._setup(tmp_path, monkeypatch, {"a.ex.com": 1},
                                  body=_map_body("new.ts", "NEW CONTENT"))
        recov2 = crawl._sourcemap_recover(ctx2, led2)
        texts = [p.read_text() for p in recov2.rglob("*") if p.is_file()]
        assert any("NEW CONTENT" in x for x in texts)
        assert not any("OLD CONTENT" in x for x in texts)       # the stale generation is gone

    def test_recovered_subdir_is_pruned_when_its_source_js_is_invalidated(self, tmp_path, monkeypatch):
        """When the JS artifact that referenced a map stops validating, that map is no longer a candidate —
        and its previously extracted sources must not stay behind as live scanner input."""
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 1},
                               body=_map_body("gone.ts", "ORPHANED"))
        recov = crawl._sourcemap_recover(ctx, led)
        assert any("ORPHANED" in p.read_text() for p in recov.rglob("*") if p.is_file())

        # tamper the JS artifact -> its ledger entry is rejected -> its map drops out of the candidate set
        raw_dir = tmp_path / "raw" / "crawl" / "js_files"
        for j in raw_dir.glob("*.js"):
            j.write_text("TAMPERED")
        ctx2 = _Ctx(tmp_path, [])                              # nothing eligible this run
        _run_crawl_js(tmp_path, monkeypatch, ctx2, _Fetcher())
        led2, _raw = crawl._js_download(ctx2)
        assert list(led2.items()) == []                        # the tampered entry is gone
        recov2 = crawl._sourcemap_recover(ctx2, led2)
        assert not any("ORPHANED" in p.read_text() for p in recov2.rglob("*") if p.is_file())

    # ── review#2: content-addressed publishing must be atomic ────────────────────────────────────────
    def test_a_truncated_artifact_at_the_final_name_is_replaced(self, tmp_path):
        """`if not dest.exists(): write_bytes()` reused whatever sat at the content-addressed name. A kill
        mid-write left truncated bytes there, and the lane then recorded the digest it INTENDED to write."""
        import hashlib as _h
        data = b"the full body" * 50
        dig = _h.sha256(data).hexdigest()
        dest = tmp_path / f"{dig}.js"
        dest.write_bytes(data[:10])                            # a truncated leftover
        assert budget.publish_bytes(dest, data, digest=dig)
        assert dest.read_bytes() == data                       # replaced, not reused

    def test_publish_reuses_a_verified_destination(self, tmp_path):
        import hashlib as _h
        data = b"body"
        dig = _h.sha256(data).hexdigest()
        dest = tmp_path / f"{dig}.js"
        dest.write_bytes(data)
        mtime = dest.stat().st_mtime_ns
        assert budget.publish_bytes(dest, data, digest=dig)
        assert dest.stat().st_mtime_ns == mtime                 # already correct -> untouched

    def test_publish_leaves_nothing_behind_when_the_write_is_corrupted(self, tmp_path, monkeypatch):
        import hashlib as _h
        data = b"body" * 10
        dig = _h.sha256(data).hexdigest()
        dest = tmp_path / f"{dig}.js"
        real = pathlib_write = type(dest).write_bytes

        def short_write(self, b):                              # simulate a partial write
            return real(self, b[:3])
        monkeypatch.setattr(type(dest), "write_bytes", short_write)
        assert budget.publish_bytes(dest, data, digest=dig) is False
        monkeypatch.setattr(type(dest), "write_bytes", real)
        assert not dest.exists()                               # no half-file published
        assert list(tmp_path.glob("*.part-*")) == []           # and no temp left over

    def test_a_failed_publish_is_never_recorded(self, tmp_path, monkeypatch):
        ctx = _Ctx(tmp_path, _urls({"a.ex.com": 2}))
        f = _Fetcher()
        _run_crawl_js(tmp_path, monkeypatch, ctx, f)
        monkeypatch.setattr(crawl.budget, "publish_bytes", lambda *a, **k: False)
        led, raw_dir = crawl._js_download(ctx)
        assert list(led.items()) == []                          # nothing claimed
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        out = [e for e in ev if e.get("measure") == "js_fetched"][-1]
        assert out["omitted"] == 2 and "write_failed" in out["reason"]

    def test_full_sha256_is_used_in_the_artifact_name(self, tmp_path, monkeypatch):
        ctx = _Ctx(tmp_path, _urls({"a.ex.com": 1}))
        _run_crawl_js(tmp_path, monkeypatch, ctx, _Fetcher())
        led, raw_dir = crawl._js_download(ctx)
        art = list(led.artifacts())[0]
        assert len(art.stem) == 64                              # not a 64-bit prefix

    # ── review#3: a hostile sourcemap shape must degrade ONE map, never the phase ─────────────────────
    @pytest.mark.parametrize("obj,cls", [
        ({"version": 3, "sources": 5, "sourcesContent": ["x"]}, "invalid_schema"),
        ({"version": 3, "sources": ["a"], "sourcesContent": "notalist"}, "invalid_schema"),
        ({"version": 3, "sources": ["a"], "sourcesContent": {"a": "b"}}, "invalid_schema"),
        ({"version": 3, "sources": [1, 2], "sourcesContent": [3, 4]}, "invalid_schema"),
        ({"version": 3, "sources": ["a"], "sourcesContent": [{"nested": 1}]}, "invalid_schema"),
        ({}, "invalid_schema"),                                  # review#2: an empty object is NOT a map
        ({"message": "not found"}, "invalid_schema"),             # ...nor is a JSON error body
        ({"version": 2, "sources": ["a"], "sourcesContent": ["x"]}, "invalid_schema"),   # wrong revision
        ({"version": 3, "sections": [{"offset": {}, "map": {}}]}, "index_map_unsupported"),
        ([1, 2, 3], "invalid_schema"),                           # not even an object
    ])
    def test_hostile_schema_is_attributed_not_merely_survived(self, tmp_path, monkeypatch, obj, cls):
        """review#3 (r2): must not abort the phase. review#2 (r3): and must be ATTRIBUTED — the earlier
        version of this test only asserted 'did not crash', which let fail-open schema checks pass while
        counting garbage as valid maps."""
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 2},
                               body=json.dumps(obj).encode())
        crawl._sourcemap_recover(ctx, led)                      # must NOT raise
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        measures = {e.get("measure") for e in ev if e.get("event") == "coverage_partial"}
        # all observations still emitted — aborting used to discard them along with valid siblings
        assert {"sourcemaps", "sourcemaps_fetched", "sourcemaps_valid",
                "sourcemaps_extracted"} <= measures
        val = [e for e in ev if e.get("measure") == "sourcemaps_valid"][-1]
        assert val["tested"] == 0 and val["omitted"] == 2        # counted as NOT valid
        assert cls in val["reason"]

    def test_one_bad_map_does_not_discard_its_valid_siblings(self, tmp_path, monkeypatch):
        """The abort happened mid-loop, so every map after the bad one was lost too."""
        good = _map_body("keep.ts", "KEEP ME")
        bad = json.dumps({"version": 3, "sources": 5, "sourcesContent": 7}).encode()
        ctx = _Ctx(tmp_path, _urls({"a.ex.com": 1, "b.ex.com": 1}))

        class _F:
            def __init__(self):
                self.calls = []

            def __call__(self, c, url, **k):
                self.calls.append(url)
                if url.endswith(".map"):
                    return (bad if "a.ex.com" in url else good), url, 200
                name = url.rsplit("/", 1)[1]
                return f"//# sourceMappingURL={name}.map\n".encode() + b"y" * 200 + url.encode(), url, 200
        f = _F()
        _run_crawl_js(tmp_path, monkeypatch, ctx, f)
        led, _raw = crawl._js_download(ctx)
        recov = crawl._sourcemap_recover(ctx, led)
        assert any("KEEP ME" in p.read_text() for p in recov.rglob("*") if p.is_file())
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        val = [e for e in ev if e.get("measure") == "sourcemaps_valid"][-1]
        assert val["tested"] == 1 and val["omitted"] == 1 and "invalid_schema" in val["reason"]

    # ── review#6: inline data: maps must appear in coverage ──────────────────────────────────────────
    def test_undecodable_inline_map_is_counted(self, tmp_path, monkeypatch):
        ctx = _Ctx(tmp_path, ["https://a.ex.com/app.js"])

        class _F:
            def __call__(self, c, url, **k):
                if url.endswith(".map"):
                    return None, url, 0                        # no separate .map
                return (b"//# sourceMappingURL=data:application/json;base64,!!!not-base64!!!\n"
                        + b"z" * 200), url, 200
        _run_crawl_js(tmp_path, monkeypatch, ctx, _F())
        led, _raw = crawl._js_download(ctx)
        crawl._sourcemap_recover(ctx, led)
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        val = [e for e in ev if e.get("measure") == "sourcemaps_valid"][-1]
        assert val["omitted"] >= 1 and "decode_error" in val["reason"]
        led_ev = [e for e in ev if e.get("event") == "ledger"][-1]
        assert led_ev["consumed"]["inline_candidates"] == 1     # the candidate itself is on the record


class TestTemplateDefectsRound3:
    """Third review round. Same lesson each time: a test that asserts the happy path proves nothing about
    the failure path, and a fix for one defect creates the conditions for the next."""

    # ── review#1: active trees published safely ───────────────────────────────────────────────────────
    def test_recovered_tree_is_swapped_not_edited_in_place(self, tmp_path, monkeypatch):
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 1},
                               body=_map_body("keep.ts", "KEPT"))
        recov = crawl._sourcemap_recover(ctx, led)
        (recov / "stray.txt").write_text("not from this generation")
        (recov / "junkdir").mkdir()
        (recov / "junkdir" / "x.js").write_text("also stale")
        recov2 = crawl._sourcemap_recover(ctx, led)
        names = {p.name for p in recov2.rglob("*") if p.is_file()}
        assert "stray.txt" not in names and "x.js" not in names   # a whole-tree swap cannot leave these
        assert any("KEPT" in p.read_text() for p in recov2.rglob("*") if p.is_file())
        assert not list(recov2.parent.glob("recovered.gen-*"))    # staging is consumed
        assert not list(recov2.parent.glob("recovered.retired-*"))

    # ── review#3: extraction failure must not read as clean ──────────────────────────────────────────
    def test_extraction_failure_is_a_gap_not_a_clean_valid_count(self, tmp_path, monkeypatch):
        """valid_maps was incremented BEFORE extraction, so a write blowing up left obtained == attempted:
        report_outcome saw a clean result and dropped extract_error from the reason entirely."""
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 2},
                               body=_map_body("a.ts", "CONTENT"))
        real_write = pathlib.Path.write_text

        def boom(self, *a, **k):
            if self.suffix in (".ts", ".js") and "recovered" in str(self):
                raise OSError("no space left on device")
            return real_write(self, *a, **k)
        monkeypatch.setattr(pathlib.Path, "write_text", boom)
        crawl._sourcemap_recover(ctx, led)
        monkeypatch.setattr(pathlib.Path, "write_text", real_write)
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        val = [e for e in ev if e.get("measure") == "sourcemaps_valid"][-1]
        ext = [e for e in ev if e.get("measure") == "sourcemaps_extracted"][-1]
        assert val["omitted"] == 0                               # the maps really were valid...
        assert ext["omitted"] == 2 and "extract_error" in ext["reason"]   # ...but extraction FAILED, visibly

    def test_a_valid_map_without_content_is_absent_from_the_extraction_denominator(self, tmp_path, monkeypatch):
        t = TestSourcemapLane()
        body = json.dumps({"version": 3, "sources": ["a.ts"], "sourcesContent": [None]}).encode()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 2}, body=body)
        crawl._sourcemap_recover(ctx, led)
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        ext = [e for e in ev if e.get("measure") == "sourcemaps_extracted"][-1]
        assert ext["eligible"] == 0 and ext["omitted"] == 0      # nothing to extract is not a failure

    # ── review#4: journal identity + tail repair ─────────────────────────────────────────────────────
    def test_an_uncompacted_journal_is_not_readable_by_another_lane(self, tmp_path):
        art = tmp_path / "f" / "a.js"
        art.parent.mkdir(parents=True)
        art.write_text("x")
        a = budget.Ledger(tmp_path / "s.json", lane="crawl.js_fetch")
        a.record("u", art)                                       # journal only — never compacted
        assert not (tmp_path / "s.json").exists()
        b = budget.Ledger(tmp_path / "s.json", lane="crawl.sourcemaps")
        assert not b.has("u")                                    # the snapshot guard alone missed this

    def test_a_torn_tail_is_repaired_before_the_next_append(self, tmp_path):
        """After a torn line the next append concatenated onto the fragment, so a second interruption cost
        the FIRST new completion as well — one bad write took out two records."""
        art = tmp_path / "f" / "a.js"
        art.parent.mkdir(parents=True)
        art.write_text("x")
        led = budget.Ledger(tmp_path / "s.json", lane="l")
        led.record("u1", art)
        with led.journal.open("a") as fh:
            fh.write('{"v": 1, "l": "l", "i": "u2"')             # killed mid-append
        reopened = budget.Ledger(tmp_path / "s.json", lane="l")  # load repairs the tail
        assert reopened.has("u1") and not reopened.has("u2")
        reopened.record("u3", art)                               # the append lands on clean ground
        final = budget.Ledger(tmp_path / "s.json", lane="l")
        assert final.has("u1") and final.has("u3")               # u3 is NOT eaten by the fragment

    # ── review#5: payload identity ───────────────────────────────────────────────────────────────────
    def test_two_inline_maps_in_one_file_do_not_overwrite_each_other(self, tmp_path, monkeypatch):
        """Both inline maps share the JS URL as their label, so a label-keyed subdir meant extracting the
        second DELETED the first's recovered sources — while both counted as recovered."""
        import base64 as _b64
        m1 = _b64.b64encode(_map_body("first.ts", "FIRST SECRET")).decode()
        m2 = _b64.b64encode(_map_body("second.ts", "SECOND SECRET")).decode()
        ctx = _Ctx(tmp_path, ["https://a.ex.com/app.js"])

        class _F:
            def __call__(self, c, url, **k):
                if url.endswith(".map"):
                    return None, url, 404
                return (f"//# sourceMappingURL=data:application/json;base64,{m1}\n"
                        f"//# sourceMappingURL=data:application/json;base64,{m2}\n").encode() + b"z" * 200, url, 200
        _run_crawl_js(tmp_path, monkeypatch, ctx, _F())
        led, _raw = crawl._js_download(ctx)
        recov = crawl._sourcemap_recover(ctx, led)
        texts = [p.read_text() for p in recov.rglob("*") if p.is_file()]
        assert any("FIRST SECRET" in x for x in texts)
        assert any("SECOND SECRET" in x for x in texts)          # BOTH survive
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        ext = [e for e in ev if e.get("measure") == "sourcemaps_extracted"][-1]
        assert ext["eligible"] == 2 and ext["omitted"] == 0

    def test_payload_identity_uses_full_digest_width(self, tmp_path):
        a = crawl._payload_key("https://h/app.js", 0, b"body")
        b = crawl._payload_key("https://h/app.js", 1, b"body")   # same label, different ref index
        c = crawl._payload_key("https://h/app.js", 0, b"other")  # same label+index, different payload
        assert len({a, b, c}) == 3 and len(a) == 64
        # domain-separated: no concatenation ambiguity between the parts
        assert crawl._payload_key("ab", 0, b"c") != crawl._payload_key("a", 0, b"bc")


class TestTemplateDefectsRound4:
    """Fourth round: publication failure and durable-state recovery. Both classes can destroy evidence or
    manufacture clean coverage, so each gets a failure-path test rather than a happy-path one."""

    # ── review#1: a failed swap must never destroy the last good generation ──────────────────────────
    def test_publish_success_consumes_staging_and_retired(self, tmp_path):
        active = tmp_path / "recovered"
        active.mkdir(); (active / "old.js").write_text("OLD")
        staging = tmp_path / "recovered.gen-1"
        staging.mkdir(); (staging / "new.js").write_text("NEW")
        ctx = _Ctx(tmp_path, [])
        assert crawl._publish_tree(ctx, active, staging) is True
        assert (active / "new.js").read_text() == "NEW" and not (active / "old.js").exists()
        assert not staging.exists() and not list(tmp_path.glob("recovered.retired-*"))

    def test_failure_moving_active_aside_keeps_the_old_tree(self, tmp_path, monkeypatch):
        active = tmp_path / "recovered"
        active.mkdir(); (active / "keep.js").write_text("KEEP")
        staging = tmp_path / "recovered.gen-1"
        staging.mkdir(); (staging / "new.js").write_text("NEW")
        ctx = _Ctx(tmp_path, [])
        monkeypatch.setattr(crawl.os, "replace", lambda *a: (_ for _ in ()).throw(OSError("boom")))
        assert crawl._publish_tree(ctx, active, staging) is False
        assert (active / "keep.js").read_text() == "KEEP"          # untouched
        assert not staging.exists()

    def test_failure_publishing_staging_rolls_back(self, tmp_path, monkeypatch):
        active = tmp_path / "recovered"
        active.mkdir(); (active / "keep.js").write_text("KEEP")
        staging = tmp_path / "recovered.gen-1"
        staging.mkdir(); (staging / "new.js").write_text("NEW")
        ctx = _Ctx(tmp_path, [])
        real = crawl.os.replace
        n = [0]

        def one_shot(src, dst):                                    # aside succeeds, publish fails
            n[0] += 1
            if n[0] == 2:
                raise OSError("cannot publish")
            return real(src, dst)
        monkeypatch.setattr(crawl.os, "replace", one_shot)
        assert crawl._publish_tree(ctx, active, staging) is False
        monkeypatch.setattr(crawl.os, "replace", real)
        assert (active / "keep.js").read_text() == "KEEP"          # rolled back
        assert not list(tmp_path.glob("recovered.retired-*"))

    def test_failed_rollback_preserves_the_retired_generation(self, tmp_path, monkeypatch):
        """THE data-loss bug: aside OK, publish fails, rollback fails — and a `finally` deleted the retired
        copy anyway, leaving no tree at all. It must survive on disk for the operator."""
        active = tmp_path / "recovered"
        active.mkdir(); (active / "precious.js").write_text("EVIDENCE")
        staging = tmp_path / "recovered.gen-1"
        staging.mkdir(); (staging / "new.js").write_text("NEW")
        ctx = _Ctx(tmp_path, [])
        real = crawl.os.replace
        n = [0]

        def aside_then_fail(src, dst):
            n[0] += 1
            if n[0] == 1:
                return real(src, dst)                              # move aside succeeds
            raise OSError("disk gone")                             # publish AND rollback fail
        monkeypatch.setattr(crawl.os, "replace", aside_then_fail)
        assert crawl._publish_tree(ctx, active, staging) is False
        monkeypatch.setattr(crawl.os, "replace", real)
        retired = list(tmp_path.glob("recovered.retired-*"))
        assert len(retired) == 1
        assert (retired[0] / "precious.js").read_text() == "EVIDENCE"   # NOT deleted
        assert any("left at" in m for m in ctx.echoed)

    def test_failed_publication_is_reported_as_a_gap(self, tmp_path, monkeypatch):
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 1},
                               body=_map_body("a.ts", "CONTENT"))
        monkeypatch.setattr(crawl, "_publish_tree", lambda c, a, s: False)
        crawl._sourcemap_recover(ctx, led)
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        pub = [e for e in ev if e.get("measure") == "sourcemaps_published"][-1]
        assert pub["eligible"] == 1 and pub["tested"] == 0 and pub["omitted"] == 1
        assert "could NOT be published" in pub["reason"]

    # ── review#2: prune failures must not read clean ─────────────────────────────────────────────────
    # ── review#3: schema gate ───────────────────────────────────────────────────────────────────────
    @pytest.mark.parametrize("obj", [
        {"version": 3},                                            # no `sources` at all
        {"version": 3, "message": "not found"},                    # a JSON error body with a version field
        {"version": 3.0, "sources": ["a"], "sourcesContent": ["x"]},   # 3.0 == 3 is True in Python
        {"version": True, "sources": ["a"], "sourcesContent": ["x"]},  # bool is an int subclass
        {"version": 3, "sources": "a.ts", "sourcesContent": ["x"]},    # sources not a list
    ])
    def test_non_maps_are_rejected(self, obj):
        assert crawl._sourcemap_schema(obj) is None

    def test_a_real_map_without_sources_content_is_still_valid(self):
        assert crawl._sourcemap_schema({"version": 3, "sources": ["a.ts"], "mappings": ";;"}) == (["a.ts"], [])

    # ── review#4: journal must never destroy the rightful lane's records ────────────────────────────
    def test_opening_a_journal_as_the_wrong_lane_does_not_destroy_it(self, tmp_path):
        """The repair dropped foreign-lane lines from `kept` and then rewrote the file without them, so lane B
        merely OPENING lane A's uncompacted journal DELETED A's completions."""
        art = tmp_path / "f" / "a.js"
        art.parent.mkdir(parents=True)
        art.write_text("x")
        a = budget.Ledger(tmp_path / "s.json", lane="lane.a")
        a.record("u1", art)
        a.record("u2", art)                                        # journal only, never compacted
        b = budget.Ledger(tmp_path / "s.json", lane="lane.b")      # the wrong lane opens it
        assert not b.has("u1")
        a2 = budget.Ledger(tmp_path / "s.json", lane="lane.a")     # ...and A's records are intact
        assert a2.has("u1") and a2.has("u2")

    def test_the_wrong_lane_cannot_append_to_a_foreign_journal(self, tmp_path):
        art = tmp_path / "f" / "a.js"
        art.parent.mkdir(parents=True)
        art.write_text("x")
        a = budget.Ledger(tmp_path / "s.json", lane="lane.a")
        a.record("u1", art)
        before = a.journal.read_text()
        b = budget.Ledger(tmp_path / "s.json", lane="lane.b")
        b.record("other", art)                                     # must not touch A's journal
        assert a.journal.read_text() == before
        assert budget.Ledger(tmp_path / "s.json", lane="lane.a").has("u1")

    def test_an_unrepairable_journal_stops_journalling_but_keeps_state(self, tmp_path, monkeypatch):
        """If the tail repair itself fails, appending would land on the fragment. Journalling stops; save()
        still compacts the in-memory state, so completions are not lost."""
        art = tmp_path / "f" / "a.js"
        art.parent.mkdir(parents=True)
        art.write_text("x")
        led = budget.Ledger(tmp_path / "s.json", lane="l")
        led.record("u1", art)
        with led.journal.open("a") as fh:
            fh.write('{"v": 1, "l": "l", "i": "torn"')
        real = budget.os.replace
        monkeypatch.setattr(budget.os, "replace",
                            lambda s, d: (_ for _ in ()).throw(OSError("ro fs"))
                            if str(s).endswith(".repair") else real(s, d))
        led2 = budget.Ledger(tmp_path / "s.json", lane="l")
        assert led2.has("u1")
        led2.record("u2", art)                                     # not journalled...
        led2.save()                                                # ...but compacted
        monkeypatch.setattr(budget.os, "replace", real)
        final = budget.Ledger(tmp_path / "s.json", lane="l")
        assert final.has("u1") and final.has("u2")

    # ── review#5: recovered count must not overstate ────────────────────────────────────────────────
    def test_recovered_count_excludes_a_rolled_back_payload(self, tmp_path, monkeypatch):
        """The counter incremented per file, but a later error deleted the whole payload directory without
        rolling those increments back."""
        t = TestSourcemapLane()
        body = json.dumps({"version": 3, "sources": ["a.ts", "b.ts", "c.ts"],
                           "sourcesContent": ["A", "B", "C"]}).encode()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 1}, body=body)
        real_write = pathlib.Path.write_text
        n = [0]

        def fail_on_third(self, *a, **k):
            if "recovered" in str(self) and self.suffix == ".ts":
                n[0] += 1
                if n[0] == 3:
                    raise OSError("no space left")
            return real_write(self, *a, **k)
        monkeypatch.setattr(pathlib.Path, "write_text", fail_on_third)
        crawl._sourcemap_recover(ctx, led)
        monkeypatch.setattr(pathlib.Path, "write_text", real_write)
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        led_ev = [e for e in ev if e.get("event") == "ledger"][-1]
        assert led_ev["produced"]["recovered_sources"] == 0        # the 2 written before the failure are gone
        ext = [e for e in ev if e.get("measure") == "sourcemaps_extracted"][-1]
        assert ext["omitted"] == 1


class TestTemplateDefectsRound5:
    """Fifth round. Three of these are about the same thing from different angles: a tree that could not be
    published exactly must not be mined, must not be counted clean, and must not be inherited."""

    # ── review#1: an unpublishable recovered tree is not mineable ────────────────────────────────────
    def test_failed_publication_yields_no_mineable_directory(self, tmp_path, monkeypatch):
        """The lane returned `recov_dir` regardless, so after a rollback jsluice / xnLinkFinder / gitleaks /
        trufflehog mined the PREVIOUS generation as if it were this run's output."""
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 1},
                               body=_map_body("a.ts", "CONTENT"))
        monkeypatch.setattr(crawl, "_publish_tree", lambda c, a, s: False)
        assert crawl._sourcemap_recover(ctx, led) is None

    def test_an_empty_generation_that_fails_to_publish_is_still_a_gap(self, tmp_path, monkeypatch):
        """Sizing publication by subdir count meant an EMPTY generation reported eligible=0/omitted=0 — no gap
        whatsoever — while the stale tree stayed on disk."""
        ctx = _Ctx(tmp_path, [])
        _run_crawl_js(tmp_path, monkeypatch, ctx, _Fetcher())
        led, _raw = crawl._js_download(ctx)
        monkeypatch.setattr(crawl, "_publish_tree", lambda c, a, s: False)
        assert crawl._sourcemap_recover(ctx, led) is None
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        pub = [e for e in ev if e.get("measure") == "sourcemaps_published"][-1]
        assert (pub["eligible"], pub["tested"], pub["omitted"]) == (1, 0, 1)

    def test_a_failed_publication_emits_a_ZEROED_ledger_not_no_ledger(self, tmp_path, monkeypatch):
        """review#4 (r6): the earlier version of this test asserted NO ledger on failure, which locked in a
        stale-value bug — views._fold_events carries the latest ledger forward, so emitting none left the
        PREVIOUS generation's recovered_sources on display as current. A current, zeroed ledger is required."""
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 1},
                               body=_map_body("a.ts", "CONTENT"))
        monkeypatch.setattr(crawl, "_publish_tree", lambda c, a, s: False)
        crawl._sourcemap_recover(ctx, led)
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        sm = [e for e in ev if e.get("event") == "ledger" and e.get("source_id") == "crawl.sourcemaps"]
        assert len(sm) == 1
        assert sm[-1]["produced"] == {"recovered_sources": 0, "valid_maps": 0, "published": 0}
        assert sm[-1]["consumed"]["payloads"] >= 1               # consumed counters stay truthful

    # ── review#2: the JS derived tree is exact by construction ──────────────────────────────────────
    def test_a_staging_failure_leaves_nothing_mineable(self, tmp_path, monkeypatch):
        """Four rounds of keeping an in-place tree correct kept leaving one more way for an unverified file to
        stay live. Staged construction means an incomplete generation is simply never published."""
        ctx = _Ctx(tmp_path, _urls({"a.ex.com": 3}))
        _run_crawl_js(tmp_path, monkeypatch, ctx, _Fetcher())
        led, raw_dir = crawl._js_download(ctx)
        real = pathlib.Path.write_bytes
        n = [0]

        def fail_third(self, b):
            if self.parent.name.startswith("js_derived.gen-"):
                n[0] += 1
                if n[0] == 3:
                    raise OSError("no space left")
            return real(self, b)
        monkeypatch.setattr(pathlib.Path, "write_bytes", fail_third)
        assert crawl._js_publish_derived(ctx, led, raw_dir) is None
        monkeypatch.setattr(pathlib.Path, "write_bytes", real)
        assert not (raw_dir.parent / "js_derived").exists()      # nothing half-built became mineable
        assert not list(raw_dir.parent.glob("js_derived.gen-*"))  # staging cleaned up
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        mine = [e for e in ev if e.get("measure") == "js_mineable"][-1]
        assert mine["tested"] == 0 and mine["omitted"] == 3      # NONE of it is available, reported as such

    def test_tool_temp_files_never_ship_in_the_published_tree(self, tmp_path, monkeypatch):
        ctx = _Ctx(tmp_path, _urls({"a.ex.com": 2}))
        _run_crawl_js(tmp_path, monkeypatch, ctx, _Fetcher())
        led, raw_dir = crawl._js_download(ctx)
        real = crawl._beautify_run

        def leave_temps(c, files):
            for f in files:                                      # js-beautify leaves .beauty on degradation
                f.with_suffix(f.suffix + ".beauty").write_text("leftover")
            return (0, len(files), crawl.Status.PARTIAL)
        monkeypatch.setattr(crawl, "_beautify_run", leave_temps)
        monkeypatch.setattr(crawl, "have", lambda t: t == "js-beautify")
        pub = crawl._js_publish_derived(ctx, led, raw_dir)
        assert pub is not None
        assert {p.suffix for p in pub.rglob("*") if p.is_file()} == {".js"}

    def test_published_tree_holds_exactly_the_validated_artifacts(self, tmp_path, monkeypatch):
        ctx = _Ctx(tmp_path, _urls({"a.ex.com": 2, "b.ex.com": 1}))
        _run_crawl_js(tmp_path, monkeypatch, ctx, _Fetcher())
        led, raw_dir = crawl._js_download(ctx)
        pub = crawl._js_publish_derived(ctx, led, raw_dir)
        assert {p.name for p in pub.glob("*.js")} == {a.name for a in led.artifacts()}
        assert [p for p in pub.rglob("*") if p.is_dir()] == []   # flat: no nested junk possible

    # ── review#3: ledger ownership vs a damaged journal ─────────────────────────────────────────────
    def test_saving_over_a_foreign_compacted_snapshot_is_refused(self, tmp_path):
        """Reproduced: opening a compacted lane-A snapshot as lane B and calling save() destroyed A."""
        art = tmp_path / "f" / "a.js"
        art.parent.mkdir(parents=True)
        art.write_text("x")
        a = budget.Ledger(tmp_path / "s.json", lane="lane.a")
        a.record("u1", art)
        a.save()
        b = budget.Ledger(tmp_path / "s.json", lane="lane.b")
        b.record("z", art)
        assert b.foreign is True and b.save() is False           # refused, not written
        assert budget.Ledger(tmp_path / "s.json", lane="lane.a").has("u1")

    def test_save_does_not_restore_append_safety_while_the_journal_survives(self, tmp_path, monkeypatch):
        """Reproduced: after a failed repair, save() cleared the flag without removing the torn journal, so the
        next record appended to the fragment and vanished on reopen."""
        art = tmp_path / "f" / "a.js"
        art.parent.mkdir(parents=True)
        art.write_text("x")
        led = budget.Ledger(tmp_path / "s.json", lane="l")
        led.record("u1", art)
        with led.journal.open("a") as fh:
            fh.write('{"v": 1, "l": "l", "i": "torn"')
        real = budget.os.replace

        def block_repair(src, dst):                              # both the repair AND the later unlink fail
            if str(src).endswith(".repair"):
                raise OSError("ro fs")
            return real(src, dst)
        monkeypatch.setattr(budget.os, "replace", block_repair)
        real_unlink = pathlib.Path.unlink
        monkeypatch.setattr(pathlib.Path, "unlink",
                            lambda self, **k: (_ for _ in ()).throw(OSError("ro"))
                            if self.name.endswith(".journal") else real_unlink(self, **k))
        led2 = budget.Ledger(tmp_path / "s.json", lane="l")
        led2.save()
        assert led2._journal_unsafe is True                      # NOT cleared while the fragment survives
        led2.record("u2", art)                                   # so this is not appended onto it
        monkeypatch.setattr(pathlib.Path, "unlink", real_unlink)
        monkeypatch.setattr(budget.os, "replace", real)
        led2.save()
        assert budget.Ledger(tmp_path / "s.json", lane="l").has("u2")

    # ── review#4: recovered-source paths cannot collide ─────────────────────────────────────────────
    def test_sources_that_sanitize_alike_do_not_overwrite_each_other(self, tmp_path, monkeypatch):
        """`../a.js`, `./a.js`, `/a.js`, `webpack:///./a.js` and `a.js` ALL reduce to `a.js`, so later sources
        silently overwrote earlier ones while every one of them was counted as recovered."""
        t = TestSourcemapLane()
        body = json.dumps({"version": 3,
                           "sources": ["../a.js", "a.js", "webpack:///./a.js", "/a.js"],
                           "sourcesContent": ["FIRST", "SECOND", "THIRD", "FOURTH"]}).encode()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 1}, body=body)
        recov = crawl._sourcemap_recover(ctx, led)
        texts = sorted(p.read_text() for p in recov.rglob("*") if p.is_file())
        assert texts == ["FIRST", "FOURTH", "SECOND", "THIRD"]   # all four survive
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        led_ev = [e for e in ev if e.get("event") == "ledger"][-1]
        assert led_ev["produced"]["recovered_sources"] == 4      # ...and the count matches what is on disk

    @pytest.mark.parametrize("obj", [
        {"version": 3, "sources": ["a.ts"], "sourcesContent": ["A", "B"]},        # more contents than sources
        {"version": 3, "sources": ["a.ts", "b.ts"], "sourcesContent": ["A"]},     # fewer
    ])
    def test_misaligned_sources_content_is_rejected(self, obj):
        assert crawl._sourcemap_schema(obj) is None

    # ── review#5: staging cannot be inherited ───────────────────────────────────────────────────────
    def test_staging_is_unique_and_exclusive(self, tmp_path):
        active = tmp_path / "tree"
        a = crawl._stage_dir(active)
        b = crawl._stage_dir(active)
        assert a is not None and b is not None and a != b       # never the same path twice
        assert list(a.iterdir()) == [] and list(b.iterdir()) == []

    def test_a_surviving_stale_generation_cannot_be_inherited(self, tmp_path, monkeypatch):
        """Cleanup used `ignore_errors=True` and then reused a PID-only path, so a file surviving an earlier
        failed attempt could ride into the active tree."""
        ctx = _Ctx(tmp_path, _urls({"a.ex.com": 2}))
        _run_crawl_js(tmp_path, monkeypatch, ctx, _Fetcher())
        led, raw_dir = crawl._js_download(ctx)
        # plant a stale generation containing a file that must never be published
        stale = raw_dir.parent / f"js_derived.gen-{crawl.os.getpid()}-deadbeef"
        stale.mkdir(parents=True)
        (stale / "planted.js").write_text("SMUGGLED")
        pub = crawl._js_publish_derived(ctx, led, raw_dir)
        assert pub is not None
        assert "planted.js" not in {p.name for p in pub.glob("*.js")}
        assert all("SMUGGLED" not in p.read_text() for p in pub.glob("*.js"))


class TestTemplateDefectsRound6:
    """Sixth round: the boundaries of the staged-tree design — memory scaling, stage ownership, and durable
    reporting. Two of these were reproduced by the reviewer before I fixed them."""

    # ── review#1: payload bodies must be streamed, not accumulated ───────────────────────────────────
    def test_map_bodies_are_not_all_held_in_memory(self, tmp_path, monkeypatch):
        """With MAP_CAP gone and 20 MiB allowed per map, collecting bodies before extraction meant a large
        target OOM'd — and every resume rebuilt the same list and OOM'd again. Peak must be ~one map, so the
        lane must EXTRACT each payload before requesting the next."""
        live = {"n": 0, "peak": 0}
        big = json.dumps({"version": 3, "sources": ["a.ts"], "sourcesContent": ["X" * 4096]}).encode()
        ctx = _Ctx(tmp_path, _urls({"a.ex.com": 12}))

        class _F:
            def __call__(self, c, url, **k):
                if not url.endswith(".map"):
                    name = url.rsplit("/", 1)[1]
                    return f"//# sourceMappingURL={name}.map\n".encode() + b"y" * 200 + url.encode(), url, 200
                live["n"] += 1
                live["peak"] = max(live["peak"], live["n"])
                return big, url, 200
        _run_crawl_js(tmp_path, monkeypatch, ctx, _F())
        led, _raw = crawl._js_download(ctx)
        real_extract = crawl._extract_payload

        def counting(text, key, staging, tally):
            r = real_extract(text, key, staging, tally)
            live["n"] -= 1                                       # this body is finished with
            return r
        monkeypatch.setattr(crawl, "_extract_payload", counting)
        recov = crawl._sourcemap_recover(ctx, led)
        assert recov is not None
        assert live["peak"] == 1                                 # never more than one body outstanding
        assert len([p for p in recov.rglob("*") if p.is_file()]) == 12

    def test_resumed_maps_are_also_streamed(self, tmp_path, monkeypatch):
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 6}, body=_map_body("a.ts", "C"))
        crawl._sourcemap_recover(ctx, led)                        # run 1 caches every map
        seen = []
        real_extract = crawl._extract_payload
        monkeypatch.setattr(crawl, "_extract_payload",
                            lambda text, key, st, ta: (seen.append(len(text)), real_extract(text, key, st, ta))[1])
        ctx2, led2, f2 = t._setup(tmp_path, monkeypatch, {"a.ex.com": 6}, body=_map_body("a.ts", "C"))
        crawl._sourcemap_recover(ctx2, led2)
        assert len(seen) == 6                                    # each resumed body handled individually

    # ── review#2: the exclusive-stage contract, end to end ──────────────────────────────────────────
    def test_publish_refuses_a_missing_stage_instead_of_creating_one(self, tmp_path):
        """REPRODUCED by the reviewer: `mkdir(exist_ok=True)` recreated a missing generation and published it
        as an empty success — replacing a populated active tree with an empty directory."""
        active = tmp_path / "tree"
        active.mkdir()
        (active / "precious.js").write_text("EVIDENCE")
        ctx = _Ctx(tmp_path, [])
        assert crawl._publish_tree(ctx, active, tmp_path / "tree.gen-gone") is False
        assert crawl._publish_tree(ctx, active, None) is False
        assert (active / "precious.js").read_text() == "EVIDENCE"   # never wiped

    def test_stage_dir_returns_none_on_any_os_error(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pathlib.Path, "mkdir",
                            lambda self, **k: (_ for _ in ()).throw(PermissionError("read-only fs")))
        assert crawl._stage_dir(tmp_path / "tree") is None       # not just FileExistsError

    def test_sourcemap_lane_survives_an_unavailable_stage(self, tmp_path, monkeypatch):
        """The lane dereferenced _stage_dir()'s result unconditionally."""
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 1}, body=_map_body("a.ts", "C"))
        monkeypatch.setattr(crawl, "_stage_dir", lambda active: None)
        assert crawl._sourcemap_recover(ctx, led) is None        # no crash, nothing mineable
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        pub = [e for e in ev if e.get("measure") == "sourcemaps_published"][-1]
        assert pub["omitted"] == 1
        assert any("staging" in m for m in ctx.echoed)

    def test_js_lane_survives_an_unavailable_stage(self, tmp_path, monkeypatch):
        ctx = _Ctx(tmp_path, _urls({"a.ex.com": 2}))
        _run_crawl_js(tmp_path, monkeypatch, ctx, _Fetcher())
        led, raw_dir = crawl._js_download(ctx)
        monkeypatch.setattr(crawl, "_stage_dir", lambda active: None)
        assert crawl._js_publish_derived(ctx, led, raw_dir) is None
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        mine = [e for e in ev if e.get("measure") == "js_mineable"][-1]
        assert mine["tested"] == 0 and mine["omitted"] == 2

    # ── review#3: an un-persisted lane is a gap ─────────────────────────────────────────────────────
    def test_js_lane_reports_a_persistence_failure(self, tmp_path, monkeypatch):
        """Both lanes discarded save()'s result, then described their remainder as resumable even though
        nothing was durable and every future run would redo the lane."""
        ctx = _Ctx(tmp_path, _urls({"a.ex.com": 3}))
        _run_crawl_js(tmp_path, monkeypatch, ctx, _Fetcher())
        monkeypatch.setattr(crawl.budget.Ledger, "save", lambda self: False)
        crawl._js_download(ctx)
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        st = [e for e in ev if e.get("measure") == "state_persisted"][-1]
        assert st["omitted"] == 1 and "resume will redo" in st["reason"]
        assert any("NOT persisted" in m for m in ctx.echoed)

    def test_a_successful_save_reports_persisted_so_a_prior_gap_clears(self, tmp_path, monkeypatch):
        ctx = _Ctx(tmp_path, _urls({"a.ex.com": 2}))
        _run_crawl_js(tmp_path, monkeypatch, ctx, _Fetcher())
        crawl._js_download(ctx)
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        st = [e for e in ev if e.get("measure") == "state_persisted"][-1]
        assert st["tested"] == 1 and st["omitted"] == 0          # latest-per-unit clears any earlier gap

    def test_a_foreign_state_path_is_reported_not_silently_lost(self, tmp_path, monkeypatch):
        ctx = _Ctx(tmp_path, _urls({"a.ex.com": 2}))
        _run_crawl_js(tmp_path, monkeypatch, ctx, _Fetcher())
        # plant another lane's compacted snapshot at the js lane's state path
        (tmp_path / "raw" / "crawl").mkdir(parents=True, exist_ok=True)
        (tmp_path / "raw" / "crawl" / "js_fetch.state.json").write_text(
            json.dumps({"lane": "someone.else", "done": {}, "digests": {}}))
        crawl._js_download(ctx)
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        st = [e for e in ev if e.get("measure") == "state_persisted"][-1]
        assert st["omitted"] == 1 and "different lane" in st["reason"]
        # ...and the other lane's snapshot is intact
        assert json.loads((tmp_path / "raw" / "crawl" / "js_fetch.state.json").read_text())["lane"] \
            == "someone.else"

    # ── review#4: a ledger every lifecycle ─────────────────────────────────────────────────────────
    def test_a_successful_empty_generation_still_zeroes_the_ledger(self, tmp_path, monkeypatch):
        """Confirmed by the reviewer: an old recovered_sources count survived a newer lifecycle that produced
        nothing, because event folding carries the latest ledger forward."""
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 3}, body=_map_body("a.ts", "C"))
        crawl._sourcemap_recover(ctx, led)
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        first = [e for e in ev if e.get("event") == "ledger"][-1]
        assert first["produced"]["recovered_sources"] == 3

        # a later lifecycle that genuinely produces nothing: invalidate the JS evidence, so no map is a
        # candidate any more. (The ledger ACCUMULATES, so merely passing an empty js_url list would still
        # re-extract run 1's maps — which is correct behaviour, not staleness.)
        for j in (tmp_path / "raw" / "crawl" / "js_files").glob("*.js"):
            j.write_text("TAMPERED")
        ctx2 = _Ctx(tmp_path, [])
        _run_crawl_js(tmp_path, monkeypatch, ctx2, _Fetcher())
        led2, _raw = crawl._js_download(ctx2)
        assert list(led2.items()) == []
        crawl._sourcemap_recover(ctx2, led2)
        ev2 = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        last = [e for e in ev2 if e.get("event") == "ledger" and e.get("source_id") == "crawl.sourcemaps"][-1]
        assert last["produced"]["recovered_sources"] == 0        # the stale 3 cannot survive
        assert last["produced"]["published"] == 1

    def test_the_folded_view_shows_the_current_generation(self, tmp_path, monkeypatch):
        """Assert against the actual folding the operator sees, not just the emitted event."""
        from quarry_recon import views
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 2}, body=_map_body("a.ts", "C"))
        crawl._sourcemap_recover(ctx, led)
        monkeypatch.setattr(crawl, "_publish_tree", lambda c, a, s: False)
        crawl._sourcemap_recover(ctx, led)
        folded = views._fold_events(tmp_path / "events.jsonl")
        produced = folded["crawl.sourcemaps"].get("produced") or {}
        assert produced.get("recovered_sources") == 0            # not the earlier generation's count


class TestTemplateDefectsRound7:
    """Seventh round: ghost evidence and ghost coverage at the extraction/publication boundary."""

    # ── review#1: a failed extraction must not leave anything publishable ────────────────────────────
    def test_a_failed_extraction_publishes_nothing_from_that_payload(self, tmp_path, monkeypatch):
        """Extraction wrote straight into staging, so a failure whose `rmtree` cleanup ALSO failed left a
        partial subdir inside the generation — published, and ingested as evidence in no counter at all."""
        t = TestSourcemapLane()
        body = json.dumps({"version": 3, "sources": ["a.ts", "b.ts", "c.ts"],
                           "sourcesContent": ["A", "B", "C"]}).encode()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 1}, body=body)
        real_write = pathlib.Path.write_text
        n = [0]

        def fail_third(self, *a, **k):
            if self.suffix == ".ts":
                n[0] += 1
                if n[0] == 3:
                    raise OSError("no space left")
            return real_write(self, *a, **k)
        monkeypatch.setattr(pathlib.Path, "write_text", fail_third)
        monkeypatch.setattr(crawl.shutil, "rmtree", lambda *a, **k: None)   # cleanup silently does nothing
        recov = crawl._sourcemap_recover(ctx, led)
        monkeypatch.setattr(pathlib.Path, "write_text", real_write)
        assert recov is not None
        # not one of the partial sources may be present — they were never inside the generation
        assert [p for p in recov.rglob("*") if p.is_file()] == []
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        ext = [e for e in ev if e.get("measure") == "sourcemaps_extracted"][-1]
        assert ext["omitted"] == 1 and "extract_error" in ext["reason"]

    def test_an_uncounted_staging_entry_blocks_publication(self, tmp_path, monkeypatch):
        """Defence in depth: anything in the generation without a counter behind it is removed, and if it
        cannot be removed, publication is refused rather than shipping uncounted evidence."""
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 1}, body=_map_body("a.ts", "OK"))
        real_extract = crawl._extract_payload

        def smuggle(text, key, staging, tally, workroot=None):
            got = real_extract(text, key, staging, tally, workroot)
            (staging / "smuggled").mkdir(exist_ok=True)          # an entry no counter knows about
            (staging / "smuggled" / "x.js").write_text("GHOST EVIDENCE")
            return got
        monkeypatch.setattr(crawl, "_extract_payload", smuggle)
        monkeypatch.setattr(crawl.shutil, "rmtree", lambda *a, **k: None)   # cannot be removed
        assert crawl._sourcemap_recover(ctx, led) is None        # publication refused
        assert any("could not be removed" in m for m in ctx.echoed)

    def test_an_uncounted_entry_that_can_be_removed_is_dropped(self, tmp_path, monkeypatch):
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 1}, body=_map_body("a.ts", "OK"))
        real_extract = crawl._extract_payload

        def smuggle(text, key, staging, tally, workroot=None):
            got = real_extract(text, key, staging, tally, workroot)
            (staging / "smuggled").mkdir(exist_ok=True)
            (staging / "smuggled" / "x.js").write_text("GHOST EVIDENCE")
            return got
        monkeypatch.setattr(crawl, "_extract_payload", smuggle)
        recov = crawl._sourcemap_recover(ctx, led)
        assert recov is not None
        assert all("GHOST" not in p.read_text() for p in recov.rglob("*") if p.is_file())
        assert any("OK" in p.read_text() for p in recov.rglob("*") if p.is_file())

    def test_work_directories_never_survive_into_the_tree(self, tmp_path, monkeypatch):
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 3}, body=_map_body("a.ts", "C"))
        recov = crawl._sourcemap_recover(ctx, led)
        assert recov is not None
        assert not list(recov.parent.glob("recovered.gen-*"))
        assert not list(recov.parent.glob("*.work-*"))

    # ── review#2: an unreadable cached map must not read as fetched ──────────────────────────────────
    def test_an_unreadable_cached_map_is_refetched_not_counted_as_fetched(self, tmp_path, monkeypatch):
        """`m_att = m_got = len(resumed)` counted it as successfully fetched while `payload_n` excluded it, so
        it vanished from every denominator.

        review#3 (r8): the artifact must become unreadable AFTER ledger validation. Deleting the cache first
        made the ledger reject the entries at LOAD, so they took the ordinary new-item path and the requeue
        branch was never executed. `Ledger._load` verifies via events.file_digest (open/read), so failing only
        `read_bytes` on cached maps validates the entry and then breaks exactly where the resumed loop reads."""
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 2}, body=_map_body("a.ts", "C"))
        crawl._sourcemap_recover(ctx, led)                        # run 1 caches both maps
        cache = tmp_path / "raw" / "crawl" / "sourcemaps" / "fetched"
        assert len(list(cache.glob("*.map"))) >= 1                # the ledger really did cache them

        real_rb = pathlib.Path.read_bytes

        def unreadable_cache(self):
            if self.suffix == ".map" and self.parent.name == "fetched":
                raise OSError("cached body unreadable")
            return real_rb(self)
        ctx2, led2, f2 = t._setup(tmp_path, monkeypatch, {"a.ex.com": 2}, body=_map_body("a.ts", "C"))
        monkeypatch.setattr(pathlib.Path, "read_bytes", unreadable_cache)
        recov = crawl._sourcemap_recover(ctx2, led2)
        monkeypatch.setattr(pathlib.Path, "read_bytes", real_rb)
        assert recov is not None
        assert len(f2.map_calls) == 2                             # REQUEUED and refetched, not skipped
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        fetched = [e for e in ev if e.get("measure") == "sourcemaps_fetched"][-1]
        val = [e for e in ev if e.get("measure") == "sourcemaps_valid"][-1]
        assert fetched["tested"] == 2 and fetched["omitted"] == 0
        assert val["eligible"] == 2                               # present in the validity denominator

    def test_a_requeued_map_that_also_fails_to_fetch_is_named(self, tmp_path, monkeypatch):
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 2}, body=_map_body("a.ts", "C"))
        crawl._sourcemap_recover(ctx, led)
        real_rb = pathlib.Path.read_bytes

        def unreadable_cache(self):
            if self.suffix == ".map" and self.parent.name == "fetched":
                raise OSError("cached body unreadable")
            return real_rb(self)
        ctx2, led2, f2 = t._setup(tmp_path, monkeypatch, {"a.ex.com": 2},
                                  body=_map_body("a.ts", "C"), fail_hosts={"a.ex.com"})
        monkeypatch.setattr(pathlib.Path, "read_bytes", unreadable_cache)
        crawl._sourcemap_recover(ctx2, led2)
        monkeypatch.setattr(pathlib.Path, "read_bytes", real_rb)
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        fetched = [e for e in ev if e.get("measure") == "sourcemaps_fetched"][-1]
        # requeued, refetch failed -> attempted but NOT obtained, and named
        assert fetched["eligible"] == 2 and fetched["tested"] == 0 and fetched["omitted"] == 2
        assert "not_contacted" in fetched["reason"]

    # ── review#3: save() never raises ───────────────────────────────────────────────────────────────
    @pytest.mark.parametrize("target", ["mkdir", "write_text"])
    def test_save_returns_false_on_any_filesystem_failure(self, tmp_path, monkeypatch, target):
        art = tmp_path / "f" / "a.js"
        art.parent.mkdir(parents=True)
        art.write_text("x")
        led = budget.Ledger(tmp_path / "s.json", lane="l")
        led.record("u", art)
        monkeypatch.setattr(pathlib.Path, target,
                            lambda self, *a, **k: (_ for _ in ()).throw(OSError("read-only fs")))
        assert led.save() is False                                # never raises out of the lane body

    def test_a_raising_save_still_produces_the_persistence_gap(self, tmp_path, monkeypatch):
        ctx = _Ctx(tmp_path, _urls({"a.ex.com": 2}))
        _run_crawl_js(tmp_path, monkeypatch, ctx, _Fetcher())
        real = budget.os.replace
        monkeypatch.setattr(budget.os, "replace",
                            lambda s, d: (_ for _ in ()).throw(OSError("full"))
                            if str(s).endswith(".json.tmp") else real(s, d))
        crawl._js_download(ctx)                                   # must not raise
        monkeypatch.setattr(budget.os, "replace", real)
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        st = [e for e in ev if e.get("measure") == "state_persisted"][-1]
        assert st["omitted"] == 1

    # ── review#4: no false "resumable" promise ──────────────────────────────────────────────────────
    def test_a_non_durable_remainder_is_not_called_resumable(self, tmp_path, monkeypatch):
        """Even after the persistence gap, the selection reason and the console line still said the remainder
        was resumable — a false promise when the next run starts over."""
        ctx = _Ctx(tmp_path, _urls({"a.ex.com": 40}))
        f = _Fetcher()
        _run_crawl_js(tmp_path, monkeypatch, ctx, f, budget_s={"JS_FETCH_BUDGET_S": 30})
        clock = [1000.0]
        monkeypatch.setattr(budget.time, "monotonic", lambda: clock[0])
        real = f.__call__

        def ticking(*a, **k):
            clock[0] += 10
            return real(*a, **k)
        monkeypatch.setattr(crawl.fetch, "scoped_get", ticking)
        monkeypatch.setattr(crawl.budget.Ledger, "save", lambda self: False)
        crawl._js_download(ctx)
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        sel = [e for e in ev if e.get("measure") == "js_urls"][-1]
        assert sel["omitted"] > 0
        assert "RESUMABLE" not in sel["reason"] and "RESTARTS" in sel["reason"]
        assert any("NOT saved, will restart" in m for m in ctx.echoed)

    def test_a_durable_remainder_is_still_called_resumable(self, tmp_path, monkeypatch):
        ctx = _Ctx(tmp_path, _urls({"a.ex.com": 40}))
        f = _Fetcher()
        _run_crawl_js(tmp_path, monkeypatch, ctx, f, budget_s={"JS_FETCH_BUDGET_S": 30})
        clock = [1000.0]
        monkeypatch.setattr(budget.time, "monotonic", lambda: clock[0])
        real = f.__call__

        def ticking(*a, **k):
            clock[0] += 10
            return real(*a, **k)
        monkeypatch.setattr(crawl.fetch, "scoped_get", ticking)
        crawl._js_download(ctx)
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        sel = [e for e in ev if e.get("measure") == "js_urls"][-1]
        assert "RESUMABLE remainder" in sel["reason"]


class TestTemplateDefectsRound8:
    """Eighth round: manifest symmetry and honest reporting of the unmeasured case."""

    # ── review#1: the generation must agree with its counters in BOTH directions ─────────────────────
    def test_a_vanished_counted_payload_refuses_publication(self, tmp_path, monkeypatch):
        """The check removed EXTRAS but never verified that every counted payload still existed — so a
        counted directory that disappeared before publication shipped an incomplete tree while `extracted`,
        `recovered` and the ledger all still counted it."""
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 2}, body=_map_body("a.ts", "C"))
        real_extract = crawl._extract_payload
        killed = {"done": False}

        def vanish_one(text, key, staging, tally, workroot=None):
            got = real_extract(text, key, staging, tally, workroot)
            if got and not killed["done"]:                       # a counted payload disappears afterwards
                crawl.shutil.rmtree(staging / got)
                killed["done"] = True
            return got
        monkeypatch.setattr(crawl, "_extract_payload", vanish_one)
        assert crawl._sourcemap_recover(ctx, led) is None        # refused, not published incomplete
        assert any("disagrees with its counters" in m for m in ctx.echoed)

    def test_a_counted_payload_replaced_by_a_file_refuses_publication(self, tmp_path, monkeypatch):
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 1}, body=_map_body("a.ts", "C"))
        real_extract = crawl._extract_payload

        def swap_for_file(text, key, staging, tally, workroot=None):
            got = real_extract(text, key, staging, tally, workroot)
            if got:
                crawl.shutil.rmtree(staging / got)
                (staging / got).write_text("not a directory")    # right name, wrong TYPE
            return got
        monkeypatch.setattr(crawl, "_extract_payload", swap_for_file)
        assert crawl._sourcemap_recover(ctx, led) is None

    def test_an_exactly_matching_manifest_publishes(self, tmp_path, monkeypatch):
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 3}, body=_map_body("a.ts", "C"))
        recov = crawl._sourcemap_recover(ctx, led)
        assert recov is not None
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        led_ev = [e for e in ev if e.get("event") == "ledger"][-1]
        # counters and disk agree: one subdir per extracted payload
        assert len([d for d in recov.iterdir() if d.is_dir()]) == 3
        assert led_ev["produced"]["recovered_sources"] == 3

    # ── review#2: unmeasured is not zero ────────────────────────────────────────────────────────────
    def test_unavailable_staging_reports_unknown_not_clean_zeros(self, tmp_path, monkeypatch):
        """With JS present but no staging, candidate discovery never ran. Clean 0/0 records implied there was
        nothing to inspect; the truth is that nothing was measured."""
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 4}, body=_map_body("a.ts", "C"))
        monkeypatch.setattr(crawl, "_stage_dir", lambda active: None)
        assert crawl._sourcemap_recover(ctx, led) is None
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        for m in ("sourcemaps", "sourcemaps_fetched", "sourcemaps_valid", "sourcemaps_extracted"):
            rec = [e for e in ev if e.get("measure") == m][-1]
            assert rec["kind"] == events.COVERAGE_UNKNOWN
            assert rec["coverage_valid"] is False                # reaches the verdict as a gap
            assert "4 JS artifact(s) were never inspected" in rec["reason"]   # attribution retained

    def test_unavailable_staging_is_a_gap_in_the_run_verdict(self, tmp_path, monkeypatch):
        """Assert the operator-visible outcome, not just the emitted events."""
        from quarry_recon.store import Run
        events.reset()
        st = Run(tmp_path / "proj", "t", run_id="r1")
        events.configure(st.dir)
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 2}, body=_map_body("a.ts", "C"))
        events.configure(st.dir)                                  # events land in the run dir
        monkeypatch.setattr(crawl, "_stage_dir", lambda active: None)
        crawl._sourcemap_recover(ctx, led)
        summ = st._run_summary()
        gaps = [g for g in summ["gaps"] if g["tool"] == "crawl.sourcemaps"]
        assert gaps and any(g["status"] == "coverage:unknown" for g in gaps)
        assert summ["verdict"] == "complete_with_gaps"

    def test_no_js_still_reports_clean_zeros_not_unknown(self, tmp_path, monkeypatch):
        """The distinction that matters: "no JS to inspect" is genuinely zero; "could not inspect" is
        unknown. They must not collapse into the same record."""
        ctx = _Ctx(tmp_path, [])
        _run_crawl_js(tmp_path, monkeypatch, ctx, _Fetcher())
        led, _raw = crawl._js_download(ctx)
        assert crawl._sourcemap_recover(ctx, led) is not None
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        for m in ("sourcemaps", "sourcemaps_fetched"):
            rec = [e for e in ev if e.get("measure") == m][-1]
            assert rec["kind"] != events.COVERAGE_UNKNOWN
            assert (rec["eligible"], rec["omitted"]) == (0, 0)


class TestTemplateDefectsRound9:
    """Ninth round: the last silent-skip, file-level manifest truth, and a verification step that cannot
    escape without reporting."""

    @staticmethod
    def _break_reads(monkeypatch, *, in_dir, suffix):
        """Make reads fail only for artifacts in `in_dir` — AFTER ledger validation, which goes through
        events.file_digest rather than read_text/read_bytes."""
        real_rt, real_rb = pathlib.Path.read_text, pathlib.Path.read_bytes

        def rt(self, *a, **k):
            if self.parent.name == in_dir and self.suffix == suffix:
                raise OSError("unreadable")
            return real_rt(self, *a, **k)
        monkeypatch.setattr(pathlib.Path, "read_text", rt)
        return real_rt, real_rb

    # ── review#1: unreadable JS evidence is a measured gap ───────────────────────────────────────────
    def test_an_unreadable_js_artifact_is_a_reported_gap(self, tmp_path, monkeypatch):
        """Skipping silently meant that if the ONLY JS artifact became unreadable after ledger validation,
        every sourcemap measure reported a clean 0/0 and an empty generation published — indistinguishable
        from "this target has no sourcemaps"."""
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 1}, body=_map_body("a.ts", "C"))
        assert len(list(led.items())) == 1
        real_rt, _ = self._break_reads(monkeypatch, in_dir="js_files", suffix=".js")
        crawl._sourcemap_recover(ctx, led)
        monkeypatch.setattr(pathlib.Path, "read_text", real_rt)
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        insp = [e for e in ev if e.get("measure") == "js_inspected"][-1]
        assert (insp["eligible"], insp["tested"], insp["omitted"]) == (1, 0, 1)
        assert "unreadable_artifact" in insp["reason"]
        # the sourcemap zeros are still emitted, but they are no longer the WHOLE story
        sm = [e for e in ev if e.get("measure") == "sourcemaps"][-1]
        assert sm["eligible"] == 0

    def test_a_partially_unreadable_js_set_reports_the_shortfall(self, tmp_path, monkeypatch):
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 3}, body=_map_body("a.ts", "C"))
        arts = sorted(a for _u, a in led.items())
        victim = arts[0].name
        real_rt = pathlib.Path.read_text

        def rt(self, *a, **k):
            if self.name == victim:
                raise OSError("unreadable")
            return real_rt(self, *a, **k)
        monkeypatch.setattr(pathlib.Path, "read_text", rt)
        crawl._sourcemap_recover(ctx, led)
        monkeypatch.setattr(pathlib.Path, "read_text", real_rt)
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        insp = [e for e in ev if e.get("measure") == "js_inspected"][-1]
        assert (insp["eligible"], insp["tested"], insp["omitted"]) == (3, 2, 1)

    def test_all_readable_js_reports_full_inspection(self, tmp_path, monkeypatch):
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 2}, body=_map_body("a.ts", "C"))
        crawl._sourcemap_recover(ctx, led)
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        insp = [e for e in ev if e.get("measure") == "js_inspected"][-1]
        assert insp["omitted"] == 0                              # so a prior gap clears

    # ── review#2: manifest truth down to the FILE ───────────────────────────────────────────────────
    def test_a_missing_recovered_file_refuses_publication(self, tmp_path, monkeypatch):
        """Comparing only top-level directory names was too coarse: a recovered file disappearing inside a
        counted directory published fine while `recovered_sources` overstated disk evidence."""
        t = TestSourcemapLane()
        body = json.dumps({"version": 3, "sources": ["a.ts", "b.ts"],
                           "sourcesContent": ["A", "B"]}).encode()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 1}, body=body)
        real_extract = crawl._extract_payload

        def drop_a_file(text, key, staging, tally, workroot=None):
            got = real_extract(text, key, staging, tally, workroot)
            if got:                                              # one recovered file vanishes afterwards
                victim = next(q for q in (staging / got).rglob("*") if q.is_file())
                victim.unlink()
            return got
        monkeypatch.setattr(crawl, "_extract_payload", drop_a_file)
        assert crawl._sourcemap_recover(ctx, led) is None
        assert any("recovered file(s), counted" in m for m in ctx.echoed)

    def test_a_symlinked_payload_directory_is_rejected(self, tmp_path, monkeypatch):
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 1}, body=_map_body("a.ts", "C"))
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "planted.js").write_text("OUT OF TREE")
        real_extract = crawl._extract_payload

        def swap_for_symlink(text, key, staging, tally, workroot=None):
            got = real_extract(text, key, staging, tally, workroot)
            if got:
                crawl.shutil.rmtree(staging / got)
                (staging / got).symlink_to(outside)              # right name, a SYMLINK out of the tree
            return got
        monkeypatch.setattr(crawl, "_extract_payload", swap_for_symlink)
        assert crawl._sourcemap_recover(ctx, led) is None
        assert (outside / "planted.js").exists()                 # unlinked the link, never followed it

    def test_an_intact_generation_passes_file_level_verification(self, tmp_path, monkeypatch):
        t = TestSourcemapLane()
        body = json.dumps({"version": 3, "sources": ["a.ts", "b.ts", "c.ts"],
                           "sourcesContent": ["A", "B", "C"]}).encode()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 2}, body=body)
        recov = crawl._sourcemap_recover(ctx, led)
        assert recov is not None
        on_disk = len([q for q in recov.rglob("*") if q.is_file()])
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        led_ev = [e for e in ev if e.get("event") == "ledger"][-1]
        assert led_ev["produced"]["recovered_sources"] == on_disk == 6   # counters == disk, exactly

    # ── review#3: verification cannot escape without reporting ──────────────────────────────────────
    def test_a_raising_unlink_still_reports_the_publication_gap(self, tmp_path, monkeypatch):
        """The existing removal test covered an ignored rmtree, not a RAISING unlink — which aborted before
        `sourcemaps_published` recorded anything, so a failure to verify became a failure to report."""
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 1}, body=_map_body("a.ts", "C"))
        real_extract = crawl._extract_payload

        def smuggle_file(text, key, staging, tally, workroot=None):
            got = real_extract(text, key, staging, tally, workroot)
            (staging / "stray.txt").write_text("uncounted")
            return got
        monkeypatch.setattr(crawl, "_extract_payload", smuggle_file)
        real_unlink = pathlib.Path.unlink
        monkeypatch.setattr(pathlib.Path, "unlink",
                            lambda self, **k: (_ for _ in ()).throw(OSError("refused"))
                            if self.name == "stray.txt" else real_unlink(self, **k))
        assert crawl._sourcemap_recover(ctx, led) is None        # must not raise out of the lane
        monkeypatch.setattr(pathlib.Path, "unlink", real_unlink)
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        pub = [e for e in ev if e.get("measure") == "sourcemaps_published"][-1]
        assert (pub["eligible"], pub["tested"], pub["omitted"]) == (1, 0, 1)

    def test_a_raising_iterdir_still_reports_the_publication_gap(self, tmp_path, monkeypatch):
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 1}, body=_map_body("a.ts", "C"))
        real_iterdir = pathlib.Path.iterdir
        monkeypatch.setattr(pathlib.Path, "iterdir",
                            lambda self: (_ for _ in ()).throw(OSError("io error"))
                            if "recovered.gen-" in self.name else real_iterdir(self))
        assert crawl._sourcemap_recover(ctx, led) is None
        monkeypatch.setattr(pathlib.Path, "iterdir", real_iterdir)
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        pub = [e for e in ev if e.get("measure") == "sourcemaps_published"][-1]
        assert pub["omitted"] == 1


class TestTemplateDefectsRound10:
    """Tenth round: containment of the published tree, closed at the file level."""

    def _plant(self, monkeypatch, mutate):
        real_extract = crawl._extract_payload

        def wrapped(text, key, staging, tally, workroot=None):
            got = real_extract(text, key, staging, tally, workroot)
            if got:
                mutate(staging / got)
            return got
        monkeypatch.setattr(crawl, "_extract_payload", wrapped)

    def test_a_nested_symlink_inside_a_valid_payload_is_rejected(self, tmp_path, monkeypatch):
        """A COUNT was not containment: counting only regular non-symlink files left the expected count
        unchanged, so `payload/extra.js -> outside/file` published — and the downstream `is_file()` follows
        symlinks, handing an out-of-tree file to the miners."""
        outside = tmp_path / "outside"
        outside.mkdir()
        secret = outside / "not_ours.js"
        secret.write_text("EXFILTRATED")
        t = TestSourcemapLane()
        self._plant(monkeypatch, lambda sub: (sub / "0000" / "extra.js").symlink_to(secret))
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 1}, body=_map_body("a.ts", "C"))
        assert crawl._sourcemap_recover(ctx, led) is None        # refused
        assert any("contains a symlink" in m for m in ctx.echoed)
        assert secret.read_text() == "EXFILTRATED"               # never followed or touched

    def test_a_symlink_replacing_an_expected_file_is_rejected(self, tmp_path, monkeypatch):
        """The path SET is unchanged here, so a path-set check alone would pass — the blanket symlink refusal
        is what catches it."""
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "evil.js").write_text("SUBSTITUTED")
        t = TestSourcemapLane()

        def swap(sub):
            victim = next(q for q in sub.rglob("*") if q.is_file())
            victim.unlink()
            victim.symlink_to(outside / "evil.js")
        self._plant(monkeypatch, swap)
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 1}, body=_map_body("a.ts", "C"))
        assert crawl._sourcemap_recover(ctx, led) is None

    def test_a_symlinked_subdirectory_inside_a_payload_is_rejected(self, tmp_path, monkeypatch):
        outside = tmp_path / "outside"
        (outside / "deep").mkdir(parents=True)
        (outside / "deep" / "x.js").write_text("OUT")
        t = TestSourcemapLane()
        self._plant(monkeypatch, lambda sub: (sub / "linked").symlink_to(outside / "deep"))
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 1}, body=_map_body("a.ts", "C"))
        assert crawl._sourcemap_recover(ctx, led) is None
        assert (outside / "deep" / "x.js").read_text() == "OUT"

    def test_an_extra_regular_file_with_a_matching_count_is_rejected(self, tmp_path, monkeypatch):
        """A count alone also missed substitution: delete one expected file, add one unexpected one, and the
        total is identical. The exact PATH SET is what rejects it."""
        t = TestSourcemapLane()
        body = json.dumps({"version": 3, "sources": ["a.ts", "b.ts"],
                           "sourcesContent": ["A", "B"]}).encode()

        def swap_paths(sub):
            victim = sorted(q for q in sub.rglob("*") if q.is_file())[0]
            victim.unlink()
            (sub / "0000" / "impostor.js").write_text("PLANTED")
        self._plant(monkeypatch, swap_paths)
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 1}, body=body)
        assert crawl._sourcemap_recover(ctx, led) is None
        assert any("the paths differ" in m for m in ctx.echoed)

    def test_an_intact_payload_still_publishes(self, tmp_path, monkeypatch):
        t = TestSourcemapLane()
        body = json.dumps({"version": 3, "sources": ["a.ts", "b.ts", "c.ts"],
                           "sourcesContent": ["A", "B", "C"]}).encode()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 2}, body=body)
        recov = crawl._sourcemap_recover(ctx, led)
        assert recov is not None
        assert len([q for q in recov.rglob("*") if q.is_file()]) == 6

    def test_path_fingerprint_is_domain_separated(self):
        fp = crawl._path_fingerprint
        assert fp(["ab/c"]) != fp(["a", "bc"])                   # no concatenation ambiguity
        assert fp(["a", "b"]) == fp(["b", "a"])                  # order-independent (it is a SET)
        assert fp(["a"]) != fp(["a", "a2"])


class TestXnLinkFinderNeverCrawls:
    """review-B-audit D1/D2: the waymore-response mining ran at DEPTH 3, which makes xnLinkFinder REQUEST
    every link it extracts — and the only scope gate on those requests is the tool's own `-sf` regex
    (xnLinkFinder 8.2 line ~1053), which is not anchored at the end of the host:

        ^([A-Za-z]*)?(://|//|^)[^/|?|#]*<apex>

    Measured against apex `acme.com` it accepts `acme.com.evil.net`, `notacme.com`,
    `//acme.com.attacker.io` and `xacme.common.io` — hosts Quarry's own scope (`host == apex or
    host.endswith("." + apex)`) refuses. The input is ARCHIVED THIRD-PARTY RESPONSE BODIES, so anyone can
    plant such a link. That crawl also followed redirects and ran with `-insecure`.

    This lane extracts from bytes we already hold. It never requests anything."""

    def _capture(self, tmp_path, monkeypatch, extra=None):
        seen = {}

        def fake_exec(tool, cmd, **kw):
            seen["tool"], seen["cmd"], seen["kw"] = tool, list(cmd), kw
            return type("R", (), {"tool": tool, "cmd": cmd, "status": crawl.Status.SUCCESS,
                                  "note": "", "duration": 0.0, "exit_code": 0})()

        monkeypatch.setattr(crawl, "exec_tool", fake_exec)
        ctx = _Ctx(tmp_path, [])
        src = tmp_path / "indir"
        src.mkdir(parents=True, exist_ok=True)
        (src / "a.js").write_text("var u = '/api/v1/users';\n")
        crawl._xnl(ctx, str(src), "t", extra=extra or [])
        return seen["cmd"]

    def test_the_command_is_always_offline(self, tmp_path, monkeypatch):
        cmd = self._capture(tmp_path, monkeypatch)
        assert "-d" in cmd and cmd[cmd.index("-d") + 1] == "0", cmd

    @pytest.mark.parametrize("flag", ["-insecure", "-u", "-rl", "-s429", "-s403", "-sTO", "-sCE"])
    def test_NO_crawl_flag_survives(self, tmp_path, monkeypatch, flag):
        """Every one of these exists only to make requests kinder — they have no meaning offline, and
        their presence would mean the lane is crawling again."""
        assert flag not in self._capture(tmp_path, monkeypatch), flag

    def test_a_CALLER_cannot_ask_for_depth(self, tmp_path, monkeypatch):
        """The parameter is GONE, not defaulted: a parameter can be passed again by a future call site, a
        missing one cannot."""
        import inspect
        assert "depth" not in inspect.signature(crawl._xnl).parameters
        with pytest.raises(TypeError):
            crawl._xnl(None, "x", "t", extra=[], depth=3)

    def test_extra_flags_cannot_reintroduce_a_crawl(self, tmp_path, monkeypatch):
        """`extra` is caller-supplied; `-d 0` must still be what the tool sees."""
        cmd = self._capture(tmp_path, monkeypatch, extra=["-spo"])
        assert cmd.count("-d") == 1 and cmd[cmd.index("-d") + 1] == "0", cmd
        assert "-spo" in cmd, cmd

    def test_the_stdin_blob_starts_with_a_BLANK_LINE(self, tmp_path, monkeypatch):
        """A first line starting with `http`/`//` makes stdin a URL LIST and the tool crawls those URLs.
        The blank line forces offline content mode — the other half of "never requests anything"."""
        seen = {}

        def fake_exec(tool, cmd, **kw):
            seen["input"] = pathlib.Path(kw["input_file"]).read_bytes()
            return type("R", (), {"tool": tool, "cmd": cmd, "status": crawl.Status.SUCCESS,
                                  "note": "", "duration": 0.0, "exit_code": 0})()

        monkeypatch.setattr(crawl, "exec_tool", fake_exec)
        ctx = _Ctx(tmp_path, [])
        src = tmp_path / "indir2"
        src.mkdir(parents=True, exist_ok=True)
        (src / "urls.txt").write_text("https://example.com/a\nhttps://example.com/b\n")
        crawl._xnl(ctx, str(src), "t2", extra=[])
        assert seen["input"].startswith(b"\n"), seen["input"][:40]

    def test_no_CALL_SITE_asks_for_a_crawl(self):
        import inspect
        src = inspect.getsource(crawl)
        calls = [ln for ln in src.splitlines()
                 if "_xnl(ctx," in ln and not ln.lstrip().startswith("def ")]
        assert len(calls) == 4, calls          # waymore, sourcemap, js, katana-resp
        for line in calls:
            assert "depth" not in line, line

    def test_the_DOCS_do_not_teach_the_broken_form(self):
        """`-i <dir>` yields nothing at exit 0, and depth-3 is the RoE hazard above — a reader copying the
        docs must not reproduce either."""
        doc = pathlib.Path(__file__).parent.parent / "docs" / "example.md"
        text = doc.read_text()
        assert "xnLinkFinder -i " not in text, "the docs still teach `-i <dir>`"
        assert "-d 3" not in text and "-insecure" not in text, "the docs still teach the depth-3 crawl"
