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
import hashlib
import os
import pathlib
import shutil
import uuid
from contextlib import contextmanager

import pytest

from quarry_recon import budget, events, settings
from quarry_recon.phases import crawl
from quarry_recon.runner_native import NativeTreeEntryEvidence

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
        # step 3: xnLinkFinder unit state is PROJECT-owned, so a run knows its project. In production
        # `Run.create()` mints `dir` fresh per run under a stable `project_dir` — a fixture that conflates
        # them is exactly what hid the cross-run defect.
        self.project_dir = d.parent if d.name == "run" else d
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


class _FakeArtifactClaim:
    """Minimal explicit adapter for legacy fake-Run tests only."""

    def __init__(self, final):
        self.final = final
        self.stage = final.with_name(f"{final.name}.claim-{uuid.uuid4().hex}")
        self.writer = -1
        self.published = False

    def open_writer(self):
        self.final.parent.mkdir(parents=True, exist_ok=True)
        self.writer = os.open(self.stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        return self.writer

    def publish(self):
        if self.writer >= 0:
            os.close(self.writer)
            self.writer = -1
        os.replace(self.stage, self.final)
        self.published = True

    def fence(self):
        if self.writer >= 0:
            os.close(self.writer)
            self.writer = -1
        self.stage.unlink(missing_ok=True)


@contextmanager
def _fake_artifact_claim(final):
    claim = _FakeArtifactClaim(final)
    try:
        yield claim
    finally:
        if not claim.published:
            claim.fence()


def _install_fake_xnl_repository(monkeypatch):
    """Adapt only this module's fake Run; production remains exact-Run-only."""
    monkeypatch.setattr(
        crawl, "_xnl_artifact_claim",
        lambda run, components: _fake_artifact_claim(run.dir.joinpath(*components)),
    )

    def publish_bytes(run, components, data):
        destination = run.dir.joinpath(*components)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        return True

    def publish_absence(run, components):
        run.dir.joinpath(*components).unlink(missing_ok=True)
        return True

    monkeypatch.setattr(crawl, "_xnl_publish_run_bytes", publish_bytes)
    monkeypatch.setattr(crawl, "_xnl_publish_run_absence", publish_absence)


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
    monkeypatch.setattr(crawl, "_owned_tree", _fake_owned_tree)
    return ctx


class _FakeTreeBuilder:
    """Path-backed adapter for legacy fake-Run tests only."""

    def __init__(self, root, run):
        self.root = root
        self.run = run
        self.faulted = False

    def mkdir(self, *components):
        self.root.joinpath(*components).mkdir(parents=True, exist_ok=True)

    def write_bytes(self, data, *components):
        destination = self.root.joinpath(*components)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)

    def copy_repository_file(self, source_components, *destination_components):
        payload = self.run.dir.joinpath(*source_components).read_bytes()
        self.write_bytes(payload, *destination_components)
        return NativeTreeEntryEvidence(
            tuple(destination_components), len(payload),
            hashlib.sha256(payload).hexdigest(),
        )


def _fake_stage_dir(destination):
    staging = destination.with_name(
        f"{destination.name}.gen-{uuid.uuid4().hex}",
    )
    try:
        staging.mkdir(parents=True)
    except OSError:
        return None
    return staging


def _fake_publish_tree(ctx, destination, staging):
    """Legacy fake-Run adapter; never reachable from production Crawl code."""
    if staging is None or not staging.is_dir():
        return False
    retired = destination.with_name(
        f"{destination.name}.retired-{uuid.uuid4().hex}",
    )
    moved_prior = False
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            os.replace(destination, retired)
            moved_prior = True
        os.replace(staging, destination)
    except OSError:
        if moved_prior and not destination.exists():
            try:
                os.replace(retired, destination)
            except OSError:
                ctx.echo(f"retired tree left at {retired}")
        shutil.rmtree(staging, ignore_errors=True)
        return False
    if moved_prior:
        shutil.rmtree(retired, ignore_errors=True)
    return True


def _fake_owned_tree(ctx, destination, build):
    """Explicit test-double adapter; production `_owned_tree` fails non-Run closed."""
    staging = _fake_stage_dir(destination)
    if staging is None:
        return False
    builder = _FakeTreeBuilder(staging, ctx.run)
    try:
        expectation = build(builder)
        entries = list(staging.rglob("*"))
        manifest = {}
        if not any(path.is_symlink() for path in entries):
            for path in entries:
                suffix = tuple(path.relative_to(staging).parts)
                if path.is_dir():
                    manifest[suffix] = (True, 0, None)
                elif path.is_file():
                    payload = path.read_bytes()
                    manifest[suffix] = (
                        False, len(payload), hashlib.sha256(payload).hexdigest(),
                    )
        complete = bool(
            type(expectation) is tuple
            and len(expectation) == 4
            and expectation[0] is True
            and not any(path.is_symlink() for path in entries)
            and expectation[1] == sum(path.is_dir() for path in entries)
            and expectation[2] == sum(path.is_file() for path in entries)
            and expectation[3] == crawl._expected_tree_digest(manifest)
            and not builder.faulted
        )
    except Exception:
        complete = False
    if not complete:
        shutil.rmtree(staging, ignore_errors=True)
        return False
    return _fake_publish_tree(ctx, destination, staging)


def _fake_built_but_unpublished_tree(ctx, destination, build):
    """Exercise a fake-Run build, then model a terminal publish refusal."""
    staging = _fake_stage_dir(destination)
    if staging is None:
        return False
    try:
        build(_FakeTreeBuilder(staging, ctx.run))
    except Exception:
        pass
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return False


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
        import os as _os

        real_fdopen = _os.fdopen

        def short_write(fd, mode="rb", *a, **k):               # simulate a partial write at the fd
            fh = real_fdopen(fd, mode, *a, **k)
            real_write = fh.write
            fh.write = lambda b: real_write(b[:3])
            return fh
        monkeypatch.setattr(_os, "fdopen", short_write)
        assert budget.publish_bytes(dest, data, digest=dig) is False
        monkeypatch.setattr(_os, "fdopen", real_fdopen)
        assert not dest.exists()                               # no half-file published
        assert list(tmp_path.glob("*.part-*")) == []           # and no temp left over
        assert list(tmp_path.glob(".*.part-*")) == []

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
        real_write = _FakeTreeBuilder.write_bytes

        def boom(self, data, *components):
            if pathlib.Path(components[-1]).suffix in (".ts", ".js"):
                raise OSError("no space left on device")
            return real_write(self, data, *components)
        monkeypatch.setattr(_FakeTreeBuilder, "write_bytes", boom)
        crawl._sourcemap_recover(ctx, led)
        monkeypatch.setattr(_FakeTreeBuilder, "write_bytes", real_write)
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
        assert _fake_publish_tree(ctx, active, staging) is True
        assert (active / "new.js").read_text() == "NEW" and not (active / "old.js").exists()
        assert not staging.exists() and not list(tmp_path.glob("recovered.retired-*"))

    def test_failure_moving_active_aside_keeps_the_old_tree(self, tmp_path, monkeypatch):
        active = tmp_path / "recovered"
        active.mkdir(); (active / "keep.js").write_text("KEEP")
        staging = tmp_path / "recovered.gen-1"
        staging.mkdir(); (staging / "new.js").write_text("NEW")
        ctx = _Ctx(tmp_path, [])
        monkeypatch.setattr(crawl.os, "replace", lambda *a: (_ for _ in ()).throw(OSError("boom")))
        assert _fake_publish_tree(ctx, active, staging) is False
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
        assert _fake_publish_tree(ctx, active, staging) is False
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
        assert _fake_publish_tree(ctx, active, staging) is False
        monkeypatch.setattr(crawl.os, "replace", real)
        retired = list(tmp_path.glob("recovered.retired-*"))
        assert len(retired) == 1
        assert (retired[0] / "precious.js").read_text() == "EVIDENCE"   # NOT deleted
        assert any("left at" in m for m in ctx.echoed)

    def test_failed_publication_is_reported_as_a_gap(self, tmp_path, monkeypatch):
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 1},
                               body=_map_body("a.ts", "CONTENT"))
        monkeypatch.setattr(crawl, "_owned_tree", _fake_built_but_unpublished_tree)
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
        real_write = _FakeTreeBuilder.write_bytes
        n = [0]

        def fail_on_third(self, data, *components):
            if pathlib.Path(components[-1]).suffix == ".ts":
                n[0] += 1
                if n[0] == 3:
                    raise OSError("no space left")
            return real_write(self, data, *components)
        monkeypatch.setattr(_FakeTreeBuilder, "write_bytes", fail_on_third)
        crawl._sourcemap_recover(ctx, led)
        monkeypatch.setattr(_FakeTreeBuilder, "write_bytes", real_write)
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
        monkeypatch.setattr(crawl, "_owned_tree", _fake_built_but_unpublished_tree)
        assert crawl._sourcemap_recover(ctx, led) is None

    def test_an_empty_generation_that_fails_to_publish_is_still_a_gap(self, tmp_path, monkeypatch):
        """Sizing publication by subdir count meant an EMPTY generation reported eligible=0/omitted=0 — no gap
        whatsoever — while the stale tree stayed on disk."""
        ctx = _Ctx(tmp_path, [])
        _run_crawl_js(tmp_path, monkeypatch, ctx, _Fetcher())
        led, _raw = crawl._js_download(ctx)
        monkeypatch.setattr(crawl, "_owned_tree", _fake_built_but_unpublished_tree)
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
        monkeypatch.setattr(crawl, "_owned_tree", _fake_built_but_unpublished_tree)
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

        def leave_temps(c, files, builder, expected_entries):
            for f in files:
                c.run.raw_path("crawl", "js-beautify", f.name + ".beauty").write_text("leftover")
                evidence = builder.copy_repository_file(
                    tuple(f.relative_to(c.run.dir).parts), f.name,
                )
                expected_entries[evidence.components] = (
                    False, evidence.size, evidence.sha256,
                )
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
        a = _fake_stage_dir(active)
        b = _fake_stage_dir(active)
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

        def counting(text, key, builder, tally):
            r = real_extract(text, key, builder, tally)
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
        assert _fake_publish_tree(ctx, active, tmp_path / "tree.gen-gone") is False
        assert _fake_publish_tree(ctx, active, None) is False
        assert (active / "precious.js").read_text() == "EVIDENCE"   # never wiped

    def test_stage_dir_returns_none_on_any_os_error(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pathlib.Path, "mkdir",
                            lambda self, **k: (_ for _ in ()).throw(PermissionError("read-only fs")))
        assert _fake_stage_dir(tmp_path / "tree") is None       # not just FileExistsError

    def test_sourcemap_lane_survives_an_unavailable_stage(self, tmp_path, monkeypatch):
        """The lane dereferenced _stage_dir()'s result unconditionally."""
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 1}, body=_map_body("a.ts", "C"))
        monkeypatch.setattr(crawl, "_owned_tree", lambda *a, **k: False)
        assert crawl._sourcemap_recover(ctx, led) is None        # no crash, nothing mineable
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        pub = [e for e in ev if e.get("measure") == "sourcemaps_published"][-1]
        assert pub["omitted"] == 1
        assert any("staging" in m for m in ctx.echoed)

    def test_js_lane_survives_an_unavailable_stage(self, tmp_path, monkeypatch):
        ctx = _Ctx(tmp_path, _urls({"a.ex.com": 2}))
        _run_crawl_js(tmp_path, monkeypatch, ctx, _Fetcher())
        led, raw_dir = crawl._js_download(ctx)
        monkeypatch.setattr(crawl, "_owned_tree", lambda *a, **k: False)
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
        monkeypatch.setattr(crawl, "_owned_tree", _fake_built_but_unpublished_tree)
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
        real_write = _FakeTreeBuilder.write_bytes
        n = [0]

        def fail_third(self, data, *components):
            if pathlib.Path(components[-1]).suffix == ".ts":
                n[0] += 1
                if n[0] == 3:
                    self.faulted = True
                    raise OSError("no space left")
            return real_write(self, data, *components)
        monkeypatch.setattr(_FakeTreeBuilder, "write_bytes", fail_third)
        monkeypatch.setattr(crawl.shutil, "rmtree", lambda *a, **k: None)   # cleanup silently does nothing
        recov = crawl._sourcemap_recover(ctx, led)
        monkeypatch.setattr(_FakeTreeBuilder, "write_bytes", real_write)
        assert recov is None
        # not one of the partial sources may be present — they were never inside the generation
        final = ctx.run.dir / "raw" / "crawl" / "sourcemaps" / "recovered"
        assert not final.exists()
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        ext = [e for e in ev if e.get("measure") == "sourcemaps_extracted"][-1]
        assert ext["omitted"] == 1 and "extract_error" in ext["reason"]

    def test_an_uncounted_staging_entry_blocks_publication(self, tmp_path, monkeypatch):
        """Defence in depth: anything in the generation without a counter behind it is removed, and if it
        cannot be removed, publication is refused rather than shipping uncounted evidence."""
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 1}, body=_map_body("a.ts", "OK"))
        real_extract = crawl._extract_payload

        def smuggle(text, key, builder, tally):
            got = real_extract(text, key, builder, tally)
            builder.write_bytes(b"GHOST EVIDENCE", "smuggled", "x.js")
            return got
        monkeypatch.setattr(crawl, "_extract_payload", smuggle)
        monkeypatch.setattr(crawl.shutil, "rmtree", lambda *a, **k: None)   # cannot be removed
        assert crawl._sourcemap_recover(ctx, led) is None        # publication refused
        assert not (ctx.run.dir / "raw" / "crawl" / "sourcemaps" / "recovered").exists()

    def test_an_uncounted_entry_that_can_be_removed_is_dropped(self, tmp_path, monkeypatch):
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 1}, body=_map_body("a.ts", "OK"))
        real_extract = crawl._extract_payload

        def smuggle(text, key, builder, tally):
            got = real_extract(text, key, builder, tally)
            builder.write_bytes(b"GHOST EVIDENCE", "smuggled", "x.js")
            return got
        monkeypatch.setattr(crawl, "_extract_payload", smuggle)
        recov = crawl._sourcemap_recover(ctx, led)
        assert recov is None
        assert not (ctx.run.dir / "raw" / "crawl" / "sourcemaps" / "recovered").exists()

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

        def vanish_one(text, key, builder, tally):
            got = real_extract(text, key, builder, tally)
            if got and not killed["done"]:                       # a counted payload disappears afterwards
                crawl.shutil.rmtree(builder.root / got)
                killed["done"] = True
            return got
        monkeypatch.setattr(crawl, "_extract_payload", vanish_one)
        assert crawl._sourcemap_recover(ctx, led) is None        # refused, not published incomplete
        assert not (ctx.run.dir / "raw" / "crawl" / "sourcemaps" / "recovered").exists()

    def test_a_counted_payload_replaced_by_a_file_refuses_publication(self, tmp_path, monkeypatch):
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 1}, body=_map_body("a.ts", "C"))
        real_extract = crawl._extract_payload

        def swap_for_file(text, key, builder, tally):
            got = real_extract(text, key, builder, tally)
            if got:
                crawl.shutil.rmtree(builder.root / got)
                (builder.root / got).write_text("not a directory")    # right name, wrong TYPE
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
        monkeypatch.setattr(crawl, "_owned_tree", lambda *a, **k: False)
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
        st = Run.create(tmp_path / "proj", "t", run_id="r1")
        events.configure(st.dir)
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 2}, body=_map_body("a.ts", "C"))
        events.configure(st.dir)                                  # events land in the run dir
        monkeypatch.setattr(crawl, "_owned_tree", lambda *a, **k: False)
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

        def drop_a_file(text, key, builder, tally):
            got = real_extract(text, key, builder, tally)
            if got:                                              # one recovered file vanishes afterwards
                victim = next(q for q in (builder.root / got).rglob("*") if q.is_file())
                victim.unlink()
            return got
        monkeypatch.setattr(crawl, "_extract_payload", drop_a_file)
        assert crawl._sourcemap_recover(ctx, led) is None
        assert not (ctx.run.dir / "raw" / "crawl" / "sourcemaps" / "recovered").exists()

    def test_a_symlinked_payload_directory_is_rejected(self, tmp_path, monkeypatch):
        t = TestSourcemapLane()
        ctx, led, f = t._setup(tmp_path, monkeypatch, {"a.ex.com": 1}, body=_map_body("a.ts", "C"))
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "planted.js").write_text("OUT OF TREE")
        real_extract = crawl._extract_payload

        def swap_for_symlink(text, key, builder, tally):
            got = real_extract(text, key, builder, tally)
            if got:
                crawl.shutil.rmtree(builder.root / got)
                (builder.root / got).symlink_to(outside)              # right name, a SYMLINK out of the tree
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

        def smuggle_file(text, key, builder, tally):
            got = real_extract(text, key, builder, tally)
            builder.write_bytes(b"uncounted", "stray.txt")
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
        monkeypatch.setattr(crawl, "_owned_tree", lambda *a, **k: False)
        assert crawl._sourcemap_recover(ctx, led) is None
        ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        pub = [e for e in ev if e.get("measure") == "sourcemaps_published"][-1]
        assert pub["omitted"] == 1


class TestTemplateDefectsRound10:
    """Tenth round: containment of the published tree, closed at the file level."""

    def _plant(self, monkeypatch, mutate):
        real_extract = crawl._extract_payload

        def wrapped(text, key, builder, tally):
            got = real_extract(text, key, builder, tally)
            if got:
                mutate(builder.root / got)
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

    def _capture(self, tmp_path, monkeypatch, **kw):
        seen = {}

        def fake_exec(tool, cmd, **kw):
            seen["tool"], seen["cmd"], seen["kw"] = tool, list(cmd), kw
            return type("R", (), {"tool": tool, "cmd": cmd, "status": crawl.Status.SUCCESS,
                                  "note": "", "duration": 0.0, "exit_code": 0})()

        monkeypatch.setattr(crawl, "exec_tool", fake_exec)
        _install_fake_xnl_repository(monkeypatch)
        ctx = _Ctx(tmp_path, [])
        src = tmp_path / "indir"
        src.mkdir(parents=True, exist_ok=True)
        (src / "a.js").write_text("var u = '/api/v1/users';\n")
        prep = crawl._xnl_blob(ctx, str(src), "t")
        crawl._xnl_run(ctx, "t", prep["blob"], prep["written"], **kw)
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
        assert "depth" not in inspect.signature(crawl._xnl_run).parameters
        assert "depth" not in inspect.signature(crawl._xnl_lane).parameters
        with pytest.raises(TypeError):
            crawl._xnl_run(None, "t", "blob", 0, depth=3)

    @pytest.mark.parametrize("injection", [
        {"extra": ["-d", "3"]}, {"extra": ["-insecure"]}, {"extra": ["-i", "https://evil.net"]},
        {"extra": []}, {"flags": ["-d", "3"]}, {"spo": True, "extra": ["-d", "3"]},
    ])
    def test_NO_free_form_flags_can_be_injected(self, tmp_path, monkeypatch, injection):
        """review-B-audit: `extra: list` was an unrestricted injection point into the command line of a lane
        whose contract is "never requests anything". A caller could pass `-d 3` or `-i <url>` straight
        through. An OPTION cannot smuggle a flag the way a list can."""
        with pytest.raises(TypeError):
            crawl._xnl_run(None, "t", "blob", 0, **injection)

    def test_the_COMMAND_is_exactly_the_allowed_flag_set(self, tmp_path, monkeypatch):
        """The strongest form of the same claim: enumerate what the tool is actually asked to do, so any
        future addition has to be stated here."""
        cmd = self._capture(tmp_path, monkeypatch)
        flags = [a for a in cmd if a.startswith("-")]
        # -owl/-os are requested only for SMALL input (they are permutation timekillers on a big blob), so
        # this fixture — a couple of hundred bytes — sees the full set.
        assert flags == ["-sp", "-sf", "-ow", "-o", "-op", "-all", "-mfs", "-owl", "-os", "-d"], flags
        assert cmd[0] == "xnLinkFinder" and cmd[cmd.index("-d") + 1] == "0", cmd

    def test_spo_is_the_ONLY_optional_flag(self, tmp_path, monkeypatch):
        """`-spo` is meaningful because `-sp` is always supplied; it is not dead, so it stays — as an
        option, not as free-form text."""
        without = self._capture(tmp_path, monkeypatch)
        with_spo = self._capture(tmp_path, monkeypatch, spo=True)
        assert "-spo" not in without and "-spo" in with_spo
        assert set(with_spo) - set(without) == {"-spo"}, (without, with_spo)

    def test_the_stdin_blob_starts_with_a_BLANK_LINE(self, tmp_path, monkeypatch):
        """A first line starting with `http`/`//` makes stdin a URL LIST and the tool crawls those URLs.
        The blank line forces offline content mode — the other half of "never requests anything"."""
        seen = {}

        def fake_exec(tool, cmd, **kw):
            seen["input"] = pathlib.Path(kw["input_file"]).read_bytes()
            return type("R", (), {"tool": tool, "cmd": cmd, "status": crawl.Status.SUCCESS,
                                  "note": "", "duration": 0.0, "exit_code": 0})()

        monkeypatch.setattr(crawl, "exec_tool", fake_exec)
        _install_fake_xnl_repository(monkeypatch)
        ctx = _Ctx(tmp_path, [])
        src = tmp_path / "indir2"
        src.mkdir(parents=True, exist_ok=True)
        (src / "urls.txt").write_text("https://example.com/a\nhttps://example.com/b\n")
        prep = crawl._xnl_blob(ctx, str(src), "t2")
        crawl._xnl_run(ctx, "t2", prep["blob"], prep["written"])
        assert seen["input"].startswith(b"\n"), seen["input"][:40]

    def test_no_CALL_SITE_asks_for_a_crawl(self):
        import inspect
        src = inspect.getsource(crawl)
        # step 3: the four inputs are COLLECTED and mined under one lifecycle, so the call sites are
        # appends. None of them may carry a crawl request.
        collected = [ln for ln in src.splitlines() if "xnl_units.append(" in ln]
        assert len(collected) == 4, collected   # waymore, sourcemap, js, katana-resp
        for line in collected:
            assert "depth" not in line, line
        runners = [ln for ln in src.splitlines()
                   if "_xnl_run(ctx," in ln and not ln.lstrip().startswith("def ")]
        assert len(runners) == 1, runners       # only the coordinator runs a unit

    def test_the_DOCS_do_not_teach_the_broken_form(self):
        """`-i <dir>` yields nothing at exit 0, and depth-3 is the RoE hazard above — a reader copying the
        docs must not reproduce either."""
        doc = pathlib.Path(__file__).parent.parent / "docs" / "example.md"
        text = doc.read_text()
        assert "xnLinkFinder -i " not in text, "the docs still teach `-i <dir>`"
        assert "-d 3" not in text and "-insecure" not in text, "the docs still teach the depth-3 crawl"


class TestXnLinkFinderOutputIsUntrusted:
    """review-B-audit step 2: xnLinkFinder's own `-sf` scope filter is not a boundary Quarry may rely on —
    its regex is unanchored at the end of the host, so for apex `acme.com` it admits `acme.com.evil.net`,
    `notacme.com` and `xacme.common.io` (measured, 8.2 ~line 1053). The lane used to ingest links "as-is,
    scope already applied by xnLinkFinder", so the inventory inherited the same defect the depth-3 crawl
    was contained for."""

    class _S:
        def in_scope(self, h):
            return h == "acme.com" or h.endswith(".acme.com")

        def is_oos(self, h):
            return h.startswith("oos.")

    @pytest.mark.parametrize("link", [
        "https://acme.com.evil.net/x",       # the tool's regex says IN
        "https://notacme.com/x",             # ...and for this one too
        "//acme.com.attacker.io/y",          # ...and scheme-relative is not an exemption
        "https://xacme.common.io/z",
        "https://evil.net/?u=acme.com",
    ])
    def test_a_link_the_TOOLS_filter_admits_is_not_an_endpoint(self, link):
        kind, _v = crawl._xnl_classify_link(link, self._S())
        assert kind == crawl.XNL_OOS, (link, kind)

    def test_an_OFF_SCOPE_scheme_relative_link_keeps_its_own_form(self):
        """Off scope either way — and we still do not know what scheme it was written under, so the
        evidence keeps the form it was found in."""
        kind, v = crawl._xnl_classify_link("//acme.com.attacker.io/y", self._S())
        assert (kind, v) == (crawl.XNL_OOS, "//acme.com.attacker.io/y")

    @pytest.mark.parametrize("link", ["https://www.acme.com/a", "http://acme.com/"])
    def test_a_genuinely_in_scope_link_IS_an_endpoint(self, link):
        assert crawl._xnl_classify_link(link, self._S())[0] == crawl.XNL_ENDPOINT, link

    def test_an_OOS_pattern_host_is_off_scope_even_under_the_apex(self):
        assert crawl._xnl_classify_link("https://oos.acme.com/x", self._S())[0] == crawl.XNL_OOS

    @pytest.mark.parametrize("link,kind", [
        ("/api/v1/users", "path"), ("./rel", "path"), ("../up", "path"),
        ("plainword", "malformed"), ("<stdin>", "ignored"), ("", "ignored"), ("   ", "ignored"),
        ("https://[bad/", "malformed"), ("http://a b.com/", "malformed"), ("x" * 5000, "malformed"),
        ("https://acme.com/\x00evil", "malformed"),
    ])
    def test_every_other_shape_is_classified_not_stored_blindly(self, link, kind):
        assert crawl._xnl_classify_link(link, self._S())[0] == kind, link

    def test_the_classifier_NEVER_raises(self):
        for junk in ["", "   ", "://", "//", "http://", "https://:80/", "%%%", "\x00", "a" * 4097]:
            crawl._xnl_classify_link(junk, self._S())

    @pytest.mark.parametrize("raw,ok", [
        ("user_id", True), ("q", True), ("a.b", True), ("x[0]", True), ("Auth-Token", True),
        ("", False), ("<stdin>", False), ("has space", False), ("a" * 65, False),
        ("=eq", False), ("{}", False), ("function(){}", False),
    ])
    def test_param_names_are_validated_too(self, raw, ok):
        assert crawl._xnl_classify_param(raw)[0] is ok, raw

    def test_UNDECODABLE_bytes_are_counted_not_replaced(self, tmp_path):
        """A whole-file `errors="replace"` decode turns invalid UTF-8 into replacement characters that then
        look like perfectly good values — mined minified sources produce exactly that."""
        f = tmp_path / "links.txt"
        f.write_bytes(b"https://www.acme.com/ok\n\xff\xfe/bad\nhttps://api.acme.com/two\n")
        lines, undecodable, unreadable = crawl._xnl_lines(f)
        assert lines == ["https://www.acme.com/ok", "https://api.acme.com/two"], lines
        assert undecodable == 1 and unreadable is False

    def test_a_MISSING_file_is_a_legitimate_zero(self, tmp_path):
        assert crawl._xnl_lines(tmp_path / "nope.txt") == ([], 0, False)

    def test_an_UNREADABLE_file_is_machinery_not_a_zero(self, tmp_path, monkeypatch):
        """review-B-audit-2#3: every OSError became `([], 0)`, so a file that EXISTS and cannot be read was
        indistinguishable from a tool that found nothing."""
        f = tmp_path / "links.txt"
        f.write_text("https://www.acme.com/ok\n")
        monkeypatch.setattr(pathlib.Path, "read_bytes",
                            lambda self: (_ for _ in ()).throw(OSError("permission denied")))
        assert crawl._xnl_lines(f) == ([], 0, True)


class TestXnLinkFinderIngestionBoundary:
    """The same claims, through `_xnl` itself: what reaches the store, and what is reported about what did
    not."""

    def _ingest(self, tmp_path, monkeypatch, links=(), params=()):
        def fake_exec(tool, cmd, **kw):
            out = {cmd[i + 1]: None for i, a in enumerate(cmd) if a in ("-o", "-op")}
            paths = list(out)
            pathlib.Path(paths[0]).write_text("\n".join(links) + ("\n" if links else ""))
            pathlib.Path(paths[1]).write_text("\n".join(params) + ("\n" if params else ""))
            return type("R", (), {"tool": tool, "cmd": cmd, "status": crawl.Status.SUCCESS,
                                  "note": "", "duration": 0.0, "exit_code": 0})()

        monkeypatch.setattr(crawl, "exec_tool", fake_exec)
        _install_fake_xnl_repository(monkeypatch)
        events.reset(); events.configure(tmp_path)
        ctx = _Ctx(tmp_path, [])
        ctx.scope = TestXnLinkFinderOutputIsUntrusted._S()
        ctx.scope.passive_only = False
        src = tmp_path / "in"
        src.mkdir(parents=True, exist_ok=True)
        (src / "a.js").write_text("x")
        prep = crawl._xnl_blob(ctx, str(src), "t")
        run = crawl._xnl_run(ctx, "t", prep["blob"], prep["written"])
        crawl._xnl_ingest(ctx, "t", crawl._xnl_snapshot(run["outs"]), blob=prep["blob"],
                          written=prep["written"])
        evs = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        return ctx.run.added, evs

    def test_only_IN_SCOPE_urls_become_endpoints(self, tmp_path, monkeypatch):
        added, _evs = self._ingest(tmp_path, monkeypatch, links=[
            "https://www.acme.com/keep", "https://acme.com.evil.net/drop", "https://notacme.com/drop"])
        endpoints = [r["value"] for k, r in added if k == "endpoint"]
        assert endpoints == ["https://www.acme.com/keep"], endpoints

    def test_an_OFF_SCOPE_url_is_review_evidence_never_surface(self, tmp_path, monkeypatch):
        added, _evs = self._ingest(tmp_path, monkeypatch, links=["https://acme.com.evil.net/x"])
        assert not [r for k, r in added if k == "endpoint"], added
        rev = [r for k, r in added if k == "review"]
        assert rev and rev[0]["klass"] == "oos-link" and rev[0]["value"] == "https://acme.com.evil.net/x"
        assert "never probed" in rev[0]["note"]

    def test_a_RELATIVE_path_says_it_has_no_origin(self, tmp_path, monkeypatch):
        """The concatenated stdin blob has already destroyed which file a path came from — a consumer must
        not be able to assume it belongs to some particular site."""
        added, _evs = self._ingest(tmp_path, monkeypatch, links=["/api/v1/users"])
        row = [r for k, r in added if k == "endpoint"][0]
        assert row["kind"] == "path" and row["origin"] == "unbound", row

    def test_MALFORMED_output_is_counted_not_stored(self, tmp_path, monkeypatch):
        added, evs = self._ingest(tmp_path, monkeypatch,
                                  links=["plainword", "https://[bad/", "https://www.acme.com/ok"])
        assert [r["value"] for k, r in added if k == "endpoint"] == ["https://www.acme.com/ok"]
        cov = [e for e in evs if e.get("measure") == "links"]
        assert cov and cov[0]["omitted"] == 2 and cov[0]["tested"] == 1, cov

    def test_the_coverage_names_each_disposition(self, tmp_path, monkeypatch):
        _added, evs = self._ingest(tmp_path, monkeypatch, links=[
            "https://www.acme.com/a", "/rel", "https://notacme.com/x", "junk"])
        cov = [e for e in evs if e.get("measure") == "links"][0]
        assert cov["eligible"] == 4 and cov["tested"] == 3 and cov["omitted"] == 1, cov
        assert "1 in-scope" in cov["reason"] and "1 off-scope" in cov["reason"], cov["reason"]

    def test_the_ledger_reports_what_the_boundary_REFUSED(self, tmp_path, monkeypatch):
        """A parser boundary that reports nothing is indistinguishable from a tool that emitted nothing."""
        _added, evs = self._ingest(tmp_path, monkeypatch,
                                   links=["https://notacme.com/x", "junk"], params=["ok_name", "not a param"])
        led = [e for e in evs if e.get("event") == "ledger"][0]
        assert led["xnl_rejected"]["links_unusable"] == 1
        assert led["xnl_rejected"]["off_scope_links"] == 1
        assert led["xnl_rejected"]["params_unusable"] == 1
        assert led["produced"]["oos_links"] == 1 and led["produced"]["endpoints"] == 0

    def test_UNUSABLE_params_never_reach_the_store(self, tmp_path, monkeypatch):
        added, _evs = self._ingest(tmp_path, monkeypatch,
                                   params=["user_id", "function(){}", "has space", "q"])
        got = sorted(r["value"] for k, r in added if k == "parameter")
        assert got == ["q", "user_id"], got


class TestXnLinkFinderAuthorityIsParsedNotGuessed:
    """review-B-audit-2#1: scope was decided on a regex-extracted host while consumers re-parse the RAW
    string. `https://acme.com:443@evil.net/graphql` read as `acme.com` and would have been fetched from
    `evil.net` — the same RoE class the containment commit removed, re-entering through the inventory."""

    class _S:
        def in_scope(self, h):
            return h == "acme.com" or h.endswith(".acme.com")

        def is_oos(self, h):
            return False

    def test_the_USERINFO_confusion_is_never_an_endpoint(self):
        kind, _v = crawl._xnl_classify_link("https://acme.com:443@evil.net/graphql", self._S())
        assert kind == crawl.XNL_CREDENTIAL

    @pytest.mark.parametrize("url", [
        "https://acme.com@evil.net/x", "https://acme.com:443@evil.net/x",
        "http://user:pass@acme.com/x", "https://acme.com%40evil.net@evil.net/x",
    ])
    def test_ANY_userinfo_is_never_surface(self, url):
        """review-B-audit-3#2: unsafe to CONTACT is not the same as worthless — a published credential is a
        finding. It gets its own disposition, and it is never an endpoint."""
        kind, v = crawl._xnl_classify_link(url, self._S())
        assert kind == crawl.XNL_CREDENTIAL, url
        assert v == url, "the evidence must be verbatim"

    @pytest.mark.parametrize("url", ["javascript:alert(1)", "data:text/html,<b>x", "file:///etc/passwd",
                                     "ftp://acme.com/x", "mailto:a@acme.com"])
    def test_only_HTTP_schemes_can_be_surface(self, url):
        assert crawl._xnl_classify_link(url, self._S())[0] == crawl.XNL_MALFORMED, url

    @pytest.mark.parametrize("url", ["https://acme.com:notaport/x", "https://acme.com:99999999/x",
                                     "https://[bad:/x"])
    def test_an_unparseable_AUTHORITY_is_refused(self, url):
        assert crawl._xnl_classify_link(url, self._S())[0] == crawl.XNL_MALFORMED, url

    def test_what_is_STORED_is_rebuilt_from_the_parsed_parts(self):
        """A downstream re-parse must not be able to disagree with the scope decision that admitted it."""
        kind, v = crawl._xnl_classify_link("https://WWW.ACME.COM:8443/a?b=1#f", self._S())
        assert kind == crawl.XNL_ENDPOINT
        assert v == "https://www.acme.com:8443/a?b=1#f", v
        from quarry_recon import normalize
        assert normalize.host_of_url(v) == "www.acme.com"

    def test_a_scheme_relative_link_keeps_its_UNKNOWN_scheme(self):
        """review-B-audit-3#1: a protocol-relative reference inherits the SOURCE DOCUMENT's scheme, and the
        blob destroyed which document that was. Manufacturing `https:` invents a target."""
        kind, v = crawl._xnl_classify_link("//api.acme.com/v1", self._S())
        assert kind == crawl.XNL_SCHEMELESS and v == "//api.acme.com/v1", v
        from quarry_recon import normalize
        assert normalize.host_of_url(v) == "", "a schemeless value must be uncontactable by construction"

    def test_the_MALICIOUS_url_reaches_no_consumer(self, tmp_path, monkeypatch):
        """End to end: it is not stored, so the GraphQL/actuator consumers never see it and nothing is
        requested."""
        ingest = TestXnLinkFinderIngestionBoundary()
        added, evs = ingest._ingest(tmp_path, monkeypatch,
                                    links=["https://acme.com:443@evil.net/graphql",
                                           "https://api.acme.com/graphql"])
        stored = [r["value"] for k, r in added if k == "endpoint"]
        assert stored == ["https://api.acme.com/graphql"], stored
        # the credential URL is retained as evidence, but never as something a lane can contact
        assert not [r for k, r in added if k == "endpoint" and "evil.net" in r["value"]], added
        rev = [r for k, r in added if k == "review"]
        assert rev and rev[0]["klass"] == "credential-in-url", rev
        assert rev[0]["value"] == "https://acme.com:443@evil.net/graphql", "evidence must be verbatim"

    @pytest.mark.parametrize("url,want", [
        ("https://acme.com:443@evil.net/g", ""),      # the confusion itself
        ("https://acme.com@evil.net/g", ""),
        ("http://user:pass@acme.com/x", ""),
        ("javascript:alert(1)", ""),                  # no host to contact
        ("data:text/html,<b>", ""),
        ("ftp://acme.com/x", ""),                     # a host, but not a scheme this project speaks
        ("file:///etc/passwd", ""),
        ("https://acme.com:notaport/x", ""),
        ("https://[bad:/x", ""),
        ("", ""),
        ("https://www.acme.com/a", "www.acme.com"),
        ("http://ACME.com:8080/x", "acme.com"),
        ("https://[::1]:8443/x", "::1"),
    ])
    def test_the_SHARED_helper_is_the_ONE_authority(self, url, want):
        """`normalize.host_of_url` is what every scope check in the repo runs through — including
        `fetch.scoped_get`, which makes the request. The boundary defers to it rather than keeping a second
        copy of the same decision."""
        from quarry_recon import normalize
        assert normalize.host_of_url(url) == want, url


class TestXnLinkFinderAcceptanceIsNotStorage:
    """review-B-audit-2#2: the counters incremented only when `add()` reported a NEW row, so an endpoint
    jsluice had already stored made the parser look like it had rejected it."""

    def _ingest_with_store(self, tmp_path, monkeypatch, links, already):
        def fake_exec(tool, cmd, **kw):
            pathlib.Path(cmd[cmd.index("-o") + 1]).write_text("\n".join(links) + "\n")
            pathlib.Path(cmd[cmd.index("-op") + 1]).write_text("")
            return type("R", (), {"tool": tool, "cmd": cmd, "status": crawl.Status.SUCCESS,
                                  "note": "", "duration": 0.0, "exit_code": 0})()

        monkeypatch.setattr(crawl, "exec_tool", fake_exec)
        _install_fake_xnl_repository(monkeypatch)
        events.reset(); events.configure(tmp_path)
        ctx = _Ctx(tmp_path, [])
        ctx.scope = TestXnLinkFinderAuthorityIsParsedNotGuessed._S()
        ctx.scope.passive_only = False
        seen = set(already)

        def add(kind, rec):
            key = (kind, rec.get("value"))
            new = key not in seen
            seen.add(key)
            ctx.run.added.append((kind, rec))
            return new

        ctx.run.add = add
        src = tmp_path / "in"
        src.mkdir(parents=True, exist_ok=True)
        (src / "a.js").write_text("x")
        prep = crawl._xnl_blob(ctx, str(src), "t")
        run = crawl._xnl_run(ctx, "t", prep["blob"], prep["written"])
        crawl._xnl_ingest(ctx, "t", crawl._xnl_snapshot(run["outs"]), blob=prep["blob"],
                          written=prep["written"])
        return [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]

    def test_an_endpoint_ANOTHER_LANE_already_stored_still_counts_as_accepted(self, tmp_path, monkeypatch):
        evs = self._ingest_with_store(tmp_path, monkeypatch, ["https://api.acme.com/x"],
                                      already={("endpoint", "https://api.acme.com/x")})
        cov = [e for e in evs if e.get("measure") == "links"][0]
        assert (cov["eligible"], cov["tested"], cov["omitted"]) == (1, 1, 0), cov

    def test_NOVELTY_is_reported_separately(self, tmp_path, monkeypatch):
        evs = self._ingest_with_store(tmp_path, monkeypatch,
                                      ["https://api.acme.com/x", "https://api.acme.com/y"],
                                      already={("endpoint", "https://api.acme.com/x")})
        led = [e for e in evs if e.get("event") == "ledger"][0]
        assert led["produced"]["endpoints"] == 2, led          # accepted
        assert led["xnl_stored"]["endpoints_new"] == 1, led    # ...one of them new to the store


class TestXnLinkFinderBoundarySemantics:
    """review-B-audit-3: four boundary meanings that were wrong — an invented scheme, a discarded finding,
    a masked read failure, and noise counted as damage."""

    _S = TestXnLinkFinderAuthorityIsParsedNotGuessed._S

    def _ingest(self, tmp_path, monkeypatch, links=(), params=()):
        return TestXnLinkFinderIngestionBoundary()._ingest(tmp_path, monkeypatch, links=links, params=params)

    # ── #1 scheme-relative ────────────────────────────────────────────────────────────────────────────
    def test_a_scheme_relative_link_is_stored_UNBOUND_on_both_axes(self, tmp_path, monkeypatch):
        added, _evs = self._ingest(tmp_path, monkeypatch, links=["//api.acme.com/graphql"])
        row = [r for k, r in added if k == "endpoint"][0]
        assert row["value"] == "//api.acme.com/graphql", "the scheme must not be invented"
        assert row["kind"] == "scheme-relative" and row["scheme"] == "unbound", row
        assert row["origin"] == "unbound", row

    def test_NO_https_is_manufactured_anywhere(self, tmp_path, monkeypatch):
        added, _evs = self._ingest(tmp_path, monkeypatch, links=["//api.acme.com/graphql"])
        assert "https://api.acme.com/graphql" not in json.dumps(added), added

    def test_a_scheme_relative_value_cannot_become_a_request(self):
        """The structural guarantee, not a promise: the authority helper every request path uses answers ""
        for a schemeless value, so a scope check refuses it."""
        from quarry_recon import normalize
        assert normalize.host_of_url("//api.acme.com/graphql") == ""

    # ── #2 credentials are evidence ───────────────────────────────────────────────────────────────────
    def test_a_credential_URL_is_kept_VERBATIM_as_review(self, tmp_path, monkeypatch):
        added, _evs = self._ingest(tmp_path, monkeypatch, links=["https://user:pass@acme.com/private"])
        assert not [r for k, r in added if k == "endpoint"], added
        rev = [r for k, r in added if k == "review"][0]
        assert rev["klass"] == "credential-in-url"
        assert rev["value"] == "https://user:pass@acme.com/private", "a discovered secret is not masked"
        assert "never contacted" in rev["note"]

    def test_a_credential_URL_is_counted_as_evidence_not_damage(self, tmp_path, monkeypatch):
        _added, evs = self._ingest(tmp_path, monkeypatch, links=["https://user:pass@acme.com/x"])
        cov = [e for e in evs if e.get("measure") == "links"][0]
        assert (cov["eligible"], cov["tested"], cov["omitted"]) == (1, 1, 0), cov
        led = [e for e in evs if e.get("event") == "ledger"][0]
        assert led["produced"]["credential_urls"] == 1, led

    # ── #3 unreadable vs absent ───────────────────────────────────────────────────────────────────────
    def test_a_read_that_fails_is_NOT_reported_as_absent(self, tmp_path, monkeypatch):
        """`exists()` collapses a stat/permission failure to False and adds a check/read race — the ERROR
        is what distinguishes the two."""
        f = tmp_path / "links.txt"
        f.write_text("x\n")
        monkeypatch.setattr(pathlib.Path, "read_bytes",
                            lambda self: (_ for _ in ()).throw(PermissionError("denied")))
        assert crawl._xnl_lines(f) == ([], 0, True)

    def test_a_genuinely_absent_file_is_a_zero(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pathlib.Path, "read_bytes",
                            lambda self: (_ for _ in ()).throw(FileNotFoundError("nope")))
        assert crawl._xnl_lines(tmp_path / "gone.txt") == ([], 0, False)

    def test_NO_exists_precheck_remains(self):
        import inspect
        src = inspect.getsource(crawl._xnl_lines)
        assert ".exists()" not in src, src

    def test_an_unreadable_file_says_so_in_the_ledger(self, tmp_path, monkeypatch):
        def fake_exec(tool, cmd, **kw):
            return type("R", (), {"tool": tool, "cmd": cmd, "status": crawl.Status.SUCCESS,
                                  "note": "", "duration": 0.0, "exit_code": 0})()

        monkeypatch.setattr(crawl, "exec_tool", fake_exec)
        _install_fake_xnl_repository(monkeypatch)
        monkeypatch.setattr(pathlib.Path, "read_bytes",
                            lambda self: (_ for _ in ()).throw(PermissionError("denied"))
                            if self.name.endswith(("_links.txt", "_params.txt")) else b"")
        events.reset(); events.configure(tmp_path)
        ctx = _Ctx(tmp_path, [])
        ctx.scope = self._S()
        ctx.scope.passive_only = False
        src = tmp_path / "in"
        src.mkdir(parents=True, exist_ok=True)
        (src / "a.js").write_text("x")
        prep = crawl._xnl_blob(ctx, str(src), "t")
        run = crawl._xnl_run(ctx, "t", prep["blob"], prep["written"])
        crawl._xnl_ingest(ctx, "t", crawl._xnl_snapshot(run["outs"]), blob=prep["blob"],
                          written=prep["written"])
        evs = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        led = [e for e in evs if e.get("event") == "ledger"][0]
        assert led["xnl_unreadable"] == {"links": True, "params": True, "wordlist": False}, led
        cov = [e for e in evs if e.get("measure") == "links"][0]
        assert "UNREADABLE" in cov["reason"], cov

    # ── #4 ignored noise is not damage ────────────────────────────────────────────────────────────────
    def test_BLANK_lines_and_the_stdin_token_are_neither_finding_nor_error(self, tmp_path, monkeypatch):
        _added, evs = self._ingest(tmp_path, monkeypatch,
                                   links=["", "<stdin>", "   ", "https://www.acme.com/real"])
        cov = [e for e in evs if e.get("measure") == "links"][0]
        assert (cov["eligible"], cov["tested"], cov["omitted"]) == (1, 1, 0), cov
        led = [e for e in evs if e.get("event") == "ledger"][0]
        assert led["xnl_rejected"]["links_ignored"] == 3, led
        assert led["xnl_rejected"]["links_unusable"] == 0, led

    def test_REAL_damage_is_still_counted_as_damage(self, tmp_path, monkeypatch):
        _added, evs = self._ingest(tmp_path, monkeypatch, links=["<stdin>", "plainword", "https://[bad/"])
        led = [e for e in evs if e.get("event") == "ledger"][0]
        assert led["xnl_rejected"]["links_ignored"] == 1 and led["xnl_rejected"]["links_unusable"] == 2, led


class TestSchemeRelativeIsNotAnExemption:
    """review-B-audit-4#1: the schemeless branch returned BEFORE the authority was parsed, so
    `//acme.com.attacker.io/y` became an `endpoint` (D12's inventory poisoning, reopened) and
    `//user:pass@evil.net/g` missed the credential classification. The temporary scheme used to PARSE such a
    reference decides nothing about what is stored."""

    class _S:
        """Scope with a real OOS rule, so "under our apex but excluded" is an actual case here."""

        def in_scope(self, h):
            return h == "acme.com" or h.endswith(".acme.com")

        def is_oos(self, h):
            return h.startswith("oos.")

    def _ingest(self, tmp_path, monkeypatch, links):
        return TestXnLinkFinderIngestionBoundary()._ingest(tmp_path, monkeypatch, links=links)

    def test_an_OFF_SCOPE_scheme_relative_link_never_reaches_the_endpoint_store(self, tmp_path, monkeypatch):
        added, _evs = self._ingest(tmp_path, monkeypatch, links=["//acme.com.attacker.io/y"])
        assert not [r for k, r in added if k == "endpoint"], added
        rev = [r for k, r in added if k == "review"][0]
        assert rev["klass"] == "oos-link" and rev["value"] == "//acme.com.attacker.io/y", rev

    def test_a_scheme_relative_CREDENTIAL_url_is_evidence_not_surface(self, tmp_path, monkeypatch):
        added, _evs = self._ingest(tmp_path, monkeypatch, links=["//user:pass@evil.net/graphql"])
        assert not [r for k, r in added if k == "endpoint"], added
        rev = [r for k, r in added if k == "review"][0]
        assert rev["klass"] == "credential-in-url"
        assert rev["value"] == "//user:pass@evil.net/graphql", "verbatim, and never given a scheme"

    def test_an_IN_SCOPE_scheme_relative_link_is_still_unbound(self, tmp_path, monkeypatch):
        added, _evs = self._ingest(tmp_path, monkeypatch, links=["//api.acme.com/v1"])
        row = [r for k, r in added if k == "endpoint"][0]
        assert row["value"] == "//api.acme.com/v1" and row["scheme"] == "unbound", row

    @pytest.mark.parametrize("link,kind", [
        ("//oos.acme.com/x", "oos"),            # an OOS pattern under our own apex
        ("//notacme.com/z", "oos"),
        ("//[bad:/x", "malformed"),
        ("//acme.com:notaport/x", "malformed"),
        ("//api.acme.com/v1", "schemeless"),
    ])
    def test_every_authority_rule_applies_identically(self, link, kind):
        assert crawl._xnl_classify_link(link, self._S())[0] == kind, link

    def test_the_PARSING_scheme_is_never_stored(self, tmp_path, monkeypatch):
        added, _evs = self._ingest(tmp_path, monkeypatch,
                                   links=["//api.acme.com/v1", "//acme.com.attacker.io/y",
                                          "//user:pass@evil.net/g"])
        assert "https://api.acme.com" not in json.dumps(added), added
        assert "https://acme.com.attacker.io" not in json.dumps(added), added
        assert "https://user:pass@evil.net" not in json.dumps(added), added


class TestXnLinkFinderHasOneLifecycle:
    """review-B-audit#D3: `_xnl` ran up to four times per phase through bare `exec_tool`, so the source
    emitted coverage and ledger events but NEVER a terminal, and its registry entry was never consulted.
    Four independent `run_contract` wraps would have been worse — competing terminals under one id."""

    class _S:
        def in_scope(self, h):
            return h == "acme.com" or h.endswith(".acme.com")

        def is_oos(self, h):
            return False

    def _lane(self, tmp_path, monkeypatch, units, status=None, links=("https://api.acme.com/x",),
              content=None, installed=True, params=(), store_novel=True, engine="8.2", add=None):
        calls = []

        def fake_exec(tool, cmd, **kw):
            calls.append(cmd)
            pathlib.Path(cmd[cmd.index("-o") + 1]).write_text("\n".join(links) + "\n")
            pathlib.Path(cmd[cmd.index("-op") + 1]).write_text("\n".join(params) + ("\n" if params else ""))
            # MEASURED (8.2, empty stdin blob): every REQUESTED artifact is created — links/params/
            # wordlist as EMPTY FILES, secrets as `[]`. A fixture that writes fewer is not the tool.
            if "-os" in cmd:
                pathlib.Path(cmd[cmd.index("-os") + 1]).write_text("[]")
            if "-owl" in cmd:
                pathlib.Path(cmd[cmd.index("-owl") + 1]).write_text("")
            return type("R", (), {"tool": tool, "cmd": cmd,
                                  "status": status or crawl.Status.SUCCESS,
                                  "note": "", "duration": 0.0, "exit_code": 0})()

        monkeypatch.setattr(crawl, "exec_tool", fake_exec)
        monkeypatch.setattr(crawl, "have", lambda t: installed)
        monkeypatch.setattr(crawl, "_xnl_engine", lambda: engine)
        events.reset(); events.configure(tmp_path)
        ctx = _Ctx(tmp_path, [])
        ctx.scope = self._S()
        ctx.scope.passive_only = False
        if not store_novel:                       # every row already present: acceptance without novelty
            _add = ctx.run.add
            ctx.run.add = lambda *a, **k: (_add(*a, **k), False)[1]
        if add is not None:
            ctx.run.add = add
        _install_fake_xnl_repository(monkeypatch)
        prepared = []
        for name in units:
            d = tmp_path / "in" / name
            d.mkdir(parents=True, exist_ok=True)
            (d / "a.js").write_text(content if content is not None else f"var x = '/{name}';")
            prepared.append((str(d), name, False))
        crawl._xnl_lane(ctx, prepared)
        log = tmp_path / "events.jsonl"
        evs = [json.loads(l) for l in log.read_text().splitlines()] if log.exists() else []
        return calls, evs, ctx

    def test_ONE_start_and_ONE_finish_for_four_inputs(self, tmp_path, monkeypatch):
        _calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js", "sourcemap", "katana", "waymore"])
        sid = "crawl.xnlinkfinder"
        starts = [e for e in evs if e.get("source_id") == sid and e.get("event") == events.TOOL_START]
        fins = [e for e in evs if e.get("source_id") == sid and e.get("event") == events.TOOL_FINISH]
        assert len(starts) == 1 and len(fins) == 1, (starts, fins)
        assert starts[0]["input_total"] == 4, starts

    def test_each_input_is_an_INDEPENDENTLY_identified_unit(self, tmp_path, monkeypatch):
        _calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js", "sourcemap"])
        prog = [e for e in evs if e.get("event") == events.TOOL_PROGRESS]
        assert len(prog) == 2, prog
        # identity is per-unit and lives on the ledger; the progress events carry the index
        assert [e.get("current_index") for e in prog] == [1, 2], prog
        cov = [e for e in evs if e.get("measure") == "files"]
        assert len({e["unit"] for e in cov}) == 2, "two inputs shared one coverage unit"

    def test_the_unit_identity_is_the_BOUNDED_INPUT_ARTIFACT(self, tmp_path, monkeypatch):
        """review-B-audit-5#7: identity is the blob — the bytes that will actually be mined, already
        reflecting the byte cap and the path order that selected them — plus every output-affecting
        setting."""
        events.reset(); events.configure(tmp_path)
        ctx = _Ctx(tmp_path, [])
        ctx.scope = self._S()
        _install_fake_xnl_repository(monkeypatch)
        a = tmp_path / "a"
        a.mkdir()
        (a / "f.js").write_text("one")
        prep1 = crawl._xnl_blob(ctx, str(a), "t")
        id1 = crawl._xnl_unit_identity(ctx, "t", False, prep1["digest"], "8.2")
        (a / "f.js").write_text("two")                      # same name, same length, different bytes
        prep2 = crawl._xnl_blob(ctx, str(a), "t")
        id2 = crawl._xnl_unit_identity(ctx, "t", False, prep2["digest"], "8.2")
        assert id1 != id2, "a same-size edit must change the identity"

    def test_identity_covers_the_OUTPUT_AFFECTING_settings(self, tmp_path, monkeypatch):
        events.reset(); events.configure(tmp_path)
        ctx = _Ctx(tmp_path, [])
        ctx.scope = self._S()
        base = crawl._xnl_unit_identity(ctx, "t", False, "deadbeef", "8.2")
        assert crawl._xnl_unit_identity(ctx, "t", True, "deadbeef", "8.2") != base, "spo changes the output"
        ctx.profile.apex_domains = ["other.com"]
        assert crawl._xnl_unit_identity(ctx, "t", False, "deadbeef", "8.2") != base, "scope changes the output"
        monkeypatch.setattr(crawl, "XNL_MAX_INPUT", crawl.XNL_MAX_INPUT + 1)
        ctx.profile.apex_domains = ["ex.com"]
        assert crawl._xnl_unit_identity(ctx, "t", False, "deadbeef", "8.2") != base, \
            "the input cap changes WHICH BYTES are mined"
        monkeypatch.undo()
        assert crawl._xnl_unit_identity(ctx, "t", False, "deadbeef", "8.3") != base, "the engine changes it"

    def test_an_UNREGISTERED_source_is_blocked_not_executed(self, tmp_path, monkeypatch):
        from quarry_recon import contract
        monkeypatch.setattr(crawl, "registered",
                            lambda sid: contract.registered("crawl.definitely-not-registered"))
        calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js"])
        assert calls == [], "an unregistered source still ran the tool"
        assert [e for e in evs if e.get("event") == "tool_blocked"], evs

    def test_a_MISSING_tool_is_a_recorded_skip(self, tmp_path, monkeypatch):
        calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js"], installed=False)
        assert calls == [], calls
        fin = [e for e in evs if e.get("event") == events.TOOL_FINISH]
        assert fin and fin[0]["status"] == "skipped", fin

    def test_NO_units_is_no_lifecycle_at_all(self, tmp_path, monkeypatch):
        _calls, evs, _ctx = self._lane(tmp_path, monkeypatch, [])
        assert [e for e in evs if e.get("source_id") == "crawl.xnlinkfinder"] == [], evs


class TestXnLinkFinderUnitsResume:
    """A unit that already mined exactly these bytes is not re-mined; one whose extraction did not finish
    is never recorded, so the next run redoes it."""

    _lane = TestXnLinkFinderHasOneLifecycle._lane
    _S = TestXnLinkFinderHasOneLifecycle._S

    def test_an_UNCHANGED_input_is_replayed_not_re_mined(self, tmp_path, monkeypatch):
        calls, _evs, _ctx = self._lane(tmp_path, monkeypatch, ["js"])
        assert len(calls) == 1
        calls2, evs2, _ctx2 = self._lane(tmp_path, monkeypatch, ["js"])
        assert calls2 == [], f"the same bytes were mined again: {calls2}"
        cov = [e for e in evs2 if e.get("measure") == "units"]
        assert cov and "replayed" in cov[0]["reason"], cov

    def test_a_CHANGED_input_is_mined_again(self, tmp_path, monkeypatch):
        self._lane(tmp_path, monkeypatch, ["js"], content="var x = '/one';")
        calls, _evs, _ctx = self._lane(tmp_path, monkeypatch, ["js"], content="var x = '/two';")
        assert len(calls) == 1, "a changed input was skipped"

    @pytest.mark.parametrize("status", ["timed_out", "failed", "partial"])
    def test_an_INCOMPLETE_extraction_is_never_recorded(self, tmp_path, monkeypatch, status):
        st = getattr(crawl.Status, status.upper())
        calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js"], status=st)
        assert len(calls) == 1
        cov = [e for e in evs if e.get("measure") == "units"]
        assert cov and cov[0]["omitted"] == 1 and "did NOT complete" in cov[0]["reason"], cov
        # ...and the next run re-mines it
        calls2, _evs2, _ctx2 = self._lane(tmp_path, monkeypatch, ["js"], status=st)
        assert len(calls2) == 1, "an unfinished unit was treated as done"

    def test_evidence_from_an_incomplete_unit_is_still_KEPT(self, tmp_path, monkeypatch):
        _calls, _evs, ctx = self._lane(tmp_path, monkeypatch, ["js"], status=crawl.Status.TIMED_OUT)
        assert [r for k, r in ctx.run.added if k == "endpoint"], ctx.run.added

    def test_the_TERMINAL_says_partial_when_evidence_survived_a_failure(self, tmp_path, monkeypatch):
        _calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js"], status=crawl.Status.TIMED_OUT)
        fin = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
        assert fin["status"] == "partial" and "did not finish" in fin["reason"], fin

    def test_the_TERMINAL_says_failed_when_nothing_survived(self, tmp_path, monkeypatch):
        _calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js"], status=crawl.Status.FAILED, links=[])
        fin = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
        assert fin["status"] == "failed", fin

    def test_a_CLEAN_run_reports_success_with_what_it_produced(self, tmp_path, monkeypatch):
        _calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js"])
        fin = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
        # review-B-audit-5#4: production covers EVERY evidence category, not links alone
        assert fin["status"] == "success", fin
        assert fin["produced"] == {"references": 1, "params": 0, "wordlist": 0, "secrets": 0}, fin

    def test_state_that_did_NOT_persist_is_reported(self, tmp_path, monkeypatch):
        from quarry_recon import budget as _b
        real_save = _b.Ledger.save
        monkeypatch.setattr(_b.Ledger, "save", lambda self: False)
        monkeypatch.setattr(_b.Ledger, "durable", property(lambda self: False))
        _calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js"])
        fin = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
        assert fin["status"] == "partial", fin
        # the note names what is actually lost, and does not disown units an earlier snapshot still owns
        assert "the journal is unusable and the snapshot failed" in fin["reason"], fin
        assert "still replay" in fin["reason"], fin
        monkeypatch.setattr(_b.Ledger, "save", real_save)


class TestXnLinkFinderResumesAcrossREALRUNS:
    """review-B-audit-5#1: the unit ledger lived under `ctx.run.dir`, which `Run.create()` mints fresh for
    every run — so "resume" was empty on every production invocation, and only a fixture reusing one
    tmp_path could see it work. The same single-run blindness that hid the Whoxy cross-run defect.

    And `has()` alone was a SKIP: no output was read, no entity re-ingested, so a resumed run silently
    lost every endpoint the earlier run had found."""

    class _S:
        def in_scope(self, h):
            return h == "acme.com" or h.endswith(".acme.com")

        def is_oos(self, h):
            return False

    def _run_once(self, project, monkeypatch, indir, links=("https://api.acme.com/x",), params=("q",),
                  status=None):
        from quarry_recon import store
        run = store.Run.create(project, "acme.com")
        events.reset(); events.configure(run.dir)
        calls = []

        def fake_exec(tool, cmd, **kw):
            calls.append(cmd)
            pathlib.Path(cmd[cmd.index("-o") + 1]).write_text("\n".join(links) + "\n")
            pathlib.Path(cmd[cmd.index("-op") + 1]).write_text("\n".join(params) + "\n")
            if "-os" in cmd:
                pathlib.Path(cmd[cmd.index("-os") + 1]).write_text("[]")   # the MEASURED no-find shapes
            if "-owl" in cmd:
                pathlib.Path(cmd[cmd.index("-owl") + 1]).write_text("")
            return type("R", (), {"tool": tool, "cmd": cmd, "status": status or crawl.Status.SUCCESS,
                                  "note": "", "duration": 0.0, "exit_code": 0})()

        monkeypatch.setattr(crawl, "exec_tool", fake_exec)
        monkeypatch.setattr(crawl, "have", lambda t: True)
        monkeypatch.setattr(crawl, "_xnl_engine", lambda: "8.2")
        added = []
        ctx = _Ctx(run.dir, [])
        ctx.run.dir = run.dir
        ctx.run.project_dir = run.project_dir
        ctx.run.add = lambda kind, rec: (added.append((kind, rec)), True)[1]
        ctx.run.raw_path = lambda ph, tl, nm: (run.dir / "raw" / ph / tl / nm)
        (run.dir / "raw" / "crawl" / "xnLinkFinder").mkdir(parents=True, exist_ok=True)
        ctx.scope = self._S()
        ctx.scope.passive_only = False
        _install_fake_xnl_repository(monkeypatch)
        crawl._xnl_lane(ctx, [(str(indir), "js", False)])
        evs = [json.loads(l) for l in (run.dir / "events.jsonl").read_text().splitlines()]
        return calls, added, evs

    def _project(self, tmp_path):
        project = tmp_path / "project"
        project.mkdir(parents=True, exist_ok=True)
        indir = tmp_path / "js"
        indir.mkdir(parents=True, exist_ok=True)
        (indir / "a.js").write_text("var u = '/api';")
        return project, indir

    def test_a_SECOND_REAL_RUN_does_not_re_mine(self, tmp_path, monkeypatch):
        project, indir = self._project(tmp_path)
        calls1, _a1, _e1 = self._run_once(project, monkeypatch, indir)
        calls2, _a2, evs2 = self._run_once(project, monkeypatch, indir)
        assert len(calls1) == 1 and calls2 == [], f"the same bytes were mined again: {calls2}"
        cov = [e for e in evs2 if e.get("measure") == "units"]
        assert cov and "replayed" in cov[0]["reason"], cov

    def test_a_SECOND_REAL_RUN_still_gets_the_EVIDENCE(self, tmp_path, monkeypatch):
        """The difference between replay and skip: the new run's store must hold what the first run found."""
        project, indir = self._project(tmp_path)
        _c1, added1, _e1 = self._run_once(project, monkeypatch, indir)
        _c2, added2, _e2 = self._run_once(project, monkeypatch, indir)
        first = sorted(r["value"] for k, r in added1 if k == "endpoint")
        second = sorted(r["value"] for k, r in added2 if k == "endpoint")
        assert first == ["https://api.acme.com/x"], first
        assert second == first, f"a resumed run lost the evidence: {second}"
        assert [r["value"] for k, r in added2 if k == "parameter"] == ["q"], added2

    def test_a_CHANGED_input_is_mined_again_across_runs(self, tmp_path, monkeypatch):
        project, indir = self._project(tmp_path)
        self._run_once(project, monkeypatch, indir)
        (indir / "a.js").write_text("var u = '/changed';")
        calls, _added, _evs = self._run_once(project, monkeypatch, indir)
        assert len(calls) == 1, "a changed input was skipped"

    def test_a_CORRUPTED_bundle_is_re_mined_not_trusted(self, tmp_path, monkeypatch):
        project, indir = self._project(tmp_path)
        self._run_once(project, monkeypatch, indir)
        state = project / "recon" / "state" / "xnlinkfinder" / f"v{crawl.XNL_PARSER_SCHEMA}"
        bundles = [p for p in state.glob("*_links.txt")]
        assert bundles, list(state.iterdir())
        bundles[0].write_text("https://evil.net/injected\n")     # digest no longer matches the manifest
        calls, added, _evs = self._run_once(project, monkeypatch, indir)
        assert len(calls) == 1, "a tampered bundle was replayed"
        assert not [r for k, r in added if k == "endpoint" and "evil.net" in r["value"]], added

    def test_an_INCOMPLETE_unit_is_not_owned_across_runs(self, tmp_path, monkeypatch):
        project, indir = self._project(tmp_path)
        self._run_once(project, monkeypatch, indir, status=crawl.Status.TIMED_OUT)
        calls, _added, _evs = self._run_once(project, monkeypatch, indir, status=crawl.Status.SUCCESS)
        assert len(calls) == 1, "an unfinished unit was treated as done by the next run"

    def test_the_state_lives_in_the_PROJECT_not_the_run(self, tmp_path, monkeypatch):
        project, indir = self._project(tmp_path)
        self._run_once(project, monkeypatch, indir)
        state = project / "recon" / "state" / "xnlinkfinder" / f"v{crawl.XNL_PARSER_SCHEMA}"
        assert state.exists() and any(state.iterdir()), list(project.rglob("*"))


class TestXnLinkFinderUnitCompleteness:
    """review-B-audit-5#2/#3/#5: a truncated input owned; a lost journal called durable; one unit's
    exception aborting the phase."""

    _S = TestXnLinkFinderResumesAcrossREALRUNS._S
    _lane = TestXnLinkFinderHasOneLifecycle._lane

    def test_a_BYTE_CAPPED_input_is_never_recorded_complete(self, tmp_path, monkeypatch):
        monkeypatch.setattr(crawl, "XNL_MAX_INPUT", 8)          # the fixture is bigger than this
        calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js"])
        assert len(calls) == 1
        cov = [e for e in evs if e.get("measure") == "units"]
        assert cov and cov[0]["omitted"] == 1 and "input incomplete" in cov[0]["reason"], cov
        calls2, _evs2, _ctx2 = self._lane(tmp_path, monkeypatch, ["js"])
        assert len(calls2) == 1, "a truncated input was owned, freezing the omitted suffix forever"

    def test_an_UNREADABLE_input_file_is_never_recorded_complete(self, tmp_path, monkeypatch):
        real = pathlib.Path.open

        def picky(self, *a, **k):
            if self.name == "a.js" and "b" in (a[0] if a else k.get("mode", "")):
                raise PermissionError("denied")
            return real(self, *a, **k)

        monkeypatch.setattr(pathlib.Path, "open", picky)
        calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js"])
        cov = [e for e in evs if e.get("measure") == "units"]
        assert cov and cov[0]["omitted"] == 1, cov

    def test_a_UNIT_EXCEPTION_does_not_abort_the_others(self, tmp_path, monkeypatch):
        real_ingest = crawl._xnl_ingest
        seen = []

        def boom(ctx, tag, outs, **kw):
            seen.append(tag)
            if tag == "js":
                raise RuntimeError("ingest exploded")
            return real_ingest(ctx, tag, outs, **kw)

        monkeypatch.setattr(crawl, "_xnl_ingest", boom)
        _calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js", "sourcemap"])
        assert seen == ["js", "sourcemap"], "the second unit never ran"
        fin = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
        assert "ingest exploded" in (fin["reason"] or ""), fin
        assert fin["status"] in ("partial", "failed"), fin

    def test_CANCELLATION_still_ends_the_run(self, tmp_path, monkeypatch):
        def boom(ctx, tag, outs, **kw):
            raise KeyboardInterrupt("ctrl-c")

        monkeypatch.setattr(crawl, "_xnl_ingest", boom)
        with pytest.raises(KeyboardInterrupt):
            self._lane(tmp_path, monkeypatch, ["js"])

    def test_a_JOURNAL_that_lost_a_completion_is_not_persisted(self, tmp_path, monkeypatch):
        from quarry_recon import budget as _b
        monkeypatch.setattr(_b.Ledger, "record", lambda self, *a, **k: False)
        monkeypatch.setattr(_b.Ledger, "save", lambda self: False)
        monkeypatch.setattr(_b.Ledger, "durable", property(lambda self: True))   # journal READABLE
        _calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js"])
        fin = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
        # the note names exactly what was lost — the completions that reached neither store
        assert "reached neither the journal nor a snapshot" in (fin.get("reason") or ""), fin
        assert fin["status"] == "partial", fin

    def test_a_PARAMETER_ONLY_extraction_is_not_EMPTY(self, tmp_path, monkeypatch):
        """review-B-audit-5#4: production counted link categories only, so a clean parameter-only run
        reported EMPTY and an unfinished one with retained parameters reported FAILED."""
        _calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js"], links=[], params=("user_id", "q"))
        fin = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
        assert fin["produced"] == {"references": 0, "params": 2, "wordlist": 0, "secrets": 0}, fin
        assert fin["status"] == "success", fin

    def test_production_is_PARSER_ACCEPTANCE_not_store_novelty(self, tmp_path, monkeypatch):
        """review-B-audit-2#2 applied to the terminal: a parameter jsluice already stored is still this
        lane's output. Every `add()` here reports "already present", so novelty is 0 throughout."""
        real_ctx_add = []

        class _Store:
            def __getattr__(self, n):
                raise AttributeError(n)

        _c, evs, ctx = self._lane(tmp_path, monkeypatch, ["js"], links=["https://api.acme.com/x"],
                                  params=("user_id",), store_novel=False)
        fin = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
        led = [e for e in evs if e.get("event") == events.LEDGER][0]
        assert led["xnl_stored"]["params_new"] == 0 and led["xnl_stored"]["endpoints_new"] == 0, led
        assert fin["produced"] == {"references": 1, "params": 1, "wordlist": 0, "secrets": 0}, fin
        assert fin["status"] == "success", fin
        assert not real_ctx_add
        # ...and when a KNOWN parameter is the only evidence, the terminal is still SUCCESS: extraction
        # happened. EMPTY here would mean "the tool found nothing", which is a different fact.
        second = tmp_path / "second"; second.mkdir()      # a FRESH project: this is a mine, not a replay
        _c2, evs2, _x2 = self._lane(second, monkeypatch, ["js"], links=[], params=("user_id",),
                                    store_novel=False)
        fin2 = [e for e in evs2 if e.get("event") == events.TOOL_FINISH][0]
        assert fin2["status"] == "success" and fin2["produced"]["params"] == 1, fin2

    def test_a_run_with_NOTHING_at_all_is_EMPTY(self, tmp_path, monkeypatch):
        _calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js"], links=[], params=())
        fin = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
        assert fin["status"] == "empty", fin

    def test_an_UNFINISHED_run_with_retained_params_is_PARTIAL_not_FAILED(self, tmp_path, monkeypatch):
        _calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js"], links=[], params=("q",),
                                       status=crawl.Status.TIMED_OUT)
        fin = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
        assert fin["status"] == "partial" and fin["produced"]["params"] == 1, fin

    def test_a_MISSING_TOOL_still_gets_a_lifecycle(self, tmp_path, monkeypatch):
        """review-B-audit-5#6: the tool check lived at every collection site, so an uninstalled tool meant
        no units, no lane, and total silence from a `tier: core` source."""
        _calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js", "sourcemap"], installed=False)
        fin = [e for e in evs if e.get("event") == events.TOOL_FINISH]
        assert fin and fin[0]["status"] == "skipped", fin
        cov = [e for e in evs if e.get("measure") == "units" and e.get("unit") == "install"]
        assert cov and cov[0]["omitted"] == 2, cov

    def test_the_COLLECTION_sites_do_not_gate_on_the_binary(self):
        import inspect
        src = inspect.getsource(crawl.run)
        for line in src.splitlines():
            if "xnl_units.append(" in line:
                assert "have(" not in line, line
        # ...and the gate exists exactly once, in the coordinator
        assert inspect.getsource(crawl._xnl_lane).count('have("xnLinkFinder")') == 1


class TestXnLinkFinderLifecycleBoundary:
    """review-B-audit-6: the ownership boundary's own defects — an unlocked project, replay mutating
    digest-bound evidence, a cancelled run signing off clean, `-os` silence, half-counted durability,
    an unreadable output published as empty, and an identity that could collapse or go stale."""

    _S = TestXnLinkFinderHasOneLifecycle._S
    _lane = TestXnLinkFinderHasOneLifecycle._lane

    # ── #1 the lane state is LOCKED ──────────────────────────────────────────────────────────────
    def test_a_BUSY_project_FAILS_with_a_gap_and_never_mines_twice(self, tmp_path, monkeypatch):
        import contextlib as _c
        from quarry_recon import budget as _b

        @_c.contextmanager
        def busy(path):
            raise _b.StateBusy(f"another lifecycle holds {path}")
            yield  # pragma: no cover

        monkeypatch.setattr(_b, "state_lock", busy)
        calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js"])
        fin = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
        assert calls == [], "a second lifecycle mined while another held the state"
        # review-B-audit-7#1: SKIPPED would claim we chose not to run. This run holds NONE of the holder's
        # evidence — its own store is empty — so zero evidence is FAILED, as everywhere else.
        assert fin["status"] == "failed" and "another lifecycle" in (fin["reason"] or ""), fin
        gap = [e for e in evs if e.get("unit") == "lock"]
        assert gap and gap[0]["omitted"] == 1, evs

    def test_the_lock_is_taken_BEFORE_prune_and_load(self, tmp_path, monkeypatch):
        """Pruning deletes superseded ledgers and `Ledger()` loads the snapshot — both are state mutations,
        so neither may happen outside the lock."""
        from quarry_recon import budget as _b
        order = []
        real_lock, real_prune = _b.state_lock, _b.prune_state
        real_init, real_save = _b.Ledger.__init__, _b.Ledger.save

        import contextlib as _c

        @_c.contextmanager
        def lock(path):
            order.append("lock")
            with real_lock(path) as p:
                yield p
            order.append("unlock")

        monkeypatch.setattr(_b, "state_lock", lock)
        monkeypatch.setattr(_b, "prune_state", lambda *a, **k: (order.append("prune"), real_prune(*a, **k))[1])
        monkeypatch.setattr(_b.Ledger, "__init__",
                            lambda self, *a, **k: (order.append("load"), real_init(self, *a, **k))[1])
        monkeypatch.setattr(_b.Ledger, "save",
                            lambda self: (order.append("save"), real_save(self))[1])
        self._lane(tmp_path, monkeypatch, ["js"])
        assert order[0] == "lock" and order[-1] == "unlock", order
        for step in ("prune", "load", "save"):
            assert 0 < order.index(step) < order.index("unlock"), (step, order)

    # ── #2 replay is READ-ONLY ───────────────────────────────────────────────────────────────────
    def test_REPLAY_never_writes_into_digest_bound_state(self, tmp_path, monkeypatch):
        monkeypatch.setattr(crawl, "XNL_WORDLIST_LIMIT", 1)      # every input is "large" -> derive a wordlist
        self._lane(tmp_path, monkeypatch, ["js"])
        state = tmp_path / "recon" / "state" / "xnlinkfinder" / f"v{crawl.XNL_PARSER_SCHEMA}"
        # the EVIDENCE — the digest-bound bundle. (The ledger's own snapshot is state, not evidence, and
        # it is rewritten by every `save()` on purpose.)
        def evidence():
            return {p.name: p.read_bytes() for p in sorted(state.rglob("*"))
                    if p.is_file() and not p.name.endswith(".state.json") and p.name != ".lock"}

        before = evidence()
        assert before, state
        _calls, evs, ctx = self._lane(tmp_path, monkeypatch, ["js"])
        assert evidence() == before, "replay mutated evidence it had just verified by digest"
        assert [e for e in evs if e.get("event") == events.LEDGER and e.get("replay")], evs

    def test_REPLAY_works_on_READ_ONLY_state(self, tmp_path, monkeypatch):
        monkeypatch.setattr(crawl, "XNL_WORDLIST_LIMIT", 1)
        self._lane(tmp_path, monkeypatch, ["js"])
        state = tmp_path / "recon" / "state" / "xnlinkfinder" / f"v{crawl.XNL_PARSER_SCHEMA}"
        bundles = [p for p in state.iterdir() if p.name.endswith("_wordlist.txt")]
        assert bundles
        for p in bundles:
            p.chmod(0o444)
        try:
            _calls, evs, ctx = self._lane(tmp_path, monkeypatch, ["js"])
        finally:
            for p in bundles:
                p.chmod(0o644)
        led = [e for e in evs if e.get("event") == events.LEDGER]
        assert led and led[-1].get("replay"), evs     # [-1]: the log spans both runs of this fixture
        assert [r["value"] for k, r in ctx.run.added if k == "endpoint"] == ["https://api.acme.com/x"]

    # ── #3 cancellation and contained initialization ─────────────────────────────────────────────
    def test_CANCELLATION_emits_an_honest_terminal_before_propagating(self, tmp_path, monkeypatch):
        def boom(ctx, tag, outs, **kw):
            raise KeyboardInterrupt("ctrl-c")

        monkeypatch.setattr(crawl, "_xnl_ingest", boom)
        with pytest.raises(KeyboardInterrupt):
            self._lane(tmp_path, monkeypatch, ["js"])
        evs = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        fins = [e for e in evs if e.get("event") == events.TOOL_FINISH]
        assert len(fins) == 1, fins
        # nothing was ingested before the interrupt, so there is no partial success to report
        assert fins[0]["status"] == "failed" and "CANCELLED" in (fins[0]["reason"] or ""), fins
        assert "nothing extracted" in fins[0]["reason"], fins

    def test_CANCELLATION_after_real_production_is_PARTIAL(self, tmp_path, monkeypatch):
        """The other half of #2: retained evidence is what makes an interrupted lane PARTIAL."""
        real = crawl._xnl_ingest

        def one_then_stop(ctx, tag, outs, **kw):
            if tag == "js":
                return real(ctx, tag, outs, **kw)
            raise KeyboardInterrupt("ctrl-c")

        monkeypatch.setattr(crawl, "_xnl_ingest", one_then_stop)
        with pytest.raises(KeyboardInterrupt):
            self._lane(tmp_path, monkeypatch, ["js", "sourcemap"])
        evs = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        fin = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
        assert fin["status"] == "partial" and "evidence KEPT" in (fin["reason"] or ""), fin
        assert fin["produced"]["references"] == 1, fin

    def test_a_STATE_failure_is_contained_and_reported(self, tmp_path, monkeypatch):
        monkeypatch.setattr(crawl, "_xnl_state_dir",
                            lambda ctx: (_ for _ in ()).throw(OSError("read-only filesystem")))
        calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js"])       # must NOT raise
        fin = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
        assert calls == [] and fin["status"] == "failed", (calls, fin)
        assert "read-only filesystem" in (fin["reason"] or ""), fin

    def test_a_SAVE_that_raises_is_contained(self, tmp_path, monkeypatch):
        from quarry_recon import budget as _b
        monkeypatch.setattr(_b.Ledger, "save",
                            lambda self: (_ for _ in ()).throw(OSError("disk full")))
        _calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js"])
        fin = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
        assert "disk full" in (fin["reason"] or "") and fin["status"] in ("partial", "failed"), fin

    # ── #4 secrets are evidence ──────────────────────────────────────────────────────────────────
    def _secret_lane(self, tmp_path, monkeypatch, body, calls=None, add=None):
        calls = [] if calls is None else calls

        def fake_exec(tool, cmd, **k):
            calls.append(cmd)
            pathlib.Path(cmd[cmd.index("-o") + 1]).write_text("https://api.acme.com/x\n")
            pathlib.Path(cmd[cmd.index("-op") + 1]).write_text("")
            if "-os" in cmd and body is not None:
                pathlib.Path(cmd[cmd.index("-os") + 1]).write_text(body)
            if "-owl" in cmd:
                pathlib.Path(cmd[cmd.index("-owl") + 1]).write_text("")
            return type("R", (), {"tool": tool, "cmd": cmd, "status": crawl.Status.SUCCESS,
                                  "note": "", "duration": 0.0, "exit_code": 0})()

        monkeypatch.setattr(crawl, "exec_tool", fake_exec)
        monkeypatch.setattr(crawl, "have", lambda t: True)
        monkeypatch.setattr(crawl, "_xnl_engine", lambda: "8.2")
        events.reset(); events.configure(tmp_path)
        ctx = _Ctx(tmp_path, [])
        ctx.scope = self._S()
        ctx.scope.passive_only = False
        if add is not None:
            ctx.run.add = add
        _install_fake_xnl_repository(monkeypatch)
        d = tmp_path / "in" / "js"
        d.mkdir(parents=True, exist_ok=True)
        (d / "a.js").write_text("var x = 1;")
        crawl._xnl_lane(ctx, [(str(d), "js", False)])
        log = tmp_path / "events.jsonl"
        evs = [json.loads(l) for l in log.read_text().splitlines()] if log.exists() else []
        return ctx, evs

    #: the MEASURED xnLinkFinder 8.2 `-os` document (offline stdin fixture, this machine)
    MEASURED_OS = ('[\n  {\n    "type": "AWS Access Key",\n    "value": "\\"AKIAIOSFODNN7EXAMPLE\\"",\n'
                   '    "sources": [\n      "<stdin>"\n    ],\n    "count": 1\n  }\n]')

    def test_a_discovered_secret_is_stored_VERBATIM(self, tmp_path, monkeypatch):
        ctx, evs = self._secret_lane(tmp_path, monkeypatch, self.MEASURED_OS)
        secs = [r for k, r in ctx.run.added if k == "secret"]
        assert len(secs) == 1, secs
        assert secs[0]["value"] == '"AKIAIOSFODNN7EXAMPLE"', secs        # not masked, not truncated
        assert secs[0]["preview"] == secs[0]["value"] and "*" not in secs[0]["preview"], secs
        assert secs[0]["kind"] == "AWS Access Key" and secs[0]["sources"] == ["xnLinkFinder"], secs
        fin = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
        assert fin["produced"]["secrets"] == 1 and fin["status"] == "success", fin

    @pytest.mark.parametrize("body,why", [
        ("{not json at all", "not the measured JSON document"),
        ('{"secrets": []}', "not the measured array"),
        ('[{"type": "AWS", "count": 1}]', "do not match the measured schema"),
        # review-B-audit-7#4: the contract names FOUR fields. A row with a string `value` and a broken
        # `type`/`sources`/`count` is a document we have not measured, whatever else is right about it.
        ('[{"type": "", "value": "v", "sources": ["<stdin>"], "count": 1}]', "do not match"),
        ('[{"type": "AWS", "value": "v", "sources": "stdin", "count": 1}]', "do not match"),
        ('[{"type": "AWS", "value": "v", "sources": [3], "count": 1}]', "do not match"),
        ('[{"type": "AWS", "value": "v", "sources": ["<stdin>"]}]', "do not match"),
        ('[{"type": "AWS", "value": "v", "sources": ["<stdin>"], "count": "1"}]', "do not match"),
        ('[{"type": "AWS", "value": "v", "sources": ["<stdin>"], "count": true}]', "do not match"),
        ('["just a string"]', "do not match"),
        # review-B-audit-8#3: the MEASURED provenance is `["<stdin>"]` and the count is a real occurrence
        ('[{"type": "AWS", "value": "v", "sources": [], "count": 1}]', "do not match"),
        ('[{"type": "AWS", "value": "v", "sources": ["elsewhere"], "count": 1}]', "do not match"),
        ('[{"type": "AWS", "value": "v", "sources": ["<stdin>"], "count": 0}]', "do not match"),
        ('[{"type": "AWS", "value": "v", "sources": ["<stdin>"], "count": -1}]', "do not match"),
        ('[{"type": "  ", "value": "v", "sources": ["<stdin>"], "count": 1}]', "do not match"),
        ('[{"type": "AWS", "value": "   ", "sources": ["<stdin>"], "count": 1}]', "do not match"),
        # #5: the MEASURED no-find shape is `[]`. An empty artifact is not that.
        ("", "is empty"),
        ("   \n", "is empty"),
    ])
    def test_MALFORMED_os_output_is_a_PARSE_GAP_never_a_clean_zero(self, tmp_path, monkeypatch, body, why):
        ctx, evs = self._secret_lane(tmp_path, monkeypatch, body)
        gaps = [e.get("reason") or "" for e in evs if e.get("event") == "coverage_partial"]
        assert any(why in g and "RETAINED" in g for g in gaps), gaps
        fin = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
        assert fin["status"] != "success", fin           # a unit we cannot account for is not clean
        state = tmp_path / "recon" / "state" / "xnlinkfinder" / f"v{crawl.XNL_PARSER_SCHEMA}"
        assert not list(state.glob("*_bundle.json")), "an unaccounted unit was OWNED"

    def test_a_VALID_row_beside_a_broken_one_is_still_ingested(self, tmp_path, monkeypatch):
        """A parse gap does not discard what we CAN read: the good row is stored verbatim, the unit stays
        retryable because the document is not fully explained."""
        body = json.dumps([{"type": "AWS Access Key", "value": "AKIA_GOOD", "sources": ["<stdin>"],
                            "count": 1},
                           {"type": "Generic", "value": "no-count", "sources": ["<stdin>"]}])
        ctx, evs = self._secret_lane(tmp_path, monkeypatch, body)
        secs = [r for k, r in ctx.run.added if k == "secret"]
        assert [x["value"] for x in secs] == ["AKIA_GOOD"], secs
        led = [e for e in evs if e.get("event") == events.LEDGER][-1]
        assert led["produced"]["secrets"] == 1 and led["xnl_rejected"]["secrets_unusable"] == 1, led
        state = tmp_path / "recon" / "state" / "xnlinkfinder" / f"v{crawl.XNL_PARSER_SCHEMA}"
        assert not list(state.glob("*_bundle.json")), "a partly-unexplained document was OWNED"

    def test_the_MEASURED_no_find_shape_is_CLEAN(self, tmp_path, monkeypatch):
        """MEASURED (8.2, offline stdin fixture with no secrets): the tool writes the array `[]`."""
        ctx, evs = self._secret_lane(tmp_path, monkeypatch, "[]")
        gaps = [e.get("reason") or "" for e in evs if e.get("event") == "coverage_partial"]
        assert not any("RETAINED" in g or "retryable" in g for g in gaps), gaps
        state = tmp_path / "recon" / "state" / "xnlinkfinder" / f"v{crawl.XNL_PARSER_SCHEMA}"
        assert list(state.glob("*_bundle.json")), "a clean no-find run was not owned"

    def test_a_REQUESTED_but_MISSING_os_artifact_fails_closed(self, tmp_path, monkeypatch):
        """review-B-audit-7#5: `-os` was passed and nothing was written. The measured no-find shape is
        `[]`, so this is OUR blind spot, not the tool's zero."""
        ctx, evs = self._secret_lane(tmp_path, monkeypatch, None)          # -os requested, never written
        gaps = [e.get("reason") or "" for e in evs if e.get("event") == "coverage_partial"]
        assert any("no artifact was written" in g and "retryable" in g for g in gaps), gaps
        state = tmp_path / "recon" / "state" / "xnlinkfinder" / f"v{crawl.XNL_PARSER_SCHEMA}"
        assert not list(state.glob("*_bundle.json")), "an unmeasured silence was OWNED"

    def test_an_UNREQUESTED_os_artifact_is_not_a_gap(self, tmp_path, monkeypatch):
        """The other side of #5: on LARGE input `-os` is never asked for, so its absence says nothing."""
        monkeypatch.setattr(crawl, "XNL_WORDLIST_LIMIT", 1)
        ctx, evs = self._secret_lane(tmp_path, monkeypatch, None)
        cmds = [e for e in evs if e.get("event") == events.TOOL_START]
        gaps = [e.get("reason") or "" for e in evs if e.get("event") == "coverage_partial"]
        assert not any("no artifact was written" in g for g in gaps), gaps
        state = tmp_path / "recon" / "state" / "xnlinkfinder" / f"v{crawl.XNL_PARSER_SCHEMA}"
        assert list(state.glob("*_bundle.json")), "a unit that was never asked for secrets stayed unowned"

    def test_the_RAW_os_artifact_survives_a_parse_gap(self, tmp_path, monkeypatch):
        ctx, _evs = self._secret_lane(tmp_path, monkeypatch, "{not json at all")
        raw = ctx.run.raw_path("crawl", "xnLinkFinder", "js_secrets.json")
        assert raw.read_text() == "{not json at all", "the evidence was discarded with the parse"

    def test_a_MALFORMED_unit_is_RE_MINED_next_run(self, tmp_path, monkeypatch):
        """A parse gap must be RETRYABLE: the same bytes are mined again, not replayed as accounted-for."""
        calls = []
        self._secret_lane(tmp_path, monkeypatch, "{not json at all", calls=calls)
        assert len(calls) == 1
        self._secret_lane(tmp_path, monkeypatch, "{not json at all", calls=calls)
        assert len(calls) == 2, "an un-accountable unit was replayed instead of re-mined"
        # ...and once the output parses, the unit IS owned
        self._secret_lane(tmp_path, monkeypatch, self.MEASURED_OS, calls=calls)
        assert len(calls) == 3
        self._secret_lane(tmp_path, monkeypatch, self.MEASURED_OS, calls=calls)
        assert len(calls) == 3, "a clean unit was re-mined"

    # ── audit-8#1 evidence already written is never absent from the accounting ───────────────────
    def test_a_SINK_that_fails_MID_ingestion_keeps_what_was_stored(self, tmp_path, monkeypatch):
        """review-B-audit-8#1: counts lived only in the ingest RETURN value, so a store that raised after
        real writes left the terminal saying `FAILED / nothing extracted` while the run store held rows."""
        seen = []

        def flaky(kind, rec):
            seen.append(kind)
            if len(seen) == 2:
                raise RuntimeError("store died")
            return True

        _calls, evs, ctx = self._lane(tmp_path, monkeypatch, ["js"],
                                      links=["https://api.acme.com/a", "https://api.acme.com/b"],
                                      add=flaky)
        fin = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
        assert len(seen) == 2, seen
        assert fin["produced"]["references"] == 1, fin       # the row that DID land is accounted for
        assert fin["status"] == "partial" and "store died" in (fin["reason"] or ""), fin

    def test_CANCELLATION_mid_ingestion_keeps_what_was_stored(self, tmp_path, monkeypatch):
        seen = []

        def stopper(kind, rec):
            seen.append(kind)
            if len(seen) == 2:
                raise KeyboardInterrupt("ctrl-c")
            return True

        with pytest.raises(KeyboardInterrupt):
            self._lane(tmp_path, monkeypatch, ["js"],
                       links=["https://api.acme.com/a", "https://api.acme.com/b"], add=stopper)
        evs = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        fin = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
        assert fin["produced"]["references"] == 1, fin
        assert fin["status"] == "partial" and "evidence KEPT" in (fin["reason"] or ""), fin

    def test_a_SINK_that_fails_MID_REPLAY_keeps_what_was_re_ingested(self, tmp_path, monkeypatch):
        """Replay owes the same accounting: its carrier joins before the re-ingestion writes."""
        self._lane(tmp_path, monkeypatch, ["js"],
                   links=["https://api.acme.com/a", "https://api.acme.com/b"])
        seen = []

        def flaky(kind, rec):
            seen.append(kind)
            if len(seen) == 2:
                raise RuntimeError("store died on replay")
            return True

        calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js"],
                                      links=["https://api.acme.com/a", "https://api.acme.com/b"],
                                      add=flaky)
        assert calls == [], "the second run mined instead of replaying"
        fin = [e for e in evs if e.get("event") == events.TOOL_FINISH][-1]   # the log spans both runs
        assert fin["produced"]["references"] == 1, fin
        assert "store died on replay" in (fin["reason"] or ""), fin

    def test_PARAMETERS_are_counted_as_DELIVERED_not_as_seen(self, tmp_path, monkeypatch):
        """review-B-audit-9#1: `params` was assigned the whole candidate set before the first write, so a
        store dying on parameter one still reported every candidate as produced."""
        def die(kind, rec):
            raise RuntimeError("store died")

        _calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js"], links=[],
                                       params=("a_param", "b_param", "c_param"), add=die)
        fin = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
        assert fin["produced"]["params"] == 0, fin
        assert fin["status"] == "failed" and "store died" in (fin["reason"] or ""), fin

    def test_PARAMETERS_delivered_before_a_failure_are_kept(self, tmp_path, monkeypatch):
        seen = []

        def flaky(kind, rec):
            seen.append(kind)
            if len(seen) == 3:
                raise RuntimeError("store died")
            return True

        _calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js"], links=[],
                                       params=("a_param", "b_param", "c_param"), add=flaky)
        fin = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
        assert fin["produced"]["params"] == 2, fin      # exactly what the store took
        assert fin["status"] == "partial", fin

    def test_SECRETS_delivered_before_a_failure_are_kept(self, tmp_path, monkeypatch):
        """review-B-audit-9#2: the secret total lived in `_xnl_secrets`'s return value, so a sink dying on
        the second secret reported zero while the first one sat in the store."""
        body = json.dumps([{"type": "AWS", "value": "AKIA_ONE", "sources": ["<stdin>"], "count": 1},
                           {"type": "AWS", "value": "AKIA_TWO", "sources": ["<stdin>"], "count": 1}])
        seen = []

        def flaky(kind, rec):
            seen.append(kind)
            if kind == "secret" and len([k for k in seen if k == "secret"]) == 2:
                raise RuntimeError("store died on secret two")
            return True

        ctx, evs = self._secret_lane(tmp_path, monkeypatch, body, add=flaky)
        fin = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
        assert fin["produced"]["secrets"] == 1, fin
        assert "store died on secret two" in (fin["reason"] or ""), fin
        assert fin["status"] == "partial", fin

    def test_SECRETS_survive_a_CANCELLATION_mid_document(self, tmp_path, monkeypatch):
        body = json.dumps([{"type": "AWS", "value": "AKIA_ONE", "sources": ["<stdin>"], "count": 1},
                           {"type": "AWS", "value": "AKIA_TWO", "sources": ["<stdin>"], "count": 1}])
        seen = []

        def stopper(kind, rec):
            seen.append(kind)
            if len([k for k in seen if k == "secret"]) == 2:
                raise KeyboardInterrupt("ctrl-c")
            return True

        with pytest.raises(KeyboardInterrupt):
            self._secret_lane(tmp_path, monkeypatch, body, add=stopper)
        evs = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        fin = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
        assert fin["produced"]["secrets"] == 1 and fin["status"] == "partial", fin

    def test_SECRETS_survive_a_failure_on_REPLAY_too(self, tmp_path, monkeypatch):
        body = json.dumps([{"type": "AWS", "value": "AKIA_ONE", "sources": ["<stdin>"], "count": 1},
                           {"type": "AWS", "value": "AKIA_TWO", "sources": ["<stdin>"], "count": 1}])
        calls = []
        self._secret_lane(tmp_path, monkeypatch, body, calls=calls)
        assert len(calls) == 1
        seen = []

        def flaky(kind, rec):
            seen.append(kind)
            if len([k for k in seen if k == "secret"]) == 2:
                raise RuntimeError("store died on replay")
            return True

        ctx, evs = self._secret_lane(tmp_path, monkeypatch, body, calls=calls, add=flaky)
        assert len(calls) == 1, "the second run mined instead of replaying"
        fin = [e for e in evs if e.get("event") == events.TOOL_FINISH][-1]
        assert fin["produced"]["secrets"] == 1, fin
        assert "store died on replay" in (fin["reason"] or ""), fin

    # ── audit-10#1 the bytes ingested are the bytes owned ────────────────────────────────────────
    def test_an_artifact_REWRITTEN_mid_ingestion_cannot_change_what_is_OWNED(self, tmp_path, monkeypatch):
        """review-B-audit-10#1: parsing, presence and publication each re-read the files, so a sink that
        rewrote an artifact between two of those reads made the run store URL A and OWN URL B — and every
        later replay ingested B."""
        links_file = {}

        def rewrite(kind, rec):
            # the first stored endpoint swaps the artifact under us
            for p in (tmp_path / "raw" / "crawl" / "xnLinkFinder").glob("*_links.txt"):
                links_file["p"] = p
                p.write_text("https://api.acme.com/SWAPPED\n")
            assert links_file, "the fixture never found the artifact to swap"
            return True

        _calls, _evs, ctx = self._lane(tmp_path, monkeypatch, ["js"],
                                       links=["https://api.acme.com/original"], add=rewrite)
        stored = [r["value"] for k, r in getattr(ctx.run, "added", []) if k == "endpoint"]
        state = tmp_path / "recon" / "state" / "xnlinkfinder" / f"v{crawl.XNL_PARSER_SCHEMA}"
        owned = next(state.glob("*_links.txt")).read_text()
        assert "SWAPPED" not in owned, "the ledger bound bytes the parser never saw"
        assert owned.strip() == "https://api.acme.com/original", owned

    def test_REPLAY_verifies_and_ingests_the_SAME_bytes(self, tmp_path, monkeypatch):
        """Verification and materialization used to read the bundle separately."""
        self._lane(tmp_path, monkeypatch, ["js"], links=["https://api.acme.com/original"])
        state = tmp_path / "recon" / "state" / "xnlinkfinder" / f"v{crawl.XNL_PARSER_SCHEMA}"
        real_read = pathlib.Path.read_bytes
        swapped = {"n": 0}

        def swapping(self, *a, **k):
            data = real_read(self, *a, **k)
            if self.name.endswith("_links.txt") and str(self).startswith(str(state)):
                swapped["n"] += 1
                if swapped["n"] == 1:                 # only the FIRST read sees the honest bytes
                    return data
                return b"https://api.acme.com/SWAPPED\n"
            return data

        monkeypatch.setattr(pathlib.Path, "read_bytes", swapping)
        calls, evs, ctx = self._lane(tmp_path, monkeypatch, ["js"],
                                     links=["https://api.acme.com/original"])
        assert calls == [], "the second run mined instead of replaying"
        stored = [r["value"] for k, r in ctx.run.added if k == "endpoint"]
        assert stored == ["https://api.acme.com/original"], stored

    def test_the_MATERIALIZED_copy_is_the_owned_evidence(self, tmp_path, monkeypatch):
        """The run-local copy exists for the operator; it must be the bytes the ledger owns, byte for
        byte — written from the verified snapshot, not re-read from anywhere."""
        self._lane(tmp_path, monkeypatch, ["js"], links=["https://api.acme.com/original"])
        state = tmp_path / "recon" / "state" / "xnlinkfinder" / f"v{crawl.XNL_PARSER_SCHEMA}"
        owned = next(state.glob("*_links.txt")).read_bytes()
        for p in (tmp_path / "raw" / "crawl" / "xnLinkFinder").glob("*_links.txt"):
            p.write_bytes(b"stale junk\n")               # a leftover from the previous run
        calls, _evs, _ctx = self._lane(tmp_path, monkeypatch, ["js"],
                                       links=["https://api.acme.com/original"])
        assert calls == [], "the second run mined instead of replaying"
        copy = next((tmp_path / "raw" / "crawl" / "xnLinkFinder").glob("*_links.txt")).read_bytes()
        assert copy == owned, (copy, owned)

    def test_an_UNDECODABLE_line_never_reaches_the_derived_wordlist(self, tmp_path, monkeypatch):
        """The derived wordlist drives an ACTIVE puredns brute in A1d, so it may only contain values this
        boundary accepted — not words re-decoded out of a line the strict reader rejected."""
        monkeypatch.setattr(crawl, "XNL_WORDLIST_LIMIT", 1)       # large input: the wordlist is DERIVED

        def fake_exec(tool, cmd, **k):
            pathlib.Path(cmd[cmd.index("-o") + 1]).write_bytes(
                b"https://api.acme.com/keep\n"
                b"admin\xffinternal\n"                       # undecodable: rejected by the reader
                b"this is not a url ###junkword\n"           # decodable, but NOT an accepted value
                b"https://oosword.evil.example/x\n")         # off-scope: evidence, never brute vocabulary
            pathlib.Path(cmd[cmd.index("-op") + 1]).write_bytes(b"good_param\nbad\xffparam\n")
            return type("R", (), {"tool": tool, "cmd": cmd, "status": crawl.Status.SUCCESS,
                                  "note": "", "duration": 0.0, "exit_code": 0})()

        monkeypatch.setattr(crawl, "exec_tool", fake_exec)
        monkeypatch.setattr(crawl, "have", lambda t: True)
        monkeypatch.setattr(crawl, "_xnl_engine", lambda: "8.2")
        events.reset(); events.configure(tmp_path)
        ctx = _Ctx(tmp_path, [])
        ctx.scope = self._S()
        ctx.scope.passive_only = False
        _install_fake_xnl_repository(monkeypatch)
        d = tmp_path / "in" / "js"
        d.mkdir(parents=True)
        (d / "a.js").write_text("var x = 1;")
        crawl._xnl_lane(ctx, [(str(d), "js", False)])
        wl = next((tmp_path / "raw" / "crawl" / "xnLinkFinder").glob("*_wordlist.txt")).read_text()
        words = set(wl.split())
        assert {"keep", "good"} <= words, wl             # accepted values contribute
        assert "admin" not in words and "internal" not in words, wl   # from the undecodable link line
        assert "bad" not in words, wl                                  # from the undecodable param line
        assert "junkword" not in words, wl               # decodable, but the parser did not accept it
        assert "oosword" not in words, wl                # off-scope evidence is not brute vocabulary

    def test_UNDECODABLE_wordlist_lines_are_counted_and_excluded(self, tmp_path, monkeypatch):
        def fake_exec(tool, cmd, **k):
            pathlib.Path(cmd[cmd.index("-o") + 1]).write_text("https://api.acme.com/x\n")
            pathlib.Path(cmd[cmd.index("-op") + 1]).write_text("")
            if "-os" in cmd:
                pathlib.Path(cmd[cmd.index("-os") + 1]).write_text("[]")
            if "-owl" in cmd:
                pathlib.Path(cmd[cmd.index("-owl") + 1]).write_bytes(b"good\nbad\xffword\n")
            return type("R", (), {"tool": tool, "cmd": cmd, "status": crawl.Status.SUCCESS,
                                  "note": "", "duration": 0.0, "exit_code": 0})()

        monkeypatch.setattr(crawl, "exec_tool", fake_exec)
        monkeypatch.setattr(crawl, "have", lambda t: True)
        monkeypatch.setattr(crawl, "_xnl_engine", lambda: "8.2")
        events.reset(); events.configure(tmp_path)
        ctx = _Ctx(tmp_path, [])
        ctx.scope = self._S()
        ctx.scope.passive_only = False
        _install_fake_xnl_repository(monkeypatch)
        d = tmp_path / "in" / "js"
        d.mkdir(parents=True)
        (d / "a.js").write_text("var x = 1;")
        crawl._xnl_lane(ctx, [(str(d), "js", False)])
        evs = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        led = [e for e in evs if e.get("event") == events.LEDGER][-1]
        assert led["produced"]["wordlist"] == 1, led                 # only the decodable line is a word
        assert led["xnl_rejected"]["wordlist_undecodable"] == 1, led

    # ── audit-8#2 every REQUESTED artifact has a measured no-find shape ──────────────────────────
    @pytest.mark.parametrize("flag", ["-o", "-op", "-owl"])
    def test_a_REQUESTED_artifact_that_was_never_written_is_retryable(self, tmp_path, monkeypatch, flag):
        """MEASURED (8.2, empty stdin blob): links/params/wordlist are CREATED as empty files and secrets
        as `[]`. A missing one is our blind spot, not the tool's zero."""
        def fake_exec(tool, cmd, **k):
            for f, body in (("-o", "https://api.acme.com/x\n"), ("-op", "id\n"), ("-owl", ""),
                            ("-os", "[]")):
                if f in cmd and f != flag:
                    pathlib.Path(cmd[cmd.index(f) + 1]).write_text(body)
            return type("R", (), {"tool": tool, "cmd": cmd, "status": crawl.Status.SUCCESS,
                                  "note": "", "duration": 0.0, "exit_code": 0})()

        monkeypatch.setattr(crawl, "exec_tool", fake_exec)
        monkeypatch.setattr(crawl, "have", lambda t: True)
        monkeypatch.setattr(crawl, "_xnl_engine", lambda: "8.2")
        events.reset(); events.configure(tmp_path)
        ctx = _Ctx(tmp_path, [])
        ctx.scope = self._S()
        ctx.scope.passive_only = False
        _install_fake_xnl_repository(monkeypatch)
        d = tmp_path / "in" / "js"
        d.mkdir(parents=True)
        (d / "a.js").write_text("var x = 1;")
        crawl._xnl_lane(ctx, [(str(d), "js", False)])
        evs = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        gaps = [e.get("reason") or "" for e in evs if e.get("measure") == "units"]
        assert any(flag in g and "no artifact written" in g for g in gaps), gaps
        state = tmp_path / "recon" / "state" / "xnlinkfinder" / f"v{crawl.XNL_PARSER_SCHEMA}"
        assert not list(state.glob("*_bundle.json")), "an unmeasured silence was OWNED"

    def test_an_UNREQUESTED_wordlist_is_not_a_gap(self, tmp_path, monkeypatch):
        """On LARGE input `-owl` is never asked for (it is a timekiller) — its absence says nothing, and
        the derived wordlist takes its place."""
        monkeypatch.setattr(crawl, "XNL_WORDLIST_LIMIT", 1)
        _calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js"])
        gaps = [e.get("reason") or "" for e in evs if e.get("measure") == "units"]
        assert not any("no artifact written" in g for g in gaps), gaps
        state = tmp_path / "recon" / "state" / "xnlinkfinder" / f"v{crawl.XNL_PARSER_SCHEMA}"
        assert list(state.glob("*_bundle.json")), "a unit whose -owl was never requested stayed unowned"

    # ── #5 the durability handshake is complete in BOTH directions ───────────────────────────────
    def test_a_failed_EVIDENCE_bind_prevents_ownership(self, tmp_path, monkeypatch):
        from quarry_recon import budget as _b
        monkeypatch.setattr(_b.Ledger, "add_evidence", lambda self, *a, **k: False)
        _calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js"])
        fin = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
        assert fin["status"] == "success", fin            # save() still compacted: the unit IS owned
        assert any("snapshot compacted" in (e.get("reason") or "") for e in evs), evs

    def test_a_failed_APPEND_plus_a_good_SNAPSHOT_is_OWNED_without_a_false_gap(self, tmp_path, monkeypatch):
        """review-B-audit-7#6: the claim is OWNERSHIP, so it is proven by REOPENING a real ledger. The
        journal append fails at the real `_append`; everything the completion binds (digests, evidence)
        is written by the real `record()`."""
        from quarry_recon import budget as _b
        real_append = _b.Ledger._append

        def no_completion(self, rec):
            if "i" in rec:                       # a COMPLETION append fails; evidence appends still work
                self._journal_unsafe = True
                return False
            return real_append(self, rec)

        monkeypatch.setattr(_b.Ledger, "_append", no_completion)
        _calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js"])
        units = [e for e in evs if e.get("measure") == "units"]
        assert units and units[-1]["omitted"] == 0 and "snapshot compacted" in units[-1]["reason"], units
        fin = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
        assert fin["status"] == "success" and "NOT persisted" not in (fin.get("reason") or ""), fin
        # the real proof: a fresh ledger opened over that snapshot still owns the unit
        monkeypatch.undo()
        state = tmp_path / "recon" / "state" / "xnlinkfinder" / f"v{crawl.XNL_PARSER_SCHEMA}"
        snap = next(state.glob("*.state.json"))
        reopened = _b.Ledger(snap, lane="crawl.xnlinkfinder")
        assert reopened.done, "the rescued snapshot owns nothing"
        assert all(reopened.artifact(u) is not None for u in reopened.done), reopened.done

    def test_a_PARTLY_journaled_run_does_not_claim_every_input_re_mines(self, tmp_path, monkeypatch):
        """One unit journaled, one only in memory, and the snapshot fails: exactly ONE re-mines."""
        from quarry_recon import budget as _b
        real_append = _b.Ledger._append
        seen = {"completions": 0}

        def second_completion_fails(self, rec):
            if "i" in rec:
                seen["completions"] += 1
                if seen["completions"] == 2:
                    self._journal_unsafe = True
                    return False
            return real_append(self, rec)

        monkeypatch.setattr(_b.Ledger, "_append", second_completion_fails)
        monkeypatch.setattr(_b.Ledger, "save", lambda self: False)
        _calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js", "sourcemap"])
        fin = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
        # the fraction is over the COMPLETION ATTEMPTS (one journaled, one only in memory) — not over
        # every result, which would include replayed and gapped units
        assert "1/2 completion(s) reached neither the journal nor a snapshot" in (fin.get("reason") or ""), fin
        assert "every input re-mines" not in (fin.get("reason") or ""), fin

    def test_the_persistence_fraction_counts_COMPLETION_ATTEMPTS_not_results(self, tmp_path, monkeypatch):
        """review-B-audit-8#4: a REPLAYED unit attempted no completion, so it does not belong in the
        denominator. One replayed + one pending completion is `1/1`, never `1/2`."""
        from quarry_recon import budget as _b
        self._lane(tmp_path, monkeypatch, ["js"])                 # js is owned from here on
        real_append = _b.Ledger._append

        def no_completion(self, rec):
            if "i" in rec:
                self._journal_unsafe = True
                return False
            return real_append(self, rec)

        monkeypatch.setattr(_b.Ledger, "_append", no_completion)
        monkeypatch.setattr(_b.Ledger, "save", lambda self: False)
        _calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js", "sourcemap"])
        fin = [e for e in evs if e.get("event") == events.TOOL_FINISH][-1]   # the log spans both runs
        assert "1/1 completion(s) reached neither the journal nor a snapshot" in (fin.get("reason") or ""), fin

    def test_a_failed_APPEND_and_a_failed_SNAPSHOT_is_NOT_owned(self, tmp_path, monkeypatch):
        from quarry_recon import budget as _b
        monkeypatch.setattr(_b.Ledger, "record", lambda self, *a, **k: False)
        monkeypatch.setattr(_b.Ledger, "save", lambda self: False)
        monkeypatch.setattr(_b.Ledger, "durable", property(lambda self: True))
        _calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js"])
        units = [e for e in evs if e.get("measure") == "units"]
        assert units and units[-1]["omitted"] == 1, units
        fin = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
        assert fin["status"] == "partial", fin
        assert "reached neither the journal nor a snapshot" in (fin.get("reason") or ""), fin

    def test_a_SUCCESSFUL_snapshot_never_consults_the_durability_fallback(self, tmp_path, monkeypatch):
        """review-B-audit-7#3: `save()` returning True has already answered the question. Reading `durable`
        anyway let a raising property fabricate machinery on a run where nothing went wrong."""
        from quarry_recon import budget as _b

        def explode(self):
            raise AssertionError("durability was consulted after a SUCCESSFUL save")

        monkeypatch.setattr(_b.Ledger, "durable", property(explode))
        _calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js"])
        fin = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
        assert fin["status"] == "success" and not fin.get("reason"), fin

    # ── #6 an unreadable output is not an empty one ──────────────────────────────────────────────
    def test_an_UNREADABLE_output_is_never_published_as_EMPTY(self, tmp_path, monkeypatch):
        real_read = pathlib.Path.read_bytes

        def picky(self, *a, **k):
            if self.name.endswith("_wordlist.txt") and "raw" in str(self):
                raise PermissionError("denied")
            return real_read(self, *a, **k)

        monkeypatch.setattr(pathlib.Path, "read_bytes", picky)
        _calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js"])
        state = tmp_path / "recon" / "state" / "xnlinkfinder" / f"v{crawl.XNL_PARSER_SCHEMA}"
        assert not list(state.glob("*_bundle.json")), "an unreadable artifact was published as evidence"
        # the single read authority catches it at the BOUNDARY (review-B-audit-9#3); either way the unit
        # is not owned and the gap says which of the two happened.
        gaps = [e.get("reason") or "" for e in evs if e.get("measure") == "units"]
        assert any("output unreadable" in g for g in gaps), gaps

    def test_an_UNREADABLE_secrets_artifact_is_never_a_clean_zero(self, tmp_path, monkeypatch):
        real_read = pathlib.Path.read_bytes

        def picky(self, *a, **k):
            if self.name.endswith("_secrets.json"):
                raise PermissionError("denied")
            return real_read(self, *a, **k)

        monkeypatch.setattr(pathlib.Path, "read_bytes", picky)
        ctx, evs = self._secret_lane(tmp_path, monkeypatch, "[]")
        gaps = [e.get("reason") or "" for e in evs if e.get("measure") == "units"]
        assert any("unreadable" in g for g in gaps), gaps
        state = tmp_path / "recon" / "state" / "xnlinkfinder" / f"v{crawl.XNL_PARSER_SCHEMA}"
        assert not list(state.glob("*_bundle.json")), "an unreadable artifact was OWNED"

    def test_a_PUBLICATION_failure_is_not_ownership(self, tmp_path, monkeypatch):
        """The other half: artifacts read fine, but writing them into project state fails."""
        from quarry_recon import budget as _b
        monkeypatch.setattr(_b, "publish_bytes", lambda *a, **k: False)
        _calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js"])
        state = tmp_path / "recon" / "state" / "xnlinkfinder" / f"v{crawl.XNL_PARSER_SCHEMA}"
        assert not list(state.glob("*_bundle.json"))
        assert any("could not be stored durably" in (e.get("reason") or "") for e in evs), evs

    def test_an_ABSENT_output_stays_absent_and_a_PLANTED_one_is_refused(self, tmp_path, monkeypatch):
        # LARGE input: `-os` is not requested at all, so a missing secrets artifact is genuine absence
        # (a REQUESTED-but-missing one is a parse gap — see the `-os` cases below).
        monkeypatch.setattr(crawl, "XNL_WORDLIST_LIMIT", 1)
        self._lane(tmp_path, monkeypatch, ["js"])
        state = tmp_path / "recon" / "state" / "xnlinkfinder" / f"v{crawl.XNL_PARSER_SCHEMA}"
        man = json.loads(next(state.glob("*_bundle.json")).read_text())
        assert man["outputs"]["secrets"]["present"] is False, man
        assert not list(state.glob("*_secrets.json")), "an artifact the tool never wrote exists in state"
        planted = next(state.glob("*_links.txt")).with_name(
            next(state.glob("*_links.txt")).name.replace("_links.txt", "_secrets.json"))
        planted.write_text('[{"type": "x", "value": "planted"}]')
        calls, _evs, ctx = self._lane(tmp_path, monkeypatch, ["js"])
        assert len(calls) == 1, "a planted artifact was replayed as our evidence"
        assert not any(r.get("value") == "planted" for k, r in ctx.run.added if k == "secret")

    # ── #7 identity cannot collapse or go stale ──────────────────────────────────────────────────
    def test_an_UNDIGESTIBLE_input_is_never_owned(self, tmp_path, monkeypatch):
        monkeypatch.setattr(crawl, "_xnl_blob", lambda ctx, indir, tag: {
            "blob": ctx.run.raw_path("crawl", "xnLinkFinder", f"{tag}_input.txt"), "written": 10,
            "capped": False, "files": 1, "files_completed": 1, "partial_files": 0,
            "unreadable_files": 0, "digest": ""})
        calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js"])
        assert calls == [], "a unit with no identity was mined anyway"
        gaps = [e.get("reason") or "" for e in evs if e.get("measure") == "units"]
        assert any("could not be digested" in g and "next run retries it" in g for g in gaps), gaps
        # ...and it is named as the INPUT problem it is. Letting the identity helper raise would also stop
        # the unit, but it would report an undigestible input as our machinery failing.
        assert not any("machinery failed" in g for g in gaps), gaps
        state = tmp_path / "recon" / "state" / "xnlinkfinder" / f"v{crawl.XNL_PARSER_SCHEMA}"
        assert not list(state.glob("*_bundle.json"))

    def test_the_identity_REFUSES_an_empty_digest_structurally(self, tmp_path, monkeypatch):
        events.reset(); events.configure(tmp_path)
        ctx = _Ctx(tmp_path, [])
        ctx.scope = self._S()
        with pytest.raises(ValueError):
            crawl._xnl_unit_identity(ctx, "t", False, "", "8.2")

    def test_an_ENGINE_UPGRADE_re_mines_instead_of_replaying(self, tmp_path, monkeypatch):
        calls1, _evs, _c = self._lane(tmp_path, monkeypatch, ["js"], engine="8.2")
        calls2, _evs2, _c2 = self._lane(tmp_path, monkeypatch, ["js"], engine="8.2")
        calls3, evs3, _c3 = self._lane(tmp_path, monkeypatch, ["js"], engine="8.3")
        assert len(calls1) == 1 and len(calls2) == 0, (calls1, calls2)
        assert len(calls3) == 1, "an upgraded extractor replayed 8.2's output forever"

    def test_an_UNPROVEN_engine_mines_but_never_owns(self, tmp_path, monkeypatch):
        calls, evs, ctx = self._lane(tmp_path, monkeypatch, ["js"], engine="")
        assert len(calls) == 1, "an unprovable engine must not stop the mining"
        assert [r["value"] for k, r in ctx.run.added if k == "endpoint"] == ["https://api.acme.com/x"]
        assert any("identity is unproven" in (e.get("reason") or "") for e in evs), evs
        calls2, _evs2, _c2 = self._lane(tmp_path, monkeypatch, ["js"], engine="")
        assert len(calls2) == 1, "an unowned unit was replayed"


class TestRetentionIsComplete:
    """step 4.1 — RETENTION and ACTIVE SELECTION are different decisions.

    Measured on OTC 20260725: xnLinkFinder produced 111,313 distinct param candidates and the store kept
    6,086 — 94.5% destroyed by a cap that bought no request safety, because the `parameter` entity has one
    consumer (`exports.parameters.txt`) and nothing turns a stored candidate into a request. What spends —
    the A1d brute vocabulary, the wildcard candidate set — is selected downstream and is NOT touched here.
    """

    _S = TestXnLinkFinderHasOneLifecycle._S
    _lane = TestXnLinkFinderHasOneLifecycle._lane

    def test_EVERY_accepted_parameter_is_stored(self, tmp_path, monkeypatch):
        params = tuple(f"p{i:05d}" for i in range(5000))          # far beyond the old 2000 cap
        _calls, evs, ctx = self._lane(tmp_path, monkeypatch, ["js"], links=[], params=params)
        stored = [r["value"] for k, r in ctx.run.added if k == "parameter"]
        assert len(stored) == 5000, len(stored)
        assert set(stored) == set(params), (len(set(stored)), len(set(params)))
        fin = [e for e in evs if e.get("event") == events.TOOL_FINISH][0]
        assert fin["produced"]["params"] == 5000, fin

    def test_the_param_coverage_record_reports_NO_omission(self, tmp_path, monkeypatch):
        params = tuple(f"p{i:05d}" for i in range(3000))
        _calls, evs, _ctx = self._lane(tmp_path, monkeypatch, ["js"], links=[], params=params)
        cov = [e for e in evs if e.get("measure") == "potential_params"][0]
        assert (cov["eligible"], cov["tested"], cov["omitted"]) == (3000, 3000, 0), cov
        assert "no cap" in cov["reason"], cov

    def test_the_DERIVED_wordlist_keeps_the_whole_vocabulary(self, tmp_path, monkeypatch):
        monkeypatch.setattr(crawl, "XNL_WORDLIST_LIMIT", 1)       # large input -> the wordlist is DERIVED
        params = tuple(f"word{i:05d}" for i in range(6000))       # beyond the old 5000 derive cap
        self._lane(tmp_path, monkeypatch, ["js"], links=[], params=params)
        wl = next((tmp_path / "raw" / "crawl" / "xnLinkFinder").glob("*_wordlist.txt")).read_text()
        words = [w for w in wl.split() if w.startswith("word")]
        assert len(words) == 6000, len(words)

    def test_a_project_holding_ONLY_v1_state_re_mines_under_v2(self, tmp_path, monkeypatch):
        """review-step4#P2: a v1 bundle holds a TRUNCATED corpus. Starting from a project that has ONLY v1
        state — the real migration — the unit must re-mine and store the WHOLE set. (My first version
        created v2 first, so the final run replayed its own v2 bundle and proved nothing.)"""
        params = tuple(f"p{i:05d}" for i in range(2500))
        state = tmp_path / "recon" / "state" / "xnlinkfinder"

        monkeypatch.setattr(crawl, "XNL_PARSER_SCHEMA", 1)          # the world before step 4.1
        calls_v1, _e, ctx_v1 = self._lane(tmp_path, monkeypatch, ["js"], links=[], params=params[:2000])
        assert len(calls_v1) == 1 and (state / "v1").exists() and not (state / "v2").exists()
        assert len([r for k, r in ctx_v1.run.added if k == "parameter"]) == 2000
        monkeypatch.undo()

        assert crawl.XNL_PARSER_SCHEMA == 2
        calls_v2, _e2, ctx_v2 = self._lane(tmp_path, monkeypatch, ["js"], links=[], params=params)
        assert len(calls_v2) == 1, "the v1 bundle was replayed instead of re-mined"
        assert (state / "v2").exists(), list(state.iterdir())
        assert len([r for k, r in ctx_v2.run.added if k == "parameter"]) == 2500

        # ...and the v2 unit is then owned normally: a third run replays IT
        calls_v3, _e3, ctx_v3 = self._lane(tmp_path, monkeypatch, ["js"], links=[], params=params)
        assert calls_v3 == [], calls_v3
        assert len([r for k, r in ctx_v3.run.added if k == "parameter"]) == 2500

    def test_ACTIVE_SELECTION_is_unchanged_by_this_commit(self, tmp_path, monkeypatch):
        """The spend-side bounds are step 4.2/4.3 and must still be exactly where they were. `ZONE_CAP`
        moved to module scope when the differ gained its own lifecycle (the work unit binds it); the
        VALUE is what this pins."""
        from quarry_recon.phases import enrich, vertical
        assert vertical.WILDCARD_WORD_CAP == 5000
        assert vertical.wildcard_zones_per_run() == 5     # a per-run ALLOWANCE now, not a membership cap
        assert enrich.A1D_WORD_CAP == 2000        # the A1d spend bound, now owned by its caller
