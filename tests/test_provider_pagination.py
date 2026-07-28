"""C06 — bounded cursor pagination + truncation truth (certspotter/censys/shodan) + cloud bucket-enum.

Schemas mirror the OFFICIAL API contracts:
  - CertSpotter (SSLMate CT Search v1): array of issuances; paginate via `after=<last id>`; terminate on an
    EMPTY array (no `limit` param); a short page is NOT terminal.
  - Censys Platform v3: query `cert.names`; request page field `page_token`; next token in the response.
  - Shodan host/search: 100 matches/page, `total` count, `page=` param, a query credit per page.

Hitting the page cap with a live cursor is TRUNCATION → a PARTIAL ProviderResult → run_provider records
PARTIAL + a coverage gap (never a clean SUCCESS). cloud._check separates definitive absence (404) from an
INDETERMINATE probe (transport/other) and emits STRUCTURED, every-run coverage the verdict can see.
"""
import json
import socket
import urllib.error

import pytest

from quarry_recon import contract, events
from quarry_recon.contract import ProviderResult

pytestmark = pytest.mark.offline


class _Resp:
    def __init__(self, body): self._b = body
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def read(self, n=None): return self._b
    status = 200


def _terminal(tmp_path):
    evs = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
    return [e for e in evs if e["event"] == "tool_finish"][0], evs


class TestCertspotterPagination:
    def _mock(self, monkeypatch, pages):
        from quarry_recon.phases import vertical

        def fake(req, timeout=30):
            after = req.full_url.split("after=")[1].split("&")[0] if "after=" in req.full_url else None
            assert "limit=" not in req.full_url                # no undocumented limit param
            return _Resp(json.dumps(pages[after]).encode())
        monkeypatch.setattr(vertical.urllib.request, "urlopen", fake)
        return vertical

    def test_follows_after_until_empty_array(self, monkeypatch):
        pages = {
            None: [{"id": "1", "dns_names": ["a.acme.com"]}, {"id": "2", "dns_names": ["b.acme.com"]}],
            "2":  [{"id": "3", "dns_names": ["c.acme.com"]}],   # SHORT but NOT terminal — keep going
            "3":  [],                                            # EMPTY array = the documented end
        }
        v = self._mock(monkeypatch, pages)
        hosts = v._certspotter("acme.com", max_pages=5)
        assert hosts == {"a.acme.com", "b.acme.com", "c.acme.com"} and not getattr(hosts, "partial", False)

    def test_cap_hit_returns_partial(self, monkeypatch):
        # every page is non-empty with an advancing id -> never reaches the empty array within the cap
        from quarry_recon.phases import vertical
        n = {"i": 0}

        def fake(req, timeout=30):
            n["i"] += 1
            return _Resp(json.dumps([{"id": str(n["i"]), "dns_names": [f"h{n['i']}.acme.com"]}]).encode())
        monkeypatch.setattr(vertical.urllib.request, "urlopen", fake)
        r = vertical._certspotter("acme.com", max_pages=3)
        assert isinstance(r, ProviderResult) and r.partial and r.pages == 3 and n["i"] == 3

    def test_non_list_root_raises(self, monkeypatch):
        v = self._mock(monkeypatch, {None: {"message": "rate limited"}})
        with pytest.raises(ValueError):
            v._certspotter("acme.com", max_pages=5)

    @pytest.mark.parametrize("row", [
        {"id": "1"},                                          # review-r5#4: missing dns_names (we expanded it)
        {"id": "1", "dns_names": None},                       # null
        {"id": "1", "dns_names": "a.acme.com"},               # a string, not a list
        {"id": "1", "dns_names": [123]},                      # a non-string element
    ])
    def test_malformed_dns_names_raise(self, monkeypatch, row):
        v = self._mock(monkeypatch, {None: [row]})
        with pytest.raises(ValueError):
            v._certspotter("acme.com", max_pages=5)


class TestCensysPagination:
    def _mock(self, monkeypatch, pages, seen=None):
        from quarry_recon.phases import vertical

        def fake(req, timeout=30):
            payload = json.loads(req.data.decode())
            assert payload["query"] == 'cert.names: "acme.com"'   # current CenQL field, not cert.parsed.names
            tok = payload.get("page_token")                     # v3 request field, not `cursor`
            if seen is not None:
                seen.append(tok)
            return _Resp(json.dumps(pages[tok]).encode())
        monkeypatch.setattr(vertical.urllib.request, "urlopen", fake)
        return vertical

    def test_follows_page_token_until_absent(self, monkeypatch):
        pages = {
            None: {"result": {"hits": [{"certificate_v1": {"resource": {"names": ["a.acme.com"]}}}], "links": {"next": "t1"}}},
            "t1": {"result": {"hits": [{"certificate_v1": {"resource": {"names": ["b.acme.com"]}}}], "next_page_token": "t2"}},
            "t2": {"result": {"hits": [{"certificate_v1": {"resource": {"names": ["c.acme.com"]}}}]}},   # no token -> done
        }
        seen = []
        v = self._mock(monkeypatch, pages, seen)
        hosts = v._censys({"token": "t", "org": "o"}, "acme.com", max_pages=5)
        assert {"a.acme.com", "b.acme.com", "c.acme.com"} <= hosts
        assert seen == [None, "t1", "t2"] and not getattr(hosts, "partial", False)

    def test_cap_hit_returns_partial(self, monkeypatch):
        from quarry_recon.phases import vertical
        n = {"i": 0}

        def fake(req, timeout=30):
            n["i"] += 1
            return _Resp(json.dumps({"result": {"hits": [{"certificate_v1": {"resource": {"names": [f"h{n['i']}.acme.com"]}}}],
                                                "links": {"next": f"t{n['i']}"}}}).encode())
        monkeypatch.setattr(vertical.urllib.request, "urlopen", fake)
        r = vertical._censys({"token": "t", "org": "o"}, "acme.com", max_pages=4)
        assert isinstance(r, ProviderResult) and r.partial and r.pages == 4

    def test_bad_envelope_raises(self, monkeypatch):
        v = self._mock(monkeypatch, {None: {"error": {"code": 401}}})
        with pytest.raises(ValueError):
            v._censys({"token": "t", "org": "o"}, "acme.com", max_pages=5)

    @pytest.mark.parametrize("hits", [[None], ["scalar"], [123]])
    def test_malformed_hit_rows_raise(self, monkeypatch, hits):
        # review-r5#3: a non-object hit (`hits:[null]`, scalar) must raise, never become a clean empty
        v = self._mock(monkeypatch, {None: {"result": {"hits": hits}}})
        with pytest.raises(ValueError):
            v._censys({"token": "t", "org": "o"}, "acme.com", max_pages=5)

    @pytest.mark.parametrize("hit", [
        {"message": "schema drift"},                          # review-r7#1: drift hit -> schema failure, NOT clean EMPTY
        {"names": ["fallback-phantom.acme.com"]},             # a top-level `names` fallback -> phantom; must RAISE now
        {"resource": {"names": ["x.acme.com"]}},              # a `resource.names` fallback -> must RAISE (no cert path)
        {"certificate_v1": {"resource": {"names": "not-a-list"}}},   # exact path but not a list
    ])
    def test_missing_exact_names_path_is_schema_failure(self, monkeypatch, hit):
        v = self._mock(monkeypatch, {None: {"result": {"hits": [hit]}}})
        with pytest.raises(ValueError):
            v._censys({"token": "t", "org": "o"}, "acme.com", max_pages=5)

    def test_request_selects_only_cert_names_field(self, monkeypatch):
        from quarry_recon.phases import vertical
        captured = {}

        def fake(req, timeout=30):
            captured.update(json.loads(req.data.decode()))
            return _Resp(json.dumps({"result": {"hits": [{"certificate_v1": {"resource": {"names": ["a.acme.com"]}}}]}}).encode())
        monkeypatch.setattr(vertical.urllib.request, "urlopen", fake)
        vertical._censys({"token": "t", "org": "o"}, "acme.com", max_pages=1)
        assert captured.get("fields") == ["cert.names"]       # request only the field we parse

    def test_names_extracted_from_structured_hits_only(self, monkeypatch):
        # a hostname in an ERROR/message field (outside hits) must NOT yield a phantom host
        pages = {None: {"result": {"hits": [{"certificate_v1": {"resource": {"names": ["real.acme.com"]}},
                                             "message": "evil.acme.com inside the hit"}]}}}
        v = self._mock(monkeypatch, pages)
        hosts = v._censys({"token": "t", "org": "o"}, "acme.com", max_pages=1)
        assert "real.acme.com" in hosts and "evil.acme.com" not in hosts

    def test_later_page_failure_keeps_earlier_hosts(self, monkeypatch):
        # review-r2#4: page 2 errors -> KEEP page 1's hosts as PARTIAL with the error class (never discard them)
        from quarry_recon.phases import vertical
        n = {"i": 0}

        def fake(req, timeout=30):
            n["i"] += 1
            if n["i"] == 1:
                return _Resp(json.dumps({"result": {"hits": [{"certificate_v1": {"resource": {"names": ["a.acme.com"]}}}], "links": {"next": "t1"}}}).encode())
            raise urllib.error.HTTPError("u", 429, "rate", {}, None)   # page 2 fails
        monkeypatch.setattr(vertical.urllib.request, "urlopen", fake)
        r = vertical._censys({"token": "t", "org": "o"}, "acme.com", max_pages=5)
        assert isinstance(r, ProviderResult) and r.partial and "a.acme.com" in r and r.error_class == "rate_limit"

    def test_first_page_failure_propagates(self, monkeypatch):
        # review-r2#4: a FIRST-page failure has no earlier evidence -> propagate (run_provider -> FAILED)
        from quarry_recon.phases import vertical

        def fake(req, timeout=30):
            raise urllib.error.HTTPError("u", 403, "forbidden", {}, None)
        monkeypatch.setattr(vertical.urllib.request, "urlopen", fake)
        with pytest.raises(urllib.error.HTTPError):
            vertical._censys({"token": "t", "org": "o"}, "acme.com", max_pages=5)


class TestRunProviderPartialOnTruncation:
    @pytest.fixture(autouse=True)
    def _ev(self, tmp_path):
        events.reset(); events.configure(tmp_path)
        yield
        events.reset()

    def test_partial_result_records_partial_terminal_and_coverage(self, tmp_path):
        pr = ProviderResult({"a.acme.com", "b.acme.com"}, partial=True, cursor="t9", pages=5)
        out = contract.run_provider("vertical.censys", lambda: pr)
        assert out == {"a.acme.com", "b.acme.com"}                # results still returned + ingested
        term, evs = _terminal(tmp_path)
        assert term["status"] == "partial" and "TRUNCATED" in (term.get("reason") or "")
        cov = [e for e in evs if e["event"] == "coverage_partial" and e.get("measure") == "pagination"]
        assert cov                                                # a truncated page-cap is a recorded gap

    def test_complete_result_is_success(self, tmp_path):
        out = contract.run_provider("vertical.censys", lambda: ProviderResult({"a.acme.com"}, partial=False))
        term, _ = _terminal(tmp_path)
        assert term["status"] == "success" and out == {"a.acme.com"}

    def _pagination_cov(self, tmp_path):
        evs = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        return [e for e in evs if e["event"] == "coverage_partial" and e.get("measure") == "pagination"]

    def test_truncation_coverage_is_structured_for_the_verdict(self, tmp_path):
        # review-r2#1: STRUCTURED counters (eligible/tested/omitted + unit) so _read_coverage feeds the verdict
        pr = ProviderResult({"a.acme.com"}, partial=True, cursor="t9", pages=5)
        contract.run_provider("vertical.censys", lambda: pr, work_unit="wu-apex-a")
        cov = self._pagination_cov(tmp_path)
        assert cov and cov[0]["eligible"] == 1 and cov[0]["tested"] == 0 and cov[0]["omitted"] == 1
        assert cov[0]["unit"] == "wu-apex-a"

    def test_complete_run_emits_zero_omitted_to_clear(self, tmp_path):
        contract.run_provider("vertical.censys", lambda: ProviderResult({"a"}, partial=False, pages=3), work_unit="wu-apex-a")
        cov = self._pagination_cov(tmp_path)
        assert cov and cov[0]["omitted"] == 0 and cov[0]["tested"] == 1   # clears a prior truncation gap

    def test_apexes_have_independent_pagination_units(self, tmp_path):
        contract.run_provider("vertical.censys", lambda: ProviderResult({"a"}, partial=True, pages=5), work_unit="wu-a")
        contract.run_provider("vertical.censys", lambda: ProviderResult({"b"}, partial=False, pages=3), work_unit="wu-b")
        units = {e["unit"]: e["omitted"] for e in self._pagination_cov(tmp_path)}
        assert units == {"wu-a": 1, "wu-b": 0}                # each apex reconciles alone

    def test_verdict_sees_the_pagination_gap(self, tmp_path):
        # end-to-end: a truncated pagination unit must surface in the store's coverage rollup (feeds verdict)
        from quarry_recon.store import Run
        run = Run.create(tmp_path, "t"); events.reset(); events.configure(run.dir)
        contract.run_provider("vertical.censys", lambda: ProviderResult({"a"}, partial=True, pages=5), work_unit="wu-a")
        cov = run._read_coverage()
        cen = [c for c in cov if c["source_id"] == "vertical.censys"]
        assert cen and cen[0]["omitted"] >= 1                 # the truncation is a real, counted gap
        events.reset()


def test_work_unit_folds_account_scope():
    # review-r5#5: a changed org / credential must change the resume identity (via a fingerprint, never the secret)
    from quarry_recon import events, secrets
    base = events.work_unit("vertical.censys", inputs={"apex": "acme.com"},
                            config={"max_pages": 5, "org": "org-1", "cred_fp": secrets.fingerprint("TOKEN-A")})
    diff_org = events.work_unit("vertical.censys", inputs={"apex": "acme.com"},
                               config={"max_pages": 5, "org": "org-2", "cred_fp": secrets.fingerprint("TOKEN-A")})
    diff_cred = events.work_unit("vertical.censys", inputs={"apex": "acme.com"},
                                config={"max_pages": 5, "org": "org-1", "cred_fp": secrets.fingerprint("TOKEN-B")})
    assert base != diff_org and base != diff_cred
    assert secrets.fingerprint("TOKEN-A") != "TOKEN-A"        # a fingerprint, not the raw credential


def test_provider_lanes_carry_work_unit_and_literal_source_ids():
    # review-r3#5/#6: cloud + shodan lanes pass a stable work_unit AND use LITERAL registered source_ids
    # (no constructed f"probe.{label}" that bypasses the registry scan).
    import inspect
    from quarry_recon.phases import probe
    from quarry_recon import cloud
    psrc = inspect.getsource(probe)
    assert 'run_provider("probe.favicon"' in psrc and 'run_provider("probe.cert"' in psrc
    assert "work_unit=wu" in psrc
    assert 'f"probe.{label}"' not in psrc                 # the constructed source_id anti-pattern is gone
    csrc = inspect.getsource(cloud)
    assert 'run_provider("horizontal.cloud_buckets"' in csrc and "work_unit=wu" in csrc


class TestVerdictFoldsProviderTerminals:
    """review-r3#1: a provider terminal (run_provider) must reach the verdict — providers never hit _tool_runs,
    so without this a FAILED/PARTIAL provider left the run looking complete."""

    def _summary(self, tmp_path, run):
        run.write_manifest({}, ["vertical"])
        return json.loads(run.manifest_path.read_text())["summary"]

    def test_failed_provider_makes_run_incomplete(self, tmp_path):
        from quarry_recon.store import Run
        run = Run.create(tmp_path, "t"); events.reset(); events.configure(run.dir)
        contract.run_provider("vertical.crtsh",
                              lambda: (_ for _ in ()).throw(urllib.error.HTTPError("u", 403, "x", {}, None)),
                              work_unit="wu-apex-a")
        s = self._summary(tmp_path, run)
        assert s["verdict"] == "complete_with_gaps"
        f = [x for x in s["failures"] if x["tool"] == "vertical.crtsh"]
        assert f and f[0]["error_class"] == "forbidden"
        events.reset()

    def test_partial_provider_is_a_gap(self, tmp_path):
        from quarry_recon.store import Run
        run = Run.create(tmp_path, "t"); events.reset(); events.configure(run.dir)
        contract.run_provider("vertical.certspotter",
                              lambda: ProviderResult({"a.acme.com"}, partial=True, pages=5), work_unit="wu-a")
        s = self._summary(tmp_path, run)
        assert s["verdict"] == "complete_with_gaps"
        assert any(g.get("tool") == "vertical.certspotter" and g.get("status") == "partial" for g in s["gaps"])
        events.reset()

    def test_clean_provider_does_not_gate(self, tmp_path):
        from quarry_recon.store import Run
        run = Run.create(tmp_path, "t"); events.reset(); events.configure(run.dir)
        contract.run_provider("vertical.crtsh", lambda: ProviderResult({"a.acme.com"}, partial=False), work_unit="wu-a")
        s = self._summary(tmp_path, run)
        assert not any(x["tool"] == "vertical.crtsh" for x in s["failures"])
        events.reset()

    def test_changed_work_unit_generation_clears_old_failure(self, tmp_path):
        # review-r4#3: a FAILED wu-old in session 1, then a SUCCESS wu-new in session 2 (changed config ->
        # changed work_unit) must NOT leave the old failure gating — the generation reset supersedes it.
        from quarry_recon.store import Run
        run = Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)             # session 1
        contract.run_provider("vertical.certspotter",
                              lambda: (_ for _ in ()).throw(urllib.error.HTTPError("u", 403, "x", {}, None)),
                              work_unit="wu-old")
        events.reset(); events.configure(run.dir)             # session 2 (resume, same log)
        contract.run_provider("vertical.certspotter",
                              lambda: ProviderResult({"a.acme.com"}, partial=False, pages=1), work_unit="wu-new")
        s = self._summary(tmp_path, run)
        assert not any(x["tool"] == "vertical.certspotter" for x in s["failures"])   # old failure superseded
        events.reset()

    def test_crash_between_start_and_terminal_is_a_gap(self, tmp_path):
        # review-r5#1: session 1 SUCCESS; session 2 opens a new generation (reset persisted at START) then
        # CRASHES before the terminal. The verdict must show a GAP (incomplete), NOT the old success.
        from quarry_recon.store import Run
        run = Run.create(tmp_path, "t"); events.reset(); events.configure(run.dir)
        contract.run_provider("vertical.crtsh", lambda: ProviderResult({"a.acme.com"}, partial=False, pages=1),
                              work_unit="wu-a")
        events.reset(); events.configure(run.dir)             # session 2 (resume, same log)
        events.tool_start("vertical.crtsh", provider=True, reset_generation=True, work_unit="wu-b")  # ...then crash
        s = self._summary(tmp_path, run)
        assert s["verdict"] == "complete_with_gaps"
        assert any(g["tool"] == "vertical.crtsh" and g["status"] == "incomplete" for g in s["gaps"])
        assert not any(x["tool"] == "vertical.crtsh" for x in s["failures"])   # old success superseded
        events.reset()

    def test_provider_terminals_count_toward_tool_status(self, tmp_path):
        # review-r4#6: a clean provider increments tool_status (a tools_failed without a matching status count lies)
        from quarry_recon.store import Run
        run = Run.create(tmp_path, "t"); events.reset(); events.configure(run.dir)
        contract.run_provider("vertical.crtsh", lambda: ProviderResult({"a.acme.com"}, partial=False, pages=1),
                              work_unit="wu-a")
        s = self._summary(tmp_path, run)
        assert s["tool_status"].get("success", 0) >= 1        # the clean provider is counted
        events.reset()

    def test_latest_terminal_per_unit_wins(self, tmp_path):
        # a retried provider that FAILED then SUCCEEDED for the same (source, work_unit) must not still gate
        from quarry_recon.store import Run
        run = Run.create(tmp_path, "t"); events.reset(); events.configure(run.dir)
        contract.run_provider("vertical.crtsh",
                              lambda: (_ for _ in ()).throw(urllib.error.URLError("boom")), work_unit="wu-a")
        contract.run_provider("vertical.crtsh", lambda: ProviderResult({"a.acme.com"}, partial=False), work_unit="wu-a")
        s = self._summary(tmp_path, run)
        assert not any(x["tool"] == "vertical.crtsh" for x in s["failures"])   # latest (success) cleared it
        events.reset()


class TestCloudCheckTriState:
    def _mock(self, monkeypatch, behavior):
        from quarry_recon import cloud
        monkeypatch.setattr(cloud.urllib.request, "urlopen", behavior)
        return cloud

    def test_transport_error_is_indeterminate_not_absent(self, monkeypatch):
        def boom(req, timeout=8):
            raise urllib.error.URLError("dns fail")
        assert self._mock(monkeypatch, boom)._check("https://x.s3.amazonaws.com/") == (None, None)

    def test_timeout_is_indeterminate(self, monkeypatch):
        def slow(req, timeout=8):
            raise socket.timeout("slow")
        assert self._mock(monkeypatch, slow)._check("https://x.s3.amazonaws.com/")[0] is None

    def test_404_is_definitive_absence(self, monkeypatch):
        def nf(req, timeout=8):
            raise urllib.error.HTTPError("u", 404, "no", {}, None)
        assert self._mock(monkeypatch, nf)._check("https://x.s3.amazonaws.com/") == (False, None)

    def test_403_is_private_existing(self, monkeypatch):
        def priv(req, timeout=8):
            raise urllib.error.HTTPError("u", 403, "forbidden", {}, None)
        assert self._mock(monkeypatch, priv)._check("https://x.s3.amazonaws.com/") == (True, "private")

    def test_5xx_is_indeterminate_not_absent(self, monkeypatch):
        def err(req, timeout=8):
            raise urllib.error.HTTPError("u", 503, "unavailable", {}, None)
        assert self._mock(monkeypatch, err)._check("https://x.s3.amazonaws.com/") == (None, None)


class TestCloudDiscoverCoverage:
    def _profile(self, orgs):
        from types import SimpleNamespace
        return SimpleNamespace(passive_only=False, apex_domains=["acme.com"], org_names=orgs, brands=[])

    def _ctx(self, monkeypatch, tmp_path, profile, check):
        from types import SimpleNamespace
        from quarry_recon import cloud
        events.reset(); events.configure(tmp_path)
        monkeypatch.setattr(cloud, "_check", check)
        recorded = []
        run = SimpleNamespace(add=lambda e, r: (recorded.append(r), True)[1])
        return cloud, SimpleNamespace(profile=profile, run=run), recorded

    def _cov(self, tmp_path, measure):
        evs = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        return [e for e in evs if e["event"] == "coverage_partial" and e.get("measure") == measure]

    def test_name_cap_is_structured_and_every_run(self, monkeypatch, tmp_path):
        orgs = [f"org{i}" for i in range(10)]                 # 10 seeds x 24 suffixes = 240 > 120 cap
        cloud, ctx, _ = self._ctx(monkeypatch, tmp_path, self._profile(orgs), lambda url, timeout=8: (False, None))
        cloud.discover(ctx)
        cap = self._cov(tmp_path, "bucket_names")
        assert cap and cap[0]["omitted"] > 0 and cap[0]["tested"] == 120 and cap[0]["unit"] == "cloud.bucket_names"

    def test_indeterminate_probes_are_structured_timeout(self, monkeypatch, tmp_path):
        cloud, ctx, _ = self._ctx(monkeypatch, tmp_path, self._profile([]), lambda url, timeout=8: (None, None))
        cloud.discover(ctx)
        pr = self._cov(tmp_path, "bucket_probes")
        assert pr and pr[0]["kind"] == "timeout" and pr[0]["omitted"] == pr[0]["eligible"] and pr[0]["omitted"] > 0

    def test_clean_run_emits_zero_omitted_to_clear(self, monkeypatch, tmp_path):
        # a clean rerun (no cap, no indeterminate) must still EMIT both units with omitted=0 so a prior gap clears
        cloud, ctx, _ = self._ctx(monkeypatch, tmp_path, self._profile([]), lambda url, timeout=8: (False, None))
        cloud.discover(ctx)
        assert self._cov(tmp_path, "bucket_names")[0]["omitted"] == 0
        assert self._cov(tmp_path, "bucket_probes")[0]["omitted"] == 0

    def test_indeterminate_is_not_recorded_as_found(self, monkeypatch, tmp_path):
        cloud, ctx, recorded = self._ctx(monkeypatch, tmp_path, self._profile([]), lambda url, timeout=8: (None, None))
        assert cloud.discover(ctx) == 0 and not recorded


class TestShodanPivot:
    def _ctx(self, tmp_path):
        from types import SimpleNamespace
        events.reset(); events.configure(tmp_path)
        added = []
        run = SimpleNamespace(
            raw_path=lambda ph, lb, nm: (tmp_path / ph / lb).joinpath(nm) if
            (tmp_path / ph / lb).mkdir(parents=True, exist_ok=True) or True else None,
            add=lambda e, r: (added.append((e, r)), True)[1],
            read=lambda e: [])
        scope = SimpleNamespace(in_scope=lambda h: h.endswith("acme.com"), is_oos=lambda h: False)
        return SimpleNamespace(run=run, scope=scope, echo=lambda *a: None), added

    def _cov(self, tmp_path, measure):
        evs = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        return [e for e in evs if e["event"] == "coverage_partial" and e.get("measure") == measure]

    def test_failed_pivots_are_classified_not_swallowed(self, monkeypatch, tmp_path):
        from quarry_recon.phases import probe
        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 1)

        def auth_fail(req, timeout=20):
            raise urllib.error.HTTPError("u", 401, "unauthorized", {}, None)
        monkeypatch.setattr(probe.urllib.request, "urlopen", auth_fail)
        ctx, _ = self._ctx(tmp_path)
        # review-r3#4: ALL pivots fail with no results -> RAISE (run_provider records FAILED + classified),
        # never a silent clean EMPTY. Coverage is still emitted before the raise.
        with pytest.raises(urllib.error.HTTPError):
            probe._shodan_pivot(ctx, "badkey", ["h1", "h2"], "http.favicon.hash", "favicon-shodan", "probe.favicon", "{}")
        piv = self._cov(tmp_path, "shodan_pivots")
        assert piv and piv[0]["omitted"] == 2 and "auth" in (piv[0].get("reason") or "")   # both auth-failed, recorded

    def test_all_fail_via_run_provider_is_failed_terminal(self, monkeypatch, tmp_path):
        # end-to-end: total failure -> run_provider FAILED terminal with the classified error (not EMPTY)
        from quarry_recon.phases import probe
        from quarry_recon import contract
        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 1)
        monkeypatch.setattr(probe.urllib.request, "urlopen",
                            lambda req, timeout=20: (_ for _ in ()).throw(urllib.error.HTTPError("u", 429, "rate", {}, None)))
        ctx, _ = self._ctx(tmp_path)
        out = contract.run_provider("probe.favicon", lambda: probe._shodan_pivot(
            ctx, "k", ["h1"], "http.favicon.hash", "favicon-shodan", "probe.favicon", "{}"))
        assert out is None
        term = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines() if '"tool_finish"' in l]
        assert term[-1]["status"] == "failed" and term[-1]["error_class"] == "rate_limit"

    def test_some_fail_is_partial_with_dominant_class(self, monkeypatch, tmp_path):
        # SOME pivots fail (with a successful one) -> PARTIAL ProviderResult carrying the dominant error class
        from quarry_recon.phases import probe
        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 1)

        def mixed(req, timeout=20):
            if "h_bad" in req.full_url:
                raise urllib.error.HTTPError("u", 429, "rate", {}, None)
            return _Resp(json.dumps({"total": 1, "matches": [{"hostnames": ["real.acme.com"]}]}).encode())
        monkeypatch.setattr(probe.urllib.request, "urlopen", mixed)
        ctx, _ = self._ctx(tmp_path)
        r = probe._shodan_pivot(ctx, "k", ["h_good", "h_bad"], "http.favicon.hash", "favicon-shodan", "probe.favicon", "{}")
        assert isinstance(r, ProviderResult) and r.partial and r.error_class == "rate_limit" and "real.acme.com" in r

    def test_truncation_flagged_when_total_exceeds_paged(self, monkeypatch, tmp_path):
        from quarry_recon.phases import probe
        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 1)   # 1 page only

        def big(req, timeout=20):
            # total 150 but page 1 only returns 100 -> truncated at 1 page (credit-bounded)
            return _Resp(json.dumps({"total": 150,
                                     "matches": [{"hostnames": [f"h{i}.acme.com"]} for i in range(100)]}).encode())
        monkeypatch.setattr(probe.urllib.request, "urlopen", big)
        ctx, added = self._ctx(tmp_path)
        probe._shodan_pivot(ctx, "k", ["hashX"], "http.favicon.hash", "favicon-shodan", "probe.favicon", "{}")
        res = self._cov(tmp_path, "shodan_results")
        assert res and res[0]["omitted"] == 1 and res[0]["kind"] == "cap"     # 1 pivot truncated

    def test_preseeded_host_clean_rerun_is_success_not_empty(self, monkeypatch, tmp_path):
        # review-r6#1: a host already in the store (Run.add -> False) must STILL appear in `found` — the
        # response HAD it. Gating found on the new-key return made a clean rerun a false EMPTY.
        from quarry_recon.phases import probe
        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 1)
        monkeypatch.setattr(probe.urllib.request, "urlopen",
                            lambda req, timeout=20: _Resp(json.dumps({"total": 1, "matches": [{"hostnames": ["seen.acme.com"]}]}).encode()))
        ctx, added = self._ctx(tmp_path)
        monkeypatch.setattr(ctx.run, "add", lambda e, r: False)   # store already has it (dedup -> False)
        found = probe._shodan_pivot(ctx, "k", ["hX"], "http.favicon.hash", "favicon-shodan", "probe.favicon", "{}")
        assert found == {"seen.acme.com"}                     # present despite the store dedup -> SUCCESS, not EMPTY

    def test_large_response_writes_complete_valid_jsonl(self, monkeypatch, tmp_path):
        # review-r7#2: the artifact holds the COMPLETE evidence as valid JSONL — never sliced/truncated, so an
        # ingested host's evidence is actually present in its raw_ref (no false provenance).
        from quarry_recon.phases import probe
        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 1)
        big = [{"hostnames": [f"h{i}.acme.com"], "pad": "x" * 4096} for i in range(1000)]   # > 2 MiB serialized
        monkeypatch.setattr(probe.urllib.request, "urlopen",
                            lambda req, timeout=20: _Resp(json.dumps({"total": 1000, "matches": big}).encode()))
        ctx, _ = self._ctx(tmp_path)
        found = probe._shodan_pivot(ctx, "k", ["hX"], "http.favicon.hash", "favicon-shodan", "probe.favicon", "{}")
        art = list((tmp_path / "probe" / "favicon").glob("*.jsonl"))[0]
        rows = [json.loads(ln) for ln in art.read_text().splitlines()]   # every line valid JSON
        assert len(rows) == 1000                              # COMPLETE — no truncation
        assert "h999.acme.com" in found and rows[-1]["hostnames"] == ["h999.acme.com"]   # last host's evidence present

    def test_high_total_still_ingests_in_scope(self, monkeypatch, tmp_path):
        # review-r2#3: a generic high-`total` pivot must NOT drop valid in-scope hosts — only off-scope noise is bounded
        from quarry_recon.phases import probe
        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 1)

        def big(req, timeout=20):
            ms = [{"hostnames": ["real.acme.com"]}] + [{"hostnames": [f"junk{i}.example.org"]} for i in range(99)]
            return _Resp(json.dumps({"total": 5000, "matches": ms}).encode())   # total>200, once dropped everything
        monkeypatch.setattr(probe.urllib.request, "urlopen", big)
        ctx, added = self._ctx(tmp_path)
        found = probe._shodan_pivot(ctx, "k", ["hashX"], "http.favicon.hash", "favicon-shodan", "probe.favicon", "{}")
        assert "real.acme.com" in found                       # in-scope kept despite the huge total
        assert sum(1 for e, r in added if e == "review") <= 15   # off-scope review bounded

    def test_pivot_cap_reported_and_zero_units_emitted(self, monkeypatch, tmp_path):
        from quarry_recon.phases import probe
        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 1)
        monkeypatch.setattr(probe.urllib.request, "urlopen",
                            lambda req, timeout=20: _Resp(json.dumps({"total": 0, "matches": []}).encode()))
        ctx, _ = self._ctx(tmp_path)
        probe._shodan_pivot(ctx, "k", [f"h{i}" for i in range(30)], "http.favicon.hash", "favicon-shodan", "probe.favicon", "{}")
        cap = self._cov(tmp_path, "shodan_pivot_values")
        assert cap and cap[0]["eligible"] == 30 and cap[0]["tested"] == 20 and cap[0]["omitted"] == 10
        # zero-count units still emitted so a prior gap clears
        assert self._cov(tmp_path, "shodan_pivots")[0]["omitted"] == 0

    @pytest.mark.parametrize("body", [
        {"total": 1, "matches": [None]},                     # review-r3#3: a null row is NOT a clean empty
        {"total": 1, "matches": "oops"},                     # non-list matches
        {"total": -1, "matches": []},                        # bad total
        {"total": 1, "matches": [{"hostnames": 12345}]},     # non-list hostnames (would crash later)
    ])
    def test_fail_closed_parser_rejects_bad_shapes(self, monkeypatch, tmp_path, body):
        # each malformed shape must be a CLASSIFIED parse failure (the only val -> all-fail -> RAISE), never a
        # crash and never a laundered clean empty.
        from quarry_recon.phases import probe
        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 1)
        monkeypatch.setattr(probe.urllib.request, "urlopen", lambda req, timeout=20: _Resp(json.dumps(body).encode()))
        ctx, added = self._ctx(tmp_path)
        with pytest.raises(ValueError):
            probe._shodan_pivot(ctx, "k", ["hashX"], "http.favicon.hash", "favicon-shodan", "probe.favicon", "{}")
        assert not added                                      # nothing ingested from a malformed response
        piv = self._cov(tmp_path, "shodan_pivots")
        assert piv and piv[-1]["omitted"] == 1 and "parse" in (piv[-1].get("reason") or "")

    def test_later_page_failure_keeps_earlier_pages(self, monkeypatch, tmp_path):
        # review-r4#1: page 2 fails -> _shodan_search returns page-1 matches + a page_error (not discarded);
        # _shodan_pivot ingests them and marks the pivot degraded.
        from quarry_recon.phases import probe
        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 3)

        def paged(req, timeout=20):
            page = int(req.full_url.split("page=")[1])
            if page == 1:
                return _Resp(json.dumps({"total": 500, "matches": [{"hostnames": [f"h{i}.acme.com"]} for i in range(100)]}).encode())
            raise urllib.error.HTTPError("u", 429, "rate", {}, None)   # page 2 fails
        monkeypatch.setattr(probe.urllib.request, "urlopen", paged)
        ms, total, pages, err = probe._shodan_search("k", "http.favicon.hash", "hX", 3)
        assert len(ms) == 100 and total == 500 and pages == 1 and isinstance(err, urllib.error.HTTPError)
        ctx, _ = self._ctx(tmp_path)
        r = probe._shodan_pivot(ctx, "k", ["hX"], "http.favicon.hash", "favicon-shodan", "probe.favicon", "{}")
        assert "h0.acme.com" in r                             # page-1 hosts preserved despite the page-2 failure
        assert isinstance(r, ProviderResult) and r.partial and r.partial_kind == "degraded"
        # review-r5#2: a DEGRADED pivot got page-1 data -> NOT counted as wholly-omitted (shodan_pivots), but
        # its result set IS incomplete (shodan_results).
        assert self._cov(tmp_path, "shodan_pivots")[0]["omitted"] == 0
        # B1.1r2: `shodan_results` now means OUR page budget only. A later page lost to a 429 is a
        # FAILURE at a later position, so it is counted in `shodan_results_failed` (a gap) — the old
        # single measure blamed Quarry's cap for a page the target rate-limited.
        assert self._cov(tmp_path, "shodan_results")[0]["omitted"] == 0
        assert self._cov(tmp_path, "shodan_results_failed")[0]["omitted"] == 1
        assert self._cov(tmp_path, "shodan_results_limited")[0]["omitted"] == 0

    def test_degraded_partial_is_not_labeled_pagination(self, monkeypatch, tmp_path):
        # review-r4#2: a generic degraded shodan PARTIAL must NOT become a "pagination TRUNCATED at None pages"
        # terminal + fabricated pagination coverage.
        from quarry_recon.phases import probe
        from quarry_recon import contract
        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 1)

        def mixed(req, timeout=20):
            if "h_bad" in req.full_url:
                raise urllib.error.HTTPError("u", 429, "rate", {}, None)
            return _Resp(json.dumps({"total": 1, "matches": [{"hostnames": ["real.acme.com"]}]}).encode())
        monkeypatch.setattr(probe.urllib.request, "urlopen", mixed)
        ctx, _ = self._ctx(tmp_path)
        contract.run_provider("probe.favicon", lambda: probe._shodan_pivot(
            ctx, "k", ["h_good", "h_bad"], "http.favicon.hash", "favicon-shodan", "probe.favicon", "{}"),
            work_unit="wu-fav")
        evs = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        term = [e for e in evs if e["event"] == "tool_finish"][-1]
        assert term["status"] == "partial" and "TRUNCATED" not in (term.get("reason") or "")
        assert not [e for e in evs if e["event"] == "coverage_partial" and e.get("measure") == "pagination"]

    def test_credit_aware_pagination_reads_more_when_configured(self, monkeypatch, tmp_path):
        from quarry_recon.phases import probe
        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 2)   # allow 2 pages
        calls = {"n": 0}

        def paged(req, timeout=20):
            calls["n"] += 1
            page = int(req.full_url.split("page=")[1])
            ms = [{"hostnames": [f"p{page}h{i}.acme.com"]} for i in range(100 if page == 1 else 50)]
            return _Resp(json.dumps({"total": 150, "matches": ms}).encode())
        monkeypatch.setattr(probe.urllib.request, "urlopen", paged)
        ctx, added = self._ctx(tmp_path)
        n = probe._shodan_pivot(ctx, "k", ["hashX"], "http.favicon.hash", "favicon-shodan", "probe.favicon", "{}")
        assert calls["n"] == 2 and len(n) == 150                   # both pages read, all 150 hosts ingested
        assert not self._cov(tmp_path, "shodan_results")[0]["omitted"]   # fully paged -> not truncated
