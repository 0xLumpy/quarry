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
    # B1.4: the Shodan lanes are declared in _SHODAN_LANES and share one coordinator, so the id reaches
    # run_provider as `spec.sid` — still a LITERAL, just declared once. What this guards against is a
    # CONSTRUCTED id (asserted below); `run_provider` itself is registry-authoritative at runtime and
    # refuses to execute an unknown source_id.
    assert '_LaneSpec("probe.favicon"' in psrc and '_LaneSpec("probe.cert"' in psrc
    # B1.4r3: the Shodan lanes are bracketed TOGETHER (run_providers), because their credit budget is
    # shared — every lane starts before any of them spends.
    assert "run_providers(entries, collect)" in psrc and "entries.append((spec.sid, wu," in psrc
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

    def _fold(self, tmp_path, result):
        from quarry_recon.store import Run
        run = Run.create(tmp_path, "t"); events.reset(); events.configure(run.dir)
        try:
            contract.run_provider("vertical.crtsh", lambda: result, work_unit="wu-a")
            return self._summary(tmp_path, run)
        finally:
            events.reset()

    def test_a_pure_OPERATOR_limit_folds_as_a_LIMIT_not_a_gap(self, tmp_path):
        """review-B1.4r7#1: reconciliation recognised a limit only by a PROVEN provider class, so an
        operator boundary — LIMITED with deliberately no class — fell into the generic gap branch and
        reversed the terminal and coverage semantics at the last step."""
        s = self._fold(tmp_path, ProviderResult({"h.acme.com"}, limited=True,
                                                partial_reason="operator reserve withheld 5 credit(s)"))
        assert s["verdict"] == "complete_with_limits", (s["gaps"], s["failures"])
        assert not s["gaps"] and not s["failures"]
        # review-B1.4r8#2: OURS, and filed as ours. `provider_limits` said the provider refused us.
        assert not s["provider_limits"], s["provider_limits"]
        assert [x["tool"] for x in s["operator_limits"]] == ["vertical.crtsh"], s["operator_limits"]
        assert s["operator_limits"][0]["origin"] == "operator"

    def test_a_PROVIDER_quota_still_folds_as_a_limit(self, tmp_path):
        """The control: the provider's own boundary is unchanged by widening the rule."""
        s = self._fold(tmp_path, ProviderResult({"h.acme.com"}, partial=True, partial_kind="degraded",
                                                error_class="quota", partial_reason="credits spent"))
        assert s["verdict"] == "complete_with_limits", (s["gaps"], s["failures"])
        assert s["provider_limits"] and not s["gaps"] and not s["operator_limits"]
        assert s["provider_limits"][0]["origin"] == "provider"

    def test_a_MALFORMED_limited_terminal_never_softens_a_real_failure(self, tmp_path):
        """A LIMITED terminal carrying a NON-limit class is a contradiction. `_partial_status` refuses to
        produce one, but reconciliation must not TRUST that — the guard is what stops a hand-built or
        future-miswired terminal from laundering a transport failure into a soft limit."""
        import quarry_recon.contract as c
        assert c.terminal_is_limit("limited", "transport") is False
        assert c.terminal_is_limit("limited", None) is True
        assert c.terminal_is_limit("limited", "quota") is True
        assert c.terminal_is_limit("partial", None) is False
        # review-B1.4r8#1: the REVERSE malformed combination. The class alone used to be enough, so a
        # FAILED/quota terminal folded as complete_with_limits with an EMPTY failure list.
        assert c.terminal_is_limit("failed", "quota") is False
        assert c.terminal_is_limit("partial", "entitlement") is False

    def test_a_FAILED_terminal_carrying_a_quota_class_stays_a_FAILURE(self, tmp_path):
        """The folded half of the same defect, end to end."""
        from quarry_recon.store import Run
        run = Run.create(tmp_path, "t"); events.reset(); events.configure(run.dir)
        try:
            (run.dir / "events.jsonl").write_text(json.dumps({
                "event": "tool_finish", "source_id": "vertical.crtsh", "status": "failed",
                "provider": True, "error_class": "quota", "reason": "hand-built contradiction",
                "work_unit": "wu-a"}) + "\n")
            s = self._summary(tmp_path, run)
        finally:
            events.reset()
        assert s["verdict"] == "complete_with_gaps", (s["gaps"], s["failures"])
        assert s["failures"] and not s["provider_limits"] and not s["operator_limits"]

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


SHODAN_QUOTA_BODY = ('{"error": "Insufficient query credits, please upgrade your API plan or wait for '
                     'the monthly limit to reset"}')


def _http_err(code, body):
    """An HTTPError carrying a real readable body, like urllib produces."""
    import io
    return urllib.error.HTTPError("http://x", code, "msg", {}, io.BytesIO(body.encode()))


def _with_balance(responder, *, credits=100):
    """Answer `/api-info` from a HEALTHY balance and send everything else to `responder`.

    B1.4: the lane reads its credit balance before scheduling any paid page, so a responder that answers
    EVERY url makes the balance read consume the scenario's first scripted response. `/api-info` is free
    and keeps working at a zero balance (measured), so a fixture where it fails alongside the search is
    testing a state Shodan does not produce."""
    class _Bal:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n=None):
            return json.dumps({"query_credits": credits, "scan_credits": 0,
                               "usage_limits": {"query_credits": credits}}).encode()

    def route(req, timeout=20):
        if "api-info" in str(getattr(req, "full_url", req)):
            return _Bal()
        return responder(req, timeout=timeout)
    return route


class TestShodanPivot:
    def _ctx(self, tmp_path):
        from types import SimpleNamespace
        events.reset(); events.configure(tmp_path)
        added = []
        run = SimpleNamespace(
            raw_path=lambda ph, lb, nm: (tmp_path / ph / lb).joinpath(nm) if
            (tmp_path / ph / lb).mkdir(parents=True, exist_ok=True) or True else None,
            dir=tmp_path,                 # B1.4: the coordinator's ledger/attempt tree lives under it
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
        monkeypatch.setattr(probe.urllib.request, "urlopen", _with_balance(auth_fail))
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
        monkeypatch.setattr(probe.urllib.request, "urlopen", _with_balance(lambda req, timeout=20: (_ for _ in ()).throw(urllib.error.HTTPError("u", 429, "rate", {}, None))))
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
        monkeypatch.setattr(probe.urllib.request, "urlopen", _with_balance(mixed))
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
        monkeypatch.setattr(probe.urllib.request, "urlopen", _with_balance(big))
        ctx, added = self._ctx(tmp_path)
        probe._shodan_pivot(ctx, "k", ["hashX"], "http.favicon.hash", "favicon-shodan", "probe.favicon", "{}")
        # B1.4: our page budget is counted in PAGES (total 150 = 2 pages, we bought 1). Still a CAP —
        # review-B1 (Lumpy): "SHODAN_MAX_PAGES=1 is still a cap".
        res = self._cov(tmp_path, "shodan_pages_withheld")
        assert res and res[0]["omitted"] == 1 and res[0]["kind"] == "cap"

    def test_preseeded_host_clean_rerun_is_success_not_empty(self, monkeypatch, tmp_path):
        # review-r6#1: a host already in the store (Run.add -> False) must STILL appear in `found` — the
        # response HAD it. Gating found on the new-key return made a clean rerun a false EMPTY.
        from quarry_recon.phases import probe
        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 1)
        monkeypatch.setattr(probe.urllib.request, "urlopen", _with_balance(lambda req, timeout=20: _Resp(json.dumps({"total": 1, "matches": [{"hostnames": ["seen.acme.com"]}]}).encode())))
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
        monkeypatch.setattr(probe.urllib.request, "urlopen", _with_balance(lambda req, timeout=20: _Resp(json.dumps({"total": 1000, "matches": big}).encode())))
        ctx, _ = self._ctx(tmp_path)
        found = probe._shodan_pivot(ctx, "k", ["hX"], "http.favicon.hash", "favicon-shodan", "probe.favicon", "{}")
        # B1.4: evidence is now ONE ARTIFACT PER PAGE, published by the coordinator and content-bound in
        # the ledger, instead of one appended JSONL per pivot. The provenance property is unchanged and
        # is what this test protects: the artifact a host's `raw_ref` points at really does contain that
        # host's row — never sliced, never truncated.
        art = list((tmp_path / "raw" / "probe" / "shodan").rglob("*.json"))
        art = [q for q in art if q.name != ".quarry-write-probe"]
        assert len(art) == 1, [str(q) for q in art]
        rows = json.loads(art[0].read_text())["matches"]
        assert len(rows) == 1000                              # COMPLETE — no truncation
        assert "h999.acme.com" in found and rows[-1]["hostnames"] == ["h999.acme.com"]

    def test_high_total_still_ingests_in_scope(self, monkeypatch, tmp_path):
        # review-r2#3: a generic high-`total` pivot must NOT drop valid in-scope hosts. B1.5b: off-scope
        # candidates are no longer bounded either — nothing about cardinality removes membership.
        from quarry_recon.phases import probe
        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 1)

        def big(req, timeout=20):
            ms = [{"hostnames": ["real.acme.com"]}] + [{"hostnames": [f"junk{i}.example.org"]} for i in range(99)]
            return _Resp(json.dumps({"total": 5000, "matches": ms}).encode())   # total>200, once dropped everything
        monkeypatch.setattr(probe.urllib.request, "urlopen", _with_balance(big))
        ctx, added = self._ctx(tmp_path)
        found = probe._shodan_pivot(ctx, "k", ["hashX"], "http.favicon.hash", "favicon-shodan", "probe.favicon", "{}")
        assert "real.acme.com" in found                       # in-scope kept despite the huge total
        # B1.5b: off-scope candidates are RETAINED IN FULL. The old first-N slice dropped them by page
        # order, so which related hosts an operator ever saw depended on where they appeared. The RoE
        # boundary is OBSERVE, never expand — retention costs no traffic (see the active-queue test).
        assert sum(1 for e, r in added if e == "review") == 99

    def test_EVERY_pivot_value_is_queried_and_none_is_sliced_away(self, monkeypatch, tmp_path):
        """review-B1.4r2#2: `all_vals[:20]` truncated MEMBERSHIP — it picked WHICH pivots to query by
        store order, so a 30-hash lane silently lost 10 of them and which 10 depended on discovery
        order. Reporting it as a gap made it honest without making it right. Throughput is bounded by
        the credit balance and the page policy; membership is not bounded at all."""
        from quarry_recon.phases import probe
        calls = []

        def counted(req, timeout=20):
            calls.append(str(req.full_url))
            return _Resp(json.dumps({"total": 0, "matches": []}).encode())

        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 1)
        monkeypatch.setattr(probe.urllib.request, "urlopen", _with_balance(counted, credits=1000))
        ctx, _ = self._ctx(tmp_path)
        probe._shodan_pivot(ctx, "k", [f"h{i}" for i in range(30)], "http.favicon.hash",
                            "favicon-shodan", "probe.favicon", "{}")
        assert len(calls) == 30, f"{len(calls)}/30 pivot values queried"
        # zero-count units still emitted so a prior gap clears
        assert self._cov(tmp_path, "shodan_pivots")[0]["omitted"] == 0
        assert self._cov(tmp_path, "shodan_pivot_values") == [], "the membership cap measure survived"

    def _events(self, tmp_path):
        return [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]

    def _both_lanes(self, monkeypatch, tmp_path, responder, *, credits=100, key="KEY"):
        from quarry_recon.phases import probe
        from quarry_recon import secrets
        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 0)
        monkeypatch.setattr(probe.secrets, "shodan", lambda: key)
        monkeypatch.setattr(secrets, "shodan", lambda: key)
        monkeypatch.setattr(probe.urllib.request, "urlopen", _with_balance(responder, credits=credits))
        ctx, _added = self._ctx(tmp_path)
        ctx.run.read = lambda e: ([{"favicon": "F1"}] if e == "live"
                                  else [{"sha1": "C1"}] if e == "certificate" else [])
        probe._shodan_pivots(ctx)
        return self._events(tmp_path)

    def test_EVERY_lane_starts_before_ANY_credit_is_spent(self, monkeypatch, tmp_path):
        """review-B1.4r3#1: the shared coordinator ran BEFORE either bracket, so /api-info and paid
        searches happened before `tool_start` and before the generation reset. An interruption mid-spend
        then left credits gone with no lane lifecycle and a stale previous generation still standing."""
        order = []

        def watched(req, timeout=20):
            order.append(("http", str(req.full_url)))
            return _Resp(json.dumps({"total": 1, "matches": []}).encode())

        import quarry_recon.events as ev
        real = ev.tool_start
        monkeypatch.setattr(ev, "tool_start",
                            lambda sid, **k: (order.append(("start", sid)), real(sid, **k))[1])
        self._both_lanes(monkeypatch, tmp_path, watched)
        starts = [i for i, (kind, _v) in enumerate(order) if kind == "start"]
        https = [i for i, (kind, _v) in enumerate(order) if kind == "http"]
        assert len(starts) == 2, [o for o in order if o[0] == "start"]
        assert max(starts) < min(https), f"spent before every lane was started: {order[:6]}"

    def test_a_failure_in_ONE_lane_does_not_contaminate_the_OTHER(self, monkeypatch, tmp_path):
        """review-B1.4r3#2: one global last-error decided both terminals — cert taking a 500 and favicon
        a quota reported BOTH as FAILED/server."""
        def split(req, timeout=20):
            if "ssl.cert.fingerprint" in req.full_url:
                raise _http_err(500, "upstream exploded")
            raise _http_err(401, SHODAN_QUOTA_BODY)

        evs = self._both_lanes(monkeypatch, tmp_path, split)
        term = {e["source_id"]: e for e in evs if e.get("event") == "tool_finish"}
        assert term["probe.cert"]["status"] == "failed", term["probe.cert"]
        assert term["probe.cert"]["error_class"] == "server", term["probe.cert"]
        assert term["probe.favicon"]["status"] == "limited", term["probe.favicon"]
        assert term["probe.favicon"]["error_class"] == "quota", term["probe.favicon"]

    def test_a_STARVED_lane_never_reports_a_clean_EMPTY(self, monkeypatch, tmp_path):
        """review-B1.4r3#3: with one credit and two eligible lanes, the loser emitted
        `shodan_pivots_unqueried omitted=1` AND an EMPTY terminal — "asked, found nothing" about a pivot
        that was never asked."""
        def ok(req, timeout=20):
            return _Resp(json.dumps({"total": 10, "matches": []}).encode())

        evs = self._both_lanes(monkeypatch, tmp_path, ok, credits=1)
        term = {e["source_id"]: e for e in evs if e.get("event") == "tool_finish"}
        starved = [s for s, e in term.items() if e["status"] != "empty"]
        assert len(term) == 2 and len(starved) == 1, term
        lost = term[starved[0]]
        assert lost["status"] in ("limited", "partial") and "never queried" in (lost["reason"] or "")

    def test_an_unconfigured_lane_still_gets_a_LIFECYCLE(self, monkeypatch, tmp_path):
        """review-B1.4r3#4: a silent early return left the PREVIOUS run's terminal and coverage
        generation standing as though current. A lane that cannot run is SKIPPED, not absent."""
        def never(req, timeout=20):
            raise AssertionError("a request was issued without a key")

        evs = self._both_lanes(monkeypatch, tmp_path, never, key=None)
        term = {e["source_id"]: e for e in evs if e.get("event") == "tool_finish"}
        assert set(term) == {"probe.favicon", "probe.cert"}, term
        assert all(e["status"] == "skipped" for e in term.values()), term
        assert all(e.get("error_class") is None for e in term.values()), term

    def test_a_lane_with_no_INPUT_is_skipped_not_empty(self, monkeypatch, tmp_path):
        from quarry_recon.phases import probe
        from quarry_recon import secrets
        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 0)
        monkeypatch.setattr(probe.secrets, "shodan", lambda: "KEY")
        monkeypatch.setattr(secrets, "shodan", lambda: "KEY")
        monkeypatch.setattr(probe.urllib.request, "urlopen", _with_balance(
            lambda req, timeout=20: _Resp(json.dumps({"total": 1, "matches": []}).encode())))
        ctx, _ = self._ctx(tmp_path)
        ctx.run.read = lambda e: [{"favicon": "F1"}] if e == "live" else []   # no certificates
        probe._shodan_pivots(ctx)
        term = {e["source_id"]: e for e in self._events(tmp_path) if e.get("event") == "tool_finish"}
        assert term["probe.cert"]["status"] == "skipped", term["probe.cert"]
        assert term["probe.favicon"]["status"] in ("empty", "success"), term["probe.favicon"]

    def test_the_balance_is_reported_for_EVERY_lane(self, monkeypatch, tmp_path):
        """review-B1.4r3#4: `_emit_shodan_balance` had no production caller at all."""
        evs = self._both_lanes(monkeypatch, tmp_path,
                               lambda req, timeout=20: _Resp(json.dumps({"total": 1,
                                                                         "matches": []}).encode()))
        bals = {e["source_id"] for e in evs
                if (e.get("balance") or {}).get("provider") == "shodan"}
        assert bals == {"probe.favicon", "probe.cert"}, bals

    def test_a_PARTIALLY_queried_pivot_never_reports_clean(self, monkeypatch, tmp_path):
        """review-B1.4r4#2: the terminal read only `unqueried`, so a pivot with one bought page and four
        provider-bounded pages left reported EMPTY while its own coverage said omitted=4 — and with a
        non-empty first page it would have reported SUCCESS."""
        def one_credit(req, timeout=20):
            return _Resp(json.dumps({"total": 500, "matches": []}).encode())

        from quarry_recon.phases import probe
        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 0)
        monkeypatch.setattr(probe.urllib.request, "urlopen", _with_balance(one_credit, credits=1))
        ctx, _ = self._ctx(tmp_path)
        r = probe._shodan_pivot(ctx, "k", ["hX"], "http.favicon.hash", "favicon-shodan",
                                "probe.favicon", "{}")
        assert isinstance(r, ProviderResult) and r.partial, r
        assert "4 page(s) unbought" in (r.partial_reason or ""), r.partial_reason
        assert self._cov(tmp_path, "shodan_pages_left")[0]["omitted"] == 4

    def test_an_OPERATOR_reserve_is_LIMITED_not_degraded(self, monkeypatch, tmp_path):
        """review-B1.4r4#3: our own reserve came back as PARTIAL with no class — a DEGRADED execution,
        which asserts something went wrong when nothing did. Nor may it borrow `quota` and blame the
        provider for our policy."""
        from quarry_recon.phases import probe
        from quarry_recon.store import Run
        ctx, _ = self._ctx(tmp_path)                 # (configures events at tmp_path; re-point below)
        run = Run.create(tmp_path, "t")
        events.reset()
        events.configure(run.dir)
        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 0)
        monkeypatch.setattr(probe, "_shodan_reserve_setting", lambda: (5, True))   # withhold 5 of 6
        monkeypatch.setattr(probe.urllib.request, "urlopen", _with_balance(
            lambda req, timeout=20: _Resp(json.dumps({"total": 500, "matches": []}).encode()),
            credits=6))
        ctx.run = run
        try:
            contract.run_provider("probe.favicon", lambda: probe._shodan_pivot(
                ctx, "k", ["hA", "hB", "hC"], "http.favicon.hash", "favicon-shodan", "probe.favicon",
                "{}"), work_unit="wu")
            term = [json.loads(l) for l in (run.dir / "events.jsonl").read_text().splitlines()
                    if '"tool_finish"' in l][-1]
        finally:
            events.reset()
        assert term["status"] == "limited", term
        assert term.get("error_class") is None, "our reserve was blamed on the provider"

    def _oos_run(self, monkeypatch, tmp_path, hosts, *, pivots=("hX",)):
        from quarry_recon.phases import probe
        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 0)
        monkeypatch.setattr(probe.urllib.request, "urlopen", _with_balance(
            lambda req, timeout=20: _Resp(json.dumps(
                {"total": len(hosts), "matches": [{"hostnames": [h]} for h in hosts]}).encode()),
            credits=50))
        ctx, added = self._ctx(tmp_path)
        probe._shodan_pivot(ctx, "k", list(pivots), "http.favicon.hash", "favicon-shodan",
                            "probe.favicon", "{}")
        return [r for e, r in added if e == "review"]

    def test_a_NON_STRING_hostname_member_makes_the_page_invalid(self, monkeypatch, tmp_path):
        """review-B1.5br1#1: the LIST was validated and its MEMBERS were not, so ingest stringified
        whatever arrived — a dict became the literal "{'x': 'a.evil.com'}" and was retained because it
        contains a dot, while null and 123 vanished before any counter moved."""
        from quarry_recon.phases import probe
        for bad in ([{"x": "a.evil.com"}], [None], [123], ["ok.evil.com", None]):
            monkeypatch.setattr(probe.urllib.request, "urlopen", _with_balance(
                lambda req, timeout=20, b=bad: _Resp(json.dumps(
                    {"total": 1, "matches": [{"hostnames": b}]}).encode())))
            ms, total, err = probe._shodan_page("k", "http.favicon.hash", "hX", 1)
            assert err is not None, f"{bad} was accepted as a valid page"
            assert "non-string hostname" in str(err), (bad, err)

    def test_unicode_and_punycode_are_the_SAME_retained_host(self, monkeypatch, tmp_path):
        """One canonical form decides identity AND scope, so a name and its punycode spelling cannot
        become two candidates (nor be scoped differently)."""
        # the A-label is DERIVED, not guessed: canon_host_strict("fäßchen.evil.com") is the authority
        # (IDNA2008/UTS-46 non-transitional, so ß does NOT become ss).
        revs = self._oos_run(monkeypatch, tmp_path, ["fäßchen.evil.com", "xn--fchen-lqa8a.evil.com"])
        assert len({r["id"] for r in revs}) == 1, [r["value"] for r in revs]
        assert {r["value"] for r in revs} == {"xn--fchen-lqa8a.evil.com"}

    def _run_hosts(self, monkeypatch, tmp_path, hosts, *, in_scope="acme.com"):
        """Drive the lane with a scope where `in_scope` really is in scope, and hand back every added
        entity — so "what became a subdomain" is directly observable."""
        from quarry_recon.phases import probe
        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 0)
        monkeypatch.setattr(probe.urllib.request, "urlopen", _with_balance(
            lambda req, timeout=20: _Resp(json.dumps(
                {"total": len(hosts), "matches": [{"hostnames": [h]} for h in hosts]}).encode()),
            credits=50))
        ctx, added = self._ctx(tmp_path)
        probe._shodan_pivot(ctx, "k", ["hX"], "http.favicon.hash", "favicon-shodan", "probe.favicon",
                            "{}")
        return added

    def test_a_NON_HOST_dns_name_is_KEPT_but_NEVER_a_subdomain(self, monkeypatch, tmp_path):
        """review-B1.5br2#1: `_dmarc.acme.com` is a valid DNS OWNER NAME and not a valid hostname. It was
        stored as a `subdomain` — an entity ACTIVE lanes consume (resolution, alterx, takeover, httpx) —
        so "this lane never contacts it" was true of this lane and false of Quarry. It is real evidence
        and is retained, as PASSIVE review evidence."""
        added = self._run_hosts(monkeypatch, tmp_path, ["_dmarc.acme.com"])
        assert not [r for e, r in added if e == "subdomain"], added
        revs = [r for e, r in added if e == "review"]
        assert [r["value"] for r in revs] == ["_dmarc.acme.com"]
        assert revs[0]["klass"] == "dns-owner-name" and revs[0]["raw_ref"]
        assert "in-scope" in revs[0]["note"]
        cov = self._cov(tmp_path, "shodan_hostnames")[0]
        assert cov["omitted"] == 0 and "PASSIVE evidence" in cov["reason"], cov

    def test_the_report_labels_passive_evidence_as_PASSIVE(self, tmp_path):
        """review-B1.5br3#2: every non-sourcemap class was labelled "gf match", so passive DNS evidence
        would read as `DNS-OWNER-NAME — gf match` — an operator taking observed evidence for something
        Quarry probed. Visible, and truthfully labelled."""
        from types import SimpleNamespace
        from quarry_recon import triage
        rows = [{"klass": "dns-owner-name", "value": "_dmarc.acme.com"},
                {"klass": "related-host", "value": "oos.evil.com"},
                {"klass": "xss", "value": "https://in.acme.com/?a=1"}]
        run = SimpleNamespace(
            target="acme.com", run_id="t-1",
            read=lambda e: rows if e == "review" else [],
            values=lambda e: [], count=lambda e: 0)
        out = triage.build(run, SimpleNamespace(in_scope=lambda h: True, is_oos=lambda h: False))
        # rendered, not just tabulated: the report is what the operator actually reads
        head = [l for l in out.splitlines() if l.startswith("## Review queues")]
        assert head and "gf buckets" not in head[0], out
        for klass in ("DNS-OWNER-NAME", "RELATED-HOST"):
            line = [l for l in out.splitlines() if l.startswith(f"### {klass}")]
            assert line, out
            assert "PASSIVE" in line[0] and "never actively expanded" in line[0], line[0]
            assert "gf match" not in line[0], line[0]
        xss = [l for l in out.splitlines() if l.startswith("### XSS")]
        assert xss and "gf match" in xss[0], xss        # a real gf bucket still says so

    def test_the_registry_declares_the_review_output(self, tmp_path):
        """review-B1.5br3#3: both lanes still declared `output: subdomain` while also writing review."""
        from quarry_recon import sources
        for sid in ("probe.favicon", "probe.cert"):
            assert sources.get(sid)["output"] == "subdomain+review", sid

    def test_MIXED_hostname_outcomes_report_BOTH_facts(self, monkeypatch, tmp_path):
        """review-B1.5br4#2: one if/else meant any unusable name suppressed the noncanonical count, so a
        page carrying `_dmarc` alongside one malformed value stopped reporting that passive DNS owner
        evidence had been retained at all. Two facts about two different names, stated independently."""
        added = self._run_hosts(monkeypatch, tmp_path,
                                ["_dmarc.acme.com", "bad name.acme.com", "real.acme.com"])
        assert [r["host"] for e, r in added if e == "subdomain"] == ["real.acme.com"]
        assert [r["value"] for e, r in added if e == "review"] == ["_dmarc.acme.com"]
        cov = self._cov(tmp_path, "shodan_hostnames")[0]
        assert cov["eligible"] == 3 and cov["omitted"] == 1, cov
        assert "1 not usable" in cov["reason"], cov["reason"]
        assert "1 valid DNS owner name(s) retained as PASSIVE" in cov["reason"], cov["reason"]

    def test_a_non_host_name_never_reaches_an_ACTIVE_review_queue(self, monkeypatch, tmp_path):
        from types import SimpleNamespace
        from quarry_recon.phases import params
        rows = [{"klass": "dns-owner-name", "value": "_dmarc.acme.com", "id": "1"}]
        ctx = SimpleNamespace(run=SimpleNamespace(read=lambda e: rows if e == "review" else []),
                              scope=SimpleNamespace(active_allowed=lambda h: True))
        for klass in ("ssti", "ssrf", "xss", "redirect"):
            assert params.active_review_values(ctx, klass) == [], klass

    @pytest.mark.parametrize("bad", ["../admin.acme.com", "a/b.acme.com", "bad name.acme.com",
                                     "-lead.acme.com", "trail-.acme.com", "a..b.acme.com",
                                     # charset-only cases: no traversal, no slash, no whitespace, so
                                     # ONLY the per-label character check can reject them
                                     "a,b.acme.com", "pct%20.acme.com", "q?x.acme.com",
                                     "at@host.acme.com"])
    def test_a_MALFORMED_suffix_looking_name_is_unusable_not_evidence(self, monkeypatch, tmp_path, bad):
        """These all end in an in-scope suffix and all pass `active_allowed`. Containing a dot was the
        only thing keeping them, and it kept traversal and whitespace alongside `_dmarc`."""
        added = self._run_hosts(monkeypatch, tmp_path, [bad])
        assert added == [], added
        cov = self._cov(tmp_path, "shodan_hostnames")[0]
        assert cov["eligible"] == 1 and cov["omitted"] == 1, cov

    def test_an_UNUSABLE_name_is_counted_not_silently_skipped(self, monkeypatch, tmp_path):
        revs = self._oos_run(monkeypatch, tmp_path, ["nodot", "", "ok.evil.com"])
        assert {r["value"] for r in revs} == {"ok.evil.com"}
        cov = self._cov(tmp_path, "shodan_hostnames")[0]
        assert cov["eligible"] == 3 and cov["omitted"] == 2, cov

    def test_EVERY_off_scope_candidate_is_retained(self, monkeypatch, tmp_path):
        """B1.5b: the last hidden membership cap. 40 off-scope hosts on one page used to become 15, and
        WHICH 15 depended on page order — the same non-deterministic breadth loss as the pivot cap."""
        hosts = [f"oos{i}.evil.com" for i in range(40)]
        revs = self._oos_run(monkeypatch, tmp_path, hosts)
        assert {r["value"] for r in revs} == set(hosts), len(revs)
        assert all(r["klass"] == "related-host" and r["raw_ref"] for r in revs)
        assert len({r["id"] for r in revs}) == 40, "identities are not stable/distinct"

    def test_repeats_are_DEDUPLICATED_not_truncated(self, monkeypatch, tmp_path):
        """The same host on the same pivot is ONE candidate however often it appears — dedup by identity
        bounds growth without ever choosing which host survives."""
        hosts = ["a.evil.com", "a.evil.com", "b.evil.com", "a.evil.com"]
        revs = self._oos_run(monkeypatch, tmp_path, hosts)
        assert {r["value"] for r in revs} == {"a.evil.com", "b.evil.com"}
        assert len({r["id"] for r in revs}) == 2
        cov = self._cov(tmp_path, "shodan_oos_retained")[0]
        assert cov["omitted"] == 0, cov          # a duplicate is NOT an omission
        assert "2 distinct" in cov["reason"], cov["reason"]

    def test_the_SAME_host_under_TWO_pivots_stays_two_candidates(self, monkeypatch, tmp_path):
        """Identity is (lane, pivot value, host): the same infrastructure reached from two different
        favicons is two pieces of evidence, and collapsing them would lose the pivot that found it."""
        revs = self._oos_run(monkeypatch, tmp_path, ["shared.evil.com"], pivots=("hA", "hB"))
        assert len({r["id"] for r in revs}) == 2, revs
        assert {r["value"] for r in revs} == {"shared.evil.com"}

    def test_retained_OOS_never_reaches_an_ACTIVE_queue(self, monkeypatch, tmp_path):
        """The RoE boundary that makes full retention safe: OBSERVE and mine, never actively expand.

        review-B1.5br1#2: this used to assert that the literal string "related-host" was absent from
        params.py — it would have passed had an active lane started selecting review rows generically,
        and failed on a harmless comment. Behavioural now: a store holding ONLY off-scope candidates,
        driven through the real selector every active lane uses."""
        from types import SimpleNamespace
        from quarry_recon.phases import params
        rows = [{"klass": "related-host", "value": "oos1.evil.com", "id": "favicon:hX:oos1.evil.com"},
                {"klass": "related-host", "value": "https://oos2.evil.com/?a=1", "id": "b"}]
        allowed = []
        ctx = SimpleNamespace(
            run=SimpleNamespace(read=lambda e: rows if e == "review" else []),
            scope=SimpleNamespace(active_allowed=lambda h: (allowed.append(h), True)[1]))
        for klass in ("ssti", "ssrf", "xss", "redirect"):
            assert params.active_review_values(ctx, klass) == [], klass
        assert allowed == [], f"an off-scope host was even scope-tested: {allowed}"

    def test_the_active_selector_requires_BOTH_klass_and_scope(self, monkeypatch, tmp_path):
        """The other half: a row of the RIGHT klass is still refused when scope says no. Without this
        the helper would be a klass filter wearing an RoE label."""
        from types import SimpleNamespace
        from quarry_recon.phases import params
        rows = [{"klass": "xss", "value": "https://in.acme.com/?a=1", "id": "1"},
                {"klass": "xss", "value": "https://out.evil.com/?a=1", "id": "2"}]
        ctx = SimpleNamespace(
            run=SimpleNamespace(read=lambda e: rows if e == "review" else []),
            scope=SimpleNamespace(active_allowed=lambda h: h.endswith("acme.com")))
        assert params.active_review_values(ctx, "xss") == ["https://in.acme.com/?a=1"]

    def test_every_active_lane_selects_THROUGH_the_helper(self, monkeypatch, tmp_path):
        """A new active lane must not be able to read `review` directly and widen the boundary."""
        import inspect
        from quarry_recon.phases import params
        src = inspect.getsource(params)
        direct = [ln.strip() for ln in src.splitlines() if 'read("review")' in ln]
        assert len(direct) == 1, f"an active lane reads review outside the helper: {direct}"
        assert "def active_review_values" in src

    def test_an_UNSTORABLE_candidate_is_reported_not_swallowed(self, monkeypatch, tmp_path):
        """Dedup is not omission, but a candidate we cannot IDENTIFY is a real evidence loss."""
        from quarry_recon import store
        monkeypatch.setattr(store, "canonical_key",
                            lambda e, r: "" if e == "review" else r.get("id", "k"))
        revs = self._oos_run(monkeypatch, tmp_path, ["oos1.evil.com", "oos2.evil.com"])
        assert revs == []
        cov = self._cov(tmp_path, "shodan_oos_retained")[0]
        assert cov["omitted"] == 2 and cov["kind"] == "timeout", cov
        assert "could not be identified" in cov["reason"]

    def test_the_DEFAULT_page_policy_is_unbounded(self, monkeypatch, tmp_path):
        """The settled design: 0 = no Quarry-imposed limit. Nothing here patches `settings.concurrency`,
        so this is the default an operator actually gets — a default of 1 would silently cap every pivot
        at page one, and the credit balance (not an arbitrary page number) is what bounds the spend."""
        from quarry_recon.phases import probe
        calls = []

        def counted(req, timeout=20):
            calls.append(str(req.full_url))
            page = int(req.full_url.split("page=")[1])
            n = 100 if page < 3 else 50
            return _Resp(json.dumps({"total": 250,
                                     "matches": [{"hostnames": [f"p{page}h{i}.acme.com"]}
                                                 for i in range(n)]}).encode())

        monkeypatch.setattr(probe.urllib.request, "urlopen", _with_balance(counted, credits=10))
        ctx, _ = self._ctx(tmp_path)
        probe._shodan_pivot(ctx, "k", ["hX"], "http.favicon.hash", "favicon-shodan", "probe.favicon",
                            "{}")
        assert len(calls) == 3, f"a 3-page pivot bought {len(calls)} page(s) by default"
        assert self._cov(tmp_path, "shodan_pages_withheld")[0]["omitted"] == 0

    def test_BOTH_lanes_are_collected_before_ANY_credit_is_spent(self, monkeypatch, tmp_path):
        """review-B1.4r2#1, the central B1.3 property in the REAL flow. Each lane used to build its own
        balance, ledger and coordinator run, called in sequence — so favicon could consume every
        spendable credit before certificate work was even collected. With one coordinator and a budget
        of 2, each lane gets one page: fairness that only existed in the isolated coordinator."""
        from quarry_recon.phases import probe
        from quarry_recon import secrets
        calls = []

        def counted(req, timeout=20):
            calls.append(str(req.full_url))
            return _Resp(json.dumps({"total": 500,
                                     "matches": [{"hostnames": ["x.acme.com"]}]}).encode())

        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 0)
        monkeypatch.setattr(secrets, "shodan", lambda: "KEY")
        monkeypatch.setattr(probe.secrets, "shodan", lambda: "KEY")
        monkeypatch.setattr(probe.urllib.request, "urlopen", _with_balance(counted, credits=2))
        ctx, _added = self._ctx(tmp_path)
        ctx.run.read = lambda e: ([{"favicon": "F1"}] if e == "live"
                                  else [{"sha1": "C1"}] if e == "certificate" else [])
        probe._shodan_pivots(ctx)
        facets = [c.split("query=")[1].split("%3A")[0] for c in calls]
        assert len(calls) == 2, f"budget of 2 bought {len(calls)} pages: {calls}"
        assert set(facets) == {"http.favicon.hash", "ssl.cert.fingerprint"}, (
            f"one lane took the whole budget: {facets}")

    def test_a_starved_budget_still_reaches_the_SECOND_lane(self, monkeypatch, tmp_path):
        """The sharper case: 1 credit, and BOTH lanes have work. Whoever wins, the other must be a
        counted remainder rather than an unqueried surprise."""
        from quarry_recon.phases import probe
        from quarry_recon import secrets
        calls = []

        def counted(req, timeout=20):
            calls.append(str(req.full_url))
            return _Resp(json.dumps({"total": 10, "matches": []}).encode())

        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 0)
        monkeypatch.setattr(probe.secrets, "shodan", lambda: "KEY")
        monkeypatch.setattr(secrets, "shodan", lambda: "KEY")
        monkeypatch.setattr(probe.urllib.request, "urlopen", _with_balance(counted, credits=1))
        ctx, _added = self._ctx(tmp_path)
        ctx.run.read = lambda e: ([{"favicon": "F1"}] if e == "live"
                                  else [{"sha1": "C1"}] if e == "certificate" else [])
        probe._shodan_pivots(ctx)
        assert len(calls) == 1
        unq = self._cov(tmp_path, "shodan_pivots_unqueried")
        assert sum(r["omitted"] for r in unq) == 1, f"the unbought lane vanished: {unq}"

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
        monkeypatch.setattr(probe.urllib.request, "urlopen", _with_balance(lambda req, timeout=20: _Resp(json.dumps(body).encode())))
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
        monkeypatch.setattr(probe.urllib.request, "urlopen", _with_balance(paged))
        # B1.4: the adapter fetches ONE page and never raises — it hands the coordinator a classified
        # error instead, and the coordinator decides what that costs.
        ms, total, err = probe._shodan_page("k", "http.favicon.hash", "hX", 1)
        assert len(ms) == 100 and total == 500 and err is None
        ms2, total2, err2 = probe._shodan_page("k", "http.favicon.hash", "hX", 2)
        assert ms2 == [] and total2 is None and isinstance(err2, urllib.error.HTTPError)
        assert err2.error_class, "the error reached the coordinator unclassified"
        ctx, _ = self._ctx(tmp_path)
        r = probe._shodan_pivot(ctx, "k", ["hX"], "http.favicon.hash", "favicon-shodan", "probe.favicon", "{}")
        assert "h0.acme.com" in r                             # page-1 hosts preserved despite the page-2 failure
        assert isinstance(r, ProviderResult) and r.partial and r.partial_kind == "degraded"
        # review-r5#2: a DEGRADED pivot got page-1 data -> NOT counted as wholly-omitted (shodan_pivots), but
        # its result set IS incomplete (shodan_results).
        assert self._cov(tmp_path, "shodan_pivots")[0]["omitted"] == 0
        # B1.1r2: our page budget is its OWN measure. A later page lost to a 429 is a FAILURE at a later
        # position, counted in `shodan_results_failed` (a gap) — never blamed on Quarry's cap.
        assert self._cov(tmp_path, "shodan_pages_withheld")[0]["omitted"] == 2   # pages 4-5, max_pages=3
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
        monkeypatch.setattr(probe.urllib.request, "urlopen", _with_balance(mixed))
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
        monkeypatch.setattr(probe.urllib.request, "urlopen", _with_balance(paged))
        ctx, added = self._ctx(tmp_path)
        n = probe._shodan_pivot(ctx, "k", ["hashX"], "http.favicon.hash", "favicon-shodan", "probe.favicon", "{}")
        assert calls["n"] == 2 and len(n) == 150                   # both pages read, all 150 hosts ingested
        assert not self._cov(tmp_path, "shodan_pages_withheld")[0]["omitted"]   # fully paged
