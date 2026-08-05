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
import io
import json
import socket
import urllib.error

import pytest

from quarry_recon import contract, events
from quarry_recon.contract import ProviderResult

pytestmark = pytest.mark.offline


class _Resp:
    """A minimal STREAM: hands out the body once, then EOF — the shape a chunked reader expects."""

    def __init__(self, body):
        self._b = body
        self._done = False

    def __enter__(self): return self
    def __exit__(self, *a): return False

    def read(self, n=None):
        if self._done:
            return b""
        if n is None or n >= len(self._b):
            self._done = True
            return self._b
        head, self._b = self._b[:n], self._b[n:]
        return head

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


class TestCensysFreeIsNotSilence:
    """MEASURED 2026-07-30 with a real Free PAT: the Censys Platform search API is ORG-GATED. The wallet
    reads fine (100 credits, resets monthly) and `/v3/global/search/query` answers HTTP 403
    `application/problem+json`:

        "This endpoint requires an organization ID for API access. Free users can only access this
         endpoint through the Platform UI."

    The refusal costs 0 credits, so this is entitlement and not money. Configuring a token WITHOUT an org
    was answered with total silence — no lifecycle, nothing in the manifest — so a Free user could not tell
    "not configured" from "cannot work"."""

    def _drive(self, tmp_path, cen):
        from quarry_recon import events
        from quarry_recon.phases import vertical
        events.reset(); events.configure(tmp_path)
        recorded = vertical.censys_entitlement_skip(cen, ["acme.com", "example.com"])
        from quarry_recon import events as _ev
        rows = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()] \
            if (tmp_path / "events.jsonl").exists() else []
        return recorded, [e for e in rows if e.get("source_id") == "vertical.censys"
                          and e.get("event") == _ev.TOOL_FINISH]

    def test_a_token_WITHOUT_an_org_records_a_skip_not_silence(self, tmp_path):
        recorded, term = self._drive(tmp_path, {"token": "PAT"})
        assert recorded is True
        assert term and term[0]["status"] == "skipped", term

    #: the sentence Censys actually returned, quoted here VERBATIM rather than imported — asserting the
    #: constant against itself would pass whatever the constant said, which is how a measurement quietly
    #: turns into a paraphrase.
    MEASURED = ("This endpoint requires an organization ID for API access. Free users can only access "
                "this endpoint through the Platform UI.")

    def test_the_skip_carries_the_PROVIDERS_OWN_sentence(self, tmp_path):
        _recorded, term = self._drive(tmp_path, {"token": "PAT"})
        why = term[0].get("reason") or ""
        assert self.MEASURED in why, why
        assert "no credit was spent" in why and "2026-07-30" in why, why

    def test_the_CONSTANT_is_the_measured_sentence(self):
        from quarry_recon.phases import vertical
        assert vertical.CENSYS_ORG_REQUIRED == self.MEASURED, vertical.CENSYS_ORG_REQUIRED

    @pytest.mark.parametrize("cen", [{}, {"org": "o"}, {"token": "", "org": ""}, {"token": "PAT", "org": "o"}])
    def test_every_OTHER_configuration_stays_silent(self, tmp_path, cen):
        """Unconfigured is not the same as configured-and-unusable, an org with no token has no credential
        to be refused, and a COMPLETE config is the lane's normal path — none of them get this skip."""
        recorded, term = self._drive(tmp_path, cen)
        assert recorded is False, cen
        assert term == [], (cen, term)

    def test_the_LANE_actually_calls_it(self):
        """A guard nothing invokes is the silence it was written to fix."""
        import inspect

        from quarry_recon.phases import vertical
        src = inspect.getsource(vertical.run)
        assert "censys_entitlement_skip(cen, prof.apex_domains)" in src, src[-400:]

    def test_the_REGISTRY_states_the_measured_entitlement(self):
        from quarry_recon import sources
        notes = (sources.get("vertical.censys") or {}).get("notes", "")
        assert "organization ID" in notes and "2026-07-30" in notes, notes
        assert "0 credits" in notes, notes


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


SHODAN_AUTH_BODY = ("<html>\n <head>\n  <title>401 Unauthorized</title>\n </head>\n <body>\n"
                    "  <h1>401 Unauthorized</h1>\n  This server could not verify that you are "
                    "authorized to access the document you requested.<br/><br/>\n </body>\n</html>")
SHODAN_QUOTA_BODY = ('{"error": "Insufficient query credits, please upgrade your API plan or wait for '
                     'the monthly limit to reset"}')


def _http_err(code, body):
    """An HTTPError carrying a real readable body, like urllib produces."""
    import io
    return urllib.error.HTTPError("http://x", code, "msg", {}, io.BytesIO(body.encode()))


def probe_mod():
    from quarry_recon.phases import probe
    return probe


def _with_balance(responder, *, credits=100):
    """Answer `/api-info` from a HEALTHY balance and send everything else to `responder`.

    B1.4: the lane reads its credit balance before scheduling any paid page, so a responder that answers
    EVERY url makes the balance read consume the scenario's first scripted response. `/api-info` is free
    and keeps working at a zero balance (measured), so a fixture where it fails alongside the search is
    testing a state Shodan does not produce."""
    class _Cnt:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        _done = False

        def read(self, n=None):
            if self._done:
                return b""
            self.__class__._done = False
            self._done = True
            return json.dumps({"total": 10}).encode()

    class _Bal:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n=None):
            if getattr(self, '_eof', False):
                return b''                      # STREAM: the body once, then EOF
            self._eof = True
            return json.dumps({"query_credits": credits, "scan_credits": 0,
                               "usage_limits": {"query_credits": credits}}).encode()

    def route(req, timeout=20):
        if "host/count" in str(getattr(req, "full_url", req)):
            return _Cnt()
        if "api-info" in str(getattr(req, "full_url", req)):
            return _Bal()
        return responder(req, timeout=timeout)
    return route


def _refuse_completion_appends(self, rec):
    """A journal that takes the writability CHECKPOINT and refuses every completion record. Patched over
    `Ledger._append`, so `record()`'s in-memory ownership update still happens first — the real sequence
    (review-B1.7a#9)."""
    return "i" not in rec


class TestShodanPivot:
    @pytest.fixture(autouse=True)
    def _no_real_sleep(self, monkeypatch):
        """B1.5 pacing is real, so a scripted 429 now costs wall-clock. Tests that are ABOUT pacing
        install their own recorder (applied later, so it wins); every other test just must not wait."""
        monkeypatch.setattr(probe_mod()._time, "sleep", lambda s: None)

    def _ctx(self, tmp_path):
        from types import SimpleNamespace
        events.reset(); events.configure(tmp_path)
        added = []
        run = SimpleNamespace(
            raw_path=lambda ph, lb, nm: (tmp_path / ph / lb).joinpath(nm) if
            (tmp_path / ph / lb).mkdir(parents=True, exist_ok=True) or True else None,
            dir=tmp_path,                 # B1.4: the coordinator's ledger/attempt tree lives under it
            # PROJECT-scoped now: purchased pages outlive the run directory, so the fake has to have a
            # project the way a real `Run` does (`Run.dir == project_dir/recon/<run_id>`)
            project_dir=tmp_path,
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
        # review-B1.5r4#2: this used to assert BOTH pivots auth-failed — i.e. it locked in asking a
        # rejected credential once per pivot. A proven refusal stops requesting: the first pivot fails
        # and is classified, and the rest are a counted, resumable remainder rather than more refusals.
        piv = self._cov(tmp_path, "shodan_pivots")
        assert piv and piv[0]["omitted"] == 1 and "auth" in (piv[0].get("reason") or "")
        unq = self._cov(tmp_path, "shodan_pivots_unqueried")
        assert unq and unq[0]["omitted"] == 1 and unq[0]["kind"] == "timeout", unq

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
        # B1.5: the attempt dir also holds free /host/count sizing evidence — the provider's EXACT
        # bytes, which carry no `matches`. Select the PAGE doc.
        # the purchased-page tree is PROJECT-scoped now (`state/shodan-pivot/v<schema>/pages/…`), because
        # a run-scoped one made the next run pay for pages it already owned
        # a paid page is kept TWICE now: the page doc (owned, replayed) and the provider's EXACT bytes
        # streamed to `raw/` — neither truncated. Lumpy, 2026-08-05: "if we are already paying, I want to
        # get EVERYTHING I pay for".
        docs = [q for q in (tmp_path / "state" / "shodan-pivot").rglob("pages/**/*.json")
                if q.name != ".quarry-write-probe" and q.parent.name != "raw"
                and "matches" in json.loads(q.read_text())]
        assert len(docs) == 1, [str(q) for q in docs]
        doc = json.loads(docs[0].read_text())
        rows = doc["matches"]
        assert len(rows) == 1000                              # COMPLETE — no truncation
        assert "h999.acme.com" in found and rows[-1]["hostnames"] == ["h999.acme.com"]
        # `raw_ref` is stored RELATIVE TO THE PAGE DOCUMENT's directory and must resolve from it. It
        # used to store just the basename, which resolved to the page document itself (review#2).
        raw = docs[0].parent / doc["raw_ref"]
        assert raw.is_file() and raw.stat().st_size == doc["raw_bytes"]
        assert len(json.loads(raw.read_text())["matches"]) == 1000, "the RESPONSE is kept whole too"

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
            ms, total, err = probe._shodan_page("k", "http.favicon.hash", "hX", 1,
                                                sink=tmp_path / f"raw-{bad!r:.12}.json")
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

    def _sized(self, monkeypatch, tmp_path, *, counts, search=None, credits=100, pivots=("hX",),
               trace=None, api_info=None, seen=None):
        """Drive the real lane with a scripted /host/count per pivot value."""
        from quarry_recon.phases import probe
        calls = seen if seen is not None else []

        def route(req, timeout=20):
            url = str(req.full_url)
            calls.append(url)
            if "api-info" in url:        # answered HERE, not by _with_balance, so the scripted counts
                if api_info is not None:   # below are the ones the lane actually receives
                    raise api_info
                return _Resp(json.dumps(
                    {"query_credits": credits, "scan_credits": 0,
                     "usage_limits": {"query_credits": max(credits, 1)}}).encode())
            if "host/count" in url:
                if trace is not None:
                    trace.append("count")
                v = url.split("%3A")[-1]
                got = counts.get(v, counts.get("*"))
                if isinstance(got, Exception):
                    raise got
                return _Resp(json.dumps({"total": got} if got is not None else {"nope": 1}).encode())
            if trace is not None:
                trace.append("search")
            if search is not None:
                return search(req, timeout=timeout)
            return _Resp(json.dumps({"total": 50, "matches": []}).encode())

        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 0)
        monkeypatch.setattr(probe.urllib.request, "urlopen", route)
        ctx, added = self._ctx(tmp_path)
        probe._shodan_pivot(ctx, "k", list(pivots), "http.favicon.hash", "favicon-shodan",
                            "probe.favicon", "{}")
        return calls, added

    def _ledger_events(self, tmp_path, field):
        return [json.loads(l)[field] for l in (tmp_path / "events.jsonl").read_text().splitlines()
                if f'"{field}"' in l]

    def _sizing(self, tmp_path):
        ev = self._ledger_events(tmp_path, "shodan_sizing")
        assert ev, "no sizing telemetry was emitted"
        return ev[-1]

    def test_sizing_order_is_CROSS_LANE_FAIR(self, monkeypatch, tmp_path):
        """review-B1.5r1#2: sizing walked lane by lane, so an early stop sized every favicon pivot and
        no certificate one — a provider slowdown deciding which lane got ordered at all."""
        from quarry_recon.phases import probe
        from quarry_recon import secrets
        calls = []

        def route(req, timeout=20):
            url = str(req.full_url)
            calls.append(url)
            if "api-info" in url:
                return _Resp(json.dumps({"query_credits": 50, "scan_credits": 0,
                                         "usage_limits": {"query_credits": 50}}).encode())
            if "host/count" in url:
                return _Resp(json.dumps({"total": 10}).encode())
            return _Resp(json.dumps({"total": 10, "matches": []}).encode())

        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 0)
        monkeypatch.setattr(probe.secrets, "shodan", lambda: "KEY")
        monkeypatch.setattr(secrets, "shodan", lambda: "KEY")
        monkeypatch.setattr(probe.urllib.request, "urlopen", route)
        ctx, _ = self._ctx(tmp_path)
        ctx.run.read = lambda e: ([{"favicon": "F1"}, {"favicon": "F2"}] if e == "live"
                                  else [{"sha1": "C1"}, {"sha1": "C2"}] if e == "certificate" else [])
        probe._shodan_pivots(ctx)
        lanes = ["cert" if "ssl.cert" in c else "fav" for c in calls if "host/count" in c]
        assert lanes == ["cert", "fav", "cert", "fav"], lanes

    def test_EVERY_eligible_pivot_is_counted(self, monkeypatch, tmp_path):
        calls, _ = self._sized(monkeypatch, tmp_path, counts={"*": 50},
                               pivots=("hA", "hB", "hC"))
        counted = {c.split("%3A")[-1] for c in calls if "host/count" in c}
        assert counted == {"hA", "hB", "hC"}, counted

    def test_sizing_spends_ZERO_query_credits(self, monkeypatch, tmp_path):
        """`/host/count` is free; only `/host/search` consumes a credit. Sizing is a SEPARATE pass that
        issues nothing but counts — so every count precedes the first paid request, and the number of
        paid requests is unchanged by sizing."""
        calls, _ = self._sized(monkeypatch, tmp_path, counts={"*": 500}, pivots=("hA", "hB"))
        kinds = ["count" if "host/count" in c else "search" if "host/search" in c else "info"
                 for c in calls]
        assert kinds.count("count") == 2
        assert kinds.index("search") > max(i for i, k in enumerate(kinds) if k == "count"), kinds

    def test_a_genuine_ZERO_count_is_KNOWN_and_orders_FIRST(self, monkeypatch, tmp_path):
        """The other side of "never read unknown as zero": a real zero must not be demoted to unknown
        either. It is the rarest possible pivot, so it is queried first — and an unsized pivot, which we
        know nothing about, is queried last."""
        calls, _ = self._sized(monkeypatch, tmp_path,
                               counts={"hZERO": 0, "hBIG": 500,
                                       "hUNK": urllib.error.URLError("refused")},
                               pivots=("hZERO", "hBIG", "hUNK"))
        seen, order = set(), []
        for c in calls:
            if "host/search" not in c:
                continue
            v = c.split("%3A")[-1].split("&")[0]
            if v not in seen:                 # FIRST page of each pivot: the tier ordering under test
                seen.add(v)
                order.append(v)
        assert order == ["hZERO", "hBIG", "hUNK"], order

    def test_a_ZERO_count_never_marks_a_pivot_COMPLETE(self, monkeypatch, tmp_path):
        """Cardinality orders work; it may not decide that there is none. A pivot Shodan currently counts
        at zero is still queried — the count is a sizing hint, not an oracle."""
        calls, _ = self._sized(monkeypatch, tmp_path, counts={"*": 0}, pivots=("hA", "hB"))
        bought = {c.split("%3A")[-1].split("&")[0] for c in calls if "host/search" in c}
        assert bought == {"hA", "hB"}, bought

    def test_sizing_still_runs_at_a_ZERO_paid_balance(self, monkeypatch, tmp_path):
        """Free operations continue when paid credits are exhausted or reserved."""
        def never_search(req, timeout=20):
            raise AssertionError("a paid search was issued at a zero balance")

        calls, _ = self._sized(monkeypatch, tmp_path, counts={"*": 500}, search=never_search,
                               credits=0, pivots=("hA", "hB"))
        assert len([c for c in calls if "host/count" in c]) == 2, calls

    def test_a_FAILED_count_leaves_its_pivot_ELIGIBLE(self, monkeypatch, tmp_path):
        """One failed count neither drops nor permanently demotes its pivot: it is still bought."""
        calls, _ = self._sized(monkeypatch, tmp_path,
                               counts={"hBAD": urllib.error.URLError("refused"), "*": 10},
                               pivots=("hBAD", "hOK"))
        bought = {c.split("%3A")[-1].split("&")[0] for c in calls if "host/search" in c}
        assert bought == {"hBAD", "hOK"}, bought

    def test_a_MALFORMED_count_is_unknown_not_zero(self, monkeypatch, tmp_path):
        calls, _ = self._sized(monkeypatch, tmp_path, counts={"*": None}, pivots=("hA",))
        assert [c for c in calls if "host/search" in c], "a malformed count suppressed the search"
        sz = self._sizing(tmp_path)
        assert sz["attempted"] == 1 and sz["succeeded"] == 0, sz
        assert sz["failed_by_class"] == {"parse": 1}, sz

    def test_a_429_is_HONORED_by_the_paid_run_too(self, monkeypatch, tmp_path):
        """review-B1.5r1#2: sizing stopped on a 429 and paid search began immediately, so the provider's
        slowdown was heard and ignored. One cooldown, shared — the paid request waits it out."""
        waits = []
        monkeypatch.setattr(probe_mod()._time, "sleep", lambda s: waits.append(s))
        calls, _ = self._sized(monkeypatch, tmp_path,
                               counts={"hA": _http_err(429, "slow down"), "*": 10},
                               pivots=("hA", "hB"))
        assert waits, "no cooldown was observed after a 429"
        first_search = min(i for i, c in enumerate(calls) if "host/search" in c)
        assert first_search > 0 and waits, calls

    def test_the_cooldown_is_honored_BEFORE_the_next_count(self, monkeypatch, tmp_path):
        """Not just "a sleep happened somewhere": the wait must fall BETWEEN the 429 and the next
        request, which is the only thing that makes it pacing."""
        seq = []
        monkeypatch.setattr(probe_mod()._time, "sleep", lambda s: seq.append("sleep"))
        calls, _ = self._sized(monkeypatch, tmp_path,
                               counts={"hA": _http_err(429, "slow"), "*": 10},
                               pivots=("hA", "hB"), trace=seq)
        counts = [i for i, s in enumerate(seq) if s == "count"]
        sleeps = [i for i, s in enumerate(seq) if s == "sleep"]
        assert len(counts) == 2 and sleeps, seq
        assert counts[0] < sleeps[0] < counts[1], seq

    def test_the_cooldown_is_honored_BEFORE_the_first_PAID_request(self, monkeypatch, tmp_path):
        """A 429 on the LAST sized pivot leaves no further count to pace — the paid run must still wait,
        which is the half that was heard and ignored."""
        seq = []
        monkeypatch.setattr(probe_mod()._time, "sleep", lambda s: seq.append("sleep"))
        self._sized(monkeypatch, tmp_path, counts={"hA": _http_err(429, "slow")},
                    pivots=("hA",), trace=seq)
        assert seq.count("count") == 1, seq
        assert "sleep" in seq and seq.index("sleep") < seq.index("search"), seq

    def test_an_API_INFO_429_paces_the_FIRST_count(self, monkeypatch, tmp_path):
        """review-B1.5r2#1: the balance read sat outside the shared cooldown, so a 429 there was followed
        immediately by a count for every pivot."""
        seq = []
        monkeypatch.setattr(probe_mod()._time, "sleep", lambda s: seq.append("sleep"))
        self._sized(monkeypatch, tmp_path, counts={"*": 10}, pivots=("hA",), trace=seq,
                    api_info=_http_err(429, "slow down"))
        assert "sleep" in seq and seq.index("sleep") < seq.index("count"), seq

    def test_a_PROVEN_BAD_KEY_issues_no_counts_at_all(self, monkeypatch, tmp_path):
        """Free is not a licence to hammer: the contract continues free operations only while Shodan
        still ACCEPTS the key. A rejected credential used to cost one count per pivot."""
        # a rejected credential is a DEFECT, so the lane also raises a classified failure (B1.4r2#3);
        # the sizing telemetry is emitted before that, which is the point under test here.
        with pytest.raises(Exception):
            self._sized(monkeypatch, tmp_path, counts={"*": 10}, pivots=("hA", "hB", "hC"),
                        api_info=_http_err(401, SHODAN_AUTH_BODY))
        calls = self._ledger_events(tmp_path, "shodan_count")
        assert calls == [], calls
        sz = self._sizing(tmp_path)
        assert sz["attempted"] == 0 and sz["not_attempted"] == 3, sz
        assert sz["stop_reason"] == "auth_refused", sz

    def test_a_QUOTA_balance_still_allows_free_counts(self, monkeypatch, tmp_path):
        """The control: quota means the SPEND is refused, not the key — sizing continues."""
        calls, _ = self._sized(monkeypatch, tmp_path, counts={"*": 10}, pivots=("hA", "hB"),
                               credits=0)
        assert len([c for c in calls if "host/count" in c]) == 2, calls

    def test_a_PAID_429_is_paced_and_recorded(self, monkeypatch, tmp_path):
        """review-B1.5r3#1: only one wait ran, before the whole paid loop, so a 429 mid-purchase was
        neither noted nor honored and the scheduler moved straight to the next pivot."""
        seq = []
        monkeypatch.setattr(probe_mod()._time, "sleep", lambda s: seq.append("sleep"))
        hits = {"n": 0}

        def flaky(req, timeout=20):
            hits["n"] += 1
            if hits["n"] == 1:
                raise _http_err(429, "slow down")
            return _Resp(json.dumps({"total": 10, "matches": []}).encode())

        self._sized(monkeypatch, tmp_path, counts={"*": 10}, search=flaky,
                    pivots=("hA", "hB"), trace=seq)
        searches = [i for i, s in enumerate(seq) if s == "search"]
        sleeps = [i for i, s in enumerate(seq) if s == "sleep"]
        assert len(searches) >= 2 and sleeps, seq
        assert any(searches[0] < s < searches[1] for s in sleeps), seq

    def test_a_paid_AUTH_refusal_stops_the_run_and_stays_a_GAP(self, monkeypatch, tmp_path):
        """review-B1.5r4#2: a key revoked after sizing cost one rejected paid request per pivot. It stops
        requesting — and stays a FAILURE, because "stop asking" and "soft limit" are different facts."""
        def revoked(req, timeout=20):
            raise _http_err(401, SHODAN_AUTH_BODY)

        calls = []
        with pytest.raises(Exception):
            self._sized(monkeypatch, tmp_path, counts={"*": 10}, search=revoked,
                        pivots=("hA", "hB", "hC"), seen=calls)
        assert len([c for c in calls if "host/search" in c]) == 1, calls
        unq = self._cov(tmp_path, "shodan_pivots_unqueried")
        assert unq and unq[0]["omitted"] == 2 and unq[0]["kind"] == "timeout", unq

    def test_a_REPEATED_paid_429_stops_the_run_but_is_NOT_a_soft_limit(self, monkeypatch, tmp_path):
        """review-B1.5r4#1: escalating a repeat into a provider LIMIT contradicted the shared taxonomy —
        `contract.PROVIDER_LIMITS` excludes rate_limit — so the remainder folded as a soft limit while
        the same exception was still remembered as a real failure. It stops the run and stays a gap."""
        monkeypatch.setattr(probe_mod()._time, "sleep", lambda s: None)

        def always(req, timeout=20):
            raise _http_err(429, "slow down")

        with pytest.raises(Exception):
            self._sized(monkeypatch, tmp_path, counts={"*": 10}, search=always,
                        pivots=("hA", "hB", "hC", "hD"))
        unq = self._cov(tmp_path, "shodan_pivots_unqueried")
        assert unq and unq[0]["kind"] == "timeout", unq
        lim = self._cov(tmp_path, "shodan_pivots_limited")
        assert lim and lim[0]["omitted"] == 0, lim

    def test_a_stop_in_ONE_lane_is_explained_in_the_OTHER(self, monkeypatch, tmp_path):
        """review-B1.5r5#1: a lane left unqueried by another lane's refused credential returned PARTIAL
        with no class, and explained its own omission with a perfectly healthy credit balance."""
        from quarry_recon.phases import probe
        from quarry_recon import secrets

        def route(req, timeout=20):
            url = str(req.full_url)
            if "api-info" in url:
                return _Resp(json.dumps({"query_credits": 50, "scan_credits": 0,
                                         "usage_limits": {"query_credits": 50}}).encode())
            if "host/count" in url:
                return _Resp(json.dumps({"total": 10}).encode())
            raise _http_err(401, SHODAN_AUTH_BODY)          # the KEY is revoked mid-run

        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 0)
        monkeypatch.setattr(probe.secrets, "shodan", lambda: "KEY")
        monkeypatch.setattr(secrets, "shodan", lambda: "KEY")
        monkeypatch.setattr(probe.urllib.request, "urlopen", route)
        ctx, _ = self._ctx(tmp_path)
        ctx.run.read = lambda e: ([{"favicon": "F1"}] if e == "live"
                                  else [{"sha1": "C1"}] if e == "certificate" else [])
        probe._shodan_pivots(ctx)
        evs = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        term = {e["source_id"]: e for e in evs if e.get("event") == "tool_finish"}
        assert set(term) == {"probe.favicon", "probe.cert"}, term
        untouched = [e for e in term.values() if e["status"] == "partial"]
        assert untouched and untouched[0]["error_class"] == "auth", untouched
        unq = [e for e in evs if e.get("measure") == "shodan_pivots_unqueried" and e["omitted"]]
        assert unq and "provider_stop:auth" in unq[0]["reason"], unq

    def test_a_count_refusal_reaches_the_FAILURE_coverage(self, monkeypatch, tmp_path):
        """review-B1.5r5#2: `shodan_failures` said "no failure" about a run stopped by a rejected key,
        because it read only page failures and the balance-read error."""
        with pytest.raises(Exception):
            self._sized(monkeypatch, tmp_path,
                        counts={"hA": _http_err(401, SHODAN_AUTH_BODY), "*": 10},
                        pivots=("hA", "hB"))
        fail = self._cov(tmp_path, "shodan_failures")[0]
        assert fail["omitted"] >= 1, fail
        assert "/host/count refused the credential (auth)" in fail["reason"], fail["reason"]

    def test_a_count_refusal_terminal_carries_the_CANONICAL_class(self, monkeypatch, tmp_path):
        with pytest.raises(Exception) as exc:
            self._sized(monkeypatch, tmp_path,
                        counts={"hA": _http_err(401, SHODAN_AUTH_BODY), "*": 10},
                        pivots=("hA", "hB"))
        assert getattr(exc.value, "error_class", None) == "auth", exc.value

    def test_EVERY_lane_gets_a_balance_record_when_the_run_EXPLODES(self, monkeypatch, tmp_path):
        """review-B1.5r5r1: the single-lane seam proves ONE record survives, not one PER LANE — a
        `finally` iterating `lanes[:1]` would pass it. Two lanes, shared coordinator, sizing explodes."""
        from quarry_recon.phases import probe
        from quarry_recon import secrets
        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 0)
        monkeypatch.setattr(probe.secrets, "shodan", lambda: "KEY")
        monkeypatch.setattr(secrets, "shodan", lambda: "KEY")
        monkeypatch.setattr(probe.urllib.request, "urlopen", _with_balance(
            lambda req, timeout=20: _Resp(json.dumps({"total": 1, "matches": []}).encode())))
        monkeypatch.setattr(probe, "_size_pivots",
                            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("setup exploded")))
        ctx, _ = self._ctx(tmp_path)
        ctx.run.read = lambda e: ([{"favicon": "F1"}] if e == "live"
                                  else [{"sha1": "C1"}] if e == "certificate" else [])
        probe._shodan_pivots(ctx)                    # ordinary failure -> best-effort, no re-raise
        evs = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        bal = [e for e in evs if (e.get("balance") or {}).get("provider") == "shodan"]
        assert {e["source_id"] for e in bal} == {"probe.favicon", "probe.cert"}, bal
        assert len(bal) == 2, f"{len(bal)} balance records for 2 lanes"

    def test_the_balance_is_emitted_even_when_the_run_EXPLODES(self, monkeypatch, tmp_path):
        """review-B1.5r5#3: moving the emission after sizing meant a failure in state setup, the cooldown
        or sizing left NO balance record — the missing-lifecycle hole this telemetry exists to close."""
        from quarry_recon.phases import probe
        monkeypatch.setattr(probe, "_size_pivots",
                            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("setup exploded")))
        # the balance read and sizing now run INSIDE the coordinator, after replay, so a failure there
        # reaches the lane through its machinery boundary (evidence kept, remainder reported) instead of
        # escaping raw. The property this test exists for is unchanged: exactly one balance record per
        # lane, on every path.
        with pytest.raises(Exception):
            self._sized(monkeypatch, tmp_path, counts={"*": 10}, pivots=("hA",))
        bal = self._ledger_events(tmp_path, "balance")
        assert len(bal) == 1 and bal[0]["provider"] == "shodan", bal

    def test_a_count_refusal_is_NOT_reported_as_a_balance_read_failure(self, monkeypatch, tmp_path):
        """review-B1.5r4#3: /api-info succeeded; overwriting `read_error` made reconciliation announce
        "balance read failed" about a read that worked, and emitted the balance twice with conflicting
        provenance."""
        with pytest.raises(Exception):
            self._sized(monkeypatch, tmp_path,
                        counts={"hA": _http_err(401, SHODAN_AUTH_BODY), "*": 10},
                        pivots=("hA", "hB"))
        bal = self._ledger_events(tmp_path, "balance")
        assert len(bal) == 1, f"the balance was emitted {len(bal)} times"
        assert bal[0]["read_error"] is None and bal[0]["count_refused"] == "auth", bal[0]
        fail = self._cov(tmp_path, "shodan_failures")
        assert fail and "balance read failed" not in (fail[0].get("reason") or ""), fail[0]

    @pytest.mark.parametrize("bad", ["inf", "1e309", "-5", "nan", "9999999", "Wed, 21 Oct 2015"])
    def test_a_MALFORMED_Retry_After_falls_back(self, monkeypatch, tmp_path, bad):
        """review-B1.5r3#3: `float()` accepts inf and 1e309; `sleep(inf)` raises OverflowError and a huge
        finite value stalls the run."""
        waits = []
        monkeypatch.setattr(probe_mod()._time, "sleep", lambda s: waits.append(s))
        err = _http_err(429, "slow")
        err.headers = {"Retry-After": bad}
        self._sized(monkeypatch, tmp_path, counts={"hA": err, "*": 10}, pivots=("hA", "hB"))
        assert waits and all(0 <= w <= 5.0 for w in waits), (bad, waits)

    def test_an_AUTH_refusal_on_COUNT_stops_sizing_AND_paid_work(self, monkeypatch, tmp_path):
        """review-B1.5r3#2: /api-info can succeed and the key be revoked a moment later. A count that
        proves the credential is refused stopped nothing — every remaining pivot was counted and then
        paid searches went out against the unchanged balance."""
        with pytest.raises(Exception):
            self._sized(monkeypatch, tmp_path,
                        counts={"hA": _http_err(401, SHODAN_AUTH_BODY), "*": 10},
                        pivots=("hA", "hB", "hC"))
        sz = self._sizing(tmp_path)
        assert sz["attempted"] == 1 and sz["stop_reason"] == "auth", sz
        assert self._ledger_events(tmp_path, "shodan_count") == []

    def test_a_FORBIDDEN_count_stops_sizing_ONLY(self, monkeypatch, tmp_path):
        """Proven for the endpoint that said it, and nothing else: the paid lane still runs."""
        monkeypatch.setattr(probe_mod()._time, "sleep", lambda s: None)
        calls, _ = self._sized(monkeypatch, tmp_path,
                               counts={"hA": _http_err(403, "nope"), "*": 10},
                               pivots=("hA", "hB", "hC"))
        assert len([c for c in calls if "host/count" in c]) == 1, calls
        bought = {c.split("%3A")[-1].split("&")[0] for c in calls if "host/search" in c}
        assert bought == {"hA", "hB", "hC"}, bought
        assert self._sizing(tmp_path)["stop_reason"] == "forbidden"

    def test_a_Retry_After_header_sets_the_cooldown(self, monkeypatch, tmp_path):
        waits = []
        monkeypatch.setattr(probe_mod()._time, "sleep", lambda s: waits.append(s))
        err = _http_err(429, "slow down")
        err.headers = {"Retry-After": "17"}
        self._sized(monkeypatch, tmp_path, counts={"hA": err, "*": 10}, pivots=("hA", "hB"))
        assert waits and max(waits) > 16, waits

    def test_a_SINGLE_429_backs_off_and_KEEPS_sizing(self, monkeypatch, tmp_path):
        monkeypatch.setattr(probe_mod()._time, "sleep", lambda s: None)
        calls, _ = self._sized(monkeypatch, tmp_path,
                               counts={"hA": _http_err(429, "slow"), "*": 10},
                               pivots=("hA", "hB", "hC"))
        assert len([c for c in calls if "host/count" in c]) == 3, calls

    def test_a_REPEATED_429_stops_sizing_but_not_the_paid_run(self, monkeypatch, tmp_path):
        monkeypatch.setattr(probe_mod()._time, "sleep", lambda s: None)
        calls, _ = self._sized(monkeypatch, tmp_path,
                               counts={"*": _http_err(429, "slow")},
                               pivots=("hA", "hB", "hC", "hD"))
        assert len([c for c in calls if "host/count" in c]) == 2, calls
        bought = {c.split("%3A")[-1].split("&")[0] for c in calls if "host/search" in c}
        assert bought == {"hA", "hB", "hC", "hD"}, bought
        sz = self._sizing(tmp_path)
        assert sz["stop_reason"] == "rate_limit" and sz["not_attempted"] == 2, sz

    def test_count_evidence_is_the_EXACT_response_bytes(self, monkeypatch, tmp_path):
        """review-B1.5r1#3: the bytes were parsed, discarded, and a fresh document synthesized in their
        place — the "raw evidence" was Quarry's account of the answer, not the answer."""
        self._sized(monkeypatch, tmp_path, counts={"*": 250}, pivots=("hA",))
        # count evidence only: the tree also holds page docs, streamed raw responses and ACQUISITION
        # RECEIPTS (`kind: acquisition`), each of which is a different artifact class.
        raws = [q.read_bytes() for q in (tmp_path / "state" / "shodan-pivot").rglob("pages/**/*.json")
                if q.name != ".quarry-write-probe"
                and "matches" not in json.loads(q.read_text())
                and json.loads(q.read_text()).get("kind") != "acquisition"]
        assert raws == [json.dumps({"total": 250}).encode()], raws
        ev = self._ledger_events(tmp_path, "shodan_count")
        assert len(ev) == 1 and ev[0]["value"] == "hA" and ev[0]["total"] == 250
        assert ev[0]["facet"] == "http.favicon.hash" and ev[0]["digest"] and ev[0]["artifact"]

    def test_UNBOUND_count_evidence_never_orders_paid_work(self, monkeypatch, tmp_path):
        """Scarce credits must not be ranked by evidence we failed to keep."""
        from quarry_recon import budget as _b
        from quarry_recon.shodan_sched import Pivot, count_key
        # fail ONLY the count artifact — pages and the pre-flight write probe must still publish, or the
        # run stops for an unrelated reason and proves nothing about sizing.
        ck = count_key(Pivot("probe.favicon", "http.favicon.hash", "hA"))
        real = _b.publish_bytes
        monkeypatch.setattr(_b, "publish_bytes",
                            lambda dest, data, digest: (False if ck in str(dest)
                                                        else real(dest, data, digest=digest)))
        calls, _ = self._sized(monkeypatch, tmp_path, counts={"*": 250}, pivots=("hA",))
        sz = self._sizing(tmp_path)
        assert sz["succeeded"] == 0 and sz["evidence_failed"] == 1, sz
        assert [c for c in calls if "host/search" in c], "the paid run was blocked by sizing"

    def test_a_fully_owned_pivot_is_STILL_counted(self, monkeypatch, tmp_path):
        """Counting is how growth beyond a completed pagination is found — an old completion is not
        permanent. Second lifecycle: page 1 is owned, and the count must still be issued."""
        self._sized(monkeypatch, tmp_path, counts={"*": 50}, pivots=("hA",))
        calls, _ = self._sized(monkeypatch, tmp_path, counts={"*": 50}, pivots=("hA",))
        assert [c for c in calls if "host/count" in c], calls

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
        ms, total, err = probe._shodan_page("k", "http.favicon.hash", "hX", 1, sink=tmp_path / "p1.json")
        assert len(ms) == 100 and total == 500 and err is None
        ms2, total2, err2 = probe._shodan_page("k", "http.favicon.hash", "hX", 2,
                                               sink=tmp_path / "p2.json")
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

    def _machinery_lanes(self, monkeypatch, tmp_path, *, hostname="a.acme.com", store_ok=True,
                         save_raises=False):
        """Both real lanes through `_shodan_pivots`, with a REAL `run_work`. `store_ok=False` makes
        `ctx.run.add` raise for the FAVICON lane's hostname only — a lane-local ingestion failure."""
        from quarry_recon.phases import probe
        from quarry_recon import budget, secrets
        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 0)
        monkeypatch.setattr(probe.secrets, "shodan", lambda: "KEY")
        monkeypatch.setattr(secrets, "shodan", lambda: "KEY")
        body = json.dumps({"total": 1, "matches": [{"hostnames": [hostname]}]}).encode()
        monkeypatch.setattr(probe.urllib.request, "urlopen",
                            _with_balance(lambda req, timeout=20: _Resp(body), credits=100))
        if save_raises:
            real_save = budget.Ledger.save
            monkeypatch.setattr(budget.Ledger, "save",
                                lambda self: (_ for _ in ()).throw(OSError("store exploded"))
                                if self.lane == "probe.shodan" else real_save(self))
        ctx, added = self._ctx(tmp_path)
        ctx.run.read = lambda e: ([{"favicon": "F1"}] if e == "live"
                                  else [{"sha1": "C1"}] if e == "certificate" else [])
        if not store_ok:
            def add(entity, rec):
                if entity == "subdomain" and "favicon-shodan" in (rec.get("sources") or []):
                    raise OSError("store exploded")
                added.append((entity, rec))
                return True
            ctx.run.add = add
        probe._shodan_pivots(ctx)
        return added, self._events(tmp_path)

    def _terminals(self, evs, sid):
        from quarry_recon import events as _ev
        return [e for e in evs if e.get("source_id") == sid and e.get("event") == _ev.TOOL_FINISH]

    def test_a_MACHINERY_failure_is_never_a_clean_lane_terminal(self, monkeypatch, tmp_path):
        """review-B1.7a: the terminal only recognised machinery when a REMAINDER was left, so a run that
        bought every page and then could not write its state returned a clean terminal. Driven through a
        real `run_work` and a real raising save — not a fabricated `WorkResult`."""
        _added, evs = self._machinery_lanes(monkeypatch, tmp_path, save_raises=True)
        term = self._terminals(evs, "probe.favicon")
        assert term, [e.get("event") for e in evs]
        assert all(e["status"] != "success" for e in term), term
        assert "store exploded" in json.dumps(term), term

    def _classes(self, evs):
        return [e.get("error_class") for e in evs
                if e.get("source_id", "").startswith("probe.") and e.get("error_class")]

    def test_the_machinery_terminal_carries_a_CANONICAL_error_class(self, monkeypatch, tmp_path):
        """review-B1.7a#3: `res.stop_cause` was emitted AS the class, so `machinery:OSError` — a value
        outside `contract.PROVIDER_CLASSES` — reached provider telemetry."""
        from quarry_recon.contract import PROVIDER_CLASSES
        _added, evs = self._machinery_lanes(monkeypatch, tmp_path, save_raises=True)
        classes = self._classes(evs)
        assert classes, evs
        assert all(c in PROVIDER_CLASSES for c in classes), classes
        assert "machinery:OSError" not in json.dumps(classes)
        assert "error" in classes, classes

    def test_EVERY_internal_stop_cause_emits_a_canonical_class(self, monkeypatch, tmp_path):
        """review-B1.7a#4: only the raising-`save` path was covered, and `publish_failed` /
        `ledger_unwritable` / `scheduler_invariant` still emitted their own scheduler vocabulary as the
        provider error class. Driven through the real lane, one internal failure per case."""
        from quarry_recon.contract import PROVIDER_CLASSES
        from quarry_recon.phases import probe
        from quarry_recon import budget, secrets

        def lane(**kw):
            monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 0)
            monkeypatch.setattr(probe.secrets, "shodan", lambda: "KEY")
            monkeypatch.setattr(secrets, "shodan", lambda: "KEY")
            body = json.dumps({"total": 1, "matches": [{"hostnames": ["a.acme.com"]}]}).encode()
            monkeypatch.setattr(probe.urllib.request, "urlopen",
                                _with_balance(lambda req, timeout=20: _Resp(body), credits=100))
            for target, attr, value in kw.get("patches", ()):
                monkeypatch.setattr(target, attr, value)
            ctx, _ = self._ctx(tmp_path)
            ctx.run.read = lambda e: [{"favicon": "F1"}] if e == "live" else []
            probe._shodan_pivots(ctx)
            return self._events(tmp_path)

        # publish_failed: the artifact store refuses the page we just paid for
        evs = lane(patches=((budget, "publish_bytes", lambda *a, **k: False),))
        classes = self._classes(evs)
        assert classes, evs
        assert all(c in PROVIDER_CLASSES for c in classes), classes
        assert "publish_failed" not in json.dumps(classes), classes
        assert "publish_failed" in json.dumps([e.get("reason") for e in evs]), evs

    def _ledger_lane(self, monkeypatch, tmp_path, *, record=None, save=None):
        from quarry_recon.phases import probe
        from quarry_recon import budget, secrets
        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 0)
        monkeypatch.setattr(probe.secrets, "shodan", lambda: "KEY")
        monkeypatch.setattr(secrets, "shodan", lambda: "KEY")
        body = json.dumps({"total": 1, "matches": [{"hostnames": ["a.acme.com"]}]}).encode()
        monkeypatch.setattr(probe.urllib.request, "urlopen",
                            _with_balance(lambda req, timeout=20: _Resp(body), credits=100))
        # review-B1.7a#9: patch `_append`, never `record`. `record` updates the in-memory ownership map
        # and THEN appends, and that order is the whole point of the durability handshake — replacing it
        # skips the update, so the test would prove nothing about a rescued append.
        if record is not None:
            monkeypatch.setattr(budget.Ledger, "_append", record)
        if save is not None:
            monkeypatch.setattr(budget.Ledger, "save", save)
        ctx, _ = self._ctx(tmp_path)
        ctx.run.read = lambda e: ([{"favicon": "F1"}] if e == "live"
                                  else [{"sha1": "C1"}] if e == "certificate" else [])
        probe._shodan_pivots(ctx)
        return self._events(tmp_path)

    def test_a_RESCUED_append_failure_is_not_a_lane_defect(self, monkeypatch, tmp_path):
        """review-B1.7a#7: `Ledger.record` updates the ownership map BEFORE appending, and a successful
        `save()` snapshots that map — so an append that failed and a snapshot that wrote leaves the pages
        owned. `persisted` is the durability handshake; both lanes reported a defect over a snapshot that
        contained both completions."""
        from quarry_recon import budget
        real = budget.Ledger._append
        seen = []

        def append(self, rec):
            if "i" not in rec:                   # a checkpoint, not a completion
                return real(self, rec)
            seen.append(rec["i"])
            if len(seen) < 2:
                return real(self, rec)           # the FIRST completion journals normally
            return False                         # the SECOND append is refused; the snapshot still writes

        evs = self._ledger_lane(monkeypatch, tmp_path, record=append)
        # PAGE completions only. Each purchase also records an `acq:` receipt — acquisition is committed
        # separately from interpretation, so a page we cannot read is still owned (review#1).
        pages = [i for i in seen if not i.startswith("acq:")]
        assert len(pages) == 2, seen             # both lanes bought their page
        for sid in ("probe.favicon", "probe.cert"):
            term = self._terminals(evs, sid)
            assert term, (sid, evs)
            assert all(e["status"] in ("success", "empty") for e in term), (sid, term)
            assert "ledger_unwritable" not in json.dumps(term), (sid, term)
        # ...and the claim underneath it: the SNAPSHOT owns both completions, so a reopened ledger has
        # them and neither page is ever bought again.
        state = [p for p in tmp_path.rglob("probe_shodan.*.state.json")]
        assert state, list((tmp_path).rglob("*.json"))
        reopened = budget.Ledger(state[0], lane="probe.shodan")
        owned = dict(reopened.items())
        # both namespaces survive the reopen: the page completions AND their acquisition receipts
        assert len(pages) == 2 and all(k in owned for k in seen), (seen, owned)
        assert sum(1 for k in owned if k.startswith("acq:")) == 2, owned

    def test_a_lane_LEFT_UNQUERIED_by_a_ledger_stop_still_reports_it(self, monkeypatch, tmp_path):
        """The counterpart: the FIRST append fails, so the second lane never gets its page. A rescued
        append is not a defect — an unqueried pivot is, and the stop is what explains it."""
        evs = self._ledger_lane(monkeypatch, tmp_path, record=_refuse_completion_appends)
        unqueried = [e for e in self._terminals(evs, "probe.favicon")
                     if "ledger_unwritable" in (e.get("reason") or "")]
        assert unqueried, self._terminals(evs, "probe.favicon")
        assert all(e["status"] != "success" for e in unqueried), unqueried
        # the lane that DID get its page keeps its clean terminal
        cert = self._terminals(evs, "probe.cert")
        assert any(e["status"] in ("success", "empty") for e in cert), cert

    def test_a_LEDGER_that_persists_NOTHING_emits_a_canonical_class(self, monkeypatch, tmp_path):
        """The other half: the append failed AND the snapshot did not write, so the pages really are lost
        and every lane owes the operator that fact — with a canonical class and no dangling prose."""
        from quarry_recon.contract import PROVIDER_CLASSES
        evs = self._ledger_lane(monkeypatch, tmp_path, record=_refuse_completion_appends,
                                save=lambda self: False)
        classes = self._classes(evs)
        assert classes, evs
        assert all(c in PROVIDER_CLASSES for c in classes), classes
        assert "ledger_unwritable" not in json.dumps(classes), classes
        reasons = [e.get("reason") or "" for e in self._terminals(evs, "probe.favicon")]
        assert any("NOT persisted" in r for r in reasons), reasons
        assert not any("—  " in r or r.endswith("— ") for r in reasons), reasons
        assert any("ledger_unwritable" in r for r in reasons), reasons

    @pytest.mark.parametrize("token,want", [
        ("auth_refused", "auth"),            # the CREDENTIAL does not work — that is `auth`
        ("reserve_invalid", "error"),         # a broken cost guard is OUR defect
        ("ledger_unwritable", "error"),
        ("publish_failed", "error"),
        ("scheduler_invariant", "error"),
        ("machinery:OSError", "error"),
        ("provider_exhausted", "error"),      # a stop KIND, not a class: `_STOP_CLASS` maps it to quota
        ("auth", "auth"), ("quota", "quota"), ("forbidden", "forbidden"),
        ("entitlement", "entitlement"), ("transport", "transport"), ("parse", "parse"),
    ])
    def test_the_canonicaliser_maps_EVERY_internal_token(self, token, want):
        """review-B1.7a#4: one mapper, so no call site has to remember. Every token the lane can hold is
        listed here, and every answer is a value `contract.PROVIDER_CLASSES` actually defines."""
        from quarry_recon.contract import PROVIDER_CLASSES
        from quarry_recon.phases import probe
        got = probe._canonical_class(token)
        assert got == want, f"{token} -> {got}"
        assert got in PROVIDER_CLASSES, got

    def test_a_COUNT_refusal_emits_its_canonical_class_not_the_token(self, monkeypatch, tmp_path):
        """The `auth_refused` path in production: a FREE /host/count proves the credential is refused,
        which stops paid work. `auth_refused` is a stop token; the class it means is `auth`."""
        from quarry_recon.contract import PROVIDER_CLASSES
        from quarry_recon.phases import probe
        from quarry_recon import secrets
        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 0)
        monkeypatch.setattr(probe.secrets, "shodan", lambda: "KEY")
        monkeypatch.setattr(secrets, "shodan", lambda: "KEY")

        body = json.dumps({"total": 1, "matches": [{"hostnames": ["a.acme.com"]}]}).encode()
        # NB not `_with_balance`: that helper answers /host/count itself, so a refusal scripted through it
        # never reaches the endpoint under test.
        info = json.dumps({"query_credits": 100, "scan_credits": 0}).encode()

        def urlopen(req, timeout=20):
            url = str(req.full_url)
            if "api-info" in url:
                return _Resp(info)
            if "/shodan/host/count" in url:
                # ONLY the free count endpoint refuses: a bad key answers 401 with HTML — the measured
                # shape that is auth, not quota. That refusal stops paid work before any search.
                raise urllib.error.HTTPError(url, 401, "unauthorized", {},
                                            io.BytesIO(b"<html>bad key</html>"))
            return _Resp(body)

        monkeypatch.setattr(probe.urllib.request, "urlopen", urlopen)
        ctx, _ = self._ctx(tmp_path)
        ctx.run.read = lambda e: [{"favicon": "F1"}] if e == "live" else []
        probe._shodan_pivots(ctx)
        evs = self._events(tmp_path)
        classes = self._classes(evs)
        assert classes, evs
        assert all(c in PROVIDER_CLASSES for c in classes), classes
        assert "auth_refused" not in json.dumps(classes), classes
        assert classes == ["auth"], classes            # what the refusal MEANS, from the free endpoint
        # ...and WHICH endpoint proved it stays in the prose, where a scheduler token belongs
        assert "/host/count" in json.dumps([e.get("reason") for e in evs]), evs

    def test_a_BROKEN_COST_GUARD_emits_a_canonical_class(self, monkeypatch, tmp_path):
        """`reserve_invalid` is the one non-canonical token production reaches through the BALANCE site: a
        present-but-unusable `SHODAN_CREDIT_RESERVE` stops spending with no read error to speak for it.
        It is OUR defect, which the taxonomy calls `error` — and the token stays in the reason."""
        from quarry_recon.contract import PROVIDER_CLASSES
        from quarry_recon.phases import probe
        from quarry_recon import secrets
        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 0)
        monkeypatch.setattr(probe.settings, "performance",
                            lambda: {"SHODAN_CREDIT_RESERVE": "not-a-number"})
        monkeypatch.setattr(probe.secrets, "shodan", lambda: "KEY")
        monkeypatch.setattr(secrets, "shodan", lambda: "KEY")
        body = json.dumps({"total": 1, "matches": [{"hostnames": ["a.acme.com"]}]}).encode()
        monkeypatch.setattr(probe.urllib.request, "urlopen",
                            _with_balance(lambda req, timeout=20: _Resp(body), credits=100))
        ctx, _ = self._ctx(tmp_path)
        ctx.run.read = lambda e: [{"favicon": "F1"}] if e == "live" else []
        probe._shodan_pivots(ctx)
        evs = self._events(tmp_path)
        classes = self._classes(evs)
        assert classes, evs
        assert all(c in PROVIDER_CLASSES for c in classes), classes
        assert "reserve_invalid" not in json.dumps(classes), classes
        assert classes == ["error"], classes
        assert "reserve_invalid" in json.dumps([e.get("reason") for e in evs]), evs

    def test_a_BALANCE_stop_token_is_not_emitted_as_a_class(self, monkeypatch, tmp_path):
        """`auth_refused` and `reserve_invalid` are stop tokens, not taxonomy classes."""
        from quarry_recon.contract import PROVIDER_CLASSES
        from quarry_recon.phases import probe
        from quarry_recon import secrets
        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 0)
        monkeypatch.setattr(probe.secrets, "shodan", lambda: "KEY")
        monkeypatch.setattr(secrets, "shodan", lambda: "KEY")

        def refused(req, timeout=20):
            raise urllib.error.HTTPError(str(req.full_url), 401, "unauthorized", {},
                                        io.BytesIO(b"<html>bad key</html>"))

        monkeypatch.setattr(probe.urllib.request, "urlopen", refused)
        ctx, _ = self._ctx(tmp_path)
        ctx.run.read = lambda e: [{"favicon": "F1"}] if e == "live" else []
        probe._shodan_pivots(ctx)
        evs = self._events(tmp_path)
        classes = self._classes(evs)
        assert classes, evs
        assert all(c in PROVIDER_CLASSES for c in classes), classes
        assert "auth_refused" not in json.dumps(classes), classes
        assert "auth" in classes, classes

    def test_lane_isolation_holds_for_a_store_error_that_REJECTS_ATTRIBUTES(self, monkeypatch,
                                                                            tmp_path):
        """review-B1.7a#5, end to end: the store raises an exception that cannot be tagged."""
        from quarry_recon.phases import probe
        from quarry_recon import secrets

        class _Immutable(OSError):
            __slots__ = ()

            def __setattr__(self, k, v):
                raise AttributeError("this exception refuses attributes")

        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 0)
        monkeypatch.setattr(probe.secrets, "shodan", lambda: "KEY")
        monkeypatch.setattr(secrets, "shodan", lambda: "KEY")
        body = json.dumps({"total": 1, "matches": [{"hostnames": ["a.acme.com"]}]}).encode()
        monkeypatch.setattr(probe.urllib.request, "urlopen",
                            _with_balance(lambda req, timeout=20: _Resp(body), credits=100))
        ctx, added = self._ctx(tmp_path)
        ctx.run.read = lambda e: ([{"favicon": "F1"}] if e == "live"
                                  else [{"sha1": "C1"}] if e == "certificate" else [])

        def add(entity, rec):
            if entity == "subdomain" and "favicon-shodan" in (rec.get("sources") or []):
                raise _Immutable("store exploded")
            added.append((entity, rec))
            return True

        ctx.run.add = add
        probe._shodan_pivots(ctx)
        evs = self._events(tmp_path)
        fav, cert = self._terminals(evs, "probe.favicon"), self._terminals(evs, "probe.cert")
        assert fav and cert, evs
        assert all(e["status"] != "success" for e in fav), fav
        assert any(e["status"] in ("success", "empty") for e in cert), cert
        assert "store exploded" not in json.dumps(cert), cert
        # ...and the failing lane says it ONCE: a double-filed fault used to appear lane-local AND global
        assert json.dumps(fav).count("store exploded") == 1, fav

    def test_a_LANE_LOCAL_store_failure_leaves_the_SIBLING_lane_successful(self, monkeypatch, tmp_path):
        """review-B1.7a#2: reproduced end-to-end — cert completed, favicon's store raised, and BOTH
        terminals read partial."""
        _added, evs = self._machinery_lanes(monkeypatch, tmp_path, store_ok=False)
        fav = self._terminals(evs, "probe.favicon")
        cert = self._terminals(evs, "probe.cert")
        assert fav and cert, evs
        assert all(e["status"] != "success" for e in fav), fav
        # the failing lane must NAME its own failure, not merely count an unconsumed page
        assert "store exploded" in json.dumps(fav), fav
        assert any(e["status"] in ("success", "empty") for e in cert), cert
        assert "store exploded" not in json.dumps(cert), cert

    def test_a_HOSTNAME_we_could_not_store_is_not_reported_as_produced(self, monkeypatch, tmp_path):
        """review-B1.7a#1: `found.add()` ran BEFORE `ctx.run.add()`, so a storage failure still announced
        the hostname the store never took. `produced` on the terminal is that announcement."""
        added, evs = self._machinery_lanes(monkeypatch, tmp_path, store_ok=False)
        assert not [r for e, r in added if e == "subdomain"
                    and "favicon-shodan" in (r.get("sources") or [])]
        fav = self._terminals(evs, "probe.favicon")
        assert fav, evs
        produced = [e.get("produced") for e in fav]
        assert all((pr or {}).get("host", 0) == 0 for pr in produced), produced
        # the SIBLING lane stored its own host and must still report it
        cert = self._terminals(evs, "probe.cert")
        assert any((e.get("produced") or {}).get("host") == 1 for e in cert), cert

    def test_a_PROVIDER_LIMIT_survives_a_later_machinery_failure(self, monkeypatch, tmp_path):
        """review-B1.7a#3: the gap dominates — and the limit is an independent fact that must not be
        destroyed by it. It keeps its own coverage measure and is named on the terminal."""
        from quarry_recon.phases import probe
        from quarry_recon import budget, secrets
        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 0)
        monkeypatch.setattr(probe.secrets, "shodan", lambda: "KEY")
        monkeypatch.setattr(secrets, "shodan", lambda: "KEY")
        page1 = json.dumps({"total": 2 * 100, "matches": [{"hostnames": ["a.acme.com"]}]}).encode()

        # MEASURED (contract.py:163): a spent Shodan account answers 401 with an "Insufficient query
        # credits" BODY. The code alone is `auth`; only the body proves `quota`.
        quota_body = json.dumps({"error": "Insufficient query credits, please upgrade your API plan "
                                          "or wait for the monthly limit to reset"}).encode()

        def responder(req, timeout=20):
            if "page=2" in str(req.full_url):
                raise urllib.error.HTTPError(str(req.full_url), 401, "unauthorized", {},
                                            io.BytesIO(quota_body))
            return _Resp(page1)

        monkeypatch.setattr(probe.urllib.request, "urlopen", _with_balance(responder, credits=100))
        real_save = budget.Ledger.save
        monkeypatch.setattr(budget.Ledger, "save",
                            lambda self: (_ for _ in ()).throw(OSError("store exploded"))
                            if self.lane == "probe.shodan" else real_save(self))
        ctx, _added = self._ctx(tmp_path)
        ctx.run.read = lambda e: [{"favicon": "F1"}] if e == "live" else []
        probe._shodan_pivots(ctx)

        evs = self._events(tmp_path)
        fav = self._terminals(evs, "probe.favicon")
        assert fav, evs
        blob = json.dumps(fav)
        assert "store exploded" in blob, blob                       # the gap
        # the LIMIT, still stated on the terminal in its own words — `provider_stop:*` is the scheduler
        # explaining why it stopped, not the count of pages the provider refused.
        assert "provider-limited" in blob, blob
        assert "'quota': 1" in blob or '"quota": 1' in blob, blob
        assert all(e.get("error_class") == "error" for e in fav if e.get("error_class")), fav
        lim = self._cov(tmp_path, "shodan_results_limited")
        assert lim and lim[0]["omitted"] == 1, lim

    def test_an_UNCONSUMED_page_reaches_coverage(self, monkeypatch, tmp_path):
        """An owned page whose ingestion failed is out of the page remainder; nothing else can say its
        rows are missing."""
        from types import SimpleNamespace

        from quarry_recon import shodan_sched
        self._ctx(tmp_path)                              # events sink
        o = shodan_sched.LaneOutcome(lane="probe.favicon", pivots=1, pages_bought=2,
                                     pages_unconsumed=1)
        shodan_sched.report("probe.favicon", o, persisted=True,
                            balance=SimpleNamespace(stop_kind="", reason="test"))
        cov = self._cov(tmp_path, "shodan_pages_unconsumed")
        assert cov and cov[0]["omitted"] == 1, cov
        assert "NOT in the store" in cov[0]["reason"], cov[0]["reason"]
