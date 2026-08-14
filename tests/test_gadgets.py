"""GADGET CANDIDATES — layer 1.

The boundary being pinned is the one that makes the queue worth reading:

    HOTLIST   things to verify as findings
    GADGETS   primitives that prove nothing alone and decide a chain later

So: impact is never claimed, suppression is explicit and named, the evidence is cited, and the classifier
contacts nothing — every input is an entity another lane already produced.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.offline

from quarry_recon import gadgets, store, triage


class _Scope:
    def __init__(self, apexes=("acme.com",), oos=()):
        self.apexes, self.oos = apexes, set(oos)

    def in_scope(self, host: str) -> bool:
        host = (host or "").lower()
        return (any(host == a or host.endswith("." + a) for a in self.apexes)
                and host not in self.oos)


def _run(tmp_path, *entities, target="acme.com"):
    run = store.Run.create(tmp_path, target)
    for kind, rec in entities:
        run.add(kind, rec)
    return run


def _live(url="https://sso.acme.com/login", *, location=None, status=302, host=None, raw="raw/x.json"):
    return ("live", {"url": url, "host": host or url.split("/")[2], "status_code": status,
                     "location": location, "raw_ref": raw, "sources": ["httpx"]})


class TestTheMalformedLocationPrimitive:
    """The seed case: a SAML/Mellon flow emitting `https:/host/path` — one slash, so a client and a
    server can resolve it to different places."""

    @pytest.mark.parametrize("bad,why", [
        ("https:/privacyidea.acme.com/saml", "ONE slash"),
        ("https:\\\\acme.com/x", "backslashes"),
        ("////evil.example/x", "three or more leading slashes"),
        (" https://acme.com/x", "whitespace"),
        ("https://acme.com/\x00x", "control character"),
        ("https://https://acme.com", "two stacked schemes")])
    def test_a_location_two_parsers_can_disagree_about(self, tmp_path, bad, why):
        run = _run(tmp_path, _live(location=bad))
        assert gadgets.classify(run, _Scope()) >= 1
        [g] = [g for g in run.read("gadget_candidate") if g["klass"] == "redirect-parser"]
        assert g["subtype"] == "malformed-location"
        assert repr(bad)[1:-1] in g["observed_behavior"] or bad.strip() in g["observed_behavior"]
        assert "parser-differential" in g["chain_potential"]

    def test_a_WELL_FORMED_location_is_not_a_gadget(self, tmp_path):
        run = _run(tmp_path, _live(location="https://acme.com/dashboard"))
        gadgets.classify(run, _Scope())
        assert not [g for g in run.read("gadget_candidate") if g["klass"] == "redirect-parser"]

    def test_inside_an_AUTH_flow_it_carries_the_auth_chains(self, tmp_path):
        run = _run(tmp_path, _live("https://x.acme.com/saml2/acs", location="https:/x.acme.com/y"))
        gadgets.classify(run, _Scope())
        [g] = [g for g in run.read("gadget_candidate") if g["klass"] == "redirect-parser"]
        assert {"saml", "oauth", "ato"} <= set(g["chain_potential"]) and g["confidence"] == "med"

    def test_outside_one_it_stays_LOW_and_generic(self, tmp_path):
        run = _run(tmp_path, _live("https://x.acme.com/files", location="https:/x.acme.com/y"))
        gadgets.classify(run, _Scope())
        [g] = [g for g in run.read("gadget_candidate") if g["klass"] == "redirect-parser"]
        assert g["confidence"] == "low" and "saml" not in g["chain_potential"]


class TestTheAuthFlowRedirectParameter:
    def test_a_redirect_param_INSIDE_an_auth_flow_is_a_gadget(self, tmp_path):
        run = _run(tmp_path, ("url", {"url": "https://acme.com/oauth2/authorize?redirect_uri=https://cb",
                                      "sources": ["katana"]}))
        gadgets.classify(run, _Scope())
        [g] = [g for g in run.read("gadget_candidate") if g["klass"] == "auth-flow"]
        assert g["param"] == "redirect_uri" and {"oauth", "ato"} <= set(g["chain_potential"])

    def test_the_SAME_param_outside_one_is_left_to_the_redirect_queue(self, tmp_path):
        run = _run(tmp_path, ("url", {"url": "https://acme.com/search?next=/x", "sources": ["katana"]}))
        gadgets.classify(run, _Scope())
        assert not [g for g in run.read("gadget_candidate") if g["klass"] == "auth-flow"]

    @pytest.mark.parametrize("param", ["RelayState", "returnUrl", "state", "continue"])
    def test_the_vocabulary_is_case_insensitive(self, tmp_path, param):
        run = _run(tmp_path, ("url", {"url": f"https://acme.com/sso/start?{param}=abc",
                                      "sources": ["gau"]}))
        gadgets.classify(run, _Scope())
        assert [g for g in run.read("gadget_candidate") if g["klass"] == "auth-flow"]

    def test_an_OOS_host_is_observed_evidence_not_our_gadget(self, tmp_path):
        run = _run(tmp_path, ("url", {"url": "https://partner.example/oauth2/authorize?redirect_uri=x",
                                      "sources": ["gau"]}))
        gadgets.classify(run, _Scope())
        assert not run.read("gadget_candidate")

    def test_an_endpoint_row_is_read_too(self, tmp_path):
        run = _run(tmp_path, ("endpoint", {"value": "https://acme.com/login?returnUrl=/a",
                                           "sources": ["jsluice"]}))
        gadgets.classify(run, _Scope())
        assert [g for g in run.read("gadget_candidate") if g["klass"] == "auth-flow"]


class TestTheCrossHostRedirect:
    def test_a_hop_that_LEAVES_the_estate_is_recorded(self, tmp_path):
        run = _run(tmp_path, _live("https://acme.com/go", location="https://tracker.example/x"))
        gadgets.classify(run, _Scope())
        [g] = [g for g in run.read("gadget_candidate") if g["klass"] == "redirect-chain"]
        assert g["subtype"] == "cross-host" and "tracker.example" in g["observed_behavior"]

    def test_ordinary_INTERNAL_structure_is_not_a_gadget(self, tmp_path):
        """An in-scope host redirecting to another in-scope host outside an auth flow is what the site
        DOES; recording it buries the queue on exactly the estates worth reading."""
        run = _run(tmp_path, _live("https://acme.com/x", location="https://www.acme.com/x"))
        gadgets.classify(run, _Scope())
        assert not [g for g in run.read("gadget_candidate") if g["klass"] == "redirect-chain"]

    def test_but_INSIDE_an_auth_flow_it_is_kept(self, tmp_path):
        run = _run(tmp_path, _live("https://acme.com/oauth2/callback",
                                   location="https://www.acme.com/x"))
        gadgets.classify(run, _Scope())
        assert [g for g in run.read("gadget_candidate") if g["klass"] == "redirect-chain"]

    def test_a_NON_3xx_location_is_not_a_redirect(self, tmp_path):
        run = _run(tmp_path, _live(location="https://other.example/x", status=200))
        gadgets.classify(run, _Scope())
        assert not [g for g in run.read("gadget_candidate") if g["klass"] == "redirect-chain"]

    def test_a_relative_location_is_not_a_cross_host_hop(self, tmp_path):
        run = _run(tmp_path, _live(location="/dashboard"))
        gadgets.classify(run, _Scope())
        assert not [g for g in run.read("gadget_candidate") if g["klass"] == "redirect-chain"]


class TestSuppressionIsExplicit:
    def test_a_site_that_redirects_EVERYTHING_to_sso_is_not_offering_a_primitive(self, tmp_path):
        run = _run(tmp_path, *[_live(f"https://app.acme.com/p{i}", location="https:/sso.acme.com/login")
                               for i in range(6)])
        gadgets.classify(run, _Scope())
        assert not run.read("gadget_candidate"), "one row per URL is what makes a queue unreadable"

    def test_a_HANDFUL_of_identical_redirects_is_still_kept(self, tmp_path):
        """The rule needs a population to be evidence of uniformity — three pages is not a pattern."""
        run = _run(tmp_path, *[_live(f"https://app.acme.com/p{i}", location="https:/sso.acme.com/login")
                               for i in range(3)])
        gadgets.classify(run, _Scope())
        assert run.read("gadget_candidate")

    def test_a_VARYING_destination_is_never_suppressed(self, tmp_path):
        run = _run(tmp_path, *[_live(f"https://app.acme.com/p{i}",
                                     location=f"https:/sso.acme.com/login?t={i}") for i in range(8)])
        gadgets.classify(run, _Scope())
        assert len(run.read("gadget_candidate")) == 8


class TestTheContractWithTheRestOfQuarry:
    def test_a_gadget_is_NEVER_a_finding(self, tmp_path):
        run = _run(tmp_path, _live(location="https:/acme.com/x"))
        gadgets.classify(run, _Scope())
        assert run.count("finding") == 0
        assert all(g["impact_state"] == "none_proven" for g in run.read("gadget_candidate"))

    def test_every_gadget_CITES_its_evidence(self, tmp_path):
        run = _run(tmp_path, _live(location="https:/acme.com/x", raw="raw/probe/httpx.json"))
        gadgets.classify(run, _Scope())
        [g] = run.read("gadget_candidate")
        # the ENTITY's own provenance, not a label the classifier invented: `klass`/`subtype` already
        # say which signal was read, `sources` says who produced the evidence
        assert g["raw_ref"] == "raw/probe/httpx.json" and g["sources"] == ["httpx"]

    def test_classification_is_IDEMPOTENT(self, tmp_path):
        run = _run(tmp_path, _live(location="https:/acme.com/x"))
        first = gadgets.classify(run, _Scope())
        assert first == 1 and gadgets.classify(run, _Scope()) == 0, "a re-run must not duplicate rows"
        assert len(run.read("gadget_candidate")) == 1

    def test_the_classifier_CONTACTS_nothing(self, tmp_path, monkeypatch):
        """It may never change what a run did to a target — only what the run remembers about it."""
        import urllib.request
        monkeypatch.setattr(urllib.request, "urlopen",
                            lambda *a, **k: pytest.fail("the classifier made a request"))
        run = _run(tmp_path, _live(location="https:/acme.com/x"),
                   ("url", {"url": "https://acme.com/sso?next=/a", "sources": ["gau"]}))
        assert gadgets.classify(run, _Scope()) == 2

    def test_the_digest_carries_gadgets_in_their_OWN_queue(self, tmp_path):
        run = _run(tmp_path, _live(location="https:/acme.com/x"))
        gadgets.classify(run, _Scope())
        run.write_manifest(profile_summary={}, phases_run=["probe"])
        digest = triage.digest_json(run, _Scope())
        assert "gadgets" in digest["queues"], "the queue key must exist in the contract"
        [item] = digest["queues"]["gadgets"]
        assert "impact:none_proven" in item["tags"] and "gadget" in item["tags"]
        assert any(t.startswith("chain:") for t in item["tags"])
        for q, items in digest["queues"].items():
            if q != "gadgets":
                assert not any(i["type"] == "gadget_candidate" for i in items), q

    def test_an_EMPTY_gadget_queue_is_still_in_the_contract(self, tmp_path):
        run = _run(tmp_path, _live(location="https://acme.com/ok"))
        run.write_manifest(profile_summary={}, phases_run=["probe"])
        assert triage.digest_json(run, _Scope())["queues"]["gadgets"] == []

    def test_the_hotlist_states_the_BOUNDARY(self, tmp_path):
        run = _run(tmp_path, _live(location="https:/acme.com/x"))
        gadgets.classify(run, _Scope())
        text = triage.build(run, _Scope())
        assert "chain material, NOT findings" in text
        assert "never report one as an impact" in text

    def test_a_malformed_entity_never_stops_the_classifier(self, tmp_path):
        run = _run(tmp_path, _live(location="https:/acme.com/x"))
        (run.normalized / "live.jsonl").write_text(
            (run.normalized / "live.jsonl").read_text() + "not json\n")
        assert gadgets.classify(run, _Scope()) >= 1


class TestEveryClassifierIsScopeGated:
    """Scope is not one classifier's concern. A primitive on a host we may never act on is observed
    behaviour, not chain material — and publishing it as ours invites the action the RoE forbids."""

    @pytest.mark.parametrize("live", [
        _live("https://partner.example/x", location="https:/partner.example/y"),      # malformed
        _live("https://partner.example/x", location="https://tracker.example/y")])    # cross-host
    def test_an_OOS_live_origin_is_never_our_gadget(self, tmp_path, live):
        run = _run(tmp_path, live)
        assert gadgets.classify(run, _Scope()) == 0
        assert not run.read("gadget_candidate")

    def test_an_EXPLICITLY_oos_subdomain_is_gated_too(self, tmp_path):
        run = _run(tmp_path, _live("https://lab.acme.com/x", location="https:/lab.acme.com/y"))
        assert gadgets.classify(run, _Scope(oos=["lab.acme.com"])) == 0

    def test_an_in_scope_origin_still_passes(self, tmp_path):
        run = _run(tmp_path, _live("https://app.acme.com/x", location="https:/app.acme.com/y"))
        assert gadgets.classify(run, _Scope()) == 1


class TestProvenanceSurvivesTheClassifier:
    def test_an_auth_param_gadget_keeps_the_ENTITY_provenance(self, tmp_path):
        run = _run(tmp_path, ("url", {"url": "https://acme.com/oauth2/authorize?redirect_uri=x",
                                      "sources": ["katana"], "raw_ref": "raw/crawl/katana.jsonl"}))
        gadgets.classify(run, _Scope())
        [g] = run.read("gadget_candidate")
        assert g["sources"] == ["katana"], "a lane name substituted for the real source"
        assert g["raw_ref"] == "raw/crawl/katana.jsonl", "the reviewer must land on the response"

    def test_raw_refs_PLURAL_is_read_when_that_is_what_the_entity_has(self, tmp_path):
        run = _run(tmp_path, ("endpoint", {"value": "https://acme.com/sso?RelayState=1",
                                           "sources": ["jsluice"], "raw_refs": ["raw/a.js", "raw/b.js"]}))
        gadgets.classify(run, _Scope())
        [g] = run.read("gadget_candidate")
        assert g["raw_ref"] == "raw/a.js" and g["sources"] == ["jsluice"]

    def test_an_entity_with_NO_provenance_says_so_rather_than_inventing_it(self, tmp_path):
        run = _run(tmp_path, ("url", {"url": "https://acme.com/login?next=/a"}))
        gadgets.classify(run, _Scope())
        [g] = run.read("gadget_candidate")
        assert g["sources"] == ["url-corpus"] and g["raw_ref"] == ""


class TestTheSuppressionPopulationIsRedirects:
    def test_ONE_redirect_beside_ordinary_pages_is_not_a_pattern(self, tmp_path):
        """Counting every live row let four unrelated 200s certify a single redirect as uniform — and
        that redirect is exactly the primitive the rule exists to keep."""
        rows = [_live(f"https://app.acme.com/ok{i}", location=None, status=200) for i in range(4)]
        rows.append(_live("https://app.acme.com/go", location="https:/sso.acme.com/login"))
        run = _run(tmp_path, *rows)
        gadgets.classify(run, _Scope())
        assert len(run.read("gadget_candidate")) == 1

    def test_FIVE_identical_redirects_are_still_suppressed(self, tmp_path):
        run = _run(tmp_path, *[_live(f"https://app.acme.com/p{i}", location="https:/sso.acme.com/login")
                               for i in range(5)])
        gadgets.classify(run, _Scope())
        assert not run.read("gadget_candidate")


class TestAuthContextComesFromThePath:
    def test_a_QUERY_VALUE_cannot_invent_an_auth_flow(self, tmp_path):
        """The parameter an attacker controls must not create the context it is judged in."""
        run = _run(tmp_path, ("url", {"url": "https://acme.com/search?next=/oauth/callback",
                                      "sources": ["gau"]}))
        gadgets.classify(run, _Scope())
        assert not run.read("gadget_candidate")

    def test_the_PATH_still_decides_it(self, tmp_path):
        run = _run(tmp_path, ("url", {"url": "https://acme.com/oauth/callback?next=/home",
                                      "sources": ["gau"]}))
        gadgets.classify(run, _Scope())
        assert [g for g in run.read("gadget_candidate") if g["klass"] == "auth-flow"]

    def test_a_malformed_location_does_not_gain_auth_chains_from_a_query(self, tmp_path):
        run = _run(tmp_path, _live("https://acme.com/x?u=/saml/acs", location="https:/acme.com/y"))
        gadgets.classify(run, _Scope())
        [g] = run.read("gadget_candidate")
        assert "saml" not in g["chain_potential"] and g["confidence"] == "low"

    def test_a_cross_host_hop_INTO_an_sso_path_is_still_auth_context(self, tmp_path):
        run = _run(tmp_path, _live("https://acme.com/go", location="https://idp.example/saml/sso"))
        gadgets.classify(run, _Scope())
        [g] = [g for g in run.read("gadget_candidate") if g["klass"] == "redirect-chain"]
        assert "saml" in g["chain_potential"]


class TestALocationAloneIsNotARedirect:
    """A `Location` on a 200 is a curiosity, not a redirect. Calling it one published false gadgets and
    let five such responses satisfy the population that protects real ones."""

    @pytest.mark.parametrize("status", [200, 404, 500, None, "302", True,
                                       304,     # Not Modified: cache validators, redirects nobody
                                       300,     # Multiple Choices: offers, does not take one
                                       305])    # Use Proxy: an instruction about HOW, not WHERE
    def test_a_location_on_a_NON_REDIRECT_status_is_not_a_gadget(self, tmp_path, status):
        run = _run(tmp_path, _live(location="https:/acme.com/y", status=status))
        assert gadgets.classify(run, _Scope()) == 0

    @pytest.mark.parametrize("status", sorted(gadgets.REDIRECT_STATUSES))
    def test_every_REDIRECTING_status_still_counts(self, tmp_path, status):
        run = _run(tmp_path, _live(location="https:/acme.com/y", status=status))
        assert gadgets.classify(run, _Scope()) == 1

    def test_non_redirect_rows_cannot_SUPPRESS_a_real_redirect(self, tmp_path):
        rows = [_live(f"https://app.acme.com/ok{i}", location="https:/sso.acme.com/login",
                      status=304 if i % 2 else 200) for i in range(6)]
        rows.append(_live("https://app.acme.com/go", location="https:/sso.acme.com/login", status=302))
        run = _run(tmp_path, *rows)
        gadgets.classify(run, _Scope())
        assert len(run.read("gadget_candidate")) == 1, "200s with a Location suppressed the real one"


class TestProvenanceIsKeptWHOLE:
    def test_every_source_survives(self, tmp_path):
        run = _run(tmp_path, ("url", {"url": "https://acme.com/oauth2/authorize?redirect_uri=x",
                                      "sources": ["katana", "gau"], "raw_ref": "raw/a.jsonl"}))
        gadgets.classify(run, _Scope())
        [g] = run.read("gadget_candidate")
        assert g["sources"] == ["katana", "gau"], "corroboration dropped with the second source"

    def test_a_live_gadget_carries_the_live_entitys_sources(self, tmp_path):
        run = _run(tmp_path, ("live", {"url": "https://acme.com/x", "host": "acme.com",
                                       "status_code": 302, "location": "https:/acme.com/y",
                                       "sources": ["httpx", "smap"], "raw_ref": "raw/p.json"}))
        gadgets.classify(run, _Scope())
        [g] = run.read("gadget_candidate")
        assert g["sources"] == ["httpx", "smap"]


class TestAuthMarkersMatchSEGMENTS:
    @pytest.mark.parametrize("path", ["/authorization-help", "/login-assets", "/ssoftware",
                                      "/authors/list", "/deauth"])
    def test_a_path_that_merely_CONTAINS_a_marker_is_not_an_auth_route(self, tmp_path, path):
        run = _run(tmp_path, ("url", {"url": f"https://acme.com{path}?next=/a", "sources": ["gau"]}))
        assert gadgets.classify(run, _Scope()) == 0, path

    @pytest.mark.parametrize("path", ["/auth/callback", "/login", "/oauth2/authorize", "/sso/start",
                                      "/api/v2/saml/acs", "/sign-in", "/.well-known/openid-configuration"])
    def test_a_real_auth_route_still_matches(self, tmp_path, path):
        run = _run(tmp_path, ("url", {"url": f"https://acme.com{path}?next=/a", "sources": ["gau"]}))
        assert gadgets.classify(run, _Scope()) == 1, path

    def test_a_marker_deep_in_the_path_still_counts(self, tmp_path):
        run = _run(tmp_path, ("url", {"url": "https://acme.com/tenant/9/idp/login?RelayState=x",
                                      "sources": ["gau"]}))
        assert gadgets.classify(run, _Scope()) == 1
