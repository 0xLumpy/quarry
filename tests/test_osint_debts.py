"""The four OSINT/preflight debts, and the notification they are reported through.

Each was a SILENT loss: a membership cap with no remainder, an `or` that dropped half its evidence, a
documented output nobody collected, and two notifications carrying the same body with Quarry's internal
vocabulary in it. What is pinned here is that nothing is dropped without saying so.
"""
from __future__ import annotations

import json
import pathlib

import pytest

pytestmark = pytest.mark.offline

from quarry_recon import fetch, netguard, network_policy, notify, osint, policy, settings
from quarry_recon.runner_repository import ArtifactDisposition, RepositoryOutput


class _Sess:
    """The parts of `OsintSession` these lanes touch."""

    def __init__(self, tmp_path):
        self.dir = tmp_path
        self.cands: list = []
        self.intel_rows: list = []
        self.records: list = []
        self.failures: list = []
        # RDAP address discovery is now a bound, mediated DNS effect even in
        # these small lane-accounting doubles.
        scope = network_policy.NetworkPolicyScope(
            block_private_targets=False, apex_domains=(), own_ips=("192.0.2.10",),
            resolver_ips=("1.1.1.1",),
        )
        scope._trace = lambda _document: None
        self._network_policy_scope = scope

    def raw_path(self, source, name):
        p = self.dir / "raw" / source
        p.mkdir(parents=True, exist_ok=True)
        return p / name

    def output(self, path=None):
        if path is None:
            return RepositoryOutput.discard()
        return RepositoryOutput.publish(*path.relative_to(self.dir).parts)

    def candidate(self, value, ctype, source, hint, reason, raw_ref=None, manual_followup=None):
        self.cands.append({"value": value, "type": ctype, "source": source, "reason": reason,
                           "hint": hint, "followup": manual_followup, "raw_ref": raw_ref})

    def intel(self, kind, value, source, **provenance):
        self.intel_rows.append({"kind": kind, "value": value, "source": source, **provenance})

    def record(self, result):
        self.records.append(result)

    def note_failure(self, tool, why):
        self.failures.append({"tool": tool, "why": why})


class TestTheRDAPLaneBoundsTHROUGHPUTNotMembership:
    @staticmethod
    def _addresses(monkeypatch, mapping):
        def fake(_scope, host, **_kwargs):
            answers = tuple(mapping.get(host, ()))
            return netguard.ContactState(
                "contact", [], [], answers=answers, approved=answers,
            )
        monkeypatch.setattr(fetch, "_contact", fake)

    def test_every_resolved_address_is_ELIGIBLE(self, tmp_path, monkeypatch):
        self._addresses(monkeypatch, {"a.com": [f"10.0.0.{i}" for i in range(30)]})
        s = _Sess(tmp_path)
        prof = type("P", (), {"apex_domains": ["a.com"]})()
        assert len(osint._rdap_addresses(prof, s)["a.com"]) == 30, "the cap must not shrink the SET"

    def test_the_bound_orders_HOST_FAIRLY(self, tmp_path, monkeypatch):
        """A flat first-N over a sorted address list let one apex's block eat the whole allowance."""
        self._addresses(monkeypatch, {"big.com": [f"10.0.0.{i}" for i in range(25)],
                                      "small.com": ["203.0.113.9"]})
        looked: list = []
        monkeypatch.setattr(osint, "_http", lambda url, timeout=25: looked.append(url) or "{}")
        s = _Sess(tmp_path)
        prof = type("P", (), {"apex_domains": ["big.com", "small.com"]})()
        osint._rdap(s, prof, lambda _m: None, 30)
        assert any("203.0.113.9" in u for u in looked), "the small apex was starved by the big one"
        assert len(looked) == 20

    def test_the_WITHHELD_remainder_is_reported_as_OUR_limit(self, tmp_path, monkeypatch):
        self._addresses(monkeypatch, {"a.com": [f"10.0.0.{i}" for i in range(25)]})
        monkeypatch.setattr(osint, "_http", lambda url, timeout=25: "{}")
        s = _Sess(tmp_path)
        osint._rdap(s, type("P", (), {"apex_domains": ["a.com"]})(), lambda _m: None, 30)
        [rec] = [r for r in s.records if r.tool == "rdap"]
        assert rec.meta["withheld"] == 5 and rec.meta["eligible"] == 25
        assert rec.meta["operator_limit"] is True, "our own bound must be OUR limit, never a gap"
        assert "RDAP_LOOKUPS" in rec.note

    def test_a_COVERED_run_claims_no_limit(self, tmp_path, monkeypatch):
        self._addresses(monkeypatch, {"a.com": ["10.0.0.1", "10.0.0.2"]})
        monkeypatch.setattr(osint, "_http", lambda url, timeout=25: "{}")
        s = _Sess(tmp_path)
        osint._rdap(s, type("P", (), {"apex_domains": ["a.com"]})(), lambda _m: None, 30)
        [rec] = [r for r in s.records if r.tool == "rdap"]
        assert rec.meta["withheld"] == 0 and "operator_limit" not in rec.meta

    def test_UNBOUND_covers_every_eligible_address(self, tmp_path, monkeypatch):
        self._addresses(monkeypatch, {"a.com": [f"10.0.0.{i}" for i in range(25)]})
        looked: list = []
        monkeypatch.setattr(osint, "_http", lambda url, timeout=25: looked.append(url) or "{}")
        s = _Sess(tmp_path)
        with settings.overrides(policy.unbound_overrides()):
            osint._rdap(s, type("P", (), {"apex_domains": ["a.com"]})(), lambda _m: None, 30)
        assert len(looked) == 25
        assert [r for r in s.records if r.tool == "rdap"][0].meta["withheld"] == 0

    def test_the_bound_is_REGISTERED_so_the_policy_prints_it(self):
        b = policy.by_name("RDAP_LOOKUPS")
        assert b and b.relaxable and b.unbounded_value == 0 and b.consumer_honours_unbounded
        from quarry_recon import sources
        assert b.lane in sources.auxiliary_sources()


class TestAzmapUnionsBothDomainLists:
    def _run(self, tmp_path, monkeypatch, payload):
        monkeypatch.setattr(osint, "_http", lambda url, timeout=25: json.dumps(payload))
        s = _Sess(tmp_path)
        osint._azmap(s, "acme.com", lambda _m: None, 30)
        return {c["value"]: c["reason"] for c in s.cands}

    def test_email_domains_are_NOT_dropped_when_related_exist(self, tmp_path, monkeypatch):
        """`related or email` short-circuited: every tenant with related domains silently lost its
        e-mail domains, which TBHM treats as additional evidence rather than as a fallback."""
        got = self._run(tmp_path, monkeypatch,
                        {"related_domains": ["r.com"], "email_domains": ["e.com"]})
        assert set(got) == {"r.com", "e.com"}
        assert "e-mail" in got["e.com"] and "e-mail" not in got["r.com"], "the two reasons must differ"

    def test_either_list_alone_still_works(self, tmp_path, monkeypatch):
        assert set(self._run(tmp_path, monkeypatch, {"email_domains": ["e.com"]})) == {"e.com"}
        assert set(self._run(tmp_path, monkeypatch, {"related_domains": ["r.com"]})) == {"r.com"}

    def test_a_domain_in_BOTH_lists_keeps_both_relationships(self, tmp_path, monkeypatch):
        """`candidate()` merges by (type, value) and keeps the first reason at equal rank, so one source
        id for both lists meant the e-mail relationship silently vanished for any domain in both."""
        monkeypatch.setattr(osint, "_http", lambda url, timeout=25: json.dumps(
            {"related_domains": ["both.com"], "email_domains": ["both.com"]}))
        s = _Sess(tmp_path)
        osint._azmap(s, "acme.com", lambda _m: None, 30)
        assert {c["source"] for c in s.cands} == {"azmap-tenant", "azmap-tenant-email"}
        assert any("e-mail" in c["reason"] for c in s.cands)

    def test_both_azmap_ids_carry_their_RELIABILITY(self):
        """A new source id that nobody weighted scores as an unknown, which silently downgrades the
        confidence of every candidate it touches."""
        assert osint._RELIABLE["azmap-tenant-email"] == osint._RELIABLE["azmap-tenant"] == 2

    def test_the_apex_itself_is_never_a_candidate(self, tmp_path, monkeypatch):
        got = self._run(tmp_path, monkeypatch,
                        {"related_domains": ["acme.com"], "email_domains": ["acme.com", "e.com"]})
        assert set(got) == {"e.com"}


class TestPorchPirateMinesWhatItDocuments:
    """MEASURED against the real tool (v1.x): `--globals` prints coloured `- Author: / - Key: / - Value:`
    triples and `--raw` does not apply to that path, so the contract is the text, not JSON."""

    SAMPLE = ("\x1b[1m\x1b[32m[+]\x1b[0m Found 7 unique workspaces. Checking globals...\x1b[0m\n"
              "\x1b[1m- Author: \x1b[0m\x1b[36mPostman Intergalactic\x1b[0m\n"
              "\x1b[1m- Key: \x1b[0m\x1b[33mapiKey\x1b[0m\n"
              "\x1b[1m- Value: \x1b[0m\x1b[32msk_live_deadbeef\x1b[0m\n"
              "\x1b[1m- Key: \x1b[0m\x1b[33mfilmList\x1b[0m\n"
              "\x1b[1m- Value: \x1b[0m\x1b[32m\x1b[0m\n")

    def test_a_workspace_SECRET_is_ingested_VERBATIM(self):
        rows = osint._porch_globals(self.SAMPLE)
        assert {"author": "Postman Intergalactic", "key": "apiKey",
                "value": "sk_live_deadbeef"} in rows, "a masked or truncated secret is not evidence"

    def test_a_global_with_an_EMPTY_value_is_still_recorded(self):
        rows = osint._porch_globals(self.SAMPLE)
        assert {"author": "Postman Intergalactic", "key": "filmList", "value": ""} in rows

    def test_noise_lines_are_not_variables(self):
        assert osint._porch_globals("[+] Query returned 623343 search results.\n- Author: X\n") == []

    def test_a_VALUE_without_its_key_is_not_invented(self):
        assert osint._porch_globals("- Author: X\n- Value: orphan\n") == []

    def test_both_VIEWS_run_and_are_recorded(self, tmp_path, monkeypatch):
        calls: list = []

        def fake_exec(tool, cmd, raw_path=None, timeout=None, **kw):
            calls.append(cmd)
            if raw_path is None and kw["stdout"].disposition is ArtifactDisposition.PUBLISH:
                raw_path = kw["repository"].dir.joinpath(*kw["stdout"].components)
            raw_path.write_text(self.SAMPLE if "--globals" in cmd else "https://api.acme.com/v1/x\n")
            return type("R", (), {"tool": tool, "raw_path": raw_path, "status": "success"})()

        monkeypatch.setattr(osint, "exec_tool", fake_exec)
        s = _Sess(tmp_path)
        osint._porch_pirate(s, "acme.com", lambda _m: None, 30)
        assert [c[-1] for c in calls] == ["--urls", "--globals"]
        assert len(s.records) == 2, "each view is its own recorded run"
        kinds = {r["kind"] for r in s.intel_rows}
        assert kinds == {"postman-endpoint", "postman-global"}
        [secret] = [r for r in s.intel_rows if r.get("key") == "apiKey"]
        assert secret["value"] == "apiKey=sk_live_deadbeef"
        assert secret["workspace_author"] == "Postman Intergalactic", \
            "a secret whose workspace was parsed and then dropped cannot be gone back to"

    def test_the_same_KEY_in_two_workspaces_stays_distinguishable(self, tmp_path, monkeypatch):
        two = ("- Author: alpha corp\n- Key: apiKey\n- Value: aaa\n"
               "- Author: beta ltd\n- Key: apiKey\n- Value: bbb\n")

        def fake_exec(tool, cmd, raw_path=None, timeout=None, **kw):
            if raw_path is None and kw["stdout"].disposition is ArtifactDisposition.PUBLISH:
                raw_path = kw["repository"].dir.joinpath(*kw["stdout"].components)
            raw_path.write_text(two if "--globals" in cmd else "")
            return type("R", (), {"tool": tool, "raw_path": raw_path, "status": "success"})()

        monkeypatch.setattr(osint, "exec_tool", fake_exec)
        s = _Sess(tmp_path)
        osint._porch_pirate(s, "acme.com", lambda _m: None, 30)
        rows = [r for r in s.intel_rows if r["kind"] == "postman-global"]
        assert {r["workspace_author"] for r in rows} == {"alpha corp", "beta ltd"}
        assert {r["value"] for r in rows} == {"apiKey=aaa", "apiKey=bbb"}


class TestOneNotificationPerRun:
    @staticmethod
    def _summary(**kw):
        base = {"verdict": "complete", "failures": [], "gaps": [], "phase_exceptions": [],
                "provider_limits": [], "operator_limits": []}
        base.update(kw)
        return base

    def test_complete_and_lead_send_ONE_message(self, monkeypatch):
        sent: list = []
        monkeypatch.setattr(notify, "enabled_events", lambda: {"complete", "lead"})
        monkeypatch.setattr(notify, "send", lambda ev, title, body="": sent.append((ev, title, body)) or 1)
        notify.send_completion(target="acme.com", run_id="r1", summary=self._summary(), leads=11)
        assert len(sent) == 1, "two messages with the same body read as a loop"
        assert sent[0][0] == "complete", "the run's own event carries it when both are subscribed"
        assert "11 promising lead(s)" in sent[0][1]

    def test_subscribing_only_to_LEADS_still_gets_the_run(self, monkeypatch):
        sent: list = []
        monkeypatch.setattr(notify, "enabled_events", lambda: {"lead"})
        monkeypatch.setattr(notify, "send", lambda ev, title, body="": sent.append(ev) or 1)
        notify.send_completion(target="acme.com", run_id="r1", summary=self._summary(), leads=3)
        assert sent == ["lead"]

    def test_leads_only_stays_QUIET_when_there_are_none(self, monkeypatch):
        monkeypatch.setattr(notify, "enabled_events", lambda: {"lead"})
        monkeypatch.setattr(notify, "send", lambda *a, **k: pytest.fail("should not send"))
        assert notify.send_completion(target="a", run_id="r", summary=self._summary(), leads=0) == 0

    @pytest.mark.parametrize("verdict,word", [
        ("complete", "run completed"),
        ("complete_with_limits", "expected limits"),
        ("complete_with_gaps", "coverage needs attention")])
    def test_the_INTERNAL_verdict_token_never_reaches_the_operator(self, verdict, word):
        title, body = notify.completion_message(target="acme.com", run_id="r1",
                                                summary=self._summary(verdict=verdict))
        # "complete" alone is a word an operator understands; `complete_with_gaps` is OUR vocabulary
        assert word in title
        assert "_with_" not in (title + body), (title, body)

    def test_GAPS_and_LIMITS_are_separate_sections(self):
        _t, body = notify.completion_message(
            target="a", run_id="r", summary=self._summary(
                verdict="complete_with_gaps", failures=[{"tool": "dalfox"}],
                gaps=[{"tool": "nuclei"}], phase_exceptions=["boom"],
                provider_limits=[{"tool": "probe.shodan_host", "why": "query credits exhausted"}],
                operator_limits=[{"tool": "rdap", "why": "5 withheld"}]))
        attention = body.split("Needs attention:")[1].split("Expected limits:")[0]
        limits = body.split("Expected limits:")[1]
        assert "dalfox" in attention and "nuclei" in attention and "phase exception" in attention
        assert "shodan" in limits and "credits" in limits
        assert "our bound" in limits, "an operator budget must not read as the provider refusing us"
        assert "shodan" not in attention, "an expected boundary is not something that went wrong"

    def test_a_long_list_POINTS_at_the_evidence(self):
        _t, body = notify.completion_message(
            target="a", run_id="r",
            summary=self._summary(provider_limits=[{"tool": f"t{i}", "why": "quota"} for i in range(9)]))
        assert body.count("•") == notify._MAX_BULLETS
        assert "+4 more in manifest.json" in body

    def test_a_CLEAN_run_says_only_what_happened(self):
        title, body = notify.completion_message(target="a", run_id="r1",
                                                summary=self._summary(), totals="live=3")
        assert title.endswith("run completed") and "Needs attention" not in body
        assert "Expected limits" not in body and "live=3" in body


class TestTheREALSessionKeepsProvenance:
    """The fake session above proves the LANE passes provenance; this proves the session STORES it. A
    test that only ever exercises its own stand-in cannot see the real one throwing the field away."""

    def _session(self, tmp_path):
        return osint.OsintSession(tmp_path, "acme.com")

    def test_intel_provenance_reaches_the_ROW(self, tmp_path):
        s = self._session(tmp_path)
        s.intel("postman-global", "apiKey=abc", "porch-pirate",
                workspace_author="alpha corp", key="apiKey")
        [row] = s._intel
        assert row["workspace_author"] == "alpha corp" and row["key"] == "apiKey"
        assert row["value"] == "apiKey=abc" and row["sources"] == ["porch-pirate"]

    def test_an_EMPTY_provenance_field_is_not_stored_as_noise(self, tmp_path):
        s = self._session(tmp_path)
        s.intel("postman-global", "k=", "porch-pirate", workspace_author="", key="k")
        assert "workspace_author" not in s._intel[0]

    def test_a_lane_that_passes_NOTHING_still_works(self, tmp_path):
        s = self._session(tmp_path)
        s.intel("postman-endpoint", "https://a/b", "porch-pirate")
        assert s._intel == [{"kind": "postman-endpoint", "value": "https://a/b",
                             "sources": ["porch-pirate"]}]


class TestThePreflightBoundIsReachable:
    """A bound whose only relaxation lives on a DIFFERENT command is a bound no operator can lift.
    `--unbound` was on `quarry run`, which never calls these lanes, so the withheld remainder named an
    action that did not exist."""

    @staticmethod
    def _invoke(argv, monkeypatch):
        from click.testing import CliRunner
        from quarry_recon import cli as cli_mod
        from quarry_recon import osint as osint_mod
        seen: dict = {}

        def fake_run(profile, scope, project, echo=print, timeout=1800):
            seen["cap"] = policy.limit("RDAP_LOOKUPS")
            (project / "osint").mkdir(parents=True, exist_ok=True)
            (project / "osint" / "osint-report.md").write_text("x")
            # the real lane closes the session with a manifest; without one the verdict is `unknown`
            (project / "osint" / "manifest.json").write_text(
                json.dumps({"summary": {"verdict": "complete"}}))
            return project / "osint" / "osint-report.md"

        monkeypatch.setattr(osint_mod, "run", fake_run)
        monkeypatch.setattr(cli_mod, "_resolve_profile", lambda v: v)
        monkeypatch.setattr(cli_mod.TargetProfile, "load", staticmethod(
            lambda _v: type("P", (), {"target": "acme.com", "apex_domains": [], "asn": [],
                                      "org_names": [], "brands": [], "scope": lambda self: None})()))
        res = CliRunner().invoke(cli_mod.cli, argv)
        return res, seen

    def test_quarry_osint_UNBOUND_lifts_the_rdap_bound(self, tmp_path, monkeypatch):
        from quarry_recon import cli as cli_mod
        monkeypatch.setattr(cli_mod, "_project_dir", lambda _p: tmp_path)
        res, seen = self._invoke(["osint", "-t", "acme", "--unbound"], monkeypatch)
        assert res.exit_code == 0, res.output
        assert seen["cap"] == 0, "the flag did not reach the lane that reads the bound"

    def test_a_plain_preflight_keeps_its_default(self, tmp_path, monkeypatch):
        from quarry_recon import cli as cli_mod
        monkeypatch.setattr(cli_mod, "_project_dir", lambda _p: tmp_path)
        res, seen = self._invoke(["osint", "-t", "acme"], monkeypatch)
        assert res.exit_code == 0 and seen["cap"] == osint.RDAP_LOOKUPS

    def test_the_override_does_not_LEAK_to_the_next_command(self, tmp_path, monkeypatch):
        from quarry_recon import cli as cli_mod
        monkeypatch.setattr(cli_mod, "_project_dir", lambda _p: tmp_path)
        self._invoke(["osint", "-t", "acme", "--unbound"], monkeypatch)
        assert policy.limit("RDAP_LOOKUPS") == osint.RDAP_LOOKUPS

    def test_the_withheld_message_names_a_command_that_EXISTS(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            fetch, "_contact",
            lambda *_a, **_k: netguard.ContactState(
                "contact", [], [], answers=tuple(f"10.0.0.{i}" for i in range(25)),
                approved=tuple(f"10.0.0.{i}" for i in range(25)),
            ),
        )
        monkeypatch.setattr(osint, "_http", lambda url, timeout=25: "{}")
        s = _Sess(tmp_path)
        osint._rdap(s, type("P", (), {"apex_domains": ["a.com"]})(), lambda _m: None, 30)
        note = [r for r in s.records if r.tool == "rdap"][0].note
        assert "quarry osint --unbound" in note


class TestASRankDiscoversASNs:
    """The preflight CLAIMED ASN discovery and only expanded ASNs the operator already had, so a target
    whose ASNs nobody knew stayed invisible.

    Shapes are MEASURED against the live API (2026-08-03): `organizations(name:, first:, offset:)` →
    `totalCount` + `edges[].node{orgId, orgName, rank, country{iso}, members{numberAsns, asns{edges[]}}}`.
    The RESTful endpoint ignores an `asn=` filter and returns the global list, which is why this is
    GraphQL.
    """

    @staticmethod
    def _org(name="Deutsche Telekom AG", *, org_id="4dab", rank=17, iso="DE", asns=(("3320", "DTAG"),),
             declared=None):
        return {"orgId": org_id, "orgName": name, "rank": rank, "country": {"iso": iso},
                "members": {"numberAsns": declared if declared is not None else len(asns),
                            "asns": {"edges": [{"node": {"asn": a, "asnName": n}} for a, n in asns]}}}

    def _api(self, monkeypatch, pages):
        """`pages` is a list of `data` objects returned in order. Once they run out the provider is
        EXHAUSTED — an empty page, the way a real one behaves — rather than repeating its last answer,
        which would hide a paging bug behind an infinite supply of results."""
        calls: list = []

        def fake(url, payload, timeout=25):
            calls.append(payload["query"])
            if len(calls) <= len(pages):
                return pages[len(calls) - 1]
            last = pages[-1].get("organizations") or {}
            return {"organizations": {"totalCount": last.get("totalCount", 0), "edges": []}}
        monkeypatch.setattr(osint, "_http_post_json", fake)
        return calls

    def _run(self, tmp_path, monkeypatch, pages, orgs=("Deutsche Telekom",)):
        calls = self._api(monkeypatch, pages)
        s = _Sess(tmp_path)
        prof = type("P", (), {"org_names": list(orgs)})()
        osint._asrank(s, prof, lambda _m: None, 30)
        return s, calls

    def test_a_member_ASN_becomes_a_review_candidate(self, tmp_path, monkeypatch):
        s, _ = self._run(tmp_path, monkeypatch,
                         [{"organizations": {"totalCount": 1, "edges": [{"node": self._org()}]}}])
        [asn] = [c for c in s.cands if c["type"] == "asn"]
        assert asn["value"] == "AS3320", "ASNs are written the way target.yaml wants them"
        assert "DTAG" in asn["reason"] and "ASRank" in asn["reason"]
        assert "bgp.he.net" in asn["followup"], "an ASN in the profile authorises active range scanning"
        # the ARTIFACT, not just a path to one: a candidate whose evidence was never written cannot be
        # reviewed, and a raw_ref pointing at nothing is worse than none at all
        art = pathlib.Path(asn["raw_ref"])
        assert art.is_file(), "the provider's response was not retained"
        node = json.loads(art.read_text())["organizations"]["edges"][0]["node"]
        assert node["orgName"] == "Deutsche Telekom AG" and node["members"]["asns"]["edges"]
        [org] = [c for c in s.cands if c["type"] == "org"]
        assert "ASRank" in org["reason"] and "rank 17" in org["reason"] and "DE" in org["reason"]

    def test_nothing_it_finds_is_ever_IN_SCOPE(self, tmp_path, monkeypatch):
        """The org search is FUZZY. An ASN in the profile authorises active range scanning, so a name
        match may never carry more than `verify-ownership`."""
        s, _ = self._run(tmp_path, monkeypatch,
                         [{"organizations": {"totalCount": 1, "edges": [{"node": self._org()}]}}])
        assert s.cands and {c["hint"] for c in s.cands} == {"verify-ownership"}
        assert all("fuzzy" in c["followup"] or "bgp.he.net" in c["followup"] for c in s.cands)

    def test_OUR_bound_and_THEIR_shortfall_are_different_facts(self, tmp_path, monkeypatch):
        """42 matches, our cap admits 10, the provider sends 1. Blaming our cap for the 9 it never sent
        tells an operator that raising the bound would recover work that is simply not there."""
        s, calls = self._run(tmp_path, monkeypatch,
                             [{"organizations": {"totalCount": 42, "edges": [{"node": self._org()}]}}])
        [rec] = [r for r in s.records if r.tool == "asrank"]
        assert rec.meta["withheld_orgs"] == 32, "ours is what the cap refused of the 42"
        assert rec.meta["provider_short_orgs"] == 9, "theirs is what they admitted and did not send"
        assert rec.meta["operator_limit"] is True and rec.status is osint.Status.PARTIAL
        assert "quarry osint --unbound" in rec.note and "did not return" in rec.note
        assert any("fewer organisation" in f["why"] for f in s.failures), "a shortfall is a GAP"
        assert len(calls) >= 2, "bounded mode stopped after one page without reaching its allowance"

    def test_a_bound_that_is_FULLY_served_claims_no_shortfall(self, tmp_path, monkeypatch):
        s, _ = self._run(tmp_path, monkeypatch, [{"organizations": {
            "totalCount": 12, "edges": [{"node": self._org(f"O{i}", org_id=f"o{i}")} for i in range(10)]}}])
        [rec] = [r for r in s.records if r.tool == "asrank"]
        assert (rec.meta["withheld_orgs"], rec.meta["provider_short_orgs"]) == (2, 0)
        assert rec.status is osint.Status.SUCCESS and not s.failures

    def test_UNBOUND_pages_through_every_match(self, tmp_path, monkeypatch):
        two = {"organizations": {"totalCount": 2, "edges": [{"node": self._org("A", org_id="a")}]}}
        three = {"organizations": {"totalCount": 2, "edges": [{"node": self._org("B", org_id="b")}]}}
        calls = self._api(monkeypatch, [two, three])
        s = _Sess(tmp_path)
        with settings.overrides(policy.unbound_overrides()):
            osint._asrank(s, type("P", (), {"org_names": ["x"]})(), lambda _m: None, 30)
        assert len(calls) == 2, "a second page was never requested"
        assert {c["value"] for c in s.cands if c["type"] == "org"} == {"A", "B"}
        assert [r for r in s.records if r.tool == "asrank"][0].meta["withheld_orgs"] == 0

    def test_an_orgs_FULL_membership_is_re_queried_not_truncated(self, tmp_path, monkeypatch):
        """`numberAsns` is the org's own count: a short page is a request-size shortfall we can fix, never
        a membership decision."""
        first = {"organizations": {"totalCount": 1, "edges": [
            {"node": self._org(asns=(("1", "a"),), declared=3)}]}}
        follow = {"organization": {"orgName": "x", "members": {"numberAsns": 3, "asns": {"edges": [
            {"node": {"asn": "1", "asnName": "a"}}, {"node": {"asn": "2", "asnName": "b"}},
            {"node": {"asn": "3", "asnName": "c"}}]}}}}
        s, calls = self._run(tmp_path, monkeypatch, [first, follow])
        assert len(calls) == 2 and "organization(orgId" in calls[1]
        assert {c["value"] for c in s.cands if c["type"] == "asn"} == {"AS1", "AS2", "AS3"}

    def test_an_INCOMPLETE_membership_is_stated_not_swallowed(self, tmp_path, monkeypatch):
        first = {"organizations": {"totalCount": 1, "edges": [
            {"node": self._org(asns=(("1", "a"),), declared=9)}]}}
        follow = {"organization": {"members": {"numberAsns": 9, "asns": {"edges": [
            {"node": {"asn": "1", "asnName": "a"}}]}}}}
        s, _ = self._run(tmp_path, monkeypatch, [first, follow])
        [rec] = [r for r in s.records if r.tool == "asrank"]
        assert rec.meta["incomplete_members"] and rec.status is osint.Status.PARTIAL

    def test_a_GRAPHQL_error_is_a_failure_not_an_empty_result(self, tmp_path, monkeypatch):
        def boom(url, payload, timeout=25):
            raise ValueError("Cannot query field \"asnCount\"")
        monkeypatch.setattr(osint, "_http_post_json", boom)
        s = _Sess(tmp_path)
        osint._asrank(s, type("P", (), {"org_names": ["x"]})(), lambda _m: None, 30)
        assert s.failures and "asnCount" in s.failures[0]["why"]
        assert [r for r in s.records if r.tool == "asrank"][0].status is osint.Status.FAILED

    def test_the_POST_helper_RAISES_on_a_graphql_error(self, monkeypatch):
        """A query the server rejected is a lane failure; reading it as "no matches" reports a clean zero
        over something nobody asked."""
        from quarry_recon import fetch
        monkeypatch.setattr(fetch, "scoped_public_provider_get", lambda *_a, **_k: (
            json.dumps({"errors": [{"message": "boom"}], "data": None}).encode(), "https://x", 200,
        ))
        session = type("S", (), {"_http_context": object()})()
        with pytest.raises(ValueError, match="boom"):
            osint._provider_post_json(session, "https://x", {"query": "{}"},
                                      source_id="osint.asrank", timeout=25)

    def test_NO_org_anchor_is_a_recorded_skip_not_silence(self, tmp_path, monkeypatch):
        s = _Sess(tmp_path)
        osint._asrank(s, type("P", (), {"org_names": []})(), lambda _m: None, 30)
        assert [r for r in s.records][0].tool == "asrank" and not s.cands

    def test_a_non_numeric_ASN_is_not_invented(self, tmp_path, monkeypatch):
        s, _ = self._run(tmp_path, monkeypatch, [{"organizations": {"totalCount": 1, "edges": [
            {"node": self._org(asns=(("not-a-number", "x"), ("64512", "ok")))}]}}])
        assert {c["value"] for c in s.cands if c["type"] == "asn"} == {"AS64512"}

    def test_the_bound_is_REGISTERED(self):
        b = policy.by_name("ASRANK_ORGS")
        assert b and b.relaxable and b.unbounded_value == 0 and b.consumer_honours_unbounded
        from quarry_recon import sources
        assert b.lane in sources.auxiliary_sources()

    def test_the_FOLLOW_UP_evidence_is_retained_with_its_asns(self, tmp_path, monkeypatch):
        """The ASNs only the full-membership query returned cannot cite a page written before it ran —
        and those are exactly the biggest organisations."""
        first = {"organizations": {"totalCount": 1, "edges": [
            {"node": self._org(asns=(("1", "a"),), declared=3)}]}}
        follow = {"organization": {"orgName": "x", "members": {"numberAsns": 3, "asns": {"edges": [
            {"node": {"asn": "1", "asnName": "a"}}, {"node": {"asn": "2", "asnName": "b"}},
            {"node": {"asn": "3", "asnName": "c"}}]}}}}
        s, _ = self._run(tmp_path, monkeypatch, [first, follow])
        for c in [c for c in s.cands if c["type"] == "asn"]:
            art = json.loads(pathlib.Path(c["raw_ref"]).read_text())
            got = {e["node"]["asn"] for e in art["organization"]["members"]["asns"]["edges"]}
            assert c["value"][2:] in got, f"{c['value']} cites a file it is not in"

    def test_each_response_is_its_OWN_immutable_artifact(self, tmp_path, monkeypatch):
        first = {"organizations": {"totalCount": 1, "edges": [
            {"node": self._org(asns=(("1", "a"),), declared=2)}]}}
        follow = {"organization": {"members": {"numberAsns": 2, "asns": {"edges": [
            {"node": {"asn": "1", "asnName": "a"}}, {"node": {"asn": "2", "asnName": "b"}}]}}}}
        s, _ = self._run(tmp_path, monkeypatch, [first, follow])
        files = sorted(pathlib.Path(tmp_path / "raw" / "asrank").glob("*.json"))
        assert len(files) == 2, [f.name for f in files]
        assert any("orgs-" in f.name for f in files) and any("members-" in f.name for f in files)
        org_ref = [c for c in s.cands if c["type"] == "org"][0]["raw_ref"]
        assert "orgs-" in org_ref, "the org still cites the page it was listed on"

    @pytest.mark.parametrize("bad", ["0", "007", "٤٢", "4294967296", 3320, True, None, "", "AS15169"])
    def test_a_malformed_ASN_is_never_published(self, tmp_path, monkeypatch, bad):
        """`str(x).isdigit()` accepted Arabic-Indic digits (which `int()` then parses), AS0, a
        non-canonical `007` — two spellings of one ASN become two candidates — and 33-bit values."""
        s, _ = self._run(tmp_path, monkeypatch, [{"organizations": {"totalCount": 1, "edges": [
            {"node": self._org(asns=((bad, "x"), ("64512", "ok")))}]}}])
        assert {c["value"] for c in s.cands if c["type"] == "asn"} == {"AS64512"}

    def test_surrounding_WHITESPACE_is_normalised_not_rejected(self, tmp_path, monkeypatch):
        """A padded string is not an ambiguous value: `" 15169"` names exactly one ASN. Only spellings
        that could mean two different things (or none) are refused."""
        s, _ = self._run(tmp_path, monkeypatch, [{"organizations": {"totalCount": 1, "edges": [
            {"node": self._org(asns=((" 15169 ", "GOOGLE"),))}]}}])
        assert {c["value"] for c in s.cands if c["type"] == "asn"} == {"AS15169"}

    @pytest.mark.parametrize("count", [True, 3.9, "7", -1, None])
    def test_an_unreadable_COUNT_is_UNKNOWN_not_complete(self, tmp_path, monkeypatch, count):
        """`int(totalCount)` turned `True` into 1 and raised on the rest — and substituting `len(nodes)`
        for the rejected value was worse: the shortfall then computes to zero precisely because nobody
        knows what the total was, so malformed provider data certified complete coverage."""
        s, _ = self._run(tmp_path, monkeypatch, [{"organizations": {
            "totalCount": count, "edges": [{"node": self._org()}]}}])
        [rec] = [r for r in s.records if r.tool == "asrank"]
        assert rec.meta["unknown_total_anchors"] == 1
        assert rec.status is osint.Status.PARTIAL, "an unknown denominator is not a clean success"
        assert "UNREADABLE match count" in rec.note
        assert any("unreadable" in f["why"] for f in s.failures), "unknown coverage is a GAP"
        assert rec.meta["withheld_orgs"] == 0 and rec.meta["provider_short_orgs"] == 0, \
            "and nothing is subtracted from a number we do not have"

    def test_an_unreadable_count_still_KEEPS_what_it_received(self, tmp_path, monkeypatch):
        """Unknown coverage is not a reason to throw away the organisations the provider did send."""
        s, _ = self._run(tmp_path, monkeypatch, [{"organizations": {
            "totalCount": None, "edges": [{"node": self._org()}]}}])
        assert {c["value"] for c in s.cands if c["type"] == "asn"} == {"AS3320"}

    def test_an_UNREADABLE_asn_row_is_counted_not_swallowed(self, tmp_path, monkeypatch):
        """One valid and one malformed ASN in the same response must not finish as SUCCESS claiming only
        the valid count: provider evidence was discarded and nothing said so."""
        s, _ = self._run(tmp_path, monkeypatch, [{"organizations": {"totalCount": 1, "edges": [
            {"node": self._org(asns=(("007", "bad"), ("64512", "ok")))}]}}])
        [rec] = [r for r in s.records if r.tool == "asrank"]
        assert rec.meta["unreadable_asn_rows"] == 1 and rec.status is osint.Status.PARTIAL
        assert "unreadable ASN row(s) discarded" in rec.note
        assert {c["value"] for c in s.cands if c["type"] == "asn"} == {"AS64512"}

    @pytest.mark.parametrize("field", [
        {"orgName": 7}, {"orgName": None}, {"country": []}, {"country": "DE"}])
    def test_a_malformed_FIELD_costs_only_that_field(self, tmp_path, monkeypatch, field):
        """A numeric `orgName` or a list-valued `country` raised OUTSIDE the query guard, so the lane
        never emitted its terminal. Typed reads make it milder than containment would: the row is still
        READABLE — its member ASNs are exactly as good — and only the unusable field goes missing."""
        node = {**self._org(asns=(("64512", "ok"),)), **field}
        s, _ = self._run(tmp_path, monkeypatch,
                         [{"organizations": {"totalCount": 1, "edges": [{"node": node}]}}])
        [rec] = [r for r in s.records if r.tool == "asrank"]
        assert rec.meta["unreadable_org_rows"] == 0, "a bad field is not an unreadable ROW"
        assert {c["value"] for c in s.cands if c["type"] == "asn"} == {"AS64512"}, \
            "the org's ASNs are unaffected by its own unreadable name"
        # ...and the loss is STATED: a field we discarded may not pass as a clean success
        want = {"orgName": str, "country": dict}
        wrong_typed = any(v is not None and not isinstance(v, want[k]) for k, v in field.items())
        if wrong_typed:
            assert rec.meta["unreadable_fields"] == 1, field
            assert rec.status is osint.Status.PARTIAL
            assert "unreadable field(s)" in rec.note
            assert any("unreadable" in f["why"] for f in s.failures)
        else:
            assert rec.meta["unreadable_fields"] == 0, "an ABSENT field is an answer, not a loss"

    @pytest.mark.parametrize("country,expected", [
        ({"iso": 7}, 1),                 # container fine, the EVIDENCE-BEARING leaf is not
        ({"iso": None}, 0),              # absent leaf is an answer
        ({}, 0),                         # ...as is an absent key
        ([], 1),                         # container unreadable: counted ONCE, leaf is unreachable
        ({"iso": "DE"}, 0)])
    def test_the_nested_ISO_is_accounted_like_every_other_field(self, tmp_path, monkeypatch,
                                                                country, expected):
        """Checking that `country` is a dict says nothing about the field inside it that carries the
        evidence."""
        s, _ = self._run(tmp_path, monkeypatch, [{"organizations": {"totalCount": 1, "edges": [
            {"node": {**self._org(), "country": country}}]}}])
        [rec] = [r for r in s.records if r.tool == "asrank"]
        assert rec.meta["unreadable_fields"] == expected, (country, rec.note)
        assert rec.status is (osint.Status.PARTIAL if expected else osint.Status.SUCCESS)
        assert {c["value"] for c in s.cands if c["type"] == "asn"} == {"AS3320"}

    def test_an_unreadable_asnName_is_not_RENDERED_into_the_reason(self, tmp_path, monkeypatch):
        """`x or 'unnamed'` let a non-string through into the f-string, so a reason could quote a value
        nobody could read as if it were a name."""
        s, _ = self._run(tmp_path, monkeypatch, [{"organizations": {"totalCount": 1, "edges": [
            {"node": self._org(asns=(("64512", {"nope": 1}),))}]}}])
        [asn] = [c for c in s.cands if c["type"] == "asn"]
        assert "(unnamed)" in asn["reason"] and "nope" not in asn["reason"]

    def test_an_absent_field_is_not_a_LOSS(self, tmp_path, monkeypatch):
        """A field the provider did not send is an answer; only a shape we could not read is discarded
        evidence. Counting both would teach an operator to ignore the counter."""
        node = {k: v for k, v in self._org().items() if k != "country"}
        s, _ = self._run(tmp_path, monkeypatch,
                         [{"organizations": {"totalCount": 1, "edges": [{"node": node}]}}])
        [rec] = [r for r in s.records if r.tool == "asrank"]
        assert rec.meta["unreadable_fields"] == 0 and rec.status is osint.Status.SUCCESS

    @pytest.mark.parametrize("node", [
        {"orgName": "x", "members": []}, {"orgName": "x", "members": {"asns": "nope"}},
        {"orgName": "x", "members": {"numberAsns": 0, "asns": []}},
        {"orgName": None, "country": None, "members": None}])
    def test_a_malformed_NODE_never_costs_the_lane_its_terminal(self, tmp_path, monkeypatch, node):
        """A members block of the wrong SHAPE is an org with no readable ASNs — not an exception, and not
        a reason to lose the row beside it or the lane's own account of itself."""
        s, _ = self._run(tmp_path, monkeypatch, [{"organizations": {"totalCount": 2, "edges": [
            {"node": node}, {"node": self._org()}]}}])
        [rec] = [r for r in s.records if r.tool == "asrank"]
        assert rec.meta["unreadable_org_rows"] == 0, "a shape we can read as empty is not an ERROR row"
        assert {c["value"] for c in s.cands if c["type"] == "asn"} == {"AS3320"}, \
            "the readable row beside it must still be published"

    def test_an_unreadable_org_row_is_COUNTED_and_partial(self, tmp_path, monkeypatch):
        """The typed accessors mean JSON data no longer raises here, so this drives the BACKSTOP itself:
        whatever goes wrong on one row, the lane keeps the others and still reports what it did."""
        real = osint._asrank_asns

        def hostile(session, node, timeout, save):
            if node.get("orgId") == "boom":
                raise TypeError("hostile row")
            return real(session, node, timeout, save)

        monkeypatch.setattr(osint, "_asrank_asns", hostile)
        s, _ = self._run(tmp_path, monkeypatch, [{"organizations": {"totalCount": 2, "edges": [
            {"node": self._org("bad", org_id="boom")}, {"node": self._org()}]}}])
        [rec] = [r for r in s.records if r.tool == "asrank"]
        assert rec.meta["unreadable_org_rows"] == 1 and rec.status is osint.Status.PARTIAL
        assert "unreadable organisation row(s) discarded" in rec.note
        assert any("unreadable organisation row" in f["why"] for f in s.failures)
        assert {c["value"] for c in s.cands if c["type"] == "asn"} == {"AS3320"}, \
            "one bad row may not cost the readable ones"

    def test_two_anchors_cannot_OVERWRITE_each_others_artifacts(self, tmp_path, monkeypatch):
        """`a/b` and `a?b` sanitise to the same slug, and a per-anchor counter restarted at 1 — so the
        second anchor's first response landed on the file the first anchor's candidates already cite."""
        calls: list = []

        def fake(url, payload, timeout=25):
            calls.append(payload["query"])
            who = "first" if len(calls) == 1 else "second"
            return {"organizations": {"totalCount": 1, "edges": [
                {"node": self._org(f"org-{who}", org_id=who)}]}}
        monkeypatch.setattr(osint, "_http_post_json", fake)
        s = _Sess(tmp_path)
        osint._asrank(s, type("P", (), {"org_names": ["a/b", "a?b"]})(), lambda _m: None, 30)
        refs = {c["raw_ref"] for c in s.cands}
        assert len(refs) == 2, "both anchors wrote to the same artifact"
        for c in [c for c in s.cands if c["type"] == "org"]:
            art = json.loads(pathlib.Path(c["raw_ref"]).read_text())
            assert art["organizations"]["edges"][0]["node"]["orgName"] == c["value"]

    def test_the_SAME_anchor_twice_does_not_overwrite_itself(self, tmp_path, monkeypatch):
        """An operator can list one org twice. Same slug, same digest — only a RUN-WIDE sequence keeps the
        second pass from landing on the first pass's files."""
        calls: list = []

        def fake(url, payload, timeout=25):
            calls.append(1)
            return {"organizations": {"totalCount": 1, "edges": [
                {"node": self._org(f"pass{len(calls)}", org_id=f"p{len(calls)}")}]}}
        monkeypatch.setattr(osint, "_http_post_json", fake)
        s = _Sess(tmp_path)
        osint._asrank(s, type("P", (), {"org_names": ["Acme", "Acme"]})(), lambda _m: None, 30)
        assert len({c["raw_ref"] for c in s.cands}) == 2
        for c in [c for c in s.cands if c["type"] == "org"]:
            art = json.loads(pathlib.Path(c["raw_ref"]).read_text())
            assert art["organizations"]["edges"][0]["node"]["orgName"] == c["value"]

    def test_the_artifact_name_IDENTIFIES_its_anchor(self, tmp_path, monkeypatch):
        """Two anchors that sanitise to one slug must not be distinguishable only by a counter — the name
        has to say WHICH anchor produced it, or an artifact directory cannot be read by a human."""
        monkeypatch.setattr(osint, "_http_post_json", lambda url, payload, timeout=25: {
            "organizations": {"totalCount": 1, "edges": [{"node": self._org()}]}})
        s = _Sess(tmp_path)
        osint._asrank(s, type("P", (), {"org_names": ["a/b", "a?b"]})(), lambda _m: None, 30)
        anchors = {pathlib.Path(c["raw_ref"]).name.split(".")[0] for c in s.cands}
        assert len(anchors) == 2, f"both anchors share the name prefix {anchors}"

    def test_a_long_anchor_name_stays_DISTINCT(self, tmp_path, monkeypatch):
        long_a, long_b = "x" * 80 + "alpha", "x" * 80 + "beta"
        calls: list = []

        def fake(url, payload, timeout=25):
            calls.append(1)
            return {"organizations": {"totalCount": 1, "edges": [
                {"node": self._org(f"o{len(calls)}", org_id=f"o{len(calls)}")}]}}
        monkeypatch.setattr(osint, "_http_post_json", fake)
        s = _Sess(tmp_path)
        osint._asrank(s, type("P", (), {"org_names": [long_a, long_b]})(), lambda _m: None, 30)
        assert len({c["raw_ref"] for c in s.cands}) == 2

    def test_an_unreadable_MEMBER_count_is_stated(self, tmp_path, monkeypatch):
        s, _ = self._run(tmp_path, monkeypatch, [{"organizations": {"totalCount": 1, "edges": [
            {"node": self._org(asns=(("1", "a"),), declared="many")}]}}])
        [rec] = [r for r in s.records if r.tool == "asrank"]
        assert any("unreadable member count" in x for x in rec.meta["incomplete_members"])
        assert rec.status is osint.Status.PARTIAL

    def test_paging_cannot_SPIN_forever(self, tmp_path, monkeypatch):
        """A provider that keeps answering with a page but never reaches its own total must not hold the
        preflight open indefinitely."""
        calls: list = []

        def fake(url, payload, timeout=25):
            calls.append(1)
            return {"organizations": {"totalCount": 10 ** 6,
                                      "edges": [{"node": self._org(org_id=f"o{len(calls)}")}]}}
        monkeypatch.setattr(osint, "_http_post_json", fake)
        s = _Sess(tmp_path)
        with settings.overrides(policy.unbound_overrides()):
            osint._asrank(s, type("P", (), {"org_names": ["x"]})(), lambda _m: None, 30)
        assert len(calls) <= 40
