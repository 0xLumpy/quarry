"""The four OSINT/preflight debts, and the notification they are reported through.

Each was a SILENT loss: a membership cap with no remainder, an `or` that dropped half its evidence, a
documented output nobody collected, and two notifications carrying the same body with Quarry's internal
vocabulary in it. What is pinned here is that nothing is dropped without saying so.
"""
from __future__ import annotations

import json

import pytest

from quarry_recon import notify, osint, policy, settings


class _Sess:
    """The parts of `OsintSession` these lanes touch."""

    def __init__(self, tmp_path):
        self.dir = tmp_path
        self.cands: list = []
        self.intel_rows: list = []
        self.records: list = []
        self.failures: list = []

    def raw_path(self, source, name):
        p = self.dir / source
        p.mkdir(parents=True, exist_ok=True)
        return p / name

    def candidate(self, value, ctype, source, hint, reason, raw_ref=None, manual_followup=None):
        self.cands.append({"value": value, "type": ctype, "source": source, "reason": reason})

    def intel(self, kind, value, source, **provenance):
        self.intel_rows.append({"kind": kind, "value": value, "source": source, **provenance})

    def record(self, result):
        self.records.append(result)

    def note_failure(self, tool, why):
        self.failures.append({"tool": tool, "why": why})


class TestTheRDAPLaneBoundsTHROUGHPUTNotMembership:
    @staticmethod
    def _addresses(monkeypatch, mapping):
        import socket

        def fake(host, _port, family, *a, **k):
            out = []
            for ip in mapping.get(host, []):
                v6 = ":" in ip
                if (family == socket.AF_INET6) == v6:
                    out.append((family, None, None, "", (ip, 0)))
            if not out:
                raise OSError("no address")
            return out
        monkeypatch.setattr(socket, "getaddrinfo", fake)

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
        assert b.lane in policy.BOUND_LANES_OUTSIDE_REGISTRY


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
        import socket
        monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **k:
                            [(None, None, None, "", (f"10.0.0.{i}", 0)) for i in range(25)])
        monkeypatch.setattr(osint, "_http", lambda url, timeout=25: "{}")
        s = _Sess(tmp_path)
        osint._rdap(s, type("P", (), {"apex_domains": ["a.com"]})(), lambda _m: None, 30)
        note = [r for r in s.records if r.tool == "rdap"][0].note
        assert "quarry osint --unbound" in note
