"""B1.7 — the `/shodan/host/{ip}` record reader, driven from the MEASURED envelope.

The committed fixtures are the real 2026-07-30 responses (public infrastructure data, no PII): a populated
record trimmed to two banners — one plain, one with `ssl` — with every top-level key at its measured type,
and the verbatim no-data body.

The claim these tests exist to protect: "this IP is not in Shodan" is an ANSWER, and it must never read as
a lane failure — while a 404 we have not measured must never read as an answer.
"""

from __future__ import annotations

import io
import json
import pathlib
import socket
import urllib.error

import pytest

from quarry_recon import shodan_host as sh
from quarry_recon.contract import PROVIDER_CLASSES, is_measured_empty

pytestmark = pytest.mark.offline

class _Resp:
    """The urlopen context manager, reduced to what the lane uses — including the STATUS, which the lane
    reads rather than assuming (review-B1.7r9#1)."""

    def __init__(self, body, status=200):
        self._body = body
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, n=None):
        if getattr(self, '_eof', False):
            return b''                      # STREAM: the body once, then EOF
        self._eof = True
        return self._body


FIX = pathlib.Path(__file__).parent / "fixtures" / "shodan"
IP = "1.1.1.1"


def _record(**over):
    doc = json.loads((FIX / f"host-{IP}.json").read_text())
    doc.update(over)
    return json.dumps(doc).encode()


class TestTheMeasuredRecord:
    def test_the_REAL_response_reads_as_a_record(self):
        kind, rec = sh.read_host(_record(), ip=IP)
        assert kind == sh.HOST_RECORD, rec
        assert rec.ip == IP and rec.complete and rec.unusable == 0
        assert rec.asn == "AS13335" and rec.org and rec.isp
        assert rec.last_update.startswith("2026-07-30")

    def test_EVERY_measured_port_survives_the_reconciliation(self):
        """`data[]` knows the transport and module; `ports` is a bare list that can hold a port no banner
        does. Both are the provider's answer about one host, so a port in EITHER is kept — a port we know
        less about is still a port."""
        doc = json.loads((FIX / f"host-{IP}.json").read_text())
        kind, rec = sh.read_host(_record(), ip=IP)
        assert kind == sh.HOST_RECORD
        assert {p.port for p in rec.ports} == set(doc["ports"]), rec.ports
        # the two banners contribute what a bare port cannot
        detailed = {p.port: p for p in rec.ports if p.transport}
        assert detailed, rec.ports
        assert all(p.seen for p in detailed.values()), detailed
        assert any(p.module for p in detailed.values()), detailed

    def test_a_TLS_banner_is_recorded_as_such(self):
        """`ssl` is present on SOME banners only (3 of 12 in the measurement)."""
        kind, rec = sh.read_host(_record(), ip=IP)
        assert kind == sh.HOST_RECORD
        assert any(p.tls for p in rec.ports), rec.ports
        assert any(not p.tls for p in rec.ports), rec.ports

    def test_ABSENT_vulns_means_none_and_is_not_a_defect(self):
        """MEASURED: the key is absent entirely when the host has none. `has("vulns")` is false — this is
        not an empty list, and it is not a shape we failed to parse."""
        doc = json.loads((FIX / f"host-{IP}.json").read_text())
        assert "vulns" not in doc, "the fixture no longer reproduces the measured absence"
        kind, rec = sh.read_host(_record(), ip=IP)
        assert kind == sh.HOST_RECORD
        assert rec.vulns == [] and rec.complete and rec.unusable == 0

    @pytest.mark.parametrize("raw,want", [
        (["CVE-2021-1234", "CVE-2022-5678"], ["CVE-2021-1234", "CVE-2022-5678"]),
        ({"CVE-2021-1234": {"verified": False}}, ["CVE-2021-1234"]),      # the map shape
        (["CVE-2021-1234", "CVE-2021-1234"], ["CVE-2021-1234"]),          # deduplicated, not truncated
    ])
    def test_BOTH_plausible_vuln_shapes_are_accepted(self, raw, want):
        """Shodan has used a list and a `{cve: detail}` map. The measured host has neither, so both are
        accepted rather than one being guessed at."""
        kind, rec = sh.read_host(_record(vulns=raw), ip=IP)
        assert kind == sh.HOST_RECORD
        assert rec.vulns == want and rec.complete, (rec.vulns, rec.unusable)

    def test_an_UNKNOWN_vuln_shape_is_counted_not_coerced(self):
        kind, rec = sh.read_host(_record(vulns="CVE-2021-1234"), ip=IP)
        assert kind == sh.HOST_RECORD
        assert rec.vulns == [] and not rec.complete and rec.unusable == 1


class TestNoDataIsAnAnswer:
    def test_the_MEASURED_404_body_is_EMPTY_not_a_failure(self):
        raw = (FIX / "host-nodata.json").read_bytes()
        kind, said = sh.read_host(raw, ip="203.0.113.1", http_code=404)
        assert kind == sh.HOST_EMPTY, (kind, said)
        assert said == "No information available for that IP."     # verbatim, never paraphrased

    def test_the_wording_is_matched_EXACTLY_not_by_containment(self):
        """`_QUOTA_REASONS` learned this the hard way: a message cannot be distinguished from its own
        negation by substring. "Some information available for that IP." contains nothing of the sort."""
        assert is_measured_empty("shodan", "No information available for that IP.")
        assert is_measured_empty("shodan", "no  INFORMATION  available for that ip.")   # case+whitespace
        assert not is_measured_empty("shodan", "Some information available for that IP.")
        assert not is_measured_empty("shodan", "No information available for that IP. Really.")
        assert not is_measured_empty("whoxy", "No information available for that IP.")

    def test_an_UNMEASURED_404_stays_a_failure(self):
        """A 404 body we have not measured is a 404 we do not understand."""
        raw = json.dumps({"error": "Rate limit reached"}).encode()
        kind, why = sh.read_host(raw, ip=IP, http_code=404)
        assert kind == sh.HOST_INVALID and "Rate limit reached" in why

    def test_a_FAILED_REQUEST_carrying_the_measured_body_reads_as_empty(self):
        """The transport raises on a 404, so the ORDINARY case — an IP Shodan has never seen — arrives as
        an exception. `empty_or_raise` is the only place that is allowed to turn one into coverage."""
        err = RuntimeError("HTTP Error 404: Not Found")
        err.code = 404
        err.body_bytes = (FIX / "host-nodata.json").read_bytes()
        assert sh.empty_or_raise(err, ip="203.0.113.1") == "No information available for that IP."

    @pytest.mark.parametrize("body", [
        b'{"error": "Invalid API key"}',       # a real failure with a body
        b"<html>gateway timeout</html>",       # not JSON at all
        b"",                                   # no body captured
        None,
    ])
    def test_every_OTHER_failure_stays_a_failure(self, body):
        err = RuntimeError("boom")
        err.code = 404
        err.body_bytes = body
        assert sh.empty_or_raise(err, ip=IP) is None

    def test_the_parse_failure_speaks_the_taxonomy(self):
        e = sh.host_body_error("response was not JSON")
        assert e.error_class in PROVIDER_CLASSES and e.error_class == "parse"
        assert e.reason == "response was not JSON" and e.provider == "shodan"


class TestTheEnvelopeMustIdentifyItself:
    def test_a_record_about_ANOTHER_ip_is_refused(self):
        """A body accepted on faith becomes a permanent wrong answer in the ledger."""
        kind, why = sh.read_host(_record(), ip="8.8.8.8")
        assert kind == sh.HOST_INVALID and "1.1.1.1" in why and "8.8.8.8" in why

    @pytest.mark.parametrize("bad", [None, "", "not-an-ip", 16843009, True, ["1.1.1.1"]])
    def test_a_record_with_no_usable_ip_str_is_refused(self, bad):
        """`ip` is an INT in the measured envelope, so `ip_str` is the only identity field."""
        kind, why = sh.read_host(_record(ip_str=bad), ip=IP)
        assert kind == sh.HOST_INVALID and "ip_str" in why

    @pytest.mark.parametrize("raw", [b"", b"not json", b"[]", b'"a string"', b"null", b"123"])
    def test_an_unusable_body_is_refused_without_raising(self, raw):
        kind, why = sh.read_host(raw, ip=IP)
        assert kind == sh.HOST_INVALID and why

    def test_a_NON_200_with_no_message_is_refused(self):
        """An empty 500 says nothing about the host, and inventing "no data" from it would report a
        provider outage as measured absence."""
        kind, why = sh.read_host(b"{}", ip=IP, http_code=500)
        assert kind == sh.HOST_INVALID and "500" in why

    @pytest.mark.parametrize("ip", ["", None, "1.1.1.256", "example.com", 1])
    def test_a_request_for_a_NON_ADDRESS_is_refused_before_anything_is_read(self, ip):
        kind, why = sh.read_host(_record(), ip=ip)
        assert kind == sh.HOST_INVALID and "IP address" in why


class TestMalformedPartsAreDroppedNotFatal:
    """A strict parse must not suppress good findings: valid evidence is KEPT and every drop is counted."""

    def test_a_bad_banner_does_not_lose_the_good_ones(self):
        doc = json.loads((FIX / f"host-{IP}.json").read_text())
        doc["data"] = [{"port": "not-a-port"}, doc["data"][0], "a string", {"port": 70000}]
        kind, rec = sh.read_host(json.dumps(doc).encode(), ip=IP)
        assert kind == sh.HOST_RECORD
        assert any(p.transport for p in rec.ports), rec.ports
        assert not rec.complete and rec.unusable == 3, rec.unusable

    @pytest.mark.parametrize("field,value", [
        ("hostnames", "a.example.com"), ("tags", "cdn"), ("domains", {}), ("vulns", "CVE-2021-1234"),
    ])
    def test_a_SOFT_list_field_that_is_not_a_list_is_one_counted_drop(self, field, value):
        """The record still carries its ports, so it is kept — one part short, and it says so. The EVIDENCE
        collections are stricter (see `TestASuccessEnvelopeMustLookLikeARecord`)."""
        kind, rec = sh.read_host(_record(**{field: value}), ip=IP)
        assert kind == sh.HOST_RECORD
        assert not rec.complete and rec.unusable >= 1

    @pytest.mark.parametrize("bad", [True, False, 0, 65536, -1, "443", None, 3.5])
    def test_an_unusable_PORT_NUMBER_is_dropped(self, bad):
        kind, rec = sh.read_host(_record(ports=[bad, 443]), ip=IP)
        assert kind == sh.HOST_RECORD
        assert {p.port for p in rec.ports if not p.transport} == {443} or any(
            p.port == 443 for p in rec.ports), rec.ports
        assert not rec.complete and rec.unusable == 1

    def test_a_BARE_LABEL_hostname_is_dropped(self):
        """It canonicalises cleanly and names no domain, so it can be neither scoped nor attributed."""
        kind, rec = sh.read_host(_record(hostnames=["localhost", "A.Example.COM."]), ip=IP)
        assert kind == sh.HOST_RECORD
        assert rec.hostnames == ["a.example.com"], rec.hostnames
        assert not rec.complete and rec.unusable == 1

    def test_hostnames_are_deduplicated_by_their_canonical_form(self):
        kind, rec = sh.read_host(_record(hostnames=["A.Example.com", "a.example.com.", "a.example.com"]),
                                 ip=IP)
        assert kind == sh.HOST_RECORD
        assert rec.hostnames == ["a.example.com"] and rec.complete


class TestIdentityAndFairness:
    @pytest.mark.parametrize("raw,want", [
        ("1.1.1.1", "1.1.1.1"), (" 1.1.1.1 ", "1.1.1.1"),
        ("2001:0db8:0000::1", "2001:db8::1"),                 # one host, one key
        ("::ffff:1.1.1.1", "1.1.1.1"),        # an IPv4-mapped address is the same host
        ("1.1.1.256", ""), ("example.com", ""), ("", ""), (None, ""), (16843009, ""),
    ])
    def test_an_address_has_ONE_canonical_key(self, raw, want):
        assert sh.canonical_ip(raw) == want

    @pytest.mark.parametrize("ip,want", [
        ("1.1.1.1", "1.1.1.0/24"), ("1.1.1.254", "1.1.1.0/24"), ("1.1.2.1", "1.1.2.0/24"),
        ("2001:db8::1", "2001:db8::/48"), ("2001:db8:1::1", "2001:db8:1::/48"),
    ])
    def test_the_fairness_group_is_the_netblock(self, ip, want):
        """One dense netblock must not monopolise a bounded run — the host-fair rule, in address space."""
        assert sh.ip_group(ip) == want

    def test_a_NON_ADDRESS_has_no_group(self):
        assert sh.ip_group("example.com") == "" and sh.ip_group("") == ""


class TestStatusAndWordingMustAgree:
    """review-B1.7#1: the wording was checked BEFORE the status, so the measured no-data body laundered a
    200, a 401, a 429 and a 500 into EMPTY — absence we never established, from an outage."""

    NODATA = b'{"error": "No information available for that IP."}'

    @pytest.mark.parametrize("code", [200, 401, 403, 429, 500, 502, 0])
    def test_only_a_404_may_carry_the_no_data_answer(self, code):
        kind, why = sh.read_host(self.NODATA, ip=IP, http_code=code)
        assert kind == sh.HOST_INVALID, (code, kind, why)
        assert str(code) in why and "No information available" in why

    def test_the_404_with_that_body_is_still_empty(self):
        kind, said = sh.read_host(self.NODATA, ip=IP, http_code=404)
        assert kind == sh.HOST_EMPTY and said == "No information available for that IP."

    def test_a_FAILED_REQUEST_with_a_NON_404_status_is_not_coverage(self):
        """`empty_or_raise` reads the same two facts: an outage that echoes the sentence is not absence."""
        for code in (200, 429, 500):
            err = RuntimeError("boom")
            err.code = code
            err.body_bytes = self.NODATA
            assert sh.empty_or_raise(err, ip=IP) is None, code
        err = RuntimeError("not found")
        err.code = 404
        err.body_bytes = self.NODATA
        assert sh.empty_or_raise(err, ip=IP) == "No information available for that IP."


class TestEveryUnusablePartIsCounted:
    """review-B1.7#2: once a record is ledger-owned, an uncounted drop is a permanent clean completion."""

    @pytest.mark.parametrize("field,value", [
        ("org", 13335), ("org", {"name": "x"}), ("isp", []), ("asn", 13335), ("asn", True),
        ("last_update", 1785000000), ("last_update", ["2026-07-30"]),
    ])
    def test_a_SCALAR_that_is_not_a_string_is_counted(self, field, value):
        kind, rec = sh.read_host(_record(**{field: value}), ip=IP)
        assert kind == sh.HOST_RECORD
        assert getattr(rec, field) == "", getattr(rec, field)
        assert not rec.complete and rec.unusable == 1, rec.unusable

    @pytest.mark.parametrize("field", ["org", "isp", "asn", "last_update"])
    def test_an_ABSENT_scalar_is_not_a_defect(self, field):
        """The provider does not always know an ISP. Absent is an answer; unreadable is a loss."""
        doc = json.loads((FIX / f"host-{IP}.json").read_text())
        doc.pop(field)
        kind, rec = sh.read_host(json.dumps(doc).encode(), ip=IP)
        assert kind == sh.HOST_RECORD and rec.complete and rec.unusable == 0

    def test_an_unreadable_TAG_MEMBER_is_counted(self):
        kind, rec = sh.read_host(_record(tags=["cdn", 7, "", None, "cdn"]), ip=IP)
        assert kind == sh.HOST_RECORD
        assert rec.tags == ["cdn"], rec.tags
        assert not rec.complete and rec.unusable == 3, rec.unusable

    def test_unreadable_BANNER_METADATA_is_counted(self):
        doc = json.loads((FIX / f"host-{IP}.json").read_text())
        doc["data"][0]["_shodan"] = "dns-tcp"
        kind, rec = sh.read_host(json.dumps(doc).encode(), ip=IP)
        assert kind == sh.HOST_RECORD
        assert not rec.complete and rec.unusable == 1, rec.unusable
        assert any(p.port == doc["data"][0]["port"] for p in rec.ports), rec.ports

    @pytest.mark.parametrize("bad", [
        "../admin.example.com", "a b.example.com", "-lead.example.com", "trail-.example.com",
        "a..example.com", "x" * 64 + ".example.com", "http://a.example.com", "a.example.com/x",
    ])
    def test_a_name_that_is_NOT_A_HOSTNAME_is_refused_and_counted(self, bad):
        """Quarry's ONE name contract (`normalize.canon_host_strict`) — a third divergent copy is what it
        exists to prevent, and `../admin.example.com` was previously accepted verbatim."""
        kind, rec = sh.read_host(_record(hostnames=[bad, "ok.example.com"]), ip=IP)
        assert kind == sh.HOST_RECORD
        assert rec.hostnames == ["ok.example.com"], rec.hostnames
        assert not rec.complete and rec.unusable == 1

    def test_an_IDNA_name_is_canonicalised_by_the_shared_policy(self):
        """Non-transitional IDNA2008: `faß.de` and `xn--fa-hia.de` are ONE host, and must not become the
        different domain `fass.de`."""
        kind, rec = sh.read_host(_record(hostnames=["faß.de", "xn--fa-hia.de"]), ip=IP)
        assert kind == sh.HOST_RECORD
        assert rec.hostnames == ["xn--fa-hia.de"], rec.hostnames
        assert rec.complete

    @pytest.mark.parametrize("bad", [
        "not-a-cve", "CVE", "CVE-21-1234", "CVE-2021-123", "CVE-2021", "2021-1234", "CVE-2021-abcd", 7,
    ])
    def test_a_value_that_is_NOT_A_CVE_ID_is_counted(self, bad):
        kind, rec = sh.read_host(_record(vulns=[bad, "CVE-2021-1234"]), ip=IP)
        assert kind == sh.HOST_RECORD
        assert rec.vulns == ["CVE-2021-1234"], rec.vulns
        assert not rec.complete and rec.unusable == 1

    def test_a_lowercase_CVE_id_is_normalised_not_dropped(self):
        kind, rec = sh.read_host(_record(vulns=["cve-2021-1234", "CVE-2021-1234"]), ip=IP)
        assert kind == sh.HOST_RECORD
        assert rec.vulns == ["CVE-2021-1234"] and rec.complete


class TestTransportIsPartOfAPortsIdentity:
    """review-B1.7#3: observations were keyed by port alone, so 53/tcp and 53/udp — two services, two
    banners in the measured record — collapsed into one while the record reported `complete`."""

    def _two_transports(self):
        doc = json.loads((FIX / f"host-{IP}.json").read_text())
        base = dict(doc["data"][0])
        base["port"], base["transport"] = 53, "tcp"
        udp = dict(base)
        udp["transport"] = "udp"
        udp["_shodan"] = {"module": "dns-udp"}
        doc["data"] = [base, udp]
        doc["ports"] = [53]
        return doc

    def test_BOTH_transports_survive(self):
        kind, rec = sh.read_host(json.dumps(self._two_transports()).encode(), ip=IP)
        assert kind == sh.HOST_RECORD and rec.complete
        assert {p.key for p in rec.ports} == {(53, "tcp"), (53, "udp")}, rec.ports
        assert {p.module for p in rec.ports} == {"dns-tcp", "dns-udp"}, rec.ports

    def test_the_BARE_LIST_adds_nothing_when_a_banner_already_knows_the_port(self):
        """`ports` holds 53 once; two banners already describe it. A third transport-less observation would
        invent a service the provider never reported."""
        kind, rec = sh.read_host(json.dumps(self._two_transports()).encode(), ip=IP)
        assert kind == sh.HOST_RECORD
        assert not any(p.transport == "" for p in rec.ports), rec.ports

    def test_a_bare_port_NO_banner_mentions_is_still_kept(self):
        doc = self._two_transports()
        doc["ports"] = [53, 8443]
        kind, rec = sh.read_host(json.dumps(doc).encode(), ip=IP)
        assert kind == sh.HOST_RECORD and rec.complete
        assert (8443, "") in {p.key for p in rec.ports}, rec.ports

    def test_a_DUPLICATE_banner_for_the_same_pair_is_not_a_loss(self):
        doc = self._two_transports()
        doc["data"].append(dict(doc["data"][0]))
        kind, rec = sh.read_host(json.dumps(doc).encode(), ip=IP)
        assert kind == sh.HOST_RECORD and rec.complete and rec.unusable == 0
        assert len(rec.ports) == 2, rec.ports


class TestReadHostNeverRaises:
    """review-B1.7#4: `json.loads` raises TypeError on non-text, and a lenient decode turned malformed
    bytes into plausible JSON."""

    @pytest.mark.parametrize("raw", [None, 7, True, 3.5, [], {}, object(), ("a",)])
    def test_a_NON_TEXT_body_is_refused_rather_than_raising(self, raw):
        kind, why = sh.read_host(raw, ip=IP)
        assert kind == sh.HOST_INVALID and "not text" in why

    def test_MALFORMED_UTF8_is_refused_rather_than_replaced(self):
        """`errors="replace"` let bytes that are not text become a record: the replacement character is
        valid JSON string content."""
        raw = b'{"ip_str": "1.1.1.1", "org": "\xff\xfe", "ports": [443]}'
        kind, why = sh.read_host(raw, ip=IP)
        assert kind == sh.HOST_INVALID and "UTF-8" in why

    def test_a_bytearray_is_accepted(self):
        kind, rec = sh.read_host(bytearray(_record()), ip=IP)
        assert kind == sh.HOST_RECORD and rec.ip == IP

    def test_a_str_body_is_accepted(self):
        kind, rec = sh.read_host(_record().decode(), ip=IP)
        assert kind == sh.HOST_RECORD and rec.ip == IP


class TestOwnershipAndFairnessSeeTheSameHost:
    """review-B1.7#5: `canonical_ip` folded `::ffff:1.1.1.1` to `1.1.1.1` while `ip_group` grouped the raw
    value under `::/48` — the record owned under one family, ordered under another."""

    @pytest.mark.parametrize("raw", ["::ffff:1.1.1.1", "::FFFF:1.1.1.1", " ::ffff:1.1.1.1 "])
    def test_a_v4_mapped_address_groups_with_its_v4_family(self, raw):
        assert sh.canonical_ip(raw) == "1.1.1.1"
        assert sh.ip_group(raw) == sh.ip_group("1.1.1.1") == "1.1.1.0/24"

    def test_a_NON_CANONICAL_v6_form_groups_with_its_canonical_one(self):
        assert sh.ip_group("2001:0DB8:0000::1") == sh.ip_group("2001:db8::1") == "2001:db8::/48"


class TestASuccessEnvelopeMustLookLikeARecord:
    """review-B1.7r2#1: `{"ip_str": "1.1.1.1"}` read as a clean COMPLETE record with no ports and no
    banners — a confident "this host has nothing open" about a host we never actually saw."""

    @pytest.mark.parametrize("key", ["ports", "data", None])
    def test_a_body_with_no_EVIDENCE_collection_is_refused(self, key):
        doc = json.loads((FIX / f"host-{IP}.json").read_text())
        if key is None:
            doc = {"ip_str": IP}
        else:
            doc.pop(key)
        kind, why = sh.read_host(json.dumps(doc).encode(), ip=IP)
        assert kind == sh.HOST_INVALID, (key, kind)
        assert "absent" in why and (key or "ports") in why

    @pytest.mark.parametrize("key", ["ports", "data"])
    @pytest.mark.parametrize("value,word", [(None, "null"), ({}, "dict"), ("80,443", "str"),
                                            (443, "int"), (True, "bool")])
    def test_an_EVIDENCE_collection_of_the_WRONG_TYPE_is_refused(self, key, value, word):
        """review-B1.7r3#1: presence was not enough — `ports: null` and `data: {}` passed the check and then
        read as "absent" downstream, so the lane got a clean complete record with no evidence in it."""
        kind, why = sh.read_host(_record(**{key: value}), ip=IP)
        assert kind == sh.HOST_INVALID, (key, value, kind)
        assert f"{key} is {word}" in why, why

    @pytest.mark.parametrize("missing", ["hostnames", "domains", "tags"])
    def test_a_missing_SOFT_collection_is_a_counted_loss_not_a_rejection(self, missing):
        """Its ports are still real evidence, so the record is kept — one collection short of the measured
        shape, and it says so."""
        doc = json.loads((FIX / f"host-{IP}.json").read_text())
        doc.pop(missing)
        kind, rec = sh.read_host(json.dumps(doc).encode(), ip=IP)
        assert kind == sh.HOST_RECORD
        assert rec.ports, rec
        assert not rec.complete and rec.unusable == 1, rec.unusable

    def test_ABSENT_vulns_is_the_ONLY_free_absence(self):
        doc = json.loads((FIX / f"host-{IP}.json").read_text())
        assert "vulns" not in doc
        kind, rec = sh.read_host(json.dumps(doc).encode(), ip=IP)
        assert kind == sh.HOST_RECORD and rec.complete and rec.unusable == 0

    def test_an_EMPTY_evidence_collection_is_present_and_fine(self):
        """A host Shodan has seen but has no banners for is a real answer — `[]` is present."""
        kind, rec = sh.read_host(_record(ports=[], data=[]), ip=IP)
        assert kind == sh.HOST_RECORD and rec.complete and rec.ports == []


class TestBannerPartsAreCountedToo:
    """review-B1.7r2#2: banner scalars were coerced to blank/False in silence."""

    @pytest.mark.parametrize("field,value", [
        ("transport", 1), ("transport", ["tcp"]), ("transport", {}),
        ("timestamp", 1785000000), ("timestamp", ["2026-07-30"]),
    ])
    def test_an_unreadable_BANNER_SCALAR_is_counted(self, field, value):
        doc = json.loads((FIX / f"host-{IP}.json").read_text())
        doc["data"][0][field] = value
        kind, rec = sh.read_host(json.dumps(doc).encode(), ip=IP)
        assert kind == sh.HOST_RECORD
        assert not rec.complete and rec.unusable == 1, rec.unusable

    @pytest.mark.parametrize("value", ["yes", 1, [], True])
    def test_an_unreadable_SSL_field_is_counted_and_never_reads_as_plaintext(self, value):
        """Answering False would assert plaintext on a service we could not read."""
        doc = json.loads((FIX / f"host-{IP}.json").read_text())
        doc["data"][0]["ssl"] = value
        kind, rec = sh.read_host(json.dumps(doc).encode(), ip=IP)
        assert kind == sh.HOST_RECORD
        assert not rec.complete and rec.unusable == 1, rec.unusable

    def test_an_unreadable_MODULE_is_counted(self):
        doc = json.loads((FIX / f"host-{IP}.json").read_text())
        doc["data"][0]["_shodan"]["module"] = 7
        kind, rec = sh.read_host(json.dumps(doc).encode(), ip=IP)
        assert kind == sh.HOST_RECORD
        assert not rec.complete and rec.unusable == 1

    @pytest.mark.parametrize("field", ["transport", "timestamp", "ssl"])
    def test_an_ABSENT_or_NULL_banner_field_is_not_a_loss(self, field):
        """Not every module reports a transport or a timestamp, and most banners have no `ssl` at all."""
        for value in (None, "absent"):
            doc = json.loads((FIX / f"host-{IP}.json").read_text())
            if value is None:
                doc["data"][0][field] = None
            else:
                doc["data"][0].pop(field, None)
            kind, rec = sh.read_host(json.dumps(doc).encode(), ip=IP)
            assert kind == sh.HOST_RECORD, (field, value)
            assert rec.complete and rec.unusable == 0, (field, value, rec.unusable)

    def test_a_NON_STRING_error_field_invalidates_the_envelope(self):
        """The provider is signalling something we cannot read; reading past it made it a record."""
        for bad in ({"code": 1}, ["nope"], 7, True):
            kind, why = sh.read_host(json.dumps({"error": bad, "ip_str": IP, "ports": [], "data": []}
                                                ).encode(), ip=IP)
            assert kind == sh.HOST_INVALID and "unreadable error" in why, bad

    def test_a_NULL_error_field_is_not_an_error(self):
        """The measured success envelope has NO `error` key at all, so a null one is unmeasured. It reads as
        absent — the scalars' rule — because rejecting an otherwise valid record over a null would discard
        real evidence, and every other validation still has to pass."""
        kind, rec = sh.read_host(_record(error=None), ip=IP)
        assert kind == sh.HOST_RECORD and rec.complete

    @pytest.mark.parametrize("field", ["org", "isp", "asn", "last_update"])
    def test_a_PRESENT_NULL_scalar_is_the_providers_own_unknown(self, field):
        """MEASURED: the envelope carries `"os": null` and `"area_code": null`. Counting a null would flag
        every record ever fetched."""
        kind, rec = sh.read_host(_record(**{field: None}), ip=IP)
        assert kind == sh.HOST_RECORD
        assert getattr(rec, field) == "" and rec.complete and rec.unusable == 0


class TestConflictingDuplicateBannersAreReconciled:
    """review-B1.7r2#3: the first observation for a (port, transport) won unconditionally, so a second
    banner that added TLS, a newer sighting or another module was discarded while reporting `complete`."""

    def _pair(self, first, second):
        doc = json.loads((FIX / f"host-{IP}.json").read_text())
        base = {"port": 443, "transport": "tcp", "_shodan": {}, "timestamp": "2026-07-01T00:00:00.0"}
        a, b = dict(base), dict(base)
        a.update(first)
        b.update(second)
        doc["data"] = [a, b]
        doc["ports"] = [443]
        kind, rec = sh.read_host(json.dumps(doc).encode(), ip=IP)
        assert kind == sh.HOST_RECORD
        obs = [p for p in rec.ports if p.key == (443, "tcp")]
        assert len(obs) == 1, rec.ports
        return obs[0], rec

    def test_TLS_seen_on_either_banner_is_TLS_seen(self):
        obs, rec = self._pair({}, {"ssl": {"cipher": "x"}})
        assert obs.tls is True and rec.complete
        obs, rec = self._pair({"ssl": {"cipher": "x"}}, {})
        assert obs.tls is True and rec.complete

    def test_the_LATEST_sighting_wins(self):
        obs, rec = self._pair({"timestamp": "2026-07-01T00:00:00.0"},
                             {"timestamp": "2026-07-29T12:00:00.0"})
        assert obs.seen == "2026-07-29T12:00:00.0" and rec.complete
        obs, rec = self._pair({"timestamp": "2026-07-29T12:00:00.0"},
                             {"timestamp": "2026-07-01T00:00:00.0"})
        assert obs.seen == "2026-07-29T12:00:00.0", "an older banner overwrote a newer sighting"

    def test_a_module_only_the_SECOND_banner_knows_is_kept(self):
        obs, rec = self._pair({"_shodan": {}}, {"_shodan": {"module": "https"}})
        assert obs.module == "https" and rec.complete

    def test_TWO_DIFFERENT_modules_are_a_counted_loss(self):
        """We model one service name per (port, transport); losing the other is real and it is counted."""
        obs, rec = self._pair({"_shodan": {"module": "https"}}, {"_shodan": {"module": "http"}})
        assert obs.module == "https"
        assert not rec.complete and rec.unusable == 1, rec.unusable

    def test_an_EXACT_duplicate_is_harmless(self):
        obs, rec = self._pair({"_shodan": {"module": "https"}, "ssl": {"cipher": "x"}},
                              {"_shodan": {"module": "https"}, "ssl": {"cipher": "x"}})
        assert obs.module == "https" and obs.tls is True
        assert rec.complete and rec.unusable == 0


class TestCveIdsAreAscii:
    @pytest.mark.parametrize("bad", ["CVE-２０２１-１２３４", "CVE-2021-１２３４", "CVE-٢٠٢١-1234"])
    def test_a_NON_ASCII_digit_is_not_a_CVE_id(self, bad):
        r"""review-B1.7r2#4: `\d` matches every Unicode decimal, so a full-width id passed as clean — an
        identifier nothing can be looked up by."""
        kind, rec = sh.read_host(_record(vulns=[bad, "CVE-2021-1234"]), ip=IP)
        assert kind == sh.HOST_RECORD
        assert rec.vulns == ["CVE-2021-1234"], rec.vulns
        assert not rec.complete and rec.unusable == 1


class TestNullCollectionsAreNotTheMeasuredEmpty:
    """review-B1.7r3#2: a MISSING soft collection was counted while a present `null` one became a clean
    empty collection. The scalars' null rule is about the provider's "unknown" for a VALUE; it does not
    extend to a container whose measured form is always a list."""

    @pytest.mark.parametrize("key", ["hostnames", "domains", "tags"])
    def test_a_NULL_soft_collection_is_counted_like_an_absent_one(self, key):
        null_kind, null_rec = sh.read_host(_record(**{key: None}), ip=IP)
        doc = json.loads((FIX / f"host-{IP}.json").read_text())
        doc.pop(key)
        gone_kind, gone_rec = sh.read_host(json.dumps(doc).encode(), ip=IP)
        assert null_kind == gone_kind == sh.HOST_RECORD
        assert not null_rec.complete and null_rec.unusable == 1, null_rec.unusable
        assert null_rec.unusable == gone_rec.unusable, "null and absent were graded differently"

    def test_a_NULL_vulns_is_counted_although_ABSENT_is_free(self):
        """Only absence was measured, and it means "this host has none". A null is a part we could not
        read, and the two must not be the same answer."""
        kind, rec = sh.read_host(_record(vulns=None), ip=IP)
        assert kind == sh.HOST_RECORD
        assert rec.vulns == [] and not rec.complete and rec.unusable == 1, rec.unusable

        doc = json.loads((FIX / f"host-{IP}.json").read_text())
        assert "vulns" not in doc
        kind, rec = sh.read_host(json.dumps(doc).encode(), ip=IP)
        assert rec.complete and rec.unusable == 0

    @pytest.mark.parametrize("key", ["hostnames", "domains", "tags"])
    def test_an_EMPTY_soft_collection_is_still_the_explicit_answer(self, key):
        kind, rec = sh.read_host(_record(**{key: []}), ip=IP)
        assert kind == sh.HOST_RECORD and rec.complete and rec.unusable == 0


class TestTimestampsMustLookLikeTimestamps:
    """review-B1.7r3#3: reconciliation compared timestamps LEXICALLY without checking the shape, so a
    duplicate banner carrying "tomorrow" sorted above every real ISO value and became the sighting we
    report — with `complete=True`."""

    def _banner(self, ts):
        doc = json.loads((FIX / f"host-{IP}.json").read_text())
        doc["data"] = [{"port": 443, "transport": "tcp", "_shodan": {}, "timestamp": ts}]
        doc["ports"] = [443]
        return sh.read_host(json.dumps(doc).encode(), ip=IP)

    @pytest.mark.parametrize("ts", ["2026-07-30T04:14:37.743242", "2026-07-30T04:14:37"])
    def test_the_MEASURED_shapes_are_accepted(self, ts):
        kind, rec = self._banner(ts)
        assert kind == sh.HOST_RECORD and rec.complete
        assert rec.ports[0].seen == ts

    @pytest.mark.parametrize("ts", ["tomorrow", "zzz", "2026-07-30", "30/07/2026",
                                    "2026-07-30 04:14:37", "９９９９-07-30T04:14:37"])
    def test_an_UNREADABLE_timestamp_is_counted_and_never_orders_anything(self, ts):
        kind, rec = self._banner(ts)
        assert kind == sh.HOST_RECORD
        assert rec.ports[0].seen == "", rec.ports[0].seen
        assert not rec.complete and rec.unusable == 1, rec.unusable

    def test_a_JUNK_duplicate_cannot_outrank_a_real_sighting(self):
        doc = json.loads((FIX / f"host-{IP}.json").read_text())
        base = {"port": 443, "transport": "tcp", "_shodan": {}}
        doc["data"] = [dict(base, timestamp="2026-07-29T12:00:00.0"), dict(base, timestamp="tomorrow")]
        doc["ports"] = [443]
        kind, rec = sh.read_host(json.dumps(doc).encode(), ip=IP)
        assert kind == sh.HOST_RECORD
        obs = [p for p in rec.ports if p.key == (443, "tcp")]
        assert len(obs) == 1 and obs[0].seen == "2026-07-29T12:00:00.0", rec.ports
        assert not rec.complete and rec.unusable == 1


class TestAPresentErrorIsAlwaysASignal:
    """review-B1.7r3#4: `"   "` was read as no error at all, and the body could then be accepted as a clean
    record. A SUCCESS was measured without the key entirely."""

    @pytest.mark.parametrize("blank", ["   ", "", "\t", "\n  "])
    def test_a_BLANK_error_invalidates_the_envelope(self, blank):
        kind, why = sh.read_host(_record(error=blank), ip=IP)
        assert kind == sh.HOST_INVALID, (blank, kind)
        assert "empty error" in why, why

    def test_a_NULL_error_is_still_read_as_absent(self):
        kind, rec = sh.read_host(_record(error=None), ip=IP)
        assert kind == sh.HOST_RECORD and rec.complete


class TestTransportIsAnIdentityBoundary:
    """review-B1.7r4#1: `transport` is half of `PortObs.key`, so whatever is accepted here becomes a SERVICE
    IDENTITY. Generic text parsing let `TCP` and `tcp` be two services on one port, and `banana` be one."""

    def _banners(self, *transports):
        doc = json.loads((FIX / f"host-{IP}.json").read_text())
        doc["data"] = [{"port": 443, "transport": tr, "_shodan": {},
                        "timestamp": "2026-07-30T04:14:37.743242"} for tr in transports]
        doc["ports"] = [443]
        return sh.read_host(json.dumps(doc).encode(), ip=IP)

    @pytest.mark.parametrize("raw", ["tcp", "TCP", "Tcp", " tcp "])
    def test_CASE_does_not_create_a_second_service(self, raw):
        kind, rec = self._banners(raw)
        assert kind == sh.HOST_RECORD and rec.complete
        assert [p.key for p in rec.ports] == [(443, "tcp")], rec.ports

    def test_the_SAME_service_written_two_ways_is_ONE_observation(self):
        kind, rec = self._banners("tcp", "TCP")
        assert kind == sh.HOST_RECORD and rec.complete
        assert [p.key for p in rec.ports] == [(443, "tcp")], rec.ports

    @pytest.mark.parametrize("raw", ["banana", "sctp", "tcp6", "t c p", "-", "0"])
    def test_an_UNMEASURED_transport_is_counted_and_the_PORT_still_survives(self, raw):
        """The port is real evidence whatever the transport said; inventing a service from a word we have
        never measured is what must not happen."""
        kind, rec = self._banners(raw)
        assert kind == sh.HOST_RECORD
        assert [p.key for p in rec.ports] == [(443, "")], rec.ports
        assert not rec.complete and rec.unusable == 1, rec.unusable

    def test_udp_is_measured_too(self):
        kind, rec = self._banners("tcp", "udp")
        assert kind == sh.HOST_RECORD and rec.complete
        assert {p.key for p in rec.ports} == {(443, "tcp"), (443, "udp")}, rec.ports


class TestTimestampsMustBeRealTimes:
    """review-B1.7r4#2: the shape check passed `2026-99-99T99:99:99`, and this value SELECTS the latest
    sighting — so an impossible date won every comparison."""

    def _banner(self, ts):
        doc = json.loads((FIX / f"host-{IP}.json").read_text())
        doc["data"] = [{"port": 443, "transport": "tcp", "_shodan": {}, "timestamp": ts}]
        doc["ports"] = [443]
        return sh.read_host(json.dumps(doc).encode(), ip=IP)

    @pytest.mark.parametrize("ts", ["2026-99-99T99:99:99", "2026-13-01T00:00:00", "2026-02-30T00:00:00",
                                    "2026-07-30T25:00:00", "2026-07-30T04:60:00", "0000-00-00T00:00:00"])
    def test_an_IMPOSSIBLE_time_is_counted_not_ordered_by(self, ts):
        kind, rec = self._banner(ts)
        assert kind == sh.HOST_RECORD
        assert rec.ports[0].seen == "", rec.ports[0].seen
        assert not rec.complete and rec.unusable == 1, rec.unusable

    @pytest.mark.parametrize("ts", ["2026-07-30T04:14:37.743242", "2026-07-30T04:14:37",
                                     "2026-07-30T04:14:37.0", "2024-02-29T23:59:59.999999"])
    def test_REAL_times_are_accepted_including_the_measured_fraction(self, ts):
        """Fraction lengths vary and `fromisoformat` disagrees about them across supported interpreters, so
        the calendar part is what gets validated — a real leap day included."""
        kind, rec = self._banner(ts)
        assert kind == sh.HOST_RECORD and rec.complete, rec.unusable
        assert rec.ports[0].seen == ts

    def test_an_IMPOSSIBLE_duplicate_cannot_outrank_a_real_sighting(self):
        doc = json.loads((FIX / f"host-{IP}.json").read_text())
        base = {"port": 443, "transport": "tcp", "_shodan": {}}
        doc["data"] = [dict(base, timestamp="2026-07-29T12:00:00.0"),
                       dict(base, timestamp="2026-99-99T99:99:99")]
        doc["ports"] = [443]
        kind, rec = sh.read_host(json.dumps(doc).encode(), ip=IP)
        assert kind == sh.HOST_RECORD
        obs = [p for p in rec.ports if p.key == (443, "tcp")]
        assert len(obs) == 1 and obs[0].seen == "2026-07-29T12:00:00.0", rec.ports
        assert not rec.complete and rec.unusable == 1


# ── the eligible set ──────────────────────────────────────────────────────────────────────────────────
def _ctx(resolved=(), ports=(), web_ports=(), apex="acme.com", cidrs=()):
    from types import SimpleNamespace
    import ipaddress as _ip

    nets = [_ip.ip_network(c) for c in cidrs]
    reads = {"resolved": list(resolved), "port": list(ports), "web_port": list(web_ports)}
    scope = SimpleNamespace(
        in_scope=lambda h: h.endswith(apex),
        is_oos=lambda h: h.startswith("oos."),
        ip_in_scope=lambda ip: any(_ip.ip_address(ip) in n for n in nets))
    return SimpleNamespace(run=SimpleNamespace(read=lambda e: reads.get(e, [])), scope=scope)


class TestOnlyObservedAddressesAreEligible:
    """A declared CIDR is a scope FILTER, never an address GENERATOR: a /16 is 65,534 addresses Quarry has
    no reason to believe exist, and enumerating them spends a run on emptiness while reporting coverage."""

    def test_A_and_AAAA_of_an_in_scope_host_are_eligible(self):
        ctx = _ctx(resolved=[{"host": "www.acme.com", "a": ["1.1.1.1"], "aaaa": ["2001:db8::1"]}])
        got = {t.ip: t for t in sh.eligible_ips(ctx)}
        assert set(got) == {"1.1.1.1", "2001:db8::1"}, got
        assert got["1.1.1.1"].hosts == ("www.acme.com",)
        assert got["1.1.1.1"].sources == ("resolved",)

    def test_an_OUT_OF_SCOPE_hosts_address_is_not_eligible(self):
        ctx = _ctx(resolved=[{"host": "www.elsewhere.net", "a": ["9.9.9.9"]}])
        assert sh.eligible_ips(ctx) == []

    def test_an_OOS_hosts_address_is_not_eligible(self):
        """RoE: observe and mine OOS evidence, never expand against it. Adding its address to the set we
        act on IS expansion — a free lookup is still a decision about what to touch next."""
        ctx = _ctx(resolved=[{"host": "oos.acme.com", "a": ["9.9.9.9"]},
                             {"host": "www.acme.com", "a": ["1.1.1.1"]}])
        assert [t.ip for t in sh.eligible_ips(ctx)] == ["1.1.1.1"]

    def test_a_PORT_record_we_already_hold_makes_its_address_eligible(self):
        ctx = _ctx(web_ports=[{"ip": "1.1.1.1", "host": "www.acme.com", "port": 443}])
        got = sh.eligible_ips(ctx)
        assert [t.ip for t in got] == ["1.1.1.1"] and got[0].hosts == ("www.acme.com",)

    def test_an_UNATTRIBUTED_port_record_needs_a_DECLARED_range(self):
        """Nothing in the run says an unattributed address is ours unless the operator declared it."""
        ctx = _ctx(ports=[{"ip": "10.0.0.5", "port": 22}], cidrs=["10.0.0.0/24"])
        assert [t.ip for t in sh.eligible_ips(ctx)] == ["10.0.0.5"]
        ctx = _ctx(ports=[{"ip": "10.0.0.5", "port": 22}])
        assert sh.eligible_ips(ctx) == []

    def test_a_port_record_attributed_to_an_OOS_host_is_not_eligible(self):
        ctx = _ctx(web_ports=[{"ip": "9.9.9.9", "host": "oos.acme.com", "port": 443}],
                   cidrs=["9.0.0.0/8"])
        assert sh.eligible_ips(ctx) == [], "an OOS attribution was overridden by a declared range"

    def test_a_CIDR_never_GENERATES_addresses(self):
        ctx = _ctx(cidrs=["10.0.0.0/16"])
        assert sh.eligible_ips(ctx) == []

    def test_one_address_seen_TWICE_is_one_target_with_both_reasons(self):
        ctx = _ctx(resolved=[{"host": "www.acme.com", "a": ["1.1.1.1"]},
                             {"host": "api.acme.com", "a": ["1.1.1.1"]}],
                   web_ports=[{"ip": "1.1.1.1", "host": "www.acme.com", "port": 443}])
        got = sh.eligible_ips(ctx)
        assert len(got) == 1, got
        assert set(got[0].hosts) == {"www.acme.com", "api.acme.com"}
        assert set(got[0].sources) == {"resolved", "web_port"}

    def test_the_SAME_HOST_written_differently_is_one_address(self):
        ctx = _ctx(resolved=[{"host": "www.acme.com", "a": ["1.1.1.1", "::ffff:1.1.1.1"]}])
        assert [t.ip for t in sh.eligible_ips(ctx)] == ["1.1.1.1"]

    @pytest.mark.parametrize("junk", ["", None, "not-an-ip", "1.1.1.256", 16843009, ["1.1.1.1"]])
    def test_a_value_that_is_not_an_address_is_ignored(self, junk):
        ctx = _ctx(resolved=[{"host": "www.acme.com", "a": [junk, "1.1.1.1"]}])
        assert [t.ip for t in sh.eligible_ips(ctx)] == ["1.1.1.1"]


class TestSchedulingIsNetblockFair:
    def test_one_dense_netblock_cannot_monopolise_a_bounded_run(self):
        dense = [sh.IpTarget(f"1.1.1.{i}") for i in range(1, 6)]
        sparse = [sh.IpTarget("2.2.2.1"), sh.IpTarget("3.3.3.1")]
        order = [t.ip for t in sh.schedule(dense + sparse)]
        assert len(order) == 7, order                      # membership is never bounded
        first3 = order[:3]
        assert len({sh.ip_group(ip) for ip in first3}) == 3, f"a bounded prefix was not fair: {first3}"

    def test_EVERY_target_appears_exactly_once(self):
        targets = [sh.IpTarget(f"1.1.{b}.{h}") for b in range(3) for h in range(1, 4)]
        order = [t.ip for t in sh.schedule(targets)]
        assert sorted(order) == sorted(t.ip for t in targets)
        assert len(set(order)) == len(order)

    def test_a_TARGET_WITH_NO_GROUP_is_filtered_rather_than_ordered(self):
        """`IpTarget` is only ever built by the collector, which canonicalises — but ordering must not be
        the place a bad value first becomes a problem."""
        order = sh.schedule([sh.IpTarget("not-an-ip"), sh.IpTarget("1.1.1.1")])
        assert [t.ip for t in order] == ["1.1.1.1"]


# ── the free work loop ────────────────────────────────────────────────────────────────────────────────
class _Provider:
    """A scripted `/shodan/host/{ip}`. Every request is recorded, so "did we ask?" is directly observable."""

    def __init__(self, records=None, errors=None, code=200):
        self.records = records or {}
        self.errors = errors or {}
        self.calls = []
        self.code = code                       # the status a SUCCESS arrives with — the provider's, not ours

    def fetch(self, ip):
        self.calls.append(ip)
        err = self.errors.get(ip)
        if err is not None:
            return b"", getattr(err, "code", 0) or 0, err
        body = self.records.get(ip)
        if body is None:
            err = _nodata_error()
            return b"", err.code, err
        return body, self.code, None


def _nodata_error(code=404):
    err = RuntimeError(f"HTTP Error {code}: Not Found")
    err.code = code
    err.error_class = "http"
    err.body_bytes = b'{"error": "No information available for that IP."}'
    return err


def _err(cls, msg="boom"):
    e = RuntimeError(msg)
    e.error_class = cls
    return e


def _body(ip, ports=(443,), hostnames=("a.acme.com",)):
    return json.dumps({"ip_str": ip, "ip": 0, "ports": list(ports),
                       "hostnames": list(hostnames), "domains": [], "tags": [],
                       "org": "Acme", "isp": "Acme", "asn": "AS1",
                       "last_update": "2026-07-30T04:14:37.743242",
                       "data": [{"port": p, "transport": "tcp", "_shodan": {"module": "https"},
                                 "timestamp": "2026-07-30T04:14:37.743242"} for p in ports]}).encode()


def _ledger(tmp_path, lane="probe.shodan_host"):
    from quarry_recon import budget
    return budget.Ledger(budget.state_path(tmp_path, lane, "fp0"), lane=lane)


def _run(tmp_path, targets, provider, *, ledger=None, ingested=None, attempt="a0", budget_s=0, **kw):
    from quarry_recon import budget as _b
    d = tmp_path / "attempts" / attempt
    d.mkdir(parents=True, exist_ok=True)

    def ingest(target, rec, art, wrote):
        if ingested is not None:
            ingested.append((target.ip, tuple(p.key for p in rec.ports), str(art)))
        for _p in rec.ports:
            wrote(sh.WROTE_PORT)
        for _h in rec.hostnames:
            wrote(sh.WROTE_HOSTNAME)
        for _v in rec.vulns:
            wrote(sh.WROTE_VULN)

    return sh.run_hosts(targets, fetch=provider.fetch, ingest=kw.pop("ingest", ingest),
                        ledger=ledger if ledger is not None else _ledger(tmp_path), attempt_dir=d,
                        bound=_b.Budget(budget_s), **kw)


class TestTheLaneIsFree:
    """No balance, no reserve, no spendable bound — the endpoint costs nothing (MEASURED at zero credits),
    so a credit control here would stop work no credit pays for."""

    def test_run_hosts_takes_no_balance_at_all(self):
        import inspect
        params = set(inspect.signature(sh.run_hosts).parameters)
        assert not params & {"balance", "reserve", "spendable", "max_pages"}, params

    def test_every_eligible_address_is_asked_about(self, tmp_path):
        targets = [sh.IpTarget(f"1.1.1.{i}") for i in range(1, 21)]
        prov = _Provider(records={t.ip: _body(t.ip) for t in targets})
        o = _run(tmp_path, targets, prov)
        assert len(prov.calls) == 20, len(prov.calls)
        assert o.records == 20 and o.not_attempted == [] and o.persisted


class TestNoDataIsCoverageNotFailure:
    def test_an_address_shodan_has_never_seen_is_EMPTY(self, tmp_path):
        targets = [sh.IpTarget("1.1.1.1"), sh.IpTarget("203.0.113.1")]
        prov = _Provider(records={"1.1.1.1": _body("1.1.1.1")})
        o = _run(tmp_path, targets, prov)
        assert o.records == 1 and o.empty == 1
        assert o.fail_classes == {} and o.fail_reason == "", o.fail_classes
        assert o.not_attempted == []

    def test_a_REAL_failure_is_still_a_failure(self, tmp_path):
        prov = _Provider(errors={"1.1.1.1": _err("transport", "connection died")})
        o = _run(tmp_path, [sh.IpTarget("1.1.1.1")], prov)
        assert o.fail_classes == {"transport": 1} and "connection died" in o.fail_reason
        assert o.empty == 0 and o.records == 0

    def test_an_ASKED_AND_FAILED_address_is_not_reported_as_unqueried(self, tmp_path):
        """"Never asked" is not "asked and failed": a failure is counted by class, and listing it as a
        remainder too would overstate the loss and hide that the attempt happened."""
        prov = _Provider(errors={"1.1.1.1": _err("server")})
        o = _run(tmp_path, [sh.IpTarget("1.1.1.1")], prov)
        assert o.attempted == 1 and o.not_attempted == [], o.not_attempted


class TestOwnedRecordsReplayForFree:
    def test_a_SECOND_lifecycle_asks_for_nothing_it_owns(self, tmp_path):
        targets = [sh.IpTarget("1.1.1.1", hosts=("www.acme.com",))]
        prov = _Provider(records={"1.1.1.1": _body("1.1.1.1")})
        led = _ledger(tmp_path)
        first = _run(tmp_path, targets, prov, ledger=led)
        assert first.records == 1 and first.replayed == 0

        seen = []
        again = _run(tmp_path, targets, prov, ledger=_ledger(tmp_path), ingested=seen, attempt="a1")
        assert len(prov.calls) == 1, f"a resumed run re-asked: {prov.calls}"
        assert again.replayed == 1 and again.attempted == 0
        assert seen and seen[0][0] == "1.1.1.1" and seen[0][1] == ((443, "tcp"),)

    def test_replayed_evidence_is_INGESTED_not_merely_counted(self, tmp_path):
        targets = [sh.IpTarget("1.1.1.1")]
        prov = _Provider(records={"1.1.1.1": _body("1.1.1.1", ports=(80, 443))})
        led = _ledger(tmp_path)
        _run(tmp_path, targets, prov, ledger=led)
        seen = []
        o = _run(tmp_path, targets, prov, ledger=_ledger(tmp_path), ingested=seen, attempt="a1")
        assert o.ports == 2 and o.hostnames == 1
        assert seen[0][1] == ((80, "tcp"), (443, "tcp"))

    def test_a_TAMPERED_artifact_is_disowned_by_the_ledger_and_asked_again(self, tmp_path):
        """The digest binding catches this before we do: the ledger drops the entry at load, so the address
        reads as one we have not asked about — which, for a free endpoint, is exactly the right answer."""
        targets = [sh.IpTarget("1.1.1.1")]
        prov = _Provider(records={"1.1.1.1": _body("1.1.1.1")})
        led = _ledger(tmp_path)
        _run(tmp_path, targets, prov, ledger=led)
        led.artifact(sh.item_key("1.1.1.1")).write_bytes(b"tampered")
        o = _run(tmp_path, targets, prov, ledger=_ledger(tmp_path), attempt="a1")
        assert o.replayed == 0 and o.records == 1
        assert prov.calls == ["1.1.1.1", "1.1.1.1"], prov.calls

    def test_an_OWNED_record_that_is_NO_LONGER_A_RECORD_is_a_counted_loss(self, tmp_path):
        """Digest-correct and semantically useless: a stored body that no longer reads as a record about
        this address. The binding cannot see it, so the READER has to, and it is asked again."""
        from quarry_recon import budget as _b
        import hashlib as _h
        led = _ledger(tmp_path)
        d = tmp_path / "attempts" / "a0"
        d.mkdir(parents=True, exist_ok=True)
        raw = b'{"ip_str": "8.8.8.8", "ports": [], "data": [], "hostnames": [], "domains": [], "tags": []}'
        art = d / f"{sh.item_key('1.1.1.1')}.json"
        dig = _h.sha256(raw).hexdigest()
        assert _b.publish_bytes(art, raw, digest=dig)
        assert led.record(sh.item_key("1.1.1.1"), art, digest=dig)
        led.save()

        prov = _Provider(records={"1.1.1.1": _body("1.1.1.1")})
        o = _run(tmp_path, [sh.IpTarget("1.1.1.1")], prov, ledger=_ledger(tmp_path), attempt="a1")
        assert o.evidence_invalid == 1 and o.replayed == 0, (o.evidence_invalid, o.replayed)
        assert prov.calls == ["1.1.1.1"], prov.calls
        assert o.records == 1

    def test_an_artifact_DELETED_MID_RUN_is_a_counted_loss(self, tmp_path):
        """`has()` is True and `artifact()` is None: the entry survived the load and the file did not."""
        targets = [sh.IpTarget("1.1.1.1")]
        prov = _Provider(records={"1.1.1.1": _body("1.1.1.1")})
        led = _ledger(tmp_path)
        _run(tmp_path, targets, prov, ledger=led)
        reopened = _ledger(tmp_path)
        assert reopened.has(sh.item_key("1.1.1.1"))
        reopened.artifact(sh.item_key("1.1.1.1")).unlink()      # after the load, before the replay
        o = _run(tmp_path, targets, prov, ledger=reopened, attempt="a1")
        assert o.evidence_invalid == 1 and o.replayed == 0
        assert prov.calls == ["1.1.1.1", "1.1.1.1"], prov.calls


class TestThroughputIsBoundedNotMembership:
    def test_a_TIME_BUDGET_leaves_an_exact_resumable_remainder(self, tmp_path, monkeypatch):
        targets = [sh.IpTarget(f"1.1.{b}.1") for b in range(6)]
        prov = _Provider(records={t.ip: _body(t.ip) for t in targets})
        from quarry_recon import budget as _b
        clock = {"t": 0.0}
        monkeypatch.setattr(_b.time, "monotonic", lambda: clock["t"])
        real = prov.fetch

        def slow(ip):
            clock["t"] += 1.0
            return real(ip)

        prov.fetch = slow
        o = _run(tmp_path, targets, prov, budget_s=3)
        assert o.attempted == 3, o.attempted
        assert o.stop_cause == "budget_time"
        assert len(o.not_attempted) == 3 and set(o.not_attempted) <= {t.ip for t in targets}
        assert o.eligible == 6, "membership was bounded, not throughput"

    def test_ZERO_is_unbounded(self, tmp_path, monkeypatch):
        targets = [sh.IpTarget(f"1.1.{b}.1") for b in range(4)]
        prov = _Provider(records={t.ip: _body(t.ip) for t in targets})
        from quarry_recon import budget as _b
        monkeypatch.setattr(_b.time, "monotonic", lambda: 1e9)   # any deadline would already have passed
        o = _run(tmp_path, targets, prov, budget_s=0)
        assert o.attempted == 4 and o.not_attempted == [] and o.stop_cause == ""

    def test_the_remainder_survives_into_the_NEXT_lifecycle(self, tmp_path, monkeypatch):
        targets = [sh.IpTarget(f"1.1.{b}.1") for b in range(4)]
        prov = _Provider(records={t.ip: _body(t.ip) for t in targets})
        from quarry_recon import budget as _b
        clock = {"t": 0.0}
        monkeypatch.setattr(_b.time, "monotonic", lambda: clock["t"])
        real = prov.fetch

        def slow(ip):
            clock["t"] += 1.0
            return real(ip)

        prov.fetch = slow
        led = _ledger(tmp_path)
        first = _run(tmp_path, targets, prov, ledger=led, budget_s=2)
        assert first.attempted == 2 and len(first.not_attempted) == 2

        clock["t"] = 0.0
        second = _run(tmp_path, targets, prov, ledger=_ledger(tmp_path), attempt="a1", budget_s=10)
        assert second.replayed == 2, "the first run's records were re-fetched"
        assert second.attempted == 2 and second.not_attempted == []
        assert sorted(prov.calls) == sorted(t.ip for t in targets), prov.calls


class TestAProvenRefusalStopsAsking:
    @pytest.mark.parametrize("cls", ["auth", "forbidden"])
    def test_a_refusal_the_next_address_would_meet_identically_ends_the_run(self, tmp_path, cls):
        targets = [sh.IpTarget(f"1.1.{b}.1") for b in range(5)]
        prov = _Provider(errors={t.ip: _err(cls) for t in targets})
        o = _run(tmp_path, targets, prov, should_stop=lambda c: c in ("auth", "forbidden"))
        assert len(prov.calls) == 1, f"a rejected credential was offered again: {prov.calls}"
        assert o.stop_cause == f"provider_stop:{cls}"
        assert o.fail_classes == {cls: 1}
        assert len(o.not_attempted) == 4, o.not_attempted

    def test_an_ORDINARY_failure_does_not_stop_the_lane(self, tmp_path):
        targets = [sh.IpTarget(f"1.1.{b}.1") for b in range(4)]
        prov = _Provider(errors={"1.1.0.1": _err("transport")},
                         records={f"1.1.{b}.1": _body(f"1.1.{b}.1") for b in range(1, 4)})
        o = _run(tmp_path, targets, prov, should_stop=lambda c: c in ("auth", "forbidden"))
        assert len(prov.calls) == 4 and o.records == 3
        assert o.fail_classes == {"transport": 1} and o.not_attempted == []


class TestMachineryFailuresKeepTheOutcome:
    """The B1.7a discipline, in this lane's own loop."""

    def test_an_INGEST_failure_keeps_what_was_already_collected(self, tmp_path):
        targets = [sh.IpTarget("1.1.1.1"), sh.IpTarget("1.1.2.1")]
        prov = _Provider(records={t.ip: _body(t.ip) for t in targets})
        seen = []

        def ingest(target, rec, art, wrote):
            if seen:
                raise RuntimeError("store exploded")
            seen.append(target.ip)

        o = _run(tmp_path, targets, prov, ingest=ingest)
        assert o.records == 2 and o.unconsumed == 1, (o.records, o.unconsumed)
        assert o.stop_cause == "machinery:RuntimeError"
        assert o.machinery == ["RuntimeError: store exploded"]
        assert "machinery" in o.fail_reason

    def test_a_SAVE_that_raises_keeps_the_records_it_fetched(self, tmp_path):
        targets = [sh.IpTarget("1.1.1.1")]
        prov = _Provider(records={"1.1.1.1": _body("1.1.1.1")})
        led = _ledger(tmp_path)
        led.save = lambda *a, **k: (_ for _ in ()).throw(OSError("store exploded"))
        led._journal_lost = True
        o = _run(tmp_path, targets, prov, ledger=led)
        assert o.records == 1 and o.persisted is False
        assert o.machinery == ["OSError: store exploded"]

    def test_a_SUCCESSFUL_save_never_consults_the_fallback(self, tmp_path):
        touched = []
        led = _ledger(tmp_path)

        class _Loud(type(led)):
            @property
            def durable(self):
                touched.append(1)
                raise OSError("fallback exploded")

        led.__class__ = _Loud
        led.save = lambda *a, **k: True
        prov = _Provider(records={"1.1.1.1": _body("1.1.1.1")})
        o = _run(tmp_path, [sh.IpTarget("1.1.1.1")], prov, ledger=led)
        assert touched == [] and o.persisted is True and o.machinery == []

    def test_a_REMAINDER_failure_keeps_the_run(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sh, "_remainder",
                            lambda *a, **k: (_ for _ in ()).throw(ValueError("accounting exploded")))
        prov = _Provider(records={"1.1.1.1": _body("1.1.1.1")})
        o = _run(tmp_path, [sh.IpTarget("1.1.1.1")], prov)
        assert o.records == 1 and o.machinery == ["ValueError: accounting exploded"]

    def test_the_REMAINDER_is_a_snapshot_not_an_accumulator(self, tmp_path):
        targets = [sh.IpTarget("1.1.1.1"), sh.IpTarget("1.1.2.1")]
        o = sh.HostOutcome(eligible=2)
        sh._remainder(targets, o, set(), set())
        first = list(o.not_attempted)
        sh._remainder(targets, o, set(), set())
        assert list(o.not_attempted) == first, o.not_attempted

    def test_CANCELLATION_still_ends_the_run(self, tmp_path):
        prov = _Provider()
        prov.fetch = lambda ip: (_ for _ in ()).throw(KeyboardInterrupt("ctrl-c"))
        with pytest.raises(KeyboardInterrupt):
            _run(tmp_path, [sh.IpTarget("1.1.1.1")], prov)

    def test_a_STORE_we_cannot_write_costs_NO_request_at_all(self, tmp_path, monkeypatch):
        """review-B1.7r5#4: writability was discovered after the first answer came back, so a broken store
        cost a request and discarded what it returned. The probe happens before anything is asked."""
        from quarry_recon import budget
        monkeypatch.setattr(budget, "store_writable", lambda d: False)
        targets = [sh.IpTarget(f"1.1.{b}.1") for b in range(4)]
        prov = _Provider(records={t.ip: _body(t.ip) for t in targets})
        o = _run(tmp_path, targets, prov)
        assert prov.calls == [], f"a broken store still cost requests: {prov.calls}"
        assert o.stop_cause == "publish_failed"
        assert len(o.not_attempted) == 4, o.not_attempted

    def test_a_PUBLISH_that_fails_mid_run_still_stops_asking(self, tmp_path, monkeypatch):
        """The probe cannot promise the store keeps working — a failure after it is still global."""
        from quarry_recon import budget
        real = budget.publish_bytes
        # the write PROBE must succeed — this is the case where the store breaks after it, so the failure
        # is only reachable through a real answer.
        monkeypatch.setattr(budget, "publish_bytes",
                            lambda path, body, **kw: (real(path, body, **kw)
                                                     if path.name == ".quarry-write-probe" else False))
        targets = [sh.IpTarget(f"1.1.{b}.1") for b in range(4)]
        prov = _Provider(records={t.ip: _body(t.ip) for t in targets})
        o = _run(tmp_path, targets, prov)
        assert len(prov.calls) == 1, f"records were fetched we could not keep: {prov.calls}"
        assert o.stop_cause == "publish_failed" and o.publish_failed == 1
        assert len(o.not_attempted) == 3

    def test_a_LEDGER_we_cannot_journal_costs_NO_request_either(self, tmp_path):
        """Both sinks are preconditions, not postconditions: a journal that cannot take a no-op record
        cannot take a completion, and an answer we cannot record is one the next run asks for again."""
        led = _ledger(tmp_path)
        led._append = lambda rec: False                  # even the writability CHECKPOINT fails
        targets = [sh.IpTarget(f"1.1.{b}.1") for b in range(3)]
        prov = _Provider(records={t.ip: _body(t.ip) for t in targets})
        o = _run(tmp_path, targets, prov, ledger=led)
        assert prov.calls == [], f"an unrecordable run still asked: {prov.calls}"
        assert o.stop_cause == "ledger_unwritable"
        assert len(o.not_attempted) == 3

    def test_a_FOREIGN_ledger_costs_NO_request(self, tmp_path):
        led = _ledger(tmp_path)
        led.foreign = True
        prov = _Provider(records={"1.1.1.1": _body("1.1.1.1")})
        o = _run(tmp_path, [sh.IpTarget("1.1.1.1")], prov, ledger=led)
        assert prov.calls == [] and o.stop_cause == "ledger_unwritable"

    def test_a_lifecycle_that_owns_EVERYTHING_never_probes_a_sink(self, tmp_path, monkeypatch):
        """The probe is lazy for the same reason the paid lanes' is: a run with no pending work has no
        reason to touch the store at all."""
        from quarry_recon import budget
        targets = [sh.IpTarget("1.1.1.1")]
        prov = _Provider(records={"1.1.1.1": _body("1.1.1.1")})
        led = _ledger(tmp_path)
        _run(tmp_path, targets, prov, ledger=led)

        probes = []
        monkeypatch.setattr(budget, "store_writable", lambda d: probes.append(d) or True)
        o = _run(tmp_path, targets, prov, ledger=_ledger(tmp_path), attempt="a1")
        assert probes == [], "a replay-only lifecycle probed the store"
        assert o.replayed == 1 and o.attempted == 0

    def test_a_LEDGER_that_cannot_journal_stops_asking(self, tmp_path):
        led = _ledger(tmp_path)
        led._append = lambda rec: "i" not in rec
        targets = [sh.IpTarget(f"1.1.{b}.1") for b in range(4)]
        prov = _Provider(records={t.ip: _body(t.ip) for t in targets})
        o = _run(tmp_path, targets, prov, ledger=led)
        assert o.stop_cause == "ledger_unwritable" and o.records_journaled is False
        assert len(prov.calls) == 1, prov.calls


class TestRecordQualityReachesTheOutcome:
    def test_an_INCOMPLETE_record_is_counted_with_its_parts(self, tmp_path):
        doc = json.loads(_body("1.1.1.1").decode())
        doc["hostnames"] = ["../evil.example.com", "ok.acme.com"]
        doc["asn"] = 1
        prov = _Provider(records={"1.1.1.1": json.dumps(doc).encode()})
        o = _run(tmp_path, [sh.IpTarget("1.1.1.1")], prov)
        assert o.records == 1 and o.incomplete == 1 and o.unusable_parts == 2, o.unusable_parts
        assert o.hostnames == 1

    def test_an_UNUSABLE_body_is_a_parse_failure_not_a_record(self, tmp_path):
        prov = _Provider(records={"1.1.1.1": b"<html>nope</html>"})
        o = _run(tmp_path, [sh.IpTarget("1.1.1.1")], prov)
        assert o.records == 0 and o.fail_classes == {"parse": 1}
        assert "JSON" in o.fail_reason

    def test_VULNS_are_counted_as_the_unverified_leads_they_are(self, tmp_path):
        doc = json.loads(_body("1.1.1.1").decode())
        doc["vulns"] = ["CVE-2021-1234", "CVE-2022-5678"]
        prov = _Provider(records={"1.1.1.1": json.dumps(doc).encode()})
        o = _run(tmp_path, [sh.IpTarget("1.1.1.1")], prov)
        assert o.vulns == 2 and o.records == 1 and o.incomplete == 0


class TestEmptyAnswersAreOwned:
    """review-B1.7r5#1: an empty answer was marked done in memory only, so a run bounded to one request
    asked the same absent address on every resume and never reached the rest of the set."""

    def test_an_EMPTY_answer_is_not_asked_for_twice(self, tmp_path):
        targets = [sh.IpTarget("203.0.113.1")]
        prov = _Provider()                                  # every address answers "no data"
        led = _ledger(tmp_path)
        first = _run(tmp_path, targets, prov, ledger=led)
        assert first.empty == 1 and prov.calls == ["203.0.113.1"]

        second = _run(tmp_path, targets, prov, ledger=_ledger(tmp_path), attempt="a1")
        assert prov.calls == ["203.0.113.1"], f"an owned empty answer was re-asked: {prov.calls}"
        assert second.replayed == 1 and second.empty == 1 and second.attempted == 0

    def test_a_BOUNDED_run_makes_progress_across_lifecycles(self, tmp_path, monkeypatch):
        """The starvation this closes: one request per lifecycle, all answers empty — every run must move
        on to a NEW address instead of re-asking the first."""
        targets = [sh.IpTarget(f"1.1.{b}.1") for b in range(3)]
        prov = _Provider()
        from quarry_recon import budget as _b
        clock = {"t": 0.0}
        monkeypatch.setattr(_b.time, "monotonic", lambda: clock["t"])
        real = prov.fetch

        def slow(ip):
            clock["t"] += 1.0
            return real(ip)

        prov.fetch = slow
        led = _ledger(tmp_path)
        for i in range(3):
            clock["t"] = 0.0
            o = _run(tmp_path, targets, prov, ledger=(led if i == 0 else _ledger(tmp_path)),
                     attempt=f"a{i}", budget_s=1)
            assert o.attempted == 1, (i, o.attempted)
        assert sorted(prov.calls) == sorted(t.ip for t in targets), prov.calls

    def test_the_STORED_answer_re_establishes_the_404_contract(self, tmp_path):
        """Replay has to prove `404 + the measured wording` again, so the stored answer carries the status.
        A bare body could never do that."""
        led = _ledger(tmp_path)
        _run(tmp_path, [sh.IpTarget("203.0.113.1")], _Provider(), ledger=led)
        raw = led.artifact(sh.item_key("203.0.113.1")).read_bytes()
        env = json.loads(raw)
        assert env["http_code"] == 404 and env["ip"] == "203.0.113.1"
        assert env["body"] == '{"error": "No information available for that IP."}'   # VERBATIM
        kind, said = sh.read_stored(raw, ip="203.0.113.1")
        assert kind == sh.HOST_EMPTY and said == "No information available for that IP."

    @pytest.mark.parametrize("mangle,why", [
        ({"schema": 99}, "schema"),
        ({"ip": "8.8.8.8"}, "about"),
        ({"http_code": "404"}, "status"),
        ({"http_code": 200}, "HTTP 200"),       # the wording alone may never mean empty
        ({"body": None}, "body is not a string"),     # the KEY is present; its value is not a body
    ])
    def test_a_STORED_answer_that_cannot_prove_itself_is_refused(self, mangle, why):
        env = {"schema": sh.SHODAN_HOST_SCHEMA, "ip": "203.0.113.1", "http_code": 404,
               "body": '{"error": "No information available for that IP."}'}
        env.update(mangle)
        kind, detail = sh.read_stored(json.dumps(env).encode(), ip="203.0.113.1")
        assert kind == sh.HOST_INVALID, (mangle, kind)
        assert why in detail, detail

    @pytest.mark.parametrize("raw", [b"", b"not json", b"[]", None, 7])
    def test_an_unreadable_STORED_answer_is_refused_without_raising(self, raw):
        kind, why = sh.read_stored(raw, ip="1.1.1.1")
        assert kind == sh.HOST_INVALID and why

    def test_an_owned_answer_that_no_longer_proves_itself_is_asked_again(self, tmp_path):
        import hashlib as _h

        from quarry_recon import budget as _b
        led = _ledger(tmp_path)
        d = tmp_path / "attempts" / "a0"
        d.mkdir(parents=True, exist_ok=True)
        raw = json.dumps({"schema": 99, "ip": "1.1.1.1", "http_code": 404, "body": "{}"}).encode()
        art = d / f"{sh.item_key('1.1.1.1')}.json"
        assert _b.publish_bytes(art, raw, digest=_h.sha256(raw).hexdigest())
        assert led.record(sh.item_key("1.1.1.1"), art, digest=_h.sha256(raw).hexdigest())
        led.save()
        prov = _Provider(records={"1.1.1.1": _body("1.1.1.1")})
        o = _run(tmp_path, [sh.IpTarget("1.1.1.1")], prov, ledger=_ledger(tmp_path), attempt="a1")
        assert o.evidence_invalid == 1 and o.records == 1 and prov.calls == ["1.1.1.1"]


class TestSeenAndConsumedAreDifferentFacts:
    """review-B1.7r5#3: the ingested counters were incremented before `ingest`, so a rejected sink still
    reported `ports=2, hostnames=1` while delivering neither."""

    def test_a_REJECTED_sink_delivers_nothing_and_says_so(self, tmp_path):
        prov = _Provider(records={"1.1.1.1": _body("1.1.1.1", ports=(80, 443))})

        def ingest(target, rec, art, wrote):
            raise RuntimeError("store exploded")

        o = _run(tmp_path, [sh.IpTarget("1.1.1.1")], prov, ingest=ingest)
        assert o.records == 1 and o.ports_seen == 2 and o.hostnames_seen == 1
        assert o.ports == 0 and o.hostnames == 0, (o.ports, o.hostnames)
        assert o.unconsumed == 1

    def test_an_ACCEPTED_sink_makes_the_two_agree(self, tmp_path):
        prov = _Provider(records={"1.1.1.1": _body("1.1.1.1", ports=(80, 443))})
        o = _run(tmp_path, [sh.IpTarget("1.1.1.1")], prov)
        assert (o.ports, o.ports_seen) == (2, 2) and (o.hostnames, o.hostnames_seen) == (1, 1)

    def test_the_split_holds_on_REPLAY_too(self, tmp_path):
        """Fresh and replayed evidence owe the same contract — the third time that rule has bitten."""
        targets = [sh.IpTarget("1.1.1.1")]
        prov = _Provider(records={"1.1.1.1": _body("1.1.1.1", ports=(80, 443))})
        led = _ledger(tmp_path)
        _run(tmp_path, targets, prov, ledger=led)

        def ingest(target, rec, art, wrote):
            raise RuntimeError("store exploded")

        o = _run(tmp_path, targets, prov, ledger=_ledger(tmp_path), attempt="a1", ingest=ingest)
        assert o.replayed == 1 and o.ports_seen == 2 and o.ports == 0 and o.unconsumed == 1


class TestFairnessIsPartOfTheLoop:
    """review-B1.7r5#5: `schedule` was correct and OPTIONAL, so fairness depended on a caller composing it
    — the same "implemented but not integrated" failure this project keeps finding."""

    def test_run_hosts_orders_its_own_input(self, tmp_path):
        dense = [sh.IpTarget(f"1.1.1.{i}") for i in range(1, 6)]
        sparse = [sh.IpTarget("2.2.2.1"), sh.IpTarget("3.3.3.1")]
        prov = _Provider(records={t.ip: _body(t.ip) for t in dense + sparse})
        o = _run(tmp_path, dense + sparse, prov, budget_s=0)
        assert o.eligible == 7 and o.records == 7
        groups = [sh.ip_group(ip) for ip in prov.calls[:3]]
        assert len(set(groups)) == 3, f"the loop asked in the order it was handed: {prov.calls}"

    def test_a_DUPLICATE_target_is_asked_about_once(self, tmp_path):
        targets = [sh.IpTarget("1.1.1.1", hosts=("www.acme.com",)),
                   sh.IpTarget("::ffff:1.1.1.1", hosts=("api.acme.com",))]
        prov = _Provider(records={"1.1.1.1": _body("1.1.1.1")})
        seen = []
        o = _run(tmp_path, targets, prov, ingested=seen)
        assert prov.calls == ["1.1.1.1"], prov.calls
        assert o.eligible == 1 and len(seen) == 1


class TestBareNaabuRowsStayEligible:
    """review-B1.7r5#2: the bare-naabu writer stored only `id`, so those addresses vanished from the
    eligible set entirely."""

    def test_the_PRODUCER_now_stores_structured_fields(self):
        import inspect

        from quarry_recon.phases import probe
        src = inspect.getsource(probe._portscan) if hasattr(probe, "_portscan") else inspect.getsource(probe)
        assert '"id": f"{ip}:{port}", "ip": ip, "port": port,' in src, "the bare-naabu row lost its fields"

    def test_an_OLD_row_with_only_an_id_is_still_eligible(self):
        ctx = _ctx(ports=[{"id": "10.0.0.5:22", "sources": ["naabu"]}], cidrs=["10.0.0.0/24"])
        assert [t.ip for t in sh.eligible_ips(ctx)] == ["10.0.0.5"]

    def test_an_IPv6_composite_id_is_read_at_the_LAST_colon(self):
        ctx = _ctx(ports=[{"id": "2001:db8::1:8443", "sources": ["naabu"]}], cidrs=["2001:db8::/48"])
        assert [t.ip for t in sh.eligible_ips(ctx)] == ["2001:db8::1"]

    @pytest.mark.parametrize("bad", ["", "no-colon", ":22", "not-an-ip:22", None, 7, "1.1.1.1"])
    def test_an_UNUSABLE_id_is_ignored(self, bad):
        ctx = _ctx(ports=[{"id": bad, "sources": ["naabu"]}], cidrs=["0.0.0.0/0"])
        assert sh.eligible_ips(ctx) == []


class TestTheProvidersAnswerIsItsOwnFact:
    """review-B1.7r6#1: `_fold` and the empty counter ran only AFTER `_keep` succeeded, so a mid-run store
    failure reported `records=0`, `ports_seen=0` or `empty=0` about an answer we had in our hands. What the
    provider said, whether we kept it, and whether the sink took it are three facts."""

    def _broken_store(self, monkeypatch):
        from quarry_recon import budget
        real = budget.publish_bytes
        monkeypatch.setattr(budget, "publish_bytes",
                            lambda path, body, **kw: (real(path, body, **kw)
                                                     if path.name == ".quarry-write-probe" else False))

    def test_a_RECORD_we_could_not_store_is_still_a_record_we_received(self, tmp_path, monkeypatch):
        self._broken_store(monkeypatch)
        prov = _Provider(records={"1.1.1.1": _body("1.1.1.1", ports=(80, 443))})
        o = _run(tmp_path, [sh.IpTarget("1.1.1.1")], prov)
        assert o.records == 1, "the answer vanished with the failed write"
        assert o.ports_seen == 2 and o.hostnames_seen == 1
        assert o.ports == 0 and o.hostnames == 0, "unstored evidence was reported as consumed"
        assert o.publish_failed == 1 and o.stop_cause == "publish_failed"

    def test_an_EMPTY_answer_we_could_not_store_is_still_an_answer(self, tmp_path, monkeypatch):
        self._broken_store(monkeypatch)
        prov = _Provider()                                   # every address answers "no data"
        o = _run(tmp_path, [sh.IpTarget("203.0.113.1")], prov)
        assert o.empty == 1, "the no-data answer vanished with the failed write"
        assert o.publish_failed == 1 and o.stop_cause == "publish_failed"

    def test_an_UNSTORED_answer_is_NOT_owned_and_is_asked_again(self, tmp_path, monkeypatch):
        """The three facts stay independent in both directions: counting the answer must not make us claim
        we have it."""
        self._broken_store(monkeypatch)
        prov = _Provider(records={"1.1.1.1": _body("1.1.1.1")})
        led = _ledger(tmp_path)
        first = _run(tmp_path, [sh.IpTarget("1.1.1.1")], prov, ledger=led)
        assert first.records == 1 and first.publish_failed == 1

        monkeypatch.undo()
        second = _run(tmp_path, [sh.IpTarget("1.1.1.1")], prov, ledger=_ledger(tmp_path), attempt="a1")
        assert prov.calls == ["1.1.1.1", "1.1.1.1"], prov.calls
        assert second.replayed == 0 and second.records == 1 and second.persisted

    def test_a_JOURNAL_failure_keeps_the_answer_too(self, tmp_path):
        led = _ledger(tmp_path)
        led._append = lambda rec: "i" not in rec             # the checkpoint passes; completions do not
        prov = _Provider(records={"1.1.1.1": _body("1.1.1.1", ports=(80,))})
        o = _run(tmp_path, [sh.IpTarget("1.1.1.1")], prov, ledger=led)
        assert o.records == 1 and o.ports_seen == 1
        assert o.ports == 0 and o.stop_cause == "ledger_unwritable"


class TestAPortRowMustNameAPort:
    """review-B1.7r6#2: the suffix was skipped over entirely, so `10.0.0.5:not-a-port` qualified an address
    by naming nothing, and a structured row needed no usable `port` at all."""

    @pytest.mark.parametrize("port", [None, 0, 65536, -1, "443", True, False, 3.5, [443]])
    def test_a_STRUCTURED_row_without_a_usable_port_is_not_port_evidence(self, port):
        ctx = _ctx(ports=[{"id": "10.0.0.5:x", "ip": "10.0.0.5", "port": port}], cidrs=["10.0.0.0/24"])
        assert sh.eligible_ips(ctx) == [], port

    def test_a_STRUCTURED_row_WITH_a_port_is(self):
        ctx = _ctx(ports=[{"id": "10.0.0.5:22", "ip": "10.0.0.5", "port": 22}], cidrs=["10.0.0.0/24"])
        assert [t.ip for t in sh.eligible_ips(ctx)] == ["10.0.0.5"]

    @pytest.mark.parametrize("bad", ["10.0.0.5:not-a-port", "10.0.0.5:0", "10.0.0.5:65536",
                                     "10.0.0.5:080", "10.0.0.5: 22", "10.0.0.5:22 ", "10.0.0.5:"])
    def test_a_COMPOSITE_id_with_an_unusable_port_qualifies_nothing(self, bad):
        ctx = _ctx(ports=[{"id": bad, "sources": ["naabu"]}], cidrs=["10.0.0.0/24"])
        assert sh.eligible_ips(ctx) == [], bad

    def test_a_valid_composite_id_still_works(self):
        ctx = _ctx(ports=[{"id": "10.0.0.5:22", "sources": ["naabu"]}], cidrs=["10.0.0.0/24"])
        assert [t.ip for t in sh.eligible_ips(ctx)] == ["10.0.0.5"]

    def test_an_IPv6_composite_id_still_reads_at_the_LAST_colon(self):
        ctx = _ctx(ports=[{"id": "2001:db8::1:8443"}], cidrs=["2001:db8::/48"])
        assert [t.ip for t in sh.eligible_ips(ctx)] == ["2001:db8::1"]


class TestStoredSchemaIsAnExactInteger:
    @pytest.mark.parametrize("schema", [True, False, 1.0, "1", None, [1]])
    def test_a_NON_INTEGER_schema_is_refused(self, schema):
        """review-B1.7r6#3: `schema: true` passed because `True == 1`."""
        env = {"schema": schema, "ip": "1.1.1.1", "http_code": 404,
               "body": '{"error": "No information available for that IP."}'}
        kind, why = sh.read_stored(json.dumps(env).encode(), ip="1.1.1.1")
        assert kind == sh.HOST_INVALID and "schema" in why, (schema, kind)

    def test_the_REAL_schema_is_accepted(self):
        env = {"schema": sh.SHODAN_HOST_SCHEMA, "ip": "1.1.1.1", "http_code": 404,
               "body": '{"error": "No information available for that IP."}'}
        kind, said = sh.read_stored(json.dumps(env).encode(), ip="1.1.1.1")
        assert kind == sh.HOST_EMPTY and said == "No information available for that IP."


# ── B1.7 step 3: the wired lane ───────────────────────────────────────────────────────────────────────
class TestTheWiredLane:
    """`probe.shodan_host` end to end: what it reads, what it writes, where it runs."""

    def _probe_ctx(self, tmp_path, monkeypatch, *, passive=False, hosts=("www.acme.com",),
                   resolved=None, ports=(), key="KEY", records=None, portscan=False):
        from types import SimpleNamespace

        from quarry_recon import events, secrets, settings
        from quarry_recon.phases import probe
        events.reset(); events.configure(tmp_path)
        monkeypatch.setattr(probe.secrets, "shodan", lambda: key)
        monkeypatch.setattr(secrets, "shodan", lambda: key)
        monkeypatch.setattr(settings, "concurrency", lambda k, d=None: 0)
        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 0)
        added, recorded = [], []
        reads = {"resolved": list(resolved if resolved is not None
                                 else [{"host": h, "a": ["1.1.1.1"]} for h in hosts]),
                 "port": list(ports), "web_port": []}
        run = SimpleNamespace(dir=tmp_path, project_dir=tmp_path / "project",
                              add=lambda e, r: (added.append((e, r)), True)[1],
                              read=lambda e: reads.get(e, []),
                              values=lambda e: [r.get("host") for r in reads.get(e, [])],
                              count=lambda e: len(reads.get(e, [])),
                              record=lambda ph, r: recorded.append((ph, r)),
                              raw_path=lambda ph, lb, nm: (tmp_path / ph / lb).joinpath(nm)
                              if (tmp_path / ph / lb).mkdir(parents=True, exist_ok=True) or True else None,
                              notes=[])
        scope = SimpleNamespace(in_scope=lambda h: h.endswith("acme.com"),
                                is_oos=lambda h: h.startswith("oos."),
                                ip_in_scope=lambda ip: False,
                                passive_only=passive,
                                filter_hosts=lambda hs, active=False: [h for h in hs if h])
        prof = SimpleNamespace(ports=[443], portscan=portscan, cidr=[], ratelimit={})
        ctx = SimpleNamespace(run=run, scope=scope, profile=prof, echo=lambda *a: None,
                              http_timeout=20, write_list=lambda n, v: tmp_path / n)

        body = records if records is not None else {"1.1.1.1": _body("1.1.1.1", ports=(80, 443))}

        def urlopen(req, timeout=20):
            url = str(req.full_url)
            ip = url.split("/shodan/host/")[1].split("?")[0]
            raw = body.get(ip)
            if raw is None:
                raise urllib.error.HTTPError(url, 404, "Not Found", {},
                                            io.BytesIO(b'{"error": "No information available for that IP."}'))
            return _Resp(raw)

        monkeypatch.setattr(probe.urllib.request, "urlopen", urlopen)
        return probe, ctx, added, recorded

    def _events(self, tmp_path):
        return [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]

    def _terminal(self, tmp_path):
        from quarry_recon import events as _ev
        return [e for e in self._events(tmp_path)
                if e.get("source_id") == "probe.shodan_host" and e.get("event") == _ev.TOOL_FINISH]

    def test_the_lane_writes_PASSIVE_port_evidence(self, tmp_path, monkeypatch):
        probe, ctx, added, _rec = self._probe_ctx(tmp_path, monkeypatch)
        probe.shodan_host_lane(ctx)
        ports = [r for e, r in added if e == "port"]
        assert {r["port"] for r in ports} == {80, 443}, ports
        for r in ports:
            assert r["passive"] is True, "a Shodan record was written as an active observation"
            assert r["sources"] == ["shodan-host"] and r["ip"] == "1.1.1.1"
            # LIST-valued provenance so a later naabu/nmap observation coexists with this one
            assert isinstance(r["transports"], list) and r["transports"] == ["tcp"]
            assert isinstance(r["modules"], list) and isinstance(r["hosts"], list)
            assert "confirmed" not in r and "state" not in r, r

    def test_a_hostname_goes_to_REVIEW_never_to_resolved_or_subdomain(self, tmp_path, monkeypatch):
        """`resolved`/`subdomain` feed `filter_hosts(active=True)` and everything downstream of it. A name
        in a Shodan record is not proof that DNS resolves it today."""
        probe, ctx, added, _rec = self._probe_ctx(tmp_path, monkeypatch)
        probe.shodan_host_lane(ctx)
        assert not [1 for e, _r in added if e in ("resolved", "subdomain")], added
        names = [r for e, r in added if e == "review" and r["klass"] == "related-host"]
        assert [r["value"] for r in names] == ["a.acme.com"], names
        assert "verify" in names[0]["note"].lower()

    def test_an_IN_SCOPE_hostname_is_still_only_review_evidence(self, tmp_path, monkeypatch):
        probe, ctx, added, _rec = self._probe_ctx(
            tmp_path, monkeypatch,
            records={"1.1.1.1": _body("1.1.1.1", hostnames=("in.acme.com",))})
        probe.shodan_host_lane(ctx)
        assert not [1 for e, _r in added if e in ("resolved", "subdomain")]
        rec = [r for e, r in added if e == "review"][0]
        assert rec["value"] == "in.acme.com" and "IN SCOPE" in rec["note"]

    def test_a_banner_CVE_goes_to_REVIEW_marked_unverified_not_to_finding(self, tmp_path, monkeypatch):
        """`finding` drives the confirmed counters and the notify summary; a banner-inferred CVE is a
        version guess."""
        doc = json.loads(_body("1.1.1.1").decode())
        doc["vulns"] = ["CVE-2021-1234"]
        probe, ctx, added, _rec = self._probe_ctx(tmp_path, monkeypatch,
                                                 records={"1.1.1.1": json.dumps(doc).encode()})
        probe.shodan_host_lane(ctx)
        assert not [1 for e, _r in added if e == "finding"], added
        cve = [r for e, r in added if e == "review" and r["klass"] == "shodan-vuln"]
        assert [r["value"] for r in cve] == ["CVE-2021-1234"]
        assert "UNVERIFIED" in cve[0]["note"]

    def test_NO_KEY_is_a_recorded_skip_not_a_silent_nothing(self, tmp_path, monkeypatch):
        probe, ctx, added, _rec = self._probe_ctx(tmp_path, monkeypatch, key="")
        probe.shodan_host_lane(ctx)
        term = self._terminal(tmp_path)
        assert term and term[0]["status"] == "skipped", term
        assert added == []

    def test_NO_OBSERVED_ADDRESS_is_a_recorded_skip(self, tmp_path, monkeypatch):
        probe, ctx, added, _rec = self._probe_ctx(tmp_path, monkeypatch, resolved=[])
        probe.shodan_host_lane(ctx)
        term = self._terminal(tmp_path)
        assert term and term[0]["status"] == "skipped" and "address" in (term[0].get("reason") or "")

    def test_an_ADDRESS_WITH_NO_RECORD_is_a_clean_lane(self, tmp_path, monkeypatch):
        probe, ctx, added, _rec = self._probe_ctx(tmp_path, monkeypatch, records={})
        probe.shodan_host_lane(ctx)
        term = self._terminal(tmp_path)
        assert term and term[0]["status"] in ("success", "empty"), term
        assert added == []

    def test_the_terminal_reports_a_FREE_lane_with_no_limits(self, tmp_path, monkeypatch):
        probe, ctx, added, _rec = self._probe_ctx(tmp_path, monkeypatch)
        probe.shodan_host_lane(ctx)
        cov = [e for e in self._events(tmp_path)
               if e.get("measure") == "shodan_host_addresses"]
        assert cov and cov[0]["omitted"] == 0, cov
        consumed = [e for e in self._events(tmp_path) if e.get("measure") == "shodan_host_consumed"]
        assert consumed and consumed[0]["omitted"] == 0, consumed

    def test_a_TRANSPORT_failure_is_a_lane_failure_with_a_canonical_class(self, tmp_path, monkeypatch):
        from quarry_recon.contract import PROVIDER_CLASSES
        from quarry_recon.phases import probe as probe_mod
        probe, ctx, added, _rec = self._probe_ctx(tmp_path, monkeypatch)
        monkeypatch.setattr(probe_mod.urllib.request, "urlopen",
                            lambda req, timeout=20: (_ for _ in ()).throw(socket.timeout("timed out")))
        probe.shodan_host_lane(ctx)
        term = self._terminal(tmp_path)
        assert term and term[0]["status"] == "failed", term
        assert term[0].get("error_class") in PROVIDER_CLASSES, term

    def test_the_lane_runs_in_PASSIVE_ONLY_mode(self, tmp_path, monkeypatch):
        """It sends no packet to the target, so the passive-only early return must not be the end of the
        phase — the wiring constraint this restructure exists for."""
        probe, ctx, added, recorded = self._probe_ctx(tmp_path, monkeypatch, passive=True)
        probe.run(ctx)
        assert [r for e, r in added if e == "port"], "the free lane did not run in passive-only mode"
        assert any(res.status.value == "skipped" for _ph, res in recorded), recorded

    def test_the_lane_runs_when_there_is_NOTHING_PROBEABLE(self, tmp_path, monkeypatch):
        probe, ctx, added, recorded = self._probe_ctx(tmp_path, monkeypatch, hosts=())
        probe.run(ctx)
        assert self._terminal(tmp_path), "no lifecycle at all for the free lane"

    def test_the_lane_runs_LAST_on_the_active_path(self, tmp_path, monkeypatch):
        """It consumes `port`/`web_port` rows naabu and smap write, so running it earlier would hand it only
        the resolved set while reporting full coverage of a smaller eligible set."""
        import inspect

        from quarry_recon.phases import probe as probe_mod
        src = inspect.getsource(probe_mod.run)
        tail = src.rsplit("shodan_host_lane(ctx)", 1)[0]
        assert "smap" in tail, "the host lane no longer runs after the port collectors"
        assert src.rstrip().endswith("shodan_host_lane(ctx)"), src[-200:]

    def test_the_source_id_is_REGISTERED(self):
        """`run_provider` is registry-authoritative: an unknown source_id is blocked, not executed."""
        from quarry_recon import sources
        entry = sources.get("probe.shodan_host")
        assert entry, "an unregistered source_id is BLOCKED by run_provider, never executed"
        assert entry["class"] == "passive" and entry["phase"] == "probe"


class TestTheBudgetKnobIsReadStrictly:
    """review-B1.7r7#1: `settings.concurrency` clamps a configured 0 to 1 — right for a worker pool,
    catastrophic for a wall-clock budget, where 0 MEANS unbounded. The tests masked it by replacing the
    accessor, so these drive the REAL settings path."""

    def _perf(self, monkeypatch, value):
        from quarry_recon import settings
        monkeypatch.setattr(settings, "performance", lambda: {"SHODAN_HOST_BUDGET_S": value})
        settings.reset_cache()

    @pytest.mark.parametrize("value", [0, "0", None, ""])
    def test_an_EXPLICIT_ZERO_is_unbounded(self, monkeypatch, value):
        from quarry_recon import budget
        self._perf(monkeypatch, value)
        assert budget.budget_seconds("SHODAN_HOST_BUDGET_S") == 0
        assert budget.Budget(budget.budget_seconds("SHODAN_HOST_BUDGET_S")).unbounded is True

    def test_a_REAL_value_is_honored(self, monkeypatch):
        from quarry_recon import budget
        self._perf(monkeypatch, 90)
        assert budget.budget_seconds("SHODAN_HOST_BUDGET_S") == 90

    def test_the_LANE_reads_it_through_the_strict_parser(self):
        import inspect

        from quarry_recon.phases import probe
        src = inspect.getsource(probe.shodan_host_lane)
        assert 'budget.budget_seconds("SHODAN_HOST_BUDGET_S")' in src, src
        assert "concurrency(\"SHODAN_HOST_BUDGET_S\"" not in src

    def test_the_knob_exists_in_the_template(self):
        import yaml

        from quarry_recon import settings as _s
        tpl = pathlib.Path(_s.__file__).parent / "data" / "config.template.yaml"
        perf = yaml.safe_load(tpl.read_text())["PERFORMANCE"]
        assert "SHODAN_HOST_BUDGET_S" in perf, sorted(perf)
        assert perf["SHODAN_HOST_BUDGET_S"] is None, "the default must be UNSET (= unbounded)"


class TestTheTerminalSpeaksTheProvidersClass:
    """review-B1.7r7#2: the terminal always emitted `error`, so an operator could not tell a refused
    credential from a timeout from an unusable body."""

    @pytest.mark.parametrize("err,want", [
        (lambda u: urllib.error.HTTPError(u, 401, "unauthorized", {}, io.BytesIO(b"<html>bad key</html>")),
         "auth"),
        (lambda u: urllib.error.HTTPError(u, 403, "forbidden", {}, io.BytesIO(b"no")), "forbidden"),
        (lambda u: urllib.error.HTTPError(u, 429, "slow down", {}, io.BytesIO(b"no")), "rate_limit"),
        (lambda u: urllib.error.HTTPError(u, 500, "boom", {}, io.BytesIO(b"no")), "server"),
        (lambda u: socket.timeout("timed out"), "transport"),
    ])
    def test_the_EXACT_class_reaches_the_terminal(self, tmp_path, monkeypatch, err, want):
        from quarry_recon.phases import probe as probe_mod
        wired = TestTheWiredLane()
        probe, ctx, _added, _rec = wired._probe_ctx(tmp_path, monkeypatch)
        monkeypatch.setattr(probe_mod.urllib.request, "urlopen",
                            lambda req, timeout=20: (_ for _ in ()).throw(err(str(req.full_url))))
        probe.shodan_host_lane(ctx)
        term = wired._terminal(tmp_path)
        assert term and term[0]["status"] == "failed", term
        assert term[0].get("error_class") == want, (want, term[0].get("error_class"))

    def test_an_UNUSABLE_BODY_is_a_parse_failure(self, tmp_path, monkeypatch):
        wired = TestTheWiredLane()
        probe, ctx, _added, _rec = wired._probe_ctx(tmp_path, monkeypatch,
                                                   records={"1.1.1.1": b"<html>nope</html>"})
        probe.shodan_host_lane(ctx)
        term = wired._terminal(tmp_path)
        assert term and term[0].get("error_class") == "parse", term

    def test_OUR_OWN_machinery_is_the_one_thing_that_says_error(self, tmp_path, monkeypatch):
        from quarry_recon import budget as _b
        wired = TestTheWiredLane()
        probe, ctx, _added, _rec = wired._probe_ctx(tmp_path, monkeypatch)
        monkeypatch.setattr(_b, "store_writable", lambda d: False)
        probe.shodan_host_lane(ctx)
        term = wired._terminal(tmp_path)
        assert term and term[0].get("error_class") == "error", term

    def test_the_FETCH_never_raises_even_for_an_untaggable_exception(self, tmp_path, monkeypatch):
        """`_shodan_host_get` used to assign `error_class` onto the raised exception, which a `__slots__`
        class refuses — from a function whose contract is "never raises"."""
        from quarry_recon.phases import probe as probe_mod

        class _Immutable(OSError):
            __slots__ = ()

            def __setattr__(self, k, v):
                raise AttributeError("this exception refuses attributes")

        wired = TestTheWiredLane()
        probe, ctx, _added, _rec = wired._probe_ctx(tmp_path, monkeypatch)
        monkeypatch.setattr(probe_mod.urllib.request, "urlopen",
                            lambda req, timeout=20: (_ for _ in ()).throw(_Immutable("nope")))
        probe.shodan_host_lane(ctx)                      # must not raise
        term = wired._terminal(tmp_path)
        assert term and term[0]["status"] == "failed", term
        # the PROVIDER's class, from a fetch that returned an error rather than throwing one: an OSError is
        # `transport`. `error` here would mean our own machinery caught the assignment blowing up.
        assert term[0].get("error_class") == "transport", term
        assert "machinery" not in json.dumps(term), term


class TestPartialIngestionCountsWhatLANDED:
    """review-B1.7r7#3: counting after `ingest` RETURNED made a partial write invisible — the first port
    stored, the second raising, and the run reporting `ports=0` about a port that is in the store."""

    def test_a_write_that_fails_HALFWAY_still_counts_what_was_stored(self, tmp_path):
        prov = _Provider(records={"1.1.1.1": _body("1.1.1.1", ports=(80, 443, 8443))})
        stored = []

        def ingest(target, rec, art, wrote):
            for obs in rec.ports:
                if len(stored) >= 2:
                    raise RuntimeError("store exploded")
                stored.append(obs.port)
                wrote(sh.WROTE_PORT)

        o = _run(tmp_path, [sh.IpTarget("1.1.1.1")], prov, ingest=ingest)
        assert len(stored) == 2, stored
        assert o.ports == 2, f"stored ports were reported as unstored: {o.ports}"
        assert o.ports_seen == 3 and o.unconsumed == 1

    def test_a_sink_that_stores_NOTHING_reports_nothing(self, tmp_path):
        prov = _Provider(records={"1.1.1.1": _body("1.1.1.1", ports=(80, 443))})

        def ingest(target, rec, art, wrote):
            raise RuntimeError("store exploded")

        o = _run(tmp_path, [sh.IpTarget("1.1.1.1")], prov, ingest=ingest)
        assert o.ports == 0 and o.ports_seen == 2 and o.unconsumed == 1

    def test_the_LANES_OWN_writer_counts_every_kind(self, tmp_path, monkeypatch):
        doc = json.loads(_body("1.1.1.1", ports=(80, 443)).decode())
        doc["vulns"] = ["CVE-2021-1234"]
        wired = TestTheWiredLane()
        probe, ctx, added, _rec = wired._probe_ctx(tmp_path, monkeypatch,
                                                  records={"1.1.1.1": json.dumps(doc).encode()})
        probe.shodan_host_lane(ctx)
        kinds = [e for e, _r in added]
        assert kinds.count("port") == 2 and kinds.count("review") == 2, kinds


class TestOnePortRowHoldsEveryObservation:
    """review-B1.7r7#4: the store keys a `port` on `ip:port`, so 53/tcp and 53/udp are ONE row — writing
    them as two adds meant the second was dropped and its `tls`/`observed_at` lost, leaving the row saying
    `tls=False` about a service that had TLS."""

    def _row(self, tmp_path, monkeypatch, banners):
        doc = json.loads(_body("1.1.1.1", ports=(53,)).decode())
        doc["data"] = banners
        doc["ports"] = [53]
        wired = TestTheWiredLane()
        probe, ctx, added, _rec = wired._probe_ctx(tmp_path, monkeypatch,
                                                  records={"1.1.1.1": json.dumps(doc).encode()})
        probe.shodan_host_lane(ctx)
        rows = [r for e, r in added if e == "port"]
        assert len(rows) == 1, rows
        return rows[0]

    def test_BOTH_transports_are_kept_in_one_row(self, tmp_path, monkeypatch):
        row = self._row(tmp_path, monkeypatch, [
            {"port": 53, "transport": "tcp", "_shodan": {"module": "dns-tcp"},
             "timestamp": "2026-07-01T00:00:00"},
            {"port": 53, "transport": "udp", "_shodan": {"module": "dns-udp"},
             "timestamp": "2026-07-29T00:00:00", "ssl": {"cipher": "x"}}])
        assert row["transports"] == ["tcp", "udp"], row
        assert row["modules"] == ["dns-tcp", "dns-udp"], row
        assert {o["transport"] for o in row["observations"]} == {"tcp", "udp"}, row

    @pytest.mark.parametrize("order", [0, 1])
    def test_TLS_and_the_LATEST_sighting_do_not_depend_on_banner_order(self, tmp_path, monkeypatch, order):
        plain = {"port": 53, "transport": "tcp", "_shodan": {}, "timestamp": "2026-07-01T00:00:00"}
        tls = {"port": 53, "transport": "udp", "_shodan": {}, "timestamp": "2026-07-29T00:00:00",
               "ssl": {"cipher": "x"}}
        row = self._row(tmp_path, monkeypatch, [plain, tls] if order == 0 else [tls, plain])
        assert row["tls"] is True, "a TLS observation was lost to banner order"
        assert row["observed_at"] == "2026-07-29T00:00:00", row["observed_at"]

    def test_the_row_still_reports_PASSIVE_provenance(self, tmp_path, monkeypatch):
        row = self._row(tmp_path, monkeypatch, [{"port": 53, "transport": "tcp", "_shodan": {},
                                                 "timestamp": "2026-07-01T00:00:00"}])
        assert row["passive"] is True and row["sources"] == ["shodan-host"]
        assert row["observations"] == [{"transport": "tcp", "module": "", "tls": False,
                                       "seen": "2026-07-01T00:00:00"}]


class TestSelectionAndOutcomeAreSeparate:
    """review-B1.7r7#5: one COVERAGE_TIMEOUT measure conflated "did we get to it" with "did it answer", so
    a run where EVERY request failed reported "all addresses answered"."""

    def _cov(self, tmp_path, measure):
        wired = TestTheWiredLane()
        return [e for e in wired._events(tmp_path) if e.get("measure") == measure]

    def test_a_BUDGET_remainder_is_a_hard_CAP_not_a_soft_sample(self, tmp_path, monkeypatch):
        from quarry_recon import budget as _b, events, settings
        wired = TestTheWiredLane()
        probe, ctx, _added, _rec = wired._probe_ctx(
            tmp_path, monkeypatch,
            resolved=[{"host": "www.acme.com", "a": [f"1.1.{b}.1" for b in range(4)]}],
            records={f"1.1.{b}.1": _body(f"1.1.{b}.1") for b in range(4)})
        monkeypatch.setattr(settings, "performance", lambda: {"SHODAN_HOST_BUDGET_S": 2})
        settings.reset_cache()
        clock = {"t": 0.0}
        monkeypatch.setattr(_b.time, "monotonic", lambda: clock["t"])
        real = probe.urllib.request.urlopen

        def slow(req, timeout=20):
            clock["t"] += 1.0
            return real(req, timeout=timeout)

        monkeypatch.setattr(probe.urllib.request, "urlopen", slow)
        probe.shodan_host_lane(ctx)
        sel = self._cov(tmp_path, "shodan_host_addresses")
        assert sel and sel[0]["kind"] == events.COVERAGE_CAP, sel
        assert sel[0]["omitted"] == 2, sel
        assert "RESUMABLE" in sel[0]["reason"], sel[0]["reason"]

    def test_a_run_where_EVERY_REQUEST_FAILED_does_not_claim_answers(self, tmp_path, monkeypatch):
        from quarry_recon import events
        from quarry_recon.phases import probe as probe_mod
        wired = TestTheWiredLane()
        probe, ctx, _added, _rec = wired._probe_ctx(tmp_path, monkeypatch)
        monkeypatch.setattr(probe_mod.urllib.request, "urlopen",
                            lambda req, timeout=20: (_ for _ in ()).throw(socket.timeout("timed out")))
        probe.shodan_host_lane(ctx)
        sel = self._cov(tmp_path, "shodan_host_addresses")
        out = self._cov(tmp_path, "shodan_host_answers")
        assert sel and sel[0]["omitted"] == 0, "the address WAS reached"
        assert out and out[0]["omitted"] == 1 and out[0]["tested"] == 0, out
        assert out[0]["kind"] == events.COVERAGE_TIMEOUT and "transport" in out[0]["reason"], out

    def test_a_CLEAN_run_reports_both_measures_with_no_loss(self, tmp_path, monkeypatch):
        wired = TestTheWiredLane()
        probe, ctx, _added, _rec = wired._probe_ctx(tmp_path, monkeypatch)
        probe.shodan_host_lane(ctx)
        for measure in ("shodan_host_addresses", "shodan_host_answers", "shodan_host_consumed"):
            cov = self._cov(tmp_path, measure)
            assert cov and cov[0]["omitted"] == 0, (measure, cov)


class TestSelectionFollowsTheActualStop:
    """review-B1.7r8#1: every remainder was filed as COVERAGE_CAP, so a five-address run stopped by the
    first 401 reported that a `0s` budget had been exhausted."""

    def _cov(self, tmp_path, measure):
        wired = TestTheWiredLane()
        return [e for e in wired._events(tmp_path) if e.get("measure") == measure]

    def _five(self, tmp_path, monkeypatch, urlopen):
        from quarry_recon.phases import probe as probe_mod
        wired = TestTheWiredLane()
        probe, ctx, _added, _rec = wired._probe_ctx(
            tmp_path, monkeypatch,
            resolved=[{"host": "www.acme.com", "a": [f"1.1.{b}.1" for b in range(5)]}])
        monkeypatch.setattr(probe_mod.urllib.request, "urlopen", urlopen)
        probe.shodan_host_lane(ctx)
        return wired

    def test_an_AUTH_stop_is_a_gap_that_names_itself_not_a_budget_cap(self, tmp_path, monkeypatch):
        from quarry_recon import events

        def refused(req, timeout=20):
            raise urllib.error.HTTPError(str(req.full_url), 401, "unauthorized", {},
                                        io.BytesIO(b"<html>bad key</html>"))

        wired = self._five(tmp_path, monkeypatch, refused)
        sel = self._cov(tmp_path, "shodan_host_addresses")
        assert sel and sel[0]["omitted"] == 4, sel
        assert sel[0]["kind"] == events.COVERAGE_TIMEOUT, sel[0]["kind"]
        assert "budget" not in sel[0]["reason"], sel[0]["reason"]
        assert "auth" in sel[0]["reason"], sel[0]["reason"]
        term = wired._terminal(tmp_path)
        assert term and term[0].get("error_class") == "auth", term

    def test_a_BUDGET_stop_is_still_a_cap(self, tmp_path, monkeypatch):
        from quarry_recon import budget as _b, events, settings
        from quarry_recon.phases import probe as probe_mod
        wired = TestTheWiredLane()
        probe, ctx, _added, _rec = wired._probe_ctx(
            tmp_path, monkeypatch,
            resolved=[{"host": "www.acme.com", "a": [f"1.1.{b}.1" for b in range(5)]}],
            records={f"1.1.{b}.1": _body(f"1.1.{b}.1") for b in range(5)})
        monkeypatch.setattr(settings, "performance", lambda: {"SHODAN_HOST_BUDGET_S": 2})
        settings.reset_cache()
        clock = {"t": 0.0}
        monkeypatch.setattr(_b.time, "monotonic", lambda: clock["t"])
        real = probe_mod.urllib.request.urlopen

        def slow(req, timeout=20):
            clock["t"] += 1.0
            return real(req, timeout=timeout)

        monkeypatch.setattr(probe_mod.urllib.request, "urlopen", slow)
        probe.shodan_host_lane(ctx)
        sel = self._cov(tmp_path, "shodan_host_addresses")
        assert sel and sel[0]["kind"] == events.COVERAGE_CAP and sel[0]["omitted"] == 3, sel

    def test_a_BUDGET_stop_carries_NO_machinery_class(self, tmp_path, monkeypatch):
        """An operator bound is not a defect of ours."""
        from quarry_recon import budget as _b, settings
        from quarry_recon.phases import probe as probe_mod
        wired = TestTheWiredLane()
        probe, ctx, _added, _rec = wired._probe_ctx(
            tmp_path, monkeypatch,
            resolved=[{"host": "www.acme.com", "a": [f"1.1.{b}.1" for b in range(4)]}],
            records={f"1.1.{b}.1": _body(f"1.1.{b}.1") for b in range(4)})
        monkeypatch.setattr(settings, "performance", lambda: {"SHODAN_HOST_BUDGET_S": 2})
        settings.reset_cache()
        clock = {"t": 0.0}
        monkeypatch.setattr(_b.time, "monotonic", lambda: clock["t"])
        real = probe_mod.urllib.request.urlopen

        def slow(req, timeout=20):
            clock["t"] += 1.0
            return real(req, timeout=timeout)

        monkeypatch.setattr(probe_mod.urllib.request, "urlopen", slow)
        probe.shodan_host_lane(ctx)
        term = wired._terminal(tmp_path)
        assert term and term[0]["status"] == "partial", term
        assert term[0].get("error_class") in (None, ""), term
        assert "machinery" not in json.dumps(term), term
        # ...and the REASON is the remainder, not a report about our own machinery having stopped
        reason = term[0].get("reason") or ""
        assert reason.startswith("2 address(es) not reached"), reason
        assert "evidence KEPT" not in reason and "stopped:" not in reason, reason

    def test_a_STORE_stop_is_a_gap_naming_the_store(self, tmp_path, monkeypatch):
        from quarry_recon import budget as _b, events
        wired = TestTheWiredLane()
        probe, ctx, _added, _rec = wired._probe_ctx(
            tmp_path, monkeypatch,
            resolved=[{"host": "www.acme.com", "a": [f"1.1.{b}.1" for b in range(3)]}])
        monkeypatch.setattr(_b, "store_writable", lambda d: False)
        probe.shodan_host_lane(ctx)
        sel = self._cov(tmp_path, "shodan_host_addresses")
        assert sel and sel[0]["kind"] == events.COVERAGE_TIMEOUT, sel
        assert "publish_failed" in sel[0]["reason"] and "budget" not in sel[0]["reason"], sel


class TestGroupedPortsDoNotFabricateAGap:
    """review-B1.7r8#2: `_fold` counts per (port, transport) while the grouped writer wrote one row, so a
    clean host with 53/tcp and 53/udp reported `ports_seen=2, ports=1` and one invented omission."""

    def _run_two_transports(self, tmp_path, monkeypatch):
        doc = json.loads(_body("1.1.1.1", ports=(53,)).decode())
        doc["data"] = [{"port": 53, "transport": "tcp", "_shodan": {"module": "dns-tcp"},
                        "timestamp": "2026-07-01T00:00:00"},
                       {"port": 53, "transport": "udp", "_shodan": {"module": "dns-udp"},
                        "timestamp": "2026-07-02T00:00:00"}]
        doc["ports"] = [53]
        wired = TestTheWiredLane()
        probe, ctx, added, _rec = wired._probe_ctx(tmp_path, monkeypatch,
                                                  records={"1.1.1.1": json.dumps(doc).encode()})
        probe.shodan_host_lane(ctx)
        return wired, added

    def test_a_clean_two_transport_host_reports_NO_consumption_gap(self, tmp_path, monkeypatch):
        wired, added = self._run_two_transports(tmp_path, monkeypatch)
        cov = [e for e in wired._events(tmp_path) if e.get("measure") == "shodan_host_consumed"]
        assert cov and cov[0]["omitted"] == 0, cov
        assert cov[0]["eligible"] == 2 and cov[0]["tested"] == 2, cov
        assert len([r for e, r in added if e == "port"]) == 1, added

    def test_the_terminal_is_CLEAN_for_that_host(self, tmp_path, monkeypatch):
        wired, _added = self._run_two_transports(tmp_path, monkeypatch)
        term = wired._terminal(tmp_path)
        assert term and term[0]["status"] in ("success", "empty"), term


class TestClassAndReasonAreOnePair:
    """review-B1.7r8#3: the terminal picked the most frequent class while quoting the FIRST failure's
    sentence, and a repeated soft limit could outrank a real failure."""

    def test_the_reason_is_about_the_class_it_names(self, tmp_path):
        o = sh.HostOutcome(eligible=3)
        sh._count_fail(o, "transport", "connection died")
        sh._count_fail(o, "server", "500 one")
        sh._count_fail(o, "server", "500 two")
        from quarry_recon.phases import probe
        cls, reason = probe._shodan_host_class(o)
        assert cls == "server" and "500 one" in reason, (cls, reason)
        assert "connection died" not in reason

    def test_a_REAL_failure_outranks_a_REPEATED_soft_limit(self):
        """Gaps dominate limits: two quotas plus one transport must not report `quota` — which
        `_partial_status` would then turn into LIMITED."""
        from quarry_recon.contract import is_provider_limit
        from quarry_recon.phases import probe
        o = sh.HostOutcome(eligible=3)
        sh._count_fail(o, "quota", "credits gone")
        sh._count_fail(o, "quota", "credits gone again")
        sh._count_fail(o, "transport", "connection died")
        cls, reason = probe._shodan_host_class(o)
        assert cls == "transport" and not is_provider_limit(cls), cls
        assert "connection died" in reason, reason

    def test_a_LIMIT_ONLY_run_still_reports_the_limit(self):
        from quarry_recon.phases import probe
        o = sh.HostOutcome(eligible=1)
        sh._count_fail(o, "quota", "credits gone")
        cls, reason = probe._shodan_host_class(o)
        assert cls == "quota" and "credits gone" in reason

    def test_a_TIE_is_broken_deterministically(self):
        from quarry_recon.phases import probe
        for order in (("server", "transport"), ("transport", "server")):
            o = sh.HostOutcome(eligible=2)
            for c in order:
                sh._count_fail(o, c, f"{c} happened")
            cls, _r = probe._shodan_host_class(o)
            assert cls == "transport", (order, cls)

    def test_NO_failure_means_no_class(self):
        from quarry_recon.phases import probe
        assert probe._shodan_host_class(sh.HostOutcome(eligible=1)) == (None, "")


class TestThePacingContractSurvivesTheCarrier:
    """review-B1.7r8#4: the carrier forwarded `code` and `body_bytes` but not `headers`, so every real 429
    ignored the `Retry-After` the provider actually sent and fell back to a flat 5s."""

    def test_a_REAL_429_is_paced_by_its_RETRY_AFTER(self, tmp_path, monkeypatch):
        from email.message import Message

        from quarry_recon.phases import probe as probe_mod
        waited = []
        hdrs = Message()
        hdrs["Retry-After"] = "7"

        wired = TestTheWiredLane()
        probe, ctx, _added, _rec = wired._probe_ctx(
            tmp_path, monkeypatch,
            resolved=[{"host": "www.acme.com", "a": ["1.1.1.1", "1.1.2.1"]}])

        def limited(req, timeout=20):
            raise urllib.error.HTTPError(str(req.full_url), 429, "slow down", hdrs, io.BytesIO(b"slow"))

        monkeypatch.setattr(probe_mod.urllib.request, "urlopen", limited)
        monkeypatch.setattr(probe_mod._time, "sleep", lambda s: waited.append(s))
        probe.shodan_host_lane(ctx)
        assert waited, "a 429 was not honored at all"
        assert max(waited) > 5.0, f"Retry-After was discarded, fell back to the flat default: {waited}"

    def test_the_error_still_carries_the_body_and_code(self, monkeypatch):
        from quarry_recon.phases import probe as probe_mod

        def refused(req, timeout=20):
            raise urllib.error.HTTPError(str(req.full_url), 404, "Not Found", {},
                                        io.BytesIO(b'{"error": "No information available for that IP."}'))

        monkeypatch.setattr(probe_mod.urllib.request, "urlopen", refused)
        raw, code, err = probe_mod._shodan_host_get("https://api.shodan.io/shodan/host/1.1.1.1?key=x", 5)
        assert raw == b"" and err is not None and code == 404
        assert err.code == 404 and err.error_class in ("http", "auth", "error"), err.error_class
        assert sh.empty_or_raise(err, ip="1.1.1.1") == "No information available for that IP."

    def test_an_HTTPError_that_REJECTS_ATTRIBUTES_does_not_escape(self, monkeypatch):
        """`capture_error_body` stamps `body_text`/`error_class` onto the exception, and a raise-site helper
        whose contract is "never raises" must survive an exception that refuses them."""
        from quarry_recon.phases import probe as probe_mod

        class _Immutable(urllib.error.HTTPError):
            def __setattr__(self, k, v):
                if k in ("body_text", "error_class", "body_bytes"):
                    raise AttributeError("this exception refuses attributes")
                super().__setattr__(k, v)

        def refused(req, timeout=20):
            raise _Immutable(str(req.full_url), 500, "boom", {}, io.BytesIO(b"nope"))

        monkeypatch.setattr(probe_mod.urllib.request, "urlopen", refused)
        raw, code, err = probe_mod._shodan_host_get("https://api.shodan.io/shodan/host/1.1.1.1?key=x", 5)
        assert raw == b"" and err is not None and err.error_class == "server", err
        assert code == 500, code


class TestTheProvidersStatusIsNotAssumed:
    """review-B1.7r9#1: the adapter returned bytes only, so any success was ASSUMED to be 200 and stored as
    200 — an HTTP 201 with a valid-looking body was accepted as the measured contract and owned."""

    def test_a_201_with_a_valid_body_FAILS_CLOSED_and_stays_unowned(self, tmp_path):
        prov = _Provider(records={"1.1.1.1": _body("1.1.1.1")}, code=201)
        led = _ledger(tmp_path)
        o = _run(tmp_path, [sh.IpTarget("1.1.1.1")], prov, ledger=led)
        assert o.records == 0 and o.fail_classes == {"parse": 1}, (o.records, o.fail_classes)
        assert "HTTP 201" in o.fail_reason, o.fail_reason
        assert not _ledger(tmp_path).has(sh.item_key("1.1.1.1")), "an unmeasured status was OWNED"

    def test_the_CONTROL_200_is_accepted(self, tmp_path):
        prov = _Provider(records={"1.1.1.1": _body("1.1.1.1")}, code=200)
        o = _run(tmp_path, [sh.IpTarget("1.1.1.1")], prov)
        assert o.records == 1 and o.fail_classes == {}

    def test_the_REAL_adapter_reports_the_response_status(self, monkeypatch):
        from quarry_recon.phases import probe as probe_mod
        monkeypatch.setattr(probe_mod.urllib.request, "urlopen",
                            lambda req, timeout=20: _Resp(_body("1.1.1.1"), status=201))
        raw, code, err = probe_mod._shodan_host_get("https://api.shodan.io/shodan/host/1.1.1.1?key=x", 5)
        assert err is None and code == 201 and raw, (code, err)

    def test_the_WIRED_lane_refuses_a_201(self, tmp_path, monkeypatch):
        from quarry_recon.phases import probe as probe_mod
        wired = TestTheWiredLane()
        probe, ctx, added, _rec = wired._probe_ctx(tmp_path, monkeypatch)
        monkeypatch.setattr(probe_mod.urllib.request, "urlopen",
                            lambda req, timeout=20: _Resp(_body("1.1.1.1"), status=201))
        probe.shodan_host_lane(ctx)
        assert added == [], "an unmeasured status produced evidence"
        term = wired._terminal(tmp_path)
        assert term and term[0].get("error_class") == "parse", term


class TestSweepProgressIsDurableAcrossRuns:
    """review-B1.7r9#2: ownership is run-scoped by design, but `Run.create()` makes a FRESH directory every
    invocation — so under a nonzero budget every run started from an empty ledger, asked the same
    deterministic prefix, and the tail was never reached."""

    def _project(self, tmp_path):
        from quarry_recon import store
        (tmp_path / "project").mkdir(parents=True, exist_ok=True)
        return tmp_path / "project", store

    def test_a_bounded_sweep_ADVANCES_across_DISTINCT_runs(self, tmp_path, monkeypatch):
        from quarry_recon import budget as _b
        project, store = self._project(tmp_path)
        targets = [sh.IpTarget(f"1.1.{b}.1") for b in range(3)]
        prov = _Provider(records={t.ip: _body(t.ip) for t in targets})
        clock = {"t": 0.0}
        monkeypatch.setattr(_b.time, "monotonic", lambda: clock["t"])
        real = prov.fetch

        def slow(ip):
            clock["t"] += 1.0
            return real(ip)

        prov.fetch = slow
        for i in range(3):
            run = store.Run.create(project, "acme.com")           # a REAL new run directory each time
            clock["t"] = 0.0
            d = run.dir / "attempts"
            d.mkdir(parents=True, exist_ok=True)
            o = sh.run_hosts(targets, fetch=prov.fetch,
                             ingest=lambda t, rec, art, wrote: None,
                             ledger=_ledger(run.dir), attempt_dir=d, bound=_b.Budget(1),
                             progress=sh.SweepProgress(sh.progress_path(project)))
            assert o.attempted == 1, (i, o.attempted)
            assert o.replayed == 0, "a fresh run replayed evidence it could not have"
        assert sorted(prov.calls) == sorted(t.ip for t in targets), prov.calls

    def test_an_UNBOUNDED_run_still_refreshes_everything(self, tmp_path):
        """Progress ORDERS; it must never make an address permanently skipped — the records are live."""
        from quarry_recon import budget as _b, store
        project, _s = self._project(tmp_path)
        targets = [sh.IpTarget(f"1.1.{b}.1") for b in range(3)]
        prov = _Provider(records={t.ip: _body(t.ip) for t in targets})
        progress = sh.SweepProgress(sh.progress_path(project))
        for _ in range(2):
            run = store.Run.create(project, "acme.com")
            d = run.dir / "attempts"
            d.mkdir(parents=True, exist_ok=True)
            o = sh.run_hosts(targets, fetch=prov.fetch, ingest=lambda t, rec, art, wrote: None,
                             ledger=_ledger(run.dir), attempt_dir=d, bound=_b.Budget(0),
                             progress=sh.SweepProgress(sh.progress_path(project)))
            assert o.attempted == 3, o.attempted
        assert len(prov.calls) == 6, prov.calls
        assert progress is not None

    def test_the_LONGEST_UNASKED_address_goes_first(self):
        progress = sh.SweepProgress(None)
        progress.asked = {"1.1.1.1": 300.0, "1.1.2.1": 100.0, "1.1.3.1": 200.0}
        order = [t.ip for t in sh.schedule([sh.IpTarget(ip) for ip in
                                            ("1.1.1.1", "1.1.2.1", "1.1.3.1", "1.1.4.1")], progress)]
        assert order[0] == "1.1.4.1", f"a never-asked address did not go first: {order}"
        assert order[1:] == ["1.1.2.1", "1.1.3.1", "1.1.1.1"], order

    def test_the_progress_file_lives_OUTSIDE_any_run_directory(self, tmp_path):
        p = sh.progress_path(tmp_path / "project")
        assert "recon" in p.parts and "state" in p.parts
        assert p.parent.name == f"v{sh.SweepProgress.SCHEMA}"

    @pytest.mark.parametrize("junk", [b"", b"not json", b"[]", b'{"schema": 99, "asked": {}}',
                                      b'{"schema": 1, "asked": "nope"}',
                                      b'{"schema": 1, "asked": {"nope": "x"}}'])
    def test_an_unusable_progress_file_costs_ORDERING_never_coverage(self, tmp_path, junk):
        p = sh.progress_path(tmp_path / "project")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(junk)
        progress = sh.SweepProgress(p)
        assert progress.asked == {}, progress.asked
        order = [t.ip for t in sh.schedule([sh.IpTarget("1.1.1.1"), sh.IpTarget("2.2.2.1")], progress)]
        assert sorted(order) == ["1.1.1.1", "2.2.2.1"], order

    def test_an_UNWRITABLE_progress_file_is_reported_not_fatal(self, tmp_path):
        from quarry_recon import budget as _b
        progress = sh.SweepProgress(sh.progress_path(tmp_path / "project"))
        progress.save = lambda: False
        prov = _Provider(records={"1.1.1.1": _body("1.1.1.1")})
        o = _run(tmp_path, [sh.IpTarget("1.1.1.1")], prov, progress=progress)
        assert o.records == 1 and o.progress_saved is False and o.machinery == []

    def test_progress_is_recorded_when_the_REQUEST_is_issued_not_when_it_succeeds(self, tmp_path):
        """The next run must rotate past an address we already spent a request on, whatever came back."""
        progress = sh.SweepProgress(sh.progress_path(tmp_path / "project"))
        prov = _Provider(errors={"1.1.1.1": _err("server")})
        _run(tmp_path, [sh.IpTarget("1.1.1.1")], prov, progress=progress)
        assert "1.1.1.1" in progress.asked, progress.asked


class TestAProductiveLaneIsNotEmpty:
    """review-B1.7r9#3: `run_provider` read status from a hostname set this lane never fills, so a run that
    stored ports and review rows was recorded `status=empty, produced.host=0`."""

    def test_a_stored_record_is_SUCCESS_with_real_produced_counts(self, tmp_path, monkeypatch):
        doc = json.loads(_body("1.1.1.1", ports=(80, 443)).decode())
        doc["vulns"] = ["CVE-2021-1234"]
        wired = TestTheWiredLane()
        probe, ctx, _added, _rec = wired._probe_ctx(tmp_path, monkeypatch,
                                                   records={"1.1.1.1": json.dumps(doc).encode()})
        probe.shodan_host_lane(ctx)
        term = wired._terminal(tmp_path)
        assert term and term[0]["status"] == "success", term
        assert term[0]["produced"] == {"port": 2, "review": 2}, term[0]["produced"]
        assert "host" not in term[0]["produced"], "a hostname count was fabricated"

    def test_a_measured_404_ONLY_is_EMPTY(self, tmp_path, monkeypatch):
        wired = TestTheWiredLane()
        probe, ctx, added, _rec = wired._probe_ctx(tmp_path, monkeypatch, records={})
        probe.shodan_host_lane(ctx)
        term = wired._terminal(tmp_path)
        assert term and term[0]["status"] == "empty", term
        assert term[0]["produced"] == {"port": 0, "review": 0}, term[0]["produced"]
        assert added == []

    def test_the_LEDGER_event_carries_the_structured_facts(self, tmp_path, monkeypatch):
        wired = TestTheWiredLane()
        probe, ctx, _added, _rec = wired._probe_ctx(tmp_path, monkeypatch)
        probe.shodan_host_lane(ctx)
        led = [e for e in wired._events(tmp_path)
               if e.get("event") == "ledger" and e.get("source_id") == "probe.shodan_host"]
        assert led, wired._events(tmp_path)
        meta = led[0]["shodan_host"]
        assert meta["records"] == 1 and meta["eligible"] == 1 and meta["attempted"] == 1
        assert led[0]["produced"] == {"port": 2, "review": 1}, led[0]["produced"]
        assert led[0]["consumed"] == {"address": 1}, led[0]["consumed"]


class TestMalformedPartsReachTheVerdict:
    """review-B1.7r9#4: `incomplete`/`unusable_parts` existed only in metadata nothing emitted, so a record
    with a valid port and a malformed hostname was owned and reported clean."""

    def _run_malformed(self, tmp_path, monkeypatch):
        doc = json.loads(_body("1.1.1.1", ports=(443,)).decode())
        doc["hostnames"] = ["../evil.example.com", "ok.acme.com"]
        doc["asn"] = 13335                                    # an int where a string was measured
        wired = TestTheWiredLane()
        probe, ctx, added, _rec = wired._probe_ctx(tmp_path, monkeypatch,
                                                  records={"1.1.1.1": json.dumps(doc).encode()})
        probe.shodan_host_lane(ctx)
        return wired, added

    def test_the_VALID_evidence_is_still_kept(self, tmp_path, monkeypatch):
        _wired, added = self._run_malformed(tmp_path, monkeypatch)
        assert [r["port"] for e, r in added if e == "port"] == [443], added
        assert [r["value"] for e, r in added if e == "review"] == ["ok.acme.com"], added

    def test_the_terminal_is_PARTIAL_with_a_parse_class(self, tmp_path, monkeypatch):
        wired, _added = self._run_malformed(tmp_path, monkeypatch)
        term = wired._terminal(tmp_path)
        assert term and term[0]["status"] == "partial", term
        assert term[0].get("error_class") == "parse", term
        assert "unusable part" in (term[0].get("reason") or ""), term[0].get("reason")

    def test_coverage_names_the_unusable_parts(self, tmp_path, monkeypatch):
        wired, _added = self._run_malformed(tmp_path, monkeypatch)
        cov = [e for e in wired._events(tmp_path) if e.get("measure") == "shodan_host_record_parts"]
        # RECORD units: one record came back incomplete. The PART count explains it in the reason — records
        # and parts cannot share a denominator (review-B1.7r10#6).
        assert cov and cov[0]["omitted"] == 1 and cov[0]["eligible"] == 1, cov
        assert "2 part(s) we could not read" in cov[0]["reason"], cov[0]["reason"]

    def test_a_CLEAN_record_reports_no_parts_gap(self, tmp_path, monkeypatch):
        wired = TestTheWiredLane()
        probe, ctx, _added, _rec = wired._probe_ctx(tmp_path, monkeypatch)
        probe.shodan_host_lane(ctx)
        cov = [e for e in wired._events(tmp_path) if e.get("measure") == "shodan_host_record_parts"]
        assert cov and cov[0]["omitted"] == 0, cov


class TestAProvenLimitIsALimit:
    """review-B1.7r9#5: `should_stop` excluded quota/entitlement, so a body-proven limit was asked of every
    address, and the coverage said timeout — a LIMITED terminal reconciling as `complete_with_gaps`."""

    QUOTA = ("Insufficient query credits, please upgrade your API plan or wait for the monthly "
             "limit to reset")

    def _quota_lane(self, tmp_path, monkeypatch, extra=None):
        from quarry_recon.phases import probe as probe_mod
        wired = TestTheWiredLane()
        probe, ctx, added, _rec = wired._probe_ctx(
            tmp_path, monkeypatch,
            resolved=[{"host": "www.acme.com", "a": [f"1.1.{b}.1" for b in range(4)]}])
        seen = []

        def urlopen(req, timeout=20):
            url = str(req.full_url)
            seen.append(url)
            if extra is not None and len(seen) == 1:
                raise extra(url)
            raise urllib.error.HTTPError(url, 401, "unauthorized", {},
                                        io.BytesIO(json.dumps({"error": self.QUOTA}).encode()))

        monkeypatch.setattr(probe_mod.urllib.request, "urlopen", urlopen)
        probe.shodan_host_lane(ctx)
        return wired, seen

    def test_exactly_ONE_refused_request_and_the_rest_are_counted(self, tmp_path, monkeypatch):
        wired, seen = self._quota_lane(tmp_path, monkeypatch)
        assert len(seen) == 1, f"a proven limit was fanned out: {seen}"
        cov = [e for e in wired._events(tmp_path) if e.get("measure") == "shodan_host_addresses"]
        assert cov and cov[0]["omitted"] == 3, cov

    def test_the_terminal_is_LIMITED_with_the_proven_class(self, tmp_path, monkeypatch):
        wired, _seen = self._quota_lane(tmp_path, monkeypatch)
        term = wired._terminal(tmp_path)
        assert term and term[0]["status"] == "limited", term
        assert term[0].get("error_class") == "quota", term

    def test_the_coverage_is_PROVIDER_kind_not_timeout(self, tmp_path, monkeypatch):
        from quarry_recon import events
        wired, _seen = self._quota_lane(tmp_path, monkeypatch)
        for measure in ("shodan_host_addresses", "shodan_host_refused"):
            cov = [e for e in wired._events(tmp_path) if e.get("measure") == measure]
            assert cov and cov[0]["kind"] == events.COVERAGE_PROVIDER, (measure, cov)
        refused = [e for e in wired._events(tmp_path) if e.get("measure") == "shodan_host_refused"]
        assert refused[0]["omitted"] == 1 and "quota" in refused[0]["reason"], refused
        # ...and the GAP measure exists too, reporting no gap: the two kinds never share a unit
        answers = [e for e in wired._events(tmp_path) if e.get("measure") == "shodan_host_answers"]
        assert answers and answers[0]["omitted"] == 0, answers

    def test_a_SIMULTANEOUS_transport_failure_still_dominates(self, tmp_path, monkeypatch):
        """Gaps dominate limits — and the limit fact is not destroyed by that. NOTHING was obtained here, so
        the terminal is a FAILURE rather than a partial: the class is what the finding is about."""
        wired, seen = self._quota_lane(tmp_path, monkeypatch,
                                       extra=lambda u: socket.timeout("timed out"))
        term = wired._terminal(tmp_path)
        assert term and term[0]["status"] == "failed", term
        assert term[0].get("error_class") == "transport", "a soft limit outranked a real failure"
        assert "quota" in (term[0].get("reason") or ""), "the limit fact was discarded by the gap"

    def test_with_EVIDENCE_the_same_pair_is_a_PARTIAL_gap(self, tmp_path, monkeypatch):
        """Evidence KEPT plus a gap plus a limit: PARTIAL, the gap's class, the limit still stated."""
        from quarry_recon.phases import probe as probe_mod
        wired = TestTheWiredLane()
        probe, ctx, added, _rec = wired._probe_ctx(
            tmp_path, monkeypatch,
            resolved=[{"host": "www.acme.com", "a": [f"1.1.{b}.1" for b in range(4)]}])
        seen = []

        def urlopen(req, timeout=20):
            url = str(req.full_url)
            seen.append(url)
            ip = url.split("/shodan/host/")[1].split("?")[0]
            if len(seen) == 1:
                return _Resp(_body(ip))                       # one real record first
            if len(seen) == 2:
                raise socket.timeout("timed out")
            raise urllib.error.HTTPError(url, 401, "unauthorized", {},
                                        io.BytesIO(json.dumps({"error": self.QUOTA}).encode()))

        monkeypatch.setattr(probe_mod.urllib.request, "urlopen", urlopen)
        probe.shodan_host_lane(ctx)
        term = wired._terminal(tmp_path)
        assert term and term[0]["status"] == "partial", term
        assert term[0].get("error_class") == "transport", term
        assert "quota" in (term[0].get("reason") or ""), term[0].get("reason")
        assert [r for e, r in added if e == "port"], "the record we DID get was discarded"


class TestFailureBodiesAreRetainedRetryably:
    """review-B1.7r9-P2: the paid lanes keep the bytes behind a refusal so an operator can see what the
    provider said and an unmeasured class is diagnosable later. Free work owes the same — and evidence is
    never ownership, so the address stays retryable."""

    def test_a_REFUSAL_body_is_kept_as_evidence_not_a_completion(self, tmp_path):
        err = RuntimeError("HTTP Error 401: unauthorized")
        err.code = 401
        err.error_class = "auth"
        err.body_bytes = b'{"error": "Invalid API key"}'
        led = _ledger(tmp_path)
        o = _run(tmp_path, [sh.IpTarget("1.1.1.1")], _Provider(errors={"1.1.1.1": err}), ledger=led)
        assert o.error_bodies == 1, o.error_bodies
        reopened = _ledger(tmp_path)
        assert not reopened.has(sh.item_key("1.1.1.1")), "a refusal was recorded as an ANSWER"
        assert reopened.evidence(sh.error_key("1.1.1.1")), "the refusal body was not retained"

    def test_an_UNUSABLE_SUCCESS_body_is_kept_too(self, tmp_path):
        led = _ledger(tmp_path)
        o = _run(tmp_path, [sh.IpTarget("1.1.1.1")], _Provider(records={"1.1.1.1": b"<html>nope</html>"}),
                 ledger=led)
        assert o.error_bodies == 1 and o.fail_classes == {"parse": 1}
        reopened = _ledger(tmp_path)
        assert not reopened.has(sh.item_key("1.1.1.1"))
        kept = reopened.evidence(sh.error_key("1.1.1.1"))
        assert kept and b"nope" in kept[0].read_bytes()

    def test_the_retained_body_uses_a_DISTINCT_namespace(self):
        assert sh.error_key("1.1.1.1") != sh.item_key("1.1.1.1")

    def test_an_address_with_a_kept_failure_is_ASKED_AGAIN(self, tmp_path):
        led = _ledger(tmp_path)
        prov = _Provider(records={"1.1.1.1": b"<html>nope</html>"})
        _run(tmp_path, [sh.IpTarget("1.1.1.1")], prov, ledger=led)
        prov.records = {"1.1.1.1": _body("1.1.1.1")}
        o = _run(tmp_path, [sh.IpTarget("1.1.1.1")], prov, ledger=_ledger(tmp_path), attempt="a1")
        assert o.records == 1 and prov.calls == ["1.1.1.1", "1.1.1.1"], prov.calls

    def test_NO_BODY_means_nothing_to_retain(self, tmp_path):
        o = _run(tmp_path, [sh.IpTarget("1.1.1.1")],
                 _Provider(errors={"1.1.1.1": _err("transport")}))
        assert o.error_bodies == 0 and o.fail_classes == {"transport": 1}


class TestProgressIsLockedAndStrict:
    """review-B1.7r10#1: no lock and one shared `.tmp` name — two runs on a project could publish a torn
    document or silently discard each other's rotation, and an unusable timestamp could pin an address to
    one end of the sweep forever."""

    def test_two_PROCESSES_do_not_lose_each_others_progress(self, tmp_path):
        path = sh.progress_path(tmp_path / "project")
        a, b = sh.SweepProgress(path), sh.SweepProgress(path)
        a.note("1.1.1.1", 100.0)
        b.note("2.2.2.2", 200.0)
        assert a.save() and b.save()                        # b saw an empty file when it loaded
        merged = sh.SweepProgress(path)
        assert merged.asked == {"1.1.1.1": 100.0, "2.2.2.2": 200.0}, merged.asked

    def test_a_LATER_ask_wins_the_merge(self, tmp_path):
        path = sh.progress_path(tmp_path / "project")
        first = sh.SweepProgress(path)
        first.note("1.1.1.1", 100.0)
        assert first.save()
        second = sh.SweepProgress(path)
        second.note("1.1.1.1", 500.0)
        assert second.save()
        assert sh.SweepProgress(path).asked == {"1.1.1.1": 500.0}
        # ...and an OLDER ask cannot pull it back up the rotation
        stale = sh.SweepProgress(path)
        stale.asked = {"1.1.1.1": 1.0}
        assert stale.save()
        assert sh.SweepProgress(path).asked == {"1.1.1.1": 500.0}

    def test_no_TEMP_FILE_is_left_behind(self, tmp_path):
        path = sh.progress_path(tmp_path / "project")
        p = sh.SweepProgress(path)
        p.note("1.1.1.1", 100.0)
        assert p.save()
        leftovers = [q.name for q in path.parent.iterdir() if q.name.endswith(".tmp")]
        assert leftovers == [], leftovers

    @pytest.mark.parametrize("schema", [True, False, 1.0, "1", None])
    def test_a_NON_INTEGER_schema_is_refused(self, tmp_path, schema):
        path = sh.progress_path(tmp_path / "project")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"schema": schema, "asked": {"1.1.1.1": 100.0}}))
        assert sh.SweepProgress(path).asked == {}, schema

    @pytest.mark.parametrize("when", [-1.0, -0.0001, float("nan"), float("inf"), float("-inf"),
                                      True, False, "100", None, [100]])
    def test_an_UNUSABLE_timestamp_orders_nothing(self, tmp_path, when):
        """NaN makes every comparison false, so it sorts unpredictably; an infinity pins an address to one
        end of the rotation for good; a negative time is a clock we cannot reason about."""
        path = sh.progress_path(tmp_path / "project")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"schema": sh.SweepProgress.SCHEMA,
                                    "asked": {"1.1.1.1": when, "2.2.2.2": 5.0}}, allow_nan=True))
        loaded = sh.SweepProgress(path)
        assert loaded.asked == {"2.2.2.2": 5.0}, (when, loaded.asked)

    def test_note_REFUSES_an_unusable_time_too(self, tmp_path):
        p = sh.SweepProgress(sh.progress_path(tmp_path / "project"))
        for bad in (float("nan"), float("inf"), -5.0, True, "now"):
            p.note("1.1.1.1", bad)
        assert p.asked == {}, p.asked

    def test_a_LOST_progress_save_means_the_remainder_is_NOT_resumable(self, tmp_path, monkeypatch):
        """A bounded run that could not record its rotation restarts from the same prefix — calling that
        remainder RESUMABLE is the false promise `report_selection`'s `durable` flag exists to prevent."""
        from quarry_recon import budget as _b, settings
        from quarry_recon.phases import probe as probe_mod
        wired = TestTheWiredLane()
        probe, ctx, _added, _rec = wired._probe_ctx(
            tmp_path, monkeypatch,
            resolved=[{"host": "www.acme.com", "a": [f"1.1.{b}.1" for b in range(4)]}],
            records={f"1.1.{b}.1": _body(f"1.1.{b}.1") for b in range(4)})
        monkeypatch.setattr(settings, "performance", lambda: {"SHODAN_HOST_BUDGET_S": 2})
        settings.reset_cache()
        clock = {"t": 0.0}
        monkeypatch.setattr(_b.time, "monotonic", lambda: clock["t"])
        real = probe_mod.urllib.request.urlopen

        def slow(req, timeout=20):
            clock["t"] += 1.0
            return real(req, timeout=timeout)

        monkeypatch.setattr(probe_mod.urllib.request, "urlopen", slow)
        monkeypatch.setattr(sh.SweepProgress, "save", lambda self: False)
        probe.shodan_host_lane(ctx)
        sel = [e for e in wired._events(tmp_path) if e.get("measure") == "shodan_host_addresses"]
        assert sel and sel[0]["omitted"] == 2, sel
        assert "RESUMABLE" not in sel[0]["reason"], sel[0]["reason"]
        assert "RESTARTS" in sel[0]["reason"], sel[0]["reason"]


class TestErrorEvidenceIsByteSafe:
    """review-B1.7r10#2: the envelope decoded STRICTLY, so a non-UTF-8 refusal became a machinery failure
    and was never retained — and a retention failure was invisible behind the provider's boundary."""

    def test_a_NON_UTF8_body_is_retained_verbatim(self, tmp_path):
        err = RuntimeError("HTTP Error 500: boom")
        err.code = 500
        err.error_class = "server"
        err.body_bytes = b"\xff\xfe\x00garbage"
        led = _ledger(tmp_path)
        o = _run(tmp_path, [sh.IpTarget("1.1.1.1")], _Provider(errors={"1.1.1.1": err}), ledger=led)
        assert o.machinery == [], f"a non-text body became a machinery failure: {o.machinery}"
        assert o.error_bodies == 1 and o.fail_classes == {"server": 1}
        kept = _ledger(tmp_path).evidence(sh.error_key("1.1.1.1"))
        assert kept, "the refusal was not retained"
        env = json.loads(kept[0].read_text())
        import base64
        assert base64.b64decode(env["body_b64"]) == b"\xff\xfe\x00garbage", env

    def test_a_TEXT_body_stays_readable_in_the_artifact(self, tmp_path):
        err = RuntimeError("HTTP Error 401: unauthorized")
        err.code = 401
        err.error_class = "auth"
        err.body_bytes = b'{"error": "Invalid API key"}'
        led = _ledger(tmp_path)
        _run(tmp_path, [sh.IpTarget("1.1.1.1")], _Provider(errors={"1.1.1.1": err}), ledger=led)
        env = json.loads(_ledger(tmp_path).evidence(sh.error_key("1.1.1.1"))[0].read_text())
        assert env["body"] == '{"error": "Invalid API key"}' and "body_b64" not in env

    def test_a_base64_ROUND_TRIP_reads_back_as_the_measured_answer(self):
        raw = sh.store_envelope("203.0.113.1", 404, b'{"error": "No information available for that IP."}')
        kind, said = sh.read_stored(raw, ip="203.0.113.1")
        assert kind == sh.HOST_EMPTY and said == "No information available for that IP."

    def test_an_UNREADABLE_base64_body_is_refused(self):
        env = {"schema": sh.SHODAN_HOST_SCHEMA, "ip": "1.1.1.1", "http_code": 404, "body_b64": "!!!not!!!"}
        kind, why = sh.read_stored(json.dumps(env).encode(), ip="1.1.1.1")
        assert kind == sh.HOST_INVALID and "base64" in why, why

    def test_a_RETENTION_failure_stops_the_run_and_outranks_the_limit(self, tmp_path, monkeypatch):
        """A quota body we could not store must not finish as a clean provider limit — our evidence loss is
        a gap, and it outranks their boundary."""
        from quarry_recon import budget as _b
        real = _b.publish_bytes
        monkeypatch.setattr(_b, "publish_bytes",
                            lambda path, body, **kw: (real(path, body, **kw)
                                                     if path.name == ".quarry-write-probe" else False))
        err = RuntimeError("HTTP Error 401: unauthorized")
        err.code = 401
        err.error_class = "quota"
        err.body_bytes = b'{"error": "Insufficient query credits"}'
        targets = [sh.IpTarget(f"1.1.{b}.1") for b in range(4)]
        prov = _Provider(errors={t.ip: err for t in targets})
        o = _run(tmp_path, targets, prov)
        assert len(prov.calls) == 1, f"we kept asking for evidence we could not keep: {prov.calls}"
        assert o.stop_cause == "publish_failed", o.stop_cause
        assert o.error_bodies == 0 and o.publish_failed == 1

    def test_the_WIRED_terminal_names_OUR_gap_not_their_limit(self, tmp_path, monkeypatch):
        from quarry_recon import budget as _b
        from quarry_recon.phases import probe as probe_mod
        wired = TestTheWiredLane()
        probe, ctx, _added, _rec = wired._probe_ctx(tmp_path, monkeypatch)
        real = _b.publish_bytes
        monkeypatch.setattr(_b, "publish_bytes",
                            lambda path, body, **kw: (real(path, body, **kw)
                                                     if path.name == ".quarry-write-probe" else False))
        quota = ("Insufficient query credits, please upgrade your API plan or wait for the monthly "
                 "limit to reset")
        monkeypatch.setattr(probe_mod.urllib.request, "urlopen",
                            lambda req, timeout=20: (_ for _ in ()).throw(
                                urllib.error.HTTPError(str(req.full_url), 401, "unauthorized", {},
                                                       io.BytesIO(json.dumps({"error": quota}).encode()))))
        probe.shodan_host_lane(ctx)
        term = wired._terminal(tmp_path)
        assert term and term[0]["status"] == "failed", term
        assert term[0].get("error_class") == "error", "the provider's limit hid our own evidence loss"
        assert "retain" in (term[0].get("reason") or ""), term[0].get("reason")


class TestMixedLimitsAreStructured:
    """review-B1.7r10#3: `provider_limit` was hard-coded False and one outcome measure could carry one
    kind, so in a transport-then-quota run the limit survived only in prose."""

    QUOTA = ("Insufficient query credits, please upgrade your API plan or wait for the monthly "
             "limit to reset")

    def _mixed(self, tmp_path, monkeypatch):
        from quarry_recon.phases import probe as probe_mod
        wired = TestTheWiredLane()
        probe, ctx, added, _rec = wired._probe_ctx(
            tmp_path, monkeypatch,
            resolved=[{"host": "www.acme.com", "a": ["1.1.1.1", "1.1.2.1"]}])
        seen = []

        def urlopen(req, timeout=20):
            url = str(req.full_url)
            seen.append(url)
            if len(seen) == 1:
                raise socket.timeout("timed out")
            raise urllib.error.HTTPError(url, 401, "unauthorized", {},
                                        io.BytesIO(json.dumps({"error": self.QUOTA}).encode()))

        monkeypatch.setattr(probe_mod.urllib.request, "urlopen", urlopen)
        probe.shodan_host_lane(ctx)
        return wired, seen

    def test_BOTH_facts_survive_with_no_remainder_at_all(self, tmp_path, monkeypatch):
        wired, seen = self._mixed(tmp_path, monkeypatch)
        assert len(seen) == 2, seen                          # both addresses attempted; nothing unqueried
        led = [e for e in wired._events(tmp_path)
               if e.get("event") == "ledger" and e.get("source_id") == "probe.shodan_host"]
        assert led, wired._events(tmp_path)
        meta = led[0]["shodan_host"]
        assert meta["provider_limit"] is True, "the limit was not structured"
        assert meta["limit_classes"] == {"quota": 1}, meta["limit_classes"]
        assert meta["gap_classes"] == {"transport": 1}, meta["gap_classes"]

    def test_the_two_KINDS_get_their_own_units(self, tmp_path, monkeypatch):
        from quarry_recon import events
        wired, _seen = self._mixed(tmp_path, monkeypatch)
        answers = [e for e in wired._events(tmp_path) if e.get("measure") == "shodan_host_answers"]
        refused = [e for e in wired._events(tmp_path) if e.get("measure") == "shodan_host_refused"]
        assert answers and answers[0]["kind"] == events.COVERAGE_TIMEOUT and answers[0]["omitted"] == 1
        assert refused and refused[0]["kind"] == events.COVERAGE_PROVIDER and refused[0]["omitted"] == 1
        assert answers[0]["unit"] != refused[0]["unit"], "one unit would overwrite the other"

    def test_the_GAP_still_dominates_the_terminal_class(self, tmp_path, monkeypatch):
        wired, _seen = self._mixed(tmp_path, monkeypatch)
        term = wired._terminal(tmp_path)
        assert term and term[0].get("error_class") == "transport", term


class TestProducedCountsCannotLie:
    """review-B1.7r10#4: booleans, negatives, strings and floats were accepted, and `{}` was turned back
    into None — resurrecting the fabricated `{"host": 0}` fallback."""

    @pytest.mark.parametrize("bad", [{"port": True}, {"port": -2}, {"port": "3"}, {"port": 1.0},
                                     {"port": None}, {"": 1}, {1: 1}, "nope", 7, [("port", 1)]])
    def test_an_IMPOSSIBLE_count_is_refused(self, bad):
        from quarry_recon.contract import ProviderResult
        with pytest.raises(ValueError):
            ProviderResult(produced=bad)

    def test_an_EXPLICIT_EMPTY_dict_is_preserved(self):
        """A lane that genuinely produced nothing said so; turning that back into None resurrected the
        hostname fallback."""
        from quarry_recon.contract import ProviderResult
        assert ProviderResult(produced={}).produced == {}

    def test_ABSENT_produced_keeps_the_hostname_behaviour(self):
        from quarry_recon.contract import ProviderResult
        assert ProviderResult({"a.example.com"}).produced is None

    def test_a_VALID_count_is_kept_exactly(self):
        from quarry_recon.contract import ProviderResult
        assert ProviderResult(produced={"port": 0, "review": 3}).produced == {"port": 0, "review": 3}


class TestCountersDoNotMixUnits:
    """review-B1.7r10#5: observations were reported as entity rows, refused requests as consumed, and an
    answer whose persistence failed as completed."""

    def test_a_GROUPED_row_is_ONE_produced_entity(self, tmp_path, monkeypatch):
        doc = json.loads(_body("1.1.1.1", ports=(53,)).decode())
        doc["data"] = [{"port": 53, "transport": "tcp", "_shodan": {}, "timestamp": "2026-07-01T00:00:00"},
                       {"port": 53, "transport": "udp", "_shodan": {}, "timestamp": "2026-07-02T00:00:00"}]
        doc["ports"] = [53]
        wired = TestTheWiredLane()
        probe, ctx, added, _rec = wired._probe_ctx(tmp_path, monkeypatch,
                                                  records={"1.1.1.1": json.dumps(doc).encode()})
        probe.shodan_host_lane(ctx)
        assert len([r for e, r in added if e == "port"]) == 1, added
        term = wired._terminal(tmp_path)
        assert term[0]["produced"]["port"] == 1, term[0]["produced"]
        led = [e for e in wired._events(tmp_path) if e.get("event") == "ledger"][0]
        assert led["shodan_host"]["port_rows"] == 1 and led["shodan_host"]["port_observations"] == 2

    def test_a_REFUSED_request_consumed_nothing(self, tmp_path, monkeypatch):
        quota = ("Insufficient query credits, please upgrade your API plan or wait for the monthly "
                 "limit to reset")
        from quarry_recon.phases import probe as probe_mod
        wired = TestTheWiredLane()
        probe, ctx, _added, _rec = wired._probe_ctx(tmp_path, monkeypatch)
        monkeypatch.setattr(probe_mod.urllib.request, "urlopen",
                            lambda req, timeout=20: (_ for _ in ()).throw(
                                urllib.error.HTTPError(str(req.full_url), 401, "unauthorized", {},
                                                       io.BytesIO(json.dumps({"error": quota}).encode()))))
        probe.shodan_host_lane(ctx)
        led = [e for e in wired._events(tmp_path) if e.get("event") == "ledger"][0]
        assert led["consumed"] == {"address": 0}, led["consumed"]
        assert led["shodan_host"]["completed"] == 0, led["shodan_host"]

    def test_an_answer_we_could_not_PERSIST_is_not_completed(self, tmp_path, monkeypatch):
        from quarry_recon import budget as _b
        from quarry_recon.phases import probe as probe_mod
        wired = TestTheWiredLane()
        probe, ctx, _added, _rec = wired._probe_ctx(tmp_path, monkeypatch)
        real = _b.publish_bytes
        monkeypatch.setattr(_b, "publish_bytes",
                            lambda path, body, **kw: (real(path, body, **kw)
                                                     if path.name == ".quarry-write-probe" else False))
        probe.shodan_host_lane(ctx)
        led = [e for e in wired._events(tmp_path) if e.get("event") == "ledger"][0]
        meta = led["shodan_host"]
        assert meta["answered"] == 1, meta                    # the provider DID answer
        assert meta["owned"] == 0 and meta["completed"] == 0, meta
        assert led["consumed"] == {"address": 0}, led["consumed"]


class TestTheProgressWriteIsSerialisedAndPrivate:
    """The lock and the per-process temp name are not observable from a single-threaded assertion about
    CONTENT, so they are pinned on the mechanism itself — and by a real two-process run."""

    def test_the_write_happens_UNDER_the_lock(self, tmp_path, monkeypatch):
        order = []
        real_open, real_release, real_replace = sh._open_lock, sh._release, sh.os.replace

        monkeypatch.setattr(sh, "_open_lock",
                            lambda path, **kw: (order.append("lock"), real_open(path, **kw))[1])
        monkeypatch.setattr(sh, "_release", lambda fh: (order.append("unlock"), real_release(fh))[1])
        monkeypatch.setattr(sh.os, "replace",
                            lambda src, dst, **kw: (order.append("replace"), real_replace(src, dst, **kw))[1]
                            if str(dst).endswith("sweep.json") else real_replace(src, dst))
        p = sh.SweepProgress(sh.progress_path(tmp_path / "project"))
        p.note("1.1.1.1", 100.0)
        assert p.save()
        assert order == ["lock", "replace", "unlock"], order

    def test_the_TEMP_NAME_is_private_to_this_process(self, tmp_path, monkeypatch):
        """A shared `<name>.tmp` lets two processes write one file and publish a torn document."""
        srcs = []
        real_replace = sh.os.replace
        monkeypatch.setattr(sh.os, "replace",
                            lambda src, dst, **kw: (srcs.append(str(src)), real_replace(src, dst, **kw))[1])
        path = sh.progress_path(tmp_path / "project")
        for when in (100.0, 200.0):
            p = sh.SweepProgress(path)
            p.note("1.1.1.1", when)
            assert p.save()
        assert len(srcs) == 2 and srcs[0] != srcs[1], srcs
        assert all(str(sh.os.getpid()) in s for s in srcs), srcs
        assert not any(s.endswith(f"{path.name}.tmp") for s in srcs), srcs


class TestOwnedAnswersIncludeTheEmptyOnes:
    def test_a_404_ONLY_run_reports_it_as_completed_and_consumed(self, tmp_path, monkeypatch):
        """A measured "no data" IS an answer we own — it is stored, journaled and never asked again."""
        wired = TestTheWiredLane()
        probe, ctx, _added, _rec = wired._probe_ctx(tmp_path, monkeypatch, records={})
        probe.shodan_host_lane(ctx)
        led = [e for e in wired._events(tmp_path) if e.get("event") == "ledger"][0]
        meta = led["shodan_host"]
        assert meta["empty"] == 1 and meta["answered"] == 1
        assert meta["owned"] == 1 and meta["completed"] == 1, meta
        assert led["consumed"] == {"address": 1}, led["consumed"]

    def test_an_EMPTY_answer_we_could_not_store_is_answered_but_NOT_owned(self, tmp_path, monkeypatch):
        from quarry_recon import budget as _b
        wired = TestTheWiredLane()
        probe, ctx, _added, _rec = wired._probe_ctx(tmp_path, monkeypatch, records={})
        real = _b.publish_bytes
        monkeypatch.setattr(_b, "publish_bytes",
                            lambda path, body, **kw: (real(path, body, **kw)
                                                     if path.name == ".quarry-write-probe" else False))
        probe.shodan_host_lane(ctx)
        led = [e for e in wired._events(tmp_path) if e.get("event") == "ledger"][0]
        meta = led["shodan_host"]
        assert meta["empty"] == 1 and meta["answered"] == 1
        assert meta["owned"] == 0 and meta["completed"] == 0, meta


class TestTheGapMeasureCountsONLYGaps:
    def test_a_LIMIT_is_not_named_in_the_gap_measure(self, tmp_path, monkeypatch):
        """review-B1.7r10#3: `report_outcome` given every class listed the quota in the timeout bucket's own
        reason — the same conflation, one level down."""
        mixed = TestMixedLimitsAreStructured()
        wired, _seen = mixed._mixed(tmp_path, monkeypatch)
        answers = [e for e in wired._events(tmp_path) if e.get("measure") == "shodan_host_answers"]
        assert answers and answers[0]["omitted"] == 1, answers
        assert "transport" in answers[0]["reason"], answers[0]["reason"]
        assert "quota" not in answers[0]["reason"], answers[0]["reason"]
        refused = [e for e in wired._events(tmp_path) if e.get("measure") == "shodan_host_refused"]
        assert "quota" in refused[0]["reason"] and "transport" not in refused[0]["reason"], refused


class TestTheLockHelperNeverSwallowsTheBody:
    """review-B1.7r11#1: acquisition and the protected BODY shared one `try`, so an `OSError` from the body
    was caught by the helper, which yielded a SECOND time — `RuntimeError: generator didn't stop after
    throw()`. A best-effort save became a machinery failure."""

    def test_a_failing_REPLACE_is_a_False_save_not_an_exception(self, tmp_path, monkeypatch):
        real = sh.os.replace
        monkeypatch.setattr(sh.os, "replace",
                            lambda src, dst, **kw: ((_ for _ in ()).throw(OSError("read-only filesystem"))
                                              if str(dst).endswith("sweep.json") else real(src, dst, **kw)))
        p = sh.SweepProgress(sh.progress_path(tmp_path / "project"))
        p.note("1.1.1.1", 100.0)
        assert p.save() is False

    def test_a_failing_WRITE_is_a_False_save_not_an_exception(self, tmp_path, monkeypatch):
        real = pathlib.Path.write_text

        def boom(self, *a, **k):
            if self.name.endswith(".tmp"):
                raise OSError("no space left on device")
            return real(self, *a, **k)

        monkeypatch.setattr(pathlib.Path, "write_text", boom)
        p = sh.SweepProgress(sh.progress_path(tmp_path / "project"))
        p.note("1.1.1.1", 100.0)
        assert p.save() is False

    def test_a_failing_save_is_reported_WITHOUT_machinery(self, tmp_path, monkeypatch):
        # NB `sh.os` IS the os module, so a blanket patch breaks the artifact store too — fail ONLY the
        # progress write, which is what this test is about.
        real = sh.os.replace
        monkeypatch.setattr(sh.os, "replace",
                            lambda src, dst, **kw: ((_ for _ in ()).throw(OSError("read-only filesystem"))
                                              if str(dst).endswith("sweep.json") else real(src, dst, **kw)))
        prov = _Provider(records={"1.1.1.1": _body("1.1.1.1")})
        o = _run(tmp_path, [sh.IpTarget("1.1.1.1")], prov,
                 progress=sh.SweepProgress(sh.progress_path(tmp_path / "project")))
        assert o.records == 1 and o.progress_saved is False
        assert o.machinery == [] and o.stop_cause == "", (o.machinery, o.stop_cause)

    def test_the_helper_yields_EXACTLY_once_when_the_body_raises(self, tmp_path):
        """The direct reproduction: a context manager that yields twice raises from the `with` itself."""
        path = sh.progress_path(tmp_path / "project")
        with pytest.raises(OSError):
            with sh._progress_lock(path):
                raise OSError("the body failed")


class TestSelectionIsAClaim:
    """review-B1.7r11#2: locking only the MERGE preserved both runs' records and still let both SELECT the
    same address — each loaded the file before either saved, so each saw it as never-asked."""

    def test_a_SECOND_session_is_refused_while_the_first_holds_it(self, tmp_path):
        path = sh.progress_path(tmp_path / "project")
        with sh.sweep_session(path) as first:
            assert first.held is True
            with pytest.raises(sh.SweepBusy):
                with sh.sweep_session(path):
                    pass

    def test_the_session_is_released_afterwards(self, tmp_path):
        path = sh.progress_path(tmp_path / "project")
        with sh.sweep_session(path) as p:
            p.note("1.1.1.1", 100.0)
            assert p.save()
        with sh.sweep_session(path) as second:                # no contention once the first has finished
            assert second.asked == {"1.1.1.1": 100.0}

    def test_the_session_is_released_even_when_the_body_RAISES(self, tmp_path):
        path = sh.progress_path(tmp_path / "project")
        with pytest.raises(ValueError):
            with sh.sweep_session(path):
                raise ValueError("the lane blew up")
        with sh.sweep_session(path):                          # still acquirable
            pass

    def test_the_WIRED_lane_declines_rather_than_duplicating_work(self, tmp_path, monkeypatch):
        """A second run must not re-select what the first is sweeping — and review-B1.7r12#1: declining is a
        local GAP, not a skip. Evidence is run-scoped, so this run receives none of the holder's records;
        their eligible sets can differ; and the holder may fail before covering anything."""
        from quarry_recon.phases import probe as probe_mod
        wired = TestTheWiredLane()
        probe, ctx, added, _rec = wired._probe_ctx(tmp_path, monkeypatch)
        calls = []
        real = probe_mod.urllib.request.urlopen
        monkeypatch.setattr(probe_mod.urllib.request, "urlopen",
                            lambda req, timeout=20: (calls.append(str(req.full_url)),
                                                     real(req, timeout=timeout))[1])
        with sh.sweep_session(sh.progress_path(ctx.run.project_dir)):
            probe.shodan_host_lane(ctx)
        assert calls == [], f"a contended run still queried: {calls}"
        assert added == []
        # review-B1.7r13#1: FAILED, not partial — PARTIAL asserts evidence was produced before degradation,
        # and this run produced nothing and inherited nothing (the holder's records live in the holder's
        # run directory). Whoxy's `LockBusy` precedent: a failure whose coverage gap folds to
        # `complete_with_gaps`.
        term = wired._terminal(tmp_path)
        assert term and term[0]["status"] == "failed", term
        assert term[0].get("error_class") == "error", term
        assert "holds this project" in (term[0].get("reason") or ""), term[0].get("reason")
        assert not term[0].get("produced"), term[0].get("produced")
        # every eligible address is reported unattempted
        cov = [e for e in wired._events(tmp_path) if e.get("measure") == "shodan_host_addresses"]
        assert cov and cov[0]["omitted"] == cov[0]["eligible"] == 1, cov
        assert cov[0]["tested"] == 0 and cov[0]["kind"] == "timeout", cov

    def test_a_CONTENDED_run_folds_to_complete_with_gaps(self, tmp_path, monkeypatch):
        """review-B1.7r14: the claim was "folds to complete_with_gaps" and nothing asserted the VERDICT.
        Driven through a real `store.Run`, which is what computes it."""
        from quarry_recon import events, secrets, settings, store
        from quarry_recon.phases import probe as probe_mod
        from types import SimpleNamespace
        project = tmp_path / "project"
        project.mkdir(parents=True, exist_ok=True)
        run = store.Run.create(project, "acme.com")
        events.reset(); events.configure(run.dir)
        monkeypatch.setattr(probe_mod.secrets, "shodan", lambda: "KEY")
        monkeypatch.setattr(secrets, "shodan", lambda: "KEY")
        monkeypatch.setattr(settings, "concurrency", lambda k, d=None: 0)
        monkeypatch.setattr(probe_mod.settings, "concurrency", lambda k, d=None: 0)
        calls = []
        monkeypatch.setattr(probe_mod.urllib.request, "urlopen",
                            lambda req, timeout=20: calls.append(str(req.full_url)))
        run.add("resolved", {"host": "www.acme.com", "a": ["1.1.1.1"]})
        ctx = SimpleNamespace(run=run, echo=lambda *a: None, http_timeout=20,
                              scope=SimpleNamespace(in_scope=lambda h: h.endswith("acme.com"),
                                                    is_oos=lambda h: False,
                                                    ip_in_scope=lambda ip: False),
                              profile=SimpleNamespace(ports=[443], portscan=False, cidr=[], ratelimit={}))
        with sh.sweep_session(sh.progress_path(run.project_dir)):
            probe_mod.shodan_host_lane(ctx)
        assert calls == [], calls
        summary = run._run_summary()
        assert summary["verdict"] == "complete_with_gaps", summary["verdict"]
        assert any(f["tool"] == "probe.shodan_host" for f in summary["failures"]), summary["failures"]
        assert not summary["provider_limits"] and not summary["operator_limits"], summary


class TestARefusalIsNotAnAnswer:
    """review-B1.7r11#3: `obtained = attempted - lost_gap` DERIVED an answer count, so a quota-only run
    reported "all 1 attempted address obtained" while `answered` was 0."""

    QUOTA = ("Insufficient query credits, please upgrade your API plan or wait for the monthly "
             "limit to reset")

    def _lane(self, tmp_path, monkeypatch, first_timeout=False, addresses=1):
        from quarry_recon.phases import probe as probe_mod
        wired = TestTheWiredLane()
        probe, ctx, _added, _rec = wired._probe_ctx(
            tmp_path, monkeypatch,
            resolved=[{"host": "www.acme.com", "a": [f"1.1.{b}.1" for b in range(addresses)]}])
        seen = []

        def urlopen(req, timeout=20):
            seen.append(str(req.full_url))
            if first_timeout and len(seen) == 1:
                raise socket.timeout("timed out")
            raise urllib.error.HTTPError(str(req.full_url), 401, "unauthorized", {},
                                        io.BytesIO(json.dumps({"error": self.QUOTA}).encode()))

        monkeypatch.setattr(probe_mod.urllib.request, "urlopen", urlopen)
        probe.shodan_host_lane(ctx)
        return wired

    def test_a_QUOTA_ONLY_run_reports_no_answer_OPPORTUNITY_at_all(self, tmp_path, monkeypatch):
        wired = self._lane(tmp_path, monkeypatch)
        answers = [e for e in wired._events(tmp_path) if e.get("measure") == "shodan_host_answers"]
        assert answers, wired._events(tmp_path)
        assert (answers[0]["eligible"], answers[0]["tested"], answers[0]["omitted"]) == (0, 0, 0), answers
        refused = [e for e in wired._events(tmp_path) if e.get("measure") == "shodan_host_refused"]
        assert refused and refused[0]["omitted"] == 1, refused

    def test_a_TRANSPORT_plus_QUOTA_run_reports_one_of_each(self, tmp_path, monkeypatch):
        wired = self._lane(tmp_path, monkeypatch, first_timeout=True, addresses=2)
        answers = [e for e in wired._events(tmp_path) if e.get("measure") == "shodan_host_answers"]
        refused = [e for e in wired._events(tmp_path) if e.get("measure") == "shodan_host_refused"]
        assert (answers[0]["eligible"], answers[0]["tested"], answers[0]["omitted"]) == (1, 0, 1), answers
        assert refused[0]["omitted"] == 1, refused

    def test_a_CLEAN_run_still_reports_its_answers(self, tmp_path, monkeypatch):
        wired = TestTheWiredLane()
        probe, ctx, _added, _rec = wired._probe_ctx(tmp_path, monkeypatch)
        probe.shodan_host_lane(ctx)
        answers = [e for e in wired._events(tmp_path) if e.get("measure") == "shodan_host_answers"]
        assert (answers[0]["eligible"], answers[0]["tested"], answers[0]["omitted"]) == (1, 1, 0), answers


class TestAStoredAnswerCarriesExactlyOneBody:
    def test_BOTH_carriers_is_refused(self):
        """review-B1.7r11#4: `body` silently won, so a stored answer could carry two different bodies and
        replay whichever we happened to check first."""
        env = {"schema": sh.SHODAN_HOST_SCHEMA, "ip": "1.1.1.1", "http_code": 404,
               "body": '{"error": "No information available for that IP."}',
               "body_b64": "eyJlcnJvciI6ICJzb21ldGhpbmcgZWxzZSJ9"}
        kind, why = sh.read_stored(json.dumps(env).encode(), ip="1.1.1.1")
        assert kind == sh.HOST_INVALID and "both" in why, why

    @pytest.mark.parametrize("carrier", ["body", "body_b64"])
    def test_EITHER_carrier_alone_still_works(self, carrier):
        import base64
        raw = b'{"error": "No information available for that IP."}'
        env = {"schema": sh.SHODAN_HOST_SCHEMA, "ip": "1.1.1.1", "http_code": 404}
        env[carrier] = raw.decode() if carrier == "body" else base64.b64encode(raw).decode("ascii")
        kind, said = sh.read_stored(json.dumps(env).encode(), ip="1.1.1.1")
        assert kind == sh.HOST_EMPTY and said == "No information available for that IP."


class TestTheStatusIsAnExactInteger:
    """review-B1.7r11#5: `http_code=200.0` passed on `200.0 == 200`, and `store_envelope` coerced with
    `int()` — a status we never received could satisfy the measured contract."""

    @pytest.mark.parametrize("code", [200.0, True, False, "200", None, [200]])
    def test_read_host_refuses_a_non_INTEGER_status(self, code):
        kind, why = sh.read_host(_record(), ip=IP, http_code=code)
        assert kind == sh.HOST_INVALID and "integer" in why, (code, kind)

    @pytest.mark.parametrize("code", [200.0, True, "404", None])
    def test_store_envelope_refuses_to_coerce(self, code):
        with pytest.raises(ValueError):
            sh.store_envelope("1.1.1.1", code, b"{}")

    def test_the_status_is_stored_UNCHANGED(self):
        env = json.loads(sh.store_envelope("1.1.1.1", 404, b"{}").decode())
        assert env["http_code"] == 404 and isinstance(env["http_code"], int)


class TestASaveCannotClaimAnUnlockedWrite:
    """review-B1.7r12#2: the bounded wait returned None on timeout (and where locking is unsupported), the
    write happened UNLOCKED, and `save()` still answered True — a contended run claiming an atomic save."""

    def test_a_CONTENDED_save_returns_False(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sh, "_PROGRESS_LOCK_WAIT_S", 0.05)
        path = sh.progress_path(tmp_path / "project")
        with sh.sweep_session(path) as holder:
            holder.note("2.2.2.2", 2.0)
            other = sh.SweepProgress(path)             # a second handle, no lock of its own
            other.note("1.1.1.1", 1.0)
            assert other.save() is False, "an unlocked write claimed an atomic save"
        assert "1.1.1.1" not in sh.SweepProgress(path).asked

    def test_an_UNSUPPORTED_lock_is_also_False(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sh, "_open_lock", lambda path, **kw: None)
        p = sh.SweepProgress(sh.progress_path(tmp_path / "project"))
        p.note("1.1.1.1", 100.0)
        assert p.save() is False

    def test_a_LOST_save_reaches_the_terminal_as_RESTARTS(self, tmp_path, monkeypatch):
        from quarry_recon import budget as _b, settings
        from quarry_recon.phases import probe as probe_mod
        wired = TestTheWiredLane()
        probe, ctx, _added, _rec = wired._probe_ctx(
            tmp_path, monkeypatch,
            resolved=[{"host": "www.acme.com", "a": [f"1.1.{b}.1" for b in range(4)]}],
            records={f"1.1.{b}.1": _body(f"1.1.{b}.1") for b in range(4)})
        monkeypatch.setattr(settings, "performance", lambda: {"SHODAN_HOST_BUDGET_S": 2})
        settings.reset_cache()
        clock = {"t": 0.0}
        monkeypatch.setattr(_b.time, "monotonic", lambda: clock["t"])
        real = probe_mod.urllib.request.urlopen
        monkeypatch.setattr(probe_mod.urllib.request, "urlopen",
                            lambda req, timeout=20: (clock.__setitem__("t", clock["t"] + 1.0),
                                                     real(req, timeout=timeout))[1])
        monkeypatch.setattr(sh, "_open_lock", lambda path, **kw: None)     # locking unavailable
        probe.shodan_host_lane(ctx)
        sel = [e for e in wired._events(tmp_path) if e.get("measure") == "shodan_host_addresses"]
        assert sel and sel[0]["omitted"] == 2, sel
        assert "RESTARTS" in sel[0]["reason"] and "RESUMABLE" not in sel[0]["reason"], sel[0]["reason"]

    def test_a_session_that_could_NOT_LOCK_never_claims_a_held_save(self, tmp_path, monkeypatch):
        """`held` means "the session owns the lock", and `save()` skips its own acquire on that word. If the
        session could not lock either, claiming `held` would make an unlocked write report success — the
        same lie one level up."""
        monkeypatch.setattr(sh, "_open_lock", lambda path, **kw: None)
        with sh.sweep_session(sh.progress_path(tmp_path / "project")) as p:
            assert p.held is False, "a session claimed a lock it does not hold"
            p.note("1.1.1.1", 100.0)
            assert p.save() is False

    def test_a_SESSION_save_still_succeeds(self, tmp_path):
        """The session holds the lock, so its own save is the atomic one."""
        path = sh.progress_path(tmp_path / "project")
        with sh.sweep_session(path) as p:
            p.note("1.1.1.1", 100.0)
            assert p.save() is True
        assert sh.SweepProgress(path).asked == {"1.1.1.1": 100.0}


class TestTheCarrierShapeIsExact:
    """review-B1.7r12#3: `is not None` tested VALUES, so a null sibling key read as one carrier."""

    @pytest.mark.parametrize("env_extra", [
        {"body": None, "body_b64": "eyJlcnJvciI6ICJ4In0="},
        {"body": '{"error": "x"}', "body_b64": None},
        {"body": None, "body_b64": None},
    ])
    def test_a_NULL_HYBRID_is_refused(self, env_extra):
        env = {"schema": sh.SHODAN_HOST_SCHEMA, "ip": "1.1.1.1", "http_code": 404}
        env.update(env_extra)
        kind, why = sh.read_stored(json.dumps(env).encode(), ip="1.1.1.1")
        assert kind == sh.HOST_INVALID, (env_extra, kind)
        assert "both" in why or "not a string" in why, why

    def test_NEITHER_carrier_is_refused(self):
        env = {"schema": sh.SHODAN_HOST_SCHEMA, "ip": "1.1.1.1", "http_code": 404}
        kind, why = sh.read_stored(json.dumps(env).encode(), ip="1.1.1.1")
        assert kind == sh.HOST_INVALID and "no usable" in why, why

    @pytest.mark.parametrize("value", [7, [], {}, True])
    def test_a_CARRIER_of_the_wrong_type_is_refused(self, value):
        env = {"schema": sh.SHODAN_HOST_SCHEMA, "ip": "1.1.1.1", "http_code": 404, "body": value}
        kind, why = sh.read_stored(json.dumps(env).encode(), ip="1.1.1.1")
        assert kind == sh.HOST_INVALID and "not a string" in why, why


class TestBothWaysAnEmptyArrivesAreOwned:
    """review-B1.7r14#1: the exception path stored the measured 404; the NON-exception path — which the
    fetch contract allows, `(body, 404, None)` — only marked it done in memory, so the same ledger re-asked
    it on every resume. Two ways in, one contract."""

    NODATA = b'{"error": "No information available for that IP."}'

    class _Direct:
        """An adapter that reports a measured 404 as an ORDINARY result rather than an error."""

        def __init__(self, body):
            self.body = body
            self.calls = []

        def fetch(self, ip):
            self.calls.append(ip)
            return self.body, 404, None

    def test_a_NON_EXCEPTION_404_is_owned_and_not_re_asked(self, tmp_path):
        prov = self._Direct(self.NODATA)
        led = _ledger(tmp_path)
        first = _run(tmp_path, [sh.IpTarget("203.0.113.1")], prov, ledger=led)
        assert (first.empty, first.answered, first.owned) == (1, 1, 1), first

        second = _run(tmp_path, [sh.IpTarget("203.0.113.1")], prov, ledger=_ledger(tmp_path),
                      attempt="a1")
        assert prov.calls == ["203.0.113.1"], f"an owned empty answer was re-asked: {prov.calls}"
        assert second.replayed == 1 and second.empty == 1 and second.attempted == 0

    def test_the_TWO_PATHS_replay_identically(self, tmp_path):
        """The exception path and the direct path must leave the ledger in the same state."""
        direct = self._Direct(self.NODATA)
        _run(tmp_path / "direct", [sh.IpTarget("203.0.113.1")], direct,
             ledger=_ledger(tmp_path / "direct"))
        raised = _Provider()                                   # answers via a 404 HTTPError-style carrier
        _run(tmp_path / "raised", [sh.IpTarget("203.0.113.1")], raised,
             ledger=_ledger(tmp_path / "raised"))
        key = sh.item_key("203.0.113.1")
        a = _ledger(tmp_path / "direct").artifact(key)
        b = _ledger(tmp_path / "raised").artifact(key)
        assert a is not None and b is not None, (a, b)
        assert json.loads(a.read_text()) == json.loads(b.read_text())

    def test_an_UNSTORABLE_direct_404_is_answered_but_NOT_owned(self, tmp_path, monkeypatch):
        from quarry_recon import budget as _b
        real = _b.publish_bytes
        monkeypatch.setattr(_b, "publish_bytes",
                            lambda path, body, **kw: (real(path, body, **kw)
                                                     if path.name == ".quarry-write-probe" else False))
        prov = self._Direct(self.NODATA)
        o = _run(tmp_path, [sh.IpTarget("203.0.113.1")], prov)
        assert (o.empty, o.answered, o.owned) == (1, 1, 0), o
        assert o.stop_cause == "publish_failed"
