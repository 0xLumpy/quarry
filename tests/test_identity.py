"""C09a entity-identity contract — the canonical dedup key per entity type.

The regression this guards: the old blanket `str(value).strip().lower()` collapsed case-DISTINCT offensive
surface (`/API` vs `/api`, case-sensitive endpoints/parameters/fingerprints). The contract lowercases ONLY
case-insensitive components (DNS names; a URL's scheme+host) and preserves everything else.

Identity table
--------------
| entity kind                                   | key field | canonicalization                          |
| host  (subdomain, resolved)                   | host      | lower + strip trailing dot (DNS)          |
| url   (live, url, js_url, screenshot)         | url       | lower scheme+host; PRESERVE path/query    |
| ip    (ip)                                    | ip        | ipaddress-normalized (compressed)         |
| id    (secret, cert, port, finding, tech, …)  | id        | strip only — case PRESERVED               |
| value (endpoint, parameter, wildcard_zone)    | value     | strip only — case PRESERVED               |
"""
import pytest

from quarry_recon.store import canonical_key

pytestmark = pytest.mark.offline


class TestHostKeyed:
    @pytest.mark.parametrize("entity", ["subdomain", "resolved"])
    def test_dns_is_case_insensitive_and_dot_stripped(self, entity):
        a = canonical_key(entity, {"host": "WWW.Example.COM."})
        b = canonical_key(entity, {"host": "www.example.com"})
        assert a == b == "www.example.com"

    def test_dns_idna_folds_unicode_and_punycode(self):
        assert canonical_key("subdomain", {"host": "faß.de"}) == canonical_key("subdomain", {"host": "xn--fa-hia.de"})

    def test_non_domain_host_best_effort(self):
        # an IP-as-host or odd label IDNA can't encode falls back to lowered form, never raises
        assert canonical_key("subdomain", {"host": "10.0.0.1"}) == "10.0.0.1"


class TestUrlKeyed:
    @pytest.mark.parametrize("entity", ["live", "url", "js_url", "screenshot"])
    def test_scheme_and_host_folded(self, entity):
        assert canonical_key(entity, {"url": "HTTPS://API.Example.COM/x"}) == "https://api.example.com/x"

    @pytest.mark.parametrize("entity", ["url", "js_url"])
    def test_path_case_preserved_api_vs_api_distinct(self, entity):
        # the headline C09 defect: /API and /api must NOT collapse
        assert canonical_key(entity, {"url": "https://h/API"}) != canonical_key(entity, {"url": "https://h/api"})

    def test_query_case_preserved(self):
        assert canonical_key("url", {"url": "https://h/p?Tok=A"}) != canonical_key("url", {"url": "https://h/p?tok=a"})

    def test_non_url_value_preserved_verbatim(self):
        # a value that isn't URL-shaped is not mangled
        assert canonical_key("url", {"url": "NotAUrl/Path"}) == "NotAUrl/Path"

    def test_userinfo_preserved_case_sensitive(self):
        # credentials are case-sensitive and a distinct lead — must NOT fold into one key
        a = canonical_key("url", {"url": "https://Admin:SeCrEt@example.com/API"})
        b = canonical_key("url", {"url": "https://admin:secret@example.com/API"})
        assert a != b and a == "https://Admin:SeCrEt@example.com/API"     # host folded, userinfo kept

    def test_trailing_dot_host_folds(self):
        assert canonical_key("url", {"url": "https://example.com./x"}) == canonical_key("url", {"url": "https://example.com/x"})

    def test_idna_host_equals_punycode(self):
        assert canonical_key("url", {"url": "https://faß.de/x"}) == canonical_key("url", {"url": "https://xn--fa-hia.de/x"})

    def test_malformed_url_does_not_crash(self):
        # urlsplit raises ValueError on a broken authority — must be preserved, never abort Run.add
        assert canonical_key("url", {"url": "http://[::1"}) == "http://[::1"

    def test_ipv6_host_rebracketed(self):
        assert canonical_key("url", {"url": "https://[2001:DB8::1]:8443/x"}) == "https://[2001:db8::1]:8443/x"


class TestIpKeyed:
    def test_ipv6_normalized_and_case_insensitive(self):
        a = canonical_key("ip", {"ip": "2001:0DB8::0001"})
        b = canonical_key("ip", {"ip": "2001:db8::1"})
        assert a == b == "2001:db8::1"

    def test_ipv4_valid_passthrough(self):
        assert canonical_key("ip", {"ip": "192.168.1.1"}) == "192.168.1.1"


class TestCasePreservingKeys:
    @pytest.mark.parametrize("entity,field", [
        ("endpoint", "value"), ("parameter", "value"), ("wildcard_zone", "value"),
        ("secret", "id"), ("certificate", "id"), ("finding", "id"), ("tech", "id"),
    ])
    def test_case_is_preserved(self, entity, field):
        # composite ids / paths / fingerprints are case-sensitive — never folded
        assert canonical_key(entity, {field: "/Admin/Config"}) == "/Admin/Config"
        assert canonical_key(entity, {field: "/Admin"}) != canonical_key(entity, {field: "/admin"})

    def test_blank_key_is_empty(self):
        assert canonical_key("endpoint", {}) == "" and canonical_key("endpoint", {"value": "  "}) == ""


class TestStoreDedupAndReplay:
    """The contract applied through Run.add — case-distinct records both persist; a reopened run reloads
    the SAME keys (no phantom re-add)."""

    def _run(self, tmp_path):
        from quarry_recon.store import Run
        return Run(tmp_path, "t", run_id="fixed")           # fixed id so a reopen hits the same normalized dir

    def test_case_distinct_urls_both_added(self, tmp_path):
        run = self._run(tmp_path)
        assert run.add("url", {"url": "https://h/API"}) is True
        assert run.add("url", {"url": "https://h/api"}) is True     # distinct path case → both kept
        assert run.count("url") == 2

    def test_dns_case_variants_dedup(self, tmp_path):
        run = self._run(tmp_path)
        assert run.add("subdomain", {"host": "WWW.example.com"}) is True
        assert run.add("subdomain", {"host": "www.example.com"}) is False   # DNS case-insensitive → one
        assert run.count("subdomain") == 1

    def test_reopened_run_reloads_keys(self, tmp_path):
        r1 = self._run(tmp_path)
        r1.add("url", {"url": "https://h/API"})
        r1.add("endpoint", {"value": "/Admin"})
        # a fresh Run over the same dir must see the existing keys (replay), not re-add
        r2 = self._run(tmp_path)
        assert r2.add("url", {"url": "https://h/API"}) is False
        assert r2.add("endpoint", {"value": "/Admin"}) is False
        assert r2.add("endpoint", {"value": "/admin"}) is True      # case-distinct → still addable

    def test_reload_ignores_non_object_and_keyless_rows(self, tmp_path):
        # a JSONL file with null/[]/keyless rows must not crash reload nor inflate count()
        run = self._run(tmp_path)
        f = run._entity_file("endpoint")
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text('null\n[]\n"scalar"\n{"nokey": 1}\n{"value": "/real"}\n')
        r2 = self._run(tmp_path)
        assert r2.count("endpoint") == 1                            # only the one real keyed row
        assert r2.add("endpoint", {"value": "/real"}) is False      # and it dedups
