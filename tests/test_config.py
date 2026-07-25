"""Profile/identifier validation (T1.7 / C04) — conservative hardening of malformed/dangerous input.

Rejects garbage that would misfire, suppress, or redirect scope, without ever narrowing a legitimate
target. The two scope-correctness cases (wildcard→root, IDNA2008 identity) are release-blockers.
"""
import pytest

from quarry_recon.config import ProfileError, _canon_domain, _flag

pytestmark = pytest.mark.offline


class TestFlag:
    @pytest.mark.parametrize("raw,default,expect", [
        (True, False, True), (False, True, False), (None, True, True), (None, False, False),
        ("true", False, True), ("false", True, False), ("off", True, False), ("", True, False),
        (1, False, True), (0, True, False),
    ])
    def test_valid(self, raw, default, expect):
        assert _flag(raw, default) is expect

    def test_quoted_false_is_false_not_bool_footgun(self):
        # bool("false") == True would silently flip PASSIVE_ONLY on → suppress the active scan
        assert _flag("false", True) is False

    @pytest.mark.parametrize("bad", ["maybe", 2, -1])
    def test_ambiguous_fails_loud(self, bad):
        with pytest.raises(ProfileError):
            _flag(bad, False)


class TestCanonDomain:
    def test_lowercases_and_strips_trailing_dot(self):
        assert _canon_domain("Example.COM.") == "example.com"

    def test_wildcard_stripped_to_root(self):
        # a preserved "*." never matches www.example.com → zero scope (release-blocker)
        assert _canon_domain("*.example.com") == "example.com"

    def test_idna2008_non_transitional_identity(self):
        # builtin codec maps faß.de → fass.de (a DIFFERENT domain); UTS-46 non-transitional is correct
        assert _canon_domain("faß.de") == "xn--fa-hia.de"
        assert _canon_domain("münchen.de") == "xn--mnchen-3ya.de"

    def test_single_label_internal_zone_accepted(self):
        assert _canon_domain("corp") == "corp"

    @pytest.mark.parametrize("bad", ["1.2.3.4", "../../etc", "a b.com", "*."])
    def test_rejects_non_domains(self, bad):
        with pytest.raises(ProfileError):
            _canon_domain(bad)


class TestProfileLoad:
    def test_valid_profile_loads(self, profile):
        p = profile("PORTS:\n  HTTP: [80, 443]\nRATELIMIT:\n  HTTP: 10\n")
        assert p.ports == [80, 443] and p.http_rl == 10 and p.apex_domains == ["example.com"]

    def test_wildcard_apex_matches_subdomains(self, profile):
        p = profile(apex='"*.example.com"')
        assert p.apex_domains == ["example.com"]
        assert p.scope().in_scope("www.example.com") and p.scope().in_scope("example.com")

    def test_duplicate_canonical_apex_is_deduped(self, profile):
        # review-r3#1: example.com and *.example.com canonicalize to the same root — kept ONCE (else a per-apex
        # loop double-runs it and overwrites its evidence)
        p = profile(apex='example.com\n  - "*.example.com"\n  - Example.COM.')
        assert p.apex_domains == ["example.com"]

    def test_passive_only_quoted_false_footgun(self, profile):
        assert profile('MODES:\n  PASSIVE_ONLY: "false"\n').passive_only is False

    @pytest.mark.parametrize("body", [
        "PORTS:\n  HTTP: [99999]\n", "PORTS:\n  HTTP: [0]\n", "PORTS:\n  HTTP: [80.9]\n",
        "PORTS:\n  HTTP: [true]\n", "RATELIMIT:\n  HTTP: -5\n", "RATELIMIT:\n  HTTP: 5.5\n",
        "RATELIMIT:\n  HTTP: abc\n", "MODES:\n  HEADLESS: maybe\n",
    ])
    def test_rejects_bad_values(self, profile, body):
        with pytest.raises(ProfileError):
            profile(body)

    def test_arming_flag_quoted_string_fails_loud(self, profile):
        # a quoted-string arming flag must not silently leave the danger lane disabled against intent
        with pytest.raises(ProfileError):
            profile('MODES:\n  SECRET_VERIFICATION: "true"\n')
        assert profile("MODES:\n  SECRET_VERIFICATION: true\n").verify_secrets is True

    def test_path_escape_apex_rejected(self, profile):
        with pytest.raises(ProfileError):
            profile(apex="../../../etc")


class TestApexOf:
    @pytest.mark.parametrize("apexes", [
        ["example.com", "dev.example.com"], ["dev.example.com", "example.com"],
    ])
    def test_longest_match_order_independent(self, apexes):
        from quarry_recon.phases.dns import _apex_of
        assert _apex_of("x.dev.example.com", apexes) == "dev.example.com"
