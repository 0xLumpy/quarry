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


class TestEveryModeIsDiscoverable:
    """`MODES.JS_AST` and `MODES.JS_CHUNK_BRUTE` existed in `config.py` and in NO template, so an
    operator could not find them: the OTC run of 2026-08-07 went out without the AST lane because
    nothing on disk said it existed. The template is the only discovery surface a profile has, so
    the two lists are compared structurally — the mode keys the code READS, against the mode keys
    the template OFFERS.

    Read from the AST, not from a grep: a comment, a docstring or a string in an unrelated file
    would satisfy a text search and prove nothing about what `TargetProfile` actually reads.
    """

    @staticmethod
    def _modes_read_by_code() -> set:
        """Literal keys in `self.modes.get("X", …)` / `modes.get("X", …)` across config.py."""
        import ast
        import pathlib

        import quarry_recon.config as cfg

        def _is_modes(node) -> bool:
            return (getattr(node, "attr", None) or getattr(node, "id", None)) == "modes"

        tree = ast.parse(pathlib.Path(cfg.__file__).read_text())
        keys = set()
        for node in ast.walk(tree):
            key = None
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "get" and node.args and _is_modes(node.func.value)):
                key = node.args[0]                       # self.modes.get("X", …) / modes.get("X", …)
            elif isinstance(node, ast.Subscript) and _is_modes(node.value):
                key = node.slice                         # self.modes["X"] — a future consumer
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                keys.add(key.value)
        return keys

    @staticmethod
    def _template_modes() -> dict:
        import yaml
        from importlib import resources

        doc = yaml.safe_load(
            resources.files("quarry_recon.data").joinpath("target.template.yaml").read_text()) or {}
        return doc.get("MODES") or {}

    @staticmethod
    def _modes_offered_by_template() -> set:
        import yaml
        from importlib import resources

        raw = resources.files("quarry_recon.data").joinpath("target.template.yaml").read_text()
        doc = yaml.safe_load(raw) or {}
        return set((doc.get("MODES") or {}).keys())

    def test_the_two_lists_are_the_same(self):
        code, template = self._modes_read_by_code(), self._modes_offered_by_template()
        assert code, "parsed no modes out of config.py — the AST walk broke, not the template"
        missing = code - template
        assert not missing, (
            f"MODES read by TargetProfile but absent from target.template.yaml: {sorted(missing)}. "
            f"A mode nobody can find is a mode nobody uses.")
        extra = template - code
        assert not extra, (
            f"MODES offered by target.template.yaml that TargetProfile never reads: {sorted(extra)}. "
            f"A profile key with no consumer reads as a setting and does nothing.")

    #: The shipped profile, frozen. `false`/`0`/`"off"` here is a SAFETY position, not a formatting
    #: choice: a template that arms BLIND_XSS or SECRET_VERIFICATION would put a stored payload — or
    #: someone else's credentials — on the wire for every operator who ran `quarry init` and read no
    #: further. Changing a value here is a deliberate act and has to edit this table to land.
    SHIPPED_DEFAULTS = {
        "PASSIVE_ONLY": False,
        "HEADLESS": False,
        "SCREENSHOTS": True,
        "TAKEOVER": True,
        "PORTSCAN": False,
        "BLOCK_PRIVATE_TARGETS": False,
        "CONTENT_DISCOVERY": "off",
        "CONTENT_RECURSION": 0,
        "JS_AST": False,
        "SECRET_VERIFICATION": False,
        "BLIND_XSS": False,
        "BLIND_XSS_DUAL": False,
        "DEEP_EVIDENCE": False,
        "JS_CHUNK_BRUTE": 0,
    }

    def test_the_shipped_defaults_are_exactly_these(self):
        assert self._modes_offered_by_template() == set(self.SHIPPED_DEFAULTS)
        template = self._template_modes()
        assert template == self.SHIPPED_DEFAULTS, (
            "target.template.yaml no longer ships the reviewed defaults: "
            f"{ {k: v for k, v in template.items() if self.SHIPPED_DEFAULTS.get(k) != v} }")

    def test_a_generated_profile_READS_those_defaults(self, tmp_path):
        """The table above pins the FILE; this pins what `TargetProfile` makes of it. The accessors
        are not a straight passthrough — each mode has its own reader (`_flag`, a strict `is True`,
        an exact-int check), so a reader could change meaning while the file stays byte-identical.
        Asserted on a profile written the way `quarry init` writes one."""
        from importlib import resources

        from quarry_recon.config import TargetProfile

        raw = resources.files("quarry_recon.data").joinpath("target.template.yaml").read_text()
        prof_file = tmp_path / "target.yaml"
        prof_file.write_text(raw.replace("TARGET: example", "TARGET: t"))
        p = TargetProfile.load(str(prof_file))
        for attr, expect in (("passive_only", False), ("headless", False), ("screenshots", True),
                             ("takeover", True), ("portscan", False),
                             ("block_private_targets", False), ("content_discovery", "off"),
                             ("content_recursion", 0), ("js_ast", False),
                             ("verify_secrets", False), ("blind_xss", False),
                             ("blind_xss_dual", False), ("deep_evidence", False),
                             ("js_chunk_brute", 0)):
            assert getattr(p, attr) == expect, f"{attr} reads {getattr(p, attr)!r}, expected {expect!r}"

    def test_no_mode_is_offered_without_a_value(self):
        """A commented-out or valueless mode is not offered."""
        blank = sorted(k for k, v in self._template_modes().items() if v is None)
        assert not blank, f"MODES with no value: {blank}"
