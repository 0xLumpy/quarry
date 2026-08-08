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
                             ("deep_evidence", False),
                             ("js_chunk_brute", 0)):
            assert getattr(p, attr) == expect, f"{attr} reads {getattr(p, attr)!r}, expected {expect!r}"

    def test_no_mode_is_offered_without_a_value(self):
        """A commented-out or valueless mode is not offered."""
        blank = sorted(k for k, v in self._template_modes().items() if v is None)
        assert not blank, f"MODES with no value: {blank}"


class TestEverySecretIsDiscoverable:
    """Same contract as the MODES table, for credentials: a key `secrets.py` reads and the template
    never mentions is a source that silently stays off, because the template is the only place an
    operator looks. `oob`, `notify` and `censys` ship COMMENTED (they are multi-field examples, and
    an empty mapping is not a usable starting point), so the template's offer is the union of its
    live YAML keys and its commented block openers — matched as `# <key>:` on its own line, a
    structural shape, never a substring search of prose.
    """

    @staticmethod
    def _secrets_read_by_code() -> set:
        """Literal keys in `load().get("X")` across secrets.py, from the AST."""
        import ast
        import pathlib

        import quarry_recon.secrets as sec

        tree = ast.parse(pathlib.Path(sec.__file__).read_text())
        keys = set()
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "get" and node.args):
                continue
            recv = node.func.value                        # must be the `load()` call itself
            if not (isinstance(recv, ast.Call) and getattr(recv.func, "id", None) == "load"):
                continue
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                keys.add(first.value)
        return keys

    @staticmethod
    def _template() -> tuple:
        import re
        from importlib import resources

        import yaml

        raw = resources.files("quarry_recon.data").joinpath("secrets.template.yaml").read_text()
        live = set((yaml.safe_load(raw) or {}).keys())
        # TOP-LEVEL openers only: `# oob:` at the margin. A nested `#   auth_token:` is a field of a
        # block, not a block, and treating it as one would let a whole block vanish while its stray
        # child kept the test green.
        commented = set(re.findall(r"(?m)^# ?([a-z][a-z0-9_]*):\s*$", raw))
        return live, commented

    #: Read by secrets.py for BACK-COMPAT only; the template must NOT advertise them, because their
    #: supported home is elsewhere. Each entry owes the test below proof of where it moved to.
    BACK_COMPAT_ONLY = {"openintel"}          # a pair of PATHS, not a credential -> config.yaml

    #: Offered DELIBERATELY ahead of a consumer, so the shape is agreed before anything reads it.
    #: A placeholder earns its exemption by staying EMPTY — the moment it carries a value it is a
    #: credential in a file nothing validates.
    FUTURE_PLACEHOLDERS = {"ai"}              # AI-assisted triage, not wired

    def test_a_placeholder_block_ships_empty(self):
        """`ai:` is commented out entirely today, which is the strongest form of empty. If it is ever
        uncommented, every field under it must still be blank."""
        import re
        from importlib import resources

        import yaml

        raw = resources.files("quarry_recon.data").joinpath("secrets.template.yaml").read_text()
        doc = yaml.safe_load(raw) or {}
        for key in self.FUTURE_PLACEHOLDERS:
            block = doc.get(key)
            if block is None:                     # still commented out
                assert re.search(rf"(?m)^#\s*{key}:\s*$", raw), f"{key} is neither offered nor commented"
                continue
            assert isinstance(block, dict), f"{key} must be a mapping, got {type(block).__name__}"
            filled = {k: v for k, v in block.items() if v not in (None, "", [], {})}
            assert not filled, f"placeholder {key} ships values: {sorted(filled)}"

    def test_the_back_compat_keys_are_offered_where_they_MOVED(self):
        """An exclusion is only honest while the key is documented somewhere. If openintel ever
        vanishes from config.template.yaml, this stops being back-compat and starts being a hole."""
        import re
        from importlib import resources

        cfg = resources.files("quarry_recon.data").joinpath("config.template.yaml").read_text()
        for key in self.BACK_COMPAT_ONLY:
            assert re.search(rf"(?m)^#?\s*{key}:\s*$", cfg), \
                f"{key} is excluded from the secrets template but not offered in config.template.yaml"

    def test_every_key_the_code_reads_is_offered(self):
        code = self._secrets_read_by_code() - self.BACK_COMPAT_ONLY
        live, commented = self._template()
        assert code, "parsed no keys out of secrets.py — the AST walk broke, not the template"
        missing = code - (live | commented)
        assert not missing, (
            f"secrets.py reads keys the template never mentions: {sorted(missing)}. "
            f"An operator cannot configure a source they cannot see.")

    def test_the_template_offers_nothing_the_code_ignores(self):
        code = self._secrets_read_by_code()   # back-compat keys MAY appear; they just need not
        live, commented = self._template()
        extra = (live | commented) - code - self.FUTURE_PLACEHOLDERS
        assert not extra, (
            f"template offers keys nothing reads: {sorted(extra)}. "
            f"A credential slot with no consumer reads as a working integration.")

    #: The FIELDS each block must keep offering. A block opener alone proves nothing: `oob:` can
    #: survive while `callback_server` is deleted, and an operator then has a section with no way in.
    #: Nested names are the schema an operator types, so they are pinned like any other contract.
    REQUIRED_FIELDS = {
        "oob": {"callback_server", "auth_token"},
        "censys": {"token", "org"},
        "notify": {"events", "slack", "discord", "telegram", "webhook"},
        "ai": {"provider", "api_key"},
    }

    @staticmethod
    def _block(name: str) -> dict:
        """One block's fields, read by UNCOMMENTING it: an example that cannot be uncommented into valid
        YAML is not an example. Works whether the block is live or commented out."""
        import re
        import textwrap
        from importlib import resources

        import yaml

        raw = resources.files("quarry_recon.data").joinpath("secrets.template.yaml").read_text()
        lines = raw.splitlines()
        start = next((i for i, ln in enumerate(lines)
                      if re.fullmatch(rf"#? ?{name}:\s*", ln)), None)
        assert start is not None, f"block {name} is not offered at all"
        body = []
        for ln in lines[start + 1:]:
            stripped = re.sub(r"^# ?", "", ln)
            if stripped and not stripped.startswith(" "):
                break                                      # the next top-level key
            body.append(stripped)
        doc = yaml.safe_load(textwrap.dedent("\n".join(body)) or "{}") or {}
        assert isinstance(doc, dict), f"{name}: the commented example is not a mapping"
        return doc

    def test_every_block_still_offers_its_fields(self):
        for block, want in self.REQUIRED_FIELDS.items():
            missing = want - set(self._block(block))
            assert not missing, f"{block} no longer offers {sorted(missing)}"

    def test_a_placeholder_ships_its_fields_EMPTY(self):
        """`ai` is exempt from the consumer check, so nothing else would notice it rotting — and a
        commented `#   api_key: sk-example` is still a credential-shaped value shipped in the repo.
        The block is parsed whether it is live or commented, and every field must be blank."""
        assert self.FUTURE_PLACEHOLDERS <= set(self.REQUIRED_FIELDS), \
            "a placeholder must also pin the fields it offers"
        for key in self.FUTURE_PLACEHOLDERS:
            doc = self._block(key)
            filled = {k: v for k, v in doc.items() if v not in (None, "", [], {})}
            assert not filled, f"placeholder {key} ships values: {sorted(filled)}"

    def test_no_credential_ships_with_a_value(self):
        """The shipped file must be inert: a live key here would be a credential in the repo, and
        `install` copies this file verbatim to ~/.config/quarry/secrets.yaml."""
        live_doc = self._template_doc()
        set_keys = {k: v for k, v in live_doc.items() if v not in (None, "", [], {})}
        assert not set_keys, f"template ships values: {sorted(set_keys)}"

    @staticmethod
    def _template_doc() -> dict:
        from importlib import resources

        import yaml

        return yaml.safe_load(
            resources.files("quarry_recon.data").joinpath("secrets.template.yaml").read_text()) or {}


class TestEveryConfigKnobIsDiscoverable:
    """`config.yaml` has the same failure mode as the MODES table: a knob the code reads and the
    template never lists is one an operator cannot find, and one that quietly keeps its built-in
    default forever. Claimed as covered on 2026-08-08 when it was not (the key sets had been compared
    by hand, in a throwaway script) — so it is a test now.

    PERFORMANCE keys reach the code through several readers (`settings.concurrency`, `settings.raw`,
    `settings.workers` via `_OVERRIDE_KEY`, `budget.budget_seconds`, `performance().get`), so the
    call sites are collected from the AST of every module rather than from one helper.
    """

    @staticmethod
    def _knobs_read_by_code() -> set:
        import ast
        import pathlib

        import quarry_recon
        from quarry_recon import settings

        root = pathlib.Path(quarry_recon.__file__).parent
        # `strict_int` reaches config too. Its keys arrive as `bound.name` today, so they are
        # recovered from policy.BOUNDS below — but a future direct `strict_int("NEW_KEY")` must not
        # slip past a test that claims to cover every knob.
        readers = {"concurrency", "raw", "budget_seconds", "policy_days", "flag_int",
                   "strict_int", "strict_int_with_source"}
        keys = set()
        for path in sorted(root.rglob("*.py")):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and node.args):
                    continue
                fn = node.func
                name = getattr(fn, "attr", None) or getattr(fn, "id", None)
                # performance().get("X") — the direct dict read
                direct = (name == "get" and isinstance(fn, ast.Attribute)
                          and isinstance(fn.value, ast.Call)
                          and (getattr(fn.value.func, "attr", None)
                               or getattr(fn.value.func, "id", None)) == "performance")
                if name not in readers and not direct:
                    continue
                first = node.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str) \
                        and first.value.isupper():
                    keys.add(first.value)
        # per-tool overrides are resolved through a table, never as literals at the call site
        keys |= set(settings._OVERRIDE_KEY.values())
        keys.add("PROFILE")
        # registered BOUNDS reach settings as `bound.name` — a variable, so no literal exists to find.
        # `module` bounds are flag-only by design (config.yaml has no say over a module constant), and
        # must therefore NOT be offered; the two config-backed readers must.
        from quarry_recon import policy
        keys |= {b.name for b in policy.BOUNDS if b.reader in ("budget_seconds", "strict_int")}
        return keys

    @staticmethod
    def _knobs_offered() -> set:
        from importlib import resources

        import yaml

        doc = yaml.safe_load(
            resources.files("quarry_recon.data").joinpath("config.template.yaml").read_text()) or {}
        return set((doc.get("PERFORMANCE") or {}).keys())

    #: Read from PERFORMANCE but deliberately NOT offered, each with the reason it stays hidden.
    NOT_OFFERED: dict = {}

    def test_every_knob_the_code_reads_is_offered(self):
        code, offered = self._knobs_read_by_code(), self._knobs_offered()
        assert code, "parsed no PERFORMANCE keys — the AST walk broke, not the template"
        missing = code - offered - set(self.NOT_OFFERED)
        assert not missing, (
            f"config.yaml knobs the template never lists: {sorted(missing)}. "
            f"An operator cannot tune what the template does not name.")

    def test_the_template_lists_nothing_the_code_ignores(self):
        extra = self._knobs_offered() - self._knobs_read_by_code()
        assert not extra, (
            f"template lists knobs nothing reads: {sorted(extra)}. "
            f"A knob with no consumer looks like a setting and changes nothing.")

    def test_only_the_two_documented_knobs_ship_with_a_value(self):
        """Everything else must ship blank, so the code's own default stays the default. A value here
        is a machine policy imposed on every install."""
        from importlib import resources

        import yaml

        perf = (yaml.safe_load(resources.files("quarry_recon.data")
                               .joinpath("config.template.yaml").read_text()) or {})["PERFORMANCE"]
        set_keys = {k: v for k, v in perf.items() if v is not None}
        assert set_keys == {"PROFILE": "auto", "WEB_PORT_PREFILTER": True}, set_keys
