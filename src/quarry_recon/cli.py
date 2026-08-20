"""quarry — recon command surface: setup (install · update · doctor · init · notify), scope (set · oos ·
policy), run (osint · run · report · status · plan), pins (lock), and oob."""
from __future__ import annotations

import os
import re
import shutil
from importlib import resources
from pathlib import Path

import click

from . import __version__, events, secrets
from .config import ProfileError, TargetProfile
from .campaign import MAX_CHILDREN as _MAX_CHILDREN
from .exit_contract import ContractGroup as _ContractGroup, json_option as _ec_json_option
from .oos_regex import OOSRegexError, compile_oos
from .registry import health, install_one, load_tools, tool_phases, tools_by_phase, verify_installed


def _projects_root(opt: str | None) -> Path:
    """Where `quarry init` creates project dirs; ~/projects unless --projects-dir or $QUARRY_PROJECTS."""
    return Path(opt or os.environ.get("QUARRY_PROJECTS") or (Path.home() / "projects"))


def _project_dir(profile) -> Path:
    """A profile's project dir: the directory its target.yaml lives in. Output co-locates here."""
    return (profile.path.parent if profile.path else Path(".")).resolve()


def _existing_run(project, target, run_id):
    """Resolve a run for read/import commands. An explicit --run must already exist (never fabricate a ghost
    dir); no run_id gives the latest, or None.
    """
    from .repository_identity import InvalidRunId
    from .store import Run
    if run_id is not None:
        try:
            return Run.open(project, target, run_id)    # open, never fabricate a ghost dir
        except InvalidRunId as e:
            raise click.UsageError(str(e))              # operator selector: invalid before any run is opened
        except FileNotFoundError:
            raise click.ClickException(f"run {run_id!r} not found under {Path(project) / 'recon'}")
    return Run.latest(project, target)


def _resolve_profile(value: str) -> str:
    """Accept `-t` as a target.yaml path, a project dir, or a bare project name (resolved under the
    projects root).
    """
    p = Path(value).expanduser()      # so a quoted ~ still works
    if p.is_file():
        return str(p)
    if p.is_dir() and (p / "target.yaml").is_file():
        return str(p / "target.yaml")
    cand = _projects_root(None) / value / "target.yaml"
    if cand.is_file():
        return str(cand)
    raise click.ClickException(
        f"no target profile for {value!r} — give a target.yaml path, or a project name under "
        f"{_projects_root(None)}/ (create it with: quarry init {value})")


# metachars (other than . and *) that signal "the user typed an actual regex"
_OOS_REGEX_META = re.compile(r"[\^$\\+?\[\](){}|]")


def _to_oos_pattern(value: str) -> str:
    """Translate an OOS argument into the shared bounded hostname grammar.

    Bare labels/FQDNs and ``*.x`` globs are conveniences.  An explicitly
    patterned value is retained only when the profile/broker matcher accepts
    the same anchors, literals, character classes, and single repetition.
    """
    if _OOS_REGEX_META.search(value):
        pat = value
    elif "." not in value:                                    # bare label -> subdomain-prefix
        # a bare label matches any host under that label (^jobs\.)
        pat = "^" + re.escape(value) + r"\."
    else:
        pat = "^" + re.escape(value).replace(r"\*", ".*") + "$"    # FQDN / glob -> anchored regex
    compile_oos(pat)
    return pat


def _c(s, color):  # tiny colorizer
    return click.style(s, fg=color)


def _echo_syscheck(rep) -> None:
    marks = {"ok": _c("✓", "green"), "warn": _c("⚠", "yellow"), "abort": _c("✗", "red")}
    for text, lvl in rep["checks"]:
        click.echo(f"  {marks[lvl]} {text}")


def _chromium() -> str | None:
    for b in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome"):
        p = shutil.which(b)
        if p:
            return p
    return None


# ContractGroup so a Click-decided exit (unknown flag, missing option, missing option argument) leaves
# through the same contract as a command body, with the same `--json` document
@click.group(cls=_ContractGroup, context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="quarry")
def cli():
    """Quarry — methodology-driven reconnaissance automation."""


def _missing_required(phase_filter=None) -> list[str]:
    """Required (non-optional) tools that are not installed, optionally limited to a set of phases —
    Quarry-owned tools only.
    """
    return sorted({t.bin for t in load_tools()
                   if not t.optional and not t.installed
                   and (phase_filter is None or t.phase in phase_filter)})


def _select_phases(phases: "str | None") -> list:
    """Validate a --phases selector and return it in canonical order. Unknown/empty/duplicate tokens raise
    UsageError (exit 2) BEFORE any run is created; an omitted selector means the full canonical set. The
    canonical order is preserved so an out-of-order selector never starves a dependent lane."""
    from .phases import ORDER
    if phases is None:                                   # flag omitted -> the full canonical set
        return list(ORDER)
    tokens = [p.strip() for p in phases.split(",")]      # an explicit "" is one empty token -> invalid below
    if any(tok == "" for tok in tokens):
        raise click.UsageError("empty phase name in --phases (stray or trailing comma?)")
    unknown = [t for t in tokens if t not in set(ORDER)]
    if unknown:
        raise click.UsageError(f"unknown phase(s): {', '.join(unknown)}. valid: {', '.join(ORDER)}")
    dupes = sorted({t for t in tokens if tokens.count(t) > 1})
    if dupes:
        raise click.UsageError(f"duplicate phase(s): {', '.join(dupes)}")
    return [p for p in ORDER if p in set(tokens)]


def _effective_phases(selected, profile) -> set:
    """Phases that will actually do work under the profile's modes, so the readiness warn does not flag
    tools for phases that self-skip.
    """
    from .phases import REGISTRY
    eff = {p for p in selected if p in REGISTRY}
    if profile.passive_only:
        eff = {p for p in eff if not REGISTRY[p][2]}          # index 2 = needs_active
    if getattr(profile, "content_discovery", None) == "off":
        eff.discard("content")
    return eff


# ── lock ──────────────────────────────────────────────────────────────────────
def _osint_verdict(cdir) -> tuple:
    """(summary, verdict) for a finished OSINT session directory; an unreadable manifest is `unknown`, never
    `complete`.
    """
    import json as _json
    try:
        summary = (_json.loads((cdir / "manifest.json").read_text()) or {}).get("summary") or {}
        return summary, (summary.get("verdict") or "unknown")
    except (OSError, _json.JSONDecodeError, ValueError, AttributeError, TypeError):
        return {}, "unknown"


@cli.command()
@click.option("--drift-only", is_flag=True, help="only print tools whose installed version DRIFTS from the pin")
@click.option("--maintenance", is_flag=True, help="refresh-policy view: tools grouped by maintenance state")
@_ec_json_option
def lock(drift_only, maintenance, as_json):
    """Capture installed tool versions on this host as a reviewable pin set (paste `version:` lines into
    data/tools.yaml). Run on a validated host. Also flags drift and unpinned tools.
    """
    from . import exit_contract as _ec
    _ec.run_command("lock", as_json, lambda: _lock(drift_only, maintenance))


def _lock(drift_only, maintenance):
    from .registry import capture_lock, load_tools
    if maintenance:
        # refresh-policy snapshot: planning only, never gates verify/drift/install/runtime, reads the
        # static registry. `release` shows only when it differs from the pin.
        from collections import defaultdict
        groups = defaultdict(list)
        for t in load_tools():
            groups[t.maintenance_state or "unset"].append(t)
        click.echo(_c("\n# refresh-policy view — maintenance state (planning only; never gates verify/runtime)\n", "cyan"))
        for st in ("active", "monitor", "frozen", "distro", "unset"):
            g = groups.get(st) or []
            if not g:
                continue
            click.echo(_c(f"[{st}]  {len(g)}", "magenta"))
            for t in sorted(g, key=lambda x: x.bin):
                pinref = t.pin or t.ref
                tag = f"  (release {t.release})" if t.release else ""
                click.echo(f"  {t.bin:<20} {str(pinref or '—'):<42}{tag}")
        click.echo(_c(f"\n{sum(len(v) for v in groups.values())} tools · active {len(groups['active'])} · "
                      f"monitor {len(groups['monitor'])} · frozen {len(groups['frozen'])} · distro {len(groups['distro'])}", "cyan"))
        return
    rows = capture_lock()
    drifts = [r for r in rows if r["drift"] == "DRIFT"]
    unpinned = [r for r in rows if r["drift"] == "unpinned"]
    if drift_only:
        # the drift check must report every violation and exit nonzero, or a wrong binary passes silently
        violations = [r for r in rows if r["drift"] in ("DRIFT", "version-unknown")]
        for r in violations:
            click.echo(_c(f"  {r['drift']:<15} {r['bin']:<20} installed={r['installed']}  pin={r['pin']}", "red"))
        if violations:
            click.echo(_c(f"\n{len(violations)} lock violation(s)", "red"))
            # a binary we cannot vouch for is coverage we cannot vouch for, the same verdict doctor gives
            from .state import CommandResult, Gap
            return CommandResult("lock", coverage="gapped", remediation="quarry install",
                                 gaps=[Gap(source_id="registry", kind="unknown", omitted=len(violations),
                                           reason=f"{len(violations)} installed tool(s) do not verify "
                                                  f"against the lock")])
        click.echo(_c("\nall installed tools verify against the lock", "green"))
        return None
    unknown = [r for r in rows if r["drift"] == "version-unknown"]
    # emit a reviewable YAML pin block from what's installed here (the known-good versions)
    click.echo(_c("\n# C08 pin capture — installed versions on this host (paste `version:` into data/tools.yaml)\n", "cyan"))
    for r in rows:
        if r["installed"]:
            mark = {"DRIFT": _c("DRIFT", "red"), "ok": _c("ok", "green"),
                    "unpinned": _c("new", "yellow")}.get(r["drift"], r["drift"])
            click.echo(f"  {r['bin']:<20} version: {r['installed']:<12} [{mark}]"
                       + (f"  (pin={r['pin']})" if r["pin"] and r["drift"] == "DRIFT" else ""))
        elif r["drift"] == "version-unknown":
            click.echo(_c(f"  {r['bin']:<20} installed but VERSION UNKNOWN — cannot capture a pin", "red"))
        else:
            click.echo(_c(f"  {r['bin']:<20} (not installed — cannot capture)", "yellow"))
    click.echo(_c(f"\n{len(rows)} tools · {len(unpinned)} unpinned · {len(drifts)} drift · "
                  f"{len(unknown)} version-unknown", "cyan"))


def _doctor_version(t, ident: str) -> str:
    """Doctor's version string from the already-probed runtime identity, so doctor agrees with install. A
    long source-ref is shortened; falls back to the banner, then "version unknown".
    """
    if ident == "distro":
        return t.version() or _c("distro", "cyan")
    if ident:
        return ident[:12] if len(ident) > 20 and all(c in "0123456789abcdef" for c in ident.lower()) else ident
    return t.version() or _c("version unknown", "yellow")   # empty = unparseable, not a pin


def _health_reason(h: dict, t) -> str:
    """Why a present tool is unverified (drift/identity/capability). Identity problems take precedence."""
    d = h["drift"]
    if d == "DRIFT":
        return f"drift — installed {h['identity'] or '?'} != pin {t.pin or t.ref}"
    if d == "version-unknown":
        return "identity unproven — shadowed PATH copy, missing/bad receipt, or unparseable"
    if d == "unpinned":
        return "unpinned — present but no pin/ref to verify against"
    if h["capability"] is False:
        return "capability probe failed"
    return d


# ── doctor ──────────────────────────────────────────────────────────────────
@cli.command()
@click.option("--phase", help="only audit tools for this phase")
@_ec_json_option
def doctor(phase, as_json):
    """Audit local setup: tools, versions, API keys, resolvers, wordlists."""
    from . import exit_contract as _ec
    _ec.run_command("doctor", as_json, lambda: _doctor(phase))


def _doctor(phase):
    if phase is not None and phase not in tool_phases():
        raise click.UsageError(f"unknown phase '{phase}'. valid: {', '.join(sorted(tool_phases()))}")
    tools = tools_by_phase(phase) if phase else load_tools()
    # a `dependency` (bun) is a runtime, not a recon tool: audited here, printed under [environment],
    # and not counted, but a broken one still degrades the verdict
    deps = [t for t in tools if t.dependency]
    tools = [t for t in tools if not t.dependency]
    ok = warn = miss = 0
    click.echo(_c(f"\nQuarry doctor — {len(tools)} tools\n", "cyan"))
    cur_phase = None
    oob_lines: list[str] = []                # printed in the [oob] section below
    dep_lines: list[str] = []                # printed in [environment]
    for t in sorted(tools + deps, key=lambda x: (x.phase, x.bin)):
        # `oob` tools are accounted for here but printed in the [oob] block, next to their server
        _oob = t.phase == "oob"
        _say = dep_lines.append if t.dependency else (oob_lines.append if _oob else click.echo)
        _w = 24 if t.dependency else 20   # [environment] column, not the tool-list one
        if t.phase != cur_phase and not _oob and not t.dependency:
            cur_phase = t.phase
            click.echo(_c(f"[{cur_phase}]", "magenta"))
        if t.installed:
            h = health(t)                                        # verify-grade verdict
            ver = _doctor_version(t, h["identity"])
            if h["ok"]:
                ok += 0 if t.dependency else 1
                _say(f"  {_c('✓', 'green')} {t.bin:<{_w}} {ver}")
            else:
                warn += 1                                        # present but unverified
                _say(f"  {_c('⚠', 'yellow')} {t.bin:<{_w}} {ver}  "
                     f"{_c('unverified: ' + _health_reason(h, t), 'yellow')}")
        elif t.optional:
            _say(f"  {_c('·', 'yellow')} {t.bin:<{_w}} optional, not installed")
        else:
            miss += 1
            _say(f"  {_c('✗', 'red')} {t.bin:<{_w}} MISSING — quarry install --only {t.bin}")
        if t.needs_chromium and t.installed and not _chromium():
            _say(f"      {_c('⚠ needs chromium — not found; screenshots/headless will fail', 'red')}")

    # environment checks
    click.echo(_c("\n[environment]", "magenta"))
    cfg = Path.home() / ".config/quarry"
    # resolvers + wordlists are required install artifacts, so a missing one is a warning with the fix.
    # Check the canonical wordlists/ path first, then the back-compat config root.
    for label, name, cands in [("resolvers", "resolvers", [cfg / "resolvers.txt"]),
                         ("trusted-resolvers", "trusted-resolvers", [cfg / "trusted-resolvers.txt"]),
                         ("dns wordlist", "dns-wordlist", [cfg / "wordlists/dns.txt", cfg / "dns-wordlist.txt"]),
                         ("vhost wordlist", "vhost-wordlist", [cfg / "wordlists/vhost.txt", cfg / "vhost-wordlist.txt"]),
                         ("content-wl balanced", "content-balanced", [cfg / "wordlists/content/balanced.txt"]),
                         ("content-wl deep", "content-deep", [cfg / "wordlists/content/deep.txt"])]:
        hit = next((c for c in cands if c.exists()), None)
        if hit:
            click.echo(f"  {_c('✓', 'green')} {label:<24} {hit}")
        else:
            click.echo(f"  {_c('⚠', 'yellow')} {label:<24} "
                       f"MISSING — run `quarry set {name}` (expected at {cands[0]})")

    for label, bin_ in [("go toolchain", "go"), ("chromium", "chromium"),
                        ("pipx", "pipx")]:
        present = shutil.which(bin_) or (bin_ == "chromium" and
                  (shutil.which("chromium-browser") or shutil.which("google-chrome")))
        mark = _c("✓", "green") if present else _c("✗", "red")
        click.echo(f"  {mark} {label}")
    # runtimes Quarry provisions itself (bun), printed under [environment]
    for _l in dep_lines:
        click.echo(_l)

    from . import bootstrap
    click.echo(_c("\n[system]", "magenta"))
    _echo_syscheck(bootstrap.system_report("run"))   # post-install: only run space matters

    # secrets.yaml — framework-read keys only; tool-native source keys live in each tool's own config
    click.echo(_c("\n[secrets]", "magenta") + f"  ({secrets.PATH})")
    secrets_present = secrets.PATH.exists()
    if not secrets_present:
        click.echo(f"  {_c('✗', 'red')} secrets.yaml NOT FOUND — run `quarry install` to recreate it "
                   f"from the template (or restore a backup); keys read as unset until it exists")
    # each row is: not set · set · malformed. The shape check is a local regex (never a request, never
    # a spend), and claims malformed only for providers with a documented format. Values never printed.
    gh = secrets.github_tokens()
    rows = [("github tokens", gh, "github"),
            ("shodan", [secrets.shodan()], "shodan"),
            ("whoxy", [secrets.whoxy()], "whoxy"),
            ("projectdiscovery/chaos", [secrets.chaos()], "chaos"),
            ("certspotter", [secrets.certspotter()], "certspotter")]
    for label, vals, kind in rows:
        vals = [v for v in vals if v]
        if not vals:
            click.echo(f"  {_c('·', 'yellow')} {label:<24} not set")
            continue
        bad = [v for v in vals if secrets.key_shape(kind, v) == "malformed"]
        note = f"{len(vals)} token(s)" if kind == "github" else ""
        if bad:
            # a shape check cannot report a rejection
            click.echo(f"  {_c('✗', 'red')} {label:<24} "
                       + (f"{len(bad)} of {len(vals)} wrong shape for this provider"
                          if len(vals) > 1 else "wrong shape for this provider"))
        else:
            click.echo(f"  {_c('✓', 'green')} {label:<24} {note}".rstrip())
    # Censys Platform — advanced opt-in; shown only when configured
    cen = secrets.censys()
    if cen.get("token") and cen.get("org"):
        click.echo(f"  {_c('✓', 'green')} censys (advanced)          Platform cert search")
    # template drift: surface any optional key the shipped template has that an existing secrets.yaml
    # predates (bootstrap never overwrites it). Only when the file exists.
    if secrets_present:
        try:
            import yaml as _yaml
            tpl = _yaml.safe_load(
                resources.files("quarry_recon.data").joinpath("secrets.template.yaml").read_text()) or {}
            drift = [k for k in tpl if k not in secrets.load()]
            if drift:
                click.echo(f"  {_c('ℹ', 'cyan')} template adds optional key(s) your secrets.yaml predates: "
                           f"{', '.join(drift)} — add manually (update never overwrites your file)")
        except Exception:
            pass

    # config.yaml — machine-scoped runtime settings (non-secret: performance/concurrency + local paths)
    from . import settings
    click.echo(_c("\n[config]", "magenta") + f"  ({settings.PATH})")
    if not settings.PATH.exists():
        click.echo(f"  {_c('·', 'yellow')} config.yaml not found — `quarry install` creates it "
                   f"(safe defaults apply until it exists)")
    click.echo(f"  {_c('✓', 'green')} performance profile     {settings.profile()}")
    _w = " · ".join(f"{t} {settings.workers(t, d)}" for t, d in (("nuclei", 25), ("httpx", 15), ("ffuf", 40)))
    click.echo(f"  {_c('ℹ', 'cyan')} workers ({os.cpu_count() or '?'} cores)      {_w}")
    oi = settings.openintel()   # advanced opt-in (config.yaml, or legacy secrets.yaml) — shown only if set
    if oi.get("binary") and oi.get("db"):
        ok_oi = (shutil.which(oi["binary"]) or Path(oi["binary"]).is_file()) and Path(oi["db"]).is_file()
        click.echo(f"  {_c('✓' if ok_oi else '✗', 'green' if ok_oi else 'red')} "
                   f"openintel-subs (advanced) {oi['db']}")

    # notify — opt-in run notifications (off unless secrets.yaml notify: is set)
    from . import notify as _notify
    nch, nev = _notify.channels(), _notify.enabled_events()
    click.echo(_c("\n[notify]", "magenta") + "  (opt-in, off by default)")
    if nch:
        ev_txt = ", ".join(sorted(nev)) if nev else _c("(no events — nothing will send)", "yellow")
        click.echo(f"  {_c('✓', 'green')} channels: {', '.join(nch)} · events: {ev_txt}")
        click.echo(f"  {_c('ℹ', 'cyan')} verify with: quarry notify --test")
    else:
        click.echo(f"  {_c('·', 'yellow')} not configured")

    # oob — readiness only: is the tool present + which backend. (The OOB model lives in README, not here.)
    ob = secrets.oob()
    _have_ic = shutil.which("interactsh-client") is not None
    # one [oob] section: the callback tool and the server it returns to. The server address is shown
    # (not a secret), the token never. The blind-XSS channel is target-scoped, so it is not here.
    click.echo(_c("\n[oob]", "magenta"))
    for _l in oob_lines:
        click.echo(_l)
    from . import nuclei_policy as _nuclei_policy
    try:
        srv = str(_nuclei_policy._freeze_oob_config(ob).get("callback_server") or "")
    except _nuclei_policy.NucleiPolicyError:
        srv = ""
        legacy_srv = ob.get("callback_server")
        if (isinstance(legacy_srv, str)
                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]*", legacy_srv)):
            click.echo(
                f"  {_c('✗', 'red')} {'callback server:':<20} {legacy_srv} "
                "(rejected: an explicit http(s) origin is required)"
            )
        else:
            click.echo(f"  {_c('✗', 'red')} {'callback server:':<20} malformed/unsafe (value withheld)")
    if srv:
        click.echo(f"  {_c('✓', 'green')} {'callback server:':<20} {srv}")
    elif not ob.get("callback_server"):
        click.echo(f"  {_c('·', 'yellow')} {'callback server:':<20} not set")

    # readiness verdict — the one-line rollup (required tools are the only blocker; keys are optional)
    from .state import CommandResult, Gap
    scope_note = f" for phase {phase}" if phase else ""
    gaps: list = []
    if miss:
        verdict = _c(f"✗ NOT READY — {miss} required tool(s) missing{scope_note}", "red") + \
            "  → quarry install"
        gaps.append(Gap(source_id="registry", kind="required_tool_missing", omitted=miss,
                        reason=f"{miss} required tool(s) missing{scope_note}"))
    elif warn:
        verdict = _c(f"⚠ DEGRADED — {warn} present but UNVERIFIED (drift/identity/capability){scope_note}", "yellow") + \
            "  → quarry install  (reinstalls to the pin)"
        # an unverified binary is coverage we cannot vouch for, not a bound we chose
        gaps.append(Gap(source_id="registry", kind="unknown", omitted=warn,
                        reason=f"{warn} tool(s) present but unverified{scope_note}"))
    else:
        verdict = _c("✓ READY", "green") + f" — {ok} tools installed + verified, all required present{scope_note}"
    click.echo(f"\n{verdict}\n")
    return CommandResult("doctor", coverage="gapped" if gaps else "clean", gaps=gaps,
                         remediation="quarry install" if gaps else None)


# ── notify ───────────────────────────────────────────────────────────────────
@cli.command("notify")
@click.option("--test", is_flag=True, help="send a test message to all configured channels")
def notify_cmd(test):
    """Show / validate opt-in run notifications (configured in secrets.yaml under `notify:`)."""
    from . import notify
    ch, ev = notify.channels(), notify.enabled_events()
    if not ch:
        click.echo("no notify channels configured — add a `notify:` block to "
                   f"{secrets.PATH} (slack/discord/telegram/webhook).")
        return
    click.echo(f"channels: {', '.join(ch)} · events: {', '.join(sorted(ev)) or '(none set)'}")
    if test:
        n = notify.send_test()
        click.echo(_c(f"sent test to {n}/{len(ch)} channel(s)", "green" if n == len(ch) else "yellow"))
    else:
        click.echo("run `quarry notify --test` to send a test message.")


@cli.command("set")
@click.argument("name")
@click.option("--url", help="override the source URL (the name still fixes the destination)")
def set_cmd(name, url):
    """Fetch/refresh a single data file by name (resolvers, dns-wordlist, vhost-wordlist, content-balanced,
    content-deep, trusted-resolvers) — granular alternative to a full install.
    """
    from . import bootstrap
    if not bootstrap.set_data_file(name, url, click.echo):
        raise click.ClickException(f"could not set '{name}' — see the message above")


# ── install / update ─────────────────────────────────────────────────────────
def _run_tool(t, marker, dry_run) -> bool:
    """Install/update one tool through the shared version-locked path, rendering one line. Shared by
    `install` and `update`. Returns install_one's ok.
    """
    if t.policy == "distro":
        pin_note = _c(" (distro)", "cyan")
    elif t.pin or t.ref:
        pin_note = f" @ {t.pin or t.ref}"
    else:
        pin_note = _c(" (unpinned)", "yellow")
    click.echo(f"  {_c(marker, 'cyan')} {t.bin}", nl=False)
    buf = []
    ok = install_one(t, buf.append, dry_run)
    if dry_run:
        if ok:
            click.echo(f"{pin_note} {_c('(dry-run)', 'yellow')}")
        else:
            click.echo(f"{pin_note} {_c('⊘ unavailable', 'yellow')}")
            for m in buf:
                click.echo(f"      {m}")
    elif ok:
        click.echo(_c(" ✓", "green"))
        for m in buf:
            if not m.startswith(f"{t.bin}: ok"):
                click.echo(f"      {m}")
    else:
        click.echo(f"{pin_note} {_c('✗', 'red')}")
        for m in buf:
            click.echo(f"      {m}")
    return ok


@cli.command()
@click.option("--dry-run", is_flag=True, help="show what would be installed, do nothing")
@click.option("--phase", help="only install tools for this phase")
@click.option("--only", help="install a single tool by bin name")
@click.option("--include-optional", is_flag=True, help="also install optional tools")
@click.option("--tools-only", is_flag=True, help="skip system packages / Go / data files")
@click.option("--yes", "-y", is_flag=True, help="install even if the host is below minimum requirements")
@_ec_json_option
def install(dry_run, phase, only, include_optional, tools_only, yes, as_json):
    """Full blank-VPS install: system pkgs -> Go -> tools -> wordlists/templates."""
    from . import exit_contract as _ec
    _ec.run_command("install", as_json,
                    lambda: _install(dry_run, phase, only, include_optional, tools_only, yes))


def _install(dry_run, phase, only, include_optional, tools_only, yes):
    from . import bootstrap

    # an explicitly-empty selector is invalid; only a truly omitted flag means "everything"
    for _flag, _val in (("--only", only), ("--phase", phase)):
        if _val is not None and _val.strip() == "":
            raise click.UsageError(f"{_flag} was given an empty value; omit it to install everything")

    # ── 1. system packages + Go toolchain + data (unless --tools-only / --only / --phase) ──
    full = not (only or phase or tools_only)

    # select first, reading only static fields: a `dependency` (bun) is provisioned in the toolchain
    # step, never listed under [3/6]
    tools = load_tools()
    # validate the selector before any install side effect (invalid -> exit 2, nothing installed)
    if only and only not in {t.bin for t in tools}:
        raise click.UsageError(f"unknown tool '{only}'. run `quarry doctor` to list installable tools")
    if phase and phase not in tool_phases():
        raise click.UsageError(f"unknown phase '{phase}'. valid: {', '.join(sorted(tool_phases()))}")
    if only:
        tools = [t for t in tools if t.bin == only]
    elif phase:
        tools = [t for t in tools if t.phase == phase]
    if not include_optional and not only:
        tools = [t for t in tools if not t.optional]
    # a narrowed run has no toolchain step, so a dependency stays in the selection it was asked for
    runtimes = [t for t in tools if t.dependency] if full else []
    if full:
        tools = [t for t in tools if not t.dependency]
    failed = []
    step_results = []          # typed InstallResult per bootstrap step; a required failure blocks

    if full:
        # install.sh prints this banner first, so don't duplicate it here
        if not os.environ.get("QUARRY_FROM_INSTALLER"):
            click.echo(_c("\n  ◤ QUARRY — methodology-driven recon automation", "cyan"))
            if not dry_run:
                click.echo(_c("  ⏳ Full install builds ~25 Go tools + fetches wordlists/templates — this "
                              "takes several minutes.\n     It is not stuck; grab a coffee.", "yellow"))
        # system-spec precheck: ok silent · warn proceeds · below minimum aborts
        rep = bootstrap.system_report("install")
        click.echo(_c("\n[*] system check", "magenta"))
        _echo_syscheck(rep)
        if rep["level"] == "abort" and not yes and not dry_run:
            from . import exit_contract as _ec
            raise _ec.Refused(
                "host is below minimum requirements — aborting. See README → Requirements. "
                "Override with --yes.")
        if rep["level"] == "warn":
            click.echo(_c("  below recommended — the run may be slow or unstable; continuing.", "yellow"))
        click.echo(_c("\n[1/6] system packages", "magenta"))
        step_results.append(bootstrap.install_system_packages(click.echo, dry_run))
        click.echo(_c("\n[2/6] runtimes", "magenta"))
        step_results.append(bootstrap.ensure_golang(click.echo, dry_run))

    # make freshly-installed Go/pipx bins visible to subsequent tool installs
    for p in (str(Path.home() / "go/bin"), str(Path.home() / ".local/bin"),
              "/usr/local/go/bin"):
        if p not in os.environ.get("PATH", ""):
            os.environ["PATH"] = p + os.pathsep + os.environ.get("PATH", "")

    def _provision(t) -> bool:
        """Install one registry entry with one line of output; a present-and-verified tool is left as-is."""
        if t.installed and not only and not dry_run:
            # a present tool is left as-is only if it verifies; otherwise it is reinstalled to the pin
            if verify_installed(t):
                # the ✓ is "present and verified"; a tool that fails verification says so and is
                # reinstalled
                click.echo(f"  {_c('→', 'cyan')} {t.bin} {_c('✓', 'green')}")
                return True
            click.echo(f"  {_c('⚠', 'yellow')} {t.bin} present but FAILED verification — reinstalling pin")
        return _run_tool(t, "→", dry_run)

    # runtimes run here, after the PATH is set, because a version probe calls the binary by name
    for t in runtimes:
        if not _provision(t):
            failed.append(t)

    # ── 2. tools from the registry ──
    click.echo(_c(f"\n[3/6] tools ({len(tools)})", "magenta"))
    for t in tools:
        if not _provision(t):
            failed.append(t)

    # ── 3. data files + extras + cleanup ──
    if full:
        click.echo(_c("\n[4/6] data files (resolvers, wordlists)", "magenta"))
        step_results.append(bootstrap.install_data_files(click.echo, dry_run))
        click.echo(_c("\n[5/6] extras (gf patterns, nuclei templates)", "magenta"))
        step_results.append(bootstrap.run_extras(click.echo, dry_run))
        click.echo(_c("\n[6/6] cleanup (reclaim disk)", "magenta"))
        bootstrap.cleanup(click.echo, dry_run)

    if dry_run:
        click.echo(_c("\n(dry-run — nothing was installed)\n", "yellow"))
        return None
    # an optional tool failing is nonfatal only in the full bootstrap; a narrowed run fails hard on any
    # selected tool the operator asked for
    soft = [t.bin for t in failed if full and include_optional and t.optional]
    fatal = [t.bin for t in failed if t.bin not in soft]
    blocked = [r for r in step_results if r.blocks]      # required bootstrap steps that failed
    for b in soft:
        click.echo(_c(f"  optional tool failed: {b} — retry: quarry install --only {b}", "yellow"))
    for r in blocked:
        click.echo(_c(f"  required step failed: {r.name} — {r.detail or 'see above'}", "yellow"))
    if fatal or blocked:
        if fatal:
            click.echo(_c(f"\n{len(fatal)} tool(s) failed: {', '.join(fatal)}", "yellow"))
            for b in fatal:
                click.echo(f"retry: quarry install --only {b}")
        from . import exit_contract as _ec
        why = ([f"{len(fatal)} tool(s) failed: {', '.join(fatal)}"] if fatal else []) \
            + [f"required step failed: {r.name}" for r in blocked]
        # the installer is machinery: a failed step is exit 5, not a coverage gap
        raise _ec.MachineryFailure("; ".join(why) or "install failed", where="install")
    if not os.environ.get("QUARRY_FROM_INSTALLER"):
        # install.sh prints the final banner itself; conclude here only when run standalone
        tail = "" if not soft else f" ({len(soft)} optional failed — see above)"
        click.echo(_c(f"\ninstall complete — required tools ok{tail}\nrun  quarry doctor  to verify", "green"))
    # an optional tool that failed in the full bootstrap is declared best-effort: it is named above and the
    # install still succeeds, so install.sh can persist PATH
    return None


@cli.command()
@click.option("--dry-run", is_flag=True)
@_ec_json_option
def update(dry_run, as_json):
    """Reinstall installed tools at their pinned lock (reproducible) and refresh templates, resolvers and gf
    patterns. Never floats to @latest — bumping a pin is the `quarry lock` workflow.
    """
    from . import exit_contract as _ec
    _ec.run_command("update", as_json, lambda: _update(dry_run))


def _update(dry_run):
    from . import bootstrap

    # every installed tool syncs to its pin, optional or not, or an installed-optional tool's drift hides
    tools = [t for t in load_tools() if t.installed]
    click.echo(_c(f"updating {len(tools)} tools (to their pins)", "magenta"))
    failed = []
    for t in tools:
        if not _run_tool(t, "↻", dry_run):               # same locked path as install
            failed.append(t.bin)
    click.echo(_c("refreshing data files + templates", "magenta"))
    data_res = bootstrap.install_data_files(click.echo, dry_run, update=True)
    bootstrap.run_extras(click.echo, dry_run)
    bootstrap.cleanup(click.echo, dry_run)   # re-running tool installs refills go caches
    if dry_run:
        click.echo(_c("\n(dry-run)\n", "yellow"))
    elif failed or data_res.blocks:
        if data_res.blocks:
            click.echo(_c(f"  required step failed: {data_res.name} — {data_res.detail or 'see above'}",
                          "yellow"))
        if failed:
            click.echo(_c(f"\n{len(failed)} tool(s) failed: {', '.join(failed)}", "yellow"))
        from . import exit_contract as _ec
        # same machinery as install: a tool that would not reinstall to its pin is not a coverage gap
        why = ([f"{len(failed)} tool(s) failed: {', '.join(failed)}"] if failed else []) \
            + ([f"required step failed: {data_res.name}"] if data_res.blocks else [])
        raise _ec.MachineryFailure("; ".join(why), where="update")
    return None


# ── init (create a project) ───────────────────────────────────────────────────
@cli.command()
@click.argument("name")
@click.option("-o", "--out", help="exact project dir (default: <projects-root>/<name>)")
@click.option("--projects-dir", help="projects root (default ~/projects or $QUARRY_PROJECTS)")
def init(name, out, projects_dir):
    """Create a project: <projects>/<name>/target.yaml (or -o <dir>). osint + recon co-locate here."""
    # the name is the target id (a single path segment), never a path; the location is -o
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*$", name) or ".." in name:
        raise click.ClickException(
            f"invalid project name {name!r}: use letters/digits/.-_ only, no path separators")
    proj = Path(out).expanduser() if out else _projects_root(projects_dir) / name
    proj.mkdir(parents=True, exist_ok=True)
    tpl = resources.files("quarry_recon.data").joinpath("target.template.yaml").read_text()
    tpl = tpl.replace("TARGET: example", f"TARGET: {name}")
    # if the name is a domain, seed APEX_DOMAINS so `quarry init target.com` is ready to run
    is_domain = bool(re.match(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$", name))
    if is_domain:
        tpl = tpl.replace("  - example.com", f"  - {name}")
    dest = proj / "target.yaml"
    if dest.exists():
        click.confirm(f"{dest} exists — overwrite?", abort=True)
    dest.write_text(tpl)
    # bare `-t <name>` resolves only under the default projects root; elsewhere point -t at the dir
    ref = name if not (out or projects_dir) else str(proj)
    click.echo(f"{_c('created project', 'green')} {proj}/  (profile: {dest})")
    if is_domain:
        click.echo(f"  APEX_DOMAINS seeded with {name} — ready to run:\n"
                   f"    quarry osint -t {ref}     # optional pre-flight\n"
                   f"    quarry run   -t {ref}")
    else:
        click.echo(f"  edit APEX_DOMAINS in {dest}, then:  quarry run -t {ref}")


# ── oos (seed out-of-scope patterns) ──────────────────────────────────────────
@cli.command()
@click.option("-t", "--target", "profile_path", required=True,
              help="project name, project dir, or target.yaml path")
@click.argument("hosts", nargs=-1, required=True)
def oos(profile_path, hosts):
    """Add out-of-scope patterns to a project's target.yaml.

    A bare host becomes an anchored pattern and ``*.x`` a subdomain glob.
    Explicit patterns must use the bounded hostname grammar documented in the
    target reference; groups, alternation, lookaround, backreferences, and
    nested/count repetitions are refused before anything is written.
    """
    import yaml
    path = Path(_resolve_profile(profile_path))
    text = path.read_text()
    lines = text.splitlines()
    idx = next((i for i, ln in enumerate(lines) if ln.rstrip() == "OOS:"), None)
    if idx is None:
        raise click.ClickException(f"no OOS: section in {path}")

    # validate + translate each input (bad regex -> refuse, profile stays untouched)
    patterns = []
    for h in hosts:
        try:
            patterns.append(_to_oos_pattern(h))
        except OOSRegexError as e:
            raise click.ClickException(f"invalid OOS pattern {h!r}: {e}")

    # structural dedup against the existing OOS list (not text/quote-style dependent)
    try:
        existing = {str(x) for x in (yaml.safe_load(text) or {}).get("OOS") or []}
    except yaml.YAMLError as e:
        raise click.ClickException(f"profile is not valid YAML: {e}")
    add, seen = [], set()
    for p in patterns:
        if p not in existing and p not in seen:
            add.append(p)
            seen.add(p)
    if not add:
        click.echo("nothing to add (already present)")
        return

    # safely-quoted YAML items (handles quotes/backslashes), inserted under OOS:
    items = ["  " + yaml.safe_dump([p], default_flow_style=False, allow_unicode=True).strip()
             for p in add]
    lines[idx + 1:idx + 1] = items
    new_text = "\n".join(lines) + "\n"

    # write to a temp file, confirm the profile still compiles (scope/OOS regex), then atomic swap
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(new_text)
    try:
        TargetProfile.load(str(tmp)).scope()   # .scope() actually compiles the OOS regexes
    except (ProfileError, Exception) as e:
        tmp.unlink(missing_ok=True)
        raise click.ClickException(f"refusing to write — resulting profile invalid: {e}")
    os.replace(tmp, path)
    click.echo(f"{_c('+OOS', 'green')} {path}")
    for p in add:
        click.echo(f"  {p}")


# ── osint (pre-flight; separate from run) ─────────────────────────────────────
@cli.command()
@click.option("-t", "--target", "profile_path", required=True,
              help="project name, project dir, or target.yaml path")
@click.option("--timeout", default=1800, help="per-lookup ceiling (seconds) for the OSINT HTTP/whois/dig lookups — each also has its own shorter default, so this only TIGHTENS them. Must be > 0 (osint has no unbounded mode; 0 would collapse every lookup to a 0-second timeout)")
@click.option("--unbound", is_flag=True,
              help="use ALL the eligible work this preflight already has: every registered "
                   "coverage/throughput ceiling in these lanes goes to its unbounded meaning (today: "
                   "RDAP_LOOKUPS — every address the apexes resolve to, instead of the first batch). It "
                   "obtains nothing extra: provider enablement, credit reserves and page budgets are "
                   "untouched, and scope, contact guards and rate limits never change. This is the "
                   "VOLUME axis, not the waiting one — see `quarry policy --unbound`")
@_ec_json_option
def osint(profile_path, timeout, unbound, as_json):
    """Pre-flight OSINT: discover scope candidates and intel. Review-only — never edits scope.

    Workflow: init -> fill anchors -> `quarry osint` -> review the report and suggested.yaml -> confirm into
    target.yaml -> `quarry run`. Output lands in the project's osint/ dir.
    """
    from . import exit_contract as _ec
    _ec.run_command("osint", as_json, lambda: _osint(profile_path, timeout, unbound))


def _osint(profile_path, timeout, unbound):
    import json
    from . import osint as osint_mod

    if timeout <= 0:      # osint bounds each lookup with min(timeout, N); 0 fails every lookup instantly
        raise click.UsageError("osint --timeout must be > 0 (it's a per-lookup ceiling; there is no unbounded osint)")
    try:
        profile = TargetProfile.load(_resolve_profile(profile_path))
    except ProfileError as e:
        raise click.ClickException(str(e))
    scope = profile.scope()
    project = _project_dir(profile)
    secrets.apply_env()   # export PDCP_API_KEY for PD tools, if set

    click.echo(_c(f"\n══ Quarry osint · target={profile.target} (pre-flight, review-only) ══", "cyan"))
    click.echo(f"   project: {project}")
    click.echo(f"   anchors: apex={len(profile.apex_domains)} asn={len(profile.asn)} "
               f"org={len(profile.org_names)} brands={len(profile.brands)}\n")
    # the same axis as `quarry run --unbound`, entered before any lane reads a bound and restored after
    from . import policy as _policy
    from . import settings as _settings
    with _settings.overrides(_policy.unbound_overrides() if unbound else {}):
        if unbound:
            click.echo(_c("   --unbound: every registered preflight ceiling at its unbounded value\n",
                          "cyan"))
        report = osint_mod.run(profile, scope, project, echo=click.echo, timeout=timeout)

    cdir = report.parent
    cfile = cdir / "candidates.jsonl"
    cands = [json.loads(l) for l in cfile.read_text().splitlines() if l.strip()] \
        if cfile.exists() else []
    apex = [c for c in cands if c["type"] == "apex" and c["scope_hint"] != "noise"]
    # surface the manifest verdict, never an unconditional green "done" over a session cut short
    _sum, _verdict = _osint_verdict(cdir)
    click.echo(_c(f"\n══ osint {_verdict.replace('_', ' ')} · {cdir}",
                  "green" if _verdict == "complete" else "yellow"))
    for _lim in _sum.get("provider_limits", []):
        click.echo(_c(f"   provider limit: {_lim.get('tool')} — {_lim.get('why')}", "yellow"))
    for _lim in _sum.get("operator_limits", []):     # ours — say so, never "provider limit"
        click.echo(_c(f"   operator limit: {_lim.get('tool')} — {_lim.get('why')}", "yellow"))
    for _gap in _sum.get("gaps", []):
        click.echo(_c(f"   incomplete: {_gap.get('tool')} — {_gap.get('why')}", "yellow"))
    click.echo(f"   report:    {report}")
    click.echo(f"   suggested: {cdir / 'target.suggested.yaml'}")
    click.echo(_c(f"   {len(apex)} apex candidate(s) — review, confirm scope, add to target.yaml:", "yellow"))
    for c in apex[:8]:
        click.echo(f"     - {c['value']}  [{c['scope_hint']}/{c['confidence']}]")
    if len(apex) > 8:
        click.echo(f"     … +{len(apex) - 8} more in the report")

    # the session's own verdict decides the status: a bound we or a provider declared is exit 3, an
    # incomplete lane or an unreadable manifest is exit 4
    from .state import CommandResult, Gap
    gaps = [Gap(source_id=g.get("tool") or "osint", kind="tool_omission", reason=g.get("why"))
            for g in _sum.get("gaps", [])]
    if _verdict == "unknown":
        gaps.append(Gap(source_id="osint", kind="unknown", reason="session manifest unreadable"))
    bounded = bool(_sum.get("provider_limits") or _sum.get("operator_limits")
                   or _verdict == "complete_with_limits")
    return CommandResult("osint", coverage="gapped" if gaps else
                         "intentionally_bounded" if bounded else "clean", gaps=gaps)


# ── policy ───────────────────────────────────────────────────────────────────
@cli.command()
@click.option("-t", "--target", "profile_path", required=False,
              help="project name, project dir, or target.yaml path (optional: the policy is machine-wide)")
@click.option("--unbound", is_flag=True, help="preview the policy `quarry run --unbound` would apply")
def policy(profile_path, unbound):
    """Show the effective coverage policy: every bound, its value, who set it, and what is held. Runs nothing
    and contacts nothing.
    """
    from . import policy as _policy
    from . import settings
    with settings.overrides(_policy.unbound_overrides() if unbound else {}):
        rows = _policy.snapshot()
        click.echo(_c(f"\n# effective coverage policy{' (--unbound)' if unbound else ''}\n", "cyan"))
        for line in _policy.render(rows):
            click.echo(line)
        click.echo(_c(f"\n{len(rows)} registered bound(s). Provider spending, rate, concurrency, resource "
                      f"and engagement controls are NOT here — they keep their own policy.\n", "cyan"))


# ── run ──────────────────────────────────────────────────────────────────────
@cli.command()
@click.option("-t", "--target", "profile_path", required=True,
              help="project name, project dir, or target.yaml path")
@click.option("--phases", help="comma list (default: all). e.g. horizontal,vertical")
@click.option("--passive", is_flag=True, help="force passive-only (override profile)")
@click.option("--timeout", default=1800, type=click.IntRange(min=0),
              help="per-tool OUTER timeout floor in seconds; httpx/ffuf/nuclei/naabu scale their wall-clock ceiling above this by workload (0 = fully unbounded, no wall-clock kill — per-probe timeouts still bound individual requests; NEGATIVE is rejected, as it would collapse every tool to an instant timeout). subfinder is separate: it self-bounds via its own -max-time COLLECTION budget per apex (PERFORMANCE.SUBFINDER_MAX_TIME minutes, default 60; only that knob unbinds it, 0 -> practically unbounded 1440m). This flag does NOT change it: --timeout 0 removes the outer kill and leaves the collection budget exactly as configured")
@click.option("--unbound", is_flag=True,
              help="use ALL the eligible work this run already has: every registered coverage/throughput "
                   "ceiling goes to its unbounded meaning for this process (see `quarry policy "
                   "--unbound`). It does NOT obtain more — provider enablement, balance, reserve and page "
                   "budgets are untouched — and it never changes scope, contact guards, rate limits, "
                   "concurrency, per-invocation chunk sizes or the outer timeout. Bounds held by policy "
                   "stay held, and are printed with the reason")
@click.option("--settle", "settle_flag", is_flag=True,
              help="keep creating child runs while resumable work still ADVANCES, and stop with a named "
                   "outcome when it does not (fixed point, terminal remainder, unknown lane, no progress, "
                   "child fault, or a bound). A supervisor over runs: each child is an ordinary run with "
                   "its own evidence, seeded from the campaign's union so nothing learned is lost between "
                   "them. It obtains nothing extra — acquisition is CLOSED from child 2 on, so provider "
                   "calls are never repeated by a continuation flag — and it changes no other axis: "
                   "--unbound widens each child, --timeout bounds each child's tools")
@click.option("--settle-max-runs", type=click.IntRange(min=1), default=None,
              help=f"how many child runs one campaign may create (default {_MAX_CHILDREN}). Needs --settle")
@click.option("--settle-budget", type=click.IntRange(min=0), default=None,
              help="wall-clock seconds after which no FURTHER child is started (0 = none). It never kills "
                   "a running child — that is --timeout's axis. Needs --settle")
@click.option("--settle-resume", "settle_resume", default=None,
              help="continue the campaign with this id instead of minting a new one: its interrupted child "
                   "is settled from the ledger and the loop goes on from there, so a killed campaign never "
                   "repeats the acquisition child 1 already paid for. With --settle and no id, a project "
                   "with exactly one resumable campaign is continued automatically. Needs --settle")
@_ec_json_option
def run(profile_path, phases, passive, timeout, unbound, settle_flag, settle_max_runs, settle_budget,
        settle_resume, as_json):
    """Run recon phases against the confirmed scope. Output lands in the project's recon/ dir."""
    from . import exit_contract as _ec
    from . import settings

    finished: dict = {}

    def body():
        # refuse the settle bounds without the axis they bound
        if not settle_flag and (settle_max_runs is not None or settle_budget is not None
                                or settle_resume is not None):
            raise click.UsageError("--settle-max-runs / --settle-budget / --settle-resume bound a "
                                   "campaign; they need --settle")

        # validate the phase selector before any run/campaign side effect (invalid -> exit 2, no run)
        _select_phases(phases)

        # --unbound for this run: entered before any lane reads a bound, restored on the way out so it
        # never leaks into another run sharing this interpreter
        from . import policy as _policy
        with settings.overrides(_policy.unbound_overrides() if unbound else {}):
            if not settle_flag:
                run_obj = _run_phases(profile_path, phases, passive, timeout, finished=finished)
                return _ec.from_summary("run", run_obj.summary(), run_id=run_obj.run_id)
            return _settle_run(profile_path, phases, passive, timeout,
                               max_runs=settle_max_runs, budget_s=settle_budget,
                               campaign_id=settle_resume)

    _ec.run_command("run", as_json, body, run_id=lambda: finished.get("run_id"))


#: campaign stops that are a declared bound rather than lost coverage (exit 3, not 4). `terminal` is not
#: one of them: its causes are classified per-cause by `remainder.terminal_class`.
_SETTLE_BOUNDED = frozenset({"max_runs", "budget"})


def _settle_run(profile_path, phases, passive, timeout, *, max_runs, budget_s, campaign_id=None):
    """`--settle`: a campaign over ordinary runs. The axes compose — `--unbound` widens every child,
    `--timeout` bounds every child's tools.
    """
    from . import campaign as _campaign
    from . import budget, settle as _settle
    from . import exit_contract as _ec

    try:
        profile = TargetProfile.load(_resolve_profile(profile_path))
    except ProfileError as e:
        raise click.ClickException(str(e))
    project = _project_dir(profile)

    def launch(index, prepare):
        return _run_phases(profile_path, phases, passive, timeout, prepare=prepare)

    # a kill that is answered with a fresh campaign re-mints child 1 and buys its acquisition again, so a
    # single interrupted campaign is continued by default; several is a choice only the operator can make
    if campaign_id is None:
        skipped = _settle.skipped_resumable(project, profile.target)
        # the classification is the settle module's, not a reading of its reasons: a campaign confirmed to
        # be another target's is knowing whose it is, and only what nobody can place is a cost to mint over
        lost = set(_settle.unconfirmable_resumable(project, profile.target))
        # scoped to this target: a campaign's union is one target's corpus, so another target's
        # interrupted campaign is never the one to continue by default
        candidates = _settle.resumable_campaigns(project, profile.target)
        if len(candidates) > 1:
            # ambiguous is not the same answer as none: minting here would start yet another campaign and
            # buy child 1's acquisition again, so the operator chooses
            raise _ec.Refused(
                f"{len(candidates)} interrupted campaigns could be continued: {', '.join(candidates)} — "
                f"choose one with --settle-resume <id>, or start a new one with --settle-resume ''")
        campaign_id = _settle.resumable(project, profile.target)
        if campaign_id:
            click.echo(_c(f"   ↻ continuing the interrupted campaign {campaign_id} "
                          f"(start a new one with --settle-resume '')", "cyan"))
        elif lost:
            # nobody can say whether this evidence was ours, so minting over it is a choice with a cost:
            # the operator makes it, naming a campaign to continue or asking explicitly for a fresh one
            raise _ec.Refused(
                f"{len(lost)} interrupted campaign(s) here cannot be confirmed, and a new campaign would "
                f"repeat acquisition they already paid for: "
                + "; ".join(f"{cid} ({why})" for cid, why in skipped if cid in lost)
                + " — continue one with --settle-resume <id>, or start fresh with --settle-resume ''")
        elif skipped:
            # confirmed as somebody else's: accounted for, so a new campaign starts — named, not silent
            click.echo(_c(f"   ⚠ {len(skipped)} interrupted campaign(s) skipped, starting a new one:",
                          "yellow"))
            for cid, why in skipped:
                click.echo(_c(f"     {cid}: {why}", "yellow"))
    campaign_id = campaign_id or None            # `--settle-resume ''` is "mint a new one", not an id

    try:
        out = _settle.settle(project_dir=project, target=profile.target, launch=launch,
                             max_runs=max_runs or _campaign.MAX_CHILDREN, budget_s=budget_s or 0,
                             campaign_id=campaign_id,
                             echo=lambda line: click.echo(_c(line, "cyan")))
    except _campaign.InvalidCampaignId as e:
        raise click.UsageError(str(e))     # a mistyped id is a bad selector, not broken machinery
    except _campaign.InvalidRunId as e:
        # a child id is not operator input: a ledger pointing outside the project is damaged machinery
        raise _ec.MachineryFailure(str(e), where="campaign ledger", after_start=False)
    except budget.StateBusy as e:
        raise _ec.Refused(f"another campaign is already running on this project ({e})")
    except _settle.CampaignRefused as e:
        # every refusal to continue a campaign — closed history, wrong target — is refused before any
        # child runs, so it is the contract's refusal, not an invalid invocation
        raise _ec.Refused(str(e))
    except _campaign.UnionUnusable as e:
        raise _ec.MachineryFailure(str(e), where="campaign union", after_start=False)

    colour = "green" if out.clean else "yellow"
    click.echo(_c(f"\n══ campaign {out.campaign_id} · {out.stop.replace('_', ' ')} · "
                  f"{len(out.children)} child run(s) · {out.elapsed_s}s", colour))
    if out.detail:
        click.echo(_c(f"   {out.detail}", colour))
    if out.recovered:
        click.echo(_c("   ⚠ this campaign's union was rebuilt after an evidence loss — not a clean "
                      "fixed point", "yellow"))
    for child in out.children:
        click.echo(f"   {child.index}. {child.run_id} · {child.verdict} · +{child.new} new / "
                   f"+{child.enriched} enriched · {child.retriable} owed")
    click.echo(f"   ledger: {project / 'recon' / 'campaigns' / out.campaign_id / 'ledger.json'}")

    from . import remainder as _remainder
    from .state import CommandResult, Fault
    last_run = out.children[-1].run_id if out.children else None
    # a `terminal` stop is not one outcome: an entitlement we accepted is a bound, an unschedulable or
    # missing dependency is coverage nobody could get, and machinery that broke is a fault
    terminal = _remainder.terminal_class(out.terminal) if out.stop == "terminal" else None
    if out.stop == "child_fault" or terminal == "fault":
        return CommandResult("run", outcome="failed", campaign_id=out.campaign_id,
                             machinery_after_start=True,
                             faults=[Fault("machinery", where="campaign", detail=out.detail or out.stop)],
                             run_id=last_run)
    # a child that ran under a declared bound reports the same evidence a standalone run does, so it must
    # reach the same status rather than converging to clean
    limited = any(c.verdict == "complete_with_limits" for c in out.children)
    # a rebuilt union is lost evidence, so it outranks any named bound the campaign stopped on
    bounded = out.stop in _SETTLE_BOUNDED or terminal == "bounded" or limited
    coverage = ("gapped" if out.recovered else "clean" if out.clean and not limited else
                "intentionally_bounded" if bounded else "gapped")
    return CommandResult("run", coverage=coverage, campaign_id=out.campaign_id, run_id=last_run,
                         remediation=out.detail or None)


def _contained(run_obj, stage: str, fn) -> None:
    """The base commit, inside the same containment the derived views get: a telemetry or manifest write
    that fails must leave a run recorded `finalization_failed`, not a `finalizing` one with no manifest and
    nothing saying why. Never returns normally on failure."""
    from . import exit_contract as _ec
    try:
        fn()
        return
    except Exception as e:                                    # noqa: BLE001
        detail = secrets.redact(str(e)) or type(e).__name__
    # recorded before the raise, so `status` and `report` read the failure rather than infer it
    run_obj.mark_stage(stage, "failed", detail=detail)
    run_obj.write_state("finalization_failed", detail=f"{stage}: {detail}")
    click.echo(_c(f"   ! finalisation stage {stage} failed — {detail}", "red"))
    raise _ec.MachineryFailure(f"{stage} failed — {detail}", where=stage)


def _finalize_stage(run_obj, stage: str, fn, *, force: bool, present=None) -> str:
    """One derived view, and what became of it: `skipped` when already published for this generation,
    `failed` when it raised (a committed publication fault, never a lost run), else `done`.

    A failed stage is durable immediately and reconciliation turns it into the
    manifest's publication fault. `present` answers whether the artifact is
    actually on disk. The generation stamp records what was rendered, not what
    survived, so a deleted view is stale however current its stamp looks.
    """
    if not force and run_obj.stage_current(stage) and (present is None or present()):
        return "skipped"
    try:
        fn()
    except Exception as e:                                    # noqa: BLE001
        detail = secrets.redact(str(e)) or type(e).__name__
        run_obj.mark_stage(stage, "failed", detail=detail)
        click.echo(_c(f"   ! finalisation stage {stage} failed — {detail}", "red"))
        return "failed"
    run_obj.mark_stage(stage, "done")
    return "done"


def _publish_views(run_obj, scope, *, checkpoints=(), force: bool = False,
                   republished: list | None = None) -> dict:
    """Every derived view of a committed run, in one place so `run` and the `report` resume publish the
    same set the same way. `republished` collects the stages this call actually rewrote."""
    import json as _json
    from . import exports, privfs, triage

    exp: dict = {}

    def _exports():
        exp.update(exports.write_all(run_obj) or {})
        exports.write_delta(run_obj)

    def _hotlist():
        privfs.write_private(run_obj.reports / "HOTLIST.md", triage.build(run_obj, scope))

    def _digest():
        privfs.write_private(run_obj.reports / "digest.json",
                             _json.dumps(triage.digest_json(run_obj, scope), indent=2, ensure_ascii=False))

    def _checkpoints():
        if checkpoints:
            privfs.write_private(run_obj.reports / "checkpoints.md",
                                 "# Checkpoints\n\n" + "\n".join(f"- {c.line()}" for c in checkpoints) + "\n")

    # a view deleted since it was stamped is stale, so it is rebuilt rather than skipped as current and
    # then certified away. Two sources, because neither sees everything: the revision pointer knows every
    # file it recorded (and is empty for a base run or an uncertifiable revision), and the artifact checks
    # below cover what no pointer lists.
    from . import revision as _revision
    missing = set(_revision.missing_views(run_obj.dir))

    def _present(own, owns):
        return lambda: own() and not any(owns(name) for name in missing)

    def _has(*names):
        return lambda: all((run_obj.reports / n).exists() for n in names)

    for stage, fn, own, owns in (
            ("exports", _exports, lambda: run_obj.exports.is_dir() and any(run_obj.exports.iterdir()),
             lambda n: n.startswith("exports/") or n == "delta.md"),
            ("hotlist", _hotlist, _has("HOTLIST.md"), lambda n: n == "HOTLIST.md"),
            ("digest", _digest, _has("digest.json"), lambda n: n == "digest.json"),
            ("checkpoints", _checkpoints, _has("checkpoints.md") if checkpoints else (lambda: True),
             lambda n: n == "checkpoints.md")):
        if _finalize_stage(run_obj, stage, fn, force=force, present=_present(own, owns)) != "skipped" \
                and republished is not None:
            republished.append(stage)
    return exp


def _publish_private_report_after_reconcile(
        run_obj, report_obj, *, force: bool = False, republished: list | None = None,
) -> str:
    """Publish the private projection against the final reconciled manifest.

    A prior implementation rendered first and then cleared/added publication
    faults in ``manifest.json``.  The freshly written report was immediately
    stale.  Marking this stage provisionally done lets reconciliation establish
    the exact manifest identity; a subsequent publication fault is recorded and
    reconciled once more, leaving no false-current report.
    """
    from . import privfs, report_truth

    current_before = (
        not force and run_obj.stage_current("private_report")
        and report_truth.published_private_report_current(report_obj)
    )
    if not current_before:
        run_obj.mark_stage("private_report", "done")
    _contained(run_obj, "reconcile", lambda: _reconcile_base(run_obj))
    if (not force and run_obj.stage_current("private_report")
            and report_truth.published_private_report_current(report_obj)):
        return "skipped"
    try:
        document = report_truth.build_private_report(report_obj)
        privfs.write_private(
            report_obj.reports / "private-report.json",
            report_truth.canonical_json_bytes(document).decode("utf-8"),
        )
    except Exception as exc:                                  # noqa: BLE001
        detail = secrets.redact(str(exc)) or type(exc).__name__
        run_obj.mark_stage("private_report", "failed", detail=detail)
        _contained(run_obj, "reconcile", lambda: _reconcile_base(run_obj))
        click.echo(_c(f"   ! finalisation stage private_report failed — {detail}", "red"))
        return "failed"
    if republished is not None:
        republished.append("private_report")
    return "done"


def _reconcile_base(run_obj) -> None:
    """Reconcile the committed manifest with what finalisation just did."""
    run_obj.reconcile_finalization()


def _revision_gap(run_obj):
    """A published revision nobody can certify, as the Gap it is — its late evidence is missing from the
    views being rendered, so nothing built on them may report clean. `absent` is not this: no late
    evidence was ever recorded, and rendering the base is the whole answer."""
    from . import revision as _revision
    from .state import Gap
    status, reason = _revision.certification(run_obj.dir)
    if status != "unusable":
        return None
    return Gap(source_id="revision", kind="unknown",
               reason=f"the published revision cannot be certified ({reason or 'unusable'}) — its late "
                      f"evidence is not in these views")


def _refusal_gap(run_obj):
    """Interactions the corpus envelope is still refusing, carried across revisions.

    A standing refusal is evidence INCOMPLETE, not evidence lost: the revision stays certified, so this is
    its own gap and never the uncertifiable one. Durable, so a later reader reports the same shortfall the
    ingest did rather than a clean run.
    """
    from . import revision as _revision
    from .state import Gap
    n = len(_revision.refusals(run_obj.dir))
    if not n:
        return None
    return Gap(source_id="oob", kind="cap", omitted=n,
               reason=f"{n} interaction(s) refused past the corpus envelope")


def _with_gap(result, *gaps):
    """The same machine result carrying more gaps, so a coverage loss can never leave a clean verdict."""
    from .state import CommandResult
    found = [g for g in gaps if g is not None]
    if not found:
        return result
    return CommandResult(result.command, outcome=result.outcome, coverage="gapped",
                         run_id=result.run_id, campaign_id=result.campaign_id,
                         faults=list(result.faults), gaps=list(result.gaps) + found,
                         remediation=result.remediation, interrupted=result.interrupted,
                         machinery_after_start=result.machinery_after_start)


def _report_view(run_obj):
    """A committed run's certified combined view, else the run itself; bookkeeping stays on the base run.
    `base_finished` is the read predicate and stays true mid-refinalisation, which is when report renders."""
    from . import revision as _revision
    if not _revision.base_finished(run_obj.dir):
        return run_obj
    return _revision.combined_view(run_obj) or run_obj


def _run_phases(profile_path, phases, passive, timeout, prepare=None, finished=None):
    """Run one pipeline inside one private managed-payload snapshot lifetime."""
    from . import runtime_identity
    with runtime_identity.managed_payload_snapshot_scope() as payload_scope:
        return _run_phases_scoped(
            profile_path, phases, passive, timeout, prepare=prepare, finished=finished,
            _payload_scope=payload_scope,
        )


def _run_phases_scoped(profile_path, phases, passive, timeout, prepare=None, finished=None,
                       *, _payload_scope):
    """The run itself, inside whatever policy overrides the flags established. `finished` collects the run
    id as soon as it exists, so a fault mid-run still names the run it happened in."""
    from .phases import REGISTRY, PhaseContext
    from .store import Run
    from . import checkpoint

    try:
        profile = TargetProfile.load(_resolve_profile(profile_path))
    except ProfileError as e:
        raise click.ClickException(str(e))
    if passive:
        profile.modes["PASSIVE_ONLY"] = True
    scope = profile.scope()
    project = _project_dir(profile)

    # pre-run disk gate on the project filesystem, before the run folder is created
    try:
        free_gb = shutil.disk_usage(str(project)).free / (1024 ** 3)
    except OSError:
        free_gb = None
    if free_gb is not None:
        if free_gb < 2:
            from . import exit_contract as _ec
            raise _ec.Refused(
                f"only {free_gb:.1f} GB free on {project} — a run needs ≥2 GB (output growth). "
                "Free space and retry.")
        if free_gb < 5:
            click.echo(_c(f"⚠ low disk: {free_gb:.1f} GB free on {project} "
                          "(recommend ≥5 GB for big targets)", "yellow"))

    secrets.apply_env()   # export PDCP_API_KEY for PD tools, if set
    from .runner import set_tool_cwd
    run_obj = Run.create(project, profile.target)   # collision-resistant id, atomically-claimed dir
    _payload_scope.bind(run_obj)
    from .network_policy import NetworkPolicyScope
    NetworkPolicyScope.from_profile(profile).bind(run_obj)
    if finished is not None:
        finished["run_id"] = run_obj.run_id
    events.configure(run_obj.dir)   # persist runtime events to <run>/events.jsonl
    workdir = run_obj.dir / "work"
    workdir.mkdir(parents=True, exist_ok=True)
    set_tool_cwd(workdir)   # stray tool files land in the run dir
    ctx = PhaseContext(run=run_obj, profile=profile, scope=scope, workdir=workdir,
                       echo=click.echo, http_timeout=timeout)
    # the only point a campaign may seed this child from earlier children (entities are run-scoped); a
    # seed that fails stops the child, because an empty corpus is not a fixed point
    if prepare is not None:
        prepare(run_obj)
    run_obj.write_state("running")

    selected = _select_phases(phases)   # validated + canonical-ordered (invalid raised before the run)

    click.echo(_c(f"\n══ Quarry run {run_obj.run_id} · target={profile.target} · "
                  f"{'PASSIVE' if profile.passive_only else 'ACTIVE'} ══", "cyan"))
    ports_disp = (f"default ({len(profile.ports)})" if profile.ports_are_default
                  else str(profile.ports))
    click.echo(f"   apexes={len(profile.apex_domains)} cidr={len(profile.cidr)} "
               f"ports={ports_disp} http_rl={profile.http_rl or 'default'}\n")

    # the effective policy, printed and persisted before any lane reads a bound: ceilings are evidence
    from . import policy as _policy
    policy_rows = _policy.snapshot()
    click.echo(_c("   ── effective coverage policy ──", "cyan"))
    for line in _policy.render(policy_rows):
        click.echo(f"   {line}")
    click.echo("")
    events.emit("policy", "run", bounds=policy_rows)

    # readiness gate: warn (never block) if a required tool for the phases that will run is missing
    missing_req = _missing_required(_effective_phases(selected, profile))
    if missing_req:
        click.echo(_c(f"   ⚠ {len(missing_req)} required tool(s) missing for selected phases "
                      f"({', '.join(missing_req[:8])}) — those steps will be skipped. "
                      "Run `quarry doctor`.\n", "yellow"))

    # runtime telemetry: per-phase wall + child CPU + inventory-at-phase
    import time as _time
    from . import metrics
    _INV = ("subdomain", "resolved", "live", "url", "endpoint", "secret", "finding")
    run_t0 = _time.perf_counter()
    run_cpu0 = metrics.rusage()[0]
    phase_metrics: list[dict] = []

    all_cps = []
    import contextlib as _contextlib
    from .runner import have as _have
    from . import nuclei_policy as _nuclei_policy
    _nuclei_selected = bool(set(selected) & {"probe", "enrich", "params"})
    _nuclei_context = (
        _nuclei_policy.run_authority(ctx)
        if _nuclei_selected and not profile.passive_only and _have("nuclei")
        else _contextlib.nullcontext(None)
    )
    with _nuclei_context as _nuclei_authority:
        ctx.nuclei_policy = _nuclei_authority
        for name in selected:
            fn, label, needs_active = REGISTRY[name]
            if needs_active and profile.passive_only:
                click.echo(_c(f"▸ {label} — skipped (passive-only)", "yellow"))
                continue
            click.echo(_c(f"▸ {label}", "magenta"))
            p_t0 = _time.perf_counter()
            p_cpu0 = metrics.rusage()[0]
            try:
                fn(ctx)
            except Exception as e:  # never let one phase kill the run
                if isinstance(e, _nuclei_policy.NucleiPolicyError):
                    # Accepted-policy identity is a run boundary, not a best-effort lane failure.  A
                    # missing/mutated policy, corpus, config, or engine must never reach a sealed manifest.
                    raise
                # redact once: an exception message can carry a URL with a key/token
                err = secrets.redact(str(e)) or ""
                run_obj.notes.append(f"{name}: EXCEPTION {err}")
                click.echo(_c(f"   ! {name} raised {err}", "red"))
                from . import notify
                notify.send("error", f"Quarry {run_obj.run_id} · {profile.target}: {name} phase raised", err)
            p_wall = round(_time.perf_counter() - p_t0, 1)
            phase_metrics.append({"phase": name, "wall_s": p_wall,
                                  "cpu_s": round(metrics.rusage()[0] - p_cpu0, 2),
                                  "size": {e: run_obj.count(e) for e in _INV}})
            # incremental flush so a killed run keeps its telemetry; a flush failure must never break the run
            try:
                _rc, _rss = metrics.rusage()
                metrics.write(run_obj, phase_metrics, _time.perf_counter() - run_t0,
                              _rc - run_cpu0, _rss / 1024)
            except Exception:
                pass
            # log-safe per-phase elapsed footer: no control chars, so tmux and runtime.log stay clean
            click.echo(_c(f"   ⏱ {name} · {p_wall}s", "cyan"))
            cps = checkpoint.evaluate(run_obj, name)
            all_cps += cps
            for cp in cps:
                click.echo("   " + _c(cp.line(), "yellow" if cp.level == "warn" else "white"))
        if _nuclei_authority is not None:
            _nuclei_authority.assert_ready()
        ctx.nuclei_policy = None

    # every checkpoint that challenges what the tool statuses already account for reaches the verdict as a
    # typed gap; committed before the base manifest, so it is in when the verdict is computed
    for cp in all_cps:
        g = cp.gap()
        if g is not None:
            run_obj.commit_gap(g)
    if all_cps:
        run_obj.notes += [c.line() for c in all_cps]

    # ── finalisation ──────────────────────────────────────────────────────────
    # Every classifier which can add an entity or emit coverage runs before the
    # irreversible seal. Derived rendering below is read-only over this base.
    from . import gadgets
    try:
        n_gadgets = gadgets.classify(run_obj, scope)
        if n_gadgets:
            click.echo(_c(f"   ⛓ {n_gadgets} gadget candidate(s) — chain material, not findings", "cyan"))
    except Exception as e:                                    # noqa: BLE001
        run_obj.notes.append(f"gadgets: EXCEPTION {secrets.redact(str(e))}")

    from . import evidence as _evidence
    _evidence.classify_ownership(run_obj)

    # telemetry -> metrics/summary.json, before the manifest so the manifest points at it. It is a derived
    # view like any other: losing it costs the run its telemetry, never its evidence
    run_wall = _time.perf_counter() - run_t0
    tele: dict = {}
    metrics_summary: dict = {}

    def _write_metrics():
        run_cpu, peak_rss_kb = metrics.rusage()
        tel = metrics.write(run_obj, phase_metrics, run_wall, run_cpu - run_cpu0, peak_rss_kb / 1024)
        tele.update(tel)
        metrics_summary.update({"artifact": "metrics/summary.json", **tel["totals"],
                                "slowest_tool": (tel["long_poles"]["tools"][0]
                                                 if tel["long_poles"]["tools"] else None)})

    metrics_error = None
    try:
        _write_metrics()
    except Exception as e:                                    # noqa: BLE001
        metrics_error = secrets.redact(str(e)) or type(e).__name__

    if _nuclei_authority is not None:
        # The launch snapshots have been settled, but the immutable policy must still be the exact bytes
        # whose digest enters the manifest. Missing/mutated policy refuses finalization rather than sealing
        # a run whose resume/events name different accepted inputs.
        _nuclei_authority.assert_artifact()

    _manifest_oob_backend = (
        _nuclei_authority.document["modes"]["oob_backend"]
        if _nuclei_authority is not None else None
    )
    _manifest_oob_channels = (
        [dict(row) for row in _nuclei_authority.document["channels"]]
        if _nuclei_authority is not None else
        _nuclei_policy.channel_summary(profile, _manifest_oob_backend)
    )
    prepared_manifest = run_obj.begin_finalization(
        profile_summary={"apex_domains": profile.apex_domains, "cidr": profile.cidr,
                         "passive_only": profile.passive_only, "ports": profile.ports,
                         "oob_enabled": profile.oob_enabled,
                         "oob_channels": _manifest_oob_channels,
                         "block_private_targets": profile.block_private_targets,
                         "nuclei_policy_digest": (getattr(_nuclei_authority, "digest", None)
                                                  if _nuclei_selected else None),
                         "nuclei_policy": (_nuclei_authority.manifest_summary()
                                           if _nuclei_authority is not None else None)},
        phases_run=selected, metrics=metrics_summary or None, policy=policy_rows,
    )
    if metrics_error is None:
        run_obj.mark_stage("metrics", "done")
    else:
        run_obj.mark_stage("metrics", "failed", detail=metrics_error)
        click.echo(_c(f"   ! finalisation stage metrics failed — {metrics_error}", "red"))

    # Without a manifest there is no verdict to resume to, so publication is
    # contained even though its bytes were computed atomically with the seal.
    _contained(run_obj, "manifest", lambda: run_obj.publish_manifest(prepared_manifest))

    # Derived views and publication bookkeeping are the only mutable surface now.
    exp = _publish_views(run_obj, scope, checkpoints=all_cps) or {}
    _publish_private_report_after_reconcile(run_obj, run_obj)
    failed = run_obj.finalization_failed()
    run_obj.write_state("finalization_failed" if failed else "finished",
                        detail="a derived view could not be published" if failed else None)

    # read the one canonical summary the manifest stores, never recompute
    summ = run_obj.summary()
    verdict, fails, gaps, pexc = (summ["verdict"], summ["failures"], summ["gaps"], summ["phase_exceptions"])
    if verdict == "complete":
        click.echo(_c(f"\n══ complete · {run_obj.dir}", "green"))
    elif verdict == "complete_with_limits":
        click.echo(_c(f"\n══ complete WITH LIMITS · {run_obj.dir}", "cyan"))    # operator-chosen samples
    else:
        click.echo(_c(f"\n══ complete WITH GAPS · {run_obj.dir}", "yellow"))
    click.echo(f"   HOTLIST: {run_obj.reports / 'HOTLIST.md'}")
    click.echo(f"   exports: {', '.join(f'{k}={v}' for k, v in exp.items() if v)}")
    if all_cps:
        click.echo(_c(f"   {len(all_cps)} checkpoint(s) raised — see reports/checkpoints.md", "yellow"))
    if fails:
        shown = ", ".join(sorted({g['tool'] for g in fails})[:6])
        click.echo(_c(f"   ⚠ {len(fails)} tool run(s) failed ({shown}) — see manifest.json "
                      "'summary.failures'", "yellow"))
    if gaps:
        tool_names = sorted({g['tool'] for g in gaps})                 # distinct tools
        detail = sorted({f"{g['tool']}:{g['status']}" for g in gaps})
        click.echo(_c(f"   ⚠ {len(gaps)} degraded run(s) across {len(tool_names)} tool(s) "
                      f"({', '.join(detail[:6])}) — coverage incomplete; preserved output remains "
                      "available where present, see manifest.json 'summary.gaps'", "yellow"))
    if pexc:
        click.echo(_c(f"   ⚠ {len(pexc)} phase exception(s) — see manifest.json 'summary.phase_exceptions'",
                      "yellow"))
    if run_obj.state == "finalization_failed":
        click.echo(_c(f"   ✗ finalisation incomplete — base evidence is committed; resume the derived "
                      f"views with: quarry report -t <target> --run {run_obj.run_id}", "red"))
    cov = [c for c in (summ.get("coverage") or []) if c["omitted"] > 0 or not c["valid"]]
    if cov:   # only sources that omitted input or reported inconsistent counters
        def _lbl(c):
            name = f"{c['source_id']}.{c['measure']}"          # e.g. crawl.xnlinkfinder.files
            if not c["valid"]:
                return f"{name} UNKNOWN"
            kinds = "/".join(sorted(k for k, v in c["by_kind"].items() if v["omitted"] > 0)) or "cap"
            return f"{name} {c['tested']}/{c['eligible']} (−{c['omitted']} {kinds})"
        parts = [_lbl(c) for c in sorted(cov, key=lambda c: -c["omitted"])]
        click.echo(_c(f"   ▤ coverage: {', '.join(parts[:6])} — see manifest.json 'summary.coverage'", "cyan"))

    if (tele.get("long_poles") or {}).get("tools"):
        lp = tele["long_poles"]["tools"][0]
        click.echo(f"   ⏱ {round(run_wall)}s total · slowest tool: {lp['tool']} {lp['wall_s']}s "
                   f"· metrics/summary.json")

    # opt-in notifications (no-op unless configured in secrets.yaml notify:)
    from . import notify
    if notify.configured():
        _fnds = run_obj.read("finding")
        n_sec = run_obj.count("secret")
        n_conf = sum(1 for f in _fnds if f.get("confirmed"))
        n_cand = len(_fnds) - n_conf
        totals = (f"live={len(run_obj.read('live'))} urls={run_obj.count('url')} "
                  f"secrets={n_sec} confirmed={n_conf} candidates={n_cand}")
        leads = n_sec + sum(1 for f in _fnds if f.get("severity") in ("critical", "high"))
        # one consolidated message, rendered from the manifest's structured fields
        notify.send_completion(target=profile.target, run_id=run_obj.run_id, summary=summ,
                               totals=totals, leads=leads)
    return run_obj      # the finished run; a campaign supervisor absorbs its evidence


# ── report ───────────────────────────────────────────────────────────────────
@cli.command()
@click.option("-t", "--target", "profile_path", required=True,
              help="project name, project dir, or target.yaml path")
@click.option("--run", "run_id", help="run id (default: latest)")
@click.option("--force", "force", is_flag=True,
              help="republish every derived view, not only the ones missing or stale against the current "
                   "base evidence")
@_ec_json_option
def report(profile_path, run_id, force, as_json):
    """Regenerate hotlist + exports from a stored run in the project (no scanning).

    Also the resume path for a run whose finalisation failed: the base evidence is untouched, and only the
    views that are missing or stale against it are republished (`--force` rewrites them all).
    """
    from . import exit_contract as _ec
    got: dict = {}

    def body():
        try:
            profile = TargetProfile.load(_resolve_profile(profile_path))
        except ProfileError as e:
            raise click.ClickException(str(e))
        project = _project_dir(profile)
        run_obj = _existing_run(project, profile.target, run_id)   # explicit --run must exist
        if run_obj is None:
            raise click.ClickException(f"no runs found under {project}/recon/")
        got["run_id"] = run_obj.run_id
        # a run whose base evidence never committed has no verdict to republish views against; saying so
        # is the only honest answer, and it is never a success. A damaged manifest is not a commitment
        if not run_obj.manifest_committed():
            raise _ec.MachineryFailure(
                f"run {run_obj.run_id} has no committed manifest — its base evidence was never sealed or "
                f"the manifest is unreadable, so there is nothing to finalise; re-run it",
                where="finalization")
        # An unusable late-evidence pointer is a coverage gap, not a
        # publication task.  Reopening finalisation and attempting to render
        # through it would turn the honest exit-4 gap into a new exit-5
        # private-report failure while still being unable to recover a view.
        revision_gap = _revision_gap(run_obj)
        if revision_gap is not None:
            click.echo(_c(f"   ⚠ {revision_gap.reason}", "yellow"))
            from .state import CommandResult
            return _with_gap(
                CommandResult("report", run_id=run_obj.run_id), revision_gap,
            )
        # minimal scope (report doesn't re-filter)
        from .config import ScopeMatcher
        scope = ScopeMatcher([], [], [], False)
        # Re-finalising reopens only derived-publication bookkeeping. Base
        # evidence remains permanently ineligible for mutation.
        run_obj.reopen_finalization(detail="resumed by report")
        view = _report_view(run_obj)
        republished: list = []
        exp = _publish_views(view, scope, force=force, republished=republished)
        _publish_private_report_after_reconcile(
            run_obj, view, force=force, republished=republished,
        )
        if view is not run_obj:
            from . import revision as _revision
            # re-hashing the regenerated views and reconciling the manifest are both machinery: uncontained,
            # a failure here returns 5 and leaves the run stuck `finalizing` with nothing recording why
            _contained(run_obj, "reseal_views", lambda: _revision.reseal_views(run_obj.dir))
        click.echo(f"{'republished ' + ', '.join(republished) if republished else 'every view was current'}"
                   f" — {view.reports / 'HOTLIST.md'}")
        click.echo(f"exports: {', '.join(f'{k}={v}' for k, v in exp.items() if v)}")
        failed = run_obj.finalization_failed()
        run_obj.write_state("finalization_failed" if failed else "finished")
        if failed:
            raise _ec.MachineryFailure("a derived view could not be published — see the stage detail in "
                                       f"{run_obj.state_path}", where="finalization")
        # late evidence missing from these views, and rows the envelope turned away, are both coverage the
        # report does not have: neither may leave it clean
        gaps = [g for g in (_revision_gap(run_obj), _refusal_gap(run_obj)) if g is not None]
        for g in gaps:
            click.echo(_c(f"   ⚠ {g.reason}", "yellow"))
        from .state import CommandResult
        return _with_gap(CommandResult("report", run_id=run_obj.run_id), *gaps)

    _ec.run_command("report", as_json, body, run_id=lambda: got.get("run_id"))


@cli.command()
@click.option("-t", "--target", "profile_path",
              help="profile/project used for an exact detached Nuclei/OOB policy plan")
def plan(profile_path):
    """Dry-run registry work plus accepted Nuclei/OOB policy. No target requests are made."""
    from . import nuclei_policy as _nuclei_policy, views
    summary = _nuclei_policy.default_plan_summary()
    if profile_path is not None:
        try:
            profile = TargetProfile.load(_resolve_profile(profile_path))
            summary = _nuclei_policy.planning_summary(profile)
        except (ProfileError, _nuclei_policy.NucleiPolicyError) as exc:
            raise click.ClickException(str(exc)) from exc
    for line in views.plan_lines(summary):
        click.echo(line)


@cli.command()
@click.option("-t", "--target", "profile_path", required=True,
              help="project name, project dir, or target.yaml path")
@click.option("--run", "run_id", help="run id (default: latest)")
@click.option("--campaign", "campaign_id", is_flag=False, flag_value="", default=None,
              help="show a `--settle` CAMPAIGN instead of one run: its children, what each added, what is "
                   "still owed and why it stopped (default: the latest campaign)")
@_ec_json_option
def status(profile_path, run_id, campaign_id, as_json):
    """Render current/last-known per-source state from a run's events.jsonl (no scanning)."""
    from . import exit_contract as _ec
    from . import views
    got: dict = {}

    def body():
        try:
            profile = TargetProfile.load(_resolve_profile(profile_path))
        except ProfileError as e:
            raise click.ClickException(str(e))
        project = _project_dir(profile)
        if campaign_id is not None:
            if run_id is not None:
                raise click.UsageError("--run names a run and --campaign a campaign; ask for one of them")
            from . import campaign as _campaign
            try:
                return _echo_campaign(project, campaign_id)
            except _campaign.InvalidCampaignId as e:
                raise click.UsageError(str(e))   # a mistyped id is a bad selector, not broken machinery
            except _campaign.InvalidRunId as e:
                raise _ec.MachineryFailure(str(e), where="campaign ledger", after_start=False)
        run_obj = _existing_run(project, profile.target, run_id)   # explicit --run must exist
        if run_obj is None:
            raise click.ClickException(f"no runs found under {project}/recon/")
        got["run_id"] = run_obj.run_id
        for line in views.status_lines(run_obj.dir / "events.jsonl"):
            click.echo(line)
        # status reports the run's verdict, not its own health. A committed manifest IS that verdict; a
        # run that never closed has none, and saying so is the honest answer
        st = run_obj.state
        from .state import CommandResult, Fault, Gap
        resume = f"resume it: quarry report -t <target> --run {run_obj.run_id}"
        # a recorded finalisation failure is what happened to this run, whatever its manifest was left
        # saying: the manifest may predate the failure entirely, and reading it would report that stale
        # verdict as the answer
        if st == "finalization_failed":
            failed = [(name, rec) for name, rec in sorted(run_obj.finalization_stages.items())
                      if (rec or {}).get("status") == "failed"]
            faults = [Fault("publication", where=name, detail=(rec or {}).get("detail"))
                      for name, rec in failed] or [Fault("publication", where="finalization")]
            return CommandResult("status", outcome="failed", machinery_after_start=True,
                                 run_id=run_obj.run_id, faults=faults, remediation=resume)
        # a damaged manifest is not a commitment: there is no verdict to report from it
        committed = (_ec.from_summary("status", run_obj.summary(), run_id=run_obj.run_id)
                     if run_obj.manifest_committed() else None)
        # late evidence missing from what the run renders, and rows its envelope turned away
        gaps = (_revision_gap(run_obj), _refusal_gap(run_obj))
        if st == "finished" and committed is not None:
            return _with_gap(committed, *gaps)
        if committed is not None and committed.exit_code not in (0, 3):
            return _with_gap(committed, *gaps)  # the committed verdict already names what went wrong
        return _with_gap(CommandResult("status", coverage="gapped", run_id=run_obj.run_id,
                                       gaps=[Gap(source_id="run", kind="unknown",
                                                 reason=f"run state is {st}, not finished")],
                                       remediation=resume), *gaps)

    _ec.run_command("status", as_json, body, run_id=lambda: got.get("run_id"))


def _echo_campaign(project, campaign_id: str):
    """One campaign, read from its ledger, so running, finished and interrupted campaigns all read the same
    way and an unreadable one says so. The ledger's recorded stop is the verdict this command reports.
    """
    from . import campaign as _campaign
    from . import settle as _settle

    if not campaign_id:
        found = _settle.campaigns(project)
        if not found:
            raise click.ClickException(f"no campaigns found under {project}/recon/campaigns/ "
                                       "(a campaign is created by `quarry run --settle`)")
        campaign_id = found[-1].parent.name
    ledger = _campaign.Campaign(project, campaign_id)
    if ledger.status == "new":
        raise click.ClickException(f"no campaign {campaign_id} under {project}/recon/campaigns/")
    for line in _settle.report_lines(ledger):
        click.echo(_c(line, "yellow" if not ledger.trustworthy else "cyan"))
    return _campaign_result(ledger, campaign_id)


def _campaign_result(ledger, campaign_id: str):
    """A campaign's own outcome as the machine result — the same verdict `run --settle` reported when it
    stopped, read back from the ledger so a status check never contradicts the run that wrote it."""
    from . import remainder as _remainder
    from .state import CommandResult, Fault, Gap

    def gapped(reason, *, kind="unknown", remediation=None):
        return CommandResult("status", coverage="gapped", campaign_id=campaign_id, remediation=remediation,
                             gaps=[Gap(source_id="campaign", kind=kind, reason=reason)])

    if not ledger.trustworthy:
        return gapped(f"campaign ledger is {ledger.status}: {ledger.reason}")
    stop = ledger.stop
    if not stop:      # recorded children and no stop: interrupted, and what it owes is unmeasured
        return gapped("the campaign recorded no stop — it did not finish",
                      remediation=f"continue it: quarry run -t <target> --settle "
                                  f"--settle-resume {campaign_id}")
    cause = stop["cause"]
    # a terminal is classified per-cause; a ledger that predates the breakdown cannot tell a bound from a
    # fault, and unmeasured is a gap
    terminal = _remainder.terminal_class(stop["terminal"]) if isinstance(stop.get("terminal"), dict) \
        else None
    if cause == "child_fault" or terminal == "fault":
        return CommandResult("status", outcome="failed", campaign_id=campaign_id,
                             machinery_after_start=True,
                             faults=[Fault("machinery", where="campaign", detail=stop["detail"] or cause)],
                             remediation=stop["detail"] or None)
    if cause == "terminal" and terminal is None:
        return gapped(f"terminal: {stop['detail']}" if stop["detail"] else "terminal work remains")
    if ledger.truth.abandoned:
        return gapped("a child run could not be measured and was abandoned")
    if stop["recovered"]:
        return gapped("this campaign's evidence was recovered after a loss")
    if ledger.truth.open_gaps:
        opened = ", ".join(sorted({gap["source_id"] for gap in ledger.truth.open_gaps}))
        return gapped(f"unresolved historical coverage: {opened}")
    # a child that ran under a declared bound reports the same evidence a standalone run does, so it must
    # reach the same status: converging it to clean would make `--settle` hide what `run` states
    limited = any(c.get("verdict") == "complete_with_limits" for c in ledger.children)
    bounded = cause in _SETTLE_BOUNDED or terminal == "bounded" or limited
    if stop["clean"] and not limited:
        return CommandResult("status", campaign_id=campaign_id)
    if bounded:
        return CommandResult("status", coverage="intentionally_bounded", campaign_id=campaign_id,
                             remediation=stop["detail"] or None)
    return gapped(f"{cause}: {stop['detail']}" if stop["detail"] else cause)


@cli.group()
def oob():
    """Out-of-band interaction: one Quarry-owned callback layer over interactsh-client. `poll` resumes a
    run's owned session and pulls delayed callbacks, correlated to their source; `import` ingests external
    callback logs, attributed only when a row matches a Quarry-issued token."""


@oob.command("import")
@click.argument("src_file", type=click.Path(exists=True, dir_okay=False))
@click.option("-t", "--target", "profile_path", required=True,
              help="project name, project dir, or target.yaml path")
@click.option("--run", "run_id", help="run id (default: latest)")
@_ec_json_option
def oob_import(src_file, profile_path, run_id, as_json):
    """Import external interactsh -json (JSONL) callback logs into a run as oob_interaction rows.

    Compatibility path for callbacks Quarry did not issue; recorded as evidence without attribution unless a
    row matches a Quarry-issued token. Raw import kept under raw/oob/. A finished run is not rewritten: its
    rows land in an append-only supplement under revisions/ and a new revision of the combined view is
    published, with its own counts, digests and reports.
    """
    from . import exit_contract as _ec
    got: dict = {}
    _ec.run_command("oob import", as_json, lambda: _oob_import(src_file, profile_path, run_id, got),
                    run_id=lambda: got.get("run_id"))


def _oob_import(src_file, profile_path, run_id, got):
    from . import oob as oobmod

    try:
        profile = TargetProfile.load(_resolve_profile(profile_path))
    except ProfileError as e:
        raise click.ClickException(str(e))
    project = _project_dir(profile)
    run_obj = _existing_run(project, profile.target, run_id)
    if run_obj is None:
        raise click.ClickException(f"no runs found under {project}/recon/")
    got["run_id"] = run_obj.run_id
    res = _oob_ingest(lambda: oobmod.import_file(run_obj, src_file, scope=profile.scope()))
    proto = ", ".join(f"{k}={v}" for k, v in sorted(res["by_protocol"].items())) or "(none)"
    ncorr = res.get("correlated", 0)
    # correlated only when the imported log carried a Quarry-issued token; otherwise uncorrelated
    attr = (f"{ncorr} correlated to a Quarry token, {res['added'] - ncorr} uncorrelated"
            if ncorr else "uncorrelated (no matching Quarry-issued token)")
    click.echo(f"oob import: {res['parsed']} parsed · {res['added']} new oob_interaction(s) [{proto}] "
               f"· {attr} -> {_oob_sink(run_obj, res)}")
    return _oob_result("oob import", run_obj, res)


@oob.command("poll")
@click.option("-t", "--target", "profile_path", required=True,
              help="project name, project dir, or target.yaml path")
@click.option("--run", "run_id", help="run id (default: latest)")
@click.option("--wait", type=click.IntRange(min=0), default=8, show_default=True,
              help="seconds to let the resumed client fetch buffered callbacks")
@_ec_json_option
def oob_poll(profile_path, run_id, wait, as_json):
    """Resume a run's owned interactsh session and poll for delayed callbacks.

    Re-opens the same session (via its -session-file) so late SSRF/blind interactions correlate back to
    their source, adding any new correlated oob_interaction rows.
    """
    from . import exit_contract as _ec
    got: dict = {}
    _ec.run_command("oob poll", as_json, lambda: _oob_poll(profile_path, run_id, wait, got),
                    run_id=lambda: got.get("run_id"))


def _oob_poll(profile_path, run_id, wait, got):
    import time as _time
    from . import oob as oobmod
    from . import exit_contract as _ec

    try:
        profile = TargetProfile.load(_resolve_profile(profile_path))
    except ProfileError as e:
        raise click.ClickException(str(e))
    if not profile.oob_enabled:
        raise _ec.Refused(
            "OOB network polling is disabled by MODES.OOB_ENABLED=false; local `quarry oob import` "
            "remains available"
        )
    project = _project_dir(profile)
    run_obj = _existing_run(project, profile.target, run_id)
    if run_obj is None:
        raise click.ClickException(f"no runs found under {project}/recon/")
    got["run_id"] = run_obj.run_id
    from . import nuclei_policy as _nuclei_policy
    if not run_obj.manifest_committed():
        raise _ec.Refused(
            f"run {run_obj.run_id} has no committed manifest/frozen OOB channel; network polling "
            "is refused, but local `quarry oob import` remains available"
        )
    from . import run_manifest as _run_manifest
    try:
        _manifest_profile = _run_manifest.read(run_obj.manifest_path).document["profile"]
    except _run_manifest.ManifestError as exc:
        raise _ec.MachineryFailure(
            f"run {run_obj.run_id} OOB policy cannot be authenticated: {exc}", where="oob policy",
        ) from exc
    if _manifest_profile.get("oob_enabled") is False:
        raise _ec.Refused(
            f"run {run_obj.run_id} was created with MODES.OOB_ENABLED=false; network polling "
            "cannot be enabled after the fact, but local `quarry oob import` remains available"
        )
    try:
        _policy_document = _nuclei_policy.published_document(
            run_obj, _manifest_profile.get("nuclei_policy"),
        )
        _poll_channel = next(
            row for row in _policy_document["channels"] if row["owner"] == "quarry.oob_poll"
        )
        if not _poll_channel["enabled"]:
            raise _ec.Refused(
                f"run {run_obj.run_id} froze quarry.oob_poll disabled; local `quarry oob import` "
                "remains available"
            )
        _modes = _policy_document["modes"]
        _current_private = (secrets.oob()
                            if _modes["oob_backend"] == "self-hosted"
                            and _modes["oob_auth"] == "private-config" else None)
        _cfg = _nuclei_policy.authenticate_frozen_oob(_policy_document, _current_private)
    except _nuclei_policy.NucleiPolicyError as exc:
        raise _ec.Refused(str(exc)) from exc
    resumed = oobmod.resume_session(run_obj, token=_cfg.get("auth_token"),
                                    server=_modes["oob_server"]
                                    if _modes["oob_backend"] == "self-hosted" else None,
                                    expected_server=_modes["oob_server"]
                                    if _modes["oob_backend"] == "self-hosted" else None)
    if resumed is None:
        raise click.ClickException("no resumable OOB session for this run "
                                   "(session.json missing, interactsh-client absent, or domain mismatch)")
    session, proc = resumed
    try:
        if wait:
            _time.sleep(wait)                       # let the resumed client fetch buffered callbacks
        rows = oobmod.poll_session(run_obj, session)
    finally:
        oobmod.close_session(proc)
    res = _oob_ingest(lambda: oobmod.import_polled(run_obj, session, rows, scope=profile.scope()))
    click.echo(f"oob poll: +{res['added']} new interaction(s) ({res['correlated']} correlated) "
               f"-> {_oob_sink(run_obj, res)}")
    return _oob_result("oob poll", run_obj, res)


def _oob_result(command: str, run_obj, res):
    """What an OOB ingest leaves behind: callbacks the corpus envelope refused are held and not stored.

    Reported on what STANDS across every revision, not just what this ingest turned away — an import that
    refused nothing still runs against a run that owes rows, and saying `clean` there would contradict the
    `status` that follows it."""
    from .state import CommandResult, Gap
    refused, outstanding = int(res.get("refused") or 0), int(res.get("outstanding") or 0)
    standing = outstanding or refused
    if not standing:
        return CommandResult(command, run_id=run_obj.run_id)
    reason = f"{standing} interaction(s) refused past the corpus envelope"
    if refused and refused != standing:
        reason += f" ({refused} in this ingest)"
    return CommandResult(command, coverage="gapped", run_id=run_obj.run_id,
                         gaps=[Gap(source_id="oob", kind="cap", omitted=standing, reason=reason)],
                         remediation="raise the corpus envelope and re-import")


def _oob_ingest(work):
    """Run one OOB ingest; a revision that cannot be published or certified is machinery, not bad input."""
    from . import exit_contract as _ec
    from .revision import RevisionError

    try:
        return work()
    except RevisionError as e:
        raise _ec.MachineryFailure(str(e), where="revision")


def _oob_sink(run_obj, res) -> str:
    """Where the rows landed: a finished run's supplement revision, else the run's own entity log."""
    rev = res.get("revision")
    if rev is None:
        return str(run_obj.dir / "normalized" / "oob_interaction.jsonl")
    return (f"revision {rev.revision} · oob_interaction={rev.entity_counts.get('oob_interaction', 0)} "
            f"· {run_obj.dir / 'revisions' / rev.views.get('dir', '')}")


if __name__ == "__main__":
    cli()
