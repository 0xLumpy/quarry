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
    from .store import Run
    if run_id:
        try:
            return Run.open(project, target, run_id)    # open, never fabricate a ghost dir
        except FileNotFoundError:
            raise click.ClickException(f"run {run_id!r} not found under {Path(project) / 'recon'}")
    return Run.latest(project)


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
    """An OOS CLI argument as a validated regex string: a bare label -> subdomain prefix, a bare FQDN ->
    anchored exact, `*.x` -> subdomain glob, an explicit regex kept as-is. Raises re.error on an invalid
    result.
    """
    if _OOS_REGEX_META.search(value):
        re.compile(value)                                      # validate explicit regex
        return value
    if "." not in value:                                       # bare label -> subdomain-prefix
        # a bare label matches any host under that label (^jobs\.)
        pat = "^" + re.escape(value) + r"\."
    else:
        pat = "^" + re.escape(value).replace(r"\*", ".*") + "$"    # FQDN / glob -> anchored regex
    re.compile(pat)
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


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
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
def lock(drift_only, maintenance):
    """Capture installed tool versions on this host as a reviewable pin set (paste `version:` lines into
    data/tools.yaml). Run on a validated host. Also flags drift and unpinned tools.
    """
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
            raise SystemExit(1)
        click.echo(_c("\nall installed tools verify against the lock", "green"))
        return
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
def doctor(phase):
    """Audit local setup: tools, versions, API keys, resolvers, wordlists."""
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
    srv = str(ob.get("callback_server") or "").strip()
    if srv:
        click.echo(f"  {_c('✓', 'green')} {'callback server:':<20} {srv}")
    else:
        click.echo(f"  {_c('·', 'yellow')} {'callback server:':<20} not set")

    # readiness verdict — the one-line rollup (required tools are the only blocker; keys are optional)
    scope_note = f" for phase {phase}" if phase else ""
    if miss:
        verdict = _c(f"✗ NOT READY — {miss} required tool(s) missing{scope_note}", "red") + \
            "  → quarry install"
    elif warn:
        verdict = _c(f"⚠ DEGRADED — {warn} present but UNVERIFIED (drift/identity/capability){scope_note}", "yellow") + \
            "  → quarry install  (reinstalls to the pin)"
    else:
        verdict = _c("✓ READY", "green") + f" — {ok} tools installed + verified, all required present{scope_note}"
    click.echo(f"\n{verdict}\n")


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
def install(dry_run, phase, only, include_optional, tools_only, yes):
    """Full blank-VPS install: system pkgs -> Go -> tools -> wordlists/templates."""
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
            raise click.ClickException(
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
        return
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
        raise SystemExit(1)                              # required failures propagate a non-zero exit
    elif not os.environ.get("QUARRY_FROM_INSTALLER"):
        # install.sh prints the final banner itself; conclude here only when run standalone
        tail = "" if not soft else f" ({len(soft)} optional failed — see above)"
        click.echo(_c(f"\ninstall complete — required tools ok{tail}\nrun  quarry doctor  to verify", "green"))


@cli.command()
@click.option("--dry-run", is_flag=True)
def update(dry_run):
    """Reinstall installed tools at their pinned lock (reproducible) and refresh templates, resolvers and gf
    patterns. Never floats to @latest — bumping a pin is the `quarry lock` workflow.
    """
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
        raise SystemExit(1)


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
    """Add out-of-scope patterns to a project's target.yaml. A bare host becomes an anchored regex, `*.x` a
    subdomain glob, a real regex is kept verbatim; the resulting profile must compile before anything is
    written.
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
        except re.error as e:
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
def osint(profile_path, timeout, unbound):
    """Pre-flight OSINT: discover scope candidates and intel. Review-only — never edits scope.

    Workflow: init -> fill anchors -> `quarry osint` -> review the report and suggested.yaml -> confirm into
    target.yaml -> `quarry run`. Output lands in the project's osint/ dir.
    """
    import json
    from . import osint as osint_mod

    if timeout <= 0:      # osint bounds each lookup with min(timeout, N); 0 fails every lookup instantly
        raise click.ClickException("osint --timeout must be > 0 (it's a per-lookup ceiling; there is no unbounded osint)")
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
def run(profile_path, phases, passive, timeout, unbound, settle_flag, settle_max_runs, settle_budget):
    """Run recon phases against the confirmed scope. Output lands in the project's recon/ dir."""
    from . import settings

    # refuse the settle bounds without the axis they bound
    if not settle_flag and (settle_max_runs is not None or settle_budget is not None):
        raise click.UsageError("--settle-max-runs / --settle-budget bound a campaign; they need --settle")

    # validate the phase selector before any run/campaign side effect (invalid -> exit 2, no run)
    _select_phases(phases)

    # --unbound for this run: entered before any lane reads a bound, restored on the way out so it
    # never leaks into another run sharing this interpreter
    from . import policy as _policy
    with settings.overrides(_policy.unbound_overrides() if unbound else {}):
        if not settle_flag:
            _run_phases(profile_path, phases, passive, timeout)
            return
        _settle_run(profile_path, phases, passive, timeout,
                    max_runs=settle_max_runs, budget_s=settle_budget)


def _settle_run(profile_path, phases, passive, timeout, *, max_runs, budget_s):
    """`--settle`: a campaign over ordinary runs. The axes compose — `--unbound` widens every child,
    `--timeout` bounds every child's tools.
    """
    from . import campaign as _campaign
    from . import budget, settle as _settle

    try:
        profile = TargetProfile.load(_resolve_profile(profile_path))
    except ProfileError as e:
        raise click.ClickException(str(e))
    project = _project_dir(profile)

    def launch(index, prepare):
        return _run_phases(profile_path, phases, passive, timeout, prepare=prepare)

    try:
        out = _settle.settle(project_dir=project, target=profile.target, launch=launch,
                             max_runs=max_runs or _campaign.MAX_CHILDREN, budget_s=budget_s or 0,
                             echo=lambda line: click.echo(_c(line, "cyan")))
    except budget.StateBusy as e:
        raise click.ClickException(f"another campaign is already running on this project ({e})")
    except (_campaign.UnionUnusable, _settle.AlreadyRun) as e:
        raise click.ClickException(str(e))

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


def _run_phases(profile_path, phases, passive, timeout, prepare=None):
    """The run itself, inside whatever policy overrides the flags established."""
    from .phases import REGISTRY, PhaseContext
    from .store import Run
    from . import checkpoint, exports, triage

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
            raise click.ClickException(
                f"only {free_gb:.1f} GB free on {project} — a run needs ≥2 GB (output growth). "
                "Free space and retry.")
        if free_gb < 5:
            click.echo(_c(f"⚠ low disk: {free_gb:.1f} GB free on {project} "
                          "(recommend ≥5 GB for big targets)", "yellow"))

    secrets.apply_env()   # export PDCP_API_KEY for PD tools, if set
    from .runner import set_tool_cwd
    run_obj = Run.create(project, profile.target)   # collision-resistant id, atomically-claimed dir
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

    # gadget candidates — chain material from evidence the run holds, before the reports so they carry
    # it. Contacts nothing; best-effort, since a classifier is a report.
    from . import gadgets
    try:
        n_gadgets = gadgets.classify(run_obj, scope)
        if n_gadgets:
            click.echo(_c(f"   ⛓ {n_gadgets} gadget candidate(s) — chain material, not findings", "cyan"))
    except Exception as e:                                    # noqa: BLE001
        run_obj.notes.append(f"gadgets: EXCEPTION {secrets.redact(str(e))}")

    # reports + exports — evidence carrying discovered findings; written 0600, O_NOFOLLOW
    from . import privfs
    exp = exports.write_all(run_obj)
    exports.write_delta(run_obj)
    hot = triage.build(run_obj, scope)
    privfs.write_private(run_obj.reports / "HOTLIST.md", hot)
    import json as _json
    privfs.write_private(run_obj.reports / "digest.json",
                         _json.dumps(triage.digest_json(run_obj, scope), indent=2, ensure_ascii=False))
    if all_cps:
        privfs.write_private(run_obj.reports / "checkpoints.md",
                             "# Checkpoints\n\n" + "\n".join(f"- {c.line()}" for c in all_cps) + "\n")
        run_obj.notes += [c.line() for c in all_cps]

    # telemetry -> metrics/summary.json, before the manifest so the manifest points at it
    run_wall = _time.perf_counter() - run_t0
    run_cpu, peak_rss_kb = metrics.rusage()
    tel = metrics.write(run_obj, phase_metrics, run_wall, run_cpu - run_cpu0, peak_rss_kb / 1024)
    metrics_summary = {"artifact": "metrics/summary.json", **tel["totals"],
                       "slowest_tool": tel["long_poles"]["tools"][0] if tel["long_poles"]["tools"] else None}

    run_obj.write_manifest(
        profile_summary={"apex_domains": profile.apex_domains, "cidr": profile.cidr,
                         "passive_only": profile.passive_only, "ports": profile.ports},
        phases_run=selected, metrics=metrics_summary, policy=policy_rows)

    # read the one canonical summary the manifest stores, never recompute
    summ = run_obj._run_summary()
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

    if tel["long_poles"]["tools"]:
        lp = tel["long_poles"]["tools"][0]
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
def report(profile_path, run_id):
    """Regenerate hotlist + exports from a stored run in the project (no scanning)."""
    from . import exports, triage

    try:
        profile = TargetProfile.load(_resolve_profile(profile_path))
    except ProfileError as e:
        raise click.ClickException(str(e))
    project = _project_dir(profile)
    run_obj = _existing_run(project, profile.target, run_id)   # explicit --run must exist
    if run_obj is None:
        raise click.ClickException(f"no runs found under {project}/recon/")
    # minimal scope (report doesn't re-filter)
    from .config import ScopeMatcher
    scope = ScopeMatcher([], [], [], False)
    from . import privfs
    exp = exports.write_all(run_obj)
    exports.write_delta(run_obj)
    privfs.write_private(run_obj.reports / "HOTLIST.md", triage.build(run_obj, scope))
    import json as _json
    privfs.write_private(run_obj.reports / "digest.json",
                         _json.dumps(triage.digest_json(run_obj, scope), indent=2, ensure_ascii=False))
    click.echo(f"regenerated {run_obj.reports / 'HOTLIST.md'} + digest.json + delta.md")
    click.echo(f"exports: {', '.join(f'{k}={v}' for k, v in exp.items() if v)}")


@cli.command()
def plan():
    """Static dry-run: explain what would run (registry + machine settings). No scanning."""
    from . import views
    for line in views.plan_lines():
        click.echo(line)


@cli.command()
@click.option("-t", "--target", "profile_path", required=True,
              help="project name, project dir, or target.yaml path")
@click.option("--run", "run_id", help="run id (default: latest)")
@click.option("--campaign", "campaign_id", is_flag=False, flag_value="", default=None,
              help="show a `--settle` CAMPAIGN instead of one run: its children, what each added, what is "
                   "still owed and why it stopped (default: the latest campaign)")
def status(profile_path, run_id, campaign_id):
    """Render current/last-known per-source state from a run's events.jsonl (no scanning)."""
    from . import views

    try:
        profile = TargetProfile.load(_resolve_profile(profile_path))
    except ProfileError as e:
        raise click.ClickException(str(e))
    project = _project_dir(profile)
    if campaign_id is not None:
        if run_id:
            raise click.UsageError("--run names a run and --campaign a campaign; ask for one of them")
        _echo_campaign(project, campaign_id)
        return
    run_obj = _existing_run(project, profile.target, run_id)   # explicit --run must exist
    if run_obj is None:
        raise click.ClickException(f"no runs found under {project}/recon/")
    for line in views.status_lines(run_obj.dir / "events.jsonl"):
        click.echo(line)


def _echo_campaign(project, campaign_id: str) -> None:
    """One campaign, read from its ledger, so running, finished and interrupted campaigns all read the same
    way and an unreadable one says so.
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
def oob_import(src_file, profile_path, run_id):
    """Import external interactsh -json (JSONL) callback logs into a run as oob_interaction rows.

    Compatibility path for callbacks Quarry did not issue; recorded as evidence without attribution unless a
    row matches a Quarry-issued token. Raw import kept under raw/oob/.
    """
    from . import oob as oobmod

    try:
        profile = TargetProfile.load(_resolve_profile(profile_path))
    except ProfileError as e:
        raise click.ClickException(str(e))
    project = _project_dir(profile)
    run_obj = _existing_run(project, profile.target, run_id)
    if run_obj is None:
        raise click.ClickException(f"no runs found under {project}/recon/")
    res = oobmod.import_file(run_obj, src_file)
    proto = ", ".join(f"{k}={v}" for k, v in sorted(res["by_protocol"].items())) or "(none)"
    ncorr = res.get("correlated", 0)
    # correlated only when the imported log carried a Quarry-issued token; otherwise uncorrelated
    attr = (f"{ncorr} correlated to a Quarry token, {res['added'] - ncorr} uncorrelated"
            if ncorr else "uncorrelated (no matching Quarry-issued token)")
    click.echo(f"oob import: {res['parsed']} parsed · {res['added']} new oob_interaction(s) [{proto}] "
               f"· {attr} -> {run_obj.dir / 'normalized' / 'oob_interaction.jsonl'}")


@oob.command("poll")
@click.option("-t", "--target", "profile_path", required=True,
              help="project name, project dir, or target.yaml path")
@click.option("--run", "run_id", help="run id (default: latest)")
@click.option("--wait", type=click.IntRange(min=0), default=8, show_default=True,
              help="seconds to let the resumed client fetch buffered callbacks")
def oob_poll(profile_path, run_id, wait):
    """Resume a run's owned interactsh session and poll for delayed callbacks.

    Re-opens the same session (via its -session-file) so late SSRF/blind interactions correlate back to
    their source, adding any new correlated oob_interaction rows.
    """
    import time as _time
    from . import oob as oobmod

    try:
        profile = TargetProfile.load(_resolve_profile(profile_path))
    except ProfileError as e:
        raise click.ClickException(str(e))
    project = _project_dir(profile)
    run_obj = _existing_run(project, profile.target, run_id)
    if run_obj is None:
        raise click.ClickException(f"no runs found under {project}/recon/")
    # current oob config; resume_session couples the token to the saved session's server (not persisted)
    _cfg = secrets.oob()
    resumed = oobmod.resume_session(run_obj, token=_cfg.get("auth_token"),
                                    server=_cfg.get("callback_server"))
    if resumed is None:
        raise click.ClickException("no resumable OOB session for this run "
                                   "(session.json missing, interactsh-client absent, or domain mismatch)")
    session, proc = resumed
    added = correlated = 0
    try:
        if wait:
            _time.sleep(wait)                       # let the resumed client fetch buffered callbacks
        for row in oobmod.poll_session(run_obj, session):
            row.setdefault("raw_ref", session.get("log"))
            if run_obj.add("oob_interaction", row):
                added += 1
                correlated += 1 if row.get("correlation") == "correlated" else 0
    finally:
        oobmod.close_session(proc)
    click.echo(f"oob poll: +{added} new interaction(s) ({correlated} correlated) "
               f"-> {run_obj.dir / 'normalized' / 'oob_interaction.jsonl'}")


if __name__ == "__main__":
    cli()
