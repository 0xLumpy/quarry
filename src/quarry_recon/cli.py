"""quarry — command surface: install · update · doctor · init · osint · run · report."""
from __future__ import annotations

import os
import re
import shutil
from importlib import resources
from pathlib import Path

import click

from . import __version__, events, secrets
from .config import ProfileError, TargetProfile
from .registry import load_tools, run_shell, tools_by_phase


def _projects_root(opt: str | None) -> Path:
    """Where `quarry init` creates project dirs. Home-anchored default (~/projects) so a run doesn't
    depend on the cwd — a project is found the same way no matter where you invoke quarry from.
    Override explicitly with --projects-dir or $QUARRY_PROJECTS (e.g. to keep them in the cwd)."""
    return Path(opt or os.environ.get("QUARRY_PROJECTS") or (Path.home() / "projects"))


def _project_dir(profile) -> Path:
    """A profile's project dir = the directory its target.yaml lives in. Output (osint/, recon/)
    co-locates with the profile (campaign/project model)."""
    return (profile.path.parent if profile.path else Path(".")).resolve()


def _existing_run(project, target, run_id):
    """Resolve a run for read/import commands. An explicit --run must ALREADY exist — Run() mkdirs, so
    a typo would silently create a ghost run (and, for import, write evidence under it). Fail loud
    instead. No run_id -> the latest run (or None)."""
    from .store import Run
    if run_id:
        if not (Path(project) / "recon" / run_id).is_dir():
            raise click.ClickException(f"run {run_id!r} not found under {Path(project) / 'recon'}")
        return Run(project, target, run_id=run_id)
    return Run.latest(project)


def _resolve_profile(value: str) -> str:
    """Accept `-t` as a target.yaml path, a project dir, or a bare project name. A name/dir
    resolves to <projects-root>/<name>/target.yaml — so `quarry run -t 0xlumpy.cc` just works."""
    p = Path(value).expanduser()      # so a quoted ~ still works (shell expands an unquoted one)
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
    """Turn an OOS CLI argument into a VALID regex string (validated via re.compile):
      - bare label       jobs            -> ^jobs\\.              (any host under the `jobs.` label)
      - bare FQDN        banana.acme.com -> ^banana\\.acme\\.com$  (exact, apex-scoped)
      - host glob `*`    *.acme.com      -> ^.*\\.acme\\.com$      (any subdomain)
      - explicit regex   ^jobs\\.         -> kept as-is (must compile)
    Raises re.error if the result (or an explicit regex) is invalid — caller refuses to write."""
    if _OOS_REGEX_META.search(value):
        re.compile(value)                                      # validate explicit regex
        return value
    if "." not in value:                                       # bare label -> subdomain-prefix
        # `jobs` means "any host under the `jobs.` label" (matches the template's ^jobs\.). The old
        # `^jobs$` never matched via .search() against a FQDN, so a bare label was a silent no-op.
        pat = "^" + re.escape(value) + r"\."
    else:
        pat = "^" + re.escape(value).replace(r"\*", ".*") + "$"    # FQDN / glob -> anchored regex
    re.compile(pat)
    return pat


def _c(s, color):  # tiny colorizer
    return click.style(s, fg=color)


def _echo_syscheck(rep) -> None:
    marks = {"ok": _c("✓", "green"), "warn": _c("⚠", "yellow"), "abort": _c("✗", "red")}
    for text, lvl in rep["checks"]:   # thresholds live in the README, not every line
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
    """Required (non-optional) tools that are NOT installed, optionally limited to a set of phases.
    The readiness signal for doctor's verdict + the pre-run gate. Quarry-owned only — tool-native
    source keys (subfinder/amass configs) are the tool's concern, documented in install/docs."""
    return sorted({t.bin for t in load_tools()
                   if not t.optional and not t.installed
                   and (phase_filter is None or t.phase in phase_filter)})


def _effective_phases(selected, profile) -> set:
    """Phases that will ACTUALLY do work under the profile's modes — so the readiness warn doesn't
    flag tools for phases that self-skip: passive mode drops needs_active phases, and
    CONTENT_DISCOVERY: off drops content (missing ffuf shouldn't warn when content is off)."""
    from .phases import REGISTRY
    eff = {p for p in selected if p in REGISTRY}
    if profile.passive_only:
        eff = {p for p in eff if not REGISTRY[p][2]}          # index 2 = needs_active
    if getattr(profile, "content_discovery", None) == "off":
        eff.discard("content")
    return eff


# ── doctor ──────────────────────────────────────────────────────────────────
@cli.command()
@click.option("--phase", help="only audit tools for this phase")
def doctor(phase):
    """Audit local setup: tools, versions, API keys, resolvers, wordlists."""
    tools = tools_by_phase(phase) if phase else load_tools()
    ok = warn = miss = 0
    click.echo(_c(f"\nQuarry doctor — {len(tools)} tools\n", "cyan"))
    cur_phase = None
    for t in sorted(tools, key=lambda x: (x.phase, x.bin)):
        if t.phase != cur_phase:
            cur_phase = t.phase
            click.echo(_c(f"[{cur_phase}]", "magenta"))
        if t.installed:
            ok += 1
            ver = t.version()
            click.echo(f"  {_c('✓', 'green')} {t.bin:<20} {ver}")
        elif t.optional:
            click.echo(f"  {_c('·', 'yellow')} {t.bin:<20} optional, not installed")
        else:
            miss += 1
            click.echo(f"  {_c('✗', 'red')} {t.bin:<20} MISSING — quarry install --only {t.bin}")
        if t.needs_chromium and t.installed and not _chromium():
            click.echo(f"      {_c('⚠ needs chromium — not found; screenshots/headless will fail', 'red')}")

    # environment checks
    click.echo(_c("\n[environment]", "magenta"))
    cfg = Path.home() / ".config/quarry"
    # Resolvers + wordlists are NOT optional (unlike API keys) — they're standard install artifacts,
    # and without them core steps can't run (no DNS wordlist → brute skips, no vhost list → vhost enum
    # skips, etc.). So a missing one is a WARNING with the fix, not a soft "(optional)". wordlists live
    # under wordlists/ (clean layout); older installs kept them at the config root — check the canonical
    # path first, then the back-compat one, and show whichever exists.
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

    from . import bootstrap
    click.echo(_c("\n[system]", "magenta"))
    _echo_syscheck(bootstrap.system_report("run"))   # post-install: only run space matters

    # secrets.yaml — framework-read keys (present / not set). Quarry-owned keys only; tool-native
    # source keys (subfinder/amass) live in each tool's own config (documented in install + docs).
    click.echo(_c("\n[secrets]", "magenta") + f"  ({secrets.PATH})")
    secrets_present = secrets.PATH.exists()
    if not secrets_present:
        click.echo(f"  {_c('✗', 'red')} secrets.yaml NOT FOUND — run `quarry install` to recreate it "
                   f"from the template (or restore a backup); keys read as unset until it exists")
    n_gh = len(secrets.github_tokens())
    rows = [("github tokens", bool(n_gh), f"{n_gh} token(s)" if n_gh else ""),
            ("shodan", bool(secrets.shodan()), ""),
            ("whoxy", bool(secrets.whoxy()), ""),
            ("projectdiscovery/chaos", bool(secrets.chaos()), ""),
            ("certspotter", bool(secrets.certspotter()), "CT (optional; free tier keyless)")]
    for label, present, extra in rows:
        mark = _c("✓", "green") if present else _c("·", "yellow")
        click.echo(f"  {mark} {label:<24} {extra or ('' if present else '(optional) not set')}")
    # Censys Platform — ADVANCED opt-in; shown ONLY when configured (silent otherwise, by design)
    cen = secrets.censys()
    if cen.get("token") and cen.get("org"):
        click.echo(f"  {_c('✓', 'green')} censys (advanced)          Platform cert search")
    # template drift: the shipped template can gain new optional keys, but bootstrap NEVER overwrites
    # an existing secrets.yaml (so it can't clobber your keys) — so surface any key the template has
    # that your file predates. ONLY when the file exists: a missing file isn't "drift" (every key
    # would falsely look predated), it's the NOT-FOUND case handled above.
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
    click.echo(_c("\n[oob]", "magenta") + "  (out-of-band interaction)")
    if _have_ic:
        click.echo(f"  {_c('✓', 'green')} interactsh-client present (probes + poll)")
    else:
        click.echo(f"  {_c('✗', 'red')} interactsh-client MISSING — quarry install --only interactsh-client")
    if ob.get("interactsh_server"):
        tok = " +token" if ob.get("interactsh_token") else " (no token)"
        click.echo(f"  {_c('✓', 'green')} backend: self-hosted {ob['interactsh_server']}{tok}")
    else:
        click.echo(f"  {_c('·', 'yellow')} backend: public interactsh (set oob.interactsh_server to self-host)")
    if ob.get("blind_xss_url"):
        click.echo(f"  {_c('✓', 'green')} blind XSS: dalfox -b → {ob['blind_xss_url']}")

    # readiness verdict — the one-line rollup (required tools are the only blocker; keys are optional)
    scope_note = f" for phase {phase}" if phase else ""
    if miss:
        verdict = _c(f"✗ NOT READY — {miss} required tool(s) missing{scope_note}", "red") + \
            "  → quarry install"
    else:
        verdict = _c("✓ READY", "green") + f" — {ok} tools installed, all required present{scope_note}"
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
    """Fetch/refresh a SINGLE data file by name (resolvers, dns-wordlist, vhost-wordlist,
    content-balanced, content-deep, trusted-resolvers) — granular alternative to a full install."""
    from . import bootstrap
    if not bootstrap.set_data_file(name, url, click.echo):
        raise click.ClickException(f"could not set '{name}' — see the message above")


# ── install / update ─────────────────────────────────────────────────────────
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

    # ── 1. system packages + Go toolchain + data (unless --tools-only / --only / --phase) ──
    full = not (only or phase or tools_only)
    if full:
        click.echo(_c("\n  ◤ QUARRY — methodology-driven recon automation", "cyan"))
        if not dry_run:
            click.echo(_c("  ⏳ Full install builds ~25 Go tools + fetches wordlists/templates — this "
                          "takes several minutes.\n     It is not stuck; grab a coffee.", "yellow"))
        # system-spec precheck (tiered): ok = silent · warn = proceed · below minimum = abort
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
        bootstrap.install_system_packages(click.echo, dry_run)
        click.echo(_c("\n[2/6] Go toolchain", "magenta"))
        bootstrap.ensure_golang(click.echo, dry_run)

    # make freshly-installed Go/pipx bins visible to subsequent tool installs
    for p in (str(Path.home() / "go/bin"), str(Path.home() / ".local/bin"),
              "/usr/local/go/bin"):
        if p not in os.environ.get("PATH", ""):
            os.environ["PATH"] = p + os.pathsep + os.environ.get("PATH", "")

    # ── 2. tools from the registry ──
    tools = load_tools()
    if only:
        tools = [t for t in tools if t.bin == only]
    elif phase:
        tools = [t for t in tools if t.phase == phase]
    if not include_optional and not only:
        tools = [t for t in tools if not t.optional]

    click.echo(_c(f"\n[3/6] tools ({len(tools)})", "magenta"))
    failed = []
    for t in tools:
        if t.installed and not only:
            click.echo(f"  {_c('✓', 'green')} {t.bin} present ({t.path}) — left as-is")
            continue
        if not t.install:
            click.echo(f"  {_c('!', 'yellow')} {t.bin} — manual: {t.doc}")
            continue
        click.echo(f"  {_c('→', 'cyan')} {t.bin}")
        code, _ = run_shell(t.install, dry_run)
        if dry_run:
            continue
        if code == 0 and t.installed:
            click.echo(f"      {_c('ok', 'green')}")
        else:
            failed.append(t.bin)
            click.echo(f"      {_c('FAILED', 'red')}    Retry after install completes: "
                       f"{_c('quarry install --only ' + t.bin, 'cyan')}")
        # (API-key reminders are NOT printed per-tool here — see the post-install summary)

    # ── 3. data files + extras + cleanup ──
    if full:
        click.echo(_c("\n[4/6] data files (resolvers, wordlists)", "magenta"))
        bootstrap.install_data_files(click.echo, dry_run)
        click.echo(_c("\n[5/6] extras (gf patterns, nuclei templates)", "magenta"))
        bootstrap.run_extras(click.echo, dry_run)
        click.echo(_c("\n[6/6] cleanup (reclaim disk)", "magenta"))
        bootstrap.cleanup(click.echo, dry_run)

    if dry_run:
        click.echo(_c("\n(dry-run — nothing was installed)\n", "yellow"))
    elif failed:
        click.echo(_c(f"\n{len(failed)} tool(s) failed: {', '.join(failed)}", "yellow"))
        for b in failed:
            click.echo(f"retry: quarry install --only {b}")
    elif not os.environ.get("QUARRY_FROM_INSTALLER"):
        # install.sh prints the final banner itself; only conclude here when run standalone
        click.echo(_c("\ninstall complete — all tools ok\nrun  quarry doctor  to verify", "green"))


@cli.command()
@click.option("--dry-run", is_flag=True)
@click.option("--include-optional", is_flag=True)
def update(dry_run, include_optional):
    """Update installed managed tools, nuclei templates, resolvers, gf patterns."""
    from . import bootstrap

    tools = [t for t in load_tools() if t.installed]
    if not include_optional:
        tools = [t for t in tools if not t.optional]
    click.echo(_c(f"updating {len(tools)} tools", "magenta"))
    for t in tools:
        cmd = t.update or t.install
        if not cmd:
            continue
        click.echo(f"  {_c('↻', 'cyan')} {t.bin}")
        run_shell(cmd, dry_run)
    click.echo(_c("refreshing data files + templates", "magenta"))
    bootstrap.install_data_files(click.echo, dry_run, update=True)
    bootstrap.run_extras(click.echo, dry_run)
    bootstrap.cleanup(click.echo, dry_run)   # re-running tool installs refills go caches — clean them (install already does)
    if dry_run:
        click.echo(_c("\n(dry-run)\n", "yellow"))


# ── init (create a project) ───────────────────────────────────────────────────
@cli.command()
@click.argument("name")
@click.option("-o", "--out", help="exact project dir (default: <projects-root>/<name>)")
@click.option("--projects-dir", help="projects root (default ~/projects or $QUARRY_PROJECTS)")
def init(name, out, projects_dir):
    """Create a project: <projects>/<name>/target.yaml (or -o <dir>). osint + recon co-locate here."""
    # sanitize: the NAME is the target id (a single path segment), never a path. The location
    # can be anywhere via -o.
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*$", name) or ".." in name:
        raise click.ClickException(
            f"invalid project name {name!r}: use letters/digits/.-_ only, no path separators")
    proj = Path(out).expanduser() if out else _projects_root(projects_dir) / name
    proj.mkdir(parents=True, exist_ok=True)
    tpl = resources.files("quarry_recon.data").joinpath("target.template.yaml").read_text()
    tpl = tpl.replace("TARGET: example", f"TARGET: {name}")
    # If the name is a domain, seed APEX_DOMAINS so `quarry init target.com` is ready to run.
    is_domain = bool(re.match(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$", name))
    if is_domain:
        tpl = tpl.replace("  - example.com", f"  - {name}")
    dest = proj / "target.yaml"
    if dest.exists():
        click.confirm(f"{dest} exists — overwrite?", abort=True)
    dest.write_text(tpl)
    # bare `-t <name>` only resolves under the default projects root; elsewhere point -t at the dir
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
    """Add out-of-scope patterns to a project's target.yaml (under OOS:). A bare host becomes an
    anchored regex, `*.x` a subdomain glob; a real regex is kept verbatim. Every pattern is
    validated and the resulting profile must compile before anything is written."""
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
@click.option("--timeout", default=1800, help="per-tool timeout floor in seconds; httpx/ffuf/nuclei/naabu scale their wall-clock ceiling above this by workload (0 = fully unbounded, no wall-clock kill — per-probe timeouts still bound individual requests)")
def osint(profile_path, timeout):
    """Pre-flight OSINT: discover scope CANDIDATES + intel. Review-only — never edits scope.

    Workflow: init → fill anchors → `quarry osint` → review report + suggested.yaml →
    confirm into target.yaml → `quarry run`. Output lands in the project's osint/ dir.
    """
    import json
    from . import osint as osint_mod

    try:
        profile = TargetProfile.load(_resolve_profile(profile_path))
    except ProfileError as e:
        raise click.ClickException(str(e))
    scope = profile.scope()
    project = _project_dir(profile)
    secrets.apply_env()   # export PDCP_API_KEY (chaos) for PD tools, if set

    click.echo(_c(f"\n══ Quarry osint · target={profile.target} (pre-flight, review-only) ══", "cyan"))
    click.echo(f"   project: {project}")
    click.echo(f"   anchors: apex={len(profile.apex_domains)} asn={len(profile.asn)} "
               f"org={len(profile.org_names)} brands={len(profile.brands)}\n")
    report = osint_mod.run(profile, scope, project, echo=click.echo, timeout=timeout)

    cdir = report.parent
    cfile = cdir / "candidates.jsonl"
    cands = [json.loads(l) for l in cfile.read_text().splitlines() if l.strip()] \
        if cfile.exists() else []
    apex = [c for c in cands if c["type"] == "apex" and c["scope_hint"] != "noise"]
    click.echo(_c(f"\n══ osint done · {cdir}", "green"))
    click.echo(f"   report:    {report}")
    click.echo(f"   suggested: {cdir / 'target.suggested.yaml'}")
    click.echo(_c(f"   {len(apex)} apex candidate(s) — review, confirm scope, add to target.yaml:", "yellow"))
    for c in apex[:8]:
        click.echo(f"     - {c['value']}  [{c['scope_hint']}/{c['confidence']}]")
    if len(apex) > 8:
        click.echo(f"     … +{len(apex) - 8} more in the report")


# ── run ──────────────────────────────────────────────────────────────────────
@cli.command()
@click.option("-t", "--target", "profile_path", required=True,
              help="project name, project dir, or target.yaml path")
@click.option("--phases", help="comma list (default: all). e.g. horizontal,vertical")
@click.option("--passive", is_flag=True, help="force passive-only (override profile)")
@click.option("--timeout", default=1800, help="per-tool timeout floor in seconds; httpx/ffuf/nuclei/naabu scale their wall-clock ceiling above this by workload (0 = fully unbounded, no wall-clock kill — per-probe timeouts still bound individual requests)")
def run(profile_path, phases, passive, timeout):
    """Run recon phases against the confirmed scope. Output lands in the project's recon/ dir."""
    from .phases import ORDER, REGISTRY, PhaseContext
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

    # pre-run disk gate on the ACTUAL project filesystem (output growth is the real driver).
    # Runs BEFORE the run folder is created so a low-disk abort leaves no empty recon/<run_id>/.
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

    secrets.apply_env()   # export PDCP_API_KEY (chaos) for PD tools, if set
    from .runner import set_tool_cwd
    run_obj = Run(project, profile.target)
    events.configure(run_obj.dir)   # persist runtime events to <run>/events.jsonl (quarry status reads it)
    workdir = run_obj.dir / "work"
    workdir.mkdir(parents=True, exist_ok=True)
    set_tool_cwd(workdir)   # stray tool files (gowitness db, github-subdomains txt, …) land in the run
    ctx = PhaseContext(run=run_obj, profile=profile, scope=scope, workdir=workdir,
                       echo=click.echo, http_timeout=timeout)

    selected = [p.strip() for p in phases.split(",")] if phases else ORDER
    selected = [p for p in selected if p in REGISTRY]

    click.echo(_c(f"\n══ Quarry run {run_obj.run_id} · target={profile.target} · "
                  f"{'PASSIVE' if profile.passive_only else 'ACTIVE'} ══", "cyan"))
    ports_disp = (f"default ({len(profile.ports)})" if profile.ports_are_default
                  else str(profile.ports))
    click.echo(f"   apexes={len(profile.apex_domains)} cidr={len(profile.cidr)} "
               f"ports={ports_disp} http_rl={profile.http_rl or 'default'}\n")

    # readiness gate: warn (don't block) if a REQUIRED tool for the phases that will ACTUALLY run
    # (mode-gating applied) is missing — better to know before a long run than in the manifest.
    missing_req = _missing_required(_effective_phases(selected, profile))
    if missing_req:
        click.echo(_c(f"   ⚠ {len(missing_req)} required tool(s) missing for selected phases "
                      f"({', '.join(missing_req[:8])}) — those steps will be skipped. "
                      "Run `quarry doctor`.\n", "yellow"))

    # runtime telemetry (data beats vibes): per-phase wall + child CPU + inventory-at-phase.
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
            # redact ONCE: an exception message can carry a URL with a key/token — keep it out of the
            # notes, the terminal/runtime.log echo, AND the notification.
            err = secrets.redact(str(e)) or ""
            run_obj.notes.append(f"{name}: EXCEPTION {err}")
            click.echo(_c(f"   ! {name} raised {err}", "red"))
            from . import notify
            notify.send("error", f"Quarry {run_obj.run_id} · {profile.target}: {name} phase raised", err)
        p_wall = round(_time.perf_counter() - p_t0, 1)
        phase_metrics.append({"phase": name, "wall_s": p_wall,
                              "cpu_s": round(metrics.rusage()[0] - p_cpu0, 2),
                              "size": {e: run_obj.count(e) for e in _INV}})
        # incremental flush → a killed / timed-out run KEEPS its telemetry. metrics were previously
        # written only at run end, so a mid-run kill (exactly when tuning data matters most) lost every
        # per-tool cpu/RAM sample. Best-effort: a flush failure must never break the run.
        try:
            _rc, _rss = metrics.rusage()
            metrics.write(run_obj, phase_metrics, _time.perf_counter() - run_t0,
                          _rc - run_cpu0, _rss / 1024)
        except Exception:
            pass
        # log-safe section timer (reconftw-style, our style) — a per-phase elapsed footer. No spinner
        # / control chars, so tmux + runtime.log stay clean. The live in-tool spinner is separate.
        click.echo(_c(f"   ⏱ {name} · {p_wall}s", "cyan"))
        cps = checkpoint.evaluate(run_obj, name)
        all_cps += cps
        for cp in cps:
            click.echo("   " + _c(cp.line(), "yellow" if cp.level == "warn" else "white"))

    # reports + exports
    exp = exports.write_all(run_obj)
    exports.write_delta(run_obj)
    hot = triage.build(run_obj, scope)
    (run_obj.reports / "HOTLIST.md").write_text(hot)
    import json as _json
    (run_obj.reports / "digest.json").write_text(
        _json.dumps(triage.digest_json(run_obj, scope), indent=2, ensure_ascii=False))
    if all_cps:
        (run_obj.reports / "checkpoints.md").write_text(
            "# Checkpoints\n\n" + "\n".join(f"- {c.line()}" for c in all_cps) + "\n")
        run_obj.notes += [c.line() for c in all_cps]

    # runtime telemetry → metrics/summary.json, written BEFORE the manifest so the manifest (the run
    # index) points at it and carries the headline totals.
    run_wall = _time.perf_counter() - run_t0
    run_cpu, peak_rss_kb = metrics.rusage()
    tel = metrics.write(run_obj, phase_metrics, run_wall, run_cpu - run_cpu0, peak_rss_kb / 1024)
    metrics_summary = {"artifact": "metrics/summary.json", **tel["totals"],
                       "slowest_tool": tel["long_poles"]["tools"][0] if tel["long_poles"]["tools"] else None}

    run_obj.write_manifest(
        profile_summary={"apex_domains": profile.apex_domains, "cidr": profile.cidr,
                         "passive_only": profile.passive_only, "ports": profile.ports},
        phases_run=selected, metrics=metrics_summary)

    # honest run verdict — read the ONE canonical summary (same logic the manifest stores), never recompute
    summ = run_obj._run_summary()
    verdict, fails, gaps, pexc = (summ["verdict"], summ["failures"], summ["gaps"], summ["phase_exceptions"])
    if verdict == "complete":
        click.echo(_c(f"\n══ complete · {run_obj.dir}", "green"))
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
        tools = sorted({f"{g['tool']}:{g['status']}" for g in gaps})   # DISTINCT tools (repeated ffuf origins != many sources)
        click.echo(_c(f"   ⚠ {len(gaps)} degraded run(s) across {len(tools)} tool(s) "
                      f"({', '.join(tools[:6])}) — evidence preserved, see manifest.json 'summary.gaps'",
                      "yellow"))
    if pexc:
        click.echo(_c(f"   ⚠ {len(pexc)} phase exception(s) — see manifest.json 'summary.phase_exceptions'",
                      "yellow"))

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
        summary = (f"{verdict} · live={len(run_obj.read('live'))} urls={run_obj.count('url')} "
                   f"secrets={n_sec} confirmed={n_conf} candidates={n_cand} "
                   f"gaps={len(gaps)} failed_tools={len(fails)}")
        notify.send("complete", f"Quarry {run_obj.run_id} · {profile.target} {verdict}", summary)
        leads = n_sec + sum(1 for f in run_obj.read("finding")
                            if f.get("severity") in ("critical", "high"))
        if leads:
            notify.send("lead", f"Quarry {profile.target}: {leads} promising lead(s)", summary)


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
    run_obj = _existing_run(project, profile.target, run_id)   # explicit --run must exist (no ghost run)
    if run_obj is None:
        raise click.ClickException(f"no runs found under {project}/recon/")
    # minimal scope (report doesn't re-filter)
    from .config import ScopeMatcher
    scope = ScopeMatcher([], [], [], False)
    exp = exports.write_all(run_obj)
    exports.write_delta(run_obj)
    (run_obj.reports / "HOTLIST.md").write_text(triage.build(run_obj, scope))
    import json as _json
    (run_obj.reports / "digest.json").write_text(
        _json.dumps(triage.digest_json(run_obj, scope), indent=2, ensure_ascii=False))
    click.echo(f"regenerated {run_obj.reports / 'HOTLIST.md'} + digest.json + delta.md")
    click.echo(f"exports: {', '.join(f'{k}={v}' for k, v in exp.items() if v)}")


@cli.command()
def plan():
    """Static dry-run: explain what WOULD run (registry + machine settings). No scanning."""
    from . import views
    for line in views.plan_lines():
        click.echo(line)


@cli.command()
@click.option("-t", "--target", "profile_path", required=True,
              help="project name, project dir, or target.yaml path")
@click.option("--run", "run_id", help="run id (default: latest)")
def status(profile_path, run_id):
    """Render current/last-known per-source state from a run's events.jsonl (no scanning)."""
    from . import views

    try:
        profile = TargetProfile.load(_resolve_profile(profile_path))
    except ProfileError as e:
        raise click.ClickException(str(e))
    project = _project_dir(profile)
    run_obj = _existing_run(project, profile.target, run_id)   # explicit --run must exist (no ghost run)
    if run_obj is None:
        raise click.ClickException(f"no runs found under {project}/recon/")
    for line in views.status_lines(run_obj.dir / "events.jsonl"):
        click.echo(line)


@cli.group()
def oob():
    """Out-of-band (OOB) interaction — one Quarry-owned callback layer.

    Quarry manages interactsh-client internally (default public backend, or override oob.interactsh_server).
    poll   = resume a run's owned session and pull DELAYED callbacks, correlated to their source
             (params.oob_probe).
    import = compatibility only — ingest EXTERNAL callback logs (Burp/XSSHunter/manual), uncorrelated
             unless a row matches a Quarry-issued token.
    """


@oob.command("import")
@click.argument("src_file", type=click.Path(exists=True, dir_okay=False))
@click.option("-t", "--target", "profile_path", required=True,
              help="project name, project dir, or target.yaml path")
@click.option("--run", "run_id", help="run id (default: latest)")
def oob_import(src_file, profile_path, run_id):
    """Import EXTERNAL interactsh -json (JSONL) callback logs into a run as oob_interaction rows.

    Compatibility path only — for callbacks Quarry did NOT issue (Burp Collaborator, XSSHunter, a manual
    interactsh-client, old dalfox -b logs). Recorded as evidence WITHOUT attribution; a row correlates
    only if it matches a Quarry-issued token. Quarry-owned probes are correlated live via the OOB layer
    (params.oob_probe / `quarry oob poll`). Raw import kept under raw/oob/.
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
    # correlated only when the imported log carried a Quarry-issued token (owned session on this run);
    # otherwise every new row is external/stray -> uncorrelated. Report honestly, never claim attribution.
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
    """Resume a run's OWNED interactsh session and poll for DELAYED callbacks (P2.4).

    SSRF/blind callbacks often arrive after the scan closes the first client. This re-opens the SAME
    session (via its -session-file, token_map preserved) so late interactions correlate back to their
    source. Adds any new (correlated) oob_interaction rows to the run.
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
    # carry the configured token so a self-hosted/protected collector can resume (secrets, not persisted)
    resumed = oobmod.resume_session(run_obj, token=secrets.oob().get("interactsh_token"))
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
