"""quarry — command surface: install · update · doctor · init · osint · run · report."""
from __future__ import annotations

import os
import re
import shutil
from importlib import resources
from pathlib import Path

import click

from . import __version__, secrets
from .config import ProfileError, TargetProfile
from .registry import load_tools, run_shell, tools_by_phase


def _projects_root(opt: str | None) -> Path:
    """Where `quarry init` creates project dirs. Default ./projects (cwd)."""
    return Path(opt or os.environ.get("QUARRY_PROJECTS") or "projects")


def _project_dir(profile) -> Path:
    """A profile's project dir = the directory its target.yaml lives in. Output (osint/, recon/)
    co-locates with the profile (campaign/project model)."""
    return (profile.path.parent if profile.path else Path(".")).resolve()


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
    for label, p in [("resolvers", cfg / "resolvers.txt"),
                     ("trusted-resolvers", cfg / "trusted-resolvers.txt"),
                     ("dns-wordlist", cfg / "dns-wordlist.txt"),
                     ("content-wl balanced", cfg / "wordlists/content/balanced.txt"),
                     ("content-wl deep", cfg / "wordlists/content/deep.txt")]:
        mark = _c("✓", "green") if p.exists() else _c("·", "yellow")
        note = "" if p.exists() else f"(optional) put at {p}"
        click.echo(f"  {mark} {label:<24} {note}")

    for label, bin_ in [("go toolchain", "go"), ("chromium", "chromium"),
                        ("pipx", "pipx")]:
        present = shutil.which(bin_) or (bin_ == "chromium" and
                  (shutil.which("chromium-browser") or shutil.which("google-chrome")))
        mark = _c("✓", "green") if present else _c("✗", "red")
        click.echo(f"  {mark} {label}")

    from . import bootstrap
    click.echo(_c("\n[system]", "magenta"))
    _echo_syscheck(bootstrap.system_report("run"))   # post-install: only run space matters

    # secrets.yaml — framework-read keys (present / not set). Tool-native keys live elsewhere.
    click.echo(_c("\n[secrets]", "magenta") + f"  ({secrets.PATH})")
    for label, present in [("github tokens", bool(secrets.github_tokens())),
                           ("shodan", bool(secrets.shodan())),
                           ("whoxy", bool(secrets.whoxy())),
                           ("projectdiscovery/chaos", bool(secrets.chaos()))]:
        mark = _c("✓", "green") if present else _c("·", "yellow")
        click.echo(f"  {mark} {label:<24} {'' if present else '(optional) not set'}")
    click.echo(f"  {_c('ℹ', 'cyan')} tool-native: subfinder · waymore")

    click.echo(_c(f"\n{ok} installed · {miss} missing (required) · audit complete\n",
                  "green" if not miss else "yellow"))


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
    if dry_run:
        click.echo(_c("\n(dry-run)\n", "yellow"))


# ── init (create a project) ───────────────────────────────────────────────────
@cli.command()
@click.argument("name")
@click.option("-o", "--out", help="exact project dir (default: <projects-root>/<name>)")
@click.option("--projects-dir", help="projects root (default ./projects or $QUARRY_PROJECTS)")
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
@click.option("--timeout", default=1800, help="per-tool timeout seconds")
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
@click.option("--timeout", default=1800, help="per-tool timeout seconds")
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
    workdir = run_obj.dir / "work"
    workdir.mkdir(parents=True, exist_ok=True)
    set_tool_cwd(workdir)   # stray tool files (gowitness db, github-subdomains txt, …) land in the run
    ctx = PhaseContext(run=run_obj, profile=profile, scope=scope, workdir=workdir,
                       echo=click.echo, http_timeout=timeout)

    selected = [p.strip() for p in phases.split(",")] if phases else ORDER
    selected = [p for p in selected if p in REGISTRY]

    click.echo(_c(f"\n══ Quarry run {run_obj.run_id} · target={profile.target} · "
                  f"{'PASSIVE' if profile.passive_only else 'ACTIVE'} ══", "cyan"))
    click.echo(f"   apexes={len(profile.apex_domains)} cidr={len(profile.cidr)} "
               f"ports={profile.ports} http_rl={profile.http_rl or 'default'}\n")

    all_cps = []
    for name in selected:
        fn, label, needs_active = REGISTRY[name]
        if needs_active and profile.passive_only:
            click.echo(_c(f"▸ {label} — skipped (passive-only)", "yellow"))
            continue
        click.echo(_c(f"▸ {label}", "magenta"))
        try:
            fn(ctx)
        except Exception as e:  # never let one phase kill the run
            # redact: an exception message can carry a URL with a key/token — keep it out of notes.
            run_obj.notes.append(f"{name}: EXCEPTION {secrets.redact(str(e))}")
            click.echo(_c(f"   ! {name} raised {e}", "red"))
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
    run_obj.write_manifest(
        profile_summary={"apex_domains": profile.apex_domains, "cidr": profile.cidr,
                         "passive_only": profile.passive_only, "ports": profile.ports},
        phases_run=selected)

    click.echo(_c(f"\n══ done · {run_obj.dir}", "green"))
    click.echo(f"   HOTLIST: {run_obj.reports / 'HOTLIST.md'}")
    click.echo(f"   exports: {', '.join(f'{k}={v}' for k, v in exp.items() if v)}")
    if all_cps:
        click.echo(_c(f"   {len(all_cps)} checkpoint(s) raised — see reports/checkpoints.md", "yellow"))
    fails = [r for r in run_obj.tool_runs() if r.status == "failed"]
    if fails:
        shown = ", ".join(sorted({r.tool for r in fails})[:6])
        click.echo(_c(f"   ⚠ {len(fails)} tool run(s) failed ({shown}) — see manifest.json "
                      "'summary.failures'", "yellow"))


# ── report ───────────────────────────────────────────────────────────────────
@cli.command()
@click.option("-t", "--target", "profile_path", required=True,
              help="project name, project dir, or target.yaml path")
@click.option("--run", "run_id", help="run id (default: latest)")
def report(profile_path, run_id):
    """Regenerate hotlist + exports from a stored run in the project (no scanning)."""
    from .store import Run
    from . import exports, triage

    try:
        profile = TargetProfile.load(_resolve_profile(profile_path))
    except ProfileError as e:
        raise click.ClickException(str(e))
    project = _project_dir(profile)
    run_obj = Run(project, profile.target, run_id=run_id) if run_id else Run.latest(project)
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


if __name__ == "__main__":
    cli()
