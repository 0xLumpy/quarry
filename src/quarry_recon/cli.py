"""quarry — command surface: install · update · doctor · init-target · run · report."""
from __future__ import annotations

import os
import shutil
from importlib import resources
from pathlib import Path

import click

from . import __version__
from .config import ProfileError, TargetProfile
from .registry import load_tools, run_shell, tools_by_phase


def _home(home: str | None) -> Path:
    base = Path(home or os.environ.get("QUARRY_HOME") or (Path.home() / ".quarry"))
    base.mkdir(parents=True, exist_ok=True)
    return base


def _c(s, color):  # tiny colorizer
    return click.style(s, fg=color)


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
        if t.deps:
            click.echo(f"      {_c('deps:', 'cyan')} {', '.join(t.deps)}")
        if t.needs_chromium and t.installed and not _chromium():
            click.echo(f"      {_c('⚠ needs chromium — not found; screenshots/headless will fail', 'red')}")
        if t.keys and t.installed:
            click.echo(f"      {_c('keys:', 'yellow')} {t.keys}")

    # environment checks
    click.echo(_c("\n[environment]", "magenta"))
    cfg = Path.home() / ".config/quarry"
    for label, p in [("resolvers", cfg / "resolvers.txt"),
                     ("trusted-resolvers", cfg / "trusted-resolvers.txt"),
                     ("dns-wordlist", cfg / "dns-wordlist.txt"),
                     ("github-tokens", cfg / "github-tokens.txt"),
                     ("shodan-key", cfg / "shodan-key.txt"),
                     ("whoxy-key", cfg / "whoxy-key.txt")]:
        mark = _c("✓", "green") if p.exists() else _c("·", "yellow")
        note = "" if p.exists() else f"(optional) put at {p}"
        click.echo(f"  {mark} {label:<24} {note}")
    for label, bin_ in [("go toolchain", "go"), ("chromium", "chromium"),
                        ("pipx", "pipx")]:
        present = shutil.which(bin_) or (bin_ == "chromium" and
                  (shutil.which("chromium-browser") or shutil.which("google-chrome")))
        mark = _c("✓", "green") if present else _c("✗", "red")
        click.echo(f"  {mark} {label}")

    click.echo(_c(f"\n{ok} installed · {miss} missing (required) · audit complete\n",
                  "green" if not miss else "yellow"))


# ── install / update ─────────────────────────────────────────────────────────
@cli.command()
@click.option("--dry-run", is_flag=True, help="show what would be installed, do nothing")
@click.option("--phase", help="only install tools for this phase")
@click.option("--only", help="install a single tool by bin name")
@click.option("--include-optional", is_flag=True, help="also install optional tools")
@click.option("--tools-only", is_flag=True, help="skip system packages / Go / data files")
def install(dry_run, phase, only, include_optional, tools_only):
    """Full blank-VPS install: system pkgs -> Go -> tools -> wordlists/templates."""
    from . import bootstrap

    # ── 1. system packages + Go toolchain + data (unless --tools-only / --only / --phase) ──
    full = not (only or phase or tools_only)
    if full:
        click.echo(_c("\n[1/5] system packages", "magenta"))
        bootstrap.install_system_packages(click.echo, dry_run)
        click.echo(_c("[2/5] Go toolchain", "magenta"))
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

    click.echo(_c(f"\n[3/5] tools ({len(tools)})", "magenta"))
    failed = []
    for t in tools:
        if t.installed and not only:
            click.echo(f"  {_c('✓', 'green')} {t.bin} present ({t.path}) — left as-is")
            continue
        if not t.install:
            click.echo(f"  {_c('!', 'yellow')} {t.bin} — manual: {t.doc}")
            continue
        click.echo(f"  {_c('→', 'cyan')} {t.bin}")
        code, tail = run_shell(t.install, dry_run)
        if dry_run:
            continue
        if code == 0 and t.installed:
            click.echo(f"      {_c('ok', 'green')}")
        else:
            failed.append(t.bin)
            click.echo(f"      {_c('FAILED', 'red')} {tail[:100]}")
        if t.keys:
            click.echo(f"      {_c('keys:', 'yellow')} {t.keys}")

    # ── 3. data files + extras (gf patterns, nuclei templates) ──
    if full:
        click.echo(_c("\n[4/5] data files (resolvers, wordlists)", "magenta"))
        bootstrap.install_data_files(click.echo, dry_run)
        click.echo(_c("[5/5] extras (gf patterns, nuclei templates)", "magenta"))
        bootstrap.run_extras(click.echo, dry_run)

    if dry_run:
        click.echo(_c("\n(dry-run — nothing was installed)\n", "yellow"))
    else:
        msg = f"\ninstall complete. {len(failed)} tool(s) failed" + (f": {', '.join(failed)}" if failed else "")
        click.echo(_c(msg, "yellow" if failed else "green"))
        click.echo("run  quarry doctor  to verify, then configure API keys (README.md)\n")


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


# ── init-target ──────────────────────────────────────────────────────────────
@cli.command(name="init-target")
@click.argument("name")
@click.option("-o", "--out", help="output path (default ./targets/<name>.yaml)")
def init_target(name, out):
    """Create an editable target profile from the template."""
    tpl = resources.files("quarry_recon.data").joinpath("target.template.yaml").read_text()
    tpl = tpl.replace("TARGET: example", f"TARGET: {name}")
    dest = Path(out) if out else Path("targets") / f"{name}.yaml"
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        click.confirm(f"{dest} exists — overwrite?", abort=True)
    dest.write_text(tpl)
    click.echo(f"{_c('created', 'green')} {dest}\nEdit APEX_DOMAINS / CIDR / OOS, then: "
               f"quarry run -t {dest}")


# ── osint (pre-flight; separate from run) ─────────────────────────────────────
@cli.command()
@click.option("-t", "--target", "profile_path", required=True, help="target profile YAML")
@click.option("--home", help="state/runs base dir (default ~/.quarry or $QUARRY_HOME)")
@click.option("--timeout", default=1800, help="per-tool timeout seconds")
def osint(profile_path, home, timeout):
    """Pre-flight OSINT: discover scope CANDIDATES + intel. Review-only — never edits scope.

    Workflow: init-target → fill anchors → `quarry osint` → review report + suggested.yaml →
    confirm into target.yaml → `quarry run`.
    """
    import json
    from . import osint as osint_mod

    try:
        profile = TargetProfile.load(profile_path)
    except ProfileError as e:
        raise click.ClickException(str(e))
    scope = profile.scope()
    base = _home(home)

    click.echo(_c(f"\n══ Quarry osint · target={profile.target} (pre-flight, review-only) ══", "cyan"))
    click.echo(f"   anchors: apex={len(profile.apex_domains)} asn={len(profile.asn)} "
               f"org={len(profile.org_names)} brands={len(profile.brands)}\n")
    report = osint_mod.run(profile, scope, base, echo=click.echo, timeout=timeout)

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
@click.option("-t", "--target", "profile_path", required=True, help="target profile YAML")
@click.option("--home", help="state/runs base dir (default ~/.quarry or $QUARRY_HOME)")
@click.option("--phases", help="comma list (default: all). e.g. horizontal,vertical")
@click.option("--passive", is_flag=True, help="force passive-only (override profile)")
@click.option("--timeout", default=1800, help="per-tool timeout seconds")
def run(profile_path, home, phases, passive, timeout):
    """Run methodology phases against a target profile."""
    from .phases import ORDER, REGISTRY, PhaseContext
    from .store import Run
    from . import checkpoint, exports, triage

    try:
        profile = TargetProfile.load(profile_path)
    except ProfileError as e:
        raise click.ClickException(str(e))
    if passive:
        profile.modes["PASSIVE_ONLY"] = True
    scope = profile.scope()
    base = _home(home)
    run_obj = Run(base, profile.target)
    workdir = run_obj.dir / "work"
    ctx = PhaseContext(run=run_obj, profile=profile, scope=scope, workdir=workdir,
                       echo=click.echo, http_timeout=timeout)

    selected = [p.strip() for p in phases.split(",")] if phases else ORDER
    selected = [p for p in selected if p in REGISTRY]

    click.echo(_c(f"\n══ Quarry run {run_obj.run_id} · target={profile.target} · "
                  f"{'PASSIVE' if profile.passive_only else 'ACTIVE'} ══", "cyan"))
    click.echo(f"   apexes={len(profile.apex_domains)} cidr={len(profile.cidr)} "
               f"ports={profile.ports} http_rl={profile.http_rl}\n")

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
            run_obj.notes.append(f"{name}: EXCEPTION {e}")
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


# ── report ───────────────────────────────────────────────────────────────────
@cli.command()
@click.option("--home", help="state/runs base dir")
@click.option("--run", "run_id", help="run id (default: latest)")
def report(home, run_id):
    """Regenerate hotlist + exports from a stored run (no scanning)."""
    from .store import Run
    from . import exports, triage

    base = _home(home)
    run_obj = Run(base, "unknown", run_id=run_id) if run_id else Run.latest(base)
    if run_obj is None:
        raise click.ClickException("no runs found")
    # minimal scope (report doesn't re-filter)
    from .config import ScopeMatcher
    scope = ScopeMatcher([], [], [], False)
    exp = exports.write_all(run_obj)
    (run_obj.reports / "HOTLIST.md").write_text(triage.build(run_obj, scope))
    click.echo(f"regenerated {run_obj.reports / 'HOTLIST.md'}")
    click.echo(f"exports: {', '.join(f'{k}={v}' for k, v in exp.items() if v)}")


if __name__ == "__main__":
    cli()
