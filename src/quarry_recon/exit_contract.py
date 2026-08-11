"""Process exit status and the machine result behind it — one precedence, one JSON document.

    0    clean; no completeness-challenging gap or machinery fault
    2    invalid selector / profile / schema / path / config, refused in preflight
    3    completed under declared terminal or soft limits (intentionally bounded)
    4    completed with gaps, unknown coverage, a missing required dependency, or an unresolved remainder
    5    machinery / persistence / installer / runner / finalisation failure
    6    the top-level operation was refused before execution by scope, authorization or policy
    130  operator interruption

Precedence: 130 > 5 (after start) > 2/6 (preflight) > 4 > 3 > 0, resolved in `state.compute_exit`.
A per-candidate scope or policy decision is a `PolicyDecision` record, never exit 6.

Human rendering is independent of the process status: prose always goes to stderr under `--json`, so
machine stdout carries the `CommandResult` document and nothing else.
"""
from __future__ import annotations

import contextlib
import json
import sys
import traceback

import click

from .state import CommandResult, Fault, Gap

#: operator hint per exit code, used when a command supplies none of its own.
REMEDIATION = {
    2: "fix the selector/profile/path and rerun",
    3: "raise the named bound (see `quarry policy`) and rerun to widen coverage",
    4: "read summary.gaps in manifest.json; install the named dependency or rerun the gapped source",
    5: "see the fault detail; `quarry report -t <target> --run <id>` resumes a failed finalisation",
    6: "the operation was refused by scope/authorization/policy — adjust the profile, not the flag",
    130: "interrupted; rerun to continue from the evidence already committed",
}


class Refused(click.ClickException):
    """A top-level operation refused before execution by scope, authorization or policy."""
    exit_code = 6


class MachineryFailure(click.ClickException):
    """Machinery, persistence, installer, runner or finalisation broke."""
    exit_code = 5

    def __init__(self, message: str, *, where: str | None = None, after_start: bool = True):
        super().__init__(message)
        self.where = where
        self.after_start = after_start


def json_option(f):
    """`--json`: the machine result on stdout, every human line on stderr."""
    return click.option("--json", "as_json", is_flag=True,
                        help="emit the machine result document on stdout (prose goes to stderr); the "
                             "process exit status follows the same contract either way")(f)


@contextlib.contextmanager
def prose_to_stderr(active: bool):
    """Keep stdout free of prose while a command body runs."""
    if not active:
        yield
        return
    with contextlib.redirect_stdout(sys.stderr):
        yield


def gap_from_summary(g: dict) -> Gap:
    """One manifest `summary.gaps` row as the typed record. `kind` is carried by the emitter, never guessed
    back out of a status label."""
    return Gap(source_id=g.get("tool") or g.get("phase") or "run", kind=g.get("kind") or "unknown",
               measure=g.get("measure"), eligible=g.get("eligible"), tested=g.get("output_lines"),
               omitted=g.get("omitted"), reason=g.get("why"))


def from_summary(command: str, summary: dict, *, run_id: str | None = None,
                 campaign_id: str | None = None, started: bool = True,
                 remediation: str | None = None) -> CommandResult:
    """The machine result for a finished run, read from the one canonical summary the manifest stores.

    A missing required dependency rides as a Gap (exit 4), not a Fault: exit 5 is reserved for machinery
    that broke, and an absent tool is coverage we did not get.
    """
    faults = [Fault.from_dict(f) for f in summary.get("faults") or []]
    faults = [f for f in faults if f.kind != "required_tool_missing"]
    gaps = [gap_from_summary(g) for g in summary.get("gaps") or []]
    verdict = summary.get("verdict")
    coverage = {"complete": "clean", "complete_with_limits": "intentionally_bounded"}.get(verdict, "gapped")
    if gaps:
        coverage = "gapped"
    challenged = any(f.challenges_completeness for f in faults)
    return CommandResult(command, outcome="failed" if challenged else "completed", coverage=coverage,
                         run_id=run_id, campaign_id=campaign_id, faults=faults, gaps=gaps,
                         machinery_after_start=bool(challenged and started),
                         remediation=remediation)


def emit(result: CommandResult, *, as_json: bool):
    """Render the machine document (when asked) and exit by the contract. Never returns."""
    if result.remediation is None and result.exit_code:
        result.remediation = REMEDIATION.get(result.exit_code)
    if as_json:
        click.echo(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    raise SystemExit(result.exit_code)


class ContractGroup(click.Group):
    """The CLI root, so every exit leaves through the contract — including the ones Click decides itself.

    Click parses before any command body runs, so a missing option, an unknown flag or a missing option
    argument never reaches the per-command wrapper: without this, those exits carry no document and an
    undocumented status. A command body that reached `run_command` has already exited through `emit`, so
    its SystemExit passes straight out and is never re-decided here.
    """

    def main(self, args=None, prog_name=None, complete_var=None, standalone_mode=True, **extra):
        argv = list(sys.argv[1:] if args is None else args)
        as_json = "--json" in argv
        # the command the operator asked for, named even when parsing never got far enough to bind it.
        # Only the first bare token: everything after it may be an option's value, not a name.
        command = next((a for a in argv if not a.startswith("-")), self.name or "quarry")

        def finish(result):
            emit(result, as_json=as_json)      # raises SystemExit

        try:
            # standalone_mode=False so Click hands the parse errors back rather than exiting behind us
            rv = super().main(args=argv, prog_name=prog_name, complete_var=complete_var,
                              standalone_mode=False, **extra)
        except click.exceptions.Exit as e:     # `--help` / `--version`, if Click ever re-raises its own
            raise SystemExit(e.exit_code)
        except (click.Abort, KeyboardInterrupt):
            click.echo("Aborted!", err=True)
            finish(CommandResult(command, outcome="failed", interrupted=True))
        except Refused as e:
            e.show()
            finish(CommandResult(command, outcome="refused", remediation=e.format_message()))
        except MachineryFailure as e:
            e.show()
            finish(CommandResult(command, outcome="failed", machinery_after_start=e.after_start,
                                 faults=[Fault("machinery", where=e.where, detail=e.format_message())],
                                 remediation=e.format_message()))
        except click.ClickException as e:      # UsageError included: the parse-level errors land here
            e.show()
            finish(CommandResult(command, outcome="invalid", remediation=e.format_message()))
        if not standalone_mode:
            return rv
        # non-standalone Click returns `--help`/`--version`'s own exit code rather than raising it
        raise SystemExit(rv if type(rv) is int else 0)


def run_command(command: str, as_json: bool, body, *, run_id=None):
    """Execute one command body and exit by the contract. Never returns.

    `body` returns a CommandResult (or None for a clean read-only command); the exceptions below are the
    only way an exit code is chosen, so no path can render a warning and still return 0.
    """
    def rid():      # read after the body ran, so a fault mid-run still names the run it happened in
        return run_id() if callable(run_id) else run_id

    with prose_to_stderr(as_json):
        try:
            result = body() or CommandResult(command, run_id=rid())
        except KeyboardInterrupt:
            result = CommandResult(command, outcome="failed", interrupted=True, run_id=rid())
        except Refused as e:
            e.show()
            result = CommandResult(command, outcome="refused", remediation=e.format_message(),
                                   run_id=rid())
        except MachineryFailure as e:
            e.show()
            result = CommandResult(command, outcome="failed", remediation=e.format_message(),
                                   faults=[Fault("machinery", where=e.where, detail=e.format_message())],
                                   machinery_after_start=e.after_start, run_id=rid())
        except click.ClickException as e:      # UsageError included: a bad selector/profile/path/config
            e.show()
            result = CommandResult(command, outcome="invalid", remediation=e.format_message(),
                                   run_id=rid())
        except Exception as e:                 # noqa: BLE001 — machinery that broke, shown whole on stderr
            from . import secrets
            traceback.print_exc(file=sys.stderr)
            # an exception message can carry a URL with a key, and the document is a persisted sink
            detail = secrets.redact(f"{type(e).__name__}: {e}")
            result = CommandResult(command, outcome="failed", machinery_after_start=True,
                                   faults=[Fault("machinery", where=command, detail=detail)],
                                   run_id=rid())
    emit(result, as_json=as_json)
