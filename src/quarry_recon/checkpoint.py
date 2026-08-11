"""Checkpoint engine — prevents silent false negatives (design §7).

After each phase, evaluate rules over the run's tool statuses and entity counts.
Any triggered checkpoint becomes an explicit review note in the manifest + report,
so "thin output" always comes with a stated cause instead of a silent zero.
"""
from __future__ import annotations

from dataclasses import dataclass

from .runner import Status


@dataclass
class Checkpoint:
    level: str        # "warn" | "info"
    phase: str
    message: str
    #: a thinness rule the tool statuses do not already account for; it must reach the verdict as a Gap.
    #: A checkpoint that only restates a recorded tool status is already a gap in the summary.
    challenges: bool = False

    def line(self) -> str:
        icon = "⚠️ " if self.level == "warn" else "ℹ️ "
        return f"{icon}[{self.phase}] {self.message}"

    def gap(self):
        """The typed Gap this checkpoint asserts, or None when it challenges nothing new."""
        from .state import Gap
        if not self.challenges:
            return None
        return Gap(source_id=f"{self.phase}.checkpoint", kind="unknown", reason=self.message)


def evaluate(run, phase: str) -> list[Checkpoint]:
    cps: list[Checkpoint] = []
    runs = run.tool_runs(phase)

    # any tool blocked/timed out/failed => surface it loudly
    for r in runs:
        if r.status == Status.BLOCKED.value:
            cps.append(Checkpoint("warn", phase,
                f"{r.tool} was BLOCKED (WAF/rate-limit/forbidden) — results are not 'nothing found'. stderr: {r.stderr_tail[:120]}"))
        elif r.status == Status.TIMED_OUT.value:
            cps.append(Checkpoint("warn", phase,
                f"{r.tool} TIMED OUT — coverage is partial. {r.note}"))
        elif r.status == Status.FAILED.value:
            cps.append(Checkpoint("warn", phase,
                f"{r.tool} FAILED ({r.note}). stderr: {r.stderr_tail[:120]}"))

    # phase-specific thinness rules
    if phase == "vertical":
        passive = run.count("subdomain")
        resolved = run.count("resolved")
        # a limited run did execute (credit-capped), so it counts as ran
        ran = {r.tool for r in runs if r.status in (Status.SUCCESS.value, Status.PARTIAL.value,
                                                   Status.EMPTY.value, Status.LIMITED.value)}
        if "subfinder" in ran and passive == 0:
            cps.append(Checkpoint("warn", phase,
                "passive subdomain enum returned ZERO for all roots — check API keys (subfinder -stats) and scope.",
                challenges=True))
        if passive and resolved == 0:
            cps.append(Checkpoint("warn", phase,
                f"{passive} candidate subs but 0 resolved — resolver/validation problem, not an empty target.",
                challenges=True))
        elif passive:
            ratio = resolved / passive if passive else 0
            if ratio < 0.10:
                cps.append(Checkpoint("warn", phase,
                    f"resolve ratio low ({resolved}/{passive}={ratio:.0%}) — check resolvers/wildcards.",
                    challenges=True))
        # source-diversity sanity: passive should not be carried by a single source alone
        srcs = {s for sub in run.read("subdomain") for s in sub.get("sources", [])}
        if passive > 50 and len(srcs) == 1:
            cps.append(Checkpoint("info", phase,
                f"all {passive} subs came from one source ({next(iter(srcs))}) — confirm other sources/keys are active."))

    if phase == "probe":
        resolved = run.count("resolved") or run.count("subdomain")
        live = run.count("live")
        if resolved >= 10 and live == 0:
            cps.append(Checkpoint("warn", phase,
                f"{resolved} resolved hosts but 0 live HTTP services — httpx blocked, wrong ports, or rate-limited.",
                challenges=True))

    if phase == "crawl":
        live = run.count("live")
        urls = run.count("url")
        if live and urls == 0:
            cps.append(Checkpoint("warn", phase,
                "live hosts present but 0 URLs collected — crawl/archive sources blocked or empty.",
                challenges=True))

    return cps
