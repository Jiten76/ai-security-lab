"""The shared lab harness: the same build → break → govern loop for every crew.

A crew declares its agents' sanctioned envelopes and a set of scenarios (a clean
run plus attacks). The harness runs each scenario, governs the resulting traces
with Yukti, and reports what was caught. Adding a crew is a data change, not a
code change.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ailab.govern import govern
from ailab.trace import export

# A scenario runs the crew for one case and returns its action spans.
ScenarioFn = Callable[[], list[dict[str, Any]]]


@dataclass
class Scenario:
    """One case the crew runs. Its OWASP codes are declared as data (not parsed
    from the label), and an attack may honestly be expected to *slip*: a known
    gap by design, not a detection failure."""

    run: ScenarioFn
    owasp: tuple[str, ...] = ()
    expect: str = "caught"   # attacks: "caught" (DENY/GATE) | "slips" (ALLOW, a known gap).
    #                          benign near-misses: "allowed" (ALLOW) | "gated" (GATE, by design)
    gap_note: str = ""       # why it slips / why a benign run is gated, shown in the report


@dataclass
class Crew:
    name: str
    service: str
    envelopes: dict[str, dict[str, Any]]
    scenarios: dict[str, Scenario]


_RANK = {"ALLOW": 0, "MONITOR": 1, "GATE": 2, "DENY": 3}
_COLOR = {"ALLOW": "green", "MONITOR": "cyan", "GATE": "yellow", "DENY": "red"}
_console = Console()


def _kind(label: str) -> str:
    """A scenario is a clean baseline, a benign near-miss (legitimate work close to
    a boundary, must not be denied), or an attack — classified by label prefix."""
    if label.startswith("Clean"):
        return "clean"
    if label.startswith("Benign"):
        return "benign"
    return "attack"


def run_lab(crews: list[Crew]) -> int:
    total_caught = 0
    total_attacks = 0
    benign_total = benign_allowed = benign_gated = benign_denied = 0
    for crew in crews:
        table = Table(
            title=f"{crew.name}: build → break → govern", expand=True, show_lines=True
        )
        table.add_column("scenario", style="bold")
        table.add_column("outcome", justify="center")
        table.add_column("what Yukti did")
        for label, sc in crew.scenarios.items():
            verdicts = govern(export(crew.service, sc.run()), crew.envelopes)
            worst = max(verdicts, key=lambda v: _RANK.get(v.decision, 0))
            kind = _kind(label)
            colour = _COLOR.get(worst.decision, "white")
            if kind == "attack":
                total_attacks += 1
                total_caught += int(worst.caught)
                if worst.caught:
                    detail = (
                        f"{worst.agent}: {worst.consequence}\n"
                        f"[dim]{', '.join(worst.patterns) or 'none'}[/dim]"
                    )
                else:
                    detail = (
                        f"[red]SLIPPED[/red] "
                        f"[dim]{sc.gap_note or 'inside the sanctioned envelope'}[/dim]"
                    )
            elif kind == "benign":
                benign_total += 1
                if worst.decision == "DENY":
                    benign_denied += 1
                    detail = (
                        f"[red]WRONGLY DENIED[/red] "
                        f"[dim]{', '.join(worst.patterns) or 'none'}[/dim]"
                    )
                elif worst.decision == "GATE":
                    benign_gated += 1
                    detail = (
                        f"[yellow]sent for human review (by design)[/yellow] "
                        f"[dim]{sc.gap_note or 'the trace cannot prove it safe'}[/dim]"
                    )
                else:
                    benign_allowed += 1
                    detail = "[green]legitimate work, allowed[/green]"
            else:  # clean baseline
                detail = "[green]nothing to act on[/green]"
            table.add_row(label, f"[{colour}]{worst.decision}[/{colour}]", detail)
        _console.print(table)

    gaps = total_attacks - total_caught
    attacks = (
        f"[bold]{total_caught}/{total_attacks}[/bold] attacks caught across "
        f"{len(crews)} crews"
    )
    if gaps:
        attacks += (
            f"; [red]{gaps} slipped[/red] inside the sanctioned envelope: a known gap "
            f"by design. The envelope governs where an action goes and which tool it "
            f"uses, not the sensitivity or volume of the payload."
        )
    benign = (
        f"[bold]{benign_allowed}/{benign_total}[/bold] benign near-misses allowed; "
        f"{benign_gated} sent for human review (GATE, by design; the reason is on the row "
        f"above); "
        + (f"[red]{benign_denied} wrongly denied[/red]" if benign_denied
           else "[green]0 wrongly denied[/green]")
        + ". A human review is the honest answer when the trace cannot prove a legitimate "
        "action safe; hard-denying legitimate work would make the detector worthless."
    )
    _console.print(Panel(attacks + "\n\n" + benign, title="result", border_style="cyan"))
    return 0
