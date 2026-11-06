"""Govern a crew's traces with Yukti, the blue team.

Generic across crews. The operator declares each agent's sanctioned task
envelope out of band; the crew's OTLP spans are converted to Yukti
observations, read-taint is propagated across each agent's run, and the spans
are bound to their envelope and run through Yukti's agentic data-flow governance
(the breakout patterns plus data-provenance and delegation narrowing). An agent
with no registered envelope fails closed (escalated), so a spawned subagent
cannot act ungoverned. Yukti is a dependency here, exercised as a real deployment
would.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, replace
from typing import Any

from yukti.core.policy.base import Decision
from yukti.integrations.opentelemetry import observations_from_otlp
from yukti.scenarios.agentic_dataflow import build_dataflow_governance, propagate_read_taint
from yukti.scenarios.breakout import envelope_from_dict


@dataclass
class Verdict:
    agent: str
    action: str
    consequence: str
    decision: str
    patterns: list[str]
    evidence: list[str] = field(default_factory=list)

    @property
    def caught(self) -> bool:
        return self.decision in {"GATE", "DENY"}


def govern(
    export: dict[str, Any], envelope_specs: dict[str, dict[str, Any]]
) -> list[Verdict]:
    """Run an OTLP export through Yukti, returning a verdict per action.

    ``envelope_specs`` maps each agent name to its sanctioned-boundary spec
    (target/egress allowlists, capability grant), built into Yukti envelopes.
    """
    envelopes = {
        agent: envelope_from_dict({**spec, "agent": agent})
        for agent, spec in envelope_specs.items()
    }
    runtime = build_dataflow_governance()
    # Reconstruct cross-span data flow before governing: a class an agent READ
    # taints it, so a later egress is attributable even if that span is unlabeled.
    observations = propagate_read_taint(observations_from_otlp(export))

    async def _run() -> list[Verdict]:
        verdicts: list[Verdict] = []
        for obs in observations:
            agent = str(obs.payload.get("agent", ""))
            envelope = envelopes.get(agent)
            flow = str(obs.extra.get("flow_type", ""))
            if envelope is None:
                # Fail closed: an agent with no registered task envelope cannot be
                # sanctioned, so its action is escalated to a human, never allowed
                # by default. This is what governs a spawned subagent's actions.
                result = await runtime.process(
                    obs,
                    flow_type=flow,
                    forced_decision=Decision.GATE,
                    forced_rationale=f"unregistered agent {agent!r}: no task envelope",
                )
            else:
                bound = replace(obs, extra={**obs.extra, "task_envelope": envelope})
                result = await runtime.process(bound, flow_type=flow)
            verdicts.append(
                Verdict(
                    agent=agent,
                    action=str(obs.payload.get("action", "")),
                    consequence=str(obs.payload.get("consequence", "")),
                    decision=result.decision.name,
                    patterns=[m.pattern_name for m in result.pattern_matches],
                    evidence=list(result.evidence_chain),
                )
            )
        return verdicts

    return asyncio.run(_run())
