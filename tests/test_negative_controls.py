"""Negative controls: the rules key on behaviour against the envelope, not on
suggestive names.

Rename every agent, tool/target, capability and destination host to a neutral
token, consistently across the scenario AND its envelope so the authorization
relationships are preserved, then assert every decision and fired-pattern set is
identical. If a decision changed, the rule was keying on a name (an agent called
``resolver``, a host called ``evil.example``, a capability called ``wire_transfer``)
instead of on the action's relationship to the sanctioned envelope.

Two kinds of token are deliberately NOT renamed, because they carry declared
policy meaning rather than being suggestive-name confounds, and a decision may
legitimately depend on them (the test documents these boundaries instead of
hiding them):

  * Data-class labels (``data_labels`` / ``data_egress_grant``): provenance is
    label-based by design.
  * Operations the engine's effectful registry declares effectful
    (``EFFECTFUL_TARGETS``, e.g. ``wire_transfer``): a declared-effectful op is
    DENY, an unrecognised one GATEs (fail-to-human for unknown effectfulness) —
    that name-dependence is a policy input, not a shortcut.
"""

from __future__ import annotations

import copy
import itertools
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import pytest
from yukti.scenarios.agent_fleet import EFFECTFUL_TARGETS

from ailab.crews import REGISTRY
from ailab.govern import Verdict, govern
from ailab.harness import Crew
from ailab.trace import export

_RANK = {"ALLOW": 0, "MONITOR": 1, "GATE": 2, "DENY": 3}

# span attribute key -> neutral-token category. action / consequence / yukti.flow /
# service.name / data_labels are intentionally left untouched.
_KEY_CATEGORY = {
    "gen_ai.agent.name": "agent",
    "child_agent": "agent",
    "target": "res",
    "tool": "res",
    "capability": "cap",
}
# delegated_grant sub-list key -> category
_GRANT_CATEGORY = {
    "capability_grant": "cap",
    "tool_allowlist": "res",
    "target_allowlist": "res",
    "egress_allowlist": "host",
}
# envelope field -> category
_ENV_CATEGORY = {
    "target_allowlist": "res",
    "tool_allowlist": "res",
    "capability_grant": "cap",
    "egress_allowlist": "host",
}


def _neutralizer() -> Callable[[str, str], str]:
    """A consistent map from any original token to a neutral one; the same input
    always yields the same output, so relationships survive the rename."""
    seen: dict[str, str] = {}
    counter = itertools.count(1)

    def neutral(original: str, category: str) -> str:
        if original not in seen:
            n = next(counter)
            seen[original] = f"host-{n}.example" if category == "host" else f"{category}-{n}"
        return seen[original]

    return neutral


def _neutral_dest(url: str, neutral: Callable[[str, str], str]) -> str:
    parts = urlsplit(url)
    if not parts.netloc:
        return neutral(url, "host")
    return urlunsplit(parts._replace(netloc=neutral(parts.netloc, "host")))


def _rename_export(exp: dict[str, Any], neutral: Callable[[str, str], str]) -> dict[str, Any]:
    exp = copy.deepcopy(exp)
    for rs in exp.get("resourceSpans", []):
        for ss in rs.get("scopeSpans", []):
            for span in ss.get("spans", []):
                for attr in span.get("attributes", []):
                    key, val = attr.get("key"), attr.get("value", {})
                    if key in _KEY_CATEGORY and "stringValue" in val:
                        cat, sv = _KEY_CATEGORY[key], val["stringValue"]
                        # preserve a declared-effectful operation name: it carries
                        # policy meaning (like a data-class label), not a confound.
                        if cat == "res" and sv in EFFECTFUL_TARGETS:
                            continue
                        val["stringValue"] = neutral(sv, cat)
                    elif key == "destination" and "stringValue" in val:
                        val["stringValue"] = _neutral_dest(val["stringValue"], neutral)
                    elif key == "delegated_grant" and "kvlistValue" in val:
                        for kv in val["kvlistValue"].get("values", []):
                            cat = _GRANT_CATEGORY.get(kv.get("key", ""))
                            arr = kv.get("value", {}).get("arrayValue", {})
                            if cat:
                                for item in arr.get("values", []):
                                    if "stringValue" in item:
                                        item["stringValue"] = neutral(item["stringValue"], cat)
    return exp


def _rename_envelopes(
    envs: dict[str, Any], neutral: Callable[[str, str], str]
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for agent, spec in envs.items():
        new_spec = dict(spec)
        for field, cat in _ENV_CATEGORY.items():
            if field in new_spec:
                new_spec[field] = [neutral(v, cat) for v in new_spec[field]]
        out[neutral(agent, "agent")] = new_spec
    return out


def _summary(verdicts: list[Verdict]) -> tuple[str, list[str]]:
    worst = max(verdicts, key=lambda v: _RANK[v.decision]).decision
    patterns = sorted(p for v in verdicts for p in v.patterns)
    return worst, patterns


@pytest.mark.parametrize("crew", REGISTRY, ids=lambda c: c.name)
def test_decisions_survive_consistent_renaming(crew: Crew) -> None:
    for label, sc in crew.scenarios.items():
        spans = sc.run()
        base = _summary(govern(export(crew.service, spans), crew.envelopes))
        neutral = _neutralizer()
        renamed = _summary(govern(
            _rename_export(export(crew.service, spans), neutral),
            _rename_envelopes(crew.envelopes, neutral),
        ))
        assert base == renamed, (
            f"{crew.name}: '{label}' changed under consistent renaming "
            f"{base} -> {renamed}: a rule is keying on a name, not on the envelope"
        )


def test_renaming_neutralizes_names_but_preserves_policy_inputs() -> None:
    # guard the guard: the transform really removes suggestive identifiers (so the
    # test above is not vacuously comparing an export to itself), AND it preserves a
    # declared-effectful operation name (a policy input, not a confound).
    crew = next(c for c in REGISTRY if c.name == "Fin-ops")
    spans = crew.scenarios["LLM03  excessive agency (unsanctioned wire transfer)"].run()
    blob = str(_rename_export(export(crew.service, spans), _neutralizer()))
    assert "payments-agent" not in blob            # a suggestive identifier: neutralized
    assert "wire_transfer" in blob                 # a declared-effectful op: preserved
    assert "agent-" in blob and ("res-" in blob or "cap-" in blob)
