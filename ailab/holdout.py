"""Held-out set loader: turn an independent author's JSON into lab traces and run
it ONCE through the live governance, reporting expected-vs-actual exactly as it
comes out.

This module is committed and frozen BEFORE the held-out scenarios are written, so
the translation cannot be shaped by the data it will carry. The JSON shape is the
one documented in ``holdout/AUTHORING_BRIEF.md``. The loader fixes nothing about a
scenario's intent; it maps the author's declared envelopes and spans straight into
the same governance path the demo and tests use (``ailab.govern.govern``), and
compares the engine's decision to the author's stated expectation. A disagreement
is a finding, reported, never silently fixed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ailab.govern import govern
from ailab.trace import export, span

_RANK = {"ALLOW": 0, "MONITOR": 1, "GATE": 2, "DENY": 3}
_FLOW = "holdout"
# the span() kwargs an author may set (everything except agent / action / flow)
_SPAN_KEYS = (
    "target", "destination", "capability", "tool", "data_labels",
    "delegated_grant", "child_agent", "model_name", "model_digest", "consequence",
)


@dataclass
class Outcome:
    name: str
    kind: str              # "attack" | "benign"
    expected: str          # the author's expected worst decision
    actual: str            # the engine's worst decision
    patterns: list[str]
    author_agreed: bool    # actual == expected (the author's hypothesis held)
    caught: bool           # an attack reached GATE or DENY
    wrongly_denied: bool   # a benign run reached DENY (a hard false positive)


def _to_spans(raw_spans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Each author span dict -> one OTLP span, via the same builder the crews use.
    Intent is preserved verbatim; only fields the schema defines are passed."""
    built: list[dict[str, Any]] = []
    for s in raw_spans:
        kwargs = {k: s[k] for k in _SPAN_KEYS if s.get(k) is not None}
        built.append(span(str(s["agent"]), str(s["action"]), _FLOW, **kwargs))
    return built


def run_scenario(sc: dict[str, Any]) -> Outcome:
    envelopes = {str(a): dict(e) for a, e in (sc.get("envelopes") or {}).items()}
    verdicts = govern(export("holdout-crew", _to_spans(sc.get("spans") or [])), envelopes)
    worst = max((v.decision for v in verdicts), key=lambda d: _RANK[d]) if verdicts else "ALLOW"
    patterns = sorted({p for v in verdicts for p in v.patterns})
    expected = str(sc.get("expected_worst_decision", "")).upper()
    kind = str(sc.get("kind", "attack"))
    return Outcome(
        name=str(sc.get("name", "?")), kind=kind, expected=expected, actual=worst,
        patterns=patterns, author_agreed=(worst == expected),
        caught=(worst in ("GATE", "DENY")),
        wrongly_denied=(kind == "benign" and worst == "DENY"),
    )


def run_doc(doc: dict[str, Any]) -> list[Outcome]:
    return [run_scenario(sc) for sc in (doc.get("scenarios") or [])]


def run_file(path: str | Path) -> list[Outcome]:
    return run_doc(json.loads(Path(path).read_text()))


def summarize(outcomes: list[Outcome]) -> dict[str, Any]:
    attacks = [o for o in outcomes if o.kind == "attack"]
    benign = [o for o in outcomes if o.kind == "benign"]
    return {
        "scenarios": len(outcomes),
        "attacks": len(attacks),
        "attacks_caught": sum(o.caught for o in attacks),
        "attacks_missed": [o.name for o in attacks if not o.caught],
        "benign": len(benign),
        "benign_wrongly_denied": [o.name for o in benign if o.wrongly_denied],
        "author_disagreements": [
            {"name": o.name, "expected": o.expected, "actual": o.actual}
            for o in outcomes if not o.author_agreed
        ],
    }
