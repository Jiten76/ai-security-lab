"""OTLP span construction.

The crew records each tool call and network action as an OpenTelemetry span in
the OTLP/JSON shape. These are the traces the governance layer (Yukti) reads, in
exactly the format a real OTel exporter would produce, so the lab exercises the
same ingestion path a production deployment would use.
"""

from __future__ import annotations

import itertools
import time
from typing import Any

# A per-process nonce so trace ids are unique across separate runs against the
# same long-lived governor (each span still gets a unique id within a run too).
_BASE = format(time.time_ns() & 0xFFFFFFFFFFFF, "012x")
_seq = itertools.count(1)


def _anyvalue(v: Any) -> dict[str, Any]:
    """Encode a Python value as an OTLP/JSON AnyValue (the wire shape Yukti's
    ingest decodes). Lists become arrayValue, dicts kvlistValue, so a span can
    carry a data-provenance label set or a delegated-grant map, not just strings."""
    if isinstance(v, bool):
        return {"boolValue": v}
    if isinstance(v, int):
        return {"intValue": str(v)}
    if isinstance(v, float):
        return {"doubleValue": v}
    if isinstance(v, (list, tuple)):
        return {"arrayValue": {"values": [_anyvalue(x) for x in v]}}
    if isinstance(v, dict):
        return {"kvlistValue": {"values": [{"key": str(k), "value": _anyvalue(x)}
                                           for k, x in v.items()]}}
    return {"stringValue": str(v)}


def span(
    agent: str,
    action: str,
    flow: str,
    *,
    target: str | None = None,
    destination: str | None = None,
    capability: str | None = None,
    tool: str | None = None,
    data_labels: list[str] | None = None,
    delegated_grant: dict[str, list[str]] | None = None,
    child_agent: str | None = None,
    model_name: str | None = None,
    model_digest: str | None = None,
    consequence: str = "",
) -> dict[str, Any]:
    """Build one OTLP/JSON span for an agent action.

    ``agent`` and ``action`` map onto GenAI/Yukti fields; ``target`` /
    ``destination`` / ``capability`` describe what the action touched.
    ``data_labels`` are the provenance classes of data this action moves (for
    taint-laundering governance); ``delegated_grant`` / ``child_agent`` describe
    a hand-off to a subagent (for delegation governance). ``model_name`` /
    ``model_digest`` record which model (by name and by weight digest) the agent
    ran, for model-provenance governance. ``consequence`` is the plain-language
    summary shown in reports.
    """
    n = next(_seq)
    attrs: dict[str, Any] = {
        "gen_ai.agent.name": agent,
        "action": action,
        "yukti.flow": flow,
    }
    if target is not None:
        attrs["target"] = target
    if destination is not None:
        attrs["destination"] = destination
    if capability is not None:
        attrs["capability"] = capability
    if tool is not None:
        attrs["tool"] = tool
    if data_labels is not None:
        attrs["data_labels"] = list(data_labels)
    if delegated_grant is not None:
        attrs["delegated_grant"] = delegated_grant
    if child_agent is not None:
        attrs["child_agent"] = child_agent
    if model_name is not None:
        attrs["gen_ai.request.model"] = model_name
    if model_digest is not None:
        attrs["gen_ai.model.digest"] = model_digest
    if consequence:
        attrs["consequence"] = consequence
    return {
        "traceId": f"{_BASE}{n:020x}",
        "spanId": f"{n:016x}",
        "name": f"gen_ai.{action}",
        "startTimeUnixNano": str(int(time.time() * 1e9)),
        "attributes": [{"key": k, "value": _anyvalue(v)} for k, v in attrs.items()],
    }


def export(service: str, spans: list[dict[str, Any]]) -> dict[str, Any]:
    """Wrap spans in an OTLP ExportTraceServiceRequest for a given service.

    One export is one agent run: all its spans share a single ``traceId`` (with
    unique spanIds), exactly as a real OTel trace groups the spans of one run.
    That shared trace id is what lets the governor scope run-level reasoning —
    read-taint propagation in particular — to this run, so two runs that reuse an
    agent name cannot cross-contaminate.
    """
    run_trace = f"{_BASE}{next(_seq):020x}"
    spans = [{**s, "traceId": run_trace} for s in spans]
    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": service}}
                    ]
                },
                "scopeSpans": [{"scope": {"name": "ailab"}, "spans": spans}],
            }
        ]
    }
