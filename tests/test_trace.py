"""Tests for OTLP span construction."""

from __future__ import annotations

from ailab.trace import export, span


def test_span_has_otlp_shape() -> None:
    s = span("triage-agent", "tool_call", "it-helpdesk", target="read_ticket",
             consequence="read the ticket")
    assert set(s) >= {"traceId", "spanId", "name", "startTimeUnixNano", "attributes"}
    attrs = {a["key"]: a["value"]["stringValue"] for a in s["attributes"]}
    assert attrs["gen_ai.agent.name"] == "triage-agent"
    assert attrs["action"] == "tool_call"
    assert attrs["target"] == "read_ticket"
    assert attrs["yukti.flow"] == "it-helpdesk"
    assert attrs["consequence"] == "read the ticket"


def test_optional_attributes_are_omitted_when_absent() -> None:
    attrs = {a["key"] for a in span("a", "tool_call", "f")["attributes"]}
    assert attrs == {"gen_ai.agent.name", "action", "yukti.flow"}


def test_trace_ids_are_unique() -> None:
    ids = {span("a", "x", "f")["traceId"] for _ in range(100)}
    assert len(ids) == 100


def test_export_wraps_spans_under_a_service() -> None:
    exp = export("helpdesk-crew", [span("a", "x", "f"), span("b", "y", "f")])
    resource = exp["resourceSpans"][0]
    assert resource["resource"]["attributes"][0]["value"]["stringValue"] == "helpdesk-crew"
    assert len(resource["scopeSpans"][0]["spans"]) == 2
