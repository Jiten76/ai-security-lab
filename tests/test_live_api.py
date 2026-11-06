"""The lab's LIVE path over HTTP — the governor app catches the data-flow attacks.

This is the integration proof that the Docker/dashboard path, not only the CLI
(`govern.py`) path, exercises the provenance and delegation governance. It drives
the actual `ailab.governor` app (dataflow mode, unbound-agent gate) with the real
dataops crew scenarios posted as OTLP to `/v1/traces`, and asserts the wire
response — so the tested path and the live path are the same system.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from yukti.core.policy.base import Decision

from ailab.crews.dataops import CREW
from ailab.trace import export

_RANK = {"ALLOW": 0, "MONITOR": 1, "GATE": 2, "DENY": 3}


@pytest.fixture()
def live(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv("YUKTI_MODE", "dataflow")
    from ailab.governor import app  # the real governor, built with the unbound gate

    with TestClient(app) as client:
        for agent, spec in CREW.envelopes.items():
            client.post("/v1/envelopes", json={**spec, "agent": agent})
        yield client


def _results(client: TestClient, label: str) -> list[dict[str, Any]]:
    body = client.post("/v1/traces", json=export(CREW.service, CREW.scenarios[label].run()))
    return list(body.json()["results"])


def _worst(results: list[dict[str, Any]]) -> str:
    return max((r["decision"] for r in results), key=lambda d: _RANK[d])


def _label(substring: str) -> str:
    return next(name for name in CREW.scenarios if substring in name.lower())


def test_governor_runs_dataflow_mode(live: TestClient) -> None:
    # the live dashboard governs with the data-flow rule set, not breakout-only.
    assert live.get("/api/meta").json()["mode"] == "dataflow"


def test_unbound_gate_is_configured() -> None:
    from ailab.governor import app

    assert app.state.unbound_agent_decision is Decision.GATE


def test_taint_laundering_caught_over_http(live: TestClient) -> None:
    results = _results(live, _label("laundering"))
    fired = {p for r in results for p in r["patterns"]}
    assert "provenance_violation" in fired  # caught by cross-span provenance
    assert "unsanctioned_egress" not in fired  # the sink is permitted
    assert _worst(results) == "DENY"


def test_delegation_escalation_gated_over_http(live: TestClient) -> None:
    results = _results(live, _label("delegation"))
    fired = {p for r in results for p in r["patterns"]}
    assert "delegation_escalation" in fired
    assert _worst(results) == "GATE"


def test_model_provenance_swap_gated_over_http(live: TestClient) -> None:
    results = _results(live, _label("model provenance"))
    fired = {p for r in results for p in r["patterns"]}
    assert "model_provenance_mismatch" in fired
    assert _worst(results) == "GATE"  # swapped weight digest -> human sign-off


def test_clean_run_allowed_over_http(live: TestClient) -> None:
    clean = next(name for name in CREW.scenarios if name.startswith("Clean"))
    assert _worst(_results(live, clean)) == "ALLOW"


def test_benign_near_misses_not_wrongly_denied_over_http(live: TestClient) -> None:
    # legitimate near-misses must never be hard-denied on the live path either.
    for label in [name for name in CREW.scenarios if name.startswith("Benign")]:
        assert _worst(_results(live, label)) != "DENY", f"{label} wrongly denied over HTTP"
