"""The governor service: Yukti's live dashboard, governing only the lab's traffic.

Runs Yukti's serve app in ``dataflow`` mode with the background simulator
disabled, so the dashboard shows exactly the crews' traces posted to
``/v1/traces`` and nothing else — and governs them with the SAME rule set as the
direct demo/test path (breakout patterns plus the data-flow provenance and
delegation patterns, with run-scoped read-taint propagation on ingest). Unbound
agents fail closed: a trace whose agent has no registered envelope is GATEd, not
silently allowed. Point an ASGI server at ``ailab.governor:app`` (see the Docker
stack), then open the dashboard to watch attacks get caught live.
"""

from __future__ import annotations

import os

os.environ.setdefault("YUKTI_MODE", "dataflow")

from yukti.core.policy.base import Decision  # noqa: E402
from yukti.serve.api import create_app  # noqa: E402

app = create_app(run_simulator=False, unbound_agent_decision=Decision.GATE)
