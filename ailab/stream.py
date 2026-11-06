"""Stream the crews' attacks at a running Yukti governor.

For each crew, registers its agents' task envelopes, then posts each scenario's
OTLP traces to the governor's ``/v1/traces`` endpoint. The governor governs them
live; open its dashboard to watch the attacks get caught.

    python -m ailab.stream [governor_url]   # default http://localhost:8899
"""

from __future__ import annotations

import os
import sys
import time

import httpx

from ailab.crews import REGISTRY
from ailab.trace import export


def stream_to(base_url: str, *, pace: float = 0.0) -> dict[str, int]:
    totals: dict[str, int] = {}
    with httpx.Client(base_url=base_url, timeout=15.0) as client:
        for crew in REGISTRY:
            for agent, spec in crew.envelopes.items():
                client.post("/v1/envelopes", json={**spec, "agent": agent})
            for label, sc in crew.scenarios.items():
                resp = client.post("/v1/traces", json=export(crew.service, sc.run()))
                decisions = resp.json().get("decisions", {})
                for decision, count in decisions.items():
                    totals[decision] = totals.get(decision, 0) + count
                print(f"  [{crew.name}] {label} → {decisions}")
                if pace:
                    time.sleep(pace)
    return totals


def main() -> int:
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8899"
    pace = float(os.environ.get("AILAB_PACE", "0"))
    scenarios = sum(len(c.scenarios) for c in REGISTRY)
    print(f"streaming {scenarios} scenarios from {len(REGISTRY)} crews at {url}\n")
    totals = stream_to(url, pace=pace)
    print(f"\ndone. decisions across all traffic: {totals}")
    print("open the governor dashboard to review the caught attacks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
