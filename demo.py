"""AI Security Lab: build, break, govern.

Runs every registered crew against a clean scenario and its attacks, governs
each with Yukti, and reports what was caught.

    python demo.py
"""

from ailab.crews import REGISTRY
from ailab.harness import run_lab

if __name__ == "__main__":
    raise SystemExit(run_lab(REGISTRY))
