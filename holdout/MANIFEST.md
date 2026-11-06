# Held-out set v1: frozen input manifest

Pre-registration record for the independent held-out scenarios. These inputs are
frozen (hashed here, committed, and tagged `holdout-v1`) BEFORE the engine is run
against them. The result is reported as it comes out, including misses and
author-vs-engine disagreements, and is never silently fixed. Any later fix ships
with a new frozen set, since this one is spent.

## Inputs (SHA-256)

- `grok-v1.json`      `077abd05f4d34d61d67922bacd4650b9692fbadf5766cc53d1405f4ef3f42971`
- `chatgpt-v1.json`   `1585ffda276daf945988569b57d4411bce49b630adc2475a6275de940f7ccfa2`

16 scenarios total (8 each; 12 attack, 4 benign). Re-hash the files to confirm they
are the ones that were frozen.

## Independence: disclosed, not blind

Both authors state prior exposure: Grok and ChatGPT reviewed the Yukti and
ai-security-lab repositories earlier in this work, rule code included. This is
therefore a **disclosed, partially-independent** held-out set: authored by a party
other than the rule author, reasoning from the public contract, and frozen before
the run, but not blind to the rules. That is weaker than a truly-blind set and
stronger than a self-authored one. It is recorded here so no one else has to point
it out. A truly-blind set would need an author that has never seen the code.

## Provenance notes

- `grok-v1.json` is Grok's output verbatim (already valid JSON).
- `chatgpt-v1.json` was transcribed from a transport-mangled paste (HTML-entity and
  backslash escaping artifacts such as `&#x20;`, `https\://`, and line-continuation
  backslashes). Only those format artifacts were removed; every envelope, span,
  expected decision, and rationale is the author's, unchanged. Validated by parse.

## How it is run

`ailab/holdout.py` (committed and frozen before these scenarios existed) maps each
scenario's declared envelopes and spans straight into the same governance path the
demo and tests use, and compares the engine's worst decision to the author's stated
`expected_worst_decision`. See `RESULTS.md` for the outcome.
