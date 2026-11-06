# Review guide: AI Security Lab

*A note to a reviewer (human or model). This document exists to make your review
sharper, not to sell you the project. It states plainly what the lab does, how it
works, what it deliberately does **not** do, and where I most want you to push.*

The lab lives at **github.com/Jiten76/ai-security-lab**. The governance engine it
exercises, **Yukti**, is a separate public repo:
**github.com/Jiten76/yukti**. The lab depends on Yukti the way a real deployment
would: it imports it, feeds it deterministic OTLP/JSON traces, and acts on its
verdicts.

A note on the OWASP codes below: they are the **2026 edition** of the OWASP LLM
Top 10 (released 4 August 2026), not the 2025 numbering. In 2026 Excessive Agency
is LLM03 (was LLM06), Vector and Embedding Weaknesses is LLM09 (was LLM08), and
System Prompt Leakage was renamed and renumbered to LLM08 Hidden Context Exposure
(was LLM07). LLM01 Prompt Injection and LLM02 Sensitive Information Disclosure are
unchanged.

---

## TL;DR

A small, reproducible lab that **builds** a multi-agent system, **breaks** it with
the exploits from the 2026 OWASP LLM Top 10, and **governs** it with Yukti. It
runs end to end with one command and **no API keys**. Across four crews it
catches **12 of 13 attacks**; one is built to slip past on purpose, to show
exactly where envelope governance stops. That slip is the most important thing in
the repo: it is the difference between a governance layer that *discriminates* and
a rigged perfect score. A fourth crew then shows the capability that catches the
general form of that gap: a **taint-laundering** disclosure and a
**subagent-delegation escalation** that destination/tool envelopes and inline
per-process taint both miss.

---

## What I'm asking you to review

I care more about these than about style nits. Please be adversarial.

1. **Is the governance model real, or is it theater?** The claim is that Yukti
   catches these attacks by reading *what the agent did* (its trace) against a
   *declared boundary* (its task envelope), not by pattern-matching attack
   strings. Read `ailab/govern.py` and the Yukti entrypoints it calls. Does the
   detection genuinely derive from the envelope, or could the same result be faked
   with a keyword list? If it's faked, say so.

2. **Is the task-envelope abstraction sound?** An envelope declares an agent's
   allowed tools (`target_allowlist`), allowed egress destinations
   (`egress_allowlist`), and granted capabilities (`capability_grant`). The thesis
   is that *most* agentic attacks reduce to "the agent did something outside its
   sanctioned boundary." Is that a defensible framing, or does it miss whole
   classes of attack? (The lab argues it misses one class on purpose. See §4.)

3. **Is the OWASP mapping honest?** Each scenario declares its OWASP codes as
   **data** (`owasp=(...)` on the `Scenario`), and the coverage matrix reports what
   each attack *is*, not what its title says. Check that the codes are applied
   correctly (and that they are the 2026 codes, not 2025), and that the matrix
   doesn't overclaim coverage. One cell is marked a **GAP**. Is that the *right*
   cell to call a gap?

4. **Does it do something meaningful, or is it vibe-coding?** This is the bar I
   hold it to. A convincing-looking demo that proves nothing is worthless. Does
   this lab demonstrate a real capability a security engineer would value, or is it
   an elaborate way to print a green checkmark? Tell me which, and why.

5. **The deterministic-crew decision: fair shortcut or fatal cheat?** The crews
   are scripted, not a live LLM (see §3). I argue this *strengthens* the claim
   because detection reads the trace, not the model, so the same inputs always
   reproduce the same verdict. Do you buy that, or does the absence of a real model
   invalidate the result? This is the single assumption most likely to be wrong.

6. **What would a real reviewer in the loop catch?** If you were the security
   engineer, the second-line risk officer, or the regulator examining this, where
   is the hole? What's the first question you'd ask that the lab can't answer?

---

## 1. Capability: what it actually does today

Three deliberately-vulnerable multi-agent **crews**, each on a shared harness:

| Crew | Agents | Attack surface |
|---|---|---|
| IT helpdesk | triage + resolver | a directive planted in a support ticket |
| Fin-ops | reconciler + payments | a directive planted in an invoice memo |
| Customer support | knowledge + CRM | a poisoned knowledge-base article (RAG) |
| Data platform | analyst + orchestrator | a poisoned analytics request; a widening subagent delegation |

Each crew runs one clean scenario and two-to-four attack scenarios. Every tool
call and network action becomes an OpenTelemetry (OTLP) span. Yukti reads those
spans, binds each to the acting agent's declared envelope, and returns a verdict
per action: **ALLOW · MONITOR · GATE · DENY**. An attack is "caught" iff its worst
action is GATE (escalated to a human) or DENY (a deny decision; enforcing it at a
gateway is a separate step the engine does not demonstrate).

The attacks span OWASP **LLM01** (prompt injection), **LLM02** (sensitive-info
disclosure), **LLM03** (excessive agency), **LLM08** (hidden context exposure, the
2026 home of system-prompt leakage), and **LLM09** (vector and embedding
weaknesses, i.e. RAG poisoning). Result: **12 of 13 caught, 1 known gap by design.**

Alongside the attacks, each crew runs benign near-misses: legitimate work close to
a boundary (a granted but sensitive capability, an egress to a sanctioned host, a
subagent handed a *narrower* grant, a raw read followed by an aggregate-only
egress). Result: **8 of 9 allowed, 1 sent for human review (an aggregate the trace
can't verify clean after a raw read, by design), 0 wrongly denied.** A detector that
flagged legitimate work as an attack would be worthless, so the human-review and
wrongly-denied figures are reported beside the catch rate. (A GATE on legitimate
work is an operator interruption, counted honestly as human review, not hidden
under a "0 false alarms" headline; this is a sanity floor on 9 authored runs, not a
statistical false-positive rate.)
The data-platform crew adds patterns beyond the destination-and-tool envelope:
`provenance_violation` (taint laundering, DENY) with its `provenance_unverifiable`
counterpart (a declared-clean aggregate the read-taint can't confirm, GATE),
`delegation_escalation` (grant widening across a subagent hand-off, GATE), and
`model_provenance_mismatch` (an agent running a model whose weight digest the
envelope does not pin, GATE). The terminal output and the generated `report.html`
show the full breakdown.

---

## 2. Approach: build, break, govern

**Build.** A crew is *data*, not new harness code: it declares its agents'
envelopes and a dict of scenarios (`ailab/crews/*.py`). Adding a crew is a module
in the registry. The crews are deliberately vulnerable in the way a real LLM agent
is: they **cannot separate instructions from data**, so a directive planted in
ingested content is followed as if it were a legitimate task.

**Break.** The attack harness plants directives in the content a crew ingests (a
ticket, an invoice memo, a KB article). Those directives drive indirect prompt
injection to exfiltration, privilege escalation via an ungranted tool, egress to an
external collector, and system-prompt leakage.

**Govern.** This is the part to scrutinize. The data path (`ailab/govern.py`):

```
crew action  →  OTLP span (ailab/trace.py)
             →  yukti.integrations.opentelemetry.observations_from_otlp(...)
             →  bind each observation to envelope_from_dict({...the agent's spec})
             →  yukti.scenarios.agentic_dataflow.build_dataflow_governance().process(obs)
             →  Verdict{decision, patterns, evidence, consequence}
             →  ranked by consequence; worst action decides the scenario
```

The envelope is declared **out of band** by the operator. It is not derived from
the attack. Detection fires because the observed action (an egress to
`harvest.evil.example`, a call to `export_all_customers`, a self-granted
`admin_grant`) falls **outside** the sanctioned boundary. The patterns Yukti
surfaces here are `unsanctioned_egress`, `envelope_escape`,
`capability_escalation`, and (for the data-platform crew) `provenance_violation`
and `delegation_escalation`. The lab ingests traces in the **same OTLP/JSON shape
a real OTel exporter produces** (`ailab/trace.py`), so it exercises a production
ingestion path, not a bespoke one.

A live variant exists: `docker compose up` runs Yukti's dashboard as the
`governor` service; the `attacker` service streams traces to it over Yukti's OTLP
endpoint (`POST /v1/traces`) after declaring each agent's envelope
(`POST /v1/envelopes`), and attacks are denied or escalated on the dashboard in
real time.

---

## 3. The deterministic-crew decision (the load-bearing assumption)

The crews are scripted Python, not a live model. Why this is deliberate, and why I
claim it makes the result *stronger*, not weaker:

- The vulnerability is *modeled*, not hoped for. A real LLM agent sometimes resists
  an injection and sometimes doesn't; a scripted crew follows the planted directive
  every time, so the attack is guaranteed to actually happen, and there is nothing
  for the governance layer to hide behind.
- Detection never depends on the crew being an LLM. Yukti reads the **trace of
  what the agent did**. Swap the scripted crew for a real model that takes the same
  action and the verdict is identical, because the input to the governor is the
  span, not the model.
- The same inputs always reproduce the same trace and the same verdict, which
  gives deterministic tests, deterministic CI, and a deterministic review.

**The honest counter-argument** (please weigh it): a scripted crew can't show that
the governor copes with the *messiness* of real model output, such as partial
actions, ambiguous tool calls, or novel egress shapes. A real-model backend (AWS
Bedrock, a local Ollama model, or an API provider) is the stated next step
precisely to close that gap. If you think the deterministic result is worthless
until then, I want to hear the argument.

---

## 4. The known gap by design, and the capability that detects it

The customer-support crew includes an attack that **slips** (`exfil_in_channel` in
`ailab/crews/support.py`): the CRM agent bundles every customer's PII into a reply
sent over the **sanctioned** support channel (`support.corp.example`). The envelope
**allows** that destination, so the action is inside the boundary and Yukti returns
ALLOW.

It is a real miss, and I show it as one. It is also a **known limitation of
envelope-scope governance**, disclosed on purpose: the envelope reasons about
*where* an action goes and *which* tool it uses, not the sensitivity or volume of
the payload. Catching in-scope bulk disclosure needs a content/volume (DLP-class)
signal this lab deliberately does not model. The coverage matrix marks that LLM02
cell a **GAP**, and a test (`test_caught_count_and_exactly_one_disclosed_gap`)
asserts that exactly one attack slips and it is the one declared to slip. A layer
that names its own blind spot is more trustworthy than one that claims a perfect
score.

**The capability that detects it.** The data-platform crew
(`ailab/crews/dataops.py`) shows the general form of this gap *flagged*. Its analyst
agent READs the raw customer table on one span, then egresses to a *sanctioned*
reporting sink on a later span that declares no label of its own, so the
destination allowlist is satisfied and an inline per-process taint model sees a
clean egress process. Yukti propagates taint across the run (`propagate_read_taint`
in `agentic_dataflow.py`): the earlier read taints the agent, so the bare egress is
flagged by `provenance_violation` even though that span carries no label. Be precise
about what this proves and what it assumes: the class is a provenance label the
trace carries, not something Yukti derives from content, so a transformation that
changes the class (a summary, a reformat, one field pulled from a record) still
evades it, and this is second-line detection, not inline prevention. The
support-crew slip persists only because that crew's trace carries no provenance
label at all; the moment a read labels one, the same pattern flags a later egress.
Delegation is governed two ways: the orchestrator handing a subagent a grant wider
than its own envelope is caught by `delegation_escalation`, and an agent acting
with no registered envelope fails closed (escalated), so a spawned subagent cannot
act ungoverned (`test_unregistered_agent_fails_closed`).

**Reviewer questions:** (a) is this the most important gap to disclose, or is there
a worse one I'm not showing? (b) is `data_egress_grant` the right abstraction, or
does governing a labeled *data class* (rather than payload content) just move the
gap to the transformation step?

---

## 5. Value aspiration: where this is heading

The honest framing: **most** agentic-AI attacks are an agent doing something it was
never sanctioned to do. If you can declare an agent's task envelope and then watch
its real behavior against that envelope, continuously, with ranked findings and a
human decision path for what the engine won't deny on its own, you have a large,
practical slice of AI security posture. This lab is the end-to-end proof of that
loop on known attacks.

The aspiration (labeled as aspiration, not a claim of done): a governance layer for
agentic AI that sits in the trace path of real deployments, the way runtime and
posture tooling sits in cloud infrastructure today. This lab is one generation of a
longer line of work: a risk-as-code platform, a public portfolio of agentic-risk
tools (**github.com/Jiten76/agentic-risk-portfolio**), Yukti as the governance
engine, and this lab exercising Yukti against real attacks. Treat the vision as
direction; review the lab on what it demonstrably does today.

---

## 6. What this does NOT claim

- **Not a product.** It's a reproducible demonstration of a governance loop.
- **Not a live-model red-team.** The crews are deterministic scripts (§3).
- **Not complete OWASP coverage.** It exercises five LLM categories, not all ten,
  and marks one of them a gap.
- **Not a compliance crosswalk.** The model aligns with the *discipline* of the
  NIST AI RMF (Measure/Manage) and ISO/IEC 42001 operational controls (a declared
  boundary, continuous detection, ranked findings, a human decision path) but it
  does **not** ship a control-by-control mapping to those regimes.
- **Not a DLP engine.** It governs *data provenance* (which class may leave, via
  `data_egress_grant`), not payload *content* or *volume*. The support-crew slip
  rides a sanctioned channel with no provenance label declared; catching in-scope
  bulk disclosure by volume alone would need a content signal this lab does not
  model.

---

## 7. Reproduce it in two minutes

```bash
pip install -r requirements.txt   # pulls Yukti from its public repo
python demo.py                    # the full build-break-govern run, no API keys
```

```bash
python -m ailab.report            # writes report.html (verdict, OWASP matrix, findings)
```

```bash
pip install -e ".[dev]" && pytest # 32 tests: 12-of-13, 0 wrongly denied, decisions survive renaming
# held-out set (independent, frozen at tag holdout-v1): see holdout/RESULTS.md
#   15/16 matched the authors' predictions; 11/12 attacks caught; 0 wrongly denied
```

```bash
docker compose up --build         # live: Yukti dashboard on http://localhost:8899
```

What you should see: every clean scenario ALLOWed, eleven attacks DENY/GATE, one
ALLOW marked SLIPPED, and a final `12 of 13 attacks caught; 1 slipped inside the
sanctioned envelope` summary.

---

## 8. Map for a deep read

Verify the claims above against the code in this order:

| File | What to check |
|---|---|
| `ailab/govern.py` | the real governance path; which Yukti entrypoints are called; that the verdict derives from the envelope, not the attack string |
| `ailab/harness.py` | `Scenario`/`Crew` dataclasses; `owasp`/`expect`/`gap_note` declared as data; how "caught" is decided (GATE/DENY) |
| `ailab/crews/support.py` | the three caught attacks and the one that slips (`exfil_in_channel`); why the slip rides the sanctioned channel |
| `ailab/crews/dataops.py` | the taint-laundering and delegation-escalation attacks; the `data_egress_grant` and `delegated_grant` signals |
| `ailab/crews/helpdesk.py`, `finops.py` | the other crews' envelopes and attacks |
| `yukti/scenarios/agentic_dataflow.py` (in Yukti) | the `provenance_violation` / `provenance_unverifiable`, `delegation_escalation`, and `model_provenance_mismatch` patterns, and that provenance fires independent of the egress allowlist |
| `ailab/trace.py` | the OTLP/JSON span shape: is it faithful to what a real OTel exporter emits? |
| `ailab/report.py` | how the coverage matrix is built from declared OWASP data (not parsed from titles) |
| `tests/test_crews.py` | the invariant that makes the 12 of 13 a *discriminating* result, not a rigged one; plus the benign near-misses: 0 wrongly denied |
| `tests/test_negative_controls.py` | rename every agent, tool, capability and host to a neutral token (consistently, envelope included) and assert every decision is unchanged: the rules key on behaviour against the envelope, not on suggestive names. Data-class labels and the declared effectful-operation registry are preserved, not renamed (policy inputs, not confounds) |
| `tests/test_live_api.py` | the same provenance/delegation decisions asserted over HTTP against the live governor app |

Thank you for reviewing. The most useful thing you can give me is the place where
this is weaker than it looks.
