"""Generate a self-contained AI security assessment report from a lab run.

Runs every crew's scenarios through Yukti's governance and renders the result
as analysis: a summary verdict, a governance-outcome breakdown, an OWASP
coverage matrix, per-crew results, and a findings table. The output is a single
static HTML file, so it is always populated (unlike a live monitor).

    python -m ailab.report              # writes report.html
"""

from __future__ import annotations

import html
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from ailab.crews import REGISTRY
from ailab.govern import Verdict, govern
from ailab.trace import export

OWASP_NAMES = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Excessive Agency",
    "LLM08": "Hidden Context Exposure",
    "LLM09": "Vector & Embedding Weaknesses",
}
OWASP_DESC = {
    "LLM01": "Untrusted input overrides the agent's instructions.",
    "LLM02": "The agent reveals data it should not.",
    "LLM03": "The agent takes an action beyond its granted authority.",
    "LLM08": "The agent's hidden context, its own configuration or system prompt, is exposed.",
    "LLM09": "Poisoned retrieved content steers the agent (RAG poisoning).",
}
_RANK = {"ALLOW": 0, "MONITOR": 1, "GATE": 2, "DENY": 3}
_OUTCOME = {"DENY": "denied", "GATE": "escalated to a human", "ALLOW": "allowed"}


@dataclass
class Finding:
    crew: str
    label: str
    owasp: list[str]
    decision: str
    agent: str
    consequence: str
    patterns: list[str]
    actions: int
    trace: list[Verdict] = field(default_factory=list)
    gap_note: str = ""


@dataclass
class Report:
    findings: list[Finding]
    decisions: Counter[str] = field(default_factory=Counter)

    @property
    def attacks(self) -> list[Finding]:
        return [f for f in self.findings if not f.label.startswith(("Clean", "Benign"))]

    @property
    def caught(self) -> list[Finding]:
        return [f for f in self.attacks if f.decision in ("GATE", "DENY")]

    @property
    def benign(self) -> list[Finding]:
        # legitimate near-misses: must not be hard-denied (wrongly denied)
        return [f for f in self.findings if f.label.startswith("Benign")]


def collect() -> Report:
    findings: list[Finding] = []
    decisions: Counter[str] = Counter()
    for crew in REGISTRY:
        for label, sc in crew.scenarios.items():
            verdicts = govern(export(crew.service, sc.run()), crew.envelopes)
            for v in verdicts:
                decisions[v.decision] += 1
            worst = max(verdicts, key=lambda v: _RANK[v.decision])
            findings.append(Finding(
                crew=crew.name, label=label, owasp=list(sc.owasp),  # declared data, not title-parsed
                decision=worst.decision, agent=worst.agent, consequence=worst.consequence,
                patterns=worst.patterns, actions=len(verdicts), trace=verdicts,
                gap_note=sc.gap_note,
            ))
    return Report(findings=findings, decisions=decisions)


def _e(s: str) -> str:
    return html.escape(str(s))


def _bar(decisions: Counter[str]) -> str:
    total = sum(decisions.values()) or 1
    order = [("ALLOW", "allow"), ("GATE", "gate"), ("DENY", "deny")]
    segs = "".join(
        f'<div class="seg {cls}" style="width:{decisions.get(k, 0) / total * 100:.1f}%" '
        f'title="{k}: {decisions.get(k, 0)}"></div>'
        for k, cls in order if decisions.get(k, 0)
    )
    legend = "".join(
        f'<span class="lg"><i class="dot {cls}"></i>{k.title()} '
        f'<b>{decisions.get(k, 0)}</b></span>'
        for k, cls in order
    )
    return f'<div class="bar">{segs}</div><div class="legend">{legend}</div>'


def _coverage(report: Report) -> str:
    per_cat: dict[str, list[Finding]] = {}
    for f in report.attacks:
        for code in f.owasp:
            per_cat.setdefault(code, []).append(f)
    cards = []
    for code in sorted(per_cat):
        fs = per_cat[code]
        all_caught = all(f.decision in ("GATE", "DENY") for f in fs)
        mark = "✓" if all_caught else "✗"
        cls = "ok" if all_caught else "gap"
        cards.append(
            f'<div class="cov {cls}"><div class="cov-h"><span class="code">{code}</span>'
            f'<span class="mark">{mark}</span></div>'
            f'<div class="cov-name">{_e(OWASP_NAMES.get(code, code))}</div>'
            f'<div class="cov-n">{len(fs)} test{"s" if len(fs) != 1 else ""} · '
            f'{"all caught" if all_caught else "GAP"}</div></div>'
        )
    return "".join(cards)


def _crew_cards(report: Report) -> str:
    cards = []
    for crew in REGISTRY:
        fs = [f for f in report.findings
              if f.crew == crew.name and not f.label.startswith(("Clean", "Benign"))]
        caught = sum(f.decision in ("GATE", "DENY") for f in fs)
        d = Counter(f.decision for f in fs)
        cards.append(
            f'<div class="crew"><div class="crew-name">{_e(crew.name)}</div>'
            f'<div class="crew-score">{caught}/{len(fs)} <span>caught</span></div>'
            f'<div class="crew-d">'
            f'<span class="pill deny">{d.get("DENY", 0)} denied</span>'
            f'<span class="pill gate">{d.get("GATE", 0)} escalated</span></div></div>'
        )
    return "".join(cards)


def _trace_rows(f: Finding) -> str:
    out = []
    for v in f.trace:
        cls = v.decision.lower()
        out.append(
            f'<div class="tr-line"><span class="dec {cls}">{v.decision}</span>'
            f'<span class="tr-agent">{_e(v.agent)}</span>'
            f'<span class="tr-what">{_e(v.consequence)}</span></div>'
        )
    return "".join(out)


def _detection_note(f: Finding) -> str:
    if f.gap_note:
        return (
            "This attack stayed inside the sanctioned envelope, so it was not caught. "
            f"A known gap by design: {_e(f.gap_note)}"
        )
    return (
        "The action left the agent's operator-declared task envelope, so it was "
        f"{_OUTCOME.get(f.decision, f.decision)}."
    )


def _detail(f: Finding, idx: int) -> str:
    owasp = "".join(
        f'<div class="owasp-item"><b>{c} {_e(OWASP_NAMES.get(c, ""))}</b>: '
        f'{_e(OWASP_DESC.get(c, ""))}</div>'
        for c in f.owasp
    )
    caught = next((v for v in f.trace if v.caught), None)
    evidence = caught.evidence if caught else []
    ev = "".join(f"<code>{_e(s[:12])}…</code>" for s in evidence) or "none"
    return (
        f'<tr class="detail" id="d{idx}" hidden><td colspan="5"><div class="detail-in">'
        f'<div class="d-sec"><h4>The attack</h4>{owasp}</div>'
        f'<div class="d-sec"><h4>Action trace: every step judged</h4>'
        f'<div class="trace">{_trace_rows(f)}</div></div>'
        f'<div class="d-sec"><h4>Detection</h4>'
        f'<div>Pattern(s): <code>{_e(", ".join(f.patterns) or "none")}</code></div>'
        f'<div class="d-note">{_detection_note(f)}</div></div>'
        f'<div class="d-sec"><h4>Evidence</h4>'
        f'<div>{len(evidence)} record(s) in the content-addressed chain: {ev}</div></div>'
        f"</div></td></tr>"
    )


def _findings_table(report: Report) -> str:
    rows = []
    for idx, f in enumerate(report.attacks):
        codes = " ".join(f'<span class="tag">{c}</span>' for c in f.owasp)
        dcls = f.decision.lower()
        pats = ", ".join(f.patterns) or "none"
        slipped = f.decision in ("ALLOW", "MONITOR")
        outcome = "slipped (known gap by design)" if slipped else _OUTCOME.get(f.decision, f.decision)
        rows.append(
            f'<tr class="row" data-id="{idx}"><td>{codes}</td><td>{_e(f.crew)}</td>'
            f'<td><div class="act">{_e(f.consequence)}</div>'
            f'<div class="who">{_e(f.agent)} <span class="expand">▸ details</span></div></td>'
            f'<td><span class="dec {dcls}">{f.decision}</span><br>'
            f'<span class="outcome">{outcome}</span></td>'
            f'<td><code>{_e(pats)}</code></td></tr>'
            + _detail(f, idx)
        )
    return "".join(rows)


_CSS = """
:root{--bg:#0b0e14;--panel:#131722;--line:#232838;--fg:#e6e9f0;--muted:#8b93a7;
--allow:#34d399;--gate:#f5b74e;--deny:#ef5b6e;--accent:#8b7cf6}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.55 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:40px 28px 64px}
h1{font-size:26px;margin:0 0 4px}.sub{color:var(--muted);margin:0 0 28px}
.verdict{background:linear-gradient(180deg,#141a26,#111520);border:1px solid var(--line);
border-left:4px solid var(--allow);border-radius:12px;padding:20px 24px;margin-bottom:28px}
.verdict b{font-size:22px}.verdict .gap{color:var(--deny)}
.tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:28px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px 18px}
.tile .n{font-size:30px;font-weight:700}.tile .l{color:var(--muted);font-size:12px;
text-transform:uppercase;letter-spacing:.06em}
.tile.deny{border-top:2px solid var(--deny)}.tile.gate{border-top:2px solid var(--gate)}
.tile.allow{border-top:2px solid var(--allow)}.tile.attacks{border-top:2px solid var(--accent)}
section{margin-bottom:32px}h2{font-size:13px;text-transform:uppercase;letter-spacing:.08em;
color:var(--muted);border-bottom:1px solid var(--line);padding-bottom:8px;margin:0 0 16px}
.bar{display:flex;height:16px;border-radius:8px;overflow:hidden;background:#0f131c;margin-bottom:10px}
.seg.allow{background:var(--allow)}.seg.gate{background:var(--gate)}.seg.deny{background:var(--deny)}
.legend{display:flex;gap:20px;color:var(--muted);font-size:13px}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px}
.dot.allow{background:var(--allow)}.dot.gate{background:var(--gate)}.dot.deny{background:var(--deny)}
.legend b{color:var(--fg)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:14px}
.cov{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.cov.ok{border-left:3px solid var(--allow)}.cov.gap{border-left:3px solid var(--deny)}
.cov-h{display:flex;justify-content:space-between;align-items:center}
.code{font-family:ui-monospace,monospace;font-weight:700}.mark{font-size:18px}
.cov.ok .mark{color:var(--allow)}.cov.gap .mark{color:var(--deny)}
.cov-name{font-size:13px;margin:6px 0 4px}.cov-n{color:var(--muted);font-size:12px}
.crews{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.crew{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px 18px}
.crew-name{font-weight:600;margin-bottom:8px}.crew-score{font-size:24px;font-weight:700}
.crew-score span{font-size:13px;color:var(--muted);font-weight:400}
.crew-d{margin-top:10px;display:flex;gap:8px;flex-wrap:wrap}
.pill{font-size:12px;padding:3px 8px;border-radius:20px}
.pill.deny{background:rgba(239,91,110,.15);color:var(--deny)}
.pill.gate{background:rgba(245,183,78,.15);color:var(--gate)}
table{width:100%;border-collapse:collapse;font-size:14px}
th{text-align:left;color:var(--muted);font-size:12px;text-transform:uppercase;
letter-spacing:.05em;padding:8px 10px;border-bottom:1px solid var(--line)}
td{padding:12px 10px;border-bottom:1px solid var(--line);vertical-align:top}
.tag{font-family:ui-monospace,monospace;font-size:11px;background:#1a2030;color:#a9b2c9;
padding:2px 6px;border-radius:5px;margin-right:4px}
.act{color:var(--fg)}.who{color:var(--muted);font-size:12px;margin-top:2px}
.dec{font-weight:700;font-size:13px}.dec.deny{color:var(--deny)}.dec.gate{color:var(--gate)}
.outcome{color:var(--muted);font-size:12px}code{font-family:ui-monospace,monospace;font-size:12px;color:#9fb0d0}
tr.row{cursor:pointer}tr.row:hover td{background:#161c28}
.expand{color:var(--accent);font-size:11px;margin-left:6px}
tr.row.open .expand{color:var(--fg)}
.detail-in{background:#0f131c;border:1px solid var(--line);border-radius:10px;padding:18px 20px;margin:4px 0 8px;display:grid;gap:16px}
.d-sec h4{margin:0 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.owasp-item{font-size:13px;margin-bottom:4px}
.trace{display:grid;gap:6px}
.tr-line{display:grid;grid-template-columns:64px 130px 1fr;gap:12px;align-items:baseline;font-size:13px;padding:5px 0;border-bottom:1px solid #171d2a}
.tr-agent{color:var(--muted);font-family:ui-monospace,monospace;font-size:12px}
.tr-what{color:var(--fg)}
.d-note{color:var(--muted);font-size:12px;margin-top:6px}
.foot{color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:16px;margin-top:32px}
"""

_JS = """
document.querySelectorAll('tr.row').forEach(function(row){
  row.addEventListener('click', function(){
    var d = document.getElementById('d' + row.dataset.id);
    if(!d) return;
    var open = !d.hidden; d.hidden = open; row.classList.toggle('open', !open);
    row.querySelector('.expand').textContent = open ? '\\u25B8 details' : '\\u25BE hide';
  });
});
"""


def render(report: Report) -> str:
    attacks, caught = report.attacks, report.caught
    gaps = len(attacks) - len(caught)
    d = report.decisions
    benign = report.benign
    benign_allowed = sum(f.decision in ("ALLOW", "MONITOR") for f in benign)
    benign_gated = sum(f.decision == "GATE" for f in benign)
    wrongly_denied = sum(f.decision == "DENY" for f in benign)
    verdict_border = "var(--allow)" if gaps == 0 and wrongly_denied == 0 else "var(--deny)"
    verdict = (
        f'<b>{len(caught)} of {len(attacks)} attacks caught</b>'
        + (' · <span style="color:var(--allow)">no gaps</span>' if gaps == 0
           else f' · <span class="gap">{gaps} known gap by design</span>')
        + f'<br><b>{benign_allowed} of {len(benign)} benign near-misses allowed</b>'
        + f' · {benign_gated} sent for human review (GATE, by design)'
        + (' · <span style="color:var(--allow)">0 wrongly denied</span>' if wrongly_denied == 0
           else f' · <span class="gap">{wrongly_denied} wrongly denied</span>')
    )
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Security Assessment</title><style>{_CSS}</style></head><body><div class="wrap">
<h1>AI Security Assessment</h1>
<p class="sub">Build → break → govern across {len(REGISTRY)} agent crews · governed by Yukti</p>
<div class="verdict" style="border-left-color:{verdict_border}">{verdict}<br>
<span class="sub" style="margin:0">Every agent action was judged against its operator-declared
task envelope; anything outside sanctioned scope was denied or escalated (a
governance decision; gateway enforcement is a separate step).</span></div>
<div class="tiles">
<div class="tile attacks"><div class="n">{len(attacks)}</div><div class="l">Attacks run</div></div>
<div class="tile deny"><div class="n">{d.get("DENY", 0)}</div><div class="l">Denied (DENY)</div></div>
<div class="tile gate"><div class="n">{d.get("GATE", 0)}</div><div class="l">Escalated (GATE)</div></div>
<div class="tile allow"><div class="n">{d.get("ALLOW", 0)}</div><div class="l">Clean actions (ALLOW)</div></div>
</div>
<section><h2>Governance outcome: every action judged</h2>{_bar(d)}</section>
<section><h2>OWASP LLM Top 10 (2026) coverage</h2>
<div class="grid">{_coverage(report)}</div></section>
<section><h2>By crew</h2><div class="crews">{_crew_cards(report)}</div></section>
<section><h2>Findings</h2><table>
<thead><tr><th>OWASP</th><th>Crew</th><th>Attack action</th><th>Verdict</th><th>Detection</th></tr></thead>
<tbody>{_findings_table(report)}</tbody></table></section>
<div class="foot">Deterministic and reproducible. Crews and attacks are synthetic; detection is
performed by <a href="https://github.com/Jiten76/yukti" style="color:var(--accent)">Yukti</a>
against each agent's task envelope. Regenerate with <code>python -m ailab.report</code>.</div>
</div><script>{_JS}</script></body></html>"""


def main() -> int:
    report = collect()
    out = Path("report.html")
    out.write_text(render(report))
    caught = len(report.caught)
    print(f"wrote {out}: {caught}/{len(report.attacks)} attacks caught, "
          f"{len(report.findings)} scenarios assessed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
