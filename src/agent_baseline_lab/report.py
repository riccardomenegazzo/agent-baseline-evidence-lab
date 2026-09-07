from __future__ import annotations

import html
import json
from collections import Counter, defaultdict
from pathlib import Path

from .catalog import CONTROL_BY_ID, OUTCOME_NAMES
from .models import RunReport, Status


STATUS_ORDER = [Status.PASS, Status.FAIL, Status.PARTIAL, Status.MANUAL, Status.NOT_APPLICABLE, Status.ERROR]
STATUS_CLASS = {
    Status.PASS: "pass",
    Status.FAIL: "fail",
    Status.PARTIAL: "partial",
    Status.MANUAL: "manual",
    Status.NOT_APPLICABLE: "na",
    Status.ERROR: "error",
}


def write_json_report(report: RunReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8")


def write_html_report(report: RunReport, path: Path) -> None:
    counts = Counter(r.status for r in report.results)
    grouped = defaultdict(list)
    for result in report.results:
        grouped[CONTROL_BY_ID[result.control_id].outcome].append(result)

    total = len(report.results)
    assessed = total - counts[Status.MANUAL] - counts[Status.NOT_APPLICABLE]
    pass_rate = round((counts[Status.PASS] / assessed) * 100) if assessed else 0

    def chip(status: Status) -> str:
        return f'<span class="chip {STATUS_CLASS[status]}">{html.escape(status.value)}</span>'

    sections = []
    for outcome in ("DIS", "CON", "AUT", "OBS", "VAL", "RES"):
        rows = []
        for result in grouped[outcome]:
            control = CONTROL_BY_ID[result.control_id]
            evidence_links = " ".join(
                f'<code title="{html.escape(e.description)}">{html.escape(e.path)}</code>' for e in result.evidence
            ) or "<span class='muted'>No collected evidence</span>"
            details = "".join(f"<li>{html.escape(d)}</li>" for d in result.details)
            rows.append(f"""
            <article class="control">
              <div class="control-head">
                <div><span class="control-id">{control.id}</span><h3>{html.escape(control.title)}</h3></div>
                {chip(result.status)}
              </div>
              <p>{html.escape(result.summary)}</p>
              <div class="meta">Evaluator: <code>{html.escape(result.evaluator)}</code> · Type: {html.escape(control.control_type)}</div>
              {f'<ul>{details}</ul>' if details else ''}
              <div class="evidence"><strong>Evidence</strong><br>{evidence_links}</div>
            </article>""")
        sections.append(f"""
        <section>
          <div class="section-title"><span>{outcome}</span><h2>{OUTCOME_NAMES[outcome]}</h2></div>
          {''.join(rows)}
        </section>""")

    cards = "".join(
        f'<div class="stat"><div class="num">{counts[s]}</div><div>{html.escape(s.value)}</div></div>'
        for s in STATUS_ORDER
    )

    audit = report.metadata.get("docker_audit", {}) if isinstance(report.metadata, dict) else {}
    audit_count = audit.get("records_selected", 0) if isinstance(audit, dict) else 0
    agent_run = report.metadata.get("agent_run", {}) if isinstance(report.metadata, dict) else {}
    agent_run_state = "EXECUTED" if agent_run.get("executed") else "NOT EXECUTED"
    correlation = report.metadata.get("mcp_correlation", {}) if isinstance(report.metadata, dict) else {}
    paired = correlation.get("paired_allowed", 0) if isinstance(correlation, dict) else 0
    allowed = correlation.get("terminal_allowed", 0) if isinstance(correlation, dict) else 0
    unmatched = len(correlation.get("unmatched_allowed", [])) if isinstance(correlation, dict) else 0
    orphan = len(correlation.get("orphan_executions", [])) if isinstance(correlation, dict) else 0
    if paired or allowed or unmatched or orphan:
        correlation_state = "GAPS" if unmatched or orphan else "HEURISTIC COMPLETE"
        correlation_pairs = f"{paired}/{allowed}"
    else:
        correlation_state = "NO MCP PAIRS"
        correlation_pairs = "0/0"
    trace_head = str(report.metadata.get("trace_head_sha256", ""))
    manifest_hash = str(report.metadata.get("evidence_manifest_sha256", ""))
    trust_cards = f"""
      <div class="trust-card"><span>Trace events</span><strong>{html.escape(str(report.metadata.get('trace_event_count', 0)))}</strong></div>
      <div class="trust-card"><span>Trace head</span><code>{html.escape(trace_head[:16] + ('…' if trace_head else ''))}</code></div>
      <div class="trust-card"><span>Manifest</span><code>{html.escape(manifest_hash[:16] + ('…' if manifest_hash else ''))}</code></div>
      <div class="trust-card"><span>Docker audit records</span><strong>{html.escape(str(audit_count))}</strong></div>
      <div class="trust-card"><span>Agent run</span><strong>{html.escape(agent_run_state)}</strong></div>
      <div class="trust-card"><span>MCP eval→execution pairs</span><strong>{html.escape(correlation_pairs)}</strong></div>
      <div class="trust-card"><span>MCP correlation</span><strong>{html.escape(correlation_state)}</strong></div>
    """

    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Agent Baseline Evidence Report · {html.escape(report.run_id)}</title>
<style>
:root{{--ink:#101828;--muted:#667085;--line:#e4e7ec;--panel:#fff;--bg:#f7f9fc;--brand:#1d63ed;--navy:#0b1f3a;}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}
.wrap{{max-width:1120px;margin:auto;padding:48px 24px 80px}} .hero{{background:linear-gradient(135deg,var(--navy),#123d72);color:white;border-radius:20px;padding:34px;box-shadow:0 16px 50px #0b1f3a24}}
.eyebrow{{text-transform:uppercase;letter-spacing:.14em;font-size:12px;opacity:.74}} h1{{font-size:38px;line-height:1.08;margin:8px 0 14px}} .hero p{{max-width:780px;color:#dce7ff}}
.run{{display:flex;gap:22px;flex-wrap:wrap;margin-top:22px;font-size:13px}} .run code{{color:#fff}} .notice{{margin:22px 0;padding:14px 16px;background:#fff8e8;border:1px solid #f5d477;border-radius:12px}}
.trust{{margin:22px 0;background:var(--navy);color:white;border-radius:16px;padding:20px}} .trust h2{{margin:0 0 14px}} .trust-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}} .trust-card{{background:#ffffff12;border:1px solid #ffffff24;border-radius:12px;padding:14px;min-width:0}} .trust-card span{{display:block;color:#bcd0ea;font-size:12px;margin-bottom:6px}} .trust-card code{{display:block;background:#ffffff12;color:white;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}} .trust-card strong{{font-size:20px}}
.stats{{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin:22px 0}} .stat{{background:white;border:1px solid var(--line);border-radius:14px;padding:17px;text-align:center}} .num{{font-size:26px;font-weight:800}} .score{{background:white;border:1px solid var(--line);border-radius:14px;padding:20px;margin-bottom:34px}} .bar{{height:9px;background:#edf1f7;border-radius:99px;overflow:hidden}} .bar>span{{display:block;height:100%;background:var(--brand);width:{pass_rate}%}}
.section-title{{display:flex;align-items:center;gap:11px;margin:42px 0 15px}} .section-title span{{background:var(--navy);color:white;border-radius:8px;padding:5px 8px;font:700 12px ui-monospace,SFMono-Regular,monospace}} h2{{margin:0}} .control{{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:20px;margin:10px 0}} .control-head{{display:flex;justify-content:space-between;gap:18px;align-items:start}} .control-head>div{{display:flex;gap:11px;align-items:baseline}} .control h3{{font-size:16px;margin:0}} .control-id{{font:700 12px ui-monospace,SFMono-Regular,monospace;color:var(--brand)}} .chip{{font:800 11px ui-monospace,SFMono-Regular,monospace;padding:5px 8px;border-radius:999px;white-space:nowrap}} .pass{{background:#ecfdf3;color:#067647}} .fail,.error{{background:#fef3f2;color:#b42318}} .partial{{background:#fff6ed;color:#b54708}} .manual{{background:#f2f4f7;color:#344054}} .na{{background:#eef4ff;color:#3538cd}} .meta,.muted{{color:var(--muted);font-size:13px}} .evidence{{margin-top:14px;padding-top:12px;border-top:1px solid var(--line);font-size:12px}} code{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:#f2f4f7;padding:2px 5px;border-radius:5px;overflow-wrap:anywhere}} footer{{margin-top:42px;color:var(--muted);font-size:12px}}
@media(max-width:800px){{.stats{{grid-template-columns:repeat(2,1fr)}}.trust-grid{{grid-template-columns:repeat(2,1fr)}}h1{{font-size:30px}}}}
</style></head><body><div class="wrap">
<header class="hero"><div class="eyebrow">Agent Baseline Evidence Lab</div><h1>Implementation Assessment</h1><p>Evidence-driven assessment against the public Agent Baseline draft. Results describe this run only and are not a certification or an official conformance claim.</p><div class="run"><span>Run <code>{html.escape(report.run_id)}</code></span><span>Baseline <code>{html.escape(report.baseline_version)}</code></span><span>Started <code>{html.escape(report.started_at)}</code></span></div></header>
<div class="notice"><strong>Draft-aware:</strong> the Agent Baseline is under public review. Pin the upstream source and review drift before presenting results.</div>
<section class="trust"><h2>Evidence trust chain</h2><div class="trust-grid">{trust_cards}</div><p style="margin:12px 0 0;color:#bcd0ea;font-size:12px">The trace is SHA-256 hash-chained and the evidence directory is SHA-256 manifested. MCP evaluation→execution pairing is explicitly heuristic until the source schema exposes a documented per-action correlation identifier. For stronger tamper evidence, pin the reported manifest or trace-head hash outside the bundle.</p></section>
<div class="stats">{cards}</div><div class="score"><strong>Observed automated pass rate: {pass_rate}%</strong><p class="muted">PASS divided by controls with a non-MANUAL, non-N/A result. This is deliberately not called a compliance score.</p><div class="bar"><span></span></div></div>
{''.join(sections)}
<footer>Generated by Agent Baseline Evidence Lab · Community project · Not affiliated with or endorsed by Docker, Snyk, Keycard, or the Agent Baseline maintainers.</footer>
</div></body></html>"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(doc, encoding="utf-8")
