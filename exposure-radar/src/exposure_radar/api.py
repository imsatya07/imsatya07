"""FastAPI surface for the exposure-radar agent."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from . import agent, correlator, data
from .models import Asset, CVE, ScanReport


app = FastAPI(
    title="exposure-radar",
    description="Agentic CVE-to-asset exposure correlator powered by Claude.",
    version="0.1.0",
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/assets", response_model=list[Asset])
def list_assets() -> list[Asset]:
    return data.load_assets()


@app.get("/cves", response_model=list[CVE])
def list_cves() -> list[CVE]:
    return data.load_cves()


@app.get("/correlate", response_model=ScanReport)
def correlate_only() -> ScanReport:
    """Deterministic correlation only — no LLM call. Fast, cheap, repeatable."""
    findings = correlator.correlate(data.load_assets(), data.load_cves())
    return ScanReport(summary=agent._summarize(findings), findings=findings)


@app.post("/scan", response_model=ScanReport)
def scan() -> ScanReport:
    """Full agentic scan — Claude investigates and writes triage notes."""
    return agent.run_scan()


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    return _DASHBOARD_HTML


_DASHBOARD_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>exposure-radar</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 960px;
         margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }
  h1 { margin-bottom: 0.25rem; }
  .sub { color: #666; margin-bottom: 1.5rem; }
  button { background: #0a0a0a; color: #fff; border: 0; padding: 0.6rem 1.1rem;
           border-radius: 6px; cursor: pointer; font-size: 0.95rem; }
  button:disabled { opacity: 0.5; cursor: wait; }
  table { width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: 0.9rem; }
  th, td { text-align: left; padding: 0.55rem 0.7rem; border-bottom: 1px solid #eee; }
  th { background: #fafafa; font-weight: 600; }
  .sev-critical { color: #b00020; font-weight: 600; }
  .sev-high { color: #c64a00; font-weight: 600; }
  .sev-medium { color: #8a6d00; }
  .sev-low { color: #4a7c59; }
  pre { background: #fafafa; padding: 1rem; border-radius: 6px;
        white-space: pre-wrap; font-size: 0.85rem; }
</style></head>
<body>
  <h1>exposure-radar</h1>
  <p class="sub">Agentic CVE-to-asset exposure correlator. Click scan to run Claude.</p>
  <button id="scan">Run agentic scan</button>
  <button id="fast">Fast correlate (no LLM)</button>
  <p id="status"></p>
  <h2>Findings</h2>
  <table id="t">
    <thead><tr><th>Score</th><th>Severity</th><th>Asset</th><th>CVE</th><th>Recommendation</th></tr></thead>
    <tbody></tbody>
  </table>
  <h2>Triage notes</h2>
  <pre id="notes">(none yet — run a scan)</pre>
<script>
  async function run(path, btn) {
    const allButtons = document.querySelectorAll('button');
    allButtons.forEach(b => b.disabled = true);
    document.getElementById('status').textContent = 'Running...';
    try {
      const r = await fetch(path, { method: path === '/scan' ? 'POST' : 'GET' });
      const data = await r.json();
      document.getElementById('status').textContent = data.summary;
      const tbody = document.querySelector('#t tbody');
      tbody.innerHTML = '';
      for (const f of data.findings) {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${f.priority_score}</td>
          <td class="sev-${f.severity}">${f.severity}</td>
          <td>${f.asset_hostname}</td>
          <td>${f.cve_id}</td>
          <td>${f.recommended_action}</td>`;
        tbody.appendChild(tr);
      }
      document.getElementById('notes').textContent = data.triage_notes || '(no triage notes)';
    } catch (e) {
      document.getElementById('status').textContent = 'Error: ' + e.message;
    } finally {
      allButtons.forEach(b => b.disabled = false);
    }
  }
  document.getElementById('scan').onclick = () => run('/scan');
  document.getElementById('fast').onclick = () => run('/correlate');
</script>
</body></html>"""
