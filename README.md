# imsatya07

Agentic AI prototypes for IT/OT cybersecurity — autonomous systems that triage incidents, correlate exposures, and reason across hybrid enterprise environments.

Built with Claude Opus 4.7, the Anthropic SDK tool-runner, and adaptive thinking. Both projects demonstrate end-to-end agent design: deterministic primitives handle the math and the I/O, the LLM does the judgment work.

---

## Featured projects

Three complementary prototypes spanning the agentic-security product lifecycle:

| Project | Pillar | Surface | The move |
|---|---|---|---|
| [threat-radar](./threat-radar) | Threat intelligence | MCP server + CLI | Turn unstructured advisories into structured exposure assessments |
| [exposure-radar](./exposure-radar) | Exposure management | FastAPI + HTML dashboard | Rank every (asset, CVE) pair by blended priority |
| [my-app](./my-app) | Detection & response | CLI agent | Triage a workspace of logs/configs into an incident report |

### [threat-radar](./threat-radar) — Agentic threat-intelligence correlator (MCP server)

An **MCP server** that any agentic client (Claude Desktop, Cursor, or your own agent) can plug into. Claude reads unstructured threat advisories — CISA alerts, vendor blogs, CERT notices — extracts structured intel (CVEs, IOCs, affected products) via `messages.parse()`, and correlates it against an IT/OT asset inventory.

**What it shows**

- **MCP-native integration.** Built on `FastMCP` with stdio transport, exposing `list_inventory`, `ingest_advisory`, and `assess_exposure` as first-class MCP tools. Any modern agent host can consume it — exactly the integration surface agentic security platforms ship with.
- **Structured outputs over free-form prose.** Uses `client.messages.parse()` with Pydantic schemas (`ExtractedIntel`, `ExposureAssessment`) instead of parsing markdown. The LLM is a validated extractor, not a chatty assistant — production-ready design.
- **Clean separation of concerns.** The LLM does the unstructured-to-structured translation; a pure-function correlator handles the asset-matching and crown-jewel/OT-aware recommendations. 5 unit tests cover the correlator deterministically, no LLM mocking required.

**Stack:** Python · `FastMCP` · Pydantic · Anthropic SDK `messages.parse` with structured outputs · prompt caching

### [exposure-radar](./exposure-radar) — Agentic CVE-to-asset exposure correlator

A FastAPI service where a Claude agent investigates a mock enterprise inventory, correlates installed software against a CVE feed, and returns a prioritized exposure report ready for a SOC manager to act on this morning.

**What it shows**

- **Hybrid agent architecture.** A pure-function scorer blends `CVSS × asset criticality × internet-exposure × CISA KEV` multipliers deterministically; the LLM owns the triage narrative and OT-aware recommendations. The right division of labor for production agentic security tools — reproducible where it needs to be, intelligent where it needs to be.
- **IT/OT depth.** Crown-jewel SCADA HMIs, Modbus PLC stacks, OT-specific patching constraints. The sample inventory surfaces Log4Shell on a Windows historian and EternalBlue on a Windows 7 SCADA HMI — exactly the findings OT security teams lose sleep over.
- **Full product surface.** Structured REST endpoints (`POST /scan`, `GET /correlate`, `/assets`, `/cves`), a zero-dependency HTML dashboard for demos, a `uvicorn` CLI entry point, Pydantic models as API contracts, and 7 unit tests pinning the scoring logic.

**Stack:** Python · FastAPI · Pydantic · Anthropic SDK `tool_runner` · `@beta_tool` decorators · adaptive thinking · prompt caching

### [my-app](./my-app) — Agentic security-triage CLI

A command-line tool that drops a Claude agent into a workspace of logs and configs, discovers artifacts, runs heuristic scanners, correlates findings across files, and produces a markdown incident report.

**What it shows**

- **Full agent loop.** The agent picks its own tools — lists the workspace, reads raw files, runs SSH brute-force and permissive-firewall detectors, then decides when it has enough evidence to stop and write the report.
- **Security engineering rigor.** Pure-function detectors live in their own module with deterministic unit tests. Every file access is sandboxed to a workspace root to block path traversal. No mocks needed to test the core.
- **Modern Anthropic SDK patterns.** `@beta_tool` decorated tool functions, a prompt-cached system prompt, adaptive thinking on Opus 4.7 — the current state of the art for Claude agents.

**Stack:** Python · Anthropic SDK `tool_runner` · argparse · pytest

---

## Running them locally

Both projects need `ANTHROPIC_API_KEY` set for the agent endpoints. The deterministic paths (`/correlate`, the detector unit tests) run without one.

```bash
# threat-radar — MCP server + CLI for advisory ingestion
cd threat-radar
pip install -e ".[dev]"
pytest                      # 5 tests, no API key needed
threat-radar                # process every file in data/advisories/
threat-radar-mcp            # launch as MCP server (stdio) for Claude Desktop etc.

# exposure-radar — web service + dashboard at http://127.0.0.1:8000
cd exposure-radar
pip install -e ".[dev]"
pytest                      # 7 tests, no API key needed
exposure-radar --reload

# my-app — CLI triage over a workspace of logs/configs
cd my-app
pip install -e ".[dev]"
pytest                      # 6 tests, no API key needed
my-app sample_data
```
