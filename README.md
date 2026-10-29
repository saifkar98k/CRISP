# CRISP 2.0 — Cyber Risk Intelligence & Security Posture Platform
### Production Cybersecurity Architecture, Supervised Multi-Agent Swarm & Closed-Loop Remediation

[![Tests](https://img.shields.io/badge/Unit%20%26%20E2E%20Tests-180%20Passed-emerald.svg)](tests/)
[![Risk Engine Throughput](https://img.shields.io/badge/Risk%20Engine-36%2C000%2B%20evals%2Fsec-cyan.svg)](scripts/run_benchmarks.py)
[![Architecture](https://img.shields.io/badge/UI%20Architecture-Strict%205--Option%20Executive-blue.svg)](src/App.tsx)
[![Compliance](https://img.shields.io/badge/Compliance-NIST%20CSF%202.0-indigo.svg)](src/engines/complianceEngine.ts)
[![Data Provenance](https://img.shields.io/badge/Data-1%2C750%2B%20Real%20NVD%20CVEs-green.svg)](src/data/)

---

## 1. Project Purpose & Scope

CRISP is an enterprise-grade operational cyber risk intelligence and continuous assessment platform that bridges raw threat telemetry and executive risk decision-making. It unifies **live public vulnerability feeds** (NIST NVD API 2.0 & CISA Known Exploited Vulnerabilities catalog) with enterprise asset telemetry and historical incident datasets within an embedded SQLite datastore, evaluating multi-factor risk scores and assessing organizational posture against the **NIST Cybersecurity Framework (CSF) 2.0**.

### Key Differentiators:
1. **Zero Data Fabrication**: Incorporates 1,753 real NIST NVD CVEs and active CISA KEV entries with real CVSS 3.1 base vectors. Synthetic simulation data is strictly and explicitly labeled as `[SIMULATION MODE]`.
2. **Deterministic Correlation Graph**: Triangulates telemetry events, vulnerability records, and enterprise assets into persistent findings without non-deterministic hallucinations.
3. **Supervised Multi-Agent LangGraph Swarm**: Coordinates 7 specialized domain agents (Threat Intel, Vuln Intel, Asset Risk, Compliance, Evidence, Verification, Remediation) under an Orchestrator supervisor with strict read-only safety bounds.
4. **Closed-Loop Remediation with Scan Evidence**: Enforces authentic verification evidence (e.g. Tenable Nessus scan or SBOM package version) before resolving findings, automatically recalculating residual cyber risk.
5. **Strict 5-Option Executive Frontend**: Completely redesigned navigation eliminating cognitive fatigue: **Overview**, **Live Monitoring**, **Security Intelligence**, **AI Swarm**, and **Data & Administration**.

---

## 2. End-to-End System Architecture

```text
               EXTERNAL FEEDS & TELEMETRY
   ┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────────┐
   │   NIST NVD 2.0 API   │  │   CISA KEV Feed      │  │ CIC-IDS2017 / Syslog │
   │ (CVSS, CWE, CPE, Ref)│  │(Active Weaponization)│  │(Historical Telemetry)│
   └──────────┬───────────┘  └──────────┬───────────┘  └──────────┬───────────┘
              │                         │                         │
              ▼                         ▼                         ▼
   ┌──────────────────────────────────────────────────────────────────────────┐
   │                         DATA INGESTION & NORMALIZERS                     │
   │  - Normalizes heterogeneous feeds into immutable schemas                 │
   │  - Bounded Event Queue (Capacity: 5000) with Dead-Letter Queue (DLQ)     │
   │  - Zero-Fabrication provenance tagging: REAL vs HISTORICAL vs SYNTHETIC  │
   └────────────────────────────────────┬─────────────────────────────────────┘
                                        │
                                        ▼
   ┌──────────────────────────────────────────────────────────────────────────┐
   │                         SQLITE PERSISTENCE LAYER                         │
   │  - Master native SQLite backend (data/crisp.db) with WAL mode            │
   │  - In-browser WebAssembly SQLite (sql.js) for instantaneous UI filtering │
   │  - Immutable audit logs protected by SQLite non-repudiation triggers     │
   └────────────────────────────────────┬─────────────────────────────────────┘
                                        │
                                        ▼
   ┌──────────────────────────────────────────────────────────────────────────┐
   │                       SECURITY CORRELATION ENGINE                        │
   │  - Triangulates incoming events with vulnerable assets and CVE records   │
   │  - Outputs deduplicated, persistent Security Findings                    │
   └──────────────────┬───────────────────────────────────────┬───────────────┘
                      │                                       │
                      ▼                                       ▼
   ┌─────────────────────────────────────┐ ┌──────────────────────────────────┐
   │       CRISP MULTI-FACTOR RISK       │ │  SUPERVISED MULTI-AGENT SWARM    │
   │  - CVSS 3.1 Severity (30 pts)       │ │  - Orchestrator (Supervisor)     │
   │  - Active CISA KEV Exploitation(15) │ │  - Threat & Vulnerability Agents │
   │  - Asset Criticality Priority (15)  │ │  - Asset Risk & Compliance Agents│
   │  - Perimeter Network Exposure (15)  │ │  - Evidence Agent (ChromaDB RAG) │
   │  - Attack Frequency (15 pts)        │ │  - Verification (Contradictions) │
   │  - Event Recency Freshness (10 pts) │ │  - Remediation Action Agent      │
   └──────────────────┬──────────────────┘ └──────────────────┬───────────────┘
                      │                                       │
                      ▼                                       ▼
   ┌──────────────────────────────────────────────────────────────────────────┐
   │                     CLOSED-LOOP REMEDIATION ENGINE                       │
   │  - Structured lifecycle: OPEN -> PLANNED -> APPROVAL -> VERIFIED         │
   │  - Mandatory verification scan evidence (Tenable/Nessus / SBOM)          │
   │  - Dynamic post-remediation risk recalculation (e.g. 88.5 -> 41.5)       │
   └────────────────────────────────────┬─────────────────────────────────────┘
                                        │
                                        ▼
   ┌──────────────────────────────────────────────────────────────────────────┐
   │              CRISP 2.0 UNIFIED 5-OPTION OPERATIONS DASHBOARD             │
   │  1. Overview  2. Live Monitoring  3. Security Intel  4. AI Swarm  5. Data│
   └──────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Technology Stack

- **Frontend**: React 19 SPA, TypeScript, Tailwind CSS, Lucide Icons, Vite.
- **Embedded Database**: WebAssembly SQLite (`sql.js`) client-side + Native SQLite3 (`data/crisp.db`) server-side.
- **Backend API Server**: Node.js 22, Express, Child Process IPC bridge with Python 3.10.
- **Agentic AI & Orchestration**: Python 3.10, LangGraph-inspired Supervised State Graph, Groq Cloud API (`llama-3.3-70b-versatile`), and deterministic offline fallback reasoning engine.
- **Vector Knowledge Base**: ChromaDB with multi-collection semantic embeddings (Vulnerabilities, NIST controls, Assets, Correlated findings, Incidents).
- **Standards & Baselines**: NIST Cybersecurity Framework (CSF) 2.0, NIST NVD 2.0, CISA KEV, MITRE CVE / CWE, CVSS v3.1.

---

## 4. Data Sources & Provenance Badges

CRISP maintains strict data provenance so security examiners never mistake test data for live threats:

| Badge / Category | Provenance Description |
| :--- | :--- |
| **`REAL EXTERNAL DATA`** | Ingested directly from NIST NVD API 2.0 and CISA Known Exploited Vulnerabilities catalog. |
| **`HISTORICAL PUBLIC DATASET`** | Collected from academic benchmarks (e.g. Canadian Institute for Cybersecurity **CIC-IDS2017**). |
| **`SYNTHETIC DEMO DATA`** | Clearly labeled `[SIMULATION MODE]` generated strictly for controlled viva demonstrations. |
| **`DERIVED RISK SCORE`** | Algorithmically computed by the CRISP quantitative multi-factor risk engine. |

---

## 5. Supervised Multi-Agent Swarm (7 Roles)

CRISP implements 7 specialized domain agents operating under a central supervisor:

1. **OrchestratorAgent**: Analyzes the analyst query, classifies workflow (CVE, Asset, Telemetry, Finding, General), formulates execution plan, and synthesizes executive briefings.
2. **ThreatIntelligenceAgent**: Analyzes security telemetry, detects attack categories, investigates IPs, and attributes events to enterprise assets.
3. **VulnerabilityIntelligenceAgent**: Queries NVD CVE metadata, CVSS 3.1 metrics, CWE weaknesses, and active CISA KEV weaponization.
4. **AssetRiskAgent**: Inspects enterprise asset inventory, calculates asset criticality, and assesses external perimeter exposure.
5. **ComplianceAgent**: Maps security deficiencies against the 6 NIST CSF 2.0 functions (GOVERN, IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER).
6. **EvidenceAgent**: Queries ChromaDB vector collections for semantically relevant documentation and official vendor references.
7. **VerificationAgent**: Anti-hallucination guardrail that cross-examines findings, isolates confirmed facts from unverified hypotheses, flags contradictions, and calculates factual confidence scores.
8. **RemediationAgent**: Formulates authoritative vendor patching steps, mitigation actions, and rollback procedures.

### Safety & Guardrails:
- **Strictly Read-Only Execution**: Agents operate in an advisory capacity; arbitrary shell and SQL execution are disabled.
- **Prompt Injection Defense**: Evaluates inputs with `detect_prompt_injection()`. Injected override commands are neutralized and flagged in passive evidence.

---

## 6. The CRISP Multi-Factor Risk Formula

The composite risk score ($0.0 - 100.0$) is calculated through an explainable multi-factor formula:

$$\text{Final Risk Score} = \min(100.0, \; S_{\text{CVSS}} + S_{\text{KEV}} + S_{\text{Criticality}} + S_{\text{Exposure}} + S_{\text{Frequency}} + S_{\text{Recency}})$$

- **CVSS Score (Max 30 pts)**: Base technical vulnerability severity ($\frac{\text{CVSS}}{10.0} \times 30.0$).
- **Threat & CISA KEV (Max 15 pts)**: Confirmed weaponization in CISA KEV ($15.0$ pts) or event telemetry severity ($2.5 - 10.0$ pts).
- **Asset Criticality (Max 15 pts)**: Mission-Critical ($14.0$), High ($10.0$), Medium ($6.0$), Low ($2.0$).
- **Perimeter Exposure (Max 15 pts)**: Public Internet ($12.0 - 15.0$), DMZ ($8.0$), Internal ($4.0$), Air-Gapped ($1.0$).
- **Attack Frequency (Max 15 pts)**: $\ge 10$ incidents ($15.0$), 5–9 ($10.0$), 2–4 ($5.0$), 1 ($2.0$).
- **Event Recency (Max 10 pts)**: $<1\text{h}$ ($10.0$), $<24\text{h}$ ($8.0$), $<7\text{d}$ ($4.0$), $>7\text{d}$ ($0.0$).

---

## 7. Performance & Observability Benchmarks

Measured via `python3 scripts/run_benchmarks.py`:

| Component / Metric | Measured Performance | Operational Context |
| :--- | :--- | :--- |
| **Risk Engine Evaluations** | **36,658 evaluations / sec** | Raw multi-factor risk calculation latency: ~27 µs |
| **Telemetry Ingestion** | **80,513 events / sec** | CEF/Syslog normalization & queue intake |
| **Vulnerabilities Query** | **1.38 ms** | Indexed lookup over 1,750+ SQLite records |
| **Correlated Findings Query** | **0.11 ms** | Primary key and composite index retrieval |
| **Security Events Query** | **0.15 ms** | Telemetry table retrieval |
| **Full Swarm Investigation** | **666.71 ms** | Concurrent execution across 5 domain agents + verification |
| **Agent Success Rate** | **100.0%** | Zero unhandled agent exceptions |
| **Investigation Completeness**| **100.0%** | Comprehensive multi-domain evidence coverage |

---

## 8. Required Test Scenarios (16 Reproducible Tests)

CRISP includes reproducible unit and integration tests for all 16 required edge cases in `tests/test_final_e2e_scenarios.py`:

```bash
python3 -m unittest tests/test_final_e2e_scenarios.py
```

1. **Scenario 1**: Critical vulnerability with confirmed CISA KEV evidence (Log4Shell CVE-2021-44228).
2. **Scenario 2**: High CVSS vulnerability without KEV match.
3. **Scenario 3**: Critical asset with suspicious security events (Risk score escalation $\ge 70.0$).
4. **Scenario 4**: Incomplete asset attribution (unmapped IP handling).
5. **Scenario 5**: Conflicting or missing evidence verification (Confidence dropped to $45\%$).
6. **Scenario 6**: One swarm agent failing while other agents succeed (Isolated execution).
7. **Scenario 7**: Groq API unavailable (Graceful deterministic fallback).
8. **Scenario 8**: ChromaDB unavailable (Graceful keyword retrieval fallback).
9. **Scenario 9**: NVD or CISA synchronization failure (Structured error reporting).
10. **Scenario 10**: Unauthorized access enforcement (`403 Forbidden` for VIEWER/GUEST).
11. **Scenario 11**: Malicious instructions embedded in retrieved content (Prompt injection defense).
12. **Scenario 12**: Invalid or duplicate security event filtering.
13. **Scenario 13**: Remediation completed without verification evidence (Strictly blocked).
14. **Scenario 14**: Successful remediation followed by an updated scan (Risk reduction $88.5 \to 41.5$).
15. **Scenario 15**: Empty database and first-run initialization.
16. **Scenario 16**: Restart and recovery after a temporary failure.

**Full Test Suite Execution**:
```bash
python3 -m unittest discover tests
# Result: Ran 180 tests in 14.0s - OK (100% Passed)
```

---

## 9. Installation & Startup Commands

### Prerequisites
- **Node.js**: v20 or v22 (npm v10+)
- **Python**: 3.10+ (standard installation; required for backend multi-agent swarm & correlation)
- **SQLite3**: Built-in with Python and WebAssembly in browser (no separate database server required)

### Windows Quick Start:
Double-click `start-local.bat` in the project root, or execute:
```cmd
start-local.bat
```
The script will verify Node.js and Python, install dependencies if missing, ensure WebAssembly binaries are in place, and boot the server at `http://localhost:3000`.

### Cross-Platform Manual Launch (Windows PowerShell / macOS / Linux):

```bash
# 1. Install Node.js dependencies
npm install

# 2. Run Database Schema Migrations & Verifications
# On Windows: python scripts/migrate.py
python3 scripts/migrate.py

# 3. Verify TypeScript build
npm run build

# 4. Start CRISP Full-Stack Development Server (Express API + Vite SPA)
npm run dev
# The platform is accessible at: http://localhost:3000
```

### Health & Readiness Check:
Verify that the full-stack server is responsive:
```bash
# Browser or curl:
curl http://localhost:3000/api/health
# Response: {"status":"ok","version":"2.2.0",...}
```

---

## 10. Final-Year 8–12 Minute Demonstration Guide

Use the built-in **"Viva Demo"** button located in the top navigation bar to launch the interactive 10-stage walkthrough:

1. **Stage 1: Executive Posture & Risk Overview** (Navigate to `Overview`) — Show executive KPI cards, 0–100 risk score, and asset tier breakdown.
2. **Stage 2: Real NVD Vulnerability Intelligence** (Navigate to `Security Intelligence` -> `Vulnerabilities`) — Demonstrate 1,753 real CVEs, CVSS 3.1 vectors, and search.
3. **Stage 3: CISA KEV Weaponization Status** (Navigate to `Security Intelligence` -> `CISA KEV`) — Show BOD 22-01 active exploitation catalog and overdue alerts.
4. **Stage 4: Historical Telemetry & Controlled Simulator** (Navigate to `Live Monitoring`) — Show CIC-IDS2017 benchmark data and toggle the `[SIMULATION MODE]` generator.
5. **Stage 5: Multi-Entity Finding Correlation** (Navigate to `Security Intelligence` -> `Findings`) — Show triangulation of Event + CVE + Asset.
6. **Stage 6: Explainable Multi-Factor Cyber Risk Score** (Navigate to `Security Intelligence` -> `Cyber Risk Matrix`) — Walk through the transparent 6-factor mathematical model.
7. **Stage 7: Autonomous Multi-Agent Swarm** (Navigate to `AI Swarm`) — Execute a live investigation query and observe real-time agent coordination.
8. **Stage 8: ChromaDB Vector Evidence & Verification** — Inspect ChromaDB semantic vector retrieval and contradiction detection.
9. **Stage 9: NIST CSF 2.0 Compliance Radar** (Navigate to `Security Intelligence` -> `NIST CSF 2.0`) — Demonstrate the 6 Core Functions and gap tracking.
10. **Stage 10: Closed-Loop Remediation & Dynamic Recalculation** (Navigate to `Security Intelligence` -> `Remediation Queue`) — Demonstrate submitting Nessus scan evidence and observing dynamic risk reduction.

---

## 11. Environment Configuration & External API Keys

### Zero Mandatory Variables for Local Execution:
CRISP requires **no external API keys or cloud services** for local development. Out of the box, it initializes the WebAssembly SQLite database, hydrates real CVE catalog records, calculates NIST CSF compliance, and executes multi-agent investigations using built-in deterministic heuristic reasoning.

### Optional Integrations:

| Integration | Environment Variable | Acquisition Link & Notes | Behavior if Omitted |
| :--- | :--- | :--- | :--- |
| **Groq Cloud LLM** | `GROQ_API_KEY` | [Obtain a Groq API Key](https://console.groq.com/keys) | AI Swarm gracefully switches to deterministic offline heuristic reasoning without crashing or hallucinating. |
| **NIST NVD API 2.0** | `NVD_API_KEY` | [Request an NVD API Key](https://nvd.nist.gov/developers/request-an-api-key) | Connects via NIST's unauthenticated public tier (5 req / 30s) or falls back to curated local CVE snapshot. |
| **Splunk SIEM** | `SPLUNK_HEC_URL`, `SPLUNK_HEC_TOKEN` | Enterprise Splunk HTTP Event Collector | Ingestion hub marks Splunk unconfigured and falls back to local synthetic telemetry. |
| **CrowdStrike Falcon** | `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET` | Falcon Cloud API Client Credentials | Ingestion hub marks CrowdStrike unconfigured and falls back to local synthetic telemetry. |

---

## 12. Windows 10/11 PowerShell Step-by-Step Guide

```powershell
# 1. Verify installed versions
node --version       # Expected: v20.x or v22.x
npm --version        # Expected: v10.x+
python --version     # Expected: Python 3.10+

# 2. (Optional) Create and activate a Python virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# 3. Install Node.js frontend and backend dependencies
npm install

# 4. Create local configuration file from template (never overwrites existing .env)
if (!(Test-Path .env)) { Copy-Item .env.example .env }

# 5. Initialize SQLite Database Schema & Seed Data
python scripts/migrate.py

# 6. Run verification test suite
npm test

# 7. Start the Full-Stack Platform (Express Backend + Vite SPA)
npm run dev

# Open in your browser: http://localhost:3000
```

---

## 13. Troubleshooting & FAQ

- **Resolving the 15% "Initializing WebAssembly SQLite Database..." Hang**:
  - *Cause*: A byte-level mismatch between installed `sql.js` (1.14.2) and `/public/sql-wasm.wasm` previously caused an unhandled Emscripten exception (`TypeError: fd.O is not a function`).
  - *Fix*: The repository now contains byte-identical binaries (`sql-wasm.wasm` and `sql-wasm-browser.wasm`, 685,235 bytes) and wraps initialization in a 15-second bounded timeout with mutex concurrency locking.
  - *Recovery*: If ever corrupted, execute `npm run test:lifecycle` to verify byte parity and instantiate the engine.
- **Database empty on first clone?**
  Run `python scripts/migrate.py` (Windows) or `python3 scripts/migrate.py` (Linux/macOS).
- **Groq API Rate Limits or Missing Key?**
  CRISP includes automatic deterministic fallback. If `GROQ_API_KEY` is omitted or throttled, all investigations and remediation assistance continue running seamlessly.
- **Port Conflict on 3000?**
  The platform is configured for port 3000 (`0.0.0.0:3000`). If in use, stop conflicting processes or specify `PORT=3001 npm run dev`.

---

## 14. Known Limitations & Production Roadmap

- **Clustered Database**: Current implementation uses embedded native SQLite; enterprise scale-out can migrate to Cloud SQL (PostgreSQL) using the provisioned adapter schemas.
- **Active Scanners**: Current verification accepts Nessus/SBOM JSON payloads; production roadmap includes direct Tenable.io and Qualys API connectors.
- **Ticketing Integration**: Future work includes bidirectional synchronization with ServiceNow SecOps and Jira Service Management.
