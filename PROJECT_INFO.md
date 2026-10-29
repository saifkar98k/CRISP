# CRISP — Cyber Risk Intelligence and Security Posture
## Project Information, Architecture & Comprehensive System Documentation

---

### Academic & Institutional Metadata

- **Project Title:** Cyber Risk Intelligence and Security Posture (CRISP): From Compliance to Threat-Informed Intelligence
- **Domain:** Cybersecurity · Artificial Intelligence / Large Language Models (LLMs) · Security Operations Center (SOC) Engineering
- **Project Team:**
  - **Yasir Khan** — *Project Lead & Frontend/Visualization* (UI Layout, Dashboard Architecture, Chat Interface UI)
  - **Tanaya Mulik** — *AI and LLM Integration* (OpenAI/Groq API, LangChain/LangGraph, RAG Pipeline)
  - **Mohammad Saif Khan** — *Backend and Data Engine* (Mock Log Datasets, NIST/CVE Database, Correlation Engine)
- **Department Review Committee:**
  - **Er. Ghazala Khan** — *Co-Guide*
  - **Er. Pragati Pal** — *Assistant Professor*
  - **Er. Zafar Khan** — *Assistant Professor*
  - **Er. Samana Jafri** — *Head of Department*
  - **Dr. Shafi Pathan** — *Principal*

---

## 1. Problem Statement & Background

Modern enterprise cybersecurity operations face two systemic points of friction:

1. **The Compliance vs. Threat Reality Divide:** Organizations often treat cybersecurity compliance (e.g., NIST CSF, ISO 27001) as a static, periodic checkbox audit rather than an operational defense. An organization can be 90% "compliant" on paper while maintaining critical unpatched vulnerabilities actively weaponized in the wild.
2. **Alert Fatigue & Disconnected Telemetry:** Security Operations Centers (SOCs) are overwhelmed with millions of disconnected event logs from firewalls, intrusion detection systems (IDS), and endpoint monitors. Analysts must manually cross-reference telemetry with vulnerability databases (NIST NVD), threat catalogs (CISA KEV), and internal asset criticality to determine actual enterprise risk.

**Problem Statement:**
> *To build CRISP, a unified web platform that bridges compliance tracking with real-time threat-informed intelligence, dynamic quantitative risk scoring, automated remediation guidance, and an explainable AI-driven multi-agent investigation swarm.*

---

## 2. Project Objectives & Statement of Purpose (SOP) Alignment

As established in the academic Statement of Purpose, the project is structured across two phases:

### Semester 7 Milestones:
- **Objective 7.1 — Interactive Security Dashboard:** Develop a real-time web dashboard for visualizing high-level organizational security posture, asset risk distributions, and analyst threat event logs.
- **Objective 7.2 — Synthetic Data Generation Pipeline:** Implement a reproducible data pipeline mapped directly to NIST framework controls and National Vulnerability Database (CVE) standards.
- **Objective 7.3 — Dynamic Risk & Compliance Calculation Engines:** Build algorithmic Python engines to calculate explainable multi-factor cyber risk scores and exact numerical compliance percentages across all NIST CSF Core Functions.

### Semester 8 Milestones:
- **Objective 8.1 — AI Security Assistant with RAG:** Develop an evidence-grounded AI assistant utilizing LLMs, LangChain/LangGraph, and ChromaDB vector retrieval for natural-language security querying.
- **Objective 8.2 — Automated Remediation Guidance:** Complete an automated closed-loop remediation engine that delivers prioritized, step-by-step patching guidance tied to verified findings and dynamically computes post-remediation risk reduction.
- **Capstone Advanced Extension — Supervised Multi-Agent Swarm:** Implement a coordinated 7-agent supervisory swarm with strict anti-hallucination verification, deterministic fallbacks, and zero synthetic fabrications.

---

## 3. System Prerequisites & Hardware Specifications

CRISP is engineered to run locally on developer workstations (Windows 10/11, macOS, Linux) with **zero mandatory external cloud dependencies**.

### Minimum Hardware:
- **CPU:** Dual-core 2.0 GHz or higher (x86_64 or ARM64 / Apple Silicon)
- **RAM:** 4 GB minimum (8 GB recommended for concurrent ChromaDB embeddings)
- **Disk:** 500 MB free storage for SQLite databases and bundled historical datasets

### Minimum Software:
- **Node.js:** v20.x or v22.x LTS (with `npm` v10+)
- **Python:** v3.10 or higher (standard installation with `sqlite3` built-in)
- **Web Browser:** Google Chrome, Microsoft Edge, Mozilla Firefox, or Brave (supporting WebAssembly)
- **Local Storage:** SQLite3 is embedded in both the browser (via WebAssembly `sql.js`) and the backend (standard library `sqlite3`). No MySQL, PostgreSQL, Docker, or Redis servers are required for local operation.

---

## 4. Full Technology Stack & Architecture

```
CRISP 2.2 ARCHITECTURAL BLUEPRINT
┌────────────────────────────────────────────────────────────────────────┐
│                      FRONTEND LAYER (Browser Runtime)                  │
│  React 19 SPA · Vite 8 · Tailwind CSS 4 · Lucide Icons · Motion        │
│  In-Browser sql.js WebAssembly SQLite (Local In-Memory Query Engine)   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ HTTP REST / SSE Stream (/api/*)
┌───────────────────────────────────▼────────────────────────────────────┐
│                  FULL-STACK APPLICATION SERVER (server.ts)             │
│  Node.js 22 · Express 4 API · Vite Development Middleware              │
│  Cross-Platform Python IPC Execution Bridge (PYTHON_BIN auto-detection)│
└──────────────────┬────────────────────────────────┬────────────────────┘
                   │                                │
┌──────────────────▼─────────────┐   ┌──────────────▼────────────────────┐
│   MASTER DATASTORE (SQLite3)   │   │     VECTOR KNOWLEDGE BASE         │
│  data/crisp.db (WAL Mode)      │   │  ChromaDB / Embedded Vector Store │
│  17 Normalized Relational      │   │  5 Logical Collections:           │
│  Tables (Vulnerabilities,      │   │  - crisp_vulnerabilities          │
│  Events, Assets, Controls,     │   │  - crisp_nist                     │
│  Findings, Remediations)       │   │  - crisp_findings                 │
└────────────────────────────────┘   │  - crisp_assets                   │
                                     │  - crisp_incidents                │
                                     └───────────────────────────────────┘
                                                    ▲
┌───────────────────────────────────────────────────┴────────────────────┐
│             ANALYTICAL & AI SECURITY ENGINES (Python 3.10)              │
│  • Correlation Engine (Triangulates Events + CVEs + Assets → Findings) │
│  • Multi-Factor Risk Engine (6-Factor Mathematical Formula 0–100)      │
│  • NIST CSF 2.0 Engine (Numerical Compliance % across 6 Functions)    │
│  • Supervised Agent Swarm (Orchestrator + Domain Specialists)          │
│  • Remediation Engine (Audit, Verification & Risk Delta Recalculation) │
└────────────────────────────────────────────────────────────────────────┘
```

### Technology Matrix:
| Layer | Technology | Version | Purpose in CRISP |
| :--- | :--- | :--- | :--- |
| **Frontend Framework** | React | `19.0.1` | Component-based interactive UI with hooks and context state management. |
| **Build & Bundler** | Vite | `8.3.5` | Fast HMR dev server and optimized roll-up production bundler. |
| **Styling & Theme** | Tailwind CSS | `4.3.3` | High-contrast dark navy/cyan SOC aesthetic with utility-first CSS. |
| **In-Browser Database** | sql.js (WebAssembly) | `1.14.2` | Compiles SQLite3 to WebAssembly; runs queries client-side in browser memory. |
| **Backend API Host** | Express / Node.js | `4.21.2` / `22.x` | Serves REST endpoints, Server-Sent Events (SSE) streaming, and Vite middleware. |
| **Analytical Backend** | Python | `3.10+` | Powers correlation, risk algorithms, and multi-agent swarm logic. |
| **Vector Database** | ChromaDB / Embedded | `0.4.x` | Stores semantic document embeddings for RAG evidence retrieval. |
| **LLM Inference** | Groq Cloud SDK / OpenAI | `llama-3.3-70b` | Ultra-low latency reasoning with deterministic zero-hallucination fallback. |
| **Relational Storage** | SQLite3 | Native | Primary persistent storage (`data/crisp.db`) with Write-Ahead Logging (WAL). |

---

## 5. External APIs, Feeds & Services Explained

CRISP ingests authoritative threat intelligence and external feeds to validate security metrics:

### 1. NIST National Vulnerability Database (NVD) 2.0 API:
- **Endpoint:** `https://services.nvd.nist.gov/rest/json/cves/2.0`
- **Purpose:** Ingests standardized Common Vulnerabilities and Exposures (CVEs), CVSS 3.1 base scores, Common Weakness Enumeration (CWE) categories, and affected CPE product configurations.
- **Authentication:** Works unauthenticated (public tier: 5 requests / 30 seconds) or with an optional `NVD_API_KEY` (elevating throughput to 50 requests / 30 seconds).
- **Resilience:** If NIST servers are unreachable or rate-limited, CRISP falls back to its pre-bundled baseline catalog of 1,753 real enterprise CVEs.

### 2. CISA Known Exploited Vulnerabilities (KEV) Catalog:
- **Authority:** Cybersecurity and Infrastructure Security Agency (CISA) — Binding Operational Directive (BOD) 22-01.
- **Purpose:** Identifies vulnerabilities with confirmed, active weaponization in the wild.
- **Integration:** Automatically flags CVEs present in KEV, extracts required remediation deadlines (CISA due dates), and feeds a mandatory $+15.0$ risk penalty into the risk calculation engine.

### 3. Groq Cloud LLM / OpenAI Integration:
- **Model:** `llama-3.3-70b-versatile` (or OpenAI compatible models).
- **Purpose:** Powers natural-language security synthesis in the AI Swarm and the Classic SOC Assistant.
- **Zero-Failure Fallback:** If `GROQ_API_KEY` is omitted or quota-limited, CRISP never crashes or fabricates text. Instead, it seamlessly switches to its built-in deterministic heuristic reasoning engine.

### 4. Benchmark Security Datasets (CIC-IDS2017 & Syslog RFC 5424):
- **Purpose:** Ingests authentic Canadian Institute for Cybersecurity intrusion detection telemetry (Brute Force, DoS, Port Scan, Botnet, Web Exploits) alongside live controllable telemetry generation.

---

## 6. Comprehensive Page-by-Page Feature Breakdown

CRISP is structured around **5 primary navigation views** accessible via the dark-themed sidebar:

---

### View 1: Overview Dashboard (`OverviewView.tsx`)
*The executive bird's-eye view of organizational security posture and high-level KPIs.*

- **Executive KPI Metric Cards:**
  - **Overall Posture Score:** 0–100 scale measuring defense maturity (e.g., 78.4% Moderate/Strong).
  - **Critical Threats Active:** Count of unresolved critical findings currently impacting enterprise assets.
  - **NIST CSF 2.0 Compliance Level:** Composite compliance percentage aggregated across all 6 core functions.
  - **Monitored Assets:** Total operational assets actively tracked in the inventory.
- **Dynamic Multi-Factor Risk Gauge:** A visual radial meter displaying enterprise-wide aggregate risk, categorized as `LOW` (0–39), `MEDIUM` (40–69), `HIGH` (70–84), or `CRITICAL` (85–100).
- **Asset Criticality Breakdown:** Segmented progress bars displaying infrastructure distribution across Mission Critical (Tier 1), Business Critical (Tier 2), and Internal Support (Tier 3).
- **Real-Time Activity Feed:** Chronological stream of latest correlated findings and intelligence updates.

---

### View 2: Live Monitoring (`LiveMonitoringView.tsx`)
*Operational telemetry console for security analysts monitoring event streams.*

- **Telemetry Stream Table:** Displays timestamped network and system security events with source IP, destination IP, target asset, attack classification, and severity.
- **CIC-IDS2017 Historical Ingestion:** Allows analysts to view real recorded intrusion benchmark events.
- **Controlled Telemetry Simulator (`[SIMULATION MODE]`):**
  - Analysts can toggle the real-time event generator on/off.
  - Configurable generation interval (1 to 5 seconds).
  - Attack scenario injection: Allows deliberate injection of specific vectors (e.g., *Log4j JNDI RCE*, *SSH Brute Force*, *DDoS Syn Flood*) to demonstrate real-time correlation.
- **Anomaly Detection Filter:** Quickly isolates events exceeding standard threshold baselines.

---

### View 3: Security Intelligence (`SecurityIntelligenceView.tsx`)
*The analytical core unifying vulnerability databases, correlation logic, compliance mapping, and remediation planning.*

This page is subdivided into 7 specialized intelligence sub-tabs:

#### Sub-tab 3.1: Vulnerabilities (NVD 2.0 Integration)
- Searchable catalog of 1,753 real CVEs.
- Displays CVSS 3.1 base score, severity badge, CWE taxonomy, and affected software products.
- **Sync NVD Button:** Triggers real-time synchronization with the live NIST NVD 2.0 API, inserting newly published CVEs into local SQLite.

#### Sub-tab 3.2: CISA Known Exploited Vulnerabilities (KEV)
- Filtered catalog of vulnerabilities actively leveraged by threat actors in active campaigns.
- Displays CISA Action Due Dates and BOD 22-01 mandates.
- Highlights overdue compliance items in high-contrast amber/rose badges.

#### Sub-tab 3.3: Correlated Security Findings
- Demonstrates CRISP's core correlation algorithm: **Triangulates Event + CVE + Asset**.
- Rather than displaying 10,000 raw firewall alerts, CRISP groups related telemetry into single actionable **Findings** (e.g., `FND-20261004-SIMCRIT525`: Exploitation attempt targeting Log4j on external Web Server).
- Displays confidence score, attack phase, and remediation status (`OPEN`, `INVESTIGATING`, `RESOLVED`).

#### Sub-tab 3.4: Cyber Risk Scoring Matrix
- Interactive breakdown of CRISP's 6-factor quantitative formula:
  $$S_{\text{CRISP}} = S_{\text{CVSS}} + S_{\text{KEV}} + S_{\text{Crit}} + S_{\text{Exp}} + S_{\text{Freq}} + S_{\text{Rec}}$$
- Sliders and parameter inspectors allowing analysts to see exactly how changing an asset's network exposure (Internal vs. External) or observing repeated attacks shifts the risk score from Medium to Critical.

#### Sub-tab 3.5: NIST CSF 2.0 Compliance Radar
- Quantitative mapping across all **6 Core Functions**:
  1. **GOVERN (GV):** Organizational context, risk strategy, and supply chain policies.
  2. **IDENTIFY (ID):** Asset management, vulnerability identification, and risk assessment.
  3. **PROTECT (PR):** Identity management, access control, data security, and awareness training.
  4. **DETECT (DE):** Continuous monitoring, event correlation, and anomaly detection.
  5. **RESPOND (RS):** Incident response management, analysis, mitigation, and reporting.
  6. **RECOVER (RC):** Incident recovery planning, backups, and resilience restoration.
- Displays numerical compliance percentages, category breakdowns, identified audit gaps, and concrete evidence justifications.

#### Sub-tab 3.6: Remediation Action Queue
- Closed-loop workflow for resolving identified vulnerabilities.
- Generates prioritized, step-by-step remediation plans (e.g., update Apache Log4j to 2.17.1, disable JNDI lookup, enforce egress filtering).
- **Mandatory Scan Verification Evidence:** Remediations cannot be closed arbitrarily; analysts submit post-remediation evidence (e.g., Tenable Nessus scan or SBOM JSON).
- **Dynamic Risk Recalculation:** Demonstrates immediate risk reduction upon verification (e.g., asset risk dynamically drops from $88.5 \to 41.5$).

#### Sub-tab 3.7: Enterprise Asset Inventory
- Comprehensive asset catalog tracking hostname, IP addresses, secondary interfaces, operating system, criticality tier, and network boundary (Internal, DMZ, External/Internet-facing).

---

### View 4: AI Agent Swarm (`AgentSwarmView.tsx`)
*The advanced multi-agent investigation console powered by a supervised LangGraph workflow.*

- **Supervised Multi-Agent Architecture:**
  - **Orchestrator Agent:** Interprets analyst natural-language queries, determines investigation workflow (`CVE_INVESTIGATION`, `ASSET_TRIAGE`, `INCIDENT_RESPONSE`, `COMPLIANCE_AUDIT`), dynamically selects active domain specialists, and synthesizes executive briefings.
  - **Threat Intelligence Agent:** Investigates telemetry events, frequency anomalies, and MITRE ATT&CK tactic mappings.
  - **Vulnerability Intelligence Agent:** Queries NVD CVE records, CVSS metrics, CWE weaknesses, and CISA KEV status.
  - **Asset Risk Agent:** Evaluates asset criticality, network boundaries, and multi-factor risk scores.
  - **Compliance Agent:** Identifies non-compliant controls across NIST CSF 2.0 functions.
  - **Evidence Agent:** Executes semantic vector searches across ChromaDB collections to retrieve similarity-grounded documentation.
  - **Verification Agent (Anti-Hallucination Guardrail):** Cross-checks every factual statement against primary database records. Any claim lacking database backing is categorized as an unconfirmed hypothesis rather than a fact.
- **Real-Time Streaming Terminal:** Live Server-Sent Events (SSE) streaming displaying real-time agent execution traces, durations, and reasoning steps.
- **Interactive Investigation Report:** Formatted executive summary, confirmed factual findings with primary source citations, verified hypotheses, and prioritized recommendations.
- **Classic SOC Assistant:** Dedicated natural-language querying panel for instant Q&A grounded in RAG evidence.

---

### View 5: Data & Administration (`DataAdminView.tsx`)
*Platform configuration, data ingestion, and database inspection tools.*

- **SQLite Database Explorer:** Direct browser interface to inspect and query the 17 tables in `data/crisp.db` without needing external database management tools.
- **Custom CSV/JSON Importer:** Custom column mapper allowing administrators to upload third-party security logs and map them to CRISP's standardized schema.
- **Data Source Health & Telemetry:** Real-time health monitors reporting status for NVD API, CISA KEV feed, local SQLite storage, and ChromaDB vector collections.

---

## 7. Mathematical Formulation of the Cyber Risk Engine

Unlike arbitrary risk matrices (High/Medium/Low), CRISP implements an explainable, deterministic 6-factor quantitative formula bounding risk between $0.0$ and $100.0$:

$$\text{Risk Score} = \min\left(100.0, S_{\text{CVSS}} + S_{\text{KEV}} + S_{\text{Crit}} + S_{\text{Exp}} + S_{\text{Freq}} + S_{\text{Rec}}\right)$$

### Parameter Weights:
1. **CVSS Base Severity ($S_{\text{CVSS}}$ — Max 30 pts):**
   $$S_{\text{CVSS}} = \frac{\text{CVSS Score}}{10.0} \times 30.0$$
2. **CISA KEV Active Exploitation ($S_{\text{KEV}}$ — Max 15 pts):**
   - $+15.0$ if the CVE is confirmed in CISA KEV catalog.
   - $+0.0$ if not known to be actively weaponized.
3. **Asset Criticality Tier ($S_{\text{Crit}}$ — Max 15 pts):**
   - Mission Critical (Tier 1): $+15.0$
   - Business Critical (Tier 2): $+10.0$
   - Internal Support (Tier 3): $+5.0$
4. **Network Exposure Boundary ($S_{\text{Exp}}$ — Max 15 pts):**
   - External / Internet-Facing: $+15.0$
   - DMZ / Edge Proxy: $+10.0$
   - Internal Isolated Subnet: $+5.0$
5. **Attack Event Frequency ($S_{\text{Freq}}$ — Max 15 pts):**
   $$S_{\text{Freq}} = \min\left(15.0, \ln(1 + N_{\text{events}}) \times 3.5\right)$$
6. **Temporal Recency ($S_{\text{Rec}}$ — Max 10 pts):**
   - Observed within last 1 hour: $+10.0$
   - Observed within last 24 hours: $+6.0$
   - Observed $> 24$ hours ago: $+2.0$

---

## 8. Installation, Local Startup & Verification Commands

### Windows 10/11 (PowerShell):
```powershell
# 1. Clone repository and navigate to folder
cd path\to\crisp

# 2. Install Node.js dependencies
npm install

# 3. Initialize SQLite Database Schema (Creates all 17 tables)
python scripts/migrate.py

# 4. Run automated test suite
npm test
python -m unittest discover tests

# 5. Launch Full-Stack Application (Express API + Vite SPA)
npm run dev
# Alternatively, double-click start-local.bat
```

### macOS / Linux:
```bash
npm install
python3 scripts/migrate.py
npm test
python3 -m unittest discover tests
npm run dev
# Alternatively: ./start-local.sh
```

**Access Platform:** Open your browser to `http://localhost:3000`.

---

## 9. 10-Stage Viva & Evaluation Walkthrough Guide

Use this sequence to present CRISP to the evaluation committee in 8–12 minutes:

1. **Stage 1: Executive Overview** (`Overview`) — Present the 0–100 posture score, KPI cards, and asset criticality tiers.
2. **Stage 2: Real NVD Vulnerability Intelligence** (`Security Intelligence` &rarr; `Vulnerabilities`) — Demonstrate the 1,753 real CVEs, CVSS 3.1 vectors, and click **"Sync NVD"** to show live NIST API synchronization.
3. **Stage 3: CISA KEV Weaponization Status** (`Security Intelligence` &rarr; `CISA KEV`) — Show active in-the-wild exploitation tags and BOD 22-01 remediation deadlines.
4. **Stage 4: Telemetry & Live Attack Simulator** (`Live Monitoring`) — Show CIC-IDS2017 benchmark data, toggle `[SIMULATION MODE]`, and inject a live Log4j attack.
5. **Stage 5: Multi-Entity Finding Correlation** (`Security Intelligence` &rarr; `Findings`) — Demonstrate triangulation of Event + CVE + Asset into single deduplicated findings.
6. **Stage 6: Explainable Risk Matrix** (`Security Intelligence` &rarr; `Cyber Risk Matrix`) — Walk through the transparent 6-factor mathematical formula.
7. **Stage 7: NIST CSF 2.0 Compliance Radar** (`Security Intelligence` &rarr; `NIST CSF 2.0`) — Showcase compliance percentages across all 6 Core Functions and explain audit gaps.
8. **Stage 8: Autonomous Multi-Agent Swarm** (`AI Swarm`) — Execute an investigation query (e.g., *"Investigate CVE-2021-44228 on AST-PROD-WEB-01"*), observe real-time agent execution traces, and inspect confirmed factual citations.
9. **Stage 9: ChromaDB Vector Evidence (RAG)** — Demonstrate semantic retrieval of documentation grounding the AI swarm's conclusions.
10. **Stage 10: Closed-Loop Remediation Verification** (`Security Intelligence` &rarr; `Remediation Queue`) — Demonstrate submitting scan verification evidence and observing immediate dynamic risk reduction ($88.5 \to 41.5$).
