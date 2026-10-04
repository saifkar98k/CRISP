# CRISP - Cyber Risk Intelligence & Scoring Platform
## Production Cybersecurity Architecture & Real Data Integration

CRISP is an enterprise-grade operational cyber risk intelligence and continuous assessment platform that bridges the gap between raw threat telemetry and executive risk decision-making. It correlates live public vulnerability intelligence (NIST NVD API 2.0 & CISA Known Exploited Vulnerabilities catalog) with enterprise asset telemetry and historical incident datasets within an embedded SQLite datastore, evaluating multi-factor risk scores and assessing organizational posture against the **NIST Cybersecurity Framework (CSF) 2.0**.

---

## 1. End-to-End Architecture & Data Pipeline

CRISP strictly separates external raw data ingestion from internal standardized domain models through a 7-stage verifiable data pipeline:

```text
       ┌─────────────────────────┐      ┌──────────────────────────┐      ┌─────────────────────────┐
       │   NIST NVD 2.0 API      │      │      CISA KEV FEED       │      │   Historical CSV/JSON   │
       │ (CVSS, CWE, Components) │      │ (Weaponized/Active CISA) │      │ (Telemetry/Event Logs)  │
       └────────────┬────────────┘      └────────────┬─────────────┘      └────────────┬────────────┘
                    │                                │                                 │
                    ▼                                ▼                                 ▼
       ┌────────────────────────────────────────────────────────────────────────────────────────────┐
       │                                     DATA PROVIDERS                                         │
       │    - NVDDataProvider (Rate limiting 5 req/30s, Exponential backoff jitter, ETag cache)     │
       │    - CISAKEVProvider (Catalog sync, CVE enrichment, due date & ransomware flags)           │
       │    - CSVDataProvider (Generic dynamic column mapper for Suricata, Zeek, or SOC logs)       │
       └─────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                                     │
                                                     ▼
       ┌────────────────────────────────────────────────────────────────────────────────────────────┐
       │                                       NORMALIZERS                                          │
       │  Converts external payloads into immutable CRISP internal schemas:                         │
       │  - Vulnerability: cve_id, cvss_score, severity, cwe, affected_products, cisa_kev status   │
       │  - SecurityEvent: event_id, timestamp, src/dest_ip, threat_category, severity, asset_id   │
       └─────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                                     │
                                                     ▼
       ┌────────────────────────────────────────────────────────────────────────────────────────────┐
       │                                        VALIDATION                                          │
       │  Enforces schema integrity: regex checks (CVE-YYYY-NNNN), CVSS numeric bounds [0.0 - 10.0],│
       │  strict ISO-8601 timestamps, IP format validation, and data provenance tagging.            │
       └─────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                                     │
                                                     ▼
       ┌────────────────────────────────────────────────────────────────────────────────────────────┐
       │                                     SQLITE STORAGE                                         │
       │  Embedded WebAssembly / Native SQLite database:                                            │
       │  - Tables: vulnerabilities, security_events, assets, nist_controls, data_source_metrics    │
       │  - Transactional bulk upserts, duplicate prevention, and zero-data-loss persistence        │
       └─────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                                     │
                                                     ▼
       ┌────────────────────────────────────────────────────────────────────────────────────────────┐
       │                              MULTI-FACTOR RISK ENGINE                                      │
       │  Calculates operational CRISP composite risk scores (0.0 - 10.0):                          │
       │  R = (CVSS × 0.30) + (KEV × 0.30) + (Criticality × 0.20) + (Exposure × 0.20)              │
       │  + Frequency Penalty (active incidents) + Threat Vector Weights                            │
       └─────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                                     │
                                                     ▼
       ┌────────────────────────────────────────────────────────────────────────────────────────────┐
       │                           NIST CSF 2.0 COMPLIANCE ENGINE                                   │
       │  Maps active vulnerabilities & incident telemetry across 6 CSF 2.0 functions:              │
       │  GOVERN (GV) • IDENTIFY (ID) • PROTECT (PR) • DETECT (DE) • RESPOND (RS) • RECOVER (RC)    │
       └─────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                                     │
                                                     ▼
       ┌────────────────────────────────────────────────────────────────────────────────────────────┐
       │                      CRISP OPERATIONS DASHBOARD (React + Tailwind)                         │
       │  - Executive KPI cards, real-time live event ticker, risk matrix, direct SQL inspector,    │
       │  - Interactive CSV column mapper modal, and NVD/CISA one-click sync controls.              │
       └────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Real vs. Historical vs. Synthetic Data Provenance

CRISP strictly enforces data transparency. Synthetic demo data is never masqueraded as real intelligence, and historical benchmark datasets are never misidentified as live attacks:

| Badge / Category | Visual Indicator | Provenance Description |
| :--- | :--- | :--- |
| **`REAL EXTERNAL DATA`** | Emerald / Green Badge | Live public vulnerability intelligence retrieved from NIST NVD API 2.0 and CISA KEV feeds. |
| **`HISTORICAL PUBLIC DATASET`** | Cyan / Blue Badge | Historical research benchmark data (e.g. **CIC-IDS2017**) collected in controlled academic environments. |
| **`SYNTHETIC DEMO DATA`** | Purple / Violet Badge | Generated deterministically in controlled simulation mode for offline academic viva demos. |
| **`DERIVED RISK SCORE`** | Purple Badge | Calculated algorithmically by the internal CRISP Risk Engine (never an official NIST/CISA score). |

---

## 3. Phase 2 Step 3: Real Historical Security Event Dataset (CIC-IDS2017)

### Dataset Overview & Official Source
- **Dataset Name**: CIC-IDS2017 (Intrusion Detection Evaluation Dataset)
- **Official Source**: Canadian Institute for Cybersecurity, University of New Brunswick (UNB)  
  [https://www.unb.ca/cic/datasets/ids-2017.html](https://www.unb.ca/cic/datasets/ids-2017.html)
- **Dataset Purpose**: An authentic, widely cited public cybersecurity research benchmark containing network traffic flows and labeled attack scenarios across multiple attack families.
- **Dataset Limitations**:
  - The dataset was collected in a controlled testbed environment (Monday through Friday, July 2017).
  - It consists of **historical network traffic flows**, **NOT** real-time or live attacks against the CRISP platform.
  - In CRISP, it is strictly classified and badged as **"Historical Public Dataset"** (`dataset_source = 'CIC-IDS2017'`).

### Inspecting the Dataset
Before importing, examine file structure, data types, and labels using the dedicated inspection tool:
```bash
python3 scripts/inspect_security_dataset.py data/cic_ids2017_sample.csv
```
The script outputs shape, columns (85 CICFlowMeter features), missing-value summaries, and unique attack labels.

### Schema Mapping (CIC-IDS2017 &rarr; CRISP Internal Schema)

The external dataset schema is strictly isolated by `SecurityDatasetProvider`:

| CIC-IDS2017 Source Field | CRISP Internal Field | Type | Transformation / Normalization |
| :--- | :--- | :--- | :--- |
| `Flow ID` | `event_id` | TEXT | Sanitized flow identifier. Preserves original ID without fabrication. |
| `Timestamp` | `timestamp` | TEXT | Parsed to standard ISO-8601 (`YYYY-MM-DDTHH:MM:SSZ`). Null if invalid. |
| `Source IP` | `source_ip` | TEXT | Validated IP address string. Null if missing. |
| `Destination IP` | `destination_ip` | TEXT | Target IP address string. Null if missing. |
| `Source Port` | `source_port` | INTEGER | Parsed integer port number (0 - 65535). |
| `Destination Port` | `destination_port` | INTEGER | Parsed integer target port (e.g. 80, 22, 445, 8080). |
| `Protocol` | `protocol` | TEXT | Mapped: `6` &rarr; `TCP`, `17` &rarr; `UDP`, `1` &rarr; `ICMP`. |
| `Label` | `original_attack_label` | TEXT | **Preserved exactly as present in dataset** (e.g. `DDoS`, `SSH-Patator`). |
| `Label` | `crisp_attack_category` | TEXT | Mapped to normalized CRISP category (see mapping table below). |
| *Derived* | `severity` | TEXT | Assigned via transparent CRISP classification rules. |
| *Derived* | `nist_function` | TEXT | Mapped to NIST CSF 2.0 function (RESPOND, DETECT, PROTECT, IDENTIFY). |
| *Constant* | `dataset_source` | TEXT | Set to `'CIC-IDS2017'`. Synthetic records retain `'MOCK'`. |

### CRISP-Defined Attack Label & Severity Mapping
*Note: This mapping is a CRISP project-defined classification for operational risk scoring. It is NOT an official rating provided by the University of New Brunswick.*

| Original Benchmark Label | CRISP Attack Category | CRISP Severity | NIST CSF 2.0 Function |
| :--- | :--- | :--- | :--- |
| `DDoS` | Denial of Service (DDoS) | **CRITICAL** | RESPOND (RS.MI) |
| `Infiltration` | Infiltration / Privilege Escalation | **CRITICAL** | RESPOND (RS.AN) |
| `Heartbleed` | Exploit (Heartbleed - CVE-2014-0160) | **CRITICAL** | RESPOND (RS.MI) |
| `SSH-Patator` | Brute Force (SSH) | **HIGH** | PROTECT (PR.AC) |
| `DoS slowloris` | Denial of Service (Slowloris) | **HIGH** | RESPOND (RS.MI) |
| `DoS Hulk` | Denial of Service (Hulk) | **HIGH** | RESPOND (RS.MI) |
| `DoS GoldenEye` | Denial of Service (GoldenEye) | **HIGH** | RESPOND (RS.MI) |
| `Bot` | Command & Control (Botnet) | **HIGH** | DETECT (DE.CM) |
| `Web Attack – Sql Injection` | Web Attack (SQL Injection) | **HIGH** | PROTECT (PR.PT) |
| `FTP-Patator` | Brute Force (FTP) | **MEDIUM** | PROTECT (PR.AC) |
| `Web Attack – Brute Force` | Web Attack (Brute Force) | **MEDIUM** | PROTECT (PR.PT) |
| `Web Attack – XSS` | Web Attack (Cross-Site Scripting) | **MEDIUM** | PROTECT (PR.PT) |
| `PortScan` | Reconnaissance (Port Scan) | **LOW** | DETECT (DE.AE) |
| `BENIGN` | Benign Network Traffic | **INFORMATIONAL** | IDENTIFY (ID.AM) |

### Large Dataset Chunking & Environmental Configuration
To support multi-gigabyte CIC-IDS2017 CSV files without memory exhaustion:
- Streaming utilizes `SecurityDatasetProvider.stream_raw_chunks()` with configurable chunk sizes (default: 5,000 rows).
- Configure dataset locations and row limits via environment variables:
  ```bash
  # Optional: Path to custom downloaded CIC-IDS2017 CSV file
  SECURITY_DATASET_PATH="data/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"

  # Optional: Maximum rows to import for rapid development/testing
  DATASET_IMPORT_LIMIT=10000
  ```

### How to Import the Dataset
- **Option A (Interactive Dashboard)**:
  1. Open the platform at `http://localhost:3000`.
  2. Navigate to **Threat Logs & Telemetry**.
  3. Click **"Sync CIC-IDS2017 Dataset"** to trigger chunked processing, risk calculation, and live SQLite insertion.
- **Option B (Python CLI)**:
  ```bash
  python3 -c "from services.security_event_service import import_dataset_into_db; print(import_dataset_into_db())"
  ```


---

## 3. Database Schema & Migration Instructions

CRISP uses SQLite for lightweight, auditable local storage. The database schema is fully defined in both SQL and TypeScript/Python abstractions.

### Table Definitions

1. **`vulnerabilities`**: Stores normalized CVE vulnerability intelligence.
   - `id` (TEXT PRIMARY KEY): Standard CVE ID (e.g. `CVE-2023-38606`).
   - `title` (TEXT), `description` (TEXT), `cwe` (TEXT).
   - `cvss_score` (REAL): Base CVSS score (0.0 to 10.0).
   - `cvss_version` (TEXT): `3.1`, `3.0`, or `2.0`.
   - `severity` (TEXT): `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.
   - `affected_products` (TEXT): JSON array of affected CPEs / software packages.
   - `source` (TEXT): `NVD`, `CISA_KEV`, `HYBRID`, or `DEMO`.
   - `is_known_exploited` (INTEGER): `1` if listed in CISA KEV, else `0`.
   - `cisa_date_added` (TEXT), `cisa_due_date` (TEXT), `cisa_action` (TEXT).
   - `cisa_ransomware_use` (TEXT): `Known` or `Unknown`.
   - `crisp_risk_score` (REAL): Derived composite risk score (0.0 to 10.0).

2. **`security_events`**: Telemetry and incident logs.
   - `id` (TEXT PRIMARY KEY), `timestamp` (TEXT), `source_ip` (TEXT), `destination_ip` (TEXT).
   - `threat_category` (TEXT), `threat_level` (TEXT), `alert_summary` (TEXT).
   - `target_asset_id` (TEXT), `cve_reference` (TEXT), `incident_state` (TEXT).
   - `data_source` (TEXT): `HISTORICAL_DATASET` or `SYNTHETIC_SIMULATION`.

3. **`assets`**: Critical infrastructure asset registry.
   - `id` (TEXT PRIMARY KEY), `name` (TEXT), `ip_address` (TEXT), `type` (TEXT).
   - `criticality` (TEXT): `TIER_1_MISSION_CRITICAL`, `TIER_2_OPERATIONAL`, `TIER_3_INTERNAL`.
   - `network_exposure` (TEXT): `PUBLIC_EDGE`, `INTERNAL_DMZ`, `AIRGAPPED`.

4. **`nist_controls`**: NIST CSF 2.0 evaluation results.
5. **`data_source_metrics`**: Operational sync timestamps, counts, and latency tracking.

### Schema Migration / Update Instructions

When updating from Phase 1 or adding new columns (e.g. CISA KEV attributes):
```sql
-- Step 1: Add CISA KEV enrichments to existing Phase-1 SQLite database
ALTER TABLE vulnerabilities ADD COLUMN is_known_exploited INTEGER DEFAULT 0;
ALTER TABLE vulnerabilities ADD COLUMN cisa_date_added TEXT;
ALTER TABLE vulnerabilities ADD COLUMN cisa_due_date TEXT;
ALTER TABLE vulnerabilities ADD COLUMN cisa_action TEXT;
ALTER TABLE vulnerabilities ADD COLUMN cisa_ransomware_use TEXT;
ALTER TABLE vulnerabilities ADD COLUMN crisp_risk_score REAL DEFAULT 0.0;

-- Step 2: Create indexes for fast lookup and dashboard filtering
CREATE INDEX IF NOT EXISTS idx_vuln_cisa_exploited ON vulnerabilities(is_known_exploited);
CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_target ON security_events(target_asset_id);
```

---

## 4. Commands to Run

### Development & Full-Stack Platform Server
CRISP runs as a full-stack platform with an Express proxy backend and Vite React frontend on port 3000:

```bash
# Install dependencies
npm install

# Start the full-stack server (runs server.ts with Vite middlewares)
npm run dev

# Lint and check TypeScript definitions
npm run lint

# Compile and create production build
npm run build
```

### Python Sync Services & CLI Tools
The backend sync services and unit test suites can be executed independently:

```bash
# Run the NVD sync service directly (fetches 20 recent CVEs)
python3 -c "from services.nvd_sync_service import sync_nvd; print(sync_nvd(resultsPerPage=20))"

# Run the CISA KEV sync service directly
python3 -c "from services.cisa_kev_sync_service import sync_cisa_kev; print(sync_cisa_kev())"

# Execute all Python unit tests
python3 -m unittest discover -s tests -v
```

---

## 5. Testing Instructions

### 1. Python Unit Test Verification
Run the 22 automated test cases covering normalization, CVSS fallbacks (v3.1, v3.0, v2.0), missing descriptions, duplicate prevention, and CISA KEV merge rules:
```bash
python3 -m unittest discover -s tests -v
```
*Expected Result*: `Ran 22 tests in 0.070s - OK`.

### 2. Live API Connectivity Tests
Test the proxy endpoints and rate-limit handlers:
```bash
# Test CISA KEV official feed proxy
curl -s http://localhost:3000/api/cisa-kev | head -c 200

# Test NIST NVD 2.0 API proxy
curl -s "http://localhost:3000/api/nvd?resultsPerPage=2" | head -c 200

# Test Historical CSV dataset endpoint
curl -s http://localhost:3000/api/datasets/historical | head -n 3
```

### 3. Frontend Interactive Tests
1. Open the application at `http://localhost:3000`.
2. Navigate to **Data Sources & Pipeline**: Click **"Run Full Pipeline Sync"**. Observe live latency metrics, database upsert counts, and log output.
3. Navigate to **Vulnerabilities**: Filter by **"CISA KEV Only"**. Notice the weaponization badge, required remediation deadline, and recalculated CRISP risk score.
4. Navigate to **CSV Importer**: Load a CSV, map custom columns (e.g. `src_ip`, `threat_level`), and click **"Import & Validate"**.
5. Navigate to **SQLite Inspector**: Execute `SELECT id, cvss_score, crisp_risk_score, is_known_exploited FROM vulnerabilities LIMIT 5;` and verify immediate tabular SQL results.

---

## 6. 5-Minute Final-Year-Project Demonstration Script (Viva / Defense)

Use this precise 5-minute timed walkthrough during project evaluations or examiner demonstrations.

### **Minute 0:00 – 1:00: Problem Statement & Architecture Overview**
* **Action**: Open the CRISP platform at `http://localhost:3000` on the **Executive Dashboard**.
* **Presenter Script**:
  > *"Respected examiners, traditional vulnerability management tools evaluate CVEs in isolation using static CVSS base scores. In reality, a CVSS 9.8 vulnerability on an isolated internal printer represents far less actual risk than a CVSS 7.5 vulnerability that is weaponized in the wild and facing the public edge.*
  > 
  > *CRISP addresses this by integrating real-time public vulnerability intelligence from NIST NVD and the CISA Known Exploited Vulnerabilities catalog with internal asset exposure and historical incident telemetry.*
  > 
  > *Notice our architectural transparency: every record on this dashboard displays its provenance badge—distinguishing real external data from NIST, historical honeypot telemetry, and our synthetic demonstration events."*

### **Minute 1:00 – 2:00: Real-Time Public Intelligence (NVD & CISA KEV)**
* **Action**: Click on the **Vulnerability Intelligence** tab. Filter by **"CISA KEV (Active Exploitation)"**. Click on an enriched record (e.g., `CVE-2023-38606` or `CVE-2021-44228`).
* **Presenter Script**:
  > *"Here is our live vulnerability intelligence view. We consume the official NIST NVD 2.0 REST API and the CISA Known Exploited Vulnerabilities catalog. Observe that for each vulnerability, we extract CVSS v3.1 vector strings, affected software components, and CWE categories.*
  > 
  > *When a vulnerability appears in the CISA KEV catalog, CRISP flags it with an Active Weaponization indicator, captures the CISA remediation due date, and immediately elevates the risk level.*
  > 
  > *Our data pipeline implements defensive engineering: automated exponential backoff with jitter to comply with NIST's 5 requests per 30-second rate limits, timeout handlers, and duplicate prevention via transactional upserts."*

### **Minute 2:00 – 3:00: Explainable Multi-Factor Risk Engine**
* **Action**: Click on the **Risk Matrix & Assets** tab. Click on the top-ranked asset (`prod-edge-web01.internal`) to open the **Risk Breakdown Modal**.
* **Presenter Script**:
  > *"Rather than relying on opaque black-box scoring or AI hallucinations, CRISP employs a deterministic, mathematically verifiable risk formula:*
  > 
  > $$\text{Score} = (W_{\text{cvss}} \times \text{CVSS}) + (W_{\text{kev}} \times F_{\text{kev}}) + (W_{\text{crit}} \times F_{\text{crit}}) + (W_{\text{exp}} \times F_{\text{exp}}) + F_{\text{freq}}$$
  > 
  > *In this modal, you can see the transparent contribution of each parameter: Base CVSS accounts for 30%, active weaponization in CISA KEV adds up to 3.0 points, asset criticality provides a weighted tier multiplier, and public Internet exposure amplifies the attack surface. This gives CISOs explainable justification for immediate patch prioritization."*

### **Minute 3:00 – 3:45: Configurable CSV Ingestion & Real Telemetry Mapping**
* **Action**: Navigate to **CSV Importer**. Show the loaded dataset and the column-mapping interface. Click **"Validate & Ingest Telemetry"**.
* **Presenter Script**:
  > *"CRISP does not hardcode vendor-specific schemas. Here we demonstrate our Generic CSV Data Provider. We can ingest incident logs from Suricata IDS, Zeek, or open SOC honeypots.*
  > 
  > *Using our dynamic column mapper, an administrator can map arbitrary external headers to our normalized internal `SecurityEvent` schema. The pipeline validates IP formatting, timestamps, and threat levels, rejecting malformed records before persisting them directly to SQLite."*

### **Minute 4:00 – 4:30: NIST CSF 2.0 Compliance & Direct SQLite Engine**
* **Action**: Click on **NIST CSF 2.0 Compliance** tab, then toggle to the **Direct SQLite Inspector** tab. Run the preloaded query:
  `SELECT source, count(*), avg(cvss_score), avg(crisp_risk_score) FROM vulnerabilities GROUP BY source;`
* **Presenter Script**:
  > *"CRISP maps all ingested telemetry directly to the six functions of the updated NIST Cybersecurity Framework 2.0: Govern, Identify, Protect, Detect, Respond, and Recover.*
  > 
  > *Under the hood, everything is stored in a zero-dependency embedded SQLite database. In this live SQLite Inspector, examiners can execute raw SQL queries to verify data integrity, table relationships, and index performance."*

### **Minute 4:30 – 5:00: Controlled Demo Simulation & Conclusion**
* **Action**: Return to the **Executive Dashboard**. Toggle **"Live Telemetry Simulation"** on at **2x Speed**. Watch the Live Attack Ticker stream incoming events and update the threat meters in real time.
* **Presenter Script**:
  > *"Finally, for demonstration and training environments, CRISP features a controlled simulation engine with adjustable clock speeds. As simulated events stream in, the risk engine continuously recalculates live exposure scores.*
  > 
  > *In summary, CRISP delivers a robust, real-data-driven cybersecurity intelligence platform with verifiable data provenance, explainable risk scoring, and zero third-party cloud database dependencies. Thank you, and I look forward to your questions."*
