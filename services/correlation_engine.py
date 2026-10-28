"""
CRISP Cybersecurity Platform - Security Data Correlation Engine
Phase 2 Step 4: Multi-source intelligence correlation connecting:
- Security Events
- Enterprise Assets
- NVD Vulnerabilities
- CISA Known Exploited Vulnerabilities (KEV)
- NIST CSF 2.0 Controls & Functions

Produces explainable Security Findings with auditable evidence trails.
"""

import json
import logging
import os
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from services.risk_engine import (
    calculate_final_risk,
    init_risk_history_db,
    record_risk_history,
)

logger = logging.getLogger("CRISP.CorrelationEngine")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] [CRISP.Correlation] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

DEFAULT_DB_PATH = os.path.join("data", "crisp.db")

# Default Enterprise Assets Registry (seeded into SQLite for correlation)
DEFAULT_ENTERPRISE_ASSETS: List[Dict[str, Any]] = [
    {
        "id": "AST-PROD-WEB-01",
        "name": "prod-edge-web01.internal",
        "ip_address": "10.0.4.15",
        "secondary_ips": "192.168.10.50",
        "type": "Web Application",
        "criticality": "CRITICAL",
        "exposure": "EXTERNAL",
        "owner": "Platform Eng (Lead: M. Patel)",
        "department": "Digital Banking",
        "associated_cves": "CVE-2021-44228,CVE-2017-5638,CVE-2022-22965,CVE-2023-22515",
    },
    {
        "id": "AST-GW-VPN-01",
        "name": "corp-vpn-gw01.internal",
        "ip_address": "10.0.5.20",
        "secondary_ips": "",
        "type": "API Gateway",
        "criticality": "CRITICAL",
        "exposure": "EXTERNAL",
        "owner": "NetSec Ops (Lead: S. Chen)",
        "department": "Infrastructure",
        "associated_cves": "CVE-2023-4966,CVE-2024-21887,CVE-2024-3400",
    },
    {
        "id": "AST-DB-FIN-01",
        "name": "db-financials01.internal",
        "ip_address": "10.0.8.12",
        "secondary_ips": "",
        "type": "Database Server",
        "criticality": "CRITICAL",
        "exposure": "INTERNAL",
        "owner": "Data Eng (Lead: A. Kowalski)",
        "department": "Finance",
        "associated_cves": "CVE-2023-34362",
    },
    {
        "id": "AST-AD-DC-01",
        "name": "ad-core-dc01.internal",
        "ip_address": "10.0.2.5",
        "secondary_ips": "192.168.10.8",
        "type": "Domain Controller",
        "criticality": "CRITICAL",
        "exposure": "INTERNAL",
        "owner": "IAM Ops (Lead: R. Gomez)",
        "department": "Enterprise Security",
        "associated_cves": "CVE-2020-1472",
    },
    {
        "id": "AST-DMZ-SSH-01",
        "name": "dmz-bastion01.internal",
        "ip_address": "10.0.4.18",
        "secondary_ips": "",
        "type": "Endpoint",
        "criticality": "HIGH",
        "exposure": "DMZ",
        "owner": "SecOps (Lead: D. Miller)",
        "department": "Security Operations",
        "associated_cves": "CVE-2023-38408",
    },
    {
        "id": "AST-PROD-APP-02",
        "name": "app-billing-svc02.internal",
        "ip_address": "10.0.6.10",
        "secondary_ips": "",
        "type": "Web Application",
        "criticality": "HIGH",
        "exposure": "INTERNAL",
        "owner": "Billing Tech (Lead: L. Wang)",
        "department": "Finance",
        "associated_cves": "CVE-2023-34362",
    },
    {
        "id": "AST-WS-ENG-44",
        "name": "ws-engineer-laptop44.internal",
        "ip_address": "10.0.14.33",
        "secondary_ips": "192.168.10.14",
        "type": "Endpoint",
        "criticality": "MEDIUM",
        "exposure": "INTERNAL",
        "owner": "Eng Endpoints",
        "department": "Software Engineering",
        "associated_cves": "",
    },
    {
        "id": "AST-DNS-CORE-01",
        "name": "dns-core01.internal",
        "ip_address": "192.168.10.3",
        "secondary_ips": "",
        "type": "Endpoint",
        "criticality": "HIGH",
        "exposure": "INTERNAL",
        "owner": "NetOps",
        "department": "Infrastructure",
        "associated_cves": "",
    },
]

# NIST CSF 2.0 Mapping per attack category
NIST_FUNCTION_MAP = {
    "Denial of Service (DDoS)": "RESPOND",
    "Denial of Service": "RESPOND",
    "Denial of Service (Slowloris)": "RESPOND",
    "Denial of Service (Hulk)": "RESPOND",
    "Denial of Service (GoldenEye)": "RESPOND",
    "Exploit (Heartbleed)": "RESPOND",
    "Exploit Public-Facing App": "RESPOND",
    "Remote Code Execution": "RESPOND",
    "Infiltration / Privilege Escalation": "RESPOND",
    "Privilege Escalation": "RESPOND",
    "Reconnaissance (Port Scan)": "DETECT",
    "Reconnaissance": "DETECT",
    "Command & Control (Botnet)": "DETECT",
    "Command & Control": "DETECT",
    "Brute Force (SSH)": "PROTECT",
    "Brute Force (FTP)": "PROTECT",
    "Brute Force": "PROTECT",
    "Web Attack (SQL Injection)": "PROTECT",
    "SQL Injection": "PROTECT",
    "Web Attack (Cross-Site Scripting)": "PROTECT",
    "Web Attack (Brute Force)": "PROTECT",
    "Data Exfiltration": "RESPOND",
    "Benign Network Traffic": "IDENTIFY",
}


def init_correlation_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """Initializes tables for assets and correlated security findings."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        # Assets table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS assets (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                ip_address TEXT,
                secondary_ips TEXT,
                type TEXT,
                criticality TEXT,
                exposure TEXT,
                owner TEXT,
                department TEXT,
                associated_cves TEXT,
                created_at TEXT NOT NULL
            );
            """
        )

        # Correlated Security Findings table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS security_findings (
                finding_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                asset_id TEXT,
                asset_name TEXT,
                event_id TEXT,
                cve_id TEXT,
                attack_category TEXT NOT NULL,
                severity TEXT NOT NULL,
                cvss_score REAL,
                known_exploited INTEGER DEFAULT 0,
                asset_criticality TEXT,
                risk_score REAL NOT NULL,
                risk_level TEXT NOT NULL,
                nist_function TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                source TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )

        # Performance indexes for fast querying and correlation
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_asset ON security_findings(asset_id);")
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                cvss_score REAL,
                severity TEXT,
                published_date TEXT,
                modified_date TEXT,
                cwe TEXT,
                affected_products TEXT,
                references_json TEXT,
                source TEXT,
                known_exploited INTEGER DEFAULT 0,
                kev_due_date TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vuln_cvss ON vulnerabilities(cvss_score);")
        cursor.execute("PRAGMA table_info(vulnerabilities);")
        vuln_cols = {row[1] for row in cursor.fetchall()}
        if "known_exploited" not in vuln_cols and "is_known_exploited" not in vuln_cols:
            try:
                cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN known_exploited INTEGER DEFAULT 0;")
                vuln_cols.add("known_exploited")
            except Exception:
                pass
        if "kev_due_date" not in vuln_cols:
            try:
                cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN kev_due_date TEXT;")
                vuln_cols.add("kev_due_date")
            except Exception:
                pass
        if "known_exploited" in vuln_cols:
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_vuln_kev ON vulnerabilities(known_exploited);")
        elif "is_known_exploited" in vuln_cols:
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_vuln_kev ON vulnerabilities(is_known_exploited);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_risk_score ON security_findings(risk_score);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON security_findings(severity);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_nist ON security_findings(nist_function);")

        # Seed assets if table is empty
        cursor.execute("SELECT COUNT(*) FROM assets")
        if cursor.fetchone()[0] == 0:
            now_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            cursor.executemany(
                """
                INSERT OR REPLACE INTO assets (
                    id, name, ip_address, secondary_ips, type, criticality,
                    exposure, owner, department, associated_cves, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                [
                    (
                        a["id"],
                        a["name"],
                        a["ip_address"],
                        a.get("secondary_ips", ""),
                        a["type"],
                        a["criticality"],
                        a["exposure"],
                        a["owner"],
                        a["department"],
                        a.get("associated_cves", ""),
                        now_iso,
                    )
                    for a in DEFAULT_ENTERPRISE_ASSETS
                ],
            )

        # Seed benchmark vulnerabilities if table is empty
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        if cursor.fetchone()[0] == 0:
            now_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            default_vulns = [
                (
                    "CVE-2021-44228",
                    "Apache Log4j2 JNDI Remote Code Execution vulnerability",
                    10.0,
                    "CRITICAL",
                    "2021-12-10T10:00:00Z",
                    "2021-12-14T10:00:00Z",
                    "CWE-502",
                    "Apache Log4j",
                    "[]",
                    "NVD",
                    1,
                    "2021-12-24",
                    now_iso,
                    now_iso,
                ),
                (
                    "CVE-2024-3400",
                    "Palo Alto Networks PAN-OS OS Command Injection vulnerability",
                    10.0,
                    "CRITICAL",
                    "2024-04-12T10:00:00Z",
                    "2024-04-15T10:00:00Z",
                    "CWE-78",
                    "PAN-OS",
                    "[]",
                    "NVD",
                    1,
                    "2024-04-19",
                    now_iso,
                    now_iso,
                ),
                (
                    "CVE-2023-34362",
                    "MOVEit Transfer SQL Injection Vulnerability",
                    9.8,
                    "CRITICAL",
                    "2023-06-02T10:00:00Z",
                    "2023-06-05T10:00:00Z",
                    "CWE-89",
                    "MOVEit Transfer",
                    "[]",
                    "NVD",
                    1,
                    "2023-06-16",
                    now_iso,
                    now_iso,
                ),
                (
                    "CVE-2020-1472",
                    "Microsoft Netlogon Elevation of Privilege Vulnerability (Zerologon)",
                    10.0,
                    "CRITICAL",
                    "2020-08-11T10:00:00Z",
                    "2020-08-17T10:00:00Z",
                    "CWE-287",
                    "Windows Server Netlogon",
                    "[]",
                    "NVD",
                    1,
                    "2020-09-01",
                    now_iso,
                    now_iso,
                ),
            ]
            kev_col_name = "known_exploited" if "known_exploited" in vuln_cols else "is_known_exploited"
            cursor.executemany(
                f"""
                INSERT OR REPLACE INTO vulnerabilities (
                    cve_id, description, cvss_score, severity, published_date,
                    modified_date, cwe, affected_products, references_json,
                    source, {kev_col_name}, kev_due_date, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                default_vulns,
            )
            conn.commit()


class SecurityCorrelationEngine:
    """
    CRISP Multi-Source Security Correlation Engine.
    Correlates Security Events with Assets, NVD CVEs, CISA KEV, and NIST CSF 2.0.
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        init_correlation_db(self.db_path)

    def _load_assets(self) -> Dict[str, Dict[str, Any]]:
        """Loads assets indexed by ID and by IP address."""
        assets_by_id: Dict[str, Dict[str, Any]] = {}
        assets_by_ip: Dict[str, Dict[str, Any]] = {}

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM assets")
            for row in cursor.fetchall():
                item = dict(row)
                assets_by_id[item["id"]] = item
                if item.get("ip_address"):
                    assets_by_ip[item["ip_address"]] = item
                # Also check secondary IPs
                if item.get("secondary_ips"):
                    for sec_ip in str(item["secondary_ips"]).split(","):
                        if sec_ip.strip():
                            assets_by_ip[sec_ip.strip()] = item

        return {"by_id": assets_by_id, "by_ip": assets_by_ip}

    def _load_vulnerabilities(self) -> Dict[str, Dict[str, Any]]:
        """Loads vulnerability catalog indexed by CVE ID."""
        vulns: Dict[str, Dict[str, Any]] = {}
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT * FROM vulnerabilities")
                for row in cursor.fetchall():
                    item = dict(row)
                    cve_id = item.get("cve_id")
                    if cve_id:
                        vulns[cve_id] = item
            except sqlite3.OperationalError:
                pass
        return vulns

    def correlate_event(
        self,
        event: Dict[str, Any],
        asset_maps: Dict[str, Dict[str, Any]],
        vuln_map: Dict[str, Dict[str, Any]],
        event_frequency: int = 1,
    ) -> Dict[str, Any]:
        """
        Executes deterministic correlation rules for a single security event.

        Relationships evaluated:
        1. Event -> Destination/Source IP -> Asset
        2. Event/Asset -> CVE -> NVD
        3. CVE -> CISA KEV (known_exploited)
        4. Attack Category -> NIST CSF 2.0 Function
        5. Evidence synthesis and risk scoring
        """
        evidence: List[str] = []
        event_id = event.get("event_id") or event.get("id") or "EVT-UNKNOWN"
        attack_category = event.get("attack_category") or event.get("crisp_attack_category") or "Unclassified Traffic"
        event_severity = event.get("severity") or "LOW"
        timestamp = event.get("timestamp") or datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        # -------------------------------------------------------------
        # Rule 1: Correlate Event to Asset
        # -------------------------------------------------------------
        asset: Optional[Dict[str, Any]] = None
        asset_id: Optional[str] = event.get("asset_id") or event.get("target_asset_id")

        if asset_id and asset_id in asset_maps["by_id"]:
            asset = asset_maps["by_id"][asset_id]
            evidence.append(f"Event target explicitly mapped to asset {asset['name']} (ID: {asset['id']})")
        else:
            # Check Destination IP
            dest_ip = event.get("destination_ip") or event.get("dest_ip")
            if dest_ip and dest_ip in asset_maps["by_ip"]:
                asset = asset_maps["by_ip"][dest_ip]
                evidence.append(f"Destination IP {dest_ip} matched enterprise asset {asset['name']} (Tier: {asset['criticality']})")
            else:
                # Check Source IP (internal compromised host)
                src_ip = event.get("source_ip") or event.get("src_ip")
                if src_ip and src_ip in asset_maps["by_ip"]:
                    asset = asset_maps["by_ip"][src_ip]
                    evidence.append(f"Source IP {src_ip} matched internal asset {asset['name']} (Outbound/Lateral movement)")

        if not asset:
            evidence.append("Asset relationship: Uncorrelated (external or unmanaged host)")

        # -------------------------------------------------------------
        # Rule 2: Correlate to Vulnerability (CVE)
        # -------------------------------------------------------------
        cve_id: Optional[str] = event.get("cve_id") or event.get("cve_reference")
        vuln: Optional[Dict[str, Any]] = None

        if cve_id and cve_id in vuln_map:
            vuln = vuln_map[cve_id]
            evidence.append(f"Direct CVE link identified in telemetry: {cve_id}")
        elif asset and asset.get("associated_cves"):
            # Check if asset has associated CVE that matches attack pattern
            asset_cve_list = [c.strip() for c in str(asset["associated_cves"]).split(",") if c.strip()]
            for candidate_cve in asset_cve_list:
                if candidate_cve in vuln_map:
                    candidate_vuln = vuln_map[candidate_cve]
                    # Correlate matching vector
                    cat_lower = attack_category.lower()
                    desc_lower = str(candidate_vuln.get("description", "")).lower()
                    if (
                        ("log4j" in desc_lower and "exploit" in cat_lower)
                        or ("struts" in desc_lower and "remote code" in cat_lower)
                        or ("vpn" in desc_lower and "gateway" in cat_lower)
                        or ("sql" in desc_lower and "sql" in cat_lower)
                        or ("heartbleed" in desc_lower and "heartbleed" in cat_lower)
                    ):
                        cve_id = candidate_cve
                        vuln = candidate_vuln
                        evidence.append(f"Correlated asset vulnerability {cve_id} based on attack pattern match")
                        break

        if not cve_id:
            evidence.append("Vulnerability relationship: Uncorrelated (no CVE mapped)")

        # -------------------------------------------------------------
        # Rule 3: Check CISA KEV (Known Exploited Vulnerability)
        # -------------------------------------------------------------
        is_known_exploited = False
        cisa_due_date = None
        if vuln:
            cvss_score = vuln.get("cvss_score")
            if cvss_score is not None:
                evidence.append(f"CVSS Base Score = {cvss_score} ({vuln.get('severity', 'UNKNOWN')})")

            if vuln.get("known_exploited") or vuln.get("is_known_exploited"):
                is_known_exploited = True
                cisa_due_date = vuln.get("kev_due_date") or vuln.get("cisa_due_date")
                due_info = f" (remediation deadline: {cisa_due_date})" if cisa_due_date else ""
                evidence.append(f"CRITICAL: Vulnerability is listed in CISA KEV Catalog - actively exploited in the wild{due_info}")
        else:
            cvss_score = None

        # -------------------------------------------------------------
        # Rule 4: Critical Asset Impact
        # -------------------------------------------------------------
        asset_criticality = asset["criticality"] if asset else "MEDIUM"
        if asset:
            evidence.append(f"Target Asset Criticality = {asset_criticality} (Exposure: {asset.get('exposure', 'INTERNAL')})")

        # -------------------------------------------------------------
        # Rule 5: Repeated Events / Frequency Multiplier
        # -------------------------------------------------------------
        if event_frequency > 1:
            evidence.append(f"Incident Frequency: {event_frequency} correlated events observed against this target")

        # -------------------------------------------------------------
        # Rule 6: NIST CSF 2.0 Mapping
        # -------------------------------------------------------------
        nist_function = NIST_FUNCTION_MAP.get(attack_category, "DETECT")
        evidence.append(f"Mapped to NIST CSF 2.0 Function: {nist_function}")

        # -------------------------------------------------------------
        # Calculate CRISP Multi-Factor Risk Score (0-100) via Risk Engine
        # -------------------------------------------------------------
        asset_exposure = asset.get("exposure") if asset else None
        risk_assessment = calculate_final_risk(
            cvss_score=cvss_score,
            cisa_kev_status=is_known_exploited,
            asset_criticality=asset_criticality if asset else None,
            asset_exposure=asset_exposure,
            event_severity=event_severity,
            attack_frequency=event_frequency,
            recency_timestamp=timestamp,
        )
        final_risk_score = risk_assessment["score"]
        risk_level = risk_assessment["risk_level"]
        evidence.append(f"CRISP Multi-Factor Risk Score: {final_risk_score}/100 ({risk_level})")

        finding_id = f"FND-{datetime.utcnow().strftime('%Y%m%d')}-{event_id[:12].replace('-', '')}"

        return {
            "finding_id": finding_id,
            "timestamp": timestamp,
            "asset_id": asset["id"] if asset else None,
            "asset_name": asset["name"] if asset else "Uncorrelated Asset",
            "event_id": event_id,
            "cve_id": cve_id,
            "attack_category": attack_category,
            "severity": event_severity,
            "cvss_score": cvss_score,
            "known_exploited": is_known_exploited,
            "asset_criticality": asset_criticality,
            "risk_score": final_risk_score,
            "risk_level": risk_level,
            "factors": risk_assessment.get("factors", []),
            "factor_scores": risk_assessment.get("factor_scores", {}),
            "explanation": risk_assessment.get("explanation", ""),
            "nist_function": nist_function,
            "evidence": evidence,
            "source": "CORRELATED_INTELLIGENCE",
        }

    def correlate_all(self, limit: int = 250) -> List[Dict[str, Any]]:
        """
        Executes correlation across all stored security events, calculates
        repeated event frequencies, and persists findings to SQLite.
        """
        asset_maps = self._load_assets()
        vuln_map = self._load_vulnerabilities()

        # Load security events from SQLite
        events: List[Dict[str, Any]] = []
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM security_events ORDER BY timestamp DESC LIMIT ?", (limit,))
            events = [dict(r) for r in cursor.fetchall()]

        if not events:
            logger.info("No security events in database to correlate.")
            return []

        # Calculate incident frequencies by destination IP / target
        frequency_counter: Dict[str, int] = {}
        for e in events:
            key = e.get("destination_ip") or e.get("target_asset_id") or e.get("cve_id") or "UNKNOWN"
            frequency_counter[key] = frequency_counter.get(key, 0) + 1

        findings: List[Dict[str, Any]] = []
        now_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        for e in events:
            target_key = e.get("destination_ip") or e.get("target_asset_id") or e.get("cve_id") or "UNKNOWN"
            freq = frequency_counter.get(target_key, 1)

            finding = self.correlate_event(
                event=e,
                asset_maps=asset_maps,
                vuln_map=vuln_map,
                event_frequency=freq,
            )
            findings.append(finding)

        # Save findings to SQLite
        self.save_findings(findings)
        logger.info(f"Correlation completed: generated and stored {len(findings)} security findings.")
        return findings

    def save_findings(self, findings: List[Dict[str, Any]]) -> None:
        """Persists findings into SQLite security_findings table."""
        now_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            records = [
                (
                    f["finding_id"],
                    f["timestamp"],
                    f.get("asset_id"),
                    f.get("asset_name"),
                    f.get("event_id"),
                    f.get("cve_id"),
                    f["attack_category"],
                    f["severity"],
                    f.get("cvss_score"),
                    1 if f.get("known_exploited") else 0,
                    f.get("asset_criticality"),
                    f["risk_score"],
                    f["risk_level"],
                    f["nist_function"],
                    json.dumps(f.get("evidence", [])),
                    f["source"],
                    now_iso,
                )
                for f in findings
            ]

            cursor.executemany(
                """
                INSERT OR REPLACE INTO security_findings (
                    finding_id, timestamp, asset_id, asset_name, event_id,
                    cve_id, attack_category, severity, cvss_score, known_exploited,
                    asset_criticality, risk_score, risk_level, nist_function,
                    evidence_json, source, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                records,
            )
            conn.commit()

        # Record findings into risk_history table
        init_risk_history_db(self.db_path)
        for f in findings:
            record_risk_history(
                score_data={
                    "score": f.get("risk_score", 0.0),
                    "risk_level": f.get("risk_level", "LOW"),
                    "factors": f.get("factors", []),
                    "factor_scores": f.get("factor_scores", {}),
                    "explanation": f.get("explanation", ""),
                },
                asset=f.get("asset_name") or f.get("asset_id"),
                finding=f.get("finding_id"),
                timestamp=f.get("timestamp"),
                db_path=self.db_path,
            )

    def get_findings(
        self,
        risk_level: Optional[str] = None,
        asset_id: Optional[str] = None,
        cve_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Retrieves findings from SQLite with filtering."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            query = "SELECT * FROM security_findings WHERE 1=1"
            params: List[Any] = []

            if risk_level and risk_level.upper() != "ALL":
                query += " AND risk_level = ?"
                params.append(risk_level.upper())
            if asset_id and asset_id.upper() != "ALL":
                query += " AND asset_id = ?"
                params.append(asset_id)
            if cve_id and cve_id.upper() != "ALL":
                query += " AND cve_id = ?"
                params.append(cve_id)

            query += " ORDER BY risk_score DESC, timestamp DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            results = []
            for r in cursor.fetchall():
                item = dict(r)
                item["known_exploited"] = bool(item.get("known_exploited"))
                try:
                    item["evidence"] = json.loads(item.get("evidence_json", "[]"))
                except Exception:
                    item["evidence"] = []
                results.append(item)
            return results

    def get_top_correlated_risks(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Returns top risk findings ranked by composite score."""
        return self.get_findings(limit=limit)

    def get_top_affected_assets(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Returns assets with highest number of correlated findings and peak risk."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT asset_id, asset_name, asset_criticality, COUNT(*) as finding_count,
                       MAX(risk_score) as max_risk_score, MAX(risk_level) as peak_risk_level
                FROM security_findings
                WHERE asset_id IS NOT NULL AND asset_id != ''
                GROUP BY asset_id, asset_name, asset_criticality
                ORDER BY max_risk_score DESC, finding_count DESC
                LIMIT ?
                """,
                (limit,),
            )
            return [
                {
                    "asset_id": r[0],
                    "asset_name": r[1],
                    "asset_criticality": r[2],
                    "finding_count": r[3],
                    "max_risk_score": r[4],
                    "peak_risk_level": r[5],
                }
                for r in cursor.fetchall()
            ]

    def get_top_vulnerabilities_with_events(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Returns CVEs most frequently associated with detected security events."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT cve_id, COUNT(*) as event_count, MAX(risk_score) as peak_risk,
                       MAX(known_exploited) as is_kev, MAX(cvss_score) as cvss
                FROM security_findings
                WHERE cve_id IS NOT NULL AND cve_id != ''
                GROUP BY cve_id
                ORDER BY event_count DESC, peak_risk DESC
                LIMIT ?
                """,
                (limit,),
            )
            return [
                {
                    "cve_id": r[0],
                    "event_count": r[1],
                    "peak_risk": r[2],
                    "is_known_exploited": bool(r[3]),
                    "cvss_score": r[4],
                }
                for r in cursor.fetchall()
            ]


# Standalone runner
def run_correlation(db_path: str = DEFAULT_DB_PATH) -> Dict[str, Any]:
    """Runs correlation engine, generates findings, and returns summary statistics."""
    engine = SecurityCorrelationEngine(db_path)
    findings = engine.correlate_all()
    top_risks = engine.get_top_correlated_risks(5)
    top_assets = engine.get_top_affected_assets(5)
    top_cves = engine.get_top_vulnerabilities_with_events(5)

    return {
        "total_findings": len(findings),
        "critical_count": sum(1 for f in findings if f["risk_level"] == "CRITICAL"),
        "high_count": sum(1 for f in findings if f["risk_level"] == "HIGH"),
        "medium_count": sum(1 for f in findings if f["risk_level"] == "MEDIUM"),
        "low_count": sum(1 for f in findings if f["risk_level"] == "LOW"),
        "top_correlated_risks": top_risks,
        "top_affected_assets": top_assets,
        "top_vulnerabilities": top_cves,
    }
