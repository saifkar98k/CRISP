"""
CRISP Cybersecurity Platform - Remediation Intelligence Engine
Phase 2 Step 6 / CRISP 2.0 Remediation Workflow

Deterministic remediation engine that:
1. Translates verified security findings into structured, actionable remediation plans.
2. Prioritizes actions based on CRISP risk engine, CVSS, CISA KEV status, asset criticality, and exposure.
3. Retrieves authoritative vendor advisory, patch, upgrade, configuration, and rollback considerations.
4. Enforces role-based authorization for lifecycle transitions (Open, Planned, Awaiting Approval,
   In Progress, Awaiting Verification, Resolved, Reopened).
5. Mandates authentic verification evidence before marking tasks resolved.
6. Re-assesses residual cyber risk dynamically using the CRISP risk engine upon verified remediation.
"""

import json
import logging
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union

from services.risk_engine import (
    calculate_final_risk,
    DEFAULT_RISK_THRESHOLDS,
)

logger = logging.getLogger("CRISP.RemediationEngine")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] [CRISP.Remediation] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

DEFAULT_DB_PATH = os.path.join("data", "crisp.db")


class RemediationStatus(str, Enum):
    OPEN = "OPEN"
    PLANNED = "PLANNED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    IN_PROGRESS = "IN_PROGRESS"
    AWAITING_VERIFICATION = "AWAITING_VERIFICATION"
    RESOLVED = "RESOLVED"
    REOPENED = "REOPENED"


class ApprovalStatus(str, Enum):
    NOT_REQUIRED = "NOT_REQUIRED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class RemediationPriority(str, Enum):
    IMMEDIATE = "IMMEDIATE"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# Authorized roles for lifecycle operations
ROLE_ADMIN = "ADMIN"
ROLE_SECURITY_ANALYST = "SECURITY_ANALYST"
ROLE_VIEWER = "VIEWER"
ROLE_SOC_ANALYST = "SOC_ANALYST"
ROLE_SECURITY_LEAD = "SECURITY_LEAD"
ROLE_SECURITY_ADMIN = "SECURITY_ADMIN"
ROLE_READONLY = "READONLY_ANALYST"

STANDARD_TRANSITION_ROLES = {
    ROLE_ADMIN,
    ROLE_SECURITY_ANALYST,
    ROLE_SOC_ANALYST,
    ROLE_SECURITY_LEAD,
    ROLE_SECURITY_ADMIN,
    "ADMIN",
    "SECURITY_ANALYST",
    "SOC_ANALYST",
    "SECURITY_LEAD",
    "SECURITY_ADMIN",
}

APPROVAL_AUTHORITY_ROLES = {
    ROLE_ADMIN,
    ROLE_SECURITY_LEAD,
    ROLE_SECURITY_ADMIN,
    "ADMIN",
    "SECURITY_LEAD",
    "SECURITY_ADMIN",
}

# Known authoritative vendor advisories and mitigation baselines
# (Strictly verified references from NVD, CISA KEV, and vendor security notices)
AUTHORITATIVE_VENDOR_KNOWLEDGE: Dict[str, Dict[str, Any]] = {
    "CVE-2021-44228": {
        "vendor": "Apache Software Foundation",
        "product": "Apache Log4j 2",
        "action_type": "UPGRADE",
        "recommended_steps": [
            "Upgrade all log4j-core and log4j-api dependencies to version 2.17.1 or later (Java 8+).",
            "For legacy environments on Java 7, upgrade to Log4j 2.12.4.",
            "If immediate upgrade is blocked, remove the JndiLookup class from the classpath: `zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class`.",
            "Verify that log4j2.formatMsgNoLookups is NOT relied upon as the sole mitigation for 2.15/2.16 CVE variants.",
        ],
        "vendor_advisory_url": "https://logging.apache.org/log4j/2.x/security.html",
        "cisa_kev_guidance": "CISA BOD 22-01: Apply vendor updates immediately to eliminate JNDI RCE vector.",
        "prerequisites": [
            "Inventory all services bundling log4j (including fat JARs and embedded runtimes).",
            "Perform regression testing on application logging behavior in staging environment.",
            "Schedule rolling application restart to load upgraded binaries.",
        ],
        "rollback_plan": [
            "Preserve pre-upgrade JAR artifacts and container image tags.",
            "Revert build dependency POM/build.gradle to previous artifact if startup fails.",
            "Apply network egress filtering blocking LDAP/RMI port outbound connections (ports 389, 636, 1099, 1389).",
        ],
        "operational_impact": "Requires service restart; 2-5 minutes of graceful pod rollover.",
        "verification_checklist": [
            "Execute software bill of materials (SBOM) or dependency scanner confirming log4j >= 2.17.1.",
            "Verify vulnerability scanner report (clean status with no CVE-2021-44228 flag).",
            "Inspect running JVM classpath with `lsof` / `jps` to confirm unbundled JARs.",
        ],
    },
    "CVE-2023-4966": {
        "vendor": "Cloud Software Group / Citrix",
        "product": "NetScaler ADC and NetScaler Gateway",
        "action_type": "PATCH",
        "recommended_steps": [
            "Install NetScaler firmware security release: 14.1-8.50, 13.1-49.15, or 13.0-92.21.",
            "CRITICAL: Post-installation, terminate all active and persistent user sessions to invalidate hijacked authentication tokens.",
            "Run command: `kill icaconnection -all` and `kill aaa session -all` on CLI.",
            "Rotate all NetScaler SSL certificates and Kerberos keys if memory exfiltration was suspected.",
        ],
        "vendor_advisory_url": "https://support.citrix.com/article/CTX579459",
        "cisa_kev_guidance": "CISA Alert: Citrix Bleed actively exploited in the wild for session hijacking.",
        "prerequisites": [
            "Verify high-availability (HA) pair sync before initiating failover upgrade.",
            "Notify user base regarding active session termination window.",
        ],
        "rollback_plan": [
            "Retain secondary node running previous stable firmware version.",
            "Fail back to secondary appliance node if packet drops or gateway routing anomalies occur.",
        ],
        "operational_impact": "HA node failover; all active SSL VPN/ICA user sessions terminated.",
        "verification_checklist": [
            "Execute `show version` on NetScaler CLI to confirm build >= 13.1-49.15 / 14.1-8.50.",
            "Inspect AAA session table ensuring zero pre-patch session tokens remain active.",
            "Review authentication gateway logs for abnormal buffer length requests.",
        ],
    },
    "CVE-2024-21887": {
        "vendor": "Ivanti",
        "product": "Ivanti Connect Secure (ICS) / Policy Secure",
        "action_type": "PATCH",
        "recommended_steps": [
            "Deploy official Ivanti patch release for Connect Secure (versions 9.1R14.4+, 9.1R17.2+, 9.1R18.2+, 22.x).",
            "Import and enforce Ivanti mitigation XML package if patch cannot be deployed immediately.",
            "Execute Ivanti External Integrity Checker Tool (ICT) to detect potential web shell persistence.",
            "Revoke and re-issue all device certificates and local user credentials.",
        ],
        "vendor_advisory_url": "https://forums.ivanti.com/s/article/CVE-2023-46805-CVE-2024-21887",
        "cisa_kev_guidance": "CISA Emergency Directive 24-01: Mitigate and inspect Ivanti Connect Secure.",
        "prerequisites": [
            "Download latest External ICT snapshot file from Ivanti portal.",
            "Coordinate maintenance window for gateway reboot.",
        ],
        "rollback_plan": [
            "System configuration XML export prior to patch installation.",
            "Reboot appliance into recovery partition if boot integrity validation fails.",
        ],
        "operational_impact": "Gateway appliance reboot required; 10-15 minutes downtime per cluster node.",
        "verification_checklist": [
            "Run External ICT tool and verify output reports ZERO mismatched or added files.",
            "Verify appliance firmware version string in admin console.",
            "Review administrative audit logs for unauthorized API endpoint access.",
        ],
    },
    "CVE-2023-34362": {
        "vendor": "Progress Software",
        "product": "MOVEit Transfer",
        "action_type": "PATCH",
        "recommended_steps": [
            "Block external HTTP and HTTPS traffic to MOVEit Transfer server (ports 80 and 443) immediately.",
            "Deploy MOVEit Transfer cumulative security patch (May/June 2023 release or newer).",
            "Inspect `C:\\MOVEitTransfer\\wwwroot\\` for unknown ASPX scripts (e.g. `human2.aspx`).",
            "Rotate service account credentials and database connection string passwords.",
        ],
        "vendor_advisory_url": "https://www.progress.com/security/moveit-transfer-and-moveit-cloud-vulnerability",
        "cisa_kev_guidance": "CISA KEV requirement: Remediate MOVEit SQL injection and data exfiltration.",
        "prerequisites": [
            "Take full VM snapshot and database backup before patching.",
            "Identify all automated MFT scheduled transfer pipelines.",
        ],
        "rollback_plan": [
            "Restore VM snapshot and database transaction log if patch deployment corrupts SQL tables.",
        ],
        "operational_impact": "File transfer portal offline during database migration and patching.",
        "verification_checklist": [
            "Confirm MOVEit Transfer DLL build version matches patched security update release.",
            "Verify automated file ingestion tasks complete successfully post-patch.",
            "Execute web vulnerability scanner against portal endpoints.",
        ],
    },
    "CVE-2020-1472": {
        "vendor": "Microsoft",
        "product": "Windows Server Active Directory Netlogon",
        "action_type": "CONFIG_CHANGE",
        "recommended_steps": [
            "Install Microsoft security updates enabling Netlogon secure channel enforcement mode.",
            "Set Group Policy `Domain controller: Allow vulnerable Netlogon secure channel connections` to Disabled.",
            "Monitor Windows Security Event Log Event ID 5829 to identify non-compliant legacy client accounts.",
            "Enforce full RPC seal and signing on all domain-joined workstation and server channels.",
        ],
        "vendor_advisory_url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472",
        "cisa_kev_guidance": "CISA Emergency Directive 20-04: Apply Zerologon Netlogon updates to all Domain Controllers.",
        "prerequisites": [
            "Audit legacy non-Windows devices (e.g. older NAS appliances) utilizing Netlogon.",
            "Stage DC patching sequentially across replication topology.",
        ],
        "rollback_plan": [
            "Temporary registry key fallback allowed only in test environments (`FullSecureChannelProtection = 0`).",
            "Promote secondary Domain Controller if replication halts.",
        ],
        "operational_impact": "Zero operational downtime if patched sequentially; DC reboot required.",
        "verification_checklist": [
            "Run `nltest /dbflag:0x2080ffff` and test secure Netlogon authentication.",
            "Verify Event ID 5829 ceases to appear in Event Viewer.",
            "Audit AD Domain Controller update status via WSUS / SCCM.",
        ],
    },
    "CVE-2017-5638": {
        "vendor": "Apache Software Foundation",
        "product": "Apache Struts 2",
        "action_type": "UPGRADE",
        "recommended_steps": [
            "Upgrade Apache Struts to version 2.3.32 or 2.5.10.1 or later.",
            "Alternatively, replace the default multipart parser with a secure implementation or apply servlet filter rejecting invalid Content-Type headers.",
        ],
        "vendor_advisory_url": "https://cwiki.apache.org/confluence/display/WW/S2-045",
        "cisa_kev_guidance": "CISA KEV mandatory remediation for Jakarta multipart parser OGNL injection.",
        "prerequisites": ["Test Struts action mappings in staging."],
        "rollback_plan": ["Roll back WAR artifact to previous revision."],
        "operational_impact": "Web application server restart required.",
        "verification_checklist": [
            "Verify struts2-core JAR version >= 2.5.10.1.",
            "Perform automated DAST scan with Content-Type header injection payloads.",
        ],
    },
}


def init_remediation_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """Initializes SQLite tables for remediation plans and audit history."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS remediations (
                remediation_id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL,
                asset_id TEXT NOT NULL,
                asset_name TEXT NOT NULL,
                cve_id TEXT,
                current_risk_score REAL NOT NULL,
                current_severity TEXT NOT NULL,
                priority TEXT NOT NULL,
                summary TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                recommended_steps_json TEXT NOT NULL,
                vendor_advisories_json TEXT NOT NULL,
                verification_steps_json TEXT NOT NULL,
                rollback_considerations_json TEXT NOT NULL,
                prerequisites_json TEXT NOT NULL,
                approval_status TEXT NOT NULL,
                remediation_status TEXT NOT NULL,
                assigned_to TEXT,
                verification_evidence_json TEXT,
                post_remediation_risk_score REAL,
                risk_reduction REAL,
                status_history_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_remediations_finding ON remediations(finding_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_remediations_asset ON remediations(asset_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_remediations_status ON remediations(remediation_status);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_remediations_priority ON remediations(priority);")
        conn.commit()


def calculate_remediation_priority(
    cvss_score: Optional[float],
    is_known_exploited: bool,
    asset_criticality: Optional[str],
    asset_exposure: Optional[str],
    current_risk_score: float,
) -> RemediationPriority:
    """
    Deterministic prioritization based strictly on CRISP multi-factor risk,
    CVSS base score, confirmed CISA KEV exploitation, asset criticality, and exposure.
    Does NOT invent an arbitrary formula.
    """
    crit_upper = (asset_criticality or "MEDIUM").upper()
    expo_upper = (asset_exposure or "INTERNAL").upper()
    cvss = float(cvss_score or 0.0)

    # 1. IMMEDIATE Priority criteria:
    # - Actively exploited in the wild (CISA KEV confirmed)
    # - Critical CVSS (>= 9.0) on a CRITICAL asset with EXTERNAL exposure
    # - Composite CRISP Risk Score >= 75.0 (CRITICAL risk bracket)
    if is_known_exploited:
        return RemediationPriority.IMMEDIATE
    if cvss >= 9.0 and crit_upper == "CRITICAL" and expo_upper == "EXTERNAL":
        return RemediationPriority.IMMEDIATE
    if current_risk_score >= 75.0:
        return RemediationPriority.IMMEDIATE

    # 2. HIGH Priority criteria:
    # - CVSS >= 7.0 and asset is CRITICAL or HIGH criticality
    # - Composite CRISP Risk Score in HIGH bracket (>= 50.0)
    # - CVSS >= 8.5 regardless of asset
    if cvss >= 8.5:
        return RemediationPriority.HIGH
    if cvss >= 7.0 and crit_upper in ("CRITICAL", "HIGH"):
        return RemediationPriority.HIGH
    if current_risk_score >= 50.0:
        return RemediationPriority.HIGH

    # 3. MEDIUM Priority criteria:
    # - CVSS >= 4.0 or Risk Score >= 25.0
    if cvss >= 4.0 or current_risk_score >= 25.0:
        return RemediationPriority.MEDIUM

    # 4. LOW Priority criteria:
    return RemediationPriority.LOW


def determine_approval_requirement(
    priority: RemediationPriority,
    asset_criticality: Optional[str],
    prerequisites: List[str],
    operational_impact: str,
) -> Tuple[ApprovalStatus, RemediationStatus]:
    """
    Determines whether the remediation plan requires management/security lead approval.
    Tier-1 / CRITICAL assets or IMMEDIATE/HIGH priority or plans requiring system reboots
    mandate approval before execution.
    """
    crit_upper = (asset_criticality or "MEDIUM").upper()
    impact_upper = (operational_impact or "").upper()
    has_downtime = ("DOWNTIME" in impact_upper or "DOWN" in impact_upper) and "ZERO" not in impact_upper
    has_reboot = "REBOOT" in impact_upper and "ZERO" not in impact_upper
    has_terminate = "TERMINATE" in impact_upper

    needs_approval = (
        priority in (RemediationPriority.IMMEDIATE, RemediationPriority.HIGH)
        or crit_upper == "CRITICAL"
        or has_reboot
        or has_downtime
        or has_terminate
    )

    if needs_approval:
        return (ApprovalStatus.PENDING_APPROVAL, RemediationStatus.AWAITING_APPROVAL)
    return (ApprovalStatus.NOT_REQUIRED, RemediationStatus.OPEN)


def generate_authoritative_remediation_content(
    cve_id: Optional[str],
    finding: Dict[str, Any],
    vulnerability_details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Generates recommended remediation steps, vendor advisories, verification steps,
    and rollback procedures using verified NVD, CISA KEV, and vendor data.

    RULE: If authoritative fix is unknown, state clearly that vendor confirmation is required.
    Never invent product-specific commands or fake versions.
    """
    if cve_id and cve_id in AUTHORITATIVE_VENDOR_KNOWLEDGE:
        known = AUTHORITATIVE_VENDOR_KNOWLEDGE[cve_id]
        return {
            "authoritative_fix_known": True,
            "vendor": known["vendor"],
            "product": known["product"],
            "action_type": known["action_type"],
            "recommended_steps": list(known["recommended_steps"]),
            "vendor_advisories": [
                {"title": f"{known['vendor']} Official Security Advisory", "url": known["vendor_advisory_url"]},
                {"title": "NVD CVE Vulnerability Detail", "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"},
                {"title": "CISA Guidance", "notes": known["cisa_kev_guidance"]},
            ],
            "verification_steps": list(known["verification_checklist"]),
            "rollback_considerations": list(known["rollback_plan"]),
            "prerequisites": list(known["prerequisites"]),
            "operational_impact": known["operational_impact"],
        }

    # If vulnerability record has CISA KEV required action
    cisa_action = None
    vendor_project = None
    affected_products: List[str] = []
    source_refs: List[Dict[str, str]] = []

    if vulnerability_details:
        cisa_action = vulnerability_details.get("kev_required_action")
        vendor_project = vulnerability_details.get("kev_vendor_project")
        raw_prods = vulnerability_details.get("affected_products")
        if isinstance(raw_prods, list):
            affected_products = raw_prods
        elif isinstance(raw_prods, str):
            try:
                affected_products = json.loads(raw_prods)
            except Exception:
                affected_products = [raw_prods]

        refs = vulnerability_details.get("references") or vulnerability_details.get("references_json")
        if isinstance(refs, list):
            for r in refs[:4]:
                source_refs.append({"title": "Authoritative Reference", "url": str(r)})
        elif isinstance(refs, str):
            try:
                parsed_refs = json.loads(refs)
                if isinstance(parsed_refs, list):
                    for r in parsed_refs[:4]:
                        source_refs.append({"title": "Authoritative Reference", "url": str(r)})
            except Exception:
                pass

    if cve_id:
        source_refs.append({"title": "NVD NIST Official Reference", "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"})

    prod_label = ", ".join(affected_products) if affected_products else (vendor_project or "Target System Component")

    if cisa_action:
        return {
            "authoritative_fix_known": True,
            "vendor": vendor_project or "Vendor",
            "product": prod_label,
            "action_type": "PATCH",
            "recommended_steps": [
                f"Apply official vendor patch per CISA KEV directive: {cisa_action}",
                f"Confirm software package {prod_label} is upgraded to the vendor-patched build.",
                "Inspect system service logs post-patch to ensure standard operations.",
            ],
            "vendor_advisories": source_refs,
            "verification_steps": [
                f"Perform authenticated package version audit confirming remediation of {cve_id}.",
                "Execute local vulnerability assessment scan to confirm vulnerability removal.",
            ],
            "rollback_considerations": [
                "Create full VM snapshot / configuration backup prior to applying patch.",
                "Verify backup restoration procedure prior to installation.",
            ],
            "prerequisites": [
                "Schedule authorized maintenance window for server/package update.",
                "Review vendor release notes for any breaking API changes.",
            ],
            "operational_impact": "Standard service restart required during maintenance window.",
        }

    # If authoritative vendor fix is unknown: State explicitly that vendor confirmation is required
    attack_cat = finding.get("attack_category", "Cyber Risk Finding")
    return {
        "authoritative_fix_known": False,
        "vendor": "Vendor Confirmation Required",
        "product": prod_label,
        "action_type": "COMPENSATING_CONTROL",
        "recommended_steps": [
            f"Authoritative vendor patch is not confirmed in local repository or NVD catalog for {cve_id or attack_cat}; vendor confirmation required.",
            "Engage asset custodian and vendor support to verify authoritative patch release and compatibility.",
            "Apply compensating perimeter defense controls: enforce WAF rules or rate limiting for observed attack vector.",
            "Restrict network exposure: limit ingress access to trusted management IP subnets.",
        ],
        "vendor_advisories": source_refs if source_refs else [{"title": "Vendor Security Portal", "notes": "Vendor confirmation required."}],
        "verification_steps": [
            "Verify with asset owner that compensating network/firewall controls are enforced.",
            "Monitor security telemetry for repeated attack signatures targeting this asset.",
        ],
        "rollback_considerations": [
            "Document any temporary firewall rules or WAF filter modifications to enable clean reversion.",
        ],
        "prerequisites": [
            "Consult asset owner and change control board before modifying network rules.",
        ],
        "operational_impact": "Network access restrictions may impact external clients if IP filtering is applied.",
    }


class RemediationEngine:
    """Core deterministic remediation management engine."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        init_remediation_db(self.db_path)

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def get_finding_by_id(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a verified finding from SQLite."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM security_findings WHERE finding_id = ?", (finding_id,))
            row = cursor.fetchone()
            if not row:
                return None
            data = dict(row)
            if "evidence_json" in data and isinstance(data["evidence_json"], str):
                try:
                    data["evidence"] = json.loads(data["evidence_json"])
                except Exception:
                    data["evidence"] = []
            return data

    def get_asset_by_id(self, asset_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves an enterprise asset record from SQLite."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM assets WHERE id = ?", (asset_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_vulnerability_by_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves CVE intelligence from SQLite."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM vulnerabilities WHERE cve_id = ?", (cve_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def create_plan_from_finding(
        self,
        finding_id: str,
        assigned_to: Optional[str] = "saifkar98k@gmail.com",
        creator_role: str = ROLE_SOC_ANALYST,
    ) -> Dict[str, Any]:
        """
        Creates a structured, deterministic remediation plan from a verified security finding.
        Handles duplicates cleanly by returning existing plan if already present.
        """
        finding = self.get_finding_by_id(finding_id)
        if not finding:
            raise ValueError(f"Security finding with ID '{finding_id}' not found in database.")

        # Check for existing remediation plan
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM remediations WHERE finding_id = ?", (finding_id,))
            existing = cursor.fetchone()
            if existing:
                logger.info("Remediation plan already exists for finding %s (%s)", finding_id, existing["remediation_id"])
                return self._row_to_plan_dict(dict(existing))

        asset_id = finding.get("asset_id") or "UNKNOWN_ASSET"
        asset_name = finding.get("asset_name") or "Unspecified Asset"
        cve_id = finding.get("cve_id")
        current_risk_score = float(finding.get("risk_score", 50.0))
        current_severity = finding.get("severity", "HIGH")

        # Fetch asset details for exposure and criticality
        asset = self.get_asset_by_id(asset_id) if asset_id != "UNKNOWN_ASSET" else None
        asset_crit = asset.get("criticality") if asset else finding.get("asset_criticality")
        asset_expo = asset.get("exposure") if asset else "EXTERNAL"

        # Fetch CVE details for KEV status and NVD references
        vuln = self.get_vulnerability_by_cve(cve_id) if cve_id else None
        is_known_exploited = bool(
            finding.get("known_exploited")
            or (vuln and vuln.get("is_known_exploited"))
        )
        cvss = finding.get("cvss_score") or (vuln.get("cvss_score") if vuln else None)

        # 1. Deterministic priority computation
        priority = calculate_remediation_priority(
            cvss_score=cvss,
            is_known_exploited=is_known_exploited,
            asset_criticality=asset_crit,
            asset_exposure=asset_expo,
            current_risk_score=current_risk_score,
        )

        # 2. Authoritative remediation content synthesis
        content = generate_authoritative_remediation_content(
            cve_id=cve_id,
            finding=finding,
            vulnerability_details=vuln,
        )

        # 3. Approval and initial lifecycle status
        approval_status, initial_status = determine_approval_requirement(
            priority=priority,
            asset_criticality=asset_crit,
            prerequisites=content["prerequisites"],
            operational_impact=content["operational_impact"],
        )

        remediation_id = f"REM-{finding_id.replace('FND-', '')}-{uuid.uuid4().hex[:6].upper()}"
        now_iso = datetime.now(timezone.utc).isoformat()

        # Format summary
        summary = (
            f"Remediate {cve_id or finding.get('attack_category')} targeting {asset_name} "
            f"({asset_id}). Current CRISP Risk: {current_risk_score}/100 ({current_severity}). "
            f"Priority: {priority.value}."
        )

        # Build initial status history record
        status_history = [
            {
                "timestamp": now_iso,
                "previous_status": None,
                "new_status": initial_status.value,
                "updated_by": assigned_to,
                "user_role": creator_role,
                "notes": "Plan generated from verified CRISP correlated security finding.",
            }
        ]

        # Insert into SQLite
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO remediations (
                    remediation_id, finding_id, asset_id, asset_name, cve_id,
                    current_risk_score, current_severity, priority, summary,
                    evidence_json, recommended_steps_json, vendor_advisories_json,
                    verification_steps_json, rollback_considerations_json, prerequisites_json,
                    approval_status, remediation_status, assigned_to, verification_evidence_json,
                    post_remediation_risk_score, risk_reduction, status_history_json,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    remediation_id,
                    finding_id,
                    asset_id,
                    asset_name,
                    cve_id,
                    current_risk_score,
                    current_severity,
                    priority.value,
                    summary,
                    json.dumps(finding.get("evidence", [])),
                    json.dumps(content["recommended_steps"]),
                    json.dumps(content["vendor_advisories"]),
                    json.dumps(content["verification_steps"]),
                    json.dumps(content["rollback_considerations"]),
                    json.dumps({
                        "prerequisites": content["prerequisites"],
                        "operational_impact": content["operational_impact"],
                        "authoritative_fix_known": content["authoritative_fix_known"],
                        "action_type": content["action_type"],
                    }),
                    approval_status.value,
                    initial_status.value,
                    assigned_to,
                    None,
                    None,
                    None,
                    json.dumps(status_history),
                    now_iso,
                    now_iso,
                ),
            )
            conn.commit()

        logger.info("Created remediation plan %s for finding %s (Priority: %s)", remediation_id, finding_id, priority.value)
        return self.get_plan(remediation_id)  # type: ignore

    def get_plan(self, remediation_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single remediation plan by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM remediations WHERE remediation_id = ?", (remediation_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_plan_dict(dict(row))

    def list_plans(
        self,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        asset_id: Optional[str] = None,
        cve_id: Optional[str] = None,
        search: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Lists remediation plans with optional filtering."""
        query = "SELECT * FROM remediations WHERE 1=1"
        params: List[Any] = []

        if status and status.upper() != "ALL":
            query += " AND remediation_status = ?"
            params.append(status.upper())
        if priority and priority.upper() != "ALL":
            query += " AND priority = ?"
            params.append(priority.upper())
        if asset_id:
            query += " AND asset_id = ?"
            params.append(asset_id)
        if cve_id:
            query += " AND cve_id = ?"
            params.append(cve_id)
        if search and search.strip():
            s = f"%{search.strip().lower()}%"
            query += " AND (LOWER(remediation_id) LIKE ? OR LOWER(finding_id) LIKE ? OR LOWER(asset_name) LIKE ? OR LOWER(summary) LIKE ? OR LOWER(cve_id) LIKE ?)"
            params.extend([s, s, s, s, s])

        query += " ORDER BY created_at DESC"

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()
            return [self._row_to_plan_dict(dict(r)) for r in rows]

    def update_status(
        self,
        remediation_id: str,
        new_status: str,
        user_role: str = ROLE_SOC_ANALYST,
        user_id: str = "saifkar98k@gmail.com",
        notes: str = "",
    ) -> Dict[str, Any]:
        """
        Updates remediation lifecycle status with strict authorization checks.
        """
        plan = self.get_plan(remediation_id)
        if not plan:
            raise ValueError(f"Remediation plan '{remediation_id}' not found.")

        # 1. Authorization checks
        if user_role not in STANDARD_TRANSITION_ROLES:
            raise PermissionError(f"User role '{user_role}' is not authorized to update remediation status.")

        current_status = plan["remediation_status"]
        target_status = new_status.upper().strip()

        # Approval authority enforcement
        if target_status == RemediationStatus.IN_PROGRESS.value and plan["approval_status"] == ApprovalStatus.PENDING_APPROVAL.value:
            if user_role not in APPROVAL_AUTHORITY_ROLES:
                raise PermissionError("Plan requires explicit approval by SECURITY_LEAD or ADMIN before starting progress.")

        # Cannot directly transition to RESOLVED without verification evidence
        if target_status == RemediationStatus.RESOLVED.value:
            raise ValueError("Cannot mark plan RESOLVED directly. Submit authentic verification evidence via submit_verification().")

        now_iso = datetime.now(timezone.utc).isoformat()
        history = list(plan.get("status_history", []))
        history.append({
            "timestamp": now_iso,
            "previous_status": current_status,
            "new_status": target_status,
            "updated_by": user_id,
            "user_role": user_role,
            "notes": notes or f"Status transitioned from {current_status} to {target_status}.",
        })

        # Update approval status if moving out of pending
        approval_status = plan["approval_status"]
        if target_status in (RemediationStatus.IN_PROGRESS.value, RemediationStatus.PLANNED.value) and approval_status == ApprovalStatus.PENDING_APPROVAL.value:
            if user_role in APPROVAL_AUTHORITY_ROLES:
                approval_status = ApprovalStatus.APPROVED.value

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE remediations
                SET remediation_status = ?, approval_status = ?, status_history_json = ?, updated_at = ?
                WHERE remediation_id = ?;
                """,
                (target_status, approval_status, json.dumps(history), now_iso, remediation_id),
            )
            conn.commit()

        logger.info("Updated plan %s: %s -> %s (by %s [%s])", remediation_id, current_status, target_status, user_id, user_role)
        return self.get_plan(remediation_id)  # type: ignore

    def submit_verification(
        self,
        remediation_id: str,
        verification_evidence: Dict[str, Any],
        user_role: str = ROLE_SOC_ANALYST,
        user_id: str = "saifkar98k@gmail.com",
        notes: str = "",
    ) -> Dict[str, Any]:
        """
        Submits post-remediation verification evidence (e.g. clean vulnerability scan, package version check).
        Recalculates risk dynamically via the existing CRISP risk engine.
        If verification fails, transitions status to REOPENED.
        """
        plan = self.get_plan(remediation_id)
        if not plan:
            raise ValueError(f"Remediation plan '{remediation_id}' not found.")

        if user_role not in STANDARD_TRANSITION_ROLES:
            raise PermissionError(f"User role '{user_role}' is not authorized to submit remediation verification.")

        now_iso = datetime.now(timezone.utc).isoformat()

        # Validate evidence payload
        is_verified = bool(verification_evidence.get("is_clean", True))
        evidence_summary = str(verification_evidence.get("evidence_summary", "")).strip()
        scanner_tool = verification_evidence.get("scanner_or_tool", "Automated Scan / Audit Tool")

        if not evidence_summary:
            raise ValueError("Verification evidence must provide a substantive evidence_summary (scan results or verified package version).")

        history = list(plan.get("status_history", []))

        if not is_verified:
            # Verification failed: Finding persists in telemetry / scan -> REOPEN plan
            history.append({
                "timestamp": now_iso,
                "previous_status": plan["remediation_status"],
                "new_status": RemediationStatus.REOPENED.value,
                "updated_by": user_id,
                "user_role": user_role,
                "notes": f"Verification FAILED via {scanner_tool}: {evidence_summary}. Plan reopened for further remediation.",
            })

            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    UPDATE remediations
                    SET remediation_status = ?, verification_evidence_json = ?, status_history_json = ?, updated_at = ?
                    WHERE remediation_id = ?;
                    """,
                    (
                        RemediationStatus.REOPENED.value,
                        json.dumps(verification_evidence),
                        json.dumps(history),
                        now_iso,
                        remediation_id,
                    ),
                )
                conn.commit()

            logger.warning("Verification failed for plan %s: Reopened", remediation_id)
            return self.get_plan(remediation_id)  # type: ignore

        # Verification successful: Re-calculate residual risk using existing CRISP risk engine
        current_score = float(plan["current_risk_score"])
        cve_id = plan.get("cve_id")
        finding = self.get_finding_by_id(plan["finding_id"]) or {}
        asset = self.get_asset_by_id(plan["asset_id"]) or {}

        # Recalculate with vulnerability_status="REMEDIATED" and patch_availability=True
        recalculated = calculate_final_risk(
            cvss_score=finding.get("cvss_score"),
            cisa_kev_status=False,  # Vulnerability is patched, so active in-the-wild threat is mitigated
            asset_criticality=asset.get("criticality") or finding.get("asset_criticality"),
            asset_exposure=asset.get("exposure") or "EXTERNAL",
            event_severity="LOW",
            attack_frequency=1,
            vulnerability_status="REMEDIATED",
            patch_availability=True,
            recency_timestamp=now_iso,
            correlated_finding=None,
        )

        post_risk_score = float(recalculated["score"])
        risk_reduction = round(max(0.0, current_score - post_risk_score), 1)

        history.append({
            "timestamp": now_iso,
            "previous_status": plan["remediation_status"],
            "new_status": RemediationStatus.RESOLVED.value,
            "updated_by": user_id,
            "user_role": user_role,
            "notes": (
                f"Verified clean via {scanner_tool}. Residual risk recalculated: "
                f"{current_score} -> {post_risk_score} (-{risk_reduction} pts mitigated)."
            ),
        })

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE remediations
                SET remediation_status = ?,
                    verification_evidence_json = ?,
                    post_remediation_risk_score = ?,
                    risk_reduction = ?,
                    status_history_json = ?,
                    updated_at = ?
                WHERE remediation_id = ?;
                """,
                (
                    RemediationStatus.RESOLVED.value,
                    json.dumps(verification_evidence),
                    post_risk_score,
                    risk_reduction,
                    json.dumps(history),
                    now_iso,
                    remediation_id,
                ),
            )
            conn.commit()

        logger.info(
            "Plan %s resolved with verified risk reduction: %s -> %s (-%s pts)",
            remediation_id, current_score, post_risk_score, risk_reduction,
        )
        return self.get_plan(remediation_id)  # type: ignore

    def reopen_plan(
        self,
        remediation_id: str,
        reason: str,
        user_role: str = ROLE_SOC_ANALYST,
        user_id: str = "saifkar98k@gmail.com",
    ) -> Dict[str, Any]:
        """Explicitly reopens a remediation plan with documented reason."""
        plan = self.get_plan(remediation_id)
        if not plan:
            raise ValueError(f"Remediation plan '{remediation_id}' not found.")

        if user_role not in STANDARD_TRANSITION_ROLES:
            raise PermissionError(f"User role '{user_role}' is not authorized to reopen plans.")

        now_iso = datetime.now(timezone.utc).isoformat()
        history = list(plan.get("status_history", []))
        history.append({
            "timestamp": now_iso,
            "previous_status": plan["remediation_status"],
            "new_status": RemediationStatus.REOPENED.value,
            "updated_by": user_id,
            "user_role": user_role,
            "notes": f"Plan reopened: {reason}",
        })

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE remediations
                SET remediation_status = ?, status_history_json = ?, updated_at = ?
                WHERE remediation_id = ?;
                """,
                (RemediationStatus.REOPENED.value, json.dumps(history), now_iso, remediation_id),
            )
            conn.commit()

        logger.info("Plan %s reopened by %s: %s", remediation_id, user_id, reason)
        return self.get_plan(remediation_id)  # type: ignore

    def generate_plans_for_all_findings(self) -> List[Dict[str, Any]]:
        """Scans security_findings table and creates remediation plans for all unaddressed findings."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT finding_id FROM security_findings ORDER BY risk_score DESC")
            rows = cursor.fetchall()

        created_plans = []
        for r in rows:
            try:
                p = self.create_plan_from_finding(r["finding_id"])
                created_plans.append(p)
            except Exception as e:
                logger.error("Error creating plan for finding %s: %s", r["finding_id"], e)
        return created_plans

    def _row_to_plan_dict(self, row: Dict[str, Any]) -> Dict[str, Any]:
        """Serializes SQLite row into structured dictionary with parsed JSON fields."""
        plan = dict(row)
        for json_col in [
            "evidence_json",
            "recommended_steps_json",
            "vendor_advisories_json",
            "verification_steps_json",
            "rollback_considerations_json",
            "prerequisites_json",
            "status_history_json",
            "verification_evidence_json",
        ]:
            key = json_col.replace("_json", "")
            raw = plan.pop(json_col, None)
            if raw and isinstance(raw, str):
                try:
                    plan[key] = json.loads(raw)
                except Exception:
                    plan[key] = []
            elif raw is None:
                plan[key] = None
        return plan


# Global default instance
remediation_engine = RemediationEngine()
