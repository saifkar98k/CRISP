"""
CRISP Agent Swarm 2.0 - Controlled Python Tools
Provides safe, controlled access to existing CRISP services and SQLite data.
Strictly read-only for security inspection: no arbitrary shell execution, no arbitrary SQL, no raw file write access.
Includes auditable persistence for investigation history in SQLite.
"""

import os
import json
import sqlite3
import logging
from typing import Any, Dict, List, Optional

from services.security_event_service import (
    get_security_events_filtered,
    get_attacks_by_category,
    get_attacks_by_severity,
    get_top_source_ips,
    get_top_destination_ports,
    get_protocol_distribution,
)
from services.correlation_engine import SecurityCorrelationEngine
from services.nvd_sync_service import get_vulnerabilities, get_nvd_sync_status
from services.cisa_kev_sync_service import (
    get_known_exploited_vulnerabilities,
    get_cisa_kev_sync_status,
)
from services.risk_engine import (
    calculate_final_risk,
    get_risk_history,
    get_risk_over_time_trend,
)
from services.rag.retriever import retrieve, CRISPRetriever
from services.rag.indexer import DEFAULT_NIST_CONTROLS

logger = logging.getLogger("CRISP.AgentTools")
DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data",
    "crisp.db",
)


def _get_read_only_connection() -> sqlite3.Connection:
    """Returns a read-only SQLite database connection."""
    db_path = os.environ.get("CRISP_DB_PATH", DEFAULT_DB_PATH)
    if os.path.exists(db_path):
        uri = f"file:{os.path.abspath(db_path)}?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
    else:
        conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _get_write_connection() -> sqlite3.Connection:
    """Returns a write connection specifically for auditable investigation history persistence."""
    db_path = os.environ.get("CRISP_DB_PATH", DEFAULT_DB_PATH)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


# =============================================================================
# 1. Threat Intelligence & Security Event Tools
# =============================================================================

def tool_query_security_events(
    dataset_source: Optional[str] = None,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    protocol: Optional[str] = None,
    limit: int = 25,
) -> List[Dict[str, Any]]:
    """Controlled query tool for security events and telemetry."""
    limit = max(1, min(limit, 100))
    try:
        events = get_security_events_filtered(
            dataset_source=dataset_source,
            attack_category=category,
            severity=severity,
            protocol=protocol,
            limit=limit,
            offset=0,
        )
        return events or []
    except Exception as e:
        logger.warning(f"tool_query_security_events failed: {e}")
        return []


def tool_get_security_event_by_id(event_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves an exact security event by its event_id."""
    if not event_id:
        return None
    try:
        conn = _get_read_only_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM security_events WHERE event_id = ? LIMIT 1", (event_id.strip(),))
            row = cur.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()
    except Exception as e:
        logger.warning(f"tool_get_security_event_by_id failed for {event_id}: {e}")
        return None


def tool_get_event_analytics() -> Dict[str, Any]:
    """Retrieves aggregated analytics across security event telemetry."""
    try:
        return {
            "by_category": get_attacks_by_category() or {},
            "by_severity": get_attacks_by_severity() or {},
            "top_source_ips": get_top_source_ips(limit=10) or [],
            "top_dest_ports": get_top_destination_ports(limit=10) or [],
            "protocol_distribution": get_protocol_distribution() or {},
        }
    except Exception as e:
        logger.warning(f"tool_get_event_analytics failed: {e}")
        return {
            "by_category": {},
            "by_severity": {},
            "top_source_ips": [],
            "top_dest_ports": [],
            "protocol_distribution": {},
        }


def tool_get_correlated_findings(
    risk_level: Optional[str] = None,
    asset_id: Optional[str] = None,
    cve_id: Optional[str] = None,
    limit: int = 25,
) -> List[Dict[str, Any]]:
    """Retrieves correlated security findings matching target parameters."""
    limit = max(1, min(limit, 50))
    try:
        engine = SecurityCorrelationEngine()
        return engine.get_findings(
            risk_level=risk_level,
            asset_id=asset_id,
            cve_id=cve_id,
            limit=limit,
        ) or []
    except Exception as e:
        logger.warning(f"tool_get_correlated_findings failed: {e}")
        return []


def tool_get_finding_by_id(finding_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a specific security finding by its finding_id."""
    if not finding_id:
        return None
    try:
        conn = _get_read_only_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM security_findings WHERE finding_id = ? LIMIT 1", (finding_id.strip(),))
            row = cur.fetchone()
            if row:
                d = dict(row)
                if d.get("evidence_json"):
                    try:
                        d["evidence"] = json.loads(d["evidence_json"])
                    except Exception:
                        d["evidence"] = []
                return d
            return None
        finally:
            conn.close()
    except Exception as e:
        logger.warning(f"tool_get_finding_by_id failed for {finding_id}: {e}")
        return None


# =============================================================================
# 2. Vulnerability Intelligence Tools
# =============================================================================

def tool_query_vulnerabilities(
    cve_id: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 25,
) -> List[Dict[str, Any]]:
    """Retrieves normalized NVD CVE vulnerabilities from the persistent catalog."""
    limit = max(1, min(limit, 50))
    try:
        if cve_id:
            conn = _get_read_only_connection()
            try:
                cur = conn.cursor()
                cur.execute(
                    "SELECT * FROM vulnerabilities WHERE UPPER(cve_id) = UPPER(?) OR cve_id LIKE ? LIMIT ?",
                    (cve_id.strip(), f"%{cve_id.strip()}%", limit),
                )
                rows = [dict(r) for r in cur.fetchall()]
                return rows
            finally:
                conn.close()
        else:
            return get_vulnerabilities(limit=limit, offset=0, severity=severity or "ALL") or []
    except Exception as e:
        logger.warning(f"tool_query_vulnerabilities failed: {e}")
        return []


def tool_query_cisa_kev(
    search: Optional[str] = None,
    vendor: Optional[str] = None,
    product: Optional[str] = None,
    limit: int = 25,
) -> List[Dict[str, Any]]:
    """Queries CISA Known Exploited Vulnerabilities (KEV) catalog."""
    limit = max(1, min(limit, 50))
    try:
        return get_known_exploited_vulnerabilities(
            limit=limit,
            offset=0,
            vendor=vendor,
            product=product,
            search=search,
        ) or []
    except Exception as e:
        logger.warning(f"tool_query_cisa_kev failed: {e}")
        return []


def tool_get_vulnerability_summary(cve_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves deep merged vulnerability intelligence for a specific CVE."""
    if not cve_id:
        return None
    try:
        vulns = tool_query_vulnerabilities(cve_id=cve_id, limit=1)
        if not vulns:
            # Fall back to KEV search
            kevs = tool_query_cisa_kev(search=cve_id, limit=1)
            if kevs:
                k = kevs[0]
                return {
                    "id": k.get("cve_id"),
                    "cve_id": k.get("cve_id"),
                    "title": k.get("vulnerability_name", k.get("cve_id")),
                    "description": k.get("short_description", ""),
                    "cvss_score": None,
                    "severity": "CRITICAL",
                    "is_known_exploited": True,
                    "cisa_due_date": k.get("due_date"),
                    "cisa_action": k.get("required_action"),
                    "cisa_ransomware_use": k.get("ransomware_use", "Unknown"),
                    "affected_products": [k.get("product")] if k.get("product") else [],
                    "references": [],
                    "source": "CISA_KEV",
                }
            return None

        v = vulns[0]
        is_kev = bool(v.get("is_known_exploited") or v.get("known_exploited"))
        refs = []
        if v.get("references_json"):
            try:
                refs = json.loads(v["references_json"])
            except Exception:
                refs = []

        affected = []
        if v.get("affected_products"):
            try:
                affected = json.loads(v["affected_products"]) if isinstance(v["affected_products"], str) and v["affected_products"].startswith("[") else [v["affected_products"]]
            except Exception:
                affected = [str(v["affected_products"])]

        cid = v.get("cve_id") or v.get("id") or cve_id
        return {
            "id": cid,
            "cve_id": cid,
            "title": v.get("title") or cid,
            "description": v.get("description", ""),
            "cvss_score": v.get("cvss_score"),
            "severity": v.get("severity", "UNKNOWN"),
            "is_known_exploited": is_kev,
            "cisa_due_date": v.get("cisa_due_date") or v.get("kev_due_date"),
            "cisa_action": v.get("cisa_action") or v.get("kev_required_action"),
            "cisa_ransomware_use": v.get("cisa_ransomware_use") or v.get("kev_ransomware_use"),
            "affected_products": affected,
            "cwe": v.get("cwe"),
            "references": refs,
            "source": v.get("source", "NVD"),
        }
    except Exception as e:
        logger.warning(f"tool_get_vulnerability_summary failed for {cve_id}: {e}")
        return None


def tool_find_assets_affected_by_cve(cve_id: str) -> List[Dict[str, Any]]:
    """Finds all assets associated with a specific CVE."""
    if not cve_id:
        return []
    try:
        conn = _get_read_only_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM assets WHERE associated_cves LIKE ?", (f"%{cve_id.strip()}%",))
            return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()
    except Exception as e:
        logger.warning(f"tool_find_assets_affected_by_cve failed for {cve_id}: {e}")
        return []


# =============================================================================
# 3. Asset Risk Tools
# =============================================================================

def tool_list_assets(criticality: Optional[str] = None, limit: int = 25, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Lists enterprise assets with tier, network exposure, mapped services, and tenant isolation."""
    limit = max(1, min(limit, 50))
    try:
        conn = _get_read_only_connection()
        try:
            cur = conn.cursor()
            if criticality and criticality != "ALL":
                cur.execute(
                    "SELECT * FROM assets WHERE UPPER(criticality) = UPPER(?) LIMIT ?",
                    (criticality.strip(), limit),
                )
            else:
                cur.execute("SELECT * FROM assets LIMIT ?", (limit,))
            rows = [dict(r) for r in cur.fetchall()]
            if tenant_id:
                # Enforce tenant isolation boundary
                rows = [r for r in rows if r.get("tenant_id") in (None, "", tenant_id)]
            return rows
        finally:
            conn.close()
    except Exception as e:
        logger.warning(f"tool_list_assets failed: {e}")
        return []


def tool_get_asset(
    asset_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Retrieves an enterprise asset by Asset ID or IP address with tenant boundary enforcement."""
    if not asset_id and not ip_address:
        return None
    try:
        conn = _get_read_only_connection()
        try:
            cur = conn.cursor()
            if asset_id:
                cur.execute(
                    "SELECT * FROM assets WHERE UPPER(id) = UPPER(?) OR name = ? OR id LIKE ? LIMIT 1",
                    (asset_id.strip(), asset_id.strip(), f"%{asset_id.strip()}%"),
                )
            elif ip_address:
                cur.execute(
                    "SELECT * FROM assets WHERE ip_address = ? OR secondary_ips LIKE ? LIMIT 1",
                    (ip_address.strip(), f"%{ip_address.strip()}%"),
                )
            row = cur.fetchone()
            if not row:
                return None
            res = dict(row)
            if tenant_id:
                asset_tenant = res.get("tenant_id")
                if not asset_tenant or asset_tenant != tenant_id:
                    logger.warning(f"Unauthorized cross-tenant access blocked: tenant '{tenant_id}' cannot view asset '{asset_id}'")
                    return None
            return res
        finally:
            conn.close()
    except Exception as e:
        logger.warning(f"tool_get_asset failed: {e}")
        return None


def tool_get_asset_details(asset_identifier: str, tenant_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Resolves an asset by identifier (ID, hostname, or IP) with tenant guard."""
    if not asset_identifier:
        return None
    asset = tool_get_asset(asset_id=asset_identifier, tenant_id=tenant_id)
    if not asset:
        asset = tool_get_asset(ip_address=asset_identifier, tenant_id=tenant_id)
    return asset


def tool_get_asset_risk_history(asset_name_or_id: str) -> List[Dict[str, Any]]:
    """Retrieves historical risk assessments for a specific asset."""
    if not asset_name_or_id:
        return []
    try:
        conn = _get_read_only_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM risk_history WHERE asset LIKE ? OR asset = ? ORDER BY timestamp DESC LIMIT 10",
                (f"%{asset_name_or_id.strip()}%", asset_name_or_id.strip()),
            )
            return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()
    except Exception as e:
        logger.warning(f"tool_get_asset_risk_history failed: {e}")
        return []


def tool_get_asset_events(asset_ip: Optional[str], asset_id: Optional[str], limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves security telemetry events targeting or originating from an asset."""
    limit = max(1, min(limit, 100))
    try:
        conn = _get_read_only_connection()
        try:
            cur = conn.cursor()
            conditions = []
            params = []
            if asset_ip:
                conditions.append("(destination_ip = ? OR source_ip = ?)")
                params.extend([asset_ip, asset_ip])
            if asset_id:
                conditions.append("asset_id = ?")
                params.append(asset_id)
            if not conditions:
                return []
            where_sql = " OR ".join(conditions)
            cur.execute(f"SELECT * FROM security_events WHERE {where_sql} ORDER BY timestamp DESC LIMIT ?", (*params, limit))
            return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()
    except Exception as e:
        logger.warning(f"tool_get_asset_events failed: {e}")
        return []


def tool_attribute_event_to_asset(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Attributes a security event to an enterprise asset based on destination or source IP."""
    if not event:
        return None
    dest_ip = event.get("destination_ip")
    src_ip = event.get("source_ip")
    asset_id = event.get("asset_id")

    if asset_id:
        asset = tool_get_asset(asset_id=asset_id)
        if asset:
            return {"asset": asset, "attribution_confidence": 0.95, "role": "TARGET"}

    if dest_ip:
        asset = tool_get_asset(ip_address=dest_ip)
        if asset:
            return {"asset": asset, "attribution_confidence": 0.90, "role": "TARGET"}

    if src_ip:
        asset = tool_get_asset(ip_address=src_ip)
        if asset:
            return {"asset": asset, "attribution_confidence": 0.75, "role": "SOURCE"}

    return None


def tool_calculate_risk(
    cvss_score: Optional[float] = None,
    cisa_kev_status: bool = False,
    asset_criticality: Optional[str] = None,
    asset_exposure: Optional[str] = None,
    event_severity: Optional[str] = None,
    attack_frequency: int = 1,
    timestamp: Optional[str] = None,
    vuln_status: Optional[str] = "OPEN",
    exploit_available: bool = False,
    patch_available: bool = False,
) -> Dict[str, Any]:
    """Evaluates explainable multi-factor risk score (0-100) using CRISP's Risk Engine."""
    try:
        return calculate_final_risk(
            cvss_score=cvss_score,
            cisa_kev_status=cisa_kev_status,
            asset_criticality=asset_criticality,
            asset_exposure=asset_exposure,
            event_severity=event_severity,
            attack_frequency=attack_frequency,
            vulnerability_status=vuln_status,
            patch_availability=patch_available,
            recency_timestamp=timestamp,
        )
    except Exception as e:
        logger.warning(f"tool_calculate_risk failed: {e}")
        return {
            "score": 0.0,
            "risk_level": "LOW",
            "explanation": f"Calculation failed: {e}",
            "factors": [],
            "error": str(e),
        }


# =============================================================================
# 4. Compliance Tools (NIST CSF 2.0)
# =============================================================================

def tool_query_nist_controls(
    function: Optional[str] = None,
    status: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Retrieves NIST CSF 2.0 controls, scores, status, and remediation requirements."""
    try:
        conn = _get_read_only_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='nist_controls'")
            has_table = cur.fetchone()
            if has_table:
                query = "SELECT * FROM nist_controls WHERE 1=1"
                params: List[Any] = []
                if function and function != "ALL":
                    query += " AND UPPER(function) = UPPER(?)"
                    params.append(function.strip())
                if status and status != "ALL":
                    query += " AND UPPER(status) = UPPER(?)"
                    params.append(status.strip())
                query += " ORDER BY id ASC"
                cur.execute(query, params)
                rows = [dict(r) for r in cur.fetchall()]
                if rows:
                    return rows
        finally:
            conn.close()

        controls = list(DEFAULT_NIST_CONTROLS)
        if function and function != "ALL":
            controls = [c for c in controls if c.get("function", "").upper() == function.strip().upper()]
        if status and status != "ALL":
            controls = [c for c in controls if c.get("status", "").upper() == status.strip().upper()]
        return controls
    except Exception as e:
        logger.warning(f"tool_query_nist_controls failed: {e}")
        return list(DEFAULT_NIST_CONTROLS)


# =============================================================================
# 5. Evidence & RAG Retrieval Tools
# =============================================================================

def tool_rag_search(
    query: str,
    collection: Optional[str] = None,
    filters: Optional[Dict[str, Any]] = None,
    n_results: int = 5,
) -> List[Dict[str, Any]]:
    """Queries ChromaDB vector knowledge base across CRISP collections."""
    if not query:
        return []
    n_results = max(1, min(n_results, 15))
    try:
        res = retrieve(
            query=query,
            filters=filters,
            n_results=n_results,
            collection=collection,
        )
        if isinstance(res, list):
            return res
        return []
    except Exception as e:
        logger.warning(f"tool_rag_search failed: {e}")
        return []


# =============================================================================
# 6. Investigation History Persistence Tools
# =============================================================================

def tool_persist_investigation(investigation: Dict[str, Any]) -> bool:
    """
    Persists an executed investigation into the investigation_history table.
    Ensures full auditability and traceability of all swarm findings.
    """
    try:
        conn = _get_write_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS investigation_history (
                    investigation_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    query TEXT NOT NULL,
                    workflow_type TEXT NOT NULL,
                    target_id TEXT,
                    overall_risk_rating TEXT,
                    overall_risk_score REAL,
                    verification_status TEXT,
                    executive_summary TEXT,
                    report_json TEXT,
                    duration_ms REAL,
                    created_at TEXT
                );
                """
            )
            # Serialize report JSON safely
            report_data = {
                "investigation_id": investigation.get("investigation_id"),
                "workflow_type": investigation.get("workflow_type"),
                "targets": investigation.get("targets"),
                "threat_intel": investigation.get("threat_intel"),
                "vuln_intel": investigation.get("vuln_intel"),
                "asset_risk": investigation.get("asset_risk"),
                "compliance": investigation.get("compliance"),
                "evidence": investigation.get("evidence"),
                "verification": investigation.get("verification"),
                "confirmed_findings": investigation.get("confirmed_findings"),
                "hypotheses": investigation.get("hypotheses"),
                "missing_evidence": investigation.get("missing_evidence"),
                "citations": investigation.get("citations"),
                "recommended_actions": investigation.get("recommended_actions"),
            }

            primary_target = investigation.get("targets", {}).get("primary_target_id")
            if not primary_target:
                cves = investigation.get("targets", {}).get("cve_ids", [])
                assets = investigation.get("targets", {}).get("asset_ids", [])
                primary_target = cves[0] if cves else (assets[0] if assets else None)

            cur.execute(
                """
                INSERT OR REPLACE INTO investigation_history (
                    investigation_id, timestamp, query, workflow_type, target_id,
                    overall_risk_rating, overall_risk_score, verification_status,
                    executive_summary, report_json, duration_ms, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    investigation.get("investigation_id"),
                    investigation.get("created_at"),
                    investigation.get("query"),
                    investigation.get("workflow_type", "GENERAL_QUESTION"),
                    primary_target,
                    investigation.get("overall_risk_rating", "LOW"),
                    float(investigation.get("overall_risk_score", 0.0)),
                    investigation.get("verification", {}).get("status", "UNVERIFIED") if isinstance(investigation.get("verification"), dict) else "UNVERIFIED",
                    investigation.get("executive_summary", ""),
                    json.dumps(report_data),
                    float(investigation.get("duration_ms", 0.0)),
                    investigation.get("created_at"),
                ),
            )
            conn.commit()
            return True
        finally:
            conn.close()
    except Exception as e:
        logger.error(f"tool_persist_investigation failed: {e}")
        return False


def tool_get_investigation_history(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves historical investigations ordered by timestamp descending."""
    limit = max(1, min(limit, 100))
    try:
        conn = _get_read_only_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='investigation_history'")
            if not cur.fetchone():
                return []
            cur.execute(
                """
                SELECT investigation_id, timestamp, query, workflow_type, target_id,
                       overall_risk_rating, overall_risk_score, verification_status,
                       executive_summary, duration_ms, created_at
                FROM investigation_history
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (limit,),
            )
            return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()
    except Exception as e:
        logger.warning(f"tool_get_investigation_history failed: {e}")
        return []


def tool_get_investigation_by_id(investigation_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a single investigation with full report details by investigation_id."""
    if not investigation_id:
        return None
    try:
        conn = _get_read_only_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM investigation_history WHERE investigation_id = ? LIMIT 1",
                (investigation_id.strip(),),
            )
            row = cur.fetchone()
            if row:
                d = dict(row)
                if d.get("report_json"):
                    try:
                        d["report"] = json.loads(d["report_json"])
                    except Exception:
                        d["report"] = {}
                return d
            return None
        finally:
            conn.close()
    except Exception as e:
        logger.warning(f"tool_get_investigation_by_id failed for {investigation_id}: {e}")
        return None


def tool_get_remediation_plans(
    status: Optional[str] = None,
    priority: Optional[str] = None,
    asset_id: Optional[str] = None,
    cve_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Controlled read-only tool to retrieve remediation plans from SQLite."""
    try:
        from services.remediation_engine import remediation_engine
        return remediation_engine.list_plans(status=status, priority=priority, asset_id=asset_id, cve_id=cve_id)
    except Exception as e:
        logger.warning(f"tool_get_remediation_plans failed: {e}")
        return []


def tool_get_remediation_plan_by_id(remediation_id: str) -> Optional[Dict[str, Any]]:
    """Controlled read-only tool to retrieve a specific remediation plan by ID."""
    if not remediation_id:
        return None
    try:
        from services.remediation_engine import remediation_engine
        return remediation_engine.get_plan(remediation_id=remediation_id.strip())
    except Exception as e:
        logger.warning(f"tool_get_remediation_plan_by_id failed for {remediation_id}: {e}")
        return None


def tool_create_remediation_plan(
    finding_id: str,
    assigned_to: Optional[str] = None,
    user_role: str = "SOC_ANALYST",
) -> Optional[Dict[str, Any]]:
    """Controlled tool to create a structured remediation plan from a verified finding."""
    if not finding_id:
        return None
    try:
        from services.remediation_engine import remediation_engine
        return remediation_engine.create_plan_from_finding(
            finding_id=finding_id.strip(),
            assigned_to=assigned_to or "saifkar98k@gmail.com",
            creator_role=user_role,
        )
    except Exception as e:
        logger.warning(f"tool_create_remediation_plan failed for finding {finding_id}: {e}")
        return None

