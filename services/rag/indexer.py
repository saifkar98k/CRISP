"""
CRISP Cybersecurity Platform - RAG Indexer
Phase 3 Step 1: Synchronizes SQLite Intelligence into ChromaDB Vector Collections.

Functions required:
- index_vulnerabilities()
- index_kev()
- index_nist()
- index_findings()
- index_assets()
Plus incident and aggregate indexing with idempotent upsert deduplication.
"""

import os
import sqlite3
import logging
from typing import Any, Dict, List, Optional

from services.rag.chroma_client import CRISPChromaManager, COLLECTION_NAMES
from services.rag.document_builder import (
    DocumentBuilder,
    build_vulnerability_doc,
    build_kev_doc,
    build_nist_doc,
    build_finding_doc,
    build_asset_doc,
    build_incident_doc,
    build_risk_assessment_doc,
)

logger = logging.getLogger("crisp.rag.indexer")

DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data",
    "crisp.db",
)

# Standard baseline NIST CSF 2.0 controls for fallback seeding if empty
DEFAULT_NIST_CONTROLS = [
    {
        "id": "GV.OC-01",
        "category": "Organizational Context",
        "subcategory": "Mission, objectives, and legal requirements understood",
        "function": "GOVERN",
        "score": 85.0,
        "status": "COMPLIANT",
        "findings": "Cyber risk governance framework documented and aligned with corporate risk appetites.",
        "evidence": "Executive Policy Doc #SEC-2024-GV01",
        "required_remediation": "Annual board review of cybersecurity policies.",
    },
    {
        "id": "GV.RM-01",
        "category": "Risk Management Strategy",
        "subcategory": "Risk appetite and risk management strategy established",
        "function": "GOVERN",
        "score": 80.0,
        "status": "COMPLIANT",
        "findings": "Quantitative multi-factor risk scoring protocol (CRISP) deployed across enterprise assets.",
        "evidence": "CRISP Engine Spec v2.1",
        "required_remediation": "Continuous risk threshold recalibration.",
    },
    {
        "id": "ID.AM-01",
        "category": "Asset Management",
        "subcategory": "Inventories of hardware and software managed",
        "function": "IDENTIFY",
        "score": 90.0,
        "status": "COMPLIANT",
        "findings": "All critical and high tier assets tracked in local SQLite configuration database.",
        "evidence": "Asset inventory SQLite query verify",
        "required_remediation": "Quarterly automated discovery scans.",
    },
    {
        "id": "ID.RA-01",
        "category": "Risk Assessment",
        "subcategory": "Vulnerabilities identified and evaluated against threat intelligence",
        "function": "IDENTIFY",
        "score": 65.0,
        "status": "PARTIAL",
        "findings": "NVD API integrated with CISA KEV real-time lookup. Multiple KEV items require expedited remediation.",
        "evidence": "CISA KEV live cross-reference feed",
        "required_remediation": "Prioritize patching of CVE-2024-3400 and CVE-2024-21887 on external gateways.",
    },
    {
        "id": "PR.AA-01",
        "category": "Identity Management & Access Control",
        "subcategory": "Identities and credentials asserted and managed",
        "function": "PROTECT",
        "score": 75.0,
        "status": "PARTIAL",
        "findings": "MFA enforced on VPN gateways; legacy credential reuse attempts observed on DMZ bastion.",
        "evidence": "Identity Provider SAML/OIDC Audit",
        "required_remediation": "Enforce hardware FIDO2 tokens on DMZ bastion jump host.",
    },
    {
        "id": "PR.PS-01",
        "category": "Platform Security",
        "subcategory": "Configuration and vulnerability management programs maintained",
        "function": "PROTECT",
        "score": 55.0,
        "status": "NON_COMPLIANT",
        "findings": "CISA KEV remediation deadlines approaching for perimeter VPN appliance and edge web proxy.",
        "evidence": "CISA Binding Operational Directive 22-01 Tracker",
        "required_remediation": "Immediate emergency maintenance window to apply hotfix patches within 7 calendar days.",
    },
    {
        "id": "DE.CM-01",
        "category": "Continuous Monitoring",
        "subcategory": "Networks and physical environments monitored for cybersecurity events",
        "function": "DETECT",
        "score": 85.0,
        "status": "COMPLIANT",
        "findings": "Network intrusion detection sensors streaming events into CRISP normalization pipeline.",
        "evidence": "Live telemetry ingestion log table",
        "required_remediation": "Expand sensor coverage to remote branch tunnels.",
    },
    {
        "id": "DE.AE-01",
        "category": "Adverse Event Analysis",
        "subcategory": "Anomalies and security events analyzed against threat intelligence",
        "function": "DETECT",
        "score": 80.0,
        "status": "COMPLIANT",
        "findings": "Automated correlation between incoming telemetry and active CVEs.",
        "evidence": "Suricata signature cross-correlator",
        "required_remediation": "Refine anomaly baseline heuristics.",
    },
    {
        "id": "RS.MA-01",
        "category": "Incident Management",
        "subcategory": "Incidents handled and triaged in accordance with operational procedures",
        "function": "RESPOND",
        "score": 70.0,
        "status": "PARTIAL",
        "findings": "High and Critical severity events automatically generate containment action proposals.",
        "evidence": "Incident triage queue table",
        "required_remediation": "Automate SOAR webhook isolation for active C2 detections.",
    },
    {
        "id": "RC.RP-01",
        "category": "Recovery Planning",
        "subcategory": "Recovery processes and procedures maintained",
        "function": "RECOVER",
        "score": 78.0,
        "status": "COMPLIANT",
        "findings": "Immutable database snapshot verified for core financial ledger server.",
        "evidence": "Disaster Recovery Runbook #DR-FIN-08",
        "required_remediation": "Conduct quarterly simulated tabletop restoration drill.",
    },
]


class CRISPIndexer:
    """
    Coordinates indexing of cybersecurity domain records into ChromaDB vector collections.
    Uses deterministic IDs and upsert semantics to prevent unwanted duplication.
    """

    def __init__(self, db_path: Optional[str] = None, persist_dir: Optional[str] = None):
        self.db_path = db_path or os.environ.get("CRISP_DB_PATH", DEFAULT_DB_PATH)
        self.chroma_mgr = CRISPChromaManager.get_instance(persist_directory=persist_dir)

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def index_vulnerabilities(
        self,
        limit: Optional[int] = None,
        batch_size: int = 50,
        only_uncataloged: bool = False,
    ) -> Dict[str, Any]:
        """
        Indexes vulnerability records into the 'vulnerabilities' collection.
        If limit is None, indexes all records.
        Deduplication: Uses 'vuln:{cve_id}' IDs with collection.upsert().
        """
        collection = self.chroma_mgr.get_collection("vulnerabilities")
        conn = self._get_connection()
        try:
            cur = conn.cursor()
            query = "SELECT * FROM vulnerabilities"
            params: List[Any] = []
            if only_uncataloged:
                query += " WHERE known_exploited = 0 OR known_exploited IS NULL"

            # Prioritize CVEs with CVSS scores or associated with assets
            query += " ORDER BY CASE WHEN cvss_score IS NOT NULL THEN cvss_score ELSE 0 END DESC"
            if limit is not None and limit > 0:
                query += " LIMIT ?"
                params.append(limit)

            cur.execute(query, params)
            rows = [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

        if not rows:
            return {"status": "SUCCESS", "indexed_count": 0, "collection": collection.name}

        total_indexed = 0
        for i in range(0, len(rows), batch_size):
            batch = rows[i : i + batch_size]
            ids: List[str] = []
            docs: List[str] = []
            metas: List[Dict[str, Any]] = []

            for record in batch:
                doc_id, doc_text, meta = build_vulnerability_doc(record)
                if doc_id and doc_text:
                    ids.append(doc_id)
                    docs.append(doc_text)
                    metas.append(meta)

            if ids:
                collection.upsert(ids=ids, documents=docs, metadatas=metas)
                total_indexed += len(ids)

        return {
            "status": "SUCCESS",
            "indexed_count": total_indexed,
            "collection": collection.name,
            "total_in_collection": collection.count(),
        }

    def index_kev(
        self,
        limit: Optional[int] = None,
        batch_size: int = 50,
    ) -> Dict[str, Any]:
        """
        Indexes CISA Known Exploited Vulnerability records into the 'vulnerabilities' collection
        (with document_type='kev' and source='CISA_KEV').
        Deduplication: Uses 'kev:{cve_id}' IDs with collection.upsert().
        """
        collection = self.chroma_mgr.get_collection("vulnerabilities")
        conn = self._get_connection()
        try:
            cur = conn.cursor()
            query = (
                "SELECT * FROM vulnerabilities WHERE known_exploited = 1 "
                "ORDER BY kev_date_added DESC"
            )
            params: List[Any] = []
            if limit is not None and limit > 0:
                query += " LIMIT ?"
                params.append(limit)

            cur.execute(query, params)
            rows = [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

        if not rows:
            return {"status": "SUCCESS", "indexed_count": 0, "collection": collection.name}

        total_indexed = 0
        for i in range(0, len(rows), batch_size):
            batch = rows[i : i + batch_size]
            ids: List[str] = []
            docs: List[str] = []
            metas: List[Dict[str, Any]] = []

            for record in batch:
                doc_id, doc_text, meta = build_kev_doc(record)
                if doc_id and doc_text:
                    ids.append(doc_id)
                    docs.append(doc_text)
                    metas.append(meta)

            if ids:
                collection.upsert(ids=ids, documents=docs, metadatas=metas)
                total_indexed += len(ids)

        return {
            "status": "SUCCESS",
            "indexed_count": total_indexed,
            "collection": collection.name,
            "total_in_collection": collection.count(),
        }

    def index_nist(self) -> Dict[str, Any]:
        """
        Indexes NIST Cybersecurity Framework (CSF 2.0) controls into 'nist' collection.
        Reads from 'nist_controls' table in SQLite; if missing or empty, seeds default controls.
        Deduplication: Uses 'nist:{control_id}' IDs with collection.upsert().
        """
        collection = self.chroma_mgr.get_collection("nist")
        conn = self._get_connection()
        rows: List[Dict[str, Any]] = []
        try:
            cur = conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS nist_controls (
                    id TEXT PRIMARY KEY,
                    category TEXT,
                    subcategory TEXT,
                    function TEXT,
                    score REAL,
                    status TEXT,
                    findings TEXT,
                    required_remediation TEXT,
                    evidence TEXT
                )
                """
            )
            conn.commit()

            cur.execute("SELECT * FROM nist_controls ORDER BY id ASC")
            db_rows = [dict(r) for r in cur.fetchall()]

            if not db_rows:
                # Seed default controls into SQLite for persistent consistency
                cur.executemany(
                    """
                    INSERT OR REPLACE INTO nist_controls (
                        id, category, subcategory, function, score, status,
                        findings, required_remediation, evidence
                    ) VALUES (
                        :id, :category, :subcategory, :function, :score, :status,
                        :findings, :required_remediation, :evidence
                    )
                    """,
                    DEFAULT_NIST_CONTROLS,
                )
                conn.commit()
                cur.execute("SELECT * FROM nist_controls ORDER BY id ASC")
                db_rows = [dict(r) for r in cur.fetchall()]

            rows = db_rows
        finally:
            conn.close()

        ids: List[str] = []
        docs: List[str] = []
        metas: List[Dict[str, Any]] = []

        for record in rows:
            doc_id, doc_text, meta = build_nist_doc(record)
            if doc_id and doc_text:
                ids.append(doc_id)
                docs.append(doc_text)
                metas.append(meta)

        if ids:
            collection.upsert(ids=ids, documents=docs, metadatas=metas)

        return {
            "status": "SUCCESS",
            "indexed_count": len(ids),
            "collection": collection.name,
            "total_in_collection": collection.count(),
        }

    def index_findings(self, limit: Optional[int] = None) -> Dict[str, Any]:
        """
        Indexes correlated security findings into the 'findings' collection.
        Deduplication: Uses 'finding:{finding_id}' IDs with collection.upsert().
        """
        collection = self.chroma_mgr.get_collection("findings")
        conn = self._get_connection()
        try:
            cur = conn.cursor()
            # Verify table exists
            cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='security_findings'"
            )
            if not cur.fetchone():
                return {"status": "SUCCESS", "indexed_count": 0, "collection": collection.name}

            query = "SELECT * FROM security_findings ORDER BY risk_score DESC"
            params: List[Any] = []
            if limit is not None and limit > 0:
                query += " LIMIT ?"
                params.append(limit)

            cur.execute(query, params)
            rows = [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

        ids: List[str] = []
        docs: List[str] = []
        metas: List[Dict[str, Any]] = []

        for record in rows:
            doc_id, doc_text, meta = build_finding_doc(record)
            if doc_id and doc_text:
                ids.append(doc_id)
                docs.append(doc_text)
                metas.append(meta)

        if ids:
            collection.upsert(ids=ids, documents=docs, metadatas=metas)

        return {
            "status": "SUCCESS",
            "indexed_count": len(ids),
            "collection": collection.name,
            "total_in_collection": collection.count(),
        }

    def index_assets(self) -> Dict[str, Any]:
        """
        Indexes enterprise asset registry records into the 'assets' collection.
        Deduplication: Uses 'asset:{asset_id}' IDs with collection.upsert().
        """
        collection = self.chroma_mgr.get_collection("assets")
        conn = self._get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='assets'"
            )
            if not cur.fetchone():
                return {"status": "SUCCESS", "indexed_count": 0, "collection": collection.name}

            cur.execute("SELECT * FROM assets ORDER BY criticality DESC")
            rows = [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

        ids: List[str] = []
        docs: List[str] = []
        metas: List[Dict[str, Any]] = []

        for record in rows:
            doc_id, doc_text, meta = build_asset_doc(record)
            if doc_id and doc_text:
                ids.append(doc_id)
                docs.append(doc_text)
                metas.append(meta)

        if ids:
            collection.upsert(ids=ids, documents=docs, metadatas=metas)

        return {
            "status": "SUCCESS",
            "indexed_count": len(ids),
            "collection": collection.name,
            "total_in_collection": collection.count(),
        }

    def index_incidents(self, limit: Optional[int] = 50) -> Dict[str, Any]:
        """
        Indexes security event telemetry and incidents into the 'incidents' collection.
        Deduplication: Uses 'incident:{event_id}' IDs with collection.upsert().
        """
        collection = self.chroma_mgr.get_collection("incidents")
        conn = self._get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='security_events'"
            )
            if not cur.fetchone():
                return {"status": "SUCCESS", "indexed_count": 0, "collection": collection.name}

            query = (
                "SELECT * FROM security_events "
                "ORDER BY CASE WHEN severity = 'CRITICAL' THEN 1 WHEN severity = 'HIGH' THEN 2 ELSE 3 END, "
                "timestamp DESC"
            )
            params: List[Any] = []
            if limit is not None and limit > 0:
                query += " LIMIT ?"
                params.append(limit)

            cur.execute(query, params)
            rows = [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

        ids: List[str] = []
        docs: List[str] = []
        metas: List[Dict[str, Any]] = []

        for record in rows:
            doc_id, doc_text, meta = build_incident_doc(record)
            if doc_id and doc_text:
                ids.append(doc_id)
                docs.append(doc_text)
                metas.append(meta)

        if ids:
            collection.upsert(ids=ids, documents=docs, metadatas=metas)

        return {
            "status": "SUCCESS",
            "indexed_count": len(ids),
            "collection": collection.name,
            "total_in_collection": collection.count(),
        }

    def index_risk_assessments(self, limit: Optional[int] = 50) -> Dict[str, Any]:
        """
        Indexes risk history evaluations into the 'findings' collection.
        Deduplication: Uses 'risk:{id}' IDs with collection.upsert().
        """
        collection = self.chroma_mgr.get_collection("findings")
        conn = self._get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='risk_history'"
            )
            if not cur.fetchone():
                return {"status": "SUCCESS", "indexed_count": 0, "collection": collection.name}

            query = "SELECT * FROM risk_history ORDER BY id DESC"
            params: List[Any] = []
            if limit is not None and limit > 0:
                query += " LIMIT ?"
                params.append(limit)

            cur.execute(query, params)
            rows = [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

        ids: List[str] = []
        docs: List[str] = []
        metas: List[Dict[str, Any]] = []

        for record in rows:
            doc_id, doc_text, meta = build_risk_assessment_doc(record)
            if doc_id and doc_text:
                ids.append(doc_id)
                docs.append(doc_text)
                metas.append(meta)

        if ids:
            collection.upsert(ids=ids, documents=docs, metadatas=metas)

        return {
            "status": "SUCCESS",
            "indexed_count": len(ids),
            "collection": collection.name,
            "total_in_collection": collection.count(),
        }

    def index_all(
        self,
        vuln_limit: Optional[int] = 50,
        kev_limit: Optional[int] = 50,
        incident_limit: Optional[int] = 50,
    ) -> Dict[str, Any]:
        """
        Runs synchronization across all knowledge base categories.
        """
        res_vuln = self.index_vulnerabilities(limit=vuln_limit)
        res_kev = self.index_kev(limit=kev_limit)
        res_nist = self.index_nist()
        res_findings = self.index_findings()
        res_assets = self.index_assets()
        res_incidents = self.index_incidents(limit=incident_limit)
        res_risk = self.index_risk_assessments(limit=50)

        total_indexed = (
            res_vuln.get("indexed_count", 0)
            + res_kev.get("indexed_count", 0)
            + res_nist.get("indexed_count", 0)
            + res_findings.get("indexed_count", 0)
            + res_assets.get("indexed_count", 0)
            + res_incidents.get("indexed_count", 0)
            + res_risk.get("indexed_count", 0)
        )

        return {
            "status": "SUCCESS",
            "total_indexed": total_indexed,
            "details": {
                "vulnerabilities": res_vuln,
                "kev": res_kev,
                "nist": res_nist,
                "findings": res_findings,
                "assets": res_assets,
                "incidents": res_incidents,
                "risk_assessments": res_risk,
            },
            "collection_stats": self.chroma_mgr.get_collection_stats(),
        }

    def get_index_stats(self) -> Dict[str, Any]:
        """Returns stats for all Chroma collections."""
        return self.chroma_mgr.get_collection_stats()


# Standalone module-level functions as specified in user requirements:
# index_vulnerabilities(), index_kev(), index_nist(), index_findings(), index_assets()
_default_indexer: Optional[CRISPIndexer] = None


def _get_default_indexer() -> CRISPIndexer:
    global _default_indexer
    if _default_indexer is None:
        _default_indexer = CRISPIndexer()
    return _default_indexer


def index_vulnerabilities(
    limit: Optional[int] = None,
    batch_size: int = 50,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    indexer = CRISPIndexer(db_path=db_path) if db_path else _get_default_indexer()
    return indexer.index_vulnerabilities(limit=limit, batch_size=batch_size)


def index_kev(
    limit: Optional[int] = None,
    batch_size: int = 50,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    indexer = CRISPIndexer(db_path=db_path) if db_path else _get_default_indexer()
    return indexer.index_kev(limit=limit, batch_size=batch_size)


def index_nist(db_path: Optional[str] = None) -> Dict[str, Any]:
    indexer = CRISPIndexer(db_path=db_path) if db_path else _get_default_indexer()
    return indexer.index_nist()


def index_findings(
    limit: Optional[int] = None,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    indexer = CRISPIndexer(db_path=db_path) if db_path else _get_default_indexer()
    return indexer.index_findings(limit=limit)


def index_assets(db_path: Optional[str] = None) -> Dict[str, Any]:
    indexer = CRISPIndexer(db_path=db_path) if db_path else _get_default_indexer()
    return indexer.index_assets()


def index_incidents(
    limit: Optional[int] = 50,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    indexer = CRISPIndexer(db_path=db_path) if db_path else _get_default_indexer()
    return indexer.index_incidents(limit=limit)


def index_all(
    vuln_limit: Optional[int] = 50,
    kev_limit: Optional[int] = 50,
    incident_limit: Optional[int] = 50,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    indexer = CRISPIndexer(db_path=db_path) if db_path else _get_default_indexer()
    return indexer.index_all(
        vuln_limit=vuln_limit,
        kev_limit=kev_limit,
        incident_limit=incident_limit,
    )


def get_index_stats() -> Dict[str, Any]:
    return _get_default_indexer().get_index_stats()
