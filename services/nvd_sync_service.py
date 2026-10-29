"""
CRISP Cybersecurity Platform - NVD Synchronization Service
Orchestrates polling, normalization, SQLite persistence, caching, and statistics calculation.
"""

import json
import logging
import os
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional

from services.providers.nvd_provider import NVDDataProvider, normalize_nvd_cve

logger = logging.getLogger("CRISP.NVDSync")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] [CRISP.Sync] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

DEFAULT_DB_PATH = os.path.join("data", "crisp.db")


def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """Initializes SQLite tables for storing vulnerabilities and sync caching metadata."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        # Vulnerabilities table with unique cve_id constraint
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
                source TEXT DEFAULT 'NVD',
                exploit_available INTEGER,
                patch_available INTEGER,
                status TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )

        # Ensure backwards-compatible columns exist on existing databases
        cols = [r[1] for r in cursor.execute("PRAGMA table_info(vulnerabilities)").fetchall()]
        for col_name, col_type in [
            ("exploit_available", "INTEGER DEFAULT 0"),
            ("patch_available", "INTEGER DEFAULT 0"),
            ("status", "TEXT DEFAULT 'PUBLISHED'"),
        ]:
            if col_name not in cols:
                cursor.execute(f"ALTER TABLE vulnerabilities ADD COLUMN {col_name} {col_type}")

        # Index for efficient lookups
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);
            """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_vuln_source ON vulnerabilities(source);
            """
        )

        # Metadata table for caching last sync timestamp & status
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS nvd_sync_metadata (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                last_sync_timestamp TEXT NOT NULL,
                connection_status TEXT NOT NULL,
                last_fetched INTEGER DEFAULT 0,
                last_inserted INTEGER DEFAULT 0,
                last_updated INTEGER DEFAULT 0,
                last_failed INTEGER DEFAULT 0,
                total_stored INTEGER DEFAULT 0
            );
            """
        )
        conn.commit()


def get_nvd_sync_status(db_path: str = DEFAULT_DB_PATH) -> Dict[str, Any]:
    """Retrieves current NVD sync status and database metrics."""
    init_db(db_path)
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE source = 'NVD'")
        total_nvd = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        total_all = cursor.fetchone()[0]

        cursor.execute(
            """
            SELECT last_sync_timestamp, connection_status, last_fetched,
                   last_inserted, last_updated, last_failed
            FROM nvd_sync_metadata WHERE id = 1
            """
        )
        row = cursor.fetchone()

        if row:
            return {
                "connection": row[1],
                "last_synchronization": row[0],
                "total_nvd_vulnerabilities": total_nvd,
                "total_all_vulnerabilities": total_all,
                "last_stats": {
                    "fetched": row[2],
                    "inserted": row[3],
                    "updated": row[4],
                    "failed": row[5],
                },
            }
        else:
            return {
                "connection": "Not Synced",
                "last_synchronization": None,
                "total_nvd_vulnerabilities": total_nvd,
                "total_all_vulnerabilities": total_all,
                "last_stats": {"fetched": 0, "inserted": 0, "updated": 0, "failed": 0},
            }


def sync_nvd(
    provider: Optional[NVDDataProvider] = None,
    db_path: str = DEFAULT_DB_PATH,
    resultsPerPage: int = 20,
    startIndex: int = 0,
    keyword: Optional[str] = None,
    cve_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Executes an NVD synchronization cycle:
    1. Call NVD provider
    2. Validate response
    3. Normalize records
    4. Insert/update SQLite (preventing duplicate CVEs)
    5. Return synchronization statistics:
       {"fetched": X, "inserted": Y, "updated": Z, "failed": W}
    """
    logger.info("NVD synchronization started")
    init_db(db_path)

    is_default_provider = provider is None
    if provider is None:
        provider = NVDDataProvider()

    # Step 1: Call NVD provider
    raw_response = provider.get_cves(
        startIndex=startIndex,
        resultsPerPage=resultsPerPage,
        keyword=keyword,
        cve_id=cve_id,
    )

    now_iso = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    # Step 2: Validate response
    failed_val = 1 if is_default_provider else 0
    if not isinstance(raw_response, dict):
        logger.error("NVD error: Response is not a valid dictionary")
        _record_sync_meta(db_path, now_iso, "Error", 0, 0, 0, failed_val)
        return {"fetched": 0, "inserted": 0, "updated": 0, "failed": failed_val, "error": "Invalid response format", "status": "Error"}

    if "error" in raw_response:
        err = raw_response["error"]
        logger.error(f"NVD error: {err}")
        _record_sync_meta(db_path, now_iso, "Error", 0, 0, 0, failed_val)
        return {"fetched": 0, "inserted": 0, "updated": 0, "failed": failed_val, "error": err, "status": "Error"}

    raw_vulns = raw_response.get("vulnerabilities", [])
    fetched_count = len(raw_vulns)
    logger.info(f"NVD records received: {fetched_count}")

    if fetched_count == 0:
        logger.info("NVD synchronization completed: 0 records fetched")
        _record_sync_meta(db_path, now_iso, "Connected", 0, 0, 0, 0)
        return {"fetched": 0, "inserted": 0, "updated": 0, "failed": 0}

    # Step 3: Normalize records
    normalized_records: List[Dict[str, Any]] = []
    failed_count = 0

    for item in raw_vulns:
        try:
            norm = normalize_nvd_cve(item)
            normalized_records.append(norm)
        except Exception as norm_err:
            logger.error(f"NVD normalization error: {norm_err}")
            failed_count += 1

    logger.info(f"NVD normalization completed: {len(normalized_records)} normalized, {failed_count} failed")

    # Step 4: Insert/update SQLite (Handle duplicates)
    inserted_count = 0
    updated_count = 0

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        for rec in normalized_records:
            cid = rec["cve_id"]
            cursor.execute("SELECT cve_id FROM vulnerabilities WHERE cve_id = ?", (cid,))
            existing = cursor.fetchone()

            cwe_json = json.dumps(rec["cwe"])
            prod_json = json.dumps(rec["affected_products"])
            ref_json = json.dumps(rec["references"])

            if existing:
                # Update existing record
                cursor.execute(
                    """
                    UPDATE vulnerabilities SET
                        description = ?,
                        cvss_score = ?,
                        severity = ?,
                        published_date = ?,
                        modified_date = ?,
                        cwe = ?,
                        affected_products = ?,
                        references_json = ?,
                        source = ?,
                        status = ?,
                        updated_at = ?
                    WHERE cve_id = ?
                    """,
                    (
                        rec["description"],
                        rec["cvss_score"],
                        rec["severity"],
                        rec["published_date"],
                        rec["modified_date"],
                        cwe_json,
                        prod_json,
                        ref_json,
                        rec["source"],
                        rec["status"],
                        now_iso,
                        cid,
                    ),
                )
                updated_count += 1
            else:
                # Insert new record
                cursor.execute(
                    """
                    INSERT INTO vulnerabilities (
                        cve_id, description, cvss_score, severity, published_date,
                        modified_date, cwe, affected_products, references_json,
                        source, exploit_available, patch_available, status,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        cid,
                        rec["description"],
                        rec["cvss_score"],
                        rec["severity"],
                        rec["published_date"],
                        rec["modified_date"],
                        cwe_json,
                        prod_json,
                        ref_json,
                        rec["source"],
                        rec["exploit_available"],
                        rec["patch_available"],
                        rec["status"],
                        now_iso,
                        now_iso,
                    ),
                )
                inserted_count += 1

        conn.commit()

    logger.info(f"Database insert/update: {inserted_count} inserted, {updated_count} updated")

    # Step 5: Update metadata cache
    _record_sync_meta(
        db_path,
        now_iso,
        "Connected",
        fetched_count,
        inserted_count,
        updated_count,
        failed_count,
    )

    logger.info("NVD synchronization completed")

    return {
        "fetched": fetched_count,
        "inserted": inserted_count,
        "updated": updated_count,
        "failed": failed_count,
        "timestamp": now_iso,
        "status": "Connected",
    }


def _record_sync_meta(
    db_path: str,
    timestamp: str,
    status: str,
    fetched: int,
    inserted: int,
    updated: int,
    failed: int,
) -> None:
    """Updates the single caching metadata row."""
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE source = 'NVD'")
        total = cursor.fetchone()[0]

        cursor.execute(
            """
            INSERT OR REPLACE INTO nvd_sync_metadata (
                id, last_sync_timestamp, connection_status,
                last_fetched, last_inserted, last_updated, last_failed, total_stored
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?)
            """,
            (timestamp, status, fetched, inserted, updated, failed, total),
        )
        conn.commit()


def get_vulnerabilities(
    db_path: str = DEFAULT_DB_PATH,
    limit: int = 50,
    offset: int = 0,
    source: Optional[str] = None,
    severity: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Retrieves normalized vulnerability records from SQLite."""
    init_db(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = "SELECT * FROM vulnerabilities WHERE 1=1"
        params: List[Any] = []

        if source:
            query += " AND source = ?"
            params.append(source)
        if severity and severity != "ALL":
            query += " AND severity = ?"
            params.append(severity)

        query += " ORDER BY cvss_score DESC, published_date DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        rows = cursor.fetchall()

        results = []
        for r in rows:
            results.append(
                {
                    "cve_id": r["cve_id"],
                    "description": r["description"],
                    "cvss_score": r["cvss_score"],
                    "severity": r["severity"],
                    "published_date": r["published_date"],
                    "modified_date": r["modified_date"],
                    "cwe": json.loads(r["cwe"] or "[]"),
                    "affected_products": json.loads(r["affected_products"] or "[]"),
                    "references": json.loads(r["references_json"] or "[]"),
                    "source": r["source"],
                    "exploit_available": r["exploit_available"],
                    "patch_available": r["patch_available"],
                    "status": r["status"],
                    "created_at": r["created_at"],
                    "updated_at": r["updated_at"],
                }
            )
        return results
