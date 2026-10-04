"""
CRISP Cybersecurity Platform - CISA KEV Synchronization Service
Orchestrates retrieving the CISA KEV catalog, merging with NVD records in SQLite,
updating risk flags, and calculating synchronization statistics.
"""

import json
import logging
import os
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional

from services.providers.cisa_kev_provider import CISAKEVProvider, normalize_cisa_kev

logger = logging.getLogger("CRISP.CISAKevSync")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] [CRISP.CISA_Sync] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

DEFAULT_DB_PATH = os.path.join("data", "crisp.db")


def migrate_db_for_kev(db_path: str = DEFAULT_DB_PATH) -> None:
    """Ensures existing SQLite vulnerabilities table has CISA KEV enrichment columns."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        # Check existing columns
        cursor.execute("PRAGMA table_info(vulnerabilities)")
        existing_cols = {col[1] for col in cursor.fetchall()}

        kev_columns = [
            ("known_exploited", "INTEGER DEFAULT 0"),
            ("kev_date_added", "TEXT"),
            ("kev_required_action", "TEXT"),
            ("kev_due_date", "TEXT"),
            ("kev_vendor_project", "TEXT"),
            ("kev_product", "TEXT"),
            ("kev_ransomware_use", "TEXT"),
            ("kev_notes", "TEXT"),
        ]

        for col_name, col_def in kev_columns:
            if col_name not in existing_cols:
                try:
                    cursor.execute(f"ALTER TABLE vulnerabilities ADD COLUMN {col_name} {col_def};")
                except Exception as ex:
                    logger.debug(f"Column {col_name} might already exist: {ex}")

        # Metadata table for CISA KEV synchronization cache
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS cisa_kev_sync_metadata (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                last_sync_timestamp TEXT NOT NULL,
                connection_status TEXT NOT NULL,
                total_kev_fetched INTEGER DEFAULT 0,
                matched_nvd_count INTEGER DEFAULT 0,
                new_records_count INTEGER DEFAULT 0,
                updated_records_count INTEGER DEFAULT 0,
                failed_count INTEGER DEFAULT 0,
                total_known_exploited_stored INTEGER DEFAULT 0
            );
            """
        )
        conn.commit()


def get_cisa_kev_sync_status(db_path: str = DEFAULT_DB_PATH) -> Dict[str, Any]:
    """Retrieves current CISA KEV synchronization status and record metrics."""
    migrate_db_for_kev(db_path)
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        # Count total in SQLite with known_exploited = 1
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE known_exploited = 1")
        total_exploited = cursor.fetchone()[0]

        # Count NVD records that matched KEV (source = 'NVD + CISA_KEV')
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE source = 'NVD + CISA_KEV'")
        matched_nvd = cursor.fetchone()[0]

        cursor.execute(
            """
            SELECT last_sync_timestamp, connection_status, total_kev_fetched,
                   matched_nvd_count, new_records_count, updated_records_count, failed_count
            FROM cisa_kev_sync_metadata WHERE id = 1
            """
        )
        row = cursor.fetchone()

        if row:
            return {
                "connection": row[1],
                "last_synchronization": row[0],
                "total_known_exploited_stored": total_exploited,
                "local_crisp_vulnerabilities_in_kev": matched_nvd,
                "last_stats": {
                    "fetched": row[2],
                    "matched_nvd": row[3],
                    "new_records": row[4],
                    "updated_records": row[5],
                    "failed": row[6],
                },
            }
        else:
            return {
                "connection": "Not Synced",
                "last_synchronization": None,
                "total_known_exploited_stored": total_exploited,
                "local_crisp_vulnerabilities_in_kev": matched_nvd,
                "last_stats": {
                    "fetched": 0,
                    "matched_nvd": 0,
                    "new_records": 0,
                    "updated_records": 0,
                    "failed": 0,
                },
            }


def sync_cisa_kev(
    provider: Optional[CISAKEVProvider] = None,
    db_path: str = DEFAULT_DB_PATH,
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Synchronizes the official CISA KEV catalog into the existing SQLite database:
    1. Retrieves catalog from CISA KEV provider
    2. Validates and normalizes records
    3. Merges with existing NVD records:
       - If CVE already exists (from NVD): enriches with KEV fields, sets source = 'NVD + CISA_KEV'
       - If CVE does not exist in local DB: inserts new record with source = 'CISA_KEV' (without inventing CVSS)
    4. Calculates actual operation statistics:
       {"fetched": ..., "matched_nvd": ..., "new_records": ..., "updated_records": ..., "failed": ...}
    """
    logger.info("CISA KEV synchronization started")
    migrate_db_for_kev(db_path)

    if provider is None:
        provider = CISAKEVProvider()

    raw_catalog = provider.get_catalog()
    now_iso = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    if not isinstance(raw_catalog, dict) or "error" in raw_catalog:
        err = raw_catalog.get("error", "Unknown error fetching CISA KEV")
        logger.error(f"CISA KEV sync error: {err}")
        _record_kev_meta(db_path, now_iso, "Error", 0, 0, 0, 0, 0)
        return {
            "fetched": 0,
            "matched_nvd": 0,
            "new_records": 0,
            "updated_records": 0,
            "failed": 0,
            "error": err,
            "status": "Error",
            "timestamp": now_iso,
        }

    raw_items = raw_catalog.get("vulnerabilities", [])
    if limit and isinstance(limit, int) and limit > 0:
        raw_items = raw_items[:limit]

    total_fetched = len(raw_items)
    logger.info(f"CISA KEV records fetched: {total_fetched}")

    matched_nvd_count = 0
    new_records_count = 0
    updated_records_count = 0
    failed_count = 0

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        for item in raw_items:
            try:
                norm = normalize_cisa_kev(item)
                cid = norm["cve_id"]

                # Check if CVE already exists in SQLite
                cursor.execute(
                    "SELECT cve_id, source, cvss_score, severity FROM vulnerabilities WHERE cve_id = ?",
                    (cid,),
                )
                existing = cursor.fetchone()

                if existing:
                    # Existing record found (from NVD or previous KEV sync)
                    existing_source = existing[1] or "NVD"
                    if "NVD" in existing_source and "CISA_KEV" not in existing_source:
                        merged_source = "NVD + CISA_KEV"
                        matched_nvd_count += 1
                    else:
                        merged_source = existing_source

                    cursor.execute(
                        """
                        UPDATE vulnerabilities SET
                            known_exploited = 1,
                            kev_date_added = ?,
                            kev_required_action = ?,
                            kev_due_date = ?,
                            kev_vendor_project = ?,
                            kev_product = ?,
                            kev_ransomware_use = ?,
                            kev_notes = ?,
                            source = ?,
                            updated_at = ?
                        WHERE cve_id = ?
                        """,
                        (
                            norm["date_added"],
                            norm["required_action"],
                            norm["due_date"],
                            norm["vendor_project"],
                            norm["product"],
                            norm["known_ransomware_campaign_use"],
                            norm["notes"],
                            merged_source,
                            now_iso,
                            cid,
                        ),
                    )
                    updated_records_count += 1
                else:
                    # New record (CVE does not exist in local DB yet)
                    # Insert with available CISA info; DO NOT invent CVSS score
                    products_json = json.dumps([f"{norm['vendor_project']} {norm['product']}".strip()] if norm["product"] else [])
                    cwe_json = json.dumps([])
                    refs_json = json.dumps([])

                    cursor.execute(
                        """
                        INSERT INTO vulnerabilities (
                            cve_id, description, cvss_score, severity, published_date,
                            modified_date, cwe, affected_products, references_json,
                            source, exploit_available, patch_available, status,
                            known_exploited, kev_date_added, kev_required_action,
                            kev_due_date, kev_vendor_project, kev_product,
                            kev_ransomware_use, kev_notes, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            cid,
                            norm["short_description"] or norm["vulnerability_name"],
                            None,      # No CVSS in CISA KEV; never fabricate
                            "UNKNOWN", # Severity not assigned by CISA directly
                            norm["date_added"],
                            norm["date_added"],
                            cwe_json,
                            products_json,
                            refs_json,
                            "CISA_KEV",
                            1,         # Exploit is known because it is in KEV
                            None,      # Patch availability not guaranteed
                            "Known Exploited",
                            1,
                            norm["date_added"],
                            norm["required_action"],
                            norm["due_date"],
                            norm["vendor_project"],
                            norm["product"],
                            norm["known_ransomware_campaign_use"],
                            norm["notes"],
                            now_iso,
                            now_iso,
                        ),
                    )
                    new_records_count += 1

            except Exception as item_err:
                logger.error(f"Error processing KEV record: {item_err}")
                failed_count += 1

        conn.commit()

    logger.info(
        f"CISA KEV synchronization completed: {total_fetched} fetched, "
        f"{matched_nvd_count} matched NVD, {new_records_count} new, "
        f"{updated_records_count} updated, {failed_count} failed."
    )

    _record_kev_meta(
        db_path,
        now_iso,
        "Connected",
        total_fetched,
        matched_nvd_count,
        new_records_count,
        updated_records_count,
        failed_count,
    )

    return {
        "fetched": total_fetched,
        "matched_nvd": matched_nvd_count,
        "new_records": new_records_count,
        "updated_records": updated_records_count,
        "failed": failed_count,
        "status": "Connected",
        "timestamp": now_iso,
    }


def _record_kev_meta(
    db_path: str,
    timestamp: str,
    status: str,
    fetched: int,
    matched: int,
    new_rec: int,
    updated: int,
    failed: int,
) -> None:
    """Updates the single CISA KEV metadata caching row in SQLite."""
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE known_exploited = 1")
        total_exploited = cursor.fetchone()[0]

        cursor.execute(
            """
            INSERT OR REPLACE INTO cisa_kev_sync_metadata (
                id, last_sync_timestamp, connection_status, total_kev_fetched,
                matched_nvd_count, new_records_count, updated_records_count,
                failed_count, total_known_exploited_stored
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (timestamp, status, fetched, matched, new_rec, updated, failed, total_exploited),
        )
        conn.commit()


def get_known_exploited_vulnerabilities(
    db_path: str = DEFAULT_DB_PATH,
    limit: int = 50,
    offset: int = 0,
    vendor: Optional[str] = None,
    product: Optional[str] = None,
    search: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Queries vulnerabilities marked as known_exploited = 1 with optional filters."""
    migrate_db_for_kev(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = "SELECT * FROM vulnerabilities WHERE known_exploited = 1"
        params: List[Any] = []

        if vendor:
            query += " AND (kev_vendor_project LIKE ? OR affected_products LIKE ?)"
            params.extend([f"%{vendor}%", f"%{vendor}%"])

        if product:
            query += " AND (kev_product LIKE ? OR affected_products LIKE ?)"
            params.extend([f"%{product}%", f"%{product}%"])

        if search:
            query += " AND (cve_id LIKE ? OR kev_vendor_project LIKE ? OR kev_product LIKE ? OR description LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%", f"%{search}%", f"%{search}%"])

        query += " ORDER BY kev_date_added DESC, cvss_score DESC LIMIT ? OFFSET ?"
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
                    "known_exploited": bool(r["known_exploited"]),
                    "kev_date_added": r["kev_date_added"],
                    "kev_required_action": r["kev_required_action"],
                    "kev_due_date": r["kev_due_date"],
                    "kev_vendor_project": r["kev_vendor_project"],
                    "kev_product": r["kev_product"],
                    "kev_ransomware_use": r["kev_ransomware_use"],
                    "kev_notes": r["kev_notes"],
                    "source": r["source"],
                    "affected_products": json.loads(r["affected_products"] or "[]"),
                    "created_at": r["created_at"],
                    "updated_at": r["updated_at"],
                }
            )
        return results
