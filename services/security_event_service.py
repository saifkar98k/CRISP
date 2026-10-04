"""
CRISP Cybersecurity Platform - Security Event Service
Handles SQLite persistence, chunked dataset import, indexing,
deduplication, risk scoring, and event aggregation analytics.
"""

import json
import logging
import os
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from services.providers.security_dataset_provider import (
    DEFAULT_CHUNK_SIZE,
    DEFAULT_DATASET_PATH,
    DEFAULT_IMPORT_LIMIT,
    SecurityDatasetProvider,
    is_valid_security_row,
    normalize_security_event,
)
from services.risk_engine import calculate_crisp_security_event_risk

logger = logging.getLogger("CRISP.SecurityEventService")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] [CRISP.EventService] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

DEFAULT_DB_PATH = os.path.join("data", "crisp.db")


def init_security_events_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """
    Initializes the security_events table in SQLite with schema migrations
    and required performance indexes.
    """
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        # Primary security_events table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS security_events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                source_port INTEGER,
                destination_port INTEGER,
                protocol TEXT,
                event_type TEXT,
                severity TEXT,
                status TEXT,
                attack_category TEXT,
                original_attack_label TEXT,
                crisp_attack_category TEXT,
                description TEXT,
                asset_id TEXT,
                nist_function TEXT,
                cve_id TEXT,
                source TEXT,
                dataset_source TEXT DEFAULT 'CIC-IDS2017',
                crisp_risk_score REAL DEFAULT 0.0,
                imported_at TEXT NOT NULL
            );
            """
        )

        # Performance Indexes requested by CRISP architecture
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sec_events_timestamp ON security_events(timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sec_events_event_type ON security_events(event_type);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sec_events_severity ON security_events(severity);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sec_events_attack_category ON security_events(attack_category);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sec_events_source_ip ON security_events(source_ip);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sec_events_destination_ip ON security_events(destination_ip);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sec_events_dataset_source ON security_events(dataset_source);")

        # Sync metadata table for tracking historical dataset operations
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS dataset_import_metadata (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                dataset_name TEXT NOT NULL,
                last_imported_timestamp TEXT NOT NULL,
                rows_read INTEGER DEFAULT 0,
                rows_imported INTEGER DEFAULT 0,
                rows_skipped INTEGER DEFAULT 0,
                duplicates INTEGER DEFAULT 0,
                invalid_rows INTEGER DEFAULT 0,
                total_stored INTEGER DEFAULT 0,
                status TEXT NOT NULL
            );
            """
        )
        conn.commit()


def import_dataset_into_db(
    dataset_path: Optional[str] = None,
    limit: Optional[int] = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    db_path: str = DEFAULT_DB_PATH,
    dataset_source: str = "CIC-IDS2017",
) -> Dict[str, Any]:
    """
    Imports historical cybersecurity dataset in chunks, normalizes,
    computes risk scores, and writes to SQLite with duplicate prevention.
    """
    init_security_events_db(db_path)
    provider = SecurityDatasetProvider(
        dataset_path=dataset_path,
        chunk_size=chunk_size,
        limit=limit,
    )

    if not provider.file_exists():
        raise FileNotFoundError(f"Target dataset file does not exist: {provider.dataset_path}")

    now_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    stats = {
        "dataset_name": dataset_source,
        "dataset_path": provider.dataset_path,
        "rows_read": 0,
        "rows_imported": 0,
        "rows_skipped": 0,
        "duplicates": 0,
        "invalid_rows": 0,
        "total_stored": 0,
        "started_at": now_iso,
    }

    # Track seen IDs from database to prevent duplicate row counts
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT event_id FROM security_events")
        existing_ids = {row[0] for row in cursor.fetchall()}

    seen_in_batch = set()
    rows_processed = 0

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        for chunk in provider.stream_raw_chunks():
            records_to_insert = []

            for raw_row in chunk:
                rows_processed += 1
                stats["rows_read"] += 1

                if not is_valid_security_row(raw_row):
                    stats["invalid_rows"] += 1
                    stats["rows_skipped"] += 1
                    continue

                try:
                    event = normalize_security_event(
                        raw_row,
                        dataset_source=dataset_source,
                        record_index=rows_processed,
                    )
                except Exception as ex:
                    logger.debug(f"Normalization failed: {ex}")
                    stats["invalid_rows"] += 1
                    stats["rows_skipped"] += 1
                    continue

                event_id = event["event_id"]
                if event_id in existing_ids or event_id in seen_in_batch:
                    stats["duplicates"] += 1
                    stats["rows_skipped"] += 1
                    continue

                seen_in_batch.add(event_id)

                # Compute operational CRISP Risk Score
                risk_res = calculate_crisp_security_event_risk(
                    event_id=event_id,
                    attack_category=event["attack_category"],
                    severity=event["severity"],
                    cve_id=event.get("cve_id"),
                    asset_id=event.get("asset_id"),
                )
                event["crisp_risk_score"] = risk_res["risk_score"]

                records_to_insert.append((
                    event["event_id"],
                    event["timestamp"],
                    event["source_ip"],
                    event["destination_ip"],
                    event["source_port"],
                    event["destination_port"],
                    event["protocol"],
                    event["event_type"],
                    event["severity"],
                    event["status"],
                    event["attack_category"],
                    event["original_attack_label"],
                    event["crisp_attack_category"],
                    event["description"],
                    event["asset_id"],
                    event["nist_function"],
                    event["cve_id"],
                    event["source"],
                    dataset_source,
                    event["crisp_risk_score"],
                    now_iso,
                ))

                stats["rows_imported"] += 1
                if provider.limit and stats["rows_imported"] >= provider.limit:
                    break

            if records_to_insert:
                cursor.executemany(
                    """
                    INSERT OR REPLACE INTO security_events (
                        event_id, timestamp, source_ip, destination_ip, source_port,
                        destination_port, protocol, event_type, severity, status,
                        attack_category, original_attack_label, crisp_attack_category,
                        description, asset_id, nist_function, cve_id, source,
                        dataset_source, crisp_risk_score, imported_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    records_to_insert,
                )
                conn.commit()

            if provider.limit and stats["rows_imported"] >= provider.limit:
                break

        # Total stored count
        cursor.execute("SELECT COUNT(*) FROM security_events")
        stats["total_stored"] = cursor.fetchone()[0]

        # Update metadata
        cursor.execute(
            """
            INSERT OR REPLACE INTO dataset_import_metadata (
                id, dataset_name, last_imported_timestamp, rows_read,
                rows_imported, rows_skipped, duplicates, invalid_rows,
                total_stored, status
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                dataset_source,
                now_iso,
                stats["rows_read"],
                stats["rows_imported"],
                stats["rows_skipped"],
                stats["duplicates"],
                stats["invalid_rows"],
                stats["total_stored"],
                "COMPLETED",
            ),
        )
        conn.commit()

    logger.info(
        f"Dataset import complete: {stats['rows_imported']} imported, "
        f"{stats['duplicates']} duplicates, {stats['invalid_rows']} invalid rows."
    )
    return stats


# ==============================================================================
# Event Correlation & Analytics Query Services
# ==============================================================================


def get_attacks_by_category(db_path: str = DEFAULT_DB_PATH, dataset_source: Optional[str] = None) -> Dict[str, int]:
    """Returns count of attacks grouped by crisp_attack_category."""
    init_security_events_db(db_path)
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        query = "SELECT attack_category, COUNT(*) FROM security_events"
        params: List[Any] = []
        if dataset_source:
            query += " WHERE dataset_source = ?"
            params.append(dataset_source)
        query += " GROUP BY attack_category ORDER BY COUNT(*) DESC"
        cursor.execute(query, params)
        return {row[0]: row[1] for row in cursor.fetchall()}


def get_attacks_by_severity(db_path: str = DEFAULT_DB_PATH, dataset_source: Optional[str] = None) -> Dict[str, int]:
    """Returns count of attacks grouped by severity."""
    init_security_events_db(db_path)
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        query = "SELECT severity, COUNT(*) FROM security_events"
        params: List[Any] = []
        if dataset_source:
            query += " WHERE dataset_source = ?"
            params.append(dataset_source)
        query += " GROUP BY severity ORDER BY COUNT(*) DESC"
        cursor.execute(query, params)
        return {row[0]: row[1] for row in cursor.fetchall()}


def get_top_source_ips(db_path: str = DEFAULT_DB_PATH, limit: int = 10) -> List[Dict[str, Any]]:
    """Returns top attacking source IP addresses with event counts and dominant attack category."""
    init_security_events_db(db_path)
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT source_ip, COUNT(*) as count, MAX(severity) as max_severity, attack_category
            FROM security_events
            WHERE source_ip IS NOT NULL AND source_ip != ''
            GROUP BY source_ip
            ORDER BY count DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [
            {"source_ip": r[0], "count": r[1], "max_severity": r[2], "attack_category": r[3]}
            for r in cursor.fetchall()
        ]


def get_top_destination_ports(db_path: str = DEFAULT_DB_PATH, limit: int = 10) -> List[Dict[str, Any]]:
    """Returns most targeted destination ports."""
    init_security_events_db(db_path)
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT destination_port, COUNT(*) as count, protocol
            FROM security_events
            WHERE destination_port IS NOT NULL
            GROUP BY destination_port
            ORDER BY count DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [
            {"port": r[0], "count": r[1], "protocol": r[2]}
            for r in cursor.fetchall()
        ]


def get_protocol_distribution(db_path: str = DEFAULT_DB_PATH) -> Dict[str, int]:
    """Returns count of events grouped by protocol."""
    init_security_events_db(db_path)
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT COALESCE(protocol, 'UNKNOWN'), COUNT(*)
            FROM security_events
            GROUP BY protocol
            ORDER BY COUNT(*) DESC
            """
        )
        return {row[0]: row[1] for row in cursor.fetchall()}


def get_source_distribution(db_path: str = DEFAULT_DB_PATH) -> Dict[str, int]:
    """Returns counts comparing historical dataset (CIC-IDS2017) vs synthetic events (MOCK)."""
    init_security_events_db(db_path)
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT dataset_source, COUNT(*)
            FROM security_events
            GROUP BY dataset_source
            """
        )
        return {row[0]: row[1] for row in cursor.fetchall()}


def get_attacks_over_time(db_path: str = DEFAULT_DB_PATH, limit: int = 30) -> List[Dict[str, Any]]:
    """Returns attack counts aggregated by date / time interval."""
    init_security_events_db(db_path)
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT SUBSTR(timestamp, 1, 10) as day, COUNT(*) as count, severity
            FROM security_events
            WHERE timestamp IS NOT NULL
            GROUP BY day, severity
            ORDER BY day ASC
            LIMIT ?
            """,
            (limit,),
        )
        return [{"date": r[0], "count": r[1], "severity": r[2]} for r in cursor.fetchall()]


def get_security_events_filtered(
    db_path: str = DEFAULT_DB_PATH,
    dataset_source: Optional[str] = None,
    attack_category: Optional[str] = None,
    severity: Optional[str] = None,
    protocol: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """Retrieves security events with multi-criteria filtering."""
    init_security_events_db(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        query = "SELECT * FROM security_events WHERE 1=1"
        params: List[Any] = []

        if dataset_source and dataset_source.upper() != "ALL":
            query += " AND dataset_source = ?"
            params.append(dataset_source)
        if attack_category and attack_category.upper() != "ALL":
            query += " AND attack_category = ?"
            params.append(attack_category)
        if severity and severity.upper() != "ALL":
            query += " AND severity = ?"
            params.append(severity.upper())
        if protocol and protocol.upper() != "ALL":
            query += " AND protocol = ?"
            params.append(protocol.upper())

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]
