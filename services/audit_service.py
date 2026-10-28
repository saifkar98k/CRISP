"""
CRISP 2.0 - Enterprise Audit Logging & Governance Service
Provides append-only, tamper-evident audit logging for security operations,
authentication events, risk updates, agent investigations, and data governance.

Immutable Design:
- Database trigger prevents updates or deletions to audit_logs.
- Strict sanitization: strips credentials, tokens, and sensitive cryptographic material.
- Parameterized SQLite transactions with structured JSON metadata.
"""

import os
import sqlite3
import json
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
import secrets

logger = logging.getLogger("CRISP.AuditService")

DEFAULT_DB_PATH = os.environ.get("CRISP_DB_PATH", os.path.join("data", "crisp.db"))

SENSITIVE_KEYS = {"password", "token", "password_hash", "secret", "authorization", "raw_token", "api_key", "cookie"}


def sanitize_audit_details(details: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Recursively removes sensitive keys such as passwords, API keys, or raw tokens."""
    if not details or not isinstance(details, dict):
        return {}
    clean: Dict[str, Any] = {}
    for k, v in details.items():
        if k.lower() in SENSITIVE_KEYS:
            clean[k] = "[REDACTED_SECRET]"
        elif isinstance(v, dict):
            clean[k] = sanitize_audit_details(v)
        elif isinstance(v, list):
            clean[k] = [
                sanitize_audit_details(item) if isinstance(item, dict) else item
                for item in v
            ]
        else:
            clean[k] = v
    return clean


def init_audit_tables(db_path: str = DEFAULT_DB_PATH) -> None:
    """Initializes SQLite audit log table and immutability triggers."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        
        # Audit Logs Table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                audit_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                actor_role TEXT NOT NULL,
                tenant_id TEXT NOT NULL DEFAULT 'default_tenant',
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT,
                result TEXT NOT NULL, -- SUCCESS, FAILURE, DENIED
                ip_address TEXT,
                details_json TEXT NOT NULL
            );
            """
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_logs(actor_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_logs(target_type, target_id);")

        # Immutability Triggers: Prevent modification or deletion of audit records
        cursor.execute(
            """
            CREATE TRIGGER IF NOT EXISTS prevent_audit_log_update
            BEFORE UPDATE ON audit_logs
            BEGIN
                SELECT RAISE(FAIL, 'CRITICAL: Audit logs are append-only and cannot be modified.');
            END;
            """
        )
        cursor.execute(
            """
            CREATE TRIGGER IF NOT EXISTS prevent_audit_log_delete
            BEFORE DELETE ON audit_logs
            BEGIN
                SELECT RAISE(FAIL, 'CRITICAL: Audit logs are append-only and cannot be deleted.');
            END;
            """
        )
        conn.commit()


class AuditService:
    """Enterprise audit trail recording and query service."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        init_audit_tables(self.db_path)

    def log_event(
        self,
        actor_id: str,
        actor_role: str,
        action: str,
        target_type: str,
        target_id: Optional[str] = None,
        result: str = "SUCCESS",
        tenant_id: str = "default_tenant",
        ip_address: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Appends an immutable audit record.
        Returns the unique audit_id.
        """
        audit_id = f"AUD-{secrets.token_hex(6).upper()}"
        timestamp = datetime.now(timezone.utc).isoformat()
        clean_details = sanitize_audit_details(details)

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO audit_logs (
                    audit_id, timestamp, actor_id, actor_role, tenant_id,
                    action, target_type, target_id, result, ip_address, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    audit_id,
                    timestamp,
                    actor_id or "system",
                    actor_role or "SYSTEM",
                    tenant_id or "default_tenant",
                    action,
                    target_type,
                    target_id,
                    result,
                    ip_address or "127.0.0.1",
                    json.dumps(clean_details),
                ),
            )
            conn.commit()

        logger.info(f"Audit record [{audit_id}]: {actor_id} performed {action} on {target_type}:{target_id} -> {result}")
        return audit_id

    def query_logs(
        self,
        actor_id: Optional[str] = None,
        action: Optional[str] = None,
        target_type: Optional[str] = None,
        result: Optional[str] = None,
        tenant_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Queries audit log entries with filters and pagination."""
        clauses = []
        params = []

        if actor_id:
            clauses.append("actor_id = ?")
            params.append(actor_id)
        if action and action != "ALL":
            clauses.append("action = ?")
            params.append(action)
        if target_type and target_type != "ALL":
            clauses.append("target_type = ?")
            params.append(target_type)
        if result and result != "ALL":
            clauses.append("result = ?")
            params.append(result)
        if tenant_id:
            clauses.append("tenant_id = ?")
            params.append(tenant_id)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"""
            SELECT audit_id, timestamp, actor_id, actor_role, tenant_id,
                   action, target_type, target_id, result, ip_address, details_json
            FROM audit_logs
            {where_sql}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """
        params.extend([max(1, min(limit, 200)), max(0, offset)])

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(sql, tuple(params))
            rows = cursor.fetchall()
            results = []
            for r in rows:
                item = dict(r)
                try:
                    item["details"] = json.loads(item.get("details_json", "{}"))
                except Exception:
                    item["details"] = {}
                results.append(item)
            return results

    def get_audit_stats(self, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """Calculates audit metrics for compliance oversight."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            tenant_clause = "WHERE tenant_id = ?" if tenant_id else ""
            t_params = (tenant_id,) if tenant_id else ()

            cursor.execute(f"SELECT COUNT(*) FROM audit_logs {tenant_clause}", t_params)
            total = cursor.fetchone()[0]

            cursor.execute(f"SELECT action, COUNT(*) FROM audit_logs {tenant_clause} GROUP BY action ORDER BY COUNT(*) DESC LIMIT 5", t_params)
            top_actions = {r[0]: r[1] for r in cursor.fetchall()}

            cursor.execute(f"SELECT result, COUNT(*) FROM audit_logs {tenant_clause} GROUP BY result", t_params)
            results_breakdown = {r[0]: r[1] for r in cursor.fetchall()}

            return {
                "total_audit_events": total,
                "top_actions": top_actions,
                "results_breakdown": results_breakdown,
                "immutability_enforced": True,
            }


# Singleton service instance
audit_service = AuditService()
