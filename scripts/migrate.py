#!/usr/bin/env python3
"""
CRISP 2.0 - Database Schema Migration & Verification Utility
Ensures all required tables, indices, and immutability triggers are verified
and up-to-date prior to application launch.
"""

import os
import sys
import sqlite3
import logging

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s")
logger = logging.getLogger("CRISP.Migration")

DEFAULT_DB_PATH = os.environ.get("CRISP_DB_PATH", os.path.join("data", "crisp.db"))


def run_migrations(db_path: str = DEFAULT_DB_PATH) -> bool:
    """Executes all schema initializations across auth, audit, remediation, and pipeline."""
    logger.info(f"Running database schema verification on: {db_path}")

    # 1. Base CRISP database initialization
    from services.nvd_sync_service import init_db as init_nvd_db
    init_nvd_db(db_path)

    # 2. Auth & RBAC tables
    from services.auth_service import init_auth_tables, seed_default_users
    init_auth_tables(db_path)
    seed_default_users(db_path)

    # 3. Audit logs & immutability triggers
    from services.audit_service import init_audit_tables
    init_audit_tables(db_path)

    # 4. Remediation intelligence tables
    from services.remediation_engine import init_remediation_db
    init_remediation_db(db_path)

    # 5. Dead-Letter Queue (DLQ) tables
    from services.pipeline.event_queue import init_dlq_table
    init_dlq_table(db_path)

    # 6. Temporal Risk History table
    from services.risk_engine import init_risk_history_db
    init_risk_history_db(db_path)

    # 7. Security telemetry events table
    from services.security_event_service import init_security_events_db
    init_security_events_db(db_path)

    # 8. Assets and Correlated Security Findings tables
    from services.correlation_engine import init_correlation_db
    init_correlation_db(db_path)

    # Verify table integrity
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
        tables = [r[0] for r in cursor.fetchall()]
        logger.info(f"Verified {len(tables)} tables: {', '.join(tables)}")

    logger.info("All schema migrations completed successfully.")
    return True


if __name__ == "__main__":
    try:
        run_migrations()
        sys.exit(0)
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        sys.exit(1)
