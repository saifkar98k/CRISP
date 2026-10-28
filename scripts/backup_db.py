#!/usr/bin/env python3
"""
CRISP 2.0 - Database Backup & Integrity Check Utility
Performs online atomic backup of the CRISP SQLite database using the native
SQLite backup API, verifies SHA-256 checksums, and manages rolling retention.
"""

import os
import sys
import time
import sqlite3
import hashlib
import shutil
import logging
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s")
logger = logging.getLogger("CRISP.Backup")

SOURCE_DB = os.environ.get("CRISP_DB_PATH", os.path.join("data", "crisp.db"))
BACKUP_DIR = os.environ.get("CRISP_BACKUP_DIR", os.path.join("data", "backups"))
RETENTION_COUNT = int(os.environ.get("CRISP_BACKUP_RETENTION", "7"))


def compute_sha256(filepath: str) -> str:
    """Computes SHA-256 checksum of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def perform_backup() -> str:
    """Executes atomic online SQLite backup without locking active readers."""
    if not os.path.exists(SOURCE_DB):
        raise FileNotFoundError(f"Source database file not found at: {SOURCE_DB}")

    os.makedirs(BACKUP_DIR, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_filename = f"crisp_backup_{timestamp}.db"
    dest_path = os.path.join(BACKUP_DIR, backup_filename)

    logger.info(f"Initiating online atomic backup from '{SOURCE_DB}' -> '{dest_path}'...")
    
    # Use SQLite native backup API
    with sqlite3.connect(SOURCE_DB) as src_conn:
        with sqlite3.connect(dest_path) as dest_conn:
            src_conn.backup(dest_conn, pages=100)

    # Verify backup integrity
    with sqlite3.connect(dest_path) as verify_conn:
        cursor = verify_conn.cursor()
        cursor.execute("PRAGMA integrity_check;")
        result = cursor.fetchone()
        if not result or result[0] != "ok":
            raise RuntimeError(f"Backup failed SQLite integrity check: {result}")

    checksum = compute_sha256(dest_path)
    size_bytes = os.path.getsize(dest_path)

    # Write checksum metadata
    meta_path = f"{dest_path}.sha256"
    with open(meta_path, "w") as f:
        f.write(f"{checksum}  {backup_filename}\n")

    logger.info(f"Backup completed successfully: {dest_path} ({size_bytes} bytes, SHA256: {checksum[:12]}...)")

    # Prune old backups
    prune_old_backups()
    return dest_path


def prune_old_backups() -> None:
    """Retains the most recent N backups and cleans older files."""
    backups = []
    for f in os.listdir(BACKUP_DIR):
        if f.startswith("crisp_backup_") and f.endswith(".db"):
            fp = os.path.join(BACKUP_DIR, f)
            backups.append((os.path.getmtime(fp), fp))

    backups.sort(reverse=True)
    if len(backups) > RETENTION_COUNT:
        for _, old_path in backups[RETENTION_COUNT:]:
            try:
                os.remove(old_path)
                meta = f"{old_path}.sha256"
                if os.path.exists(meta):
                    os.remove(meta)
                logger.info(f"Pruned old backup: {old_path}")
            except Exception as e:
                logger.warning(f"Could not remove old backup {old_path}: {e}")


if __name__ == "__main__":
    try:
        perform_backup()
        sys.exit(0)
    except Exception as e:
        logger.error(f"Backup failed: {e}")
        sys.exit(1)
