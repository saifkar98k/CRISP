"""
CRISP 2.0 - Enterprise Authentication & Role-Based Access Control (RBAC) Service
Provides secure password hashing (PBKDF2-HMAC-SHA256 with cryptographically random salt),
signed session token management, login rate limiting, session revocation, and tenant isolation.

Roles supported:
- ADMIN: Full administrative control, user management, audit logs, provider config.
- SECURITY_ANALYST: Triage findings, trigger investigations, submit remediations, manage events.
- VIEWER: Read-only access to dashboards, reports, metrics, and threat intelligence.
"""

import os
import sqlite3
import hashlib
import hmac
import secrets
import time
import json
import logging
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timezone, timedelta

logger = logging.getLogger("CRISP.AuthService")

DEFAULT_DB_PATH = os.environ.get("CRISP_DB_PATH", os.path.join("data", "crisp.db"))
SECRET_KEY = os.environ.get("CRISP_SESSION_SECRET", "crisp_enterprise_default_secret_key_change_in_prod_2026")

# PBKDF2 Parameters
PBKDF2_ITERATIONS = 100_000
SALT_BYTES = 16
HASH_NAME = "sha256"

# Session Expiration
SESSION_TTL_HOURS = 8

# Rate Limiting: Max 5 failed attempts within 15 minutes
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15

# Supported Roles
ROLE_ADMIN = "ADMIN"
ROLE_SECURITY_ANALYST = "SECURITY_ANALYST"
ROLE_VIEWER = "VIEWER"

VALID_ROLES = {ROLE_ADMIN, ROLE_SECURITY_ANALYST, ROLE_VIEWER}

# Role Hierarchy / Permission Mapping
ROLE_PERMISSIONS = {
    ROLE_ADMIN: {
        "view_dashboards", "view_intelligence", "view_findings", "view_remediations",
        "investigate_swarm", "update_findings", "create_remediations", "approve_remediations",
        "verify_remediations", "manage_datasources", "import_data", "view_audit_logs",
        "manage_users", "configure_providers", "recalculate_risk"
    },
    ROLE_SECURITY_ANALYST: {
        "view_dashboards", "view_intelligence", "view_findings", "view_remediations",
        "investigate_swarm", "update_findings", "create_remediations",
        "verify_remediations", "manage_datasources", "import_data", "recalculate_risk"
    },
    ROLE_VIEWER: {
        "view_dashboards", "view_intelligence", "view_findings", "view_remediations"
    }
}


def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    """Hashes password using PBKDF2-HMAC-SHA256 with 100,000 iterations and random salt."""
    if not salt:
        salt = secrets.token_bytes(SALT_BYTES)
    derived = hashlib.pbkdf2_hmac(HASH_NAME, password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_{HASH_NAME}${PBKDF2_ITERATIONS}${salt.hex()}${derived.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verifies a password against the stored PBKDF2 hash using constant-time comparison."""
    try:
        parts = stored_hash.split("$")
        if len(parts) != 4 or parts[0] != f"pbkdf2_{HASH_NAME}":
            return False
        iterations = int(parts[1])
        salt = bytes.fromhex(parts[2])
        expected_hash = parts[3]
        derived = hashlib.pbkdf2_hmac(HASH_NAME, password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(derived.hex(), expected_hash)
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False


def generate_session_token(user_id: str, email: str, role: str) -> Tuple[str, str]:
    """
    Generates a secure cryptographically random session token and its SHA256 storage hash.
    Returns: (raw_token, token_hash)
    """
    raw_token = f"crisp_tok_{secrets.token_urlsafe(32)}"
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    return raw_token, token_hash


def init_auth_tables(db_path: str = DEFAULT_DB_PATH) -> None:
    """Initializes SQLite tables for users, sessions, and login attempt rate limiting."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        
        # Users Table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                tenant_id TEXT NOT NULL DEFAULT 'default_tenant',
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                last_login_at TEXT
            );
            """
        )
        
        # User Sessions Table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS user_sessions (
                session_id TEXT PRIMARY KEY,
                token_hash TEXT UNIQUE NOT NULL,
                user_id TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                is_revoked INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            );
            """
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_token ON user_sessions(token_hash);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id);")

        # Login Attempts Table for Rate Limiting & Lockout
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                identifier TEXT NOT NULL,
                ip_address TEXT,
                attempt_time TEXT NOT NULL,
                success INTEGER NOT NULL
            );
            """
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_attempts_ident ON login_attempts(identifier, attempt_time);")

        conn.commit()


def seed_default_users(db_path: str = DEFAULT_DB_PATH) -> None:
    """Seeds default enterprise administrative and analyst accounts if they do not exist."""
    init_auth_tables(db_path)
    now = datetime.now(timezone.utc).isoformat()
    
    defaults = [
        {
            "user_id": "USR-ADMIN-01",
            "email": "admin@crisp.local",
            "username": "admin",
            "password": "Admin#Crisp2026!",
            "role": ROLE_ADMIN,
            "tenant_id": "default_tenant",
        },
        {
            "user_id": "USR-ANALYST-SK",
            "email": "saifkar98k@gmail.com",
            "username": "saifkar98k",
            "password": "Crisp#Analyst2026!",
            "role": ROLE_SECURITY_ANALYST,
            "tenant_id": "default_tenant",
        },
        {
            "user_id": "USR-ANALYST-02",
            "email": "analyst@crisp.local",
            "username": "analyst",
            "password": "Analyst#Crisp2026!",
            "role": ROLE_SECURITY_ANALYST,
            "tenant_id": "default_tenant",
        },
        {
            "user_id": "USR-VIEWER-01",
            "email": "viewer@crisp.local",
            "username": "viewer",
            "password": "Viewer#Crisp2026!",
            "role": ROLE_VIEWER,
            "tenant_id": "default_tenant",
        },
    ]

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        for u in defaults:
            cursor.execute("SELECT user_id FROM users WHERE email = ? OR username = ?", (u["email"], u["username"]))
            existing = cursor.fetchone()
            if not existing:
                p_hash = hash_password(u["password"])
                cursor.execute(
                    """
                    INSERT INTO users (user_id, email, username, password_hash, role, tenant_id, is_active, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, 1, ?)
                    """,
                    (u["user_id"], u["email"], u["username"], p_hash, u["role"], u["tenant_id"], now),
                )
                logger.info(f"Seeded default enterprise user: {u['email']} [{u['role']}]")
        conn.commit()


class AuthService:
    """Core enterprise authentication and session management service."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        init_auth_tables(self.db_path)
        seed_default_users(self.db_path)

    def check_rate_limit(self, identifier: str) -> Tuple[bool, Optional[str]]:
        """
        Checks if identifier (email or IP) is currently locked out due to excessive failed attempts.
        Returns: (is_allowed, error_message_if_blocked)
        """
        fifteen_mins_ago = (datetime.now(timezone.utc) - timedelta(minutes=LOCKOUT_DURATION_MINUTES)).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT COUNT(*) FROM login_attempts
                WHERE identifier = ? AND attempt_time >= ? AND success = 0
                """,
                (identifier.lower().strip(), fifteen_mins_ago)
            )
            failed_count = cursor.fetchone()[0]
            if failed_count >= MAX_FAILED_ATTEMPTS:
                return False, f"Account or IP temporarily locked due to {failed_count} failed login attempts. Please try again after {LOCKOUT_DURATION_MINUTES} minutes."
            return True, None

    def record_login_attempt(self, identifier: str, ip_address: Optional[str], success: bool) -> None:
        """Records a login attempt for rate limiting and auditing."""
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO login_attempts (identifier, ip_address, attempt_time, success)
                VALUES (?, ?, ?, ?)
                """,
                (identifier.lower().strip(), ip_address or "127.0.0.1", now, 1 if success else 0)
            )
            conn.commit()

    def authenticate(
        self,
        identifier: str,
        password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Authenticates a user via email or username.
        Enforces rate limiting, password verification, session creation, and returns token info.
        """
        clean_id = (identifier or "").strip().lower()
        if not clean_id or not password:
            return {"success": False, "error": "Identifier and password are required.", "code": "INVALID_CREDENTIALS"}

        # 1. Rate limiting check
        allowed, lockout_err = self.check_rate_limit(clean_id)
        if not allowed:
            self.record_login_attempt(clean_id, ip_address, False)
            return {"success": False, "error": lockout_err, "code": "RATE_LIMITED"}

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT user_id, email, username, password_hash, role, tenant_id, is_active
                FROM users
                WHERE lower(email) = ? OR lower(username) = ?
                """,
                (clean_id, clean_id)
            )
            user_row = cursor.fetchone()

        if not user_row:
            self.record_login_attempt(clean_id, ip_address, False)
            return {"success": False, "error": "Invalid credentials or account does not exist.", "code": "INVALID_CREDENTIALS"}

        if not user_row["is_active"]:
            self.record_login_attempt(clean_id, ip_address, False)
            return {"success": False, "error": "Account is disabled. Contact your CRISP administrator.", "code": "ACCOUNT_DISABLED"}

        # 2. Constant-time password check
        if not verify_password(password, user_row["password_hash"]):
            self.record_login_attempt(clean_id, ip_address, False)
            return {"success": False, "error": "Invalid credentials.", "code": "INVALID_CREDENTIALS"}

        # 3. Successful login
        self.record_login_attempt(clean_id, ip_address, True)
        now_dt = datetime.now(timezone.utc)
        now_str = now_dt.isoformat()
        expires_str = (now_dt + timedelta(hours=SESSION_TTL_HOURS)).isoformat()
        
        raw_token, token_hash = generate_session_token(user_row["user_id"], user_row["email"], user_row["role"])
        session_id = f"SES-{secrets.token_hex(8)}"

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            # Insert session
            cursor.execute(
                """
                INSERT INTO user_sessions (session_id, token_hash, user_id, email, role, tenant_id, ip_address, user_agent, created_at, expires_at, is_revoked)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (session_id, token_hash, user_row["user_id"], user_row["email"], user_row["role"], user_row["tenant_id"], ip_address, user_agent, now_str, expires_str)
            )
            # Update last login
            cursor.execute("UPDATE users SET last_login_at = ? WHERE user_id = ?", (now_str, user_row["user_id"]))
            conn.commit()

        # Log audit event
        try:
            from services.audit_service import audit_service
            audit_service.log_event(
                actor_id=user_row["email"],
                actor_role=user_row["role"],
                tenant_id=user_row["tenant_id"],
                action="AUTH_LOGIN",
                target_type="USER_SESSION",
                target_id=session_id,
                result="SUCCESS",
                ip_address=ip_address,
                details={"username": user_row["username"], "role": user_row["role"]}
            )
        except Exception:
            pass

        return {
            "success": True,
            "token": raw_token,
            "user": {
                "user_id": user_row["user_id"],
                "email": user_row["email"],
                "username": user_row["username"],
                "role": user_row["role"],
                "tenant_id": user_row["tenant_id"],
                "permissions": list(ROLE_PERMISSIONS.get(user_row["role"], set())),
            },
            "expires_at": expires_str,
            "session_id": session_id,
        }

    def validate_session(self, raw_token: str) -> Optional[Dict[str, Any]]:
        """
        Validates a bearer token. Checks signature hash, expiration, and revocation.
        Returns user dictionary if valid, None otherwise.
        """
        if not raw_token or not isinstance(raw_token, str):
            return None
        
        clean_token = raw_token.replace("Bearer ", "").strip()
        token_hash = hashlib.sha256(clean_token.encode("utf-8")).hexdigest()
        now_str = datetime.now(timezone.utc).isoformat()

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT s.session_id, s.user_id, s.email, s.role, s.tenant_id, s.expires_at, s.is_revoked, u.username, u.is_active
                FROM user_sessions s
                JOIN users u ON s.user_id = u.user_id
                WHERE s.token_hash = ?
                """,
                (token_hash,)
            )
            session = cursor.fetchone()

        if not session:
            return None

        # Check revocation, active account, and expiry
        if session["is_revoked"] or not session["is_active"]:
            return None

        if session["expires_at"] <= now_str:
            return None

        return {
            "session_id": session["session_id"],
            "user_id": session["user_id"],
            "email": session["email"],
            "username": session["username"],
            "role": session["role"],
            "tenant_id": session["tenant_id"],
            "permissions": list(ROLE_PERMISSIONS.get(session["role"], set())),
        }

    def logout(self, raw_token: str, ip_address: Optional[str] = None) -> bool:
        """Revokes an active session."""
        if not raw_token:
            return False
        clean_token = raw_token.replace("Bearer ", "").strip()
        token_hash = hashlib.sha256(clean_token.encode("utf-8")).hexdigest()

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT session_id, email, role, tenant_id FROM user_sessions WHERE token_hash = ?", (token_hash,))
            row = cursor.fetchone()
            if row:
                cursor.execute("UPDATE user_sessions SET is_revoked = 1 WHERE token_hash = ?", (token_hash,))
                conn.commit()
                try:
                    from services.audit_service import audit_service
                    audit_service.log_event(
                        actor_id=row["email"],
                        actor_role=row["role"],
                        tenant_id=row["tenant_id"],
                        action="AUTH_LOGOUT",
                        target_type="USER_SESSION",
                        target_id=row["session_id"],
                        result="SUCCESS",
                        ip_address=ip_address,
                    )
                except Exception:
                    pass
                return True
        return False

    def list_users(self, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Lists users, optionally filtered by tenant (ADMIN only)."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            if tenant_id:
                cursor.execute(
                    "SELECT user_id, email, username, role, tenant_id, is_active, created_at, last_login_at FROM users WHERE tenant_id = ?",
                    (tenant_id,)
                )
            else:
                cursor.execute("SELECT user_id, email, username, role, tenant_id, is_active, created_at, last_login_at FROM users")
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def create_user(
        self,
        email: str,
        username: str,
        password: str,
        role: str,
        tenant_id: str = "default_tenant",
        creator_role: str = ROLE_ADMIN,
    ) -> Dict[str, Any]:
        """Creates a new user account with role enforcement."""
        if creator_role != ROLE_ADMIN:
            raise PermissionError("Only users with ADMIN role can create new user accounts.")

        role_upper = (role or "").strip().upper()
        if role_upper not in VALID_ROLES:
            raise ValueError(f"Invalid role '{role}'. Must be one of: {list(VALID_ROLES)}")

        user_id = f"USR-{secrets.token_hex(4).upper()}"
        p_hash = hash_password(password)
        now_str = datetime.now(timezone.utc).isoformat()

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO users (user_id, email, username, password_hash, role, tenant_id, is_active, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 1, ?)
                """,
                (user_id, email.strip().lower(), username.strip(), p_hash, role_upper, tenant_id, now_str)
            )
            conn.commit()

        return {
            "user_id": user_id,
            "email": email.strip().lower(),
            "username": username.strip(),
            "role": role_upper,
            "tenant_id": tenant_id,
            "created_at": now_str,
        }


# Singleton service instance
auth_service = AuthService()
