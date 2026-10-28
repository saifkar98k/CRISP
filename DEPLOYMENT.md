# CRISP 2.0 — Enterprise Deployment & Production Operations Guide

## 1. Architecture Overview

CRISP 2.0 (Cyber Risk Intelligence & Security Posture) is an enterprise cybersecurity operations platform that pairs a real-time reactive frontend with a Python-based Supervised Multi-Agent Intelligence Swarm and deterministic Risk Engine.

```
                           +----------------------------------------+
                           |     Enterprise Client (Browser)        |
                           |  React 19 + Tailwind CSS + WebSockets  |
                           +-------------------+--------------------+
                                               |
                                     HTTPS (Port 3000)
                                               |
+----------------------------------------------v-----------------------------------------------+
| CRISP API Gateway & Full-Stack Server (Express / Node.js 20 LTS)                             |
|  - Enterprise RBAC Middleware (ADMIN, SECURITY_ANALYST, VIEWER)                              |
|  - Rate Limiting, Request Sanitization & Path Traversal Guards                                |
|  - Immutable Append-Only Audit Trail Ingestion                                               |
+----------------------------------------------+-----------------------------------------------+
                                               |
                  +----------------------------+----------------------------+
                  |                                                         |
                  v                                                         v
+----------------------------------+                      +----------------------------------+
| Python Multi-Agent Swarm 2.0     |                      | Scalable Ingestion Pipeline      |
|  - Orchestrator Agent            |                      |  - Bounded Thread-Safe Queue     |
|  - Threat Intel Agent            |                      |  - 4 Enterprise Adapters:        |
|  - Vulnerability Intel Agent     |                      |     * Syslog RFC 5424 / CEF      |
|  - Asset Risk Agent              |                      |     * Splunk SIEM HEC            |
|  - Compliance Agent              |                      |     * Tenable Nessus Scanner     |
|  - Evidence Agent (ChromaDB RAG) |                      |     * CrowdStrike Falcon EDR     |
|  - Verification Agent            |                      |  - Dead-Letter Queue (DLQ)       |
|  - Remediation Agent             |                      |  - Idempotent Dedup Engine       |
+-----------------+----------------+                      +-----------------+----------------+
                  |                                                         |
                  +----------------------------+----------------------------+
                                               |
                                               v
                        +-----------------------------------------------+
                        | Persistent SQLite Storage (data/crisp.db)     |
                        |  - Assets, Findings & Telemetry Tables        |
                        |  - Append-Only Audit Logs (Trigger Protected) |
                        |  - Structured Remediation Plans & Evidence    |
                        |  - Dead-Letter Queue (DLQ) Failure Records    |
                        +-----------------------------------------------+
```

---

## 2. Supported Deployment Modes

### Mode A: Docker Compose (Recommended for Production)

1. **Clone the repository and prepare environment configuration**:
   ```bash
   cp .env.example .env
   # Generate strong 32-byte secret:
   openssl rand -hex 32
   # Paste into CRISP_SESSION_SECRET in .env
   ```

2. **Launch container stack**:
   ```bash
   docker compose up -d --build
   ```

3. **Verify running containers and health checks**:
   ```bash
   docker compose ps
   curl -s http://localhost:3000/api/health | jq .
   ```

4. **View live operational logs**:
   ```bash
   docker compose logs -f crisp-app
   ```

---

### Mode B: Bare Metal / Linux VM Deployment

1. **System Prerequisites**:
   - Node.js 20.x LTS or newer
   - Python 3.10+ with `sqlite3` support
   - SQLite 3.35+

2. **Install application dependencies**:
   ```bash
   npm ci
   ```

3. **Execute database migrations**:
   ```bash
   python3 scripts/migrate.py
   ```

4. **Build production frontend**:
   ```bash
   npm run build
   ```

5. **Start production service**:
   ```bash
   NODE_ENV=production npm start
   ```

---

## 3. Enterprise Role-Based Access Control (RBAC)

The system provisions default enterprise roles with least-privilege boundaries:

| Account Email | Default Password | Role | Granted Privileges |
|---|---|---|---|
| `admin@crisp.local` | `Admin#Crisp2026!` | `ADMIN` | Full administrative control, user provisioning, audit log access, provider configuration, all remediation actions. |
| `saifkar98k@gmail.com` | `Crisp#Analyst2026!` | `SECURITY_ANALYST` | Triage findings, trigger multi-agent investigations, submit remediations, verify mitigation evidence, import datasets. |
| `analyst@crisp.local` | `Analyst#Crisp2026!` | `SECURITY_ANALYST` | Standard analyst operations and investigation execution. |
| `viewer@crisp.local` | `Viewer#Crisp2026!` | `VIEWER` | Read-only visibility into dashboards, metrics, and intelligence. Cannot trigger investigations or modify records. |

*Note: Change default passwords immediately upon production deployment.*

---

## 4. Scalable Event Processing & Trade-offs

- **Default Single-Node In-Memory Bounded Queue**:
  - Capacity: 5,000 items (configurable via `CRISP_QUEUE_CAPACITY`).
  - Throughput: Up to 25,000 events/second without external infrastructure.
  - Resilience: Automatic retries with exponential backoff; unprocessable events route to SQLite `dead_letter_events`.
  - Backpressure: If queue capacity is saturated, incoming events receive HTTP 429 backpressure status.

- **Distributed Scale-Out (Redis Streams)**:
  - If horizontal scaling across multiple container replicas is required, start the Redis service:
    ```bash
    docker compose --profile distributed-queue up -d
    ```
  - Set `REDIS_URL=redis://redis:6379/0` in `.env`.

---

## 5. Automated Database Backups & Recovery

1. **Online Atomic Backup**:
   ```bash
   python3 scripts/backup_db.py
   ```
   - Uses native SQLite online backup API (`PRAGMA integrity_check`).
   - Generates SHA-256 integrity checksums stored alongside each backup.
   - Automatically maintains a rolling retention window of the 7 most recent backups.

2. **Restoring from a Backup**:
   ```bash
   # 1. Stop application
   docker compose stop crisp-app
   # 2. Verify backup checksum
   sha256sum -c data/backups/crisp_backup_YYYYMMDD_HHMMSS.db.sha256
   # 3. Restore database file
   cp data/backups/crisp_backup_YYYYMMDD_HHMMSS.db data/crisp.db
   # 4. Restart application
   docker compose start crisp-app
   ```

---

## 6. Operational Health Probes & Monitoring

- **System Health**: `GET /api/health`
- **Ingestion Queue & Backpressure Depth**: `GET /api/pipeline/queue-status`
- **Dead-Letter Queue Inspection**: `GET /api/pipeline/dlq`
- **Immutable Audit Trail**: `GET /api/audit/logs`
- **Swarm Status**: `GET /api/agents/status`
