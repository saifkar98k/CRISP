"""
CRISP Cybersecurity Platform - Multi-Factor Cyber Risk Engine
Phase 2 Step 5: Explainable Multi-Factor Risk Assessment Engine.

IMPORTANT METHODOLOGY NOTICE:
This is a CRISP project-defined risk assessment model designed for operational cybersecurity prioritization.
It is NOT an official NIST risk formula, nor an official CISA or FIRST standard.

Methodology Breakdown (0–100 Scale):
1. Vulnerability Risk (calculate_vulnerability_risk): Max 30 points
   - Evaluates CVSS base score (0.0–10.0 scaled to 0–30 pts).
   - Adjusts for vulnerability status (e.g. OPEN vs REMEDIATED) and patch availability.
2. Asset Risk (calculate_asset_risk): Max 15 points
   - Evaluates organizational criticality tier (CRITICAL, HIGH, MEDIUM, LOW).
3. Threat Risk (calculate_threat_risk): Max 15 points
   - Evaluates CISA KEV status (actively exploited in the wild) and event severity.
4. Exposure Risk (calculate_exposure_risk): Max 15 points
   - Evaluates network exposure (EXTERNAL / public-facing, DMZ, INTERNAL, ISOLATED).
5. Frequency Risk (calculate_frequency_risk): Max 15 points
   - Evaluates telemetry incident frequency and repeated attacks targeting the asset.
6. Recency Risk (calculate_recency_risk): Max 10 points
   - Evaluates recency of observed attack activity / finding detection.

Total Score: 0–100 (strictly bounded).
Configurable Risk Levels:
  0–24   LOW
  25–49  MEDIUM
  50–74  HIGH
  75–100 CRITICAL
"""

import json
import logging
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger("CRISP.RiskEngine")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] [CRISP.RiskEngine] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

DEFAULT_DB_PATH = os.path.join("data", "crisp.db")

# Default Configurable Risk Level Thresholds
DEFAULT_RISK_THRESHOLDS: Dict[str, Tuple[float, float]] = {
    "LOW": (0.0, 24.9),
    "MEDIUM": (25.0, 49.9),
    "HIGH": (50.0, 74.9),
    "CRITICAL": (75.0, 100.0),
}

# Backward compatibility constants
KEV_RISK_WEIGHT: float = 15.0
CVSS_WEIGHT: float = 0.40
CRITICALITY_WEIGHT: float = 0.25
EXPOSURE_WEIGHT: float = 0.20


def get_risk_level(
    score: float,
    thresholds: Optional[Dict[str, Tuple[float, float]]] = None,
) -> str:
    """
    Maps a quantitative score [0–100] to a qualitative Risk Level
    using configurable threshold boundaries.
    """
    th = thresholds or DEFAULT_RISK_THRESHOLDS
    if score >= th["CRITICAL"][0]:
        return "CRITICAL"
    elif score >= th["HIGH"][0]:
        return "HIGH"
    elif score >= th["MEDIUM"][0]:
        return "MEDIUM"
    else:
        return "LOW"


def calculate_vulnerability_risk(
    cvss_score: Optional[float] = None,
    vulnerability_status: Optional[str] = "OPEN",
    patch_availability: Optional[Union[str, bool]] = None,
    max_points: float = 30.0,
) -> Dict[str, Any]:
    """
    Calculates the vulnerability component score (0 to max_points, default 30.0).

    Inputs:
    - cvss_score: CVSS base score (0.0–10.0) from NVD or telemetry. None if uncorrelated.
    - vulnerability_status: 'OPEN', 'UNPATCHED', 'UNDER_INVESTIGATION', 'MITIGATED', 'REMEDIATED'.
    - patch_availability: True/'AVAILABLE', False/'UNAVAILABLE' (zero-day), or 'WORKAROUND'.
    """
    if cvss_score is None:
        return {
            "score": 0.0,
            "max_points": max_points,
            "ratio": f"0/{int(max_points)}",
            "description": "No CVSS score assigned (uncorrelated vulnerability)",
            "details": {
                "cvss_score": None,
                "vulnerability_status": vulnerability_status,
                "patch_availability": patch_availability,
            },
        }

    # Bounded CVSS base contribution (0.0 - 10.0 scaled to max_points)
    bounded_cvss = max(0.0, min(10.0, float(cvss_score)))
    base_points = (bounded_cvss / 10.0) * max_points

    status_str = (vulnerability_status or "OPEN").upper().strip()

    # Patch and remediation modifiers
    if status_str in ("REMEDIATED", "RESOLVED", "PATCHED"):
        # Remediation significantly reduces active vulnerability risk (90% reduction)
        base_points *= 0.10
        desc_patch = "Vulnerability is marked remediated/patched"
    elif status_str in ("MITIGATED", "CONTAINED"):
        # Compensating controls mitigate 60% of exposure
        base_points *= 0.40
        desc_patch = "Compensating controls/mitigations applied"
    else:
        # Open / Unpatched vulnerability
        if patch_availability is False or (
            patch_availability is not None and str(patch_availability).upper() in ("UNAVAILABLE", "ZERO_DAY", "NO_PATCH")
        ):
            # Zero-day / no official patch increases urgency
            base_points = min(max_points, base_points + 2.0)
            desc_patch = "Zero-day / no vendor patch currently available"
        elif patch_availability is True or (
            patch_availability is not None and str(patch_availability).upper() in ("AVAILABLE", "VENDOR_FIX")
        ):
            desc_patch = "Vendor patch available but pending installation"
        else:
            desc_patch = "Vulnerability status is active"

    final_score = round(max(0.0, min(max_points, base_points)), 1)
    # Formatted ratio matching display conventions, e.g. "28/30"
    score_int = int(round(final_score))
    max_int = int(max_points)

    return {
        "score": final_score,
        "max_points": max_points,
        "ratio": f"{score_int}/{max_int}",
        "description": f"CVSS {bounded_cvss} base score contribution ({desc_patch})",
        "details": {
            "cvss_score": bounded_cvss,
            "vulnerability_status": status_str,
            "patch_availability": patch_availability,
        },
    }


def calculate_asset_risk(
    asset_criticality: Optional[str] = "MEDIUM",
    max_points: float = 15.0,
) -> Dict[str, Any]:
    """
    Calculates the asset criticality risk component (0 to max_points, default 15.0).

    Inputs:
    - asset_criticality: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', or None.
    """
    if not asset_criticality:
        return {
            "score": 0.0,
            "max_points": max_points,
            "ratio": f"0/{int(max_points)}",
            "description": "Uncorrelated target asset (no tier assigned)",
            "details": {"asset_criticality": None},
        }

    crit_upper = asset_criticality.upper().strip()
    tier_weights = {
        "CRITICAL": 14.0 / 15.0,  # 14 out of 15
        "HIGH": 10.0 / 15.0,      # 10 out of 15
        "MEDIUM": 6.0 / 15.0,     # 6 out of 15
        "LOW": 2.0 / 15.0,        # 2 out of 15
    }
    ratio_multiplier = tier_weights.get(crit_upper, 6.0 / 15.0)
    score = round(ratio_multiplier * max_points, 1)
    score_int = int(round(score))
    max_int = int(max_points)

    return {
        "score": score,
        "max_points": max_points,
        "ratio": f"{score_int}/{max_int}",
        "description": f"Asset classified as {crit_upper} enterprise priority",
        "details": {"asset_criticality": crit_upper},
    }


def calculate_threat_risk(
    cisa_kev_status: bool = False,
    event_severity: Optional[str] = None,
    attack_category: Optional[str] = None,
    max_points: float = 15.0,
) -> Dict[str, Any]:
    """
    Calculates the active threat and exploitation component (0 to max_points, default 15.0).
    Evaluates:
    - CISA KEV presence (actively exploited in the wild): up to 15 points.
    - Correlated event severity (CRITICAL, HIGH, MEDIUM, LOW) if observed.
    """
    points = 0.0
    reasons: List[str] = []

    if cisa_kev_status:
        points += 12.0
        reasons.append("Listed in CISA Known Exploited Vulnerabilities (KEV) catalog")

    if event_severity:
        sev_upper = event_severity.upper().strip()
        sev_map = {
            "CRITICAL": 3.0,
            "HIGH": 2.5,
            "MEDIUM": 1.5,
            "LOW": 0.5,
            "INFORMATIONAL": 0.0,
        }
        points += sev_map.get(sev_upper, 1.0)
        reasons.append(f"Observed event severity: {sev_upper}")

    if not cisa_kev_status and not event_severity:
        return {
            "score": 0.0,
            "max_points": max_points,
            "ratio": f"0/{int(max_points)}",
            "description": "No active threat intelligence or event severity linked",
            "details": {
                "cisa_kev_status": False,
                "event_severity": None,
                "attack_category": attack_category,
            },
        }

    final_score = round(min(max_points, max(0.0, points)), 1)
    score_int = int(round(final_score))
    max_int = int(max_points)

    desc = "; ".join(reasons) if reasons else "Threat telemetry evaluated"

    return {
        "score": final_score,
        "max_points": max_points,
        "ratio": f"{score_int}/{max_int}",
        "description": desc,
        "details": {
            "cisa_kev_status": bool(cisa_kev_status),
            "event_severity": event_severity,
            "attack_category": attack_category,
        },
    }


def calculate_exposure_risk(
    asset_exposure: Optional[str] = None,
    internet_exposed: Optional[bool] = None,
    max_points: float = 15.0,
) -> Dict[str, Any]:
    """
    Calculates the network perimeter exposure component (0 to max_points, default 15.0).

    Inputs:
    - asset_exposure: 'EXTERNAL', 'DMZ', 'INTERNAL', 'ISOLATED'
    - internet_exposed: bool
    """
    if asset_exposure is None and internet_exposed is None:
        return {
            "score": 0.0,
            "max_points": max_points,
            "ratio": f"0/{int(max_points)}",
            "description": "Network exposure boundary uncorrelated / missing",
            "details": {"asset_exposure": None, "internet_exposed": None},
        }

    exp_str = (asset_exposure or "").upper().strip()
    if internet_exposed is True or exp_str in ("EXTERNAL", "PUBLIC", "INTERNET"):
        score = 12.0  # 12 out of 15
        desc = "Public internet-facing perimeter"
    elif exp_str == "DMZ":
        score = 8.0   # 8 out of 15
        desc = "Demilitarized zone (DMZ) perimeter"
    elif exp_str in ("INTERNAL", "PRIVATE"):
        score = 4.0   # 4 out of 15
        desc = "Internal segmented corporate network"
    elif exp_str in ("ISOLATED", "AIR_GAPPED"):
        score = 1.0   # 1 out of 15
        desc = "Air-gapped or strongly isolated network"
    else:
        score = 4.0
        desc = "Standard internal enterprise segment"

    score = round(min(max_points, max(0.0, score)), 1)
    score_int = int(round(score))
    max_int = int(max_points)

    return {
        "score": score,
        "max_points": max_points,
        "ratio": f"{score_int}/{max_int}",
        "description": desc,
        "details": {"asset_exposure": asset_exposure, "internet_exposed": internet_exposed},
    }


def calculate_frequency_risk(
    attack_frequency: int = 1,
    max_points: float = 15.0,
) -> Dict[str, Any]:
    """
    Calculates the incident attack frequency component (0 to max_points, default 15.0).

    Inputs:
    - attack_frequency: count of observed attacks/events against target.
    """
    count = max(0, int(attack_frequency))
    if count == 0:
        return {
            "score": 0.0,
            "max_points": max_points,
            "ratio": f"0/{int(max_points)}",
            "description": "No security events recorded (zero frequency)",
            "details": {"attack_frequency": 0},
        }
    elif count == 1:
        # Isolated single event
        score = 2.0
        desc = "Single isolated security event recorded"
    elif count <= 3:
        score = 5.0
        desc = f"Moderate incident telemetry ({count} occurrences observed)"
    elif count <= 7:
        score = 10.0
        desc = f"Repeated attacks observed ({count} occurrences logged)"
    else:
        # High repeated attacks (e.g. 8+ occurrences)
        score = min(max_points, 10.0 + (count - 7) * 1.0)
        desc = f"Severe repeated sustained attacks ({count} occurrences logged)"

    score = round(min(max_points, max(0.0, score)), 1)
    score_int = int(round(score))
    max_int = int(max_points)

    return {
        "score": score,
        "max_points": max_points,
        "ratio": f"{score_int}/{max_int}",
        "description": desc,
        "details": {"attack_frequency": count},
    }


def calculate_recency_risk(
    timestamp: Optional[str] = None,
    hours_ago: Optional[float] = None,
    max_points: float = 10.0,
) -> Dict[str, Any]:
    """
    Calculates the temporal recency component (0 to max_points, default 10.0).

    Inputs:
    - timestamp: ISO-8601 string or None.
    - hours_ago: elapsed hours since event/finding. If None, calculated from timestamp.
    """
    elapsed: Optional[float] = hours_ago

    if elapsed is None and timestamp:
        try:
            # Parse ISO 8601 string
            clean_ts = timestamp.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean_ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            elapsed = max(0.0, (now - dt).total_seconds() / 3600.0)
        except Exception:
            elapsed = None

    if elapsed is None:
        return {
            "score": 0.0,
            "max_points": max_points,
            "ratio": f"0/{int(max_points)}",
            "description": "Event timestamp missing or uncorrelated",
            "details": {"timestamp": timestamp, "hours_ago": None},
        }

    # Bounded decay formula matching operational SLA brackets
    if elapsed <= 1.0:
        score = 10.0
        desc = f"Active incident observed within the past hour ({round(elapsed * 60)} min ago)"
    elif elapsed <= 24.0:
        score = 8.0
        desc = f"Recent incident observed within past 24 hours ({round(elapsed, 1)} hrs ago)"
    elif elapsed <= 168.0:  # 7 days
        score = 5.0
        desc = f"Incident observed within past 7 days ({round(elapsed / 24.0, 1)} days ago)"
    elif elapsed <= 720.0:  # 30 days
        score = 3.0
        desc = f"Historical incident observed within past 30 days ({round(elapsed / 24.0, 1)} days ago)"
    else:
        score = 1.0
        desc = f"Older historical telemetry (> 30 days ago)"

    score = round(min(max_points, max(0.0, score)), 1)
    score_int = int(round(score))
    max_int = int(max_points)

    return {
        "score": score,
        "max_points": max_points,
        "ratio": f"{score_int}/{max_int}",
        "description": desc,
        "details": {"timestamp": timestamp, "hours_ago": elapsed},
    }


def calculate_final_risk(
    cvss_score: Optional[float] = None,
    cisa_kev_status: bool = False,
    asset_criticality: Optional[str] = None,
    asset_exposure: Optional[str] = None,
    event_severity: Optional[str] = None,
    attack_frequency: int = 1,
    vulnerability_status: Optional[str] = "OPEN",
    patch_availability: Optional[Union[str, bool]] = None,
    recency_timestamp: Optional[str] = None,
    recency_hours_ago: Optional[float] = None,
    correlated_finding: Optional[Dict[str, Any]] = None,
    thresholds: Optional[Dict[str, Tuple[float, float]]] = None,
) -> Dict[str, Any]:
    """
    Computes the explainable CRISP Multi-Factor Cyber Risk Score (0–100 scale).

    Inputs can be supplied individually or extracted directly from a correlated_finding.

    Returns:
    - score: float (0–100)
    - risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
    - factors: List[Dict[str, Any]]
    - factor_scores: Dict[str, str] (e.g. {'CVSS': '28/30', 'Known Exploited': '15/15', ...})
    - explanation: Human-readable transparent explanation
    - methodology: CRISP project-defined methodology statement
    """
    # If correlated_finding is provided, unpack missing arguments
    if correlated_finding:
        if cvss_score is None:
            cvss_score = correlated_finding.get("cvss_score")
        if not cisa_kev_status:
            cisa_kev_status = bool(
                correlated_finding.get("known_exploited")
                or correlated_finding.get("is_known_exploited")
            )
        if asset_criticality is None:
            asset_criticality = correlated_finding.get("asset_criticality")
        if event_severity is None:
            event_severity = correlated_finding.get("severity")
        if attack_frequency == 1 and correlated_finding.get("event_frequency"):
            attack_frequency = int(correlated_finding["event_frequency"])
        if recency_timestamp is None:
            recency_timestamp = correlated_finding.get("timestamp")

    # 1. Vulnerability Risk (Max 30 pts)
    vuln_comp = calculate_vulnerability_risk(
        cvss_score=cvss_score,
        vulnerability_status=vulnerability_status,
        patch_availability=patch_availability,
        max_points=30.0,
    )

    # 2. Threat Risk (Max 15 pts) - incorporates CISA KEV and Event Severity
    threat_comp = calculate_threat_risk(
        cisa_kev_status=cisa_kev_status,
        event_severity=event_severity,
        max_points=15.0,
    )

    # 3. Asset Risk (Max 15 pts) - evaluates criticality tier
    asset_comp = calculate_asset_risk(
        asset_criticality=asset_criticality,
        max_points=15.0,
    )

    # 4. Exposure Risk (Max 15 pts) - evaluates perimeter boundary
    exp_comp = calculate_exposure_risk(
        asset_exposure=asset_exposure,
        max_points=15.0,
    )

    # 5. Frequency Risk (Max 15 pts) - evaluates repeated incident attacks
    freq_comp = calculate_frequency_risk(
        attack_frequency=attack_frequency,
        max_points=15.0,
    )

    # 6. Recency Risk (Max 10 pts) - evaluates temporal freshness
    recency_comp = calculate_recency_risk(
        timestamp=recency_timestamp,
        hours_ago=recency_hours_ago,
        max_points=10.0,
    )

    # Sum raw scores (strictly bounded [0.0, 100.0])
    raw_total = (
        vuln_comp["score"]
        + threat_comp["score"]
        + asset_comp["score"]
        + exp_comp["score"]
        + freq_comp["score"]
        + recency_comp["score"]
    )
    final_score = round(max(0.0, min(100.0, raw_total)), 1)
    risk_level = get_risk_level(final_score, thresholds=thresholds)

    # Standard factor scores mapping required by CRISP specifications
    factor_scores = {
        "CVSS": vuln_comp["ratio"],
        "Known Exploited": threat_comp["ratio"],
        "Asset Criticality": asset_comp["ratio"],
        "Exposure": exp_comp["ratio"],
        "Attack Frequency": freq_comp["ratio"],
        "Recency": recency_comp["ratio"],
        # Normalized key aliases for machine accessibility
        "cvss": vuln_comp["ratio"],
        "known_exploited": threat_comp["ratio"],
        "asset_criticality": asset_comp["ratio"],
        "exposure": exp_comp["ratio"],
        "attack_frequency": freq_comp["ratio"],
        "recency": recency_comp["ratio"],
    }

    factors = [
        {
            "factor": "CVSS",
            "name": "CVSS Vulnerability Severity",
            "score": vuln_comp["score"],
            "max_score": vuln_comp["max_points"],
            "ratio": vuln_comp["ratio"],
            "description": vuln_comp["description"],
        },
        {
            "factor": "Known Exploited",
            "name": "Threat & CISA KEV Exploitation",
            "score": threat_comp["score"],
            "max_score": threat_comp["max_points"],
            "ratio": threat_comp["ratio"],
            "description": threat_comp["description"],
        },
        {
            "factor": "Asset Criticality",
            "name": "Asset Criticality Priority",
            "score": asset_comp["score"],
            "max_score": asset_comp["max_points"],
            "ratio": asset_comp["ratio"],
            "description": asset_comp["description"],
        },
        {
            "factor": "Exposure",
            "name": "Perimeter Exposure",
            "score": exp_comp["score"],
            "max_score": exp_comp["max_points"],
            "ratio": exp_comp["ratio"],
            "description": exp_comp["description"],
        },
        {
            "factor": "Attack Frequency",
            "name": "Attack Frequency Telemetry",
            "score": freq_comp["score"],
            "max_score": freq_comp["max_points"],
            "ratio": freq_comp["ratio"],
            "description": freq_comp["description"],
        },
        {
            "factor": "Recency",
            "name": "Event Recency",
            "score": recency_comp["score"],
            "max_score": recency_comp["max_points"],
            "ratio": recency_comp["ratio"],
            "description": recency_comp["description"],
        },
    ]

    # Generate transparent explainability rationale
    explanation_clauses: List[str] = []
    if cvss_score is not None and cvss_score >= 7.0:
        explanation_clauses.append("has high vulnerability severity")
    elif cvss_score is not None and cvss_score >= 4.0:
        explanation_clauses.append("has moderate vulnerability severity")

    if cisa_kev_status:
        explanation_clauses.append("is present in the CISA KEV catalog")

    crit_upper = (asset_criticality or "").upper().strip()
    exp_upper = (asset_exposure or "").upper().strip()
    if crit_upper in ("CRITICAL", "HIGH") and exp_upper in ("EXTERNAL", "PUBLIC", "INTERNET"):
        explanation_clauses.append("affects a highly critical exposed asset")
    elif crit_upper in ("CRITICAL", "HIGH"):
        explanation_clauses.append("affects a highly critical asset")
    elif exp_upper in ("EXTERNAL", "PUBLIC", "INTERNET"):
        explanation_clauses.append("is exposed to the public internet")

    if attack_frequency > 1:
        explanation_clauses.append("has repeated recent security events")
    elif recency_comp["score"] >= 8.0:
        explanation_clauses.append("occurred recently")

    if explanation_clauses:
        explanation = "The finding " + ", ".join(explanation_clauses) + "."
    else:
        explanation = f"Assessed at {risk_level} risk under baseline operational profile with minimal active threat signals."

    return {
        "score": final_score,
        "risk_level": risk_level,
        "factors": factors,
        "factor_scores": factor_scores,
        "explanation": explanation,
        "methodology": "CRISP project-defined multi-factor risk model (NOT an official NIST formula)",
        "component_breakdown": {
            "vulnerability_score": vuln_comp["score"],
            "threat_score": threat_comp["score"],
            "asset_score": asset_comp["score"],
            "exposure_score": exp_comp["score"],
            "frequency_score": freq_comp["score"],
            "recency_score": recency_comp["score"],
        },
    }


# =========================================================================
# SQLite Risk History Tracking
# =========================================================================

def init_risk_history_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """Initializes the risk_history table in SQLite for temporal risk tracking."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS risk_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                asset TEXT,
                finding TEXT,
                score REAL NOT NULL,
                level TEXT NOT NULL,
                factors_json TEXT,
                factor_scores_json TEXT,
                explanation TEXT,
                created_at TEXT NOT NULL
            );
            """
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_risk_hist_ts ON risk_history(timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_risk_hist_asset ON risk_history(asset);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_risk_hist_finding ON risk_history(finding);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_risk_hist_level ON risk_history(level);")
        conn.commit()


def record_risk_history(
    score_data: Dict[str, Any],
    asset: Optional[str] = None,
    finding: Optional[str] = None,
    timestamp: Optional[str] = None,
    db_path: str = DEFAULT_DB_PATH,
) -> int:
    """
    Inserts a risk calculation entry into the risk_history table.
    Returns the newly inserted record id.
    """
    init_risk_history_db(db_path)
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ts = timestamp or now_iso
    score = float(score_data.get("score", 0.0))
    level = str(score_data.get("risk_level", "LOW"))
    factors_json = json.dumps(score_data.get("factors", []))
    factor_scores_json = json.dumps(score_data.get("factor_scores", {}))
    explanation = score_data.get("explanation", "")

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO risk_history (
                timestamp, asset, finding, score, level,
                factors_json, factor_scores_json, explanation, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (ts, asset, finding, score, level, factors_json, factor_scores_json, explanation, now_iso),
        )
        conn.commit()
        return cursor.lastrowid or 0


def get_risk_history(
    asset: Optional[str] = None,
    finding: Optional[str] = None,
    level: Optional[str] = None,
    limit: int = 100,
    db_path: str = DEFAULT_DB_PATH,
) -> List[Dict[str, Any]]:
    """Retrieves risk history calculations over time."""
    init_risk_history_db(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        query = "SELECT * FROM risk_history WHERE 1=1"
        params: List[Any] = []

        if asset and asset.upper() != "ALL":
            query += " AND asset = ?"
            params.append(asset)
        if finding and finding.upper() != "ALL":
            query += " AND finding = ?"
            params.append(finding)
        if level and level.upper() != "ALL":
            query += " AND level = ?"
            params.append(level.upper())

        query += " ORDER BY timestamp DESC, id DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        records = []
        for r in cursor.fetchall():
            row_dict = dict(r)
            try:
                row_dict["factors"] = json.loads(row_dict.get("factors_json") or "[]")
            except Exception:
                row_dict["factors"] = []
            try:
                row_dict["factor_scores"] = json.loads(row_dict.get("factor_scores_json") or "{}")
            except Exception:
                row_dict["factor_scores"] = {}
            records.append(row_dict)
        return records


def get_risk_over_time_trend(
    asset: Optional[str] = None,
    limit: int = 50,
    db_path: str = DEFAULT_DB_PATH,
) -> List[Dict[str, Any]]:
    """
    Returns time-series risk trend data suitable for rendering Risk Over Time charts.
    """
    records = get_risk_history(asset=asset, limit=limit, db_path=db_path)
    # Reverse so chronologically ascending for charts
    records.reverse()
    return [
        {
            "timestamp": r["timestamp"],
            "asset": r["asset"],
            "finding": r["finding"],
            "score": r["score"],
            "level": r["level"],
        }
        for r in records
    ]


# =========================================================================
# Backward Compatibility Wrappers
# =========================================================================

def calculate_crisp_vulnerability_risk(
    cve_id: str,
    cvss_score: Optional[float] = None,
    known_exploited: bool = False,
    asset_criticality: str = "HIGH",
    internet_exposed: bool = True,
    kev_risk_weight: float = KEV_RISK_WEIGHT,
) -> Dict[str, Any]:
    """
    Backward-compatible adapter for tests and legacy callers.
    Retains exact return interface and KEV_RISK_WEIGHT arithmetic.
    """
    factors: List[Dict[str, Any]] = []

    # 1. CVSS Component
    if cvss_score is not None and cvss_score > 0:
        cvss_points = min(40.0, cvss_score * 4.0)
        cvss_label = (
            "Critical" if cvss_score >= 9.0 else "High" if cvss_score >= 7.0 else "Medium" if cvss_score >= 4.0 else "Low"
        )
    else:
        cvss_points = 0.0
        cvss_label = "None (No CVSS provided)"

    factors.append({
        "factor": "CVSS Score",
        "value": cvss_label,
        "score_contribution": round(cvss_points, 1),
        "description": f"CVSS base metric contribution: {cvss_score if cvss_score is not None else 'N/A'}",
    })

    # 2. Asset Criticality Component
    crit_upper = (asset_criticality or "MEDIUM").upper()
    crit_points_map = {"CRITICAL": 25.0, "HIGH": 18.0, "MEDIUM": 10.0, "LOW": 5.0}
    crit_points = crit_points_map.get(crit_upper, 10.0)
    factors.append({
        "factor": "Asset Criticality",
        "value": crit_upper.title(),
        "score_contribution": round(crit_points, 1),
        "description": f"Target asset classified as {crit_upper} tier",
    })

    # 3. Internet Exposure Component
    exposure_points = 20.0 if internet_exposed else 5.0
    factors.append({
        "factor": "Internet Exposure",
        "value": "High (Publicly Facing)" if internet_exposed else "Low (Internal Isolated)",
        "score_contribution": round(exposure_points, 1),
        "description": "Public internet-facing perimeter" if internet_exposed else "Internal segment",
    })

    # 4. Known Exploited Vulnerability (CISA KEV) Component
    kev_points = kev_risk_weight if known_exploited else 0.0
    factors.append({
        "factor": "Known Exploited Vulnerability",
        "value": "YES" if known_exploited else "NO",
        "score_contribution": round(kev_points, 1),
        "description": (
            f"CRISP project-defined risk weighting (+{kev_risk_weight} pts for active in-the-wild exploitation)"
            if known_exploited
            else "Not currently listed in CISA KEV catalog"
        ),
    })

    # Total Score bounded [0, 100]
    total_score = round(min(100.0, max(0.0, cvss_points + crit_points + exposure_points + kev_points)), 1)
    risk_level = get_risk_level(total_score)

    # Transparent Explanation Generator
    explanation_parts = []
    if cvss_score is not None and cvss_score >= 7.0:
        explanation_parts.append(f"has a high CVSS base score ({cvss_score})")
    elif cvss_score is None:
        explanation_parts.append("has no official CVSS score assigned yet")

    if known_exploited:
        explanation_parts.append("is listed in the CISA Known Exploited Vulnerabilities catalog (actively exploited in the wild)")

    if crit_upper in ("CRITICAL", "HIGH"):
        explanation_parts.append(f"the affected asset is classified as {crit_upper.lower()} priority")

    if internet_exposed:
        explanation_parts.append("the host is exposed directly to the public internet")

    if explanation_parts:
        explanation = f"{cve_id} is considered {risk_level.lower()} risk because it " + ", and ".join(explanation_parts) + "."
    else:
        explanation = f"{cve_id} is assessed at {risk_level.lower()} risk under baseline enterprise exposure."

    return {
        "cve_id": cve_id,
        "risk_score": total_score,
        "risk_level": risk_level,
        "contributing_factors": factors,
        "explanation": explanation,
        "known_exploited": known_exploited,
        "methodology": "CRISP project-defined risk weighting (NOT an official NIST or CISA score)",
    }


def calculate_crisp_security_event_risk(
    event_id: str,
    attack_category: str,
    severity: str,
    cve_id: Optional[str] = None,
    asset_id: Optional[str] = None,
    asset_criticality: Optional[str] = None,
    frequency_count: int = 1,
) -> Dict[str, Any]:
    """
    Backward-compatible adapter for security event risk scoring.
    """
    sev_upper = (severity or "LOW").upper()
    sev_points_map = {"CRITICAL": 65.0, "HIGH": 45.0, "MEDIUM": 25.0, "LOW": 10.0, "INFORMATIONAL": 0.0}
    sev_points = sev_points_map.get(sev_upper, 10.0)

    cat_upper = (attack_category or "").upper()
    cat_points = 15.0 if "EXPLOIT" in cat_upper else 12.0 if "DDOS" in cat_upper else 5.0
    freq_count = max(1, frequency_count)
    freq_points = min(20.0, max(0.0, (freq_count - 1) * 3.0))
    cve_points = 15.0 if (cve_id and cve_id.strip() and cve_id.upper() != "NONE") else 0.0
    crit_upper = (asset_criticality or "MEDIUM").upper() if asset_id else "NONE"
    crit_points_map = {"CRITICAL": 12.0, "HIGH": 8.0, "MEDIUM": 4.0, "LOW": 0.0, "NONE": 0.0}
    crit_points = crit_points_map.get(crit_upper, 0.0)

    total_score = round(min(100.0, max(0.0, sev_points + cat_points + freq_points + cve_points + crit_points)), 1)
    risk_level = get_risk_level(total_score)

    return {
        "event_id": event_id,
        "risk_score": total_score,
        "risk_level": risk_level,
        "contributing_factors": [
            {"factor": "Event Severity", "value": sev_upper, "score_contribution": sev_points},
            {"factor": "Attack Frequency", "value": f"{freq_count} observed", "score_contribution": freq_points},
        ],
        "explanation": f"Security event {event_id} assessed at {risk_level} risk (score: {total_score}/100).",
        "methodology": "CRISP project-defined event scoring (NOT an official dataset rating)",
    }
