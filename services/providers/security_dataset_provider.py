"""
CRISP Cybersecurity Platform - Security Dataset Provider (CIC-IDS2017)
Phase 2 Step 3: Ingestion, normalization, attack label mapping, and chunked processing
for historical public research cybersecurity datasets (e.g. CIC-IDS2017).

Official dataset source:
https://www.unb.ca/cic/datasets/ids-2017.html

Data Provenance:
- Labeled: 'Historical Public Dataset'
- dataset_source: 'CIC-IDS2017'
- Strict zero-fabrication policy for missing network attributes.
"""

import csv
import logging
import os
import re
from datetime import datetime
from typing import Any, Dict, Generator, List, Optional, Set, Tuple

logger = logging.getLogger("CRISP.SecurityDataset")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] [CRISP.Dataset] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# Default paths and configurations
DEFAULT_DATASET_PATH = os.path.join("data", "cic_ids2017_sample.csv")
DEFAULT_CHUNK_SIZE = 5000
DEFAULT_IMPORT_LIMIT = 10000

# Transparent CRISP project-defined attack label & severity mappings
# IMPORTANT: This is a CRISP project-defined categorization, NOT an official rating from UNB CIC.
CIC_ATTACK_MAPPING: Dict[str, Dict[str, str]] = {
    "DDoS": {
        "category": "Denial of Service (DDoS)",
        "severity": "CRITICAL",
        "event_type": "Distributed Denial of Service Attack",
        "nist_function": "RESPOND",
    },
    "PortScan": {
        "category": "Reconnaissance (Port Scan)",
        "severity": "LOW",
        "event_type": "Network Port Scanning & Sweep",
        "nist_function": "DETECT",
    },
    "FTP-Patator": {
        "category": "Brute Force (FTP)",
        "severity": "MEDIUM",
        "event_type": "FTP Credential Brute Force Attempt",
        "nist_function": "PROTECT",
    },
    "SSH-Patator": {
        "category": "Brute Force (SSH)",
        "severity": "HIGH",
        "event_type": "SSH Authentication Dictionary Attack",
        "nist_function": "PROTECT",
    },
    "DoS slowloris": {
        "category": "Denial of Service (Slowloris)",
        "severity": "HIGH",
        "event_type": "Slowloris HTTP Exhaustion Attack",
        "nist_function": "RESPOND",
    },
    "DoS Slowhttptest": {
        "category": "Denial of Service (SlowHTTP)",
        "severity": "HIGH",
        "event_type": "SlowHTTP DoS Attack",
        "nist_function": "RESPOND",
    },
    "DoS Hulk": {
        "category": "Denial of Service (Hulk)",
        "severity": "HIGH",
        "event_type": "Hulk Web Server Flooding Attack",
        "nist_function": "RESPOND",
    },
    "DoS GoldenEye": {
        "category": "Denial of Service (GoldenEye)",
        "severity": "HIGH",
        "event_type": "GoldenEye Layer-7 DoS Attack",
        "nist_function": "RESPOND",
    },
    "Heartbleed": {
        "category": "Exploit (Heartbleed)",
        "severity": "CRITICAL",
        "event_type": "OpenSSL TLS Heartbeat Memory Disclosure (CVE-2014-0160)",
        "nist_function": "RESPOND",
    },
    "Bot": {
        "category": "Command & Control (Botnet)",
        "severity": "HIGH",
        "event_type": "Botnet Command & Control Communication",
        "nist_function": "DETECT",
    },
    "Web Attack – Brute Force": {
        "category": "Web Attack (Brute Force)",
        "severity": "MEDIUM",
        "event_type": "Web Application Password Brute Force",
        "nist_function": "PROTECT",
    },
    "Web Attack – XSS": {
        "category": "Web Attack (Cross-Site Scripting)",
        "severity": "MEDIUM",
        "event_type": "Reflected / Stored Cross-Site Scripting Attempt",
        "nist_function": "PROTECT",
    },
    "Web Attack – Sql Injection": {
        "category": "Web Attack (SQL Injection)",
        "severity": "HIGH",
        "event_type": "SQL Injection Query Probe",
        "nist_function": "PROTECT",
    },
    "Infiltration": {
        "category": "Infiltration / Privilege Escalation",
        "severity": "CRITICAL",
        "event_type": "Internal Network Infiltration & Lateral Movement",
        "nist_function": "RESPOND",
    },
    "BENIGN": {
        "category": "Benign Network Traffic",
        "severity": "INFORMATIONAL",
        "event_type": "Normal Baseline Enterprise Traffic Flow",
        "nist_function": "IDENTIFY",
    },
}

# Standard IP Protocol Mapping
PROTOCOL_MAP: Dict[int, str] = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
}


def map_attack_label(raw_label: Optional[str]) -> Dict[str, str]:
    """
    Maps an external dataset attack label to the CRISP internal classification.
    Preserves original label without hallucination or fabrication.
    """
    if not raw_label or not isinstance(raw_label, str):
        return {
            "crisp_attack_category": "Unclassified Traffic",
            "severity": "LOW",
            "event_type": "Unclassified Network Event",
            "nist_function": "DETECT",
        }

    clean_label = raw_label.strip()

    # Exact match
    if clean_label in CIC_ATTACK_MAPPING:
        mapping = CIC_ATTACK_MAPPING[clean_label]
        return {
            "crisp_attack_category": mapping["category"],
            "severity": mapping["severity"],
            "event_type": mapping["event_type"],
            "nist_function": mapping["nist_function"],
        }

    # Case-insensitive / whitespace-tolerant match
    lower_label = clean_label.lower()
    for known_lbl, mapping in CIC_ATTACK_MAPPING.items():
        if known_lbl.lower() == lower_label:
            return {
                "crisp_attack_category": mapping["category"],
                "severity": mapping["severity"],
                "event_type": mapping["event_type"],
                "nist_function": mapping["nist_function"],
            }

    # Partial keyword heuristic for variants in sub-files
    if "ddos" in lower_label:
        return {"crisp_attack_category": "Denial of Service (DDoS)", "severity": "CRITICAL", "event_type": clean_label, "nist_function": "RESPOND"}
    if "dos" in lower_label:
        return {"crisp_attack_category": "Denial of Service", "severity": "HIGH", "event_type": clean_label, "nist_function": "RESPOND"}
    if "portscan" in lower_label or "scan" in lower_label:
        return {"crisp_attack_category": "Reconnaissance (Port Scan)", "severity": "LOW", "event_type": clean_label, "nist_function": "DETECT"}
    if "brute" in lower_label or "patator" in lower_label:
        return {"crisp_attack_category": "Brute Force", "severity": "MEDIUM", "event_type": clean_label, "nist_function": "PROTECT"}
    if "sql" in lower_label:
        return {"crisp_attack_category": "Web Attack (SQL Injection)", "severity": "HIGH", "event_type": clean_label, "nist_function": "PROTECT"}
    if "xss" in lower_label:
        return {"crisp_attack_category": "Web Attack (Cross-Site Scripting)", "severity": "MEDIUM", "event_type": clean_label, "nist_function": "PROTECT"}
    if "bot" in lower_label:
        return {"crisp_attack_category": "Command & Control (Botnet)", "severity": "HIGH", "event_type": clean_label, "nist_function": "DETECT"}
    if "infiltrat" in lower_label:
        return {"crisp_attack_category": "Infiltration / Privilege Escalation", "severity": "CRITICAL", "event_type": clean_label, "nist_function": "RESPOND"}
    if "benign" in lower_label:
        return {"crisp_attack_category": "Benign Network Traffic", "severity": "INFORMATIONAL", "event_type": "Normal Traffic", "nist_function": "IDENTIFY"}

    return {
        "crisp_attack_category": f"External ({clean_label})",
        "severity": "MEDIUM",
        "event_type": clean_label,
        "nist_function": "DETECT",
    }


def parse_timestamp(raw_ts: Optional[str]) -> Optional[str]:
    """
    Parses CIC-IDS2017 timestamps into standard ISO-8601 strings (YYYY-MM-DDTHH:MM:SSZ).
    Handles formats like '07/07/2017 01:23:45', '7/7/2017 8:30', or standard ISO-8601.
    Returns None if missing or completely invalid.
    """
    if not raw_ts or not isinstance(raw_ts, str):
        return None

    clean_ts = raw_ts.strip()
    if clean_ts == "" or clean_ts.lower() in ("null", "none", "nan"):
        return None

    formats = [
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(clean_ts, fmt)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            pass

    # If unparseable but looks like a timestamp, return clean string or None
    return None


def is_valid_security_row(raw_record: Dict[str, Any]) -> bool:
    """Checks whether a raw record has at least minimal valid fields (not all empty/whitespace)."""
    if not raw_record or not isinstance(raw_record, dict):
        return False
    # Check if there is at least one non-whitespace, non-null value
    non_empty = [
        str(v).strip() for v in raw_record.values()
        if v is not None and str(v).strip() != "" and str(v).strip().lower() not in ("null", "none", "nan")
    ]
    return len(non_empty) > 0


def normalize_security_event(
    raw_record: Dict[str, Any],
    dataset_source: str = "CIC-IDS2017",
    record_index: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Normalizes a single row from an external security dataset into the
    canonical CRISP SecurityEvent internal schema.

    Strict zero-fabrication rules:
    - Never invent missing IP addresses, ports, or timestamps.
    - If a field is missing, set to None.
    - Keep original_attack_label intact alongside crisp_attack_category.
    """
    if not isinstance(raw_record, dict):
        raise ValueError("raw_record must be a dictionary")

    if not is_valid_security_row(raw_record):
        raise ValueError("Invalid row: record has no non-empty values")

    # Clean keys (CICFlowMeter headers often have leading/trailing whitespace like ' Label')
    cleaned_record = {k.strip(): v for k, v in raw_record.items() if k is not None}

    # Extract Flow ID / Event ID
    flow_id = cleaned_record.get("Flow ID") or cleaned_record.get("event_id") or cleaned_record.get("id")
    if not flow_id or str(flow_id).strip() == "" or str(flow_id).strip().lower() in ("null", "none"):
        # Generate deterministic synthetic event ID if none present in file
        idx_str = f"{record_index:06d}" if record_index is not None else "000001"
        event_id = f"EVT-CIC-{idx_str}"
    else:
        event_id = str(flow_id).strip()

    # Extract Source & Destination IP
    src_ip = cleaned_record.get("Source IP") or cleaned_record.get("src_ip") or cleaned_record.get("SourceIP")
    if src_ip:
        src_ip = str(src_ip).strip()
        if src_ip.lower() in ("null", "none", "nan", ""):
            src_ip = None

    dest_ip = cleaned_record.get("Destination IP") or cleaned_record.get("dest_ip") or cleaned_record.get("DestinationIP")
    if dest_ip:
        dest_ip = str(dest_ip).strip()
        if dest_ip.lower() in ("null", "none", "nan", ""):
            dest_ip = None

    # Extract Ports
    src_port: Optional[int] = None
    raw_src_port = cleaned_record.get("Source Port") or cleaned_record.get("src_port")
    if raw_src_port not in (None, "", "null", "None", "nan"):
        try:
            src_port = int(float(str(raw_src_port).strip()))
        except (ValueError, TypeError):
            src_port = None

    dest_port: Optional[int] = None
    raw_dest_port = cleaned_record.get("Destination Port") or cleaned_record.get("dest_port")
    if raw_dest_port not in (None, "", "null", "None", "nan"):
        try:
            dest_port = int(float(str(raw_dest_port).strip()))
        except (ValueError, TypeError):
            dest_port = None

    # Extract Protocol
    raw_protocol = cleaned_record.get("Protocol") or cleaned_record.get("protocol")
    protocol_str: Optional[str] = None
    if raw_protocol not in (None, "", "null", "None", "nan"):
        try:
            proto_int = int(float(str(raw_protocol).strip()))
            protocol_str = PROTOCOL_MAP.get(proto_int, f"PROTO-{proto_int}")
        except (ValueError, TypeError):
            protocol_str = str(raw_protocol).strip().upper()

    # Extract Timestamp
    raw_ts = cleaned_record.get("Timestamp") or cleaned_record.get("timestamp") or cleaned_record.get("timestamp_utc")
    timestamp_iso = parse_timestamp(raw_ts)

    # Extract Attack Label
    raw_label = (
        cleaned_record.get("Label")
        or cleaned_record.get("attack_label")
        or cleaned_record.get("threat_category")
        or cleaned_record.get("attack_category")
    )
    original_label = str(raw_label).strip() if raw_label not in (None, "", "null", "None", "nan") else "Unlabeled"

    # Map attack label & severity
    mapping = map_attack_label(original_label)
    crisp_category = mapping["crisp_attack_category"]
    severity = mapping["severity"]
    event_type = mapping["event_type"]
    nist_function = mapping["nist_function"]

    # Explicitly check for Heartbleed CVE reference in benchmark
    cve_id: Optional[str] = cleaned_record.get("cve_reference") or cleaned_record.get("cve_id")
    if not cve_id and "heartbleed" in original_label.lower():
        cve_id = "CVE-2014-0160"
    elif cve_id:
        cve_id = str(cve_id).strip()
        if cve_id.lower() in ("null", "none", "nan", ""):
            cve_id = None

    # Asset ID if present in dataset
    asset_id = cleaned_record.get("target_asset_id") or cleaned_record.get("asset_id")
    if asset_id:
        asset_id = str(asset_id).strip()
        if asset_id.lower() in ("null", "none", "nan", ""):
            asset_id = None

    # Construct descriptive narrative
    description = (
        cleaned_record.get("alert_summary")
        or cleaned_record.get("description")
        or f"Historical security benchmark telemetry: {original_label} detected on destination port {dest_port or 'N/A'} via protocol {protocol_str or 'N/A'}."
    )

    return {
        "event_id": event_id,
        "timestamp": timestamp_iso,
        "source_ip": src_ip,
        "destination_ip": dest_ip,
        "source_port": src_port,
        "destination_port": dest_port,
        "protocol": protocol_str,
        "event_type": event_type,
        "severity": severity,
        "status": "HISTORICAL_RECORD",
        "attack_category": crisp_category,
        "original_attack_label": original_label,
        "crisp_attack_category": crisp_category,
        "description": description,
        "asset_id": asset_id,
        "nist_function": nist_function,
        "cve_id": cve_id,
        "source": dataset_source,
        "dataset_source": dataset_source,
        "crisp_risk_score": 0.0,  # Will be evaluated by risk engine
    }


class SecurityDatasetProvider:
    """
    Data Provider for historical cybersecurity research datasets.
    Supports chunked CSV streaming, schema normalization, and validation.
    """

    def __init__(
        self,
        dataset_path: Optional[str] = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        limit: Optional[int] = None,
    ) -> None:
        env_path = os.environ.get("SECURITY_DATASET_PATH")
        self.dataset_path = dataset_path or env_path or DEFAULT_DATASET_PATH
        self.chunk_size = chunk_size

        env_limit = os.environ.get("DATASET_IMPORT_LIMIT")
        if limit is not None:
            self.limit = limit
        elif env_limit:
            try:
                self.limit = int(env_limit)
            except ValueError:
                self.limit = DEFAULT_IMPORT_LIMIT
        else:
            self.limit = DEFAULT_IMPORT_LIMIT

        logger.info(
            f"Initialized SecurityDatasetProvider: path='{self.dataset_path}', "
            f"chunk_size={self.chunk_size}, limit={self.limit}"
        )

    def file_exists(self) -> bool:
        """Checks if the configured dataset file exists."""
        return os.path.exists(self.dataset_path)

    def get_dataset_info(self) -> Dict[str, Any]:
        """Returns metadata about the target dataset file."""
        if not self.file_exists():
            return {
                "file_name": os.path.basename(self.dataset_path),
                "file_path": self.dataset_path,
                "exists": False,
                "error": "File not found",
            }

        size_bytes = os.path.getsize(self.dataset_path)
        size_mb = round(size_bytes / (1024 * 1024), 2)

        column_names: List[str] = []
        with open(self.dataset_path, mode="r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            try:
                headers = next(reader)
                column_names = [h.strip() for h in headers]
            except StopIteration:
                pass

        return {
            "file_name": os.path.basename(self.dataset_path),
            "file_path": self.dataset_path,
            "file_size_mb": size_mb,
            "exists": True,
            "column_count": len(column_names),
            "columns": column_names,
            "dataset_source": "CIC-IDS2017",
            "provenance": "Historical Public Dataset",
        }

    def stream_raw_chunks(self) -> Generator[List[Dict[str, str]], None, None]:
        """
        Streams records in chunks of `self.chunk_size` from the CSV file.
        Provides constant-memory footprint for large datasets.
        """
        if not self.file_exists():
            raise FileNotFoundError(f"Security dataset not found at: {self.dataset_path}")

        current_chunk: List[Dict[str, str]] = []
        total_yielded = 0

        with open(self.dataset_path, mode="r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                current_chunk.append(row)
                if len(current_chunk) >= self.chunk_size:
                    yield current_chunk
                    total_yielded += len(current_chunk)
                    current_chunk = []
                    if self.limit and total_yielded >= self.limit:
                        break

            if current_chunk and (not self.limit or total_yielded < self.limit):
                yield current_chunk

    def load_normalized_events(
        self,
        limit: Optional[int] = None,
        dataset_source: str = "CIC-IDS2017",
    ) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
        """
        Loads, normalizes, validates, and deduplicates security events.
        Returns:
            (normalized_events, import_summary_stats)
        """
        max_rows = limit or self.limit
        events: List[Dict[str, Any]] = []
        seen_ids: Set[str] = set()

        stats = {
            "rows_read": 0,
            "rows_imported": 0,
            "rows_skipped": 0,
            "duplicates": 0,
            "invalid_rows": 0,
        }

        row_idx = 0
        for chunk in self.stream_raw_chunks():
            for raw_row in chunk:
                row_idx += 1
                stats["rows_read"] += 1

                # Validation checks
                if not raw_row or not any(raw_row.values()):
                    stats["invalid_rows"] += 1
                    stats["rows_skipped"] += 1
                    continue

                try:
                    event = normalize_security_event(
                        raw_row,
                        dataset_source=dataset_source,
                        record_index=row_idx,
                    )
                except Exception as ex:
                    logger.debug(f"Row {row_idx} failed normalization: {ex}")
                    stats["invalid_rows"] += 1
                    stats["rows_skipped"] += 1
                    continue

                event_id = event["event_id"]
                if event_id in seen_ids:
                    stats["duplicates"] += 1
                    stats["rows_skipped"] += 1
                    continue

                seen_ids.add(event_id)
                events.append(event)
                stats["rows_imported"] += 1

                if max_rows and stats["rows_imported"] >= max_rows:
                    return events, stats

        return events, stats
