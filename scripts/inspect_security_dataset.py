#!/usr/bin/env python3
"""
CRISP Cybersecurity Platform - Dataset Inspection Script
Phase 2 Step 3: Inspects real historical cybersecurity datasets (e.g. CIC-IDS2017).

Determines:
- File name and path
- Dataset shape (rows, columns)
- Exact column names (preserving case/whitespace)
- Data types detected
- Sample records (top 3)
- Missing-value summary
- Unique attack/traffic labels
"""

import csv
import json
import os
import sys
from collections import Counter
from typing import Any, Dict, List, Set, Tuple


def infer_type(val: str) -> str:
    """Infers the primitive type of a string value."""
    if val is None or val.strip() == "":
        return "NULL"
    val = val.strip()
    # Check int
    try:
        int(val)
        return "int"
    except ValueError:
        pass
    # Check float
    try:
        float(val)
        return "float"
    except ValueError:
        pass
    # Check bool
    if val.lower() in ("true", "false"):
        return "bool"
    return "str"


def inspect_dataset(file_path: str, sample_limit: int = 3) -> Dict[str, Any]:
    """Inspects a CSV cybersecurity dataset without external dependencies."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Dataset file not found at: {file_path}")

    row_count = 0
    column_names: List[str] = []
    sample_records: List[Dict[str, str]] = []
    missing_counts: Dict[str, int] = {}
    type_candidates: Dict[str, Set[str]] = {}
    label_counter: Counter = Counter()

    # Identify potential label column candidates (e.g. 'Label', ' Label', 'attack_label', etc.)
    label_col_name: str = ""

    with open(file_path, mode="r", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        try:
            raw_headers = next(reader)
        except StopIteration:
            return {
                "file_path": file_path,
                "shape": (0, 0),
                "columns": [],
                "error": "Empty file",
            }

        column_names = raw_headers
        missing_counts = {col: 0 for col in column_names}
        type_candidates = {col: set() for col in column_names}

        # Find label column
        for col in column_names:
            if col.strip().lower() in ("label", "attack", "threat_category", "class"):
                label_col_name = col
                break

        for row_idx, row in enumerate(reader):
            row_count += 1
            # Build row dict
            row_dict = {}
            for col_idx, col in enumerate(column_names):
                val = row[col_idx] if col_idx < len(row) else ""
                row_dict[col] = val

                # Track missing values
                if val is None or val.strip() == "" or val.strip().lower() in ("null", "none", "nan"):
                    missing_counts[col] += 1
                else:
                    t = infer_type(val)
                    type_candidates[col].add(t)

            if len(sample_records) < sample_limit:
                sample_records.append(row_dict)

            # Track label frequencies
            if label_col_name and label_col_name in row_dict:
                lbl = row_dict[label_col_name].strip()
                label_counter[lbl] += 1

    # Consolidate data types
    data_types: Dict[str, str] = {}
    for col, types in type_candidates.items():
        if "str" in types:
            data_types[col] = "string / object"
        elif "float" in types:
            data_types[col] = "float64"
        elif "int" in types:
            data_types[col] = "int64"
        elif "bool" in types:
            data_types[col] = "boolean"
        else:
            data_types[col] = "empty / unknown"

    return {
        "file_name": os.path.basename(file_path),
        "file_path": file_path,
        "shape": (row_count, len(column_names)),
        "rows": row_count,
        "columns_count": len(column_names),
        "column_names": column_names,
        "data_types": data_types,
        "sample_records": sample_records,
        "missing_values": {k: v for k, v in missing_counts.items() if v > 0},
        "total_missing_cells": sum(missing_counts.values()),
        "label_column": label_col_name,
        "unique_labels": dict(label_counter),
    }


def print_inspection_report(info: Dict[str, Any]) -> None:
    """Pretty prints the inspection summary."""
    print("=" * 80)
    print("CRISP CYBERSECURITY DATASET INSPECTION REPORT")
    print("=" * 80)
    print(f"File Name:        {info.get('file_name')}")
    print(f"File Path:        {info.get('file_path')}")
    shape = info.get("shape", (0, 0))
    print(f"Dataset Shape:    {shape[0]} rows × {shape[1]} columns")
    print(f"Total Columns:    {info.get('columns_count')}")
    print("-" * 80)

    print("\n[1] ALL COLUMN NAMES:")
    for idx, col in enumerate(info.get("column_names", []), start=1):
        dtype = info.get("data_types", {}).get(col, "unknown")
        print(f"  {idx:2d}. '{col}' (Type: {dtype})")

    print("\n[2] UNIQUE ATTACK / TRAFFIC LABELS:")
    labels = info.get("unique_labels", {})
    if labels:
        for lbl, count in sorted(labels.items(), key=lambda x: -x[1]):
            print(f"  - '{lbl}': {count} occurrences")
    else:
        print("  (No dedicated label column detected)")

    print("\n[3] MISSING VALUES SUMMARY:")
    missing = info.get("missing_values", {})
    if missing:
        for col, count in missing.items():
            print(f"  - {col}: {count} missing values")
    else:
        print("  ✓ Zero missing values detected across all inspected rows.")

    print(f"\n[4] SAMPLE RECORDS (Top {len(info.get('sample_records', []))}):")
    for s_idx, sample in enumerate(info.get("sample_records", []), start=1):
        print(f"\n--- Sample #{s_idx} ---")
        # Print key identifiers
        key_fields = ["Flow ID", "Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Timestamp", "Label"]
        printed = 0
        for k in key_fields:
            if k in sample:
                print(f"  {k}: {sample[k]}")
                printed += 1
        if printed == 0:
            for k, v in list(sample.items())[:6]:
                print(f"  {k}: {v}")

    print("\n" + "=" * 80)


if __name__ == "__main__":
    target_path = os.environ.get("SECURITY_DATASET_PATH")
    if len(sys.argv) > 1:
        target_path = sys.argv[1]
    if not target_path:
        default_candidate = os.path.join("data", "cic_ids2017_sample.csv")
        target_path = default_candidate if os.path.exists(default_candidate) else os.path.join("src", "data", "historical_security_events.csv")

    try:
        report = inspect_dataset(target_path)
        print_inspection_report(report)
    except Exception as e:
        print(f"Error inspecting dataset: {e}", file=sys.stderr)
        sys.exit(1)
