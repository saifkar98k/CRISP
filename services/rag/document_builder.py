"""
CRISP Cybersecurity Platform - RAG Document Builder
Phase 3 Step 1: Transforms SQLite Records into Rich Semantic Text Documents.

Converts structured records from NVD, CISA KEV, NIST CSF 2.0, Assets,
Security Findings, and Telemetry into descriptive prose suitable for
vector embedding and semantic retrieval.

All built documents contain standard metadata:
- source (str)
- cve_id (str)
- asset_id (str)
- nist_function (str)
- severity (str)
- document_type (str)
"""

import json
from typing import Any, Dict, List, Optional, Tuple


class DocumentBuilder:
    """
    Transforms structured database records into semantic text representations
    and standardized Chroma-compliant metadata dictionaries.
    """

    @staticmethod
    def _sanitize_metadata(meta: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ensures all metadata fields are ChromaDB-compatible primitives
        (str, int, float, bool). Converts None and lists/dicts to strings.
        """
        sanitized = {}
        for k, v in meta.items():
            if v is None:
                sanitized[k] = ""
            elif isinstance(v, (str, int, float, bool)):
                sanitized[k] = v
            elif isinstance(v, (list, dict)):
                sanitized[k] = json.dumps(v)
            else:
                sanitized[k] = str(v)

        # Enforce required standard metadata keys
        required_defaults = {
            "source": "CRISP_KNOWLEDGE_BASE",
            "cve_id": "",
            "asset_id": "",
            "nist_function": "IDENTIFY",
            "severity": "INFORMATIONAL",
            "document_type": "generic",
        }
        for req_key, default_val in required_defaults.items():
            if req_key not in sanitized or sanitized[req_key] == "":
                sanitized[req_key] = default_val

        return sanitized

    @classmethod
    def build_vulnerability_doc(cls, record: Dict[str, Any]) -> Tuple[str, str, Dict[str, Any]]:
        """
        Converts an NVD / common vulnerability record into a semantic document.
        Returns: (doc_id, text_document, metadata)
        """
        cve_id = str(record.get("cve_id") or "").strip().upper()
        doc_id = f"vuln:{cve_id}"

        description = record.get("description") or "No technical description available."
        cvss = record.get("cvss_score")
        cvss_str = f"{cvss:.1f}" if cvss is not None else "Unscored / Unknown"
        severity = str(record.get("severity") or "UNKNOWN").upper()
        status = record.get("status") or "ACTIVE"

        # Affected products
        products_raw = record.get("affected_products") or "[]"
        products_list: List[str] = []
        if isinstance(products_raw, str):
            try:
                products_list = json.loads(products_raw)
            except Exception:
                products_list = [p.strip() for p in products_raw.split(",") if p.strip()]
        elif isinstance(products_raw, list):
            products_list = products_raw
        products_str = ", ".join(products_list) if products_list else "Unspecified software product"

        # Exploit / Patch status
        exploit_avail = record.get("exploit_available")
        is_known_exploited = bool(record.get("known_exploited"))
        patch_avail = record.get("patch_available")

        exploit_sentence = (
            "Active exploit code is known and published in the threat landscape."
            if (exploit_avail or is_known_exploited)
            else "No public exploit code is currently cataloged."
        )

        patch_sentence = (
            "An official security patch or vendor update is verified available."
            if patch_avail is True or patch_avail == 1
            else (
                "No official patch currently reported; requires compensating controls."
                if patch_avail is False or patch_avail == 0
                else "Patch status is pending verification."
            )
        )

        # Meaningful text document format
        # Example format: "CVE-XXXX-XXXX is a vulnerability affecting ..."
        text = (
            f"{cve_id} is a {severity} severity cybersecurity vulnerability affecting {products_str}. "
            f"It has a CVSS base score of {cvss_str}. "
            f"Description: {description} "
            f"Status: {status}. {exploit_sentence} {patch_sentence}"
        )

        metadata = cls._sanitize_metadata({
            "source": str(record.get("source") or "NVD"),
            "cve_id": cve_id,
            "asset_id": "",
            "nist_function": "PROTECT",
            "severity": severity,
            "document_type": "vulnerability",
            "cvss_score": float(cvss) if cvss is not None else -1.0,
            "is_known_exploited": is_known_exploited,
            "affected_products": products_str[:300],
        })

        return doc_id, text, metadata

    @classmethod
    def build_kev_doc(cls, record: Dict[str, Any]) -> Tuple[str, str, Dict[str, Any]]:
        """
        Converts a CISA Known Exploited Vulnerability record into an authoritative advisory doc.
        Returns: (doc_id, text_document, metadata)
        """
        cve_id = str(record.get("cve_id") or "").strip().upper()
        doc_id = f"kev:{cve_id}"

        vendor = record.get("kev_vendor_project") or record.get("affected_products") or "Enterprise Vendor"
        product = record.get("kev_product") or "Enterprise Software"
        description = record.get("description") or "Actively exploited security vulnerability."
        date_added = record.get("kev_date_added") or "Unknown"
        due_date = record.get("kev_due_date") or "Immediate action required"
        action = record.get("kev_required_action") or "Apply vendor mitigations per CISA BOD guidelines."
        ransomware = record.get("kev_ransomware_use") or "Unknown"
        notes = record.get("kev_notes") or ""

        text = (
            f"{cve_id} is a confirmed CISA Known Exploited Vulnerability (KEV) affecting {vendor} {product}. "
            f"Description: {description} "
            f"CISA Catalog Addition Date: {date_added}. "
            f"Remediation Due Date: {due_date}. "
            f"Known Ransomware Campaign Use: {ransomware}. "
            f"Required Remediation Action: {action}. "
            f"Threat Guidance: This vulnerability is under active exploitation by threat actors in the wild. "
            f"Notes & Advisories: {notes}"
        ).strip()

        severity = str(record.get("severity") or "CRITICAL").upper()
        if severity in ("UNKNOWN", "NONE", ""):
            severity = "CRITICAL"

        cvss = record.get("cvss_score")

        metadata = cls._sanitize_metadata({
            "source": "CISA_KEV",
            "cve_id": cve_id,
            "asset_id": "",
            "nist_function": "RESPOND",
            "severity": severity,
            "document_type": "kev",
            "vendor": str(vendor)[:100],
            "product": str(product)[:100],
            "due_date": str(due_date),
            "ransomware_use": str(ransomware),
            "cvss_score": float(cvss) if cvss is not None else -1.0,
        })

        return doc_id, text, metadata

    @classmethod
    def build_nist_doc(cls, record: Dict[str, Any]) -> Tuple[str, str, Dict[str, Any]]:
        """
        Converts a NIST CSF 2.0 control evaluation or standard into a semantic document.
        Returns: (doc_id, text_document, metadata)
        """
        control_id = str(record.get("id") or record.get("control_id") or "").strip()
        doc_id = f"nist:{control_id}"

        function_name = str(record.get("function") or "GOVERN").upper()
        category = record.get("category") or "General Security Category"
        subcategory = record.get("subcategory") or "Control requirement specification"
        score = record.get("score")
        score_str = f"{score:.0f}/100" if score is not None else "Not Scored"
        status = str(record.get("status") or "COMPLIANT").upper()
        findings = record.get("findings") or "No audit findings logged."
        remediation = record.get("required_remediation") or record.get("requiredRemediation") or "Maintain operational compliance standards."
        evidence = record.get("evidence") or "Baseline compliance policy."

        # Severity representation based on compliance status
        if status in ("NON_COMPLIANT", "FAIL"):
            severity = "HIGH"
        elif status in ("PARTIAL", "IN_PROGRESS", "NEEDS_REVIEW"):
            severity = "MEDIUM"
        else:
            severity = "LOW"

        text = (
            f"NIST Cybersecurity Framework (CSF 2.0) Control {control_id} is a security benchmark "
            f"governed under Function {function_name} ({category}). "
            f"Subcategory Objective: {subcategory}. "
            f"Operational Compliance Status: {status} (Audit Score: {score_str}). "
            f"Audit Findings: {findings} "
            f"Required Remediation & Hardening: {remediation} "
            f"Audit Evidence: {evidence}"
        )

        metadata = cls._sanitize_metadata({
            "source": "NIST_CSF_2.0",
            "cve_id": "",
            "asset_id": "",
            "nist_function": function_name,
            "severity": severity,
            "document_type": "nist",
            "control_id": control_id,
            "category": str(category)[:100],
            "compliance_status": status,
            "compliance_score": float(score) if score is not None else -1.0,
        })

        return doc_id, text, metadata

    @classmethod
    def build_finding_doc(cls, record: Dict[str, Any]) -> Tuple[str, str, Dict[str, Any]]:
        """
        Converts a correlated security finding into a semantic knowledge document.
        Returns: (doc_id, text_document, metadata)
        """
        finding_id = str(record.get("finding_id") or "").strip()
        doc_id = f"finding:{finding_id}"

        timestamp = record.get("timestamp") or "Recent"
        asset_id = str(record.get("asset_id") or "").strip()
        asset_name = record.get("asset_name") or asset_id or "Enterprise Asset"
        attack_category = record.get("attack_category") or "Security Anomaly"
        severity = str(record.get("severity") or "MEDIUM").upper()
        risk_score = record.get("risk_score")
        risk_str = f"{risk_score:.1f}/100" if risk_score is not None else "Uncalculated"
        risk_level = str(record.get("risk_level") or severity).upper()
        nist_function = str(record.get("nist_function") or "DETECT").upper()
        cve_id = str(record.get("cve_id") or "").strip()
        cve_mention = f"Correlated with {cve_id}." if cve_id and cve_id != "None" else "No specific CVE directly mapped."
        known_exploited = "Known actively exploited in CISA KEV." if record.get("known_exploited") else "Not marked in KEV."
        asset_criticality = record.get("asset_criticality") or "MEDIUM"

        evidence_raw = record.get("evidence_json") or "[]"
        evidence_list: List[str] = []
        if isinstance(evidence_raw, str):
            try:
                evidence_list = json.loads(evidence_raw)
            except Exception:
                evidence_list = [evidence_raw]
        elif isinstance(evidence_raw, list):
            evidence_list = evidence_raw
        evidence_str = " | ".join(evidence_list) if evidence_list else "Correlated via CRISP automated engine."

        text = (
            f"Security Finding {finding_id} is an active correlated security incident affecting asset "
            f"{asset_name} ({asset_id}). Attack Category: {attack_category}. "
            f"Severity: {severity}. CRISP Multi-Factor Risk Score: {risk_str} ({risk_level}). "
            f"{cve_mention} {known_exploited} Target Asset Criticality: {asset_criticality}. "
            f"Governed under NIST CSF Function: {nist_function}. "
            f"Observation Timestamp: {timestamp}. "
            f"Correlation Evidence & Findings: {evidence_str}"
        )

        metadata = cls._sanitize_metadata({
            "source": str(record.get("source") or "CORRELATED_INTELLIGENCE"),
            "cve_id": cve_id if cve_id != "None" else "",
            "asset_id": asset_id,
            "nist_function": nist_function,
            "severity": severity,
            "document_type": "finding",
            "finding_id": finding_id,
            "risk_score": float(risk_score) if risk_score is not None else -1.0,
            "risk_level": risk_level,
            "attack_category": str(attack_category)[:100],
        })

        return doc_id, text, metadata

    @classmethod
    def build_asset_doc(cls, record: Dict[str, Any]) -> Tuple[str, str, Dict[str, Any]]:
        """
        Converts an enterprise asset record into a semantic document.
        Returns: (doc_id, text_document, metadata)
        """
        asset_id = str(record.get("id") or record.get("asset_id") or "").strip()
        doc_id = f"asset:{asset_id}"

        name = record.get("name") or asset_id
        ip = record.get("ip_address") or "Internal IP"
        secondary_ips = record.get("secondary_ips") or ""
        asset_type = record.get("type") or "Server"
        criticality = str(record.get("criticality") or "MEDIUM").upper()
        exposure = str(record.get("exposure") or "INTERNAL").upper()
        owner = record.get("owner") or "IT Operations"
        dept = record.get("department") or "Engineering"
        cves = record.get("associated_cves") or "None"

        cve_sentence = (
            f"Known associated vulnerabilities: {cves}."
            if cves and cves != "None"
            else "No known associated vulnerabilities mapped in inventory."
        )

        text = (
            f"Enterprise Asset {name} (Asset ID: {asset_id}) is a {asset_type} system operated by "
            f"{owner} in the {dept} department. "
            f"Primary IP Address: {ip}"
            + (f" (Secondary IPs: {secondary_ips}). " if secondary_ips else ". ")
            + f"Criticality Classification: {criticality} priority. "
            f"Perimeter Exposure: {exposure}. "
            f"{cve_sentence} "
            f"Asset security profile requires monitoring aligned with NIST CSF 2.0 IDENTIFY and PROTECT controls."
        )

        metadata = cls._sanitize_metadata({
            "source": "ASSET_REGISTRY",
            "cve_id": "",
            "asset_id": asset_id,
            "nist_function": "IDENTIFY",
            "severity": criticality,
            "document_type": "asset",
            "asset_name": str(name)[:100],
            "asset_type": str(asset_type)[:50],
            "exposure": exposure,
            "department": str(dept)[:50],
        })

        return doc_id, text, metadata

    @classmethod
    def build_incident_doc(cls, record: Dict[str, Any]) -> Tuple[str, str, Dict[str, Any]]:
        """
        Converts a raw or simulated security telemetry event into a semantic document.
        Returns: (doc_id, text_document, metadata)
        """
        event_id = str(record.get("event_id") or "").strip()
        doc_id = f"incident:{event_id}"

        timestamp = record.get("timestamp") or "Recorded Timestamp"
        src_ip = record.get("source_ip") or "Unknown Source"
        dst_ip = record.get("destination_ip") or "Unknown Target"
        dst_port = record.get("destination_port") or "Any"
        proto = record.get("protocol") or "IP"
        event_type = record.get("event_type") or "Security Anomaly"
        attack_category = record.get("attack_category") or record.get("crisp_attack_category") or "Intrusion Attempt"
        severity = str(record.get("severity") or "MEDIUM").upper()
        description = record.get("description") or f"{event_type} detected on network telemetry."
        asset_id = str(record.get("asset_id") or "").strip()
        nist_func = str(record.get("nist_function") or "DETECT").upper()
        cve_id = str(record.get("cve_id") or "").strip()
        risk_score = record.get("crisp_risk_score")

        risk_sentence = (
            f"Assigned CRISP Risk Score: {risk_score:.1f}/100."
            if risk_score is not None
            else "Standard operational telemetry classification."
        )

        cve_sentence = f"Associated with {cve_id}." if cve_id and cve_id != "None" else ""

        text = (
            f"Security Telemetry Event {event_id} recorded at {timestamp}. "
            f"Event Type: {event_type} (Classification: {attack_category}). "
            f"Severity: {severity}. Traffic: {src_ip} -> {dst_ip}:{dst_port} ({proto}). "
            f"Description: {description} "
            f"{risk_sentence} {cve_sentence} "
            f"NIST CSF 2.0 Operational Function: {nist_func}."
        ).strip()

        metadata = cls._sanitize_metadata({
            "source": str(record.get("source") or record.get("dataset_source") or "SECURITY_TELEMETRY"),
            "cve_id": cve_id if cve_id != "None" else "",
            "asset_id": asset_id,
            "nist_function": nist_func,
            "severity": severity,
            "document_type": "incident",
            "event_id": event_id,
            "source_ip": str(src_ip)[:45],
            "destination_ip": str(dst_ip)[:45],
            "attack_category": str(attack_category)[:100],
        })

        return doc_id, text, metadata

    @classmethod
    def build_risk_assessment_doc(cls, record: Dict[str, Any]) -> Tuple[str, str, Dict[str, Any]]:
        """
        Converts a multi-factor risk assessment record into a semantic document.
        Returns: (doc_id, text_document, metadata)
        """
        risk_id = str(record.get("id") or record.get("finding") or "RISK").strip()
        doc_id = f"risk:{risk_id}"

        timestamp = record.get("timestamp") or "Recorded Time"
        asset = record.get("asset") or "Enterprise Asset"
        finding = record.get("finding") or "Security Finding"
        score = record.get("score")
        score_val = float(score) if score is not None else 0.0
        level = str(record.get("level") or "MEDIUM").upper()
        explanation = record.get("explanation") or "Multi-factor cybersecurity risk evaluation."

        text = (
            f"CRISP Cyber Risk Assessment for finding {finding} affecting asset {asset}. "
            f"Assessment Timestamp: {timestamp}. "
            f"Calculated CRISP Risk Score: {score_val:.1f}/100 (Risk Tier: {level}). "
            f"Plain-English Explanation: {explanation} "
            f"Framework Alignment: NIST CSF 2.0 GOVERN & RESPOND multi-factor quantitative methodology."
        )

        metadata = cls._sanitize_metadata({
            "source": "RISK_ENGINE",
            "cve_id": "",
            "asset_id": str(asset)[:50],
            "nist_function": "GOVERN",
            "severity": level,
            "document_type": "risk_assessment",
            "risk_score": score_val,
            "risk_level": level,
        })

        return doc_id, text, metadata


# Top-level helper functions for functional convenience
build_vulnerability_doc = DocumentBuilder.build_vulnerability_doc
build_kev_doc = DocumentBuilder.build_kev_doc
build_nist_doc = DocumentBuilder.build_nist_doc
build_finding_doc = DocumentBuilder.build_finding_doc
build_asset_doc = DocumentBuilder.build_asset_doc
build_incident_doc = DocumentBuilder.build_incident_doc
build_risk_assessment_doc = DocumentBuilder.build_risk_assessment_doc
