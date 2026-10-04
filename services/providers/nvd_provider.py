"""
CRISP Cybersecurity Platform - NVD 2.0 API Provider
Service for retrieving, querying, and normalizing vulnerability intelligence from the NIST NVD API 2.0.
"""

import json
import logging
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CRISP.NVDProvider")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] [CRISP.NVD] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def load_env_file(filepath: str = ".env") -> None:
    """Simple parser for .env files without requiring python-dotenv."""
    if not os.path.exists(filepath):
        return
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip("'\"")
                    if k and k not in os.environ:
                        os.environ[k] = v
    except Exception as e:
        logger.debug(f"Could not load .env file: {e}")


# Load environment variables on module import
load_env_file()


class NVDDataProvider:
    """Data provider for querying the NIST National Vulnerability Database (NVD) 2.0 API."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0",
        timeout: int = 15,
    ):
        # Support API key from parameter or environment variable
        self.api_key = api_key or os.getenv("NVD_API_KEY", "").strip() or None
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _execute_request(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes an HTTP GET request to the NVD 2.0 API with proper error handling,
        timeout protection, and rate-limit handling.
        """
        query_string = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        url = f"{self.base_url}?{query_string}" if query_string else self.base_url

        # Log request without exposing API key
        logger.info(f"NVD API request: GET {self.base_url}?{query_string}")

        headers = {
            "User-Agent": "CRISP-Cyber-Risk-Intelligence-Platform/2.0",
            "Accept": "application/json",
        }
        if self.api_key:
            headers["apiKey"] = self.api_key

        req = urllib.request.Request(url, headers=headers, method="GET")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status_code = resp.getcode()
                raw_data = resp.read()

                if status_code != 200:
                    err_msg = f"NVD API returned non-200 HTTP status: {status_code}"
                    logger.error(f"NVD error: {err_msg}")
                    return {"error": err_msg, "status_code": status_code, "vulnerabilities": []}

                try:
                    data = json.loads(raw_data.decode("utf-8"))
                    vuln_count = len(data.get("vulnerabilities", []))
                    logger.info(f"NVD records received: {vuln_count} (Total in NVD: {data.get('totalResults', 0)})")
                    return data
                except (json.JSONDecodeError, UnicodeDecodeError) as json_err:
                    err_msg = f"Invalid JSON received from NVD: {str(json_err)}"
                    logger.error(f"NVD error: {err_msg}")
                    return {"error": err_msg, "vulnerabilities": []}

        except urllib.error.HTTPError as http_err:
            if http_err.code in (403, 429):
                err_msg = f"NVD rate limit or access forbidden (HTTP {http_err.code}). Please wait or supply NVD_API_KEY."
            elif http_err.code == 503:
                err_msg = "NVD API service temporarily unavailable (HTTP 503)."
            else:
                err_msg = f"NVD HTTP error {http_err.code}: {http_err.reason}"
            logger.error(f"NVD error: {err_msg}")
            return {"error": err_msg, "status_code": http_err.code, "vulnerabilities": []}

        except urllib.error.URLError as url_err:
            err_msg = f"NVD connection failure / timeout: {url_err.reason}"
            logger.error(f"NVD error: {err_msg}")
            return {"error": err_msg, "vulnerabilities": []}

        except Exception as ex:
            err_msg = f"Unexpected error during NVD query: {str(ex)}"
            logger.error(f"NVD error: {err_msg}")
            return {"error": err_msg, "vulnerabilities": []}

    def get_cves(
        self,
        startIndex: int = 0,
        resultsPerPage: int = 20,
        keyword: Optional[str] = None,
        cve_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Retrieves paginated CVE records from NVD 2.0 API.
        Default resultsPerPage is 20 for controlled testing.
        """
        params: Dict[str, Any] = {
            "startIndex": max(0, startIndex),
            "resultsPerPage": max(1, min(resultsPerPage, 100)),
        }
        if cve_id:
            params["cveId"] = cve_id.strip()
        elif keyword:
            params["keywordSearch"] = keyword.strip()

        return self._execute_request(params)

    def get_cve_by_id(self, cve_id: str) -> Dict[str, Any]:
        """Retrieves a single CVE by its identifier (e.g. CVE-2024-3400)."""
        if not cve_id or not cve_id.strip():
            return {"error": "cve_id parameter is required", "vulnerabilities": []}
        return self.get_cves(cve_id=cve_id.strip(), resultsPerPage=1)

    def get_recent_cves(self, days: int = 30, resultsPerPage: int = 20) -> Dict[str, Any]:
        """Retrieves CVEs published in the last N days."""
        now = datetime.utcnow()
        start = now - timedelta(days=days)
        # NVD format: [YYYY-MM-DDTHH:mm:ss.000]
        pub_start = start.strftime("%Y-%m-%dT00:00:00.000")
        pub_end = now.strftime("%Y-%m-%dT23:59:59.000")

        params = {
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
            "resultsPerPage": resultsPerPage,
            "startIndex": 0,
        }
        return self._execute_request(params)

    def get_modified_cves(self, last_mod_start_date: str, resultsPerPage: int = 20) -> Dict[str, Any]:
        """Retrieves CVEs modified since a given timestamp."""
        now = datetime.utcnow().strftime("%Y-%m-%dT23:59:59.000")
        params = {
            "lastModStartDate": last_mod_start_date,
            "lastModEndDate": now,
            "resultsPerPage": resultsPerPage,
            "startIndex": 0,
        }
        return self._execute_request(params)


def map_cvss_severity(raw_severity: Any, score: Optional[float] = None) -> str:
    """Maps CVSS severity consistently to NONE, LOW, MEDIUM, HIGH, CRITICAL."""
    if isinstance(raw_severity, str):
        val = raw_severity.strip().upper()
        if val in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"):
            return val
    if score is not None:
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0.0:
            return "LOW"
    return "NONE"


def normalize_nvd_cve(raw_cve: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalizes an NVD 2.0 CVE JSON object into the CRISP Vulnerability schema.

    Isolates NVD-specific internal structure so the rest of the application
    consumes a normalized model.

    Schema:
    - cve_id: str (e.g. 'CVE-2024-3400')
    - description: Optional[str]
    - cvss_score: Optional[float] (0.0 - 10.0)
    - severity: str ('NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
    - published_date: Optional[str]
    - modified_date: Optional[str]
    - cwe: List[str]
    - affected_products: List[str]
    - references: List[str]
    - source: 'NVD'
    - exploit_available: Optional[bool] (None - not fabricated)
    - patch_available: Optional[bool] (None - not fabricated)
    - status: Optional[str]
    """
    if not isinstance(raw_cve, dict):
        raise ValueError("raw_cve must be a dictionary")

    # Handle both wrapped {"cve": {...}} and raw {...} items
    cve_data = raw_cve.get("cve", raw_cve)

    cve_id = cve_data.get("id", "").strip().upper()
    if not cve_id:
        cve_id = "CVE-UNKNOWN"

    # Description extraction (prefer English)
    description = None
    descriptions = cve_data.get("descriptions", [])
    if isinstance(descriptions, list):
        for desc in descriptions:
            if isinstance(desc, dict) and desc.get("lang") == "en":
                description = desc.get("value")
                break
        if not description and descriptions:
            first = descriptions[0]
            if isinstance(first, dict):
                description = first.get("value")

    # CVSS score & severity extraction
    cvss_score: Optional[float] = None
    severity: str = "NONE"
    metrics = cve_data.get("metrics", {})

    if isinstance(metrics, dict):
        # 1. Prefer CVSS v3.1
        cvss31_metrics = metrics.get("cvssMetricV31", [])
        if cvss31_metrics and isinstance(cvss31_metrics, list):
            cvss_data = cvss31_metrics[0].get("cvssData", {})
            if "baseScore" in cvss_data:
                try:
                    cvss_score = float(cvss_data["baseScore"])
                except (ValueError, TypeError):
                    cvss_score = None
            raw_sev = cvss_data.get("baseSeverity") or cvss31_metrics[0].get("baseSeverity")
            severity = map_cvss_severity(raw_sev, cvss_score)

        # 2. Fallback to CVSS v3.0
        elif metrics.get("cvssMetricV30"):
            cvss30_metrics = metrics["cvssMetricV30"]
            if isinstance(cvss30_metrics, list) and cvss30_metrics:
                cvss_data = cvss30_metrics[0].get("cvssData", {})
                if "baseScore" in cvss_data:
                    try:
                        cvss_score = float(cvss_data["baseScore"])
                    except (ValueError, TypeError):
                        cvss_score = None
                raw_sev = cvss_data.get("baseSeverity") or cvss30_metrics[0].get("baseSeverity")
                severity = map_cvss_severity(raw_sev, cvss_score)

        # 3. Fallback to CVSS v2.0
        elif metrics.get("cvssMetricV2"):
            cvss2_metrics = metrics["cvssMetricV2"]
            if isinstance(cvss2_metrics, list) and cvss2_metrics:
                cvss_data = cvss2_metrics[0].get("cvssData", {})
                if "baseScore" in cvss_data:
                    try:
                        cvss_score = float(cvss_data["baseScore"])
                    except (ValueError, TypeError):
                        cvss_score = None
                raw_sev = cvss2_metrics[0].get("baseSeverity") or cvss_data.get("baseSeverity")
                severity = map_cvss_severity(raw_sev, cvss_score)

    if cvss_score is not None:
        cvss_score = round(max(0.0, min(10.0, cvss_score)), 1)
        if severity == "NONE":
            severity = map_cvss_severity(None, cvss_score)

    # Dates
    published_date = cve_data.get("published")
    modified_date = cve_data.get("lastModified")

    # CWE extraction
    cwe_list: List[str] = []
    weaknesses = cve_data.get("weaknesses", [])
    if isinstance(weaknesses, list):
        for w in weaknesses:
            if isinstance(w, dict):
                for d in w.get("description", []):
                    if isinstance(d, dict) and d.get("value"):
                        val = d.get("value", "")
                        if val.startswith("CWE-") and val not in cwe_list:
                            cwe_list.append(val)

    # Affected products extraction from configurations
    affected_products: List[str] = []
    configurations = cve_data.get("configurations", [])
    if isinstance(configurations, list):
        for config in configurations:
            if isinstance(config, dict):
                for node in config.get("nodes", []):
                    if isinstance(node, dict):
                        for match in node.get("cpeMatch", []):
                            if isinstance(match, dict) and match.get("criteria"):
                                parts = match["criteria"].split(":")
                                if len(parts) > 4:
                                    vendor = parts[3].replace("_", " ").title()
                                    product = parts[4].replace("_", " ").title()
                                    name = f"{vendor} {product}".strip()
                                    if name and name not in affected_products:
                                        affected_products.append(name)

    # References
    references: List[str] = []
    raw_refs = cve_data.get("references", [])
    if isinstance(raw_refs, list):
        for ref in raw_refs:
            if isinstance(ref, dict) and ref.get("url"):
                url = ref.get("url")
                if url and url not in references:
                    references.append(url)

    status = cve_data.get("vulnStatus")

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "severity": severity,
        "published_date": published_date,
        "modified_date": modified_date,
        "cwe": cwe_list,
        "affected_products": affected_products,
        "references": references,
        "source": "NVD",
        "exploit_available": None,  # Not supplied by NVD; never fabricate
        "patch_available": None,    # Not supplied by NVD; never fabricate
        "status": status,
    }
