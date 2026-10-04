"""
CRISP Cybersecurity Platform - CISA KEV Data Provider
Retrieves, queries, and normalizes the official CISA Known Exploited Vulnerabilities Catalog.
Official Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
Feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""

import json
import logging
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CRISP.CISAKEVProvider")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] [CRISP.CISA_KEV] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

CISA_KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def normalize_cisa_kev(raw_entry: Dict[str, Any]) -> Dict[str, Any]:
    """
    Converts a single raw entry from the CISA KEV JSON catalog into
    the normalized CRISP KEV model.

    Schema:
    - cve_id: str (e.g. 'CVE-2021-44228')
    - vendor_project: Optional[str]
    - product: Optional[str]
    - vulnerability_name: Optional[str]
    - date_added: Optional[str]
    - short_description: Optional[str]
    - required_action: Optional[str]
    - due_date: Optional[str]
    - known_ransomware_campaign_use: Optional[str]
    - notes: Optional[str]
    - source: 'CISA_KEV'
    - known_exploited: bool (True for all KEV catalog items)
    """
    if not isinstance(raw_entry, dict):
        raise ValueError("raw_entry must be a dictionary")

    cve_id = (raw_entry.get("cveID") or raw_entry.get("cve_id") or "").strip().upper()
    if not cve_id:
        cve_id = "CVE-UNKNOWN"

    vendor = raw_entry.get("vendorProject") or raw_entry.get("vendor_project")
    product = raw_entry.get("product")
    vuln_name = raw_entry.get("vulnerabilityName") or raw_entry.get("vulnerability_name")
    date_added = raw_entry.get("dateAdded") or raw_entry.get("date_added")
    desc = raw_entry.get("shortDescription") or raw_entry.get("short_description")
    action = raw_entry.get("requiredAction") or raw_entry.get("required_action")
    due_date = raw_entry.get("dueDate") or raw_entry.get("due_date")
    ransomware = raw_entry.get("knownRansomwareCampaignUse") or raw_entry.get("known_ransomware_campaign_use")
    notes = raw_entry.get("notes")

    return {
        "cve_id": cve_id,
        "vendor_project": vendor if vendor else None,
        "product": product if product else None,
        "vulnerability_name": vuln_name if vuln_name else None,
        "date_added": date_added if date_added else None,
        "short_description": desc if desc else None,
        "required_action": action if action else None,
        "due_date": due_date if due_date else None,
        "known_ransomware_campaign_use": ransomware if ransomware else None,
        "notes": notes if notes else None,
        "source": "CISA_KEV",
        "known_exploited": True,
    }


class CISAKEVProvider:
    """Data provider for the official CISA Known Exploited Vulnerabilities Catalog."""

    def __init__(self, catalog_url: str = CISA_KEV_FEED_URL, timeout: int = 15):
        self.catalog_url = catalog_url
        self.timeout = timeout
        self._cached_catalog: Optional[Dict[str, Any]] = None

    def get_catalog(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Retrieves the complete CISA KEV catalog.
        Handles network failures, timeouts, and malformed JSON cleanly.
        """
        if self._cached_catalog and not force_refresh:
            return self._cached_catalog

        logger.info(f"CISA KEV request: GET {self.catalog_url}")

        req = urllib.request.Request(
            self.catalog_url,
            headers={
                "User-Agent": "CRISP-Cyber-Risk-Intelligence-Platform/2.0",
                "Accept": "application/json",
            },
            method="GET",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status_code = resp.getcode()
                raw_data = resp.read()

                if status_code != 200:
                    err_msg = f"CISA KEV endpoint returned HTTP {status_code}"
                    logger.error(f"CISA KEV error: {err_msg}")
                    return {"error": err_msg, "status_code": status_code, "vulnerabilities": []}

                try:
                    data = json.loads(raw_data.decode("utf-8"))
                    vulns = data.get("vulnerabilities", [])
                    logger.info(f"CISA KEV records received: {len(vulns)} items (Version: {data.get('catalogVersion', 'N/A')})")
                    self._cached_catalog = data
                    return data
                except (json.JSONDecodeError, UnicodeDecodeError) as json_err:
                    err_msg = f"Invalid JSON received from CISA KEV: {str(json_err)}"
                    logger.error(f"CISA KEV error: {err_msg}")
                    return {"error": err_msg, "vulnerabilities": []}

        except urllib.error.HTTPError as http_err:
            err_msg = f"CISA KEV HTTP error {http_err.code}: {http_err.reason}"
            logger.error(f"CISA KEV error: {err_msg}")
            return {"error": err_msg, "status_code": http_err.code, "vulnerabilities": []}

        except urllib.error.URLError as url_err:
            err_msg = f"CISA KEV connection failure / timeout: {url_err.reason}"
            logger.error(f"CISA KEV error: {err_msg}")
            return {"error": err_msg, "vulnerabilities": []}

        except Exception as ex:
            err_msg = f"Unexpected error during CISA KEV fetch: {str(ex)}"
            logger.error(f"CISA KEV error: {err_msg}")
            return {"error": err_msg, "vulnerabilities": []}

    def get_known_exploited_cves(self) -> List[Dict[str, Any]]:
        """Returns normalized records of all vulnerabilities in the CISA KEV catalog."""
        catalog = self.get_catalog()
        raw_items = catalog.get("vulnerabilities", [])
        results = []
        for item in raw_items:
            try:
                results.append(normalize_cisa_kev(item))
            except Exception as e:
                logger.debug(f"Skipping malformed KEV record: {e}")
        return results

    def get_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Looks up a specific CVE in the KEV catalog."""
        if not cve_id:
            return None
        target = cve_id.strip().upper()
        catalog = self.get_catalog()
        for item in catalog.get("vulnerabilities", []):
            cid = (item.get("cveID") or item.get("cve_id") or "").strip().upper()
            if cid == target:
                return normalize_cisa_kev(item)
        return None
