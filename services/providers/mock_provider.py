"""
CRISP Cybersecurity Platform - Mock Data Provider
Preserves mock data and demo functionality for controlled demonstrations.
"""

from typing import Any, Dict, List


class MockDataProvider:
    """Provides synthetic / mock vulnerability records for offline and demo usage."""

    def __init__(self):
        self.mock_cves: List[Dict[str, Any]] = [
            {
                "cve_id": "CVE-2024-DEMO-01",
                "description": "Simulated Remote Code Execution vulnerability in Web Application framework.",
                "cvss_score": 9.8,
                "severity": "CRITICAL",
                "published_date": "2024-01-15T10:00:00Z",
                "modified_date": "2024-01-20T12:00:00Z",
                "cwe": ["CWE-78", "CWE-94"],
                "affected_products": ["Demo Web Framework 3.2"],
                "references": ["https://example.com/advisory/demo-01"],
                "source": "Mock/Demo",
                "exploit_available": None,
                "patch_available": None,
                "status": "Analyzed",
            },
            {
                "cve_id": "CVE-2024-DEMO-02",
                "description": "Simulated SQL Injection in authentication endpoint.",
                "cvss_score": 8.5,
                "severity": "HIGH",
                "published_date": "2024-02-01T08:30:00Z",
                "modified_date": "2024-02-05T14:15:00Z",
                "cwe": ["CWE-89"],
                "affected_products": ["Demo Auth Portal 1.0"],
                "references": ["https://example.com/advisory/demo-02"],
                "source": "Mock/Demo",
                "exploit_available": None,
                "patch_available": None,
                "status": "Analyzed",
            },
            {
                "cve_id": "CVE-2024-DEMO-03",
                "description": "Simulated Cross-Site Scripting (XSS) in user dashboard profile view.",
                "cvss_score": 5.4,
                "severity": "MEDIUM",
                "published_date": "2024-03-10T11:00:00Z",
                "modified_date": "2024-03-12T09:00:00Z",
                "cwe": ["CWE-79"],
                "affected_products": ["Demo Dashboard UI 2.4"],
                "references": ["https://example.com/advisory/demo-03"],
                "source": "Mock/Demo",
                "exploit_available": None,
                "patch_available": None,
                "status": "Analyzed",
            },
        ]

    def get_cves(self, startIndex: int = 0, resultsPerPage: int = 20) -> Dict[str, Any]:
        records = self.mock_cves[startIndex : startIndex + resultsPerPage]
        return {
            "resultsPerPage": len(records),
            "startIndex": startIndex,
            "totalResults": len(self.mock_cves),
            "vulnerabilities": [{"cve": r} for r in records],
        }

    def get_cve_by_id(self, cve_id: str) -> Dict[str, Any]:
        match = [c for c in self.mock_cves if c["cve_id"].upper() == cve_id.upper()]
        return {
            "resultsPerPage": len(match),
            "startIndex": 0,
            "totalResults": len(match),
            "vulnerabilities": [{"cve": match[0]}] if match else [],
        }
