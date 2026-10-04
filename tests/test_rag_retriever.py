"""
Unit Tests for CRISP RAG Retrieval Infrastructure
Phase 3 Step 2: Validates semantic retrieval across all 5 test questions,
domain-specific retrievers, metadata filtering, and no-hallucination protection.

Test Questions Required by Specification:
1. What critical vulnerabilities exist?
2. Which assets have the highest risk?
3. Which vulnerabilities are known exploited?
4. What security events occurred?
5. Which NIST function is affected?
"""

import unittest
from services.rag.retriever import (
    retrieve,
    retrieve_vulnerabilities,
    retrieve_findings,
    retrieve_nist,
    retrieve_assets,
    retrieve_incidents,
    build_chroma_filter,
    NO_RELEVANT_DATA_MSG,
    CRISPRetriever,
)


class TestRAGRetriever(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.retriever = CRISPRetriever()

    # =========================================================================
    # 1. Test Question 1: What critical vulnerabilities exist?
    # =========================================================================

    def test_question_1_critical_vulnerabilities(self):
        query = "What critical vulnerabilities exist?"
        results = retrieve(query, n_results=3)

        self.assertNotEqual(
            results,
            NO_RELEVANT_DATA_MSG,
            "Retriever failed to find critical vulnerabilities in CRISP knowledge base.",
        )
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)

        # Verify returned data format: document, metadata, similarity
        first = results[0]
        self.assertIn("document", first)
        self.assertIn("metadata", first)
        self.assertIn("similarity", first)
        self.assertIn("similarity_score", first)
        self.assertIn("relevance", first)
        self.assertIn("collection", first)

        # Verify documents contain authentic vulnerability or finding intelligence
        doc_text = first["document"]
        meta = first["metadata"]
        self.assertTrue(
            "CVE" in doc_text or meta.get("severity") in ("CRITICAL", "HIGH"),
            f"Expected critical vulnerability text or metadata, got: {first}",
        )

    # =========================================================================
    # 2. Test Question 2: Which assets have the highest risk?
    # =========================================================================

    def test_question_2_highest_risk_assets(self):
        query = "Which assets have the highest risk?"
        results = retrieve(query, n_results=3)

        self.assertNotEqual(results, NO_RELEVANT_DATA_MSG)
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)

        first = results[0]
        self.assertIn("document", first)
        self.assertIn("metadata", first)

        # Check for asset or finding reference with high risk/criticality
        collections_found = {r["collection"] for r in results}
        self.assertTrue(
            "assets" in collections_found or "findings" in collections_found,
            f"Expected asset or finding in results, got collections: {collections_found}",
        )

    # =========================================================================
    # 3. Test Question 3: Which vulnerabilities are known exploited?
    # =========================================================================

    def test_question_3_known_exploited_vulnerabilities(self):
        query = "Which vulnerabilities are known exploited?"
        results = retrieve(query, n_results=3)

        self.assertNotEqual(results, NO_RELEVANT_DATA_MSG)
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)

        # Verify CISA KEV or known exploited indicators in results
        found_kev_indicator = False
        for hit in results:
            doc = hit["document"].lower()
            meta = hit["metadata"]
            if (
                "known exploited" in doc
                or "cisa" in doc
                or meta.get("source") == "CISA_KEV"
                or meta.get("document_type") == "kev"
                or meta.get("is_known_exploited") is True
            ):
                found_kev_indicator = True
                break

        self.assertTrue(
            found_kev_indicator,
            f"Expected CISA KEV or known exploited reference in results: {results}",
        )

    # =========================================================================
    # 4. Test Question 4: What security events occurred?
    # =========================================================================

    def test_question_4_security_events_occurred(self):
        query = "What security events occurred?"
        results = retrieve(query, n_results=3)

        self.assertNotEqual(results, NO_RELEVANT_DATA_MSG)
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)

        # Should match incidents or security findings
        collections = {r["collection"] for r in results}
        self.assertTrue(
            "incidents" in collections or "findings" in collections,
            f"Expected incidents or findings in results, got: {collections}",
        )

    # =========================================================================
    # 5. Test Question 5: Which NIST function is affected?
    # =========================================================================

    def test_question_5_nist_function_affected(self):
        query = "Which NIST function is affected?"
        results = retrieve(query, n_results=3)

        self.assertNotEqual(results, NO_RELEVANT_DATA_MSG)
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)

        # Check that NIST CSF 2.0 functions are present
        nist_functions = {"GOVERN", "IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"}
        found_function = False
        for hit in results:
            meta_fn = hit["metadata"].get("nist_function")
            if meta_fn in nist_functions:
                found_function = True
                break
            for fn in nist_functions:
                if fn in hit["document"]:
                    found_function = True
                    break

        self.assertTrue(
            found_function,
            f"Expected NIST function in metadata or text, got: {results}",
        )

    # =========================================================================
    # 6. Domain-Specific Retrievers Verification
    # =========================================================================

    def test_retrieve_vulnerabilities(self):
        results = retrieve_vulnerabilities("command injection PAN-OS", n_results=2)
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)
        self.assertEqual(results[0]["collection"], "vulnerabilities")
        self.assertIn("document", results[0])
        self.assertIn("metadata", results[0])
        self.assertIn("similarity", results[0])

    def test_retrieve_findings(self):
        results = retrieve_findings("brute force attack on web server", n_results=2)
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)
        self.assertEqual(results[0]["collection"], "findings")

    def test_retrieve_nist(self):
        results = retrieve_nist("incident management response procedures", n_results=2)
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)
        self.assertEqual(results[0]["collection"], "nist")
        self.assertIn("NIST", results[0]["document"])

    # =========================================================================
    # 7. Metadata Filtering Capabilities
    # =========================================================================

    def test_filter_by_cve(self):
        filter_dict = {"cve": "CVE-2021-44228"}
        results = retrieve("remote code execution", filters=filter_dict, n_results=2)
        if results != NO_RELEVANT_DATA_MSG:
            for hit in results:
                self.assertEqual(hit["metadata"].get("cve_id"), "CVE-2021-44228")

    def test_filter_by_asset(self):
        filter_dict = {"asset": "AST-PROD-WEB-01"}
        results = retrieve("banking web system", filters=filter_dict, n_results=2)
        self.assertNotEqual(results, NO_RELEVANT_DATA_MSG)
        for hit in results:
            self.assertEqual(hit["metadata"].get("asset_id"), "AST-PROD-WEB-01")

    def test_filter_by_severity(self):
        filter_dict = {"severity": "CRITICAL"}
        results = retrieve("security risks", filters=filter_dict, n_results=3)
        self.assertNotEqual(results, NO_RELEVANT_DATA_MSG)
        for hit in results:
            self.assertEqual(hit["metadata"].get("severity"), "CRITICAL")

    def test_filter_by_source(self):
        filter_dict = {"source": "NIST_CSF_2.0"}
        results = retrieve("governance and protection", filters=filter_dict, n_results=3)
        self.assertNotEqual(results, NO_RELEVANT_DATA_MSG)
        for hit in results:
            self.assertEqual(hit["metadata"].get("source"), "NIST_CSF_2.0")

    def test_filter_by_nist_function(self):
        filter_dict = {"nist_function": "PROTECT"}
        results = retrieve("identity platform security", filters=filter_dict, n_results=3)
        self.assertNotEqual(results, NO_RELEVANT_DATA_MSG)
        for hit in results:
            self.assertEqual(hit["metadata"].get("nist_function"), "PROTECT")

    def test_filter_by_document_type(self):
        filter_dict = {"document_type": "asset"}
        results = retrieve("infrastructure systems", filters=filter_dict, n_results=3)
        self.assertNotEqual(results, NO_RELEVANT_DATA_MSG)
        for hit in results:
            self.assertEqual(hit["metadata"].get("document_type"), "asset")

    def test_build_chroma_filter_syntax(self):
        # Single filter
        f1 = build_chroma_filter({"severity": "critical"})
        self.assertEqual(f1, {"severity": "CRITICAL"})

        # Multiple filters combined with $and
        f2 = build_chroma_filter({"cve": "CVE-2024-3400", "source": "NVD", "severity": "CRITICAL"})
        self.assertIn("$and", f2)
        clauses = f2["$and"]
        self.assertEqual(len(clauses), 3)

    # =========================================================================
    # 8. No Hallucination Foundation
    # =========================================================================

    def test_no_hallucination_on_nonexistent_cve(self):
        # Filtering for a non-existent CVE should return NO_RELEVANT_DATA_MSG
        res = retrieve(
            "What is the status of CVE-9999-99999?",
            filters={"cve": "CVE-9999-99999"},
        )
        self.assertEqual(
            res,
            NO_RELEVANT_DATA_MSG,
            f"Expected '{NO_RELEVANT_DATA_MSG}' for non-existent CVE, got: {res}",
        )

    def test_no_hallucination_on_out_of_domain_query(self):
        # Querying an out-of-domain dessert recipe must NOT hallucinate security data
        res = retrieve("recipe for chocolate chip strawberry cake dessert with whipped cream")
        self.assertEqual(
            res,
            NO_RELEVANT_DATA_MSG,
            f"Expected '{NO_RELEVANT_DATA_MSG}' for out-of-domain query, got: {res}",
        )


if __name__ == "__main__":
    unittest.main()
