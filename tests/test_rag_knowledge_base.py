"""
Unit Tests for CRISP RAG Knowledge Base Foundation
Phase 3 Step 1: Validates ChromaDB Vector Store, Document Builder, Indexer & Retriever.

Test Suite Verifies:
1. Document format and standard metadata schema:
   - source, cve_id, asset_id, nist_function, severity, document_type
2. Document insertion into ChromaDB collections
3. Embeddings exist and have valid dimensionality (384-dim)
4. Metadata exists and is preserved accurately
5. Semantic retrieval works across knowledge domains
6. Metadata-filtered retrieval (where clauses)
7. Deduplication idempotency (re-indexing does not duplicate documents)
8. Multi-collection coverage (vulnerabilities, nist, findings, assets, incidents)
"""

import os
import shutil
import tempfile
import unittest

from services.rag.chroma_client import CRISPChromaManager, COLLECTION_NAMES
from services.rag.document_builder import (
    DocumentBuilder,
    build_vulnerability_doc,
    build_kev_doc,
    build_nist_doc,
    build_finding_doc,
    build_asset_doc,
    build_incident_doc,
    build_risk_assessment_doc,
)
from services.rag.indexer import CRISPIndexer
from services.rag.retriever import CRISPRetriever


class TestCRISPRAGKnowledgeBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create an isolated temporary directory for test ChromaDB collections
        cls.temp_dir = tempfile.mkdtemp(prefix="crisp_chroma_test_")
        cls.chroma_mgr = CRISPChromaManager(persist_directory=cls.temp_dir)
        cls.indexer = CRISPIndexer(persist_dir=cls.temp_dir)
        cls.retriever = CRISPRetriever(persist_dir=cls.temp_dir)

    @classmethod
    def tearDownClass(cls):
        try:
            shutil.rmtree(cls.temp_dir)
        except Exception:
            pass
        CRISPChromaManager._instance = None

    # =========================================================================
    # 1. Document Format & Metadata Schema Verification
    # =========================================================================

    def test_document_builder_vulnerability(self):
        sample_vuln = {
            "cve_id": "CVE-2024-3400",
            "description": "An OS command injection vulnerability in PAN-OS allows remote code execution.",
            "cvss_score": 10.0,
            "severity": "CRITICAL",
            "affected_products": '["Palo Alto Networks PAN-OS"]',
            "status": "Known Exploited",
            "known_exploited": 1,
            "source": "NVD",
            "exploit_available": 1,
            "patch_available": 1,
        }
        doc_id, text, meta = build_vulnerability_doc(sample_vuln)

        # Verify ID and format
        self.assertEqual(doc_id, "vuln:CVE-2024-3400")
        self.assertIn("CVE-2024-3400", text)
        self.assertIn("CRITICAL", text)
        self.assertIn("vulnerability affecting", text)

        # Verify all mandatory metadata keys
        required_keys = ["source", "cve_id", "asset_id", "nist_function", "severity", "document_type"]
        for k in required_keys:
            self.assertIn(k, meta, f"Missing required metadata key: {k}")

        self.assertEqual(meta["cve_id"], "CVE-2024-3400")
        self.assertEqual(meta["severity"], "CRITICAL")
        self.assertEqual(meta["document_type"], "vulnerability")
        self.assertEqual(meta["source"], "NVD")

    def test_document_builder_kev(self):
        sample_kev = {
            "cve_id": "CVE-2023-4966",
            "kev_vendor_project": "Citrix",
            "kev_product": "NetScaler ADC",
            "description": "Sensitive information disclosure in NetScaler Bleed.",
            "kev_date_added": "2023-10-18",
            "kev_due_date": "2023-10-23",
            "kev_required_action": "Apply vendor hotfix patch.",
            "kev_ransomware_use": "Known",
            "severity": "CRITICAL",
            "cvss_score": 9.4,
        }
        doc_id, text, meta = build_kev_doc(sample_kev)

        self.assertEqual(doc_id, "kev:CVE-2023-4966")
        self.assertIn("CISA Known Exploited Vulnerability", text)
        self.assertIn("Citrix", text)
        self.assertIn("NetScaler ADC", text)

        for k in ["source", "cve_id", "asset_id", "nist_function", "severity", "document_type"]:
            self.assertIn(k, meta)

        self.assertEqual(meta["source"], "CISA_KEV")
        self.assertEqual(meta["cve_id"], "CVE-2023-4966")
        self.assertEqual(meta["document_type"], "kev")

    def test_document_builder_nist(self):
        sample_nist = {
            "id": "ID.RA-01",
            "category": "Risk Assessment",
            "subcategory": "Vulnerabilities identified and evaluated against threat intelligence",
            "function": "IDENTIFY",
            "score": 65.0,
            "status": "PARTIAL",
            "findings": "Multiple active KEV CVEs need patching.",
            "required_remediation": "Apply emergency patches.",
            "evidence": "CISA KEV live feed",
        }
        doc_id, text, meta = build_nist_doc(sample_nist)

        self.assertEqual(doc_id, "nist:ID.RA-01")
        self.assertIn("NIST Cybersecurity Framework (CSF 2.0) Control ID.RA-01", text)
        self.assertIn("IDENTIFY", text)

        for k in ["source", "cve_id", "asset_id", "nist_function", "severity", "document_type"]:
            self.assertIn(k, meta)

        self.assertEqual(meta["source"], "NIST_CSF_2.0")
        self.assertEqual(meta["nist_function"], "IDENTIFY")
        self.assertEqual(meta["document_type"], "nist")

    def test_document_builder_finding_and_asset(self):
        sample_finding = {
            "finding_id": "FND-TEST-001",
            "timestamp": "2026-10-04T08:00:00Z",
            "asset_id": "AST-PROD-WEB-01",
            "asset_name": "prod-edge-web01.internal",
            "attack_category": "Web Attack (SQL Injection)",
            "severity": "HIGH",
            "risk_score": 68.5,
            "risk_level": "HIGH",
            "nist_function": "PROTECT",
            "cve_id": "CVE-2021-44228",
            "known_exploited": 1,
            "asset_criticality": "CRITICAL",
        }
        f_id, f_text, f_meta = build_finding_doc(sample_finding)
        self.assertEqual(f_id, "finding:FND-TEST-001")
        self.assertIn("Security Finding FND-TEST-001", f_text)
        self.assertEqual(f_meta["asset_id"], "AST-PROD-WEB-01")
        self.assertEqual(f_meta["document_type"], "finding")
        self.assertEqual(f_meta["nist_function"], "PROTECT")

        sample_asset = {
            "id": "AST-PROD-WEB-01",
            "name": "prod-edge-web01.internal",
            "ip_address": "10.0.4.15",
            "type": "Web Application",
            "criticality": "CRITICAL",
            "exposure": "EXTERNAL",
            "owner": "Platform Eng",
            "department": "Digital Banking",
            "associated_cves": "CVE-2021-44228",
        }
        a_id, a_text, a_meta = build_asset_doc(sample_asset)
        self.assertEqual(a_id, "asset:AST-PROD-WEB-01")
        self.assertIn("Enterprise Asset prod-edge-web01.internal", a_text)
        self.assertEqual(a_meta["asset_id"], "AST-PROD-WEB-01")
        self.assertEqual(a_meta["severity"], "CRITICAL")
        self.assertEqual(a_meta["document_type"], "asset")

    # =========================================================================
    # 2. Document Insertion Verification
    # =========================================================================

    def test_indexing_inserts_documents(self):
        # Index discrete domains with controlled limits for test speed
        v_res = self.indexer.index_vulnerabilities(limit=5)
        self.assertEqual(v_res["status"], "SUCCESS")
        self.assertGreater(v_res["indexed_count"], 0)

        k_res = self.indexer.index_kev(limit=5)
        self.assertEqual(k_res["status"], "SUCCESS")
        self.assertGreater(k_res["indexed_count"], 0)

        n_res = self.indexer.index_nist()
        self.assertEqual(n_res["status"], "SUCCESS")
        self.assertEqual(n_res["indexed_count"], 10)

        f_res = self.indexer.index_findings(limit=5)
        self.assertEqual(f_res["status"], "SUCCESS")
        self.assertGreater(f_res["indexed_count"], 0)

        a_res = self.indexer.index_assets()
        self.assertEqual(a_res["status"], "SUCCESS")
        self.assertEqual(a_res["indexed_count"], 8)

        stats = self.indexer.get_index_stats()
        self.assertGreater(stats["vulnerabilities"]["document_count"], 0)
        self.assertGreater(stats["nist"]["document_count"], 0)
        self.assertGreater(stats["findings"]["document_count"], 0)
        self.assertGreater(stats["assets"]["document_count"], 0)

    # =========================================================================
    # 3. Embeddings Exist & Dimensionality Verification
    # =========================================================================

    def test_embeddings_exist_and_valid_dimension(self):
        col = self.chroma_mgr.get_collection("nist")
        res = col.get(limit=1, include=["embeddings", "documents", "metadatas"])
        self.assertTrue(len(res["ids"]) > 0, "No documents in nist collection")

        embeddings = res.get("embeddings")
        self.assertIsNotNone(embeddings, "Embeddings not returned")
        self.assertTrue(len(embeddings) > 0, "Embeddings list is empty")

        first_emb = embeddings[0]
        # MiniLM generates dense 384-dimensional embeddings
        self.assertEqual(len(first_emb), 384, f"Expected 384-dim vector, got {len(first_emb)}")
        # Check non-zero vector
        self.assertTrue(any(x != 0.0 for x in first_emb), "Embedding vector is entirely zero")

    # =========================================================================
    # 4. Metadata Exists & Preserved Verification
    # =========================================================================

    def test_metadata_exists_on_stored_records(self):
        col = self.chroma_mgr.get_collection("assets")
        res = col.get(limit=3, include=["metadatas", "documents"])
        for meta in res["metadatas"]:
            self.assertIn("source", meta)
            self.assertIn("cve_id", meta)
            self.assertIn("asset_id", meta)
            self.assertIn("nist_function", meta)
            self.assertIn("severity", meta)
            self.assertIn("document_type", meta)
            self.assertEqual(meta["source"], "ASSET_REGISTRY")
            self.assertEqual(meta["document_type"], "asset")

    # =========================================================================
    # 5. Semantic Retrieval Verification
    # =========================================================================

    def test_retrieval_works_semantically(self):
        # Query NIST collection for risk assessment controls
        results = self.retriever.search_nist("vulnerabilities and threat intelligence", n_results=3)
        self.assertTrue(len(results) > 0, "Semantic search returned no results")

        top_hit = results[0]
        self.assertIn("id", top_hit)
        self.assertIn("document", top_hit)
        self.assertIn("similarity_score", top_hit)
        self.assertGreater(top_hit["similarity_score"], 0.0)

        # ID.RA-01 should be a top hit for vulnerabilities & threat intelligence
        hit_ids = [h["id"] for h in results]
        self.assertTrue(
            any("ID.RA" in hid or "PR.PS" in hid or "ID.AM" in hid for hid in hit_ids),
            f"Expected ID.RA-01 in hits, got: {hit_ids}",
        )

    def test_retrieval_vulnerabilities_and_assets(self):
        # Query vulnerabilities
        vuln_hits = self.retriever.search_vulnerabilities("exploit remote execution", n_results=2)
        self.assertTrue(len(vuln_hits) > 0)
        self.assertEqual(vuln_hits[0]["collection"], "vulnerabilities")

        # Query assets
        asset_hits = self.retriever.search_assets("perimeter web server banking", n_results=2)
        self.assertTrue(len(asset_hits) > 0)
        self.assertEqual(asset_hits[0]["collection"], "assets")

    # =========================================================================
    # 6. Metadata Filtering Verification
    # =========================================================================

    def test_metadata_filtering(self):
        # Filter NIST controls by compliance_status = 'NON_COMPLIANT'
        filtered_hits = self.retriever.search_nist(
            "security policy",
            n_results=5,
            where={"compliance_status": "NON_COMPLIANT"},
        )
        self.assertTrue(len(filtered_hits) > 0)
        for h in filtered_hits:
            self.assertEqual(h["metadata"].get("compliance_status"), "NON_COMPLIANT")
            self.assertEqual(h["id"], "nist:PR.PS-01")

    # =========================================================================
    # 7. Deduplication Idempotency Verification
    # =========================================================================

    def test_deduplication_idempotency(self):
        col = self.chroma_mgr.get_collection("nist")
        # First index run
        self.indexer.index_nist()
        count_first = col.count()
        self.assertGreater(count_first, 0, "Initial NIST indexing produced 0 documents")

        # Second index run (should be idempotent / no duplicates)
        self.indexer.index_nist()
        count_second = col.count()

        self.assertEqual(
            count_first,
            count_second,
            f"Deduplication failed: collection count changed from {count_first} to {count_second}",
        )

    # =========================================================================
    # 8. All Logical Collections Coverage
    # =========================================================================

    def test_all_collections_coverage(self):
        expected_keys = ["vulnerabilities", "nist", "findings", "assets", "incidents"]
        for key in expected_keys:
            self.assertIn(key, COLLECTION_NAMES)
            col = self.chroma_mgr.get_collection(key)
            self.assertIsNotNone(col)


if __name__ == "__main__":
    unittest.main()
