"""
CRISP Cybersecurity Platform - RAG Knowledge Base Package
Phase 3 Step 1: ChromaDB Vector Store, Semantic Indexer & Retriever Foundation.

Provides:
- Persistent ChromaDB vector collection management
- Structured Document Builder for NVD, CISA KEV, NIST CSF 2.0, Assets, Findings, Incidents
- Synchronous and incremental Indexer with deduplication
- Multi-collection and filtered semantic Retriever
"""

from services.rag.chroma_client import (
    CRISPChromaManager,
    get_chroma_client,
    get_collection,
    COLLECTION_NAMES,
)
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
from services.rag.indexer import (
    CRISPIndexer,
    index_vulnerabilities,
    index_kev,
    index_nist,
    index_findings,
    index_assets,
    index_incidents,
    index_all,
    get_index_stats,
)
from services.rag.retriever import (
    CRISPRetriever,
    get_retriever,
    retrieve,
    retrieve_vulnerabilities,
    retrieve_findings,
    retrieve_nist,
    retrieve_assets,
    retrieve_incidents,
    NO_RELEVANT_DATA_MSG,
)

__all__ = [
    "CRISPChromaManager",
    "get_chroma_client",
    "get_collection",
    "COLLECTION_NAMES",
    "DocumentBuilder",
    "build_vulnerability_doc",
    "build_kev_doc",
    "build_nist_doc",
    "build_finding_doc",
    "build_asset_doc",
    "build_incident_doc",
    "build_risk_assessment_doc",
    "CRISPIndexer",
    "index_vulnerabilities",
    "index_kev",
    "index_nist",
    "index_findings",
    "index_assets",
    "index_incidents",
    "index_all",
    "get_index_stats",
    "CRISPRetriever",
    "get_retriever",
    "retrieve",
    "retrieve_vulnerabilities",
    "retrieve_findings",
    "retrieve_nist",
    "retrieve_assets",
    "retrieve_incidents",
    "NO_RELEVANT_DATA_MSG",
]
