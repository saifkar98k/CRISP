"""
CRISP Cybersecurity Platform - RAG Semantic Retriever
Phase 3 Step 2: Retrieval-Augmented Generation Infrastructure.

Provides authoritative, multi-collection semantic retrieval for security questions
over CRISP knowledge bases:
- Vulnerabilities (NVD & CISA KEV)
- NIST CSF 2.0 Controls
- Correlated Security Findings
- Enterprise Asset Inventory
- Security Incidents & Telemetry

NO HALLUCINATION FOUNDATION:
If no relevant CRISP information exists or candidate matches fall below
the relevance threshold, returns:
"No relevant CRISP data was found."
"""

from typing import Any, Dict, List, Optional, Union
from services.rag.chroma_client import CRISPChromaManager, COLLECTION_NAMES

NO_RELEVANT_DATA_MSG = "No relevant CRISP data was found."

# Empirical threshold: if top hit distance > 1.82 (or collections/filters produce 0 hits),
# it indicates out-of-domain / irrelevant input.
DEFAULT_MAX_DISTANCE = 1.82


def build_chroma_filter(filters: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Transforms user-facing filter parameters into valid ChromaDB 'where' clause.
    Supported filters:
    - CVE: 'cve' or 'cve_id'
    - asset: 'asset' or 'asset_id'
    - severity: 'severity'
    - source: 'source'
    - NIST function: 'nist_function' or 'nist'
    - document type: 'document_type' or 'type'
    """
    if not filters:
        return None

    clauses: List[Dict[str, Any]] = []

    # 1. CVE filter
    cve = filters.get("cve") or filters.get("cve_id") or filters.get("CVE")
    if cve:
        clauses.append({"cve_id": str(cve).strip().upper()})

    # 2. Asset filter
    asset = filters.get("asset") or filters.get("asset_id") or filters.get("asset_name")
    if asset:
        clauses.append({"asset_id": str(asset).strip()})

    # 3. Severity filter (normalize case)
    severity = filters.get("severity")
    if severity:
        clauses.append({"severity": str(severity).strip().upper()})

    # 4. Source filter
    source = filters.get("source")
    if source:
        clauses.append({"source": str(source).strip()})

    # 5. NIST function filter
    nist_func = (
        filters.get("nist_function")
        or filters.get("nist")
        or filters.get("function")
        or filters.get("NIST_FUNCTION")
    )
    if nist_func:
        clauses.append({"nist_function": str(nist_func).strip().upper()})

    # 6. Document type filter
    doc_type = (
        filters.get("document_type")
        or filters.get("type")
        or filters.get("doc_type")
    )
    if doc_type:
        clauses.append({"document_type": str(doc_type).strip().lower()})

    # 7. Pass-through for any direct Chroma metadata keys
    handled_keys = {
        "cve", "cve_id", "CVE", "asset", "asset_id", "asset_name",
        "severity", "source", "nist_function", "nist", "function",
        "NIST_FUNCTION", "document_type", "type", "doc_type",
    }
    for k, v in filters.items():
        if k not in handled_keys and isinstance(v, (str, int, float, bool)):
            clauses.append({k: v})

    if not clauses:
        return None
    if len(clauses) == 1:
        return clauses[0]
    return {"$and": clauses}


class CRISPRetriever:
    """
    Retrieves authentic CRISP documents with semantic relevance and metadata filtering.
    """

    def __init__(self, persist_dir: Optional[str] = None):
        self.chroma_mgr = CRISPChromaManager.get_instance(persist_directory=persist_dir)

    def _query_collection(
        self,
        collection_key: str,
        query: str,
        n_results: int = 5,
        filters: Optional[Dict[str, Any]] = None,
        include_embeddings: bool = False,
    ) -> List[Dict[str, Any]]:
        """Internal worker executing query on a specific logical collection."""
        try:
            col = self.chroma_mgr.get_collection(collection_key)
            if col.count() == 0:
                return []

            includes = ["documents", "metadatas", "distances"]
            if include_embeddings:
                includes.append("embeddings")

            k = min(n_results, col.count())
            if k <= 0:
                return []

            where_clause = build_chroma_filter(filters)

            kwargs: Dict[str, Any] = {
                "query_texts": [query],
                "n_results": k,
                "include": includes,
            }
            if where_clause:
                kwargs["where"] = where_clause

            res = col.query(**kwargs)

            results: List[Dict[str, Any]] = []
            if not res or not res.get("ids") or len(res["ids"]) == 0:
                return results

            ids = res.get("ids", [[]])[0] if res.get("ids") is not None and len(res.get("ids", [])) > 0 else []
            docs = res.get("documents", [[]])[0] if res.get("documents") is not None and len(res.get("documents", [])) > 0 else [""] * len(ids)
            metas = res.get("metadatas", [[]])[0] if res.get("metadatas") is not None and len(res.get("metadatas", [])) > 0 else [{}] * len(ids)
            distances = res.get("distances", [[]])[0] if res.get("distances") is not None and len(res.get("distances", [])) > 0 else [0.0] * len(ids)

            raw_embeddings = res.get("embeddings")
            embeddings_list = None
            if include_embeddings and raw_embeddings is not None and len(raw_embeddings) > 0:
                batch_embeddings = raw_embeddings[0]
                if batch_embeddings is not None:
                    embeddings_list = batch_embeddings

            for i in range(len(ids)):
                dist = float(distances[i]) if i < len(distances) else 0.0
                similarity = round(1.0 / (1.0 + max(0.0, dist)), 4)
                item: Dict[str, Any] = {
                    "id": ids[i],
                    "document": docs[i] if i < len(docs) else "",
                    "metadata": metas[i] if i < len(metas) else {},
                    "similarity": similarity,
                    "similarity_score": similarity,
                    "relevance": similarity,
                    "relevance_score": similarity,
                    "distance": dist,
                    "collection": collection_key,
                }
                if embeddings_list is not None and i < len(embeddings_list):
                    emb = embeddings_list[i]
                    if hasattr(emb, "tolist"):
                        item["embedding"] = emb.tolist()
                    elif isinstance(emb, (list, tuple)):
                        item["embedding"] = list(emb)
                    else:
                        item["embedding"] = [float(x) for x in emb]
                results.append(item)

            results.sort(key=lambda x: x["similarity_score"], reverse=True)
            return results

        except Exception as e:
            return []

    # =========================================================================
    # Domain-Specific Retrieval Functions
    # =========================================================================

    def retrieve_vulnerabilities(
        self,
        query: str,
        filters: Optional[Dict[str, Any]] = None,
        n_results: int = 5,
        max_distance: float = DEFAULT_MAX_DISTANCE,
        empty_as_str: bool = True,
    ) -> Union[List[Dict[str, Any]], str]:
        """
        Retrieves relevant vulnerability documents (NVD CVEs & CISA KEV).
        Supports filters: CVE, severity, source, asset, document_type.
        If no relevant records match, returns 'No relevant CRISP data was found.'.
        """
        hits = self._query_collection("vulnerabilities", query, n_results=n_results, filters=filters)

        # Filter out hits exceeding max distance threshold if any
        valid_hits = [h for h in hits if h["distance"] <= max_distance]
        if not valid_hits:
            return NO_RELEVANT_DATA_MSG if empty_as_str else []
        return valid_hits

    def retrieve_findings(
        self,
        query: str,
        filters: Optional[Dict[str, Any]] = None,
        n_results: int = 5,
        max_distance: float = DEFAULT_MAX_DISTANCE,
        empty_as_str: bool = True,
    ) -> Union[List[Dict[str, Any]], str]:
        """
        Retrieves relevant correlated security findings and risk assessments.
        Supports filters: asset, severity, CVE, NIST function, source.
        """
        hits = self._query_collection("findings", query, n_results=n_results, filters=filters)
        valid_hits = [h for h in hits if h["distance"] <= max_distance]
        if not valid_hits:
            return NO_RELEVANT_DATA_MSG if empty_as_str else []
        return valid_hits

    def retrieve_nist(
        self,
        query: str,
        filters: Optional[Dict[str, Any]] = None,
        n_results: int = 5,
        max_distance: float = DEFAULT_MAX_DISTANCE,
        empty_as_str: bool = True,
    ) -> Union[List[Dict[str, Any]], str]:
        """
        Retrieves relevant NIST CSF 2.0 controls and benchmarks.
        Supports filters: NIST function, severity/status.
        """
        hits = self._query_collection("nist", query, n_results=n_results, filters=filters)
        valid_hits = [h for h in hits if h["distance"] <= max_distance]
        if not valid_hits:
            return NO_RELEVANT_DATA_MSG if empty_as_str else []
        return valid_hits

    def retrieve_assets(
        self,
        query: str,
        filters: Optional[Dict[str, Any]] = None,
        n_results: int = 5,
        max_distance: float = DEFAULT_MAX_DISTANCE,
        empty_as_str: bool = True,
    ) -> Union[List[Dict[str, Any]], str]:
        """
        Retrieves relevant enterprise assets.
        Supports filters: asset_id, severity (criticality).
        """
        hits = self._query_collection("assets", query, n_results=n_results, filters=filters)
        valid_hits = [h for h in hits if h["distance"] <= max_distance]
        if not valid_hits:
            return NO_RELEVANT_DATA_MSG if empty_as_str else []
        return valid_hits

    def retrieve_incidents(
        self,
        query: str,
        filters: Optional[Dict[str, Any]] = None,
        n_results: int = 5,
        max_distance: float = DEFAULT_MAX_DISTANCE,
        empty_as_str: bool = True,
    ) -> Union[List[Dict[str, Any]], str]:
        """
        Retrieves relevant security event telemetry summaries.
        Supports filters: severity, asset, CVE, NIST function.
        """
        hits = self._query_collection("incidents", query, n_results=n_results, filters=filters)
        valid_hits = [h for h in hits if h["distance"] <= max_distance]
        if not valid_hits:
            return NO_RELEVANT_DATA_MSG if empty_as_str else []
        return valid_hits

    # =========================================================================
    # Universal / Primary Retrieval Function
    # =========================================================================

    def retrieve(
        self,
        query: str,
        filters: Optional[Dict[str, Any]] = None,
        n_results: int = 5,
        collection: Optional[str] = None,
        max_distance: float = DEFAULT_MAX_DISTANCE,
        empty_as_str: bool = True,
    ) -> Union[List[Dict[str, Any]], str]:
        """
        Given a security question, retrieves the most relevant CRISP documents.
        Supports automatic federated routing or targeted collection queries with filters.
        
        If collection is specified, searches that specific collection.
        If collection is None, executes federated search across all CRISP knowledge stores.
        
        NO HALLUCINATION POLICY:
        If no relevant CRISP data exists, returns "No relevant CRISP data was found."
        """
        if collection:
            hits = self._query_collection(
                collection,
                query,
                n_results=n_results,
                filters=filters,
            )
            valid_hits = [h for h in hits if h["distance"] <= max_distance]
            if not valid_hits:
                return NO_RELEVANT_DATA_MSG if empty_as_str else []
            return valid_hits[:n_results]

        # Multi-collection federated search
        all_hits: List[Dict[str, Any]] = []
        for col_key in COLLECTION_NAMES.keys():
            col_hits = self._query_collection(
                col_key,
                query,
                n_results=n_results,
                filters=filters,
            )
            for h in col_hits:
                if h["distance"] <= max_distance:
                    all_hits.append(h)

        if not all_hits:
            return NO_RELEVANT_DATA_MSG if empty_as_str else []

        # Sort by similarity score descending
        all_hits.sort(key=lambda x: x.get("similarity_score", 0.0), reverse=True)

        # Deduplicate hits by id
        seen_ids = set()
        deduped_hits: List[Dict[str, Any]] = []
        for hit in all_hits:
            hid = hit["id"]
            if hid not in seen_ids:
                seen_ids.add(hid)
                deduped_hits.append(hit)
            if len(deduped_hits) >= n_results:
                break

        if not deduped_hits:
            return NO_RELEVANT_DATA_MSG if empty_as_str else []

        return deduped_hits

    # =========================================================================
    # Compatibility Wrappers for Previous Interface
    # =========================================================================

    def search_collection(self, collection_key: str, query: str, n_results: int = 5, where: Optional[Dict] = None, include_embeddings: bool = False):
        return self._query_collection(collection_key, query, n_results, filters=where, include_embeddings=include_embeddings)

    def search_vulnerabilities(self, query: str, n_results: int = 5, where: Optional[Dict] = None, include_embeddings: bool = False):
        return self._query_collection("vulnerabilities", query, n_results, filters=where, include_embeddings=include_embeddings)

    def search_nist(self, query: str, n_results: int = 5, where: Optional[Dict] = None, include_embeddings: bool = False):
        return self._query_collection("nist", query, n_results, filters=where, include_embeddings=include_embeddings)

    def search_findings(self, query: str, n_results: int = 5, where: Optional[Dict] = None, include_embeddings: bool = False):
        return self._query_collection("findings", query, n_results, filters=where, include_embeddings=include_embeddings)

    def search_assets(self, query: str, n_results: int = 5, where: Optional[Dict] = None, include_embeddings: bool = False):
        return self._query_collection("assets", query, n_results, filters=where, include_embeddings=include_embeddings)

    def search_incidents(self, query: str, n_results: int = 5, where: Optional[Dict] = None, include_embeddings: bool = False):
        return self._query_collection("incidents", query, n_results, filters=where, include_embeddings=include_embeddings)

    def search_all(self, query: str, n_results_per_collection: int = 3, where: Optional[Dict] = None):
        all_res = []
        for col in COLLECTION_NAMES.keys():
            hits = self._query_collection(col, query, n_results=n_results_per_collection, filters=where)
            all_res.extend(hits)
        all_res.sort(key=lambda x: x.get("similarity_score", 0.0), reverse=True)
        return all_res

    def get_relevant_context(self, query: str, max_tokens_approx: int = 2000) -> Dict[str, Any]:
        retrieval = self.retrieve(query, n_results=6, empty_as_str=False)
        if isinstance(retrieval, str) or not retrieval:
            return {
                "query": query,
                "total_matches": 0,
                "context_document": NO_RELEVANT_DATA_MSG,
                "citations": [],
            }

        context_texts = [f"[{h.get('collection', '').upper()} | {h.get('id', '')}] {h.get('document', '')}" for h in retrieval]
        return {
            "query": query,
            "total_matches": len(retrieval),
            "context_document": "\n\n".join(context_texts),
            "citations": [
                {
                    "id": h.get("id"),
                    "source": h.get("metadata", {}).get("source", ""),
                    "collection": h.get("collection", ""),
                    "similarity": h.get("similarity_score", 0.0),
                }
                for h in retrieval
            ],
        }


# =============================================================================
# Standalone Module-Level Functions
# retrieve(query), retrieve_vulnerabilities(query), retrieve_findings(query), retrieve_nist(query)
# =============================================================================

_default_retriever: Optional[CRISPRetriever] = None


def get_retriever(persist_dir: Optional[str] = None) -> CRISPRetriever:
    global _default_retriever
    if _default_retriever is None or persist_dir:
        _default_retriever = CRISPRetriever(persist_dir=persist_dir)
    return _default_retriever


def retrieve(
    query: str,
    filters: Optional[Dict[str, Any]] = None,
    n_results: int = 5,
    collection: Optional[str] = None,
    persist_dir: Optional[str] = None,
) -> Union[List[Dict[str, Any]], str]:
    """Top-level retrieve(query) implementation."""
    return get_retriever(persist_dir).retrieve(
        query=query,
        filters=filters,
        n_results=n_results,
        collection=collection,
    )


def retrieve_vulnerabilities(
    query: str,
    filters: Optional[Dict[str, Any]] = None,
    n_results: int = 5,
    persist_dir: Optional[str] = None,
) -> Union[List[Dict[str, Any]], str]:
    """Top-level retrieve_vulnerabilities(query) implementation."""
    return get_retriever(persist_dir).retrieve_vulnerabilities(
        query=query,
        filters=filters,
        n_results=n_results,
    )


def retrieve_findings(
    query: str,
    filters: Optional[Dict[str, Any]] = None,
    n_results: int = 5,
    persist_dir: Optional[str] = None,
) -> Union[List[Dict[str, Any]], str]:
    """Top-level retrieve_findings(query) implementation."""
    return get_retriever(persist_dir).retrieve_findings(
        query=query,
        filters=filters,
        n_results=n_results,
    )


def retrieve_nist(
    query: str,
    filters: Optional[Dict[str, Any]] = None,
    n_results: int = 5,
    persist_dir: Optional[str] = None,
) -> Union[List[Dict[str, Any]], str]:
    """Top-level retrieve_nist(query) implementation."""
    return get_retriever(persist_dir).retrieve_nist(
        query=query,
        filters=filters,
        n_results=n_results,
    )


def retrieve_assets(
    query: str,
    filters: Optional[Dict[str, Any]] = None,
    n_results: int = 5,
    persist_dir: Optional[str] = None,
) -> Union[List[Dict[str, Any]], str]:
    return get_retriever(persist_dir).retrieve_assets(
        query=query,
        filters=filters,
        n_results=n_results,
    )


def retrieve_incidents(
    query: str,
    filters: Optional[Dict[str, Any]] = None,
    n_results: int = 5,
    persist_dir: Optional[str] = None,
) -> Union[List[Dict[str, Any]], str]:
    return get_retriever(persist_dir).retrieve_incidents(
        query=query,
        filters=filters,
        n_results=n_results,
    )
