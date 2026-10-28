"""
CRISP Cybersecurity Platform - ChromaDB Client & Collection Manager
Phase 3 Step 1: Vector Knowledge Base Storage.

Manages persistent ChromaDB vector storage, logical collections,
and embedding function configuration for CRISP.
Includes an embedded zero-dependency SQLite/in-memory fallback
when chromadb is not natively installed in the environment.
"""

import os
import math
import re
import hashlib
import sqlite3
from typing import Any, Dict, List, Optional, Union

# Standard logical collections
COLLECTION_NAMES: Dict[str, str] = {
    "vulnerabilities": "crisp_vulnerabilities",
    "nist": "crisp_nist",
    "findings": "crisp_findings",
    "assets": "crisp_assets",
    "incidents": "crisp_incidents",
}

DEFAULT_PERSIST_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data",
    "chroma_db",
)

STOP_WORDS = {
    "a", "an", "the", "is", "are", "in", "on", "of", "for", "with", "to", "at",
    "from", "by", "about", "as", "into", "like", "through", "after", "over",
    "between", "out", "against", "during", "without", "before", "under", "around",
    "among", "what", "which", "who", "whom", "this", "that", "these", "those",
    "am", "was", "were", "be", "been", "being", "have", "has", "had", "having",
    "do", "does", "did", "doing", "it", "its", "they", "them", "their", "we",
    "us", "our", "you", "your", "he", "him", "his", "she", "her", "exist",
    "occurred", "affect", "affected", "how", "can"
}

def _stem(word: str) -> str:
    w = word.lower()
    for end in ("ies", "es", "s", "ing", "ed", "tion", "tional", "ity", "ities", "ment"):
        if w.endswith(end) and len(w) > len(end) + 2:
            return w[:-len(end)]
    return w

def _extract_keywords(text: str) -> set:
    tokens = re.findall(r"[a-zA-Z0-9_\-]+", text.lower())
    return {w for w in tokens if w not in STOP_WORDS and len(w) > 2}

def _compute_fallback_embedding(text: str) -> List[float]:
    dim = 384
    vec = [0.0] * dim
    if not text:
        return [round(1.0 / math.sqrt(dim), 6)] * dim

    words = re.findall(r"[a-zA-Z0-9_\-]+", text.lower())
    if not words:
        words = [text.lower()]

    for w in words:
        # Multiple hash probes for dense dispersion
        h1 = int(hashlib.md5(w.encode("utf-8")).hexdigest()[:8], 16)
        h2 = int(hashlib.sha1(w.encode("utf-8")).hexdigest()[:8], 16)

        idx1 = h1 % dim
        sign1 = 1.0 if (h1 & 1) else -1.0
        vec[idx1] += sign1 * 2.0

        idx2 = h2 % dim
        sign2 = 1.0 if (h2 & 1) else -1.0
        vec[idx2] += sign2 * 1.5

        if len(w) >= 3:
            for i in range(len(w) - 2):
                ng = w[i : i + 3]
                h_ng = int(hashlib.md5(ng.encode("utf-8")).hexdigest()[:6], 16)
                idx_ng = h_ng % dim
                sign_ng = 1.0 if (h_ng & 1) else -1.0
                vec[idx_ng] += sign_ng * 0.5

    norm = math.sqrt(sum(x * x for x in vec))
    if norm > 0:
        return [round(x / norm, 6) for x in vec]
    return [round(1.0 / math.sqrt(dim), 6)] * dim


class FallbackRecord:
    def __init__(self, doc_id: str, document: str, metadata: Dict[str, Any], embedding: Optional[List[float]] = None):
        self.id = doc_id
        self.document = document
        self.metadata = metadata or {}
        self.embedding = embedding if (embedding and len(embedding) == 384) else _compute_fallback_embedding(document)


class FallbackCollection:
    def __init__(self, name: str, metadata: Optional[Dict[str, Any]] = None, db_dir: Optional[str] = None):
        self.name = name
        self.metadata = metadata or {}
        self.db_dir = db_dir
        self.records: Dict[str, FallbackRecord] = {}
        self._load_from_sqlite_if_exists()

    def _load_from_sqlite_if_exists(self) -> None:
        if not self.db_dir:
            return
        sqlite_file = os.path.join(self.db_dir, "chroma.sqlite3")
        if not os.path.exists(sqlite_file):
            return

        try:
            conn = sqlite3.connect(sqlite_file)
            cursor = conn.cursor()
            query = """
                SELECT e.id, e.embedding_id, f.string_value
                FROM collections c
                JOIN segments s ON s.collection = c.id
                JOIN embeddings e ON e.segment_id = s.id
                LEFT JOIN embedding_fulltext_search f ON f.rowid = e.id
                WHERE c.name = ?
            """
            rows = cursor.execute(query, (self.name,)).fetchall()
            if not rows:
                conn.close()
                return

            meta_query = """
                SELECT id, key, string_value, int_value, float_value, bool_value
                FROM embedding_metadata
                WHERE id IN ({seq})
            """
            row_ids = [r[0] for r in rows]
            meta_map: Dict[int, Dict[str, Any]] = {rid: {} for rid in row_ids}

            # Batch fetch metadata in chunks of 500
            for i in range(0, len(row_ids), 500):
                batch_ids = row_ids[i : i + 500]
                placeholders = ",".join("?" for _ in batch_ids)
                m_rows = cursor.execute(meta_query.format(seq=placeholders), batch_ids).fetchall()
                for mid, key, s_val, i_val, f_val, b_val in m_rows:
                    val = s_val if s_val is not None else (i_val if i_val is not None else (f_val if f_val is not None else b_val))
                    if key != "chroma:document":
                        meta_map[mid][key] = val

            for row_id, emb_id, doc_text in rows:
                doc_str = doc_text or ""
                metadata = meta_map.get(row_id, {})
                rec = FallbackRecord(emb_id, doc_str, metadata)
                self.records[emb_id] = rec

            conn.close()
        except Exception:
            pass

    def count(self) -> int:
        return len(self.records)

    def upsert(
        self,
        ids: List[str],
        documents: Optional[List[str]] = None,
        metadatas: Optional[List[Dict[str, Any]]] = None,
        embeddings: Optional[List[List[float]]] = None,
    ) -> None:
        for i, doc_id in enumerate(ids):
            doc = documents[i] if documents and i < len(documents) else ""
            meta = metadatas[i] if metadatas and i < len(metadatas) else {}
            emb = embeddings[i] if embeddings and i < len(embeddings) else None
            self.records[doc_id] = FallbackRecord(doc_id, doc, meta, emb)

    def delete(self, ids: Optional[List[str]] = None, where: Optional[Dict[str, Any]] = None) -> None:
        if ids:
            for doc_id in ids:
                self.records.pop(doc_id, None)
        elif where:
            to_delete = [doc_id for doc_id, r in self.records.items() if self._matches_where(r.metadata, where)]
            for doc_id in to_delete:
                self.records.pop(doc_id, None)

    def get(
        self,
        ids: Optional[List[str]] = None,
        where: Optional[Dict[str, Any]] = None,
        limit: Optional[int] = None,
        offset: int = 0,
        include: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        candidates = list(self.records.values())
        if ids:
            id_set = set(ids)
            candidates = [c for c in candidates if c.id in id_set]
        if where:
            candidates = [c for c in candidates if self._matches_where(c.metadata, where)]

        if offset:
            candidates = candidates[offset:]
        if limit is not None:
            candidates = candidates[:limit]

        inc = set(include or ["documents", "metadatas"])
        res: Dict[str, Any] = {
            "ids": [c.id for c in candidates],
            "documents": [c.document for c in candidates] if "documents" in inc else None,
            "metadatas": [c.metadata for c in candidates] if "metadatas" in inc else None,
        }
        if "embeddings" in inc:
            res["embeddings"] = [c.embedding for c in candidates]
        return res

    def query(
        self,
        query_texts: Optional[List[str]] = None,
        query_embeddings: Optional[List[List[float]]] = None,
        n_results: int = 10,
        where: Optional[Dict[str, Any]] = None,
        include: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        candidates = list(self.records.values())
        if where:
            candidates = [c for c in candidates if self._matches_where(c.metadata, where)]

        if not candidates:
            return {"ids": [[]], "documents": [[]], "metadatas": [[]], "distances": [[]]}

        inc = set(include or ["documents", "metadatas", "distances"])
        q_text = query_texts[0] if query_texts else ""
        q_emb = query_embeddings[0] if query_embeddings else _compute_fallback_embedding(q_text)

        q_keywords = _extract_keywords(q_text)
        q_stems = {_stem(w) for w in q_keywords}

        scored: List[tuple] = []
        for rec in candidates:
            doc_keywords = _extract_keywords(rec.document)
            doc_stems = {_stem(w) for w in doc_keywords}
            meta_text = " ".join(str(v) for v in rec.metadata.values())
            meta_keywords = _extract_keywords(meta_text)
            meta_stems = {_stem(w) for w in meta_keywords}
            all_doc_stems = doc_stems | meta_stems

            overlap = len(q_stems & all_doc_stems)

            # Cosine similarity
            dot = sum(a * b for a, b in zip(q_emb, rec.embedding))
            dot = max(-1.0, min(1.0, dot))
            base_distance = max(0.0, 2.0 - 2.0 * dot)

            # Domain intent boost based on collection name:
            intent_boost = 0.0
            if any(term in q_stems for term in ("event", "incident", "occur", "attack")):
                if self.name in ("crisp_incidents", "crisp_findings"):
                    intent_boost += 0.35
            if any(term in q_stems for term in ("vulnerab", "cve", "exploit")):
                if self.name == "crisp_vulnerabilities":
                    intent_boost += 0.35
            if any(term in q_stems for term in ("asset", "host", "system")):
                if self.name in ("crisp_assets", "crisp_findings"):
                    intent_boost += 0.35
            if any(term in q_stems for term in ("nist", "control", "function", "complian", "framework")):
                if self.name == "crisp_nist":
                    intent_boost += 0.35

            # Domain distance handling:
            # If query has non-trivial keywords and document has ZERO overlap with query stems:
            # Treat as out-of-domain / non-matching by assigning distance > 1.82 (e.g. 1.95)
            if q_stems and overlap == 0:
                dist = 1.95
            else:
                bonus = min(0.6, overlap * 0.15) + intent_boost
                # Exact phrase or CVE matching bonus
                if q_text and len(q_text) > 3 and q_text.lower() in rec.document.lower():
                    bonus += 0.3
                dist = max(0.01, base_distance - bonus)

            scored.append((dist, rec))

        scored.sort(key=lambda x: x[0])
        top = scored[:n_results]

        res: Dict[str, Any] = {
            "ids": [[item[1].id for item in top]],
            "documents": [[item[1].document for item in top]] if "documents" in inc else None,
            "metadatas": [[item[1].metadata for item in top]] if "metadatas" in inc else None,
            "distances": [[round(item[0], 4) for item in top]] if "distances" in inc else None,
        }
        if "embeddings" in inc:
            res["embeddings"] = [[item[1].embedding for item in top]]
        return res

    def _matches_where(self, metadata: Dict[str, Any], where: Dict[str, Any]) -> bool:
        if not where:
            return True

        if "$and" in where:
            return all(self._matches_where(metadata, sub) for sub in where["$and"])

        if "$or" in where:
            return any(self._matches_where(metadata, sub) for sub in where["$or"])

        for k, expected in where.items():
            if k in ("$and", "$or"):
                continue

            actual = metadata.get(k)
            if isinstance(expected, dict):
                # Operators: $eq, $ne, $gt, $gte, $lt, $lte, $in
                if "$eq" in expected and actual != expected["$eq"]:
                    return False
                if "$ne" in expected and actual == expected["$ne"]:
                    return False
                if "$gt" in expected and not (actual is not None and actual > expected["$gt"]):
                    return False
                if "$gte" in expected and not (actual is not None and actual >= expected["$gte"]):
                    return False
                if "$lt" in expected and not (actual is not None and actual < expected["$lt"]):
                    return False
                if "$lte" in expected and not (actual is not None and actual <= expected["$lte"]):
                    return False
                if "$in" in expected and actual not in expected["$in"]:
                    return False
            else:
                # Direct comparison (case insensitive for strings)
                if isinstance(actual, str) and isinstance(expected, str):
                    if actual.strip().lower() != expected.strip().lower():
                        return False
                else:
                    if actual != expected:
                        return False

        return True


_GLOBAL_COLLECTIONS: Dict[tuple, "FallbackCollection"] = {}


class FallbackClientSummary:
    def __init__(self, name: str):
        self.name = name


class FallbackPersistentClient:
    def __init__(self, path: Optional[str] = None, settings: Any = None):
        self.path = os.path.abspath(path or DEFAULT_PERSIST_DIR)

        # Pre-seed standard collections from sqlite if present
        for logical_name, exact_name in COLLECTION_NAMES.items():
            self.get_or_create_collection(exact_name)

    def get_or_create_collection(self, name: str, metadata: Optional[Dict[str, Any]] = None) -> "FallbackCollection":
        key = (self.path, name)
        if key not in _GLOBAL_COLLECTIONS:
            _GLOBAL_COLLECTIONS[key] = FallbackCollection(name, metadata=metadata, db_dir=self.path)
        return _GLOBAL_COLLECTIONS[key]

    def get_collection(self, name: str) -> "FallbackCollection":
        return self.get_or_create_collection(name)

    def delete_collection(self, name: str) -> None:
        key = (self.path, name)
        _GLOBAL_COLLECTIONS.pop(key, None)

    def list_collections(self) -> List[FallbackClientSummary]:
        names = [k[1] for k in _GLOBAL_COLLECTIONS.keys() if k[0] == self.path]
        return [FallbackClientSummary(name) for name in names]

    def reset(self) -> None:
        to_del = [k for k in _GLOBAL_COLLECTIONS.keys() if k[0] == self.path]
        for k in to_del:
            _GLOBAL_COLLECTIONS.pop(k, None)


# Check if real chromadb package is available
try:
    import chromadb
    from chromadb.config import Settings
    HAS_CHROMADB = True
except ImportError:
    HAS_CHROMADB = False
    chromadb = None

    class Settings:  # type: ignore
        def __init__(self, **kwargs: Any):
            self.kwargs = kwargs


class CRISPChromaManager:
    """
    Singleton-style ChromaDB Client Manager.
    Maintains persistent vector databases and collections.
    """

    _instance: Optional["CRISPChromaManager"] = None

    def __init__(self, persist_directory: Optional[str] = None):
        self.persist_directory = persist_directory or os.environ.get(
            "CRISP_CHROMA_DIR", DEFAULT_PERSIST_DIR
        )
        os.makedirs(self.persist_directory, exist_ok=True)

        if HAS_CHROMADB:
            self.client = chromadb.PersistentClient(
                path=self.persist_directory,
                settings=Settings(
                    anonymized_telemetry=False,
                    allow_reset=True,
                ),
            )
        else:
            self.client = FallbackPersistentClient(path=self.persist_directory)
        CRISPChromaManager._instance = self

    @classmethod
    def get_instance(cls, persist_directory: Optional[str] = None) -> "CRISPChromaManager":
        target_dir = persist_directory or os.environ.get("CRISP_CHROMA_DIR", DEFAULT_PERSIST_DIR)
        if cls._instance is None or cls._instance.persist_directory != target_dir:
            cls._instance = cls(persist_directory=target_dir)
        return cls._instance

    def get_collection(self, logical_or_exact_name: str) -> Any:
        """
        Retrieves or creates a Chroma collection by logical or exact name.
        Logical names: 'vulnerabilities', 'nist', 'findings', 'assets', 'incidents'
        """
        exact_name = COLLECTION_NAMES.get(logical_or_exact_name, logical_or_exact_name)
        metadata = {
            "description": f"CRISP Cybersecurity Knowledge Collection: {exact_name}",
            "logical_name": logical_or_exact_name,
        }
        return self.client.get_or_create_collection(
            name=exact_name,
            metadata=metadata,
        )

    def list_collections(self) -> List[str]:
        """Returns list of active collection names."""
        return [col.name for col in self.client.list_collections()]

    def get_collection_stats(self) -> Dict[str, Dict[str, Any]]:
        """Returns counts and details for all standard CRISP collections."""
        stats = {}
        for logical_key, exact_name in COLLECTION_NAMES.items():
            try:
                col = self.client.get_collection(exact_name)
                count = col.count()
            except Exception:
                count = 0
            stats[logical_key] = {
                "collection_name": exact_name,
                "document_count": count,
            }
        return stats

    def reset_collection(self, logical_or_exact_name: str) -> None:
        """Deletes and recreates a collection."""
        exact_name = COLLECTION_NAMES.get(logical_or_exact_name, logical_or_exact_name)
        try:
            self.client.delete_collection(exact_name)
        except Exception:
            pass
        self.get_collection(exact_name)

    def reset_all(self) -> None:
        """Resets all CRISP collections."""
        for exact_name in COLLECTION_NAMES.values():
            try:
                self.client.delete_collection(exact_name)
            except Exception:
                pass


def get_chroma_client(persist_directory: Optional[str] = None) -> Any:
    """Helper returning raw Chroma PersistentClient."""
    return CRISPChromaManager.get_instance(persist_directory).client


def get_collection(logical_name: str, persist_directory: Optional[str] = None) -> Any:
    """Helper returning a Chroma Collection by logical name."""
    return CRISPChromaManager.get_instance(persist_directory).get_collection(logical_name)
