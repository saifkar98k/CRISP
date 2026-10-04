"""
CRISP Cybersecurity Platform - ChromaDB Client & Collection Manager
Phase 3 Step 1: Vector Knowledge Base Storage.

Manages persistent ChromaDB vector storage, logical collections,
and embedding function configuration for CRISP.
"""

import os
from typing import Dict, List, Optional
import chromadb
from chromadb.config import Settings

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
        self.client = chromadb.PersistentClient(
            path=self.persist_directory,
            settings=Settings(
                anonymized_telemetry=False,
                allow_reset=True,
            ),
        )

    @classmethod
    def get_instance(cls, persist_directory: Optional[str] = None) -> "CRISPChromaManager":
        target_dir = persist_directory or os.environ.get("CRISP_CHROMA_DIR", DEFAULT_PERSIST_DIR)
        if cls._instance is None or cls._instance.persist_directory != target_dir:
            cls._instance = cls(persist_directory=target_dir)
        return cls._instance

    def get_collection(self, logical_or_exact_name: str) -> chromadb.Collection:
        """
        Retrieves or creates a Chroma collection by logical or exact name.
        Logical names: 'vulnerabilities', 'nist', 'findings', 'assets', 'incidents'
        """
        exact_name = COLLECTION_NAMES.get(logical_or_exact_name, logical_or_exact_name)
        # Chroma collection names must be 3-63 chars, alphanumeric with underscore/hyphen
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

    def get_collection_stats(self) -> Dict[str, Dict[str, any]]:
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


def get_chroma_client(persist_directory: Optional[str] = None) -> chromadb.PersistentClient:
    """Helper returning raw Chroma PersistentClient."""
    return CRISPChromaManager.get_instance(persist_directory).client


def get_collection(logical_name: str, persist_directory: Optional[str] = None) -> chromadb.Collection:
    """Helper returning a Chroma Collection by logical name."""
    return CRISPChromaManager.get_instance(persist_directory).get_collection(logical_name)
