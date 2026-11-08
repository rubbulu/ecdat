from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from backend.app.models.artefact import Artefact, QuantumStatus
from backend.app.models.catalogue import CatalogueEntry, CryptoCatalogue

logger = logging.getLogger(__name__)

# Default path relative to project structure
DEFAULT_CATALOGUE_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "crypto_catalogue.json"


class CryptoCatalogueService:
    """
    Service for loading, querying, and enriching cryptographic artefacts
    using the central NIST PQC & classical cryptographic catalogue.
    """

    def __init__(self, catalogue_path: Optional[Path] = None):
        self.catalogue_path = catalogue_path or DEFAULT_CATALOGUE_PATH
        self._catalogue: Optional[CryptoCatalogue] = None
        self._lookup_map: Dict[str, Tuple[str, CatalogueEntry]] = {}
        self._load()

    def _normalize_key(self, name: str) -> str:
        """Normalize algorithm strings for robust matching."""
        return name.strip().lower().replace("_", "-").replace(" ", "-")

    def _load(self) -> None:
        if not self.catalogue_path.exists():
            raise FileNotFoundError(f"Catalogue file not found at {self.catalogue_path}")

        with open(self.catalogue_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

        self._catalogue = CryptoCatalogue(**raw_data)
        self._lookup_map.clear()

        for canonical_name, entry in self._catalogue.algorithms.items():
            norm_canonical = self._normalize_key(canonical_name)
            self._lookup_map[norm_canonical] = (canonical_name, entry)

            for alias in entry.aliases:
                norm_alias = self._normalize_key(alias)
                self._lookup_map[norm_alias] = (canonical_name, entry)

        logger.info(f"Loaded {len(self._catalogue.algorithms)} algorithms ({len(self._lookup_map)} aliases) from {self.catalogue_path}")

    @property
    def catalogue(self) -> CryptoCatalogue:
        if self._catalogue is None:
            self._load()
        return self._catalogue

    def get_algorithm(self, name: str) -> Optional[Tuple[str, CatalogueEntry]]:
        """
        Lookup an algorithm by canonical name or alias.
        Returns (canonical_name, CatalogueEntry) or None.
        """
        norm = self._normalize_key(name)
        if norm in self._lookup_map:
            return self._lookup_map[norm]

        # Partial matching heuristic (e.g. 'AES-128-GCM' -> matches 'aes-128')
        for key, val in self._lookup_map.items():
            if norm.startswith(key) or key.startswith(norm):
                return val

        return None

    def enrich_artefact(self, artefact: Artefact) -> Artefact:
        """
        Enrich an Artefact with quantum status, NIST PQC replacement, and notes from catalogue.
        Also normalizes the artefact name to the canonical catalogue name.
        """
        lookup = self.get_algorithm(artefact.name)
        if lookup:
            canonical_name, entry = lookup
            artefact.name = canonical_name
            artefact.quantum_status = entry.quantum_status
            artefact.nist_replacement = entry.nist_replacement
            artefact.notes = entry.notes
            artefact.metadata["canonical_name"] = canonical_name
            artefact.metadata["family"] = entry.family
            artefact.metadata["primitive"] = entry.primitive
        return artefact

    def get_vulnerable_algorithms(self) -> List[Tuple[str, CatalogueEntry]]:
        """Return all algorithms vulnerable to Shor's algorithm."""
        return [
            (name, entry)
            for name, entry in self.catalogue.algorithms.items()
            if entry.quantum_status == QuantumStatus.VULNERABLE_SHOR
        ]

    def get_quantum_safe_algorithms(self) -> List[Tuple[str, CatalogueEntry]]:
        """Return all quantum-safe / PQC algorithms."""
        return [
            (name, entry)
            for name, entry in self.catalogue.algorithms.items()
            if entry.quantum_status == QuantumStatus.QUANTUM_SAFE
        ]


# Global singleton instance for easy import across modules
catalogue_service = CryptoCatalogueService()
