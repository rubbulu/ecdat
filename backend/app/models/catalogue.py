from __future__ import annotations

from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from backend.app.models.artefact import QuantumStatus


class CatalogueEntry(BaseModel):
    family: str
    primitive: str
    quantum_status: QuantumStatus
    nist_replacement: str
    notes: str = ""
    aliases: List[str] = Field(default_factory=list)


class CryptoCatalogue(BaseModel):
    version: str = "1.0.0"
    updated_at: str
    algorithms: Dict[str, CatalogueEntry]
