from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional, Union
from pydantic import BaseModel, Field, field_validator


class ArtefactType(str, Enum):
    ALGORITHM = "algorithm"
    KEY = "key"
    CERTIFICATE = "certificate"
    PROTOCOL = "protocol"
    LIBRARY = "library"
    SERVICE = "service"


class QuantumStatus(str, Enum):
    VULNERABLE_SHOR = "vulnerable_shor"
    WEAKENED_GROVER = "weakened_grover"
    CLASSICALLY_BROKEN = "classically_broken"
    QUANTUM_SAFE = "quantum_safe"


class Location(BaseModel):
    file: str
    line: int = Field(default=1, ge=1)
    column: Optional[int] = Field(default=None, ge=1)

    def __str__(self) -> str:
        if self.column is not None:
            return f"{self.file}:{self.line}:{self.column}"
        return f"{self.file}:{self.line}"

    @classmethod
    def from_str_or_dict(cls, val: Union[str, Dict[str, Any], "Location"]) -> "Location":
        if isinstance(val, cls):
            return val
        if isinstance(val, dict):
            return cls(**val)
        if isinstance(val, str):
            parts = val.split(":")
            file_part = parts[0]
            line_part = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 1
            col_part = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else None
            return cls(file=file_part, line=line_part, column=col_part)
        raise ValueError(f"Cannot parse Location from {val}")


class Artefact(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: Optional[str] = None
    type: ArtefactType
    name: str = Field(..., min_length=1)
    version: Optional[str] = None
    mode: Optional[str] = None
    key_size: Optional[int] = Field(default=None, ge=0)
    location: Location
    detection_method: str = Field(..., min_length=1)
    evidence: str = Field(default="")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    
    # Enrichment fields (from catalogue or risk engine)
    quantum_status: Optional[QuantumStatus] = None
    nist_replacement: Optional[str] = None
    notes: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("id", mode="before")
    @classmethod
    def ensure_id(cls, v: Any) -> str:
        if not v:
            return str(uuid.uuid4())
        return str(v)

    @field_validator("location", mode="before")
    @classmethod
    def parse_location(cls, v: Any) -> Location:
        return Location.from_str_or_dict(v)

    @field_validator("type", mode="before")
    @classmethod
    def parse_type(cls, v: Any) -> ArtefactType:
        if isinstance(v, str):
            v_lower = v.lower().strip()
            for item in ArtefactType:
                if item.value == v_lower:
                    return item
        return v

    @field_validator("quantum_status", mode="before")
    @classmethod
    def parse_quantum_status(cls, v: Any) -> Optional[QuantumStatus]:
        if v is None:
            return None
        if isinstance(v, str):
            v_lower = v.lower().strip()
            for item in QuantumStatus:
                if item.value == v_lower:
                    return item
        return v


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Scan(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_path: str
    status: ScanStatus = ScanStatus.PENDING
    total_artefacts: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("id", mode="before")
    @classmethod
    def ensure_id(cls, v: Any) -> str:
        if not v:
            return str(uuid.uuid4())
        return str(v)

