from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional

from backend.app.models.artefact import Artefact, ArtefactType


class LifetimeClass(str, Enum):
    SHORT = "short"     # < 2 years (e.g. session keys, ephemeral tokens)
    MEDIUM = "medium"   # 2 - 10 years (e.g. TLS certificates, API keys)
    LONG = "long"       # > 10 years (e.g. code signing, root CAs, archived/encrypted DB data)

    @property
    def default_years(self) -> float:
        """Default data shelf-life X in years."""
        if self == LifetimeClass.SHORT:
            return 1.0
        elif self == LifetimeClass.MEDIUM:
            return 5.0
        elif self == LifetimeClass.LONG:
            return 15.0
        return 5.0


class Criticality(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> float:
        if self == Criticality.CRITICAL:
            return 2.5
        elif self == Criticality.HIGH:
            return 2.0
        elif self == Criticality.MEDIUM:
            return 1.5
        return 1.0


# Keyword dictionaries for inferring business criticality from file path and context
CRITICALITY_KEYWORDS = {
    Criticality.CRITICAL: [
        "payment",
        "pci",
        "billing",
        "checkout",
        "auth",
        "login",
        "credential",
        "prod",
        "production",
        "wallet",
        "banking",
        "identity",
        "oauth",
    ],
    Criticality.HIGH: [
        "db",
        "database",
        "backup",
        "vault",
        "secret",
        "user",
        "account",
        "admin",
        "crypto",
        "session",
        "key",
        "ssl",
        "master",
        "core",
    ],
    Criticality.MEDIUM: [
        "api",
        "service",
        "gateway",
        "config",
        "server",
        "internal",
        "router",
        "proxy",
        "network",
    ],
    Criticality.LOW: [
        "test",
        "mock",
        "sample",
        "demo",
        "example",
        "fixture",
        "doc",
        "bench",
    ],
}


class AssetClassifier:
    """
    Classifies cryptographic artefacts by operational lifetime class (<2y, 2-10y, >10y)
    and business criticality (low, medium, high, critical).
    Supports keyword-based path heuristics and explicit manual overrides.
    """

    @classmethod
    def infer_criticality(
        cls,
        artefact: Artefact,
        override: Optional[Criticality | str] = None,
    ) -> Criticality:
        if override:
            return Criticality(override) if isinstance(override, str) else override

        # Check metadata override
        if "criticality" in artefact.metadata:
            val = artefact.metadata["criticality"]
            if isinstance(val, str):
                try:
                    return Criticality(val.lower())
                except ValueError:
                    pass

        file_str = artefact.location.file.lower().replace("\\", "/")
        path_obj = Path(file_str)

        # Check for test/sample path first
        if any(kw in file_str for kw in CRITICALITY_KEYWORDS[Criticality.LOW]):
            # If specifically in test or mock, default to LOW unless payment/auth
            if not any(kw in file_str for kw in CRITICALITY_KEYWORDS[Criticality.CRITICAL]):
                return Criticality.LOW

        # Check CRITICAL keywords
        if any(kw in file_str for kw in CRITICALITY_KEYWORDS[Criticality.CRITICAL]):
            return Criticality.CRITICAL

        # Check HIGH keywords
        if any(kw in file_str for kw in CRITICALITY_KEYWORDS[Criticality.HIGH]):
            return Criticality.HIGH

        # Check MEDIUM keywords
        if any(kw in file_str for kw in CRITICALITY_KEYWORDS[Criticality.MEDIUM]):
            return Criticality.MEDIUM

        return Criticality.MEDIUM

    @classmethod
    def infer_lifetime(
        cls,
        artefact: Artefact,
        override: Optional[LifetimeClass | str] = None,
    ) -> LifetimeClass:
        if override:
            return LifetimeClass(override) if isinstance(override, str) else override

        # Check metadata override
        if "lifetime" in artefact.metadata:
            val = artefact.metadata["lifetime"]
            if isinstance(val, str):
                try:
                    return LifetimeClass(val.lower())
                except ValueError:
                    pass

        name_lower = artefact.name.lower()
        evidence_lower = artefact.evidence.lower()
        file_lower = artefact.location.file.lower().replace("\\", "/")

        # 1. Certificate heuristics
        if artefact.type == ArtefactType.CERTIFICATE:
            # Root CA / Self-signed root / Code signing certs are long-lived
            if artefact.metadata.get("self_signed") or "root" in evidence_lower or "ca" in evidence_lower:
                return LifetimeClass.LONG
            return LifetimeClass.MEDIUM

        # 2. Key heuristics
        if artefact.type == ArtefactType.KEY:
            if any(k in name_lower or k in evidence_lower for k in ["master", "root", "signing", "private"]):
                return LifetimeClass.LONG
            if any(k in name_lower or k in evidence_lower for k in ["session", "ephemeral", "jwt", "token"]):
                return LifetimeClass.SHORT
            return LifetimeClass.MEDIUM

        # 3. Algorithm heuristics based on usage location
        if any(k in file_lower for k in ["backup", "archive", "db", "database", "storage", "vault"]):
            return LifetimeClass.LONG

        if any(k in name_lower or k in evidence_lower for k in ["ephemeral", "session", "tls_client", "handshake"]):
            return LifetimeClass.SHORT

        # Protocols (TLS, SSH) are medium lifetime (infrastructure configuration cycle)
        if artefact.type == ArtefactType.PROTOCOL:
            return LifetimeClass.MEDIUM

        # Libraries are typically updated within medium horizon
        if artefact.type == ArtefactType.LIBRARY:
            return LifetimeClass.MEDIUM

        return LifetimeClass.MEDIUM
