from __future__ import annotations

import logging
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.app.models.artefact import Artefact, ArtefactType, QuantumStatus
from backend.app.risk.classifier import AssetClassifier, LifetimeClass
from backend.app.risk.engine import RiskEngine
from backend.app.risk.mosca import MoscaAssessment, MoscaEngine

logger = logging.getLogger(__name__)


class EffortLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class MigrationApproach(str, Enum):
    HYBRID = "hybrid"
    PURE_PQC = "pure_pqc"
    CLASSICAL_UPGRADE = "classical_upgrade"
    NOT_NEEDED = "not_needed"


class Recommendation(BaseModel):
    artefact_id: str
    artefact_name: str
    current_primitive: str
    quantum_status: Optional[str]
    risk_score: float
    risk_level: str
    replacement: str
    migration_effort: EffortLevel
    size_impact: str
    performance_note: str
    library_suggestion: List[str]
    hybrid_vs_pure: MigrationApproach
    guidance: str
    action_items: List[str]


class RecommendationEngine:
    """
    Automated Post-Quantum Cryptography (PQC) & Classical Hardening Advisory Engine.
    Maps cryptographic assets to NIST standardized PQC algorithms (FIPS 203, 204, 205),
    hybrid transitional mechanisms, and modern symmetric/hashing ciphers.
    Ranks outputs by risk urgency score.
    """

    @classmethod
    def recommend_for_artefact(
        cls,
        artefact: Artefact,
        assessment: Optional[MoscaAssessment] = None,
        x: Optional[float] = None,
        y: Optional[float] = None,
        z: Optional[float] = None,
    ) -> Recommendation:
        if assessment is None:
            assessment = MoscaEngine.evaluate(artefact, x_override=x, y=y, z=z)

        name_upper = artefact.name.upper()
        q_status = artefact.quantum_status
        lifetime = assessment.lifetime_class
        file_path = artefact.location.file

        # Default fallback values
        replacement = artefact.nist_replacement or "Upgrade to NIST standardized quantum-safe primitive"
        effort = EffortLevel.MEDIUM
        size_impact = "Moderate change in public key or ciphertext dimensions."
        perf_note = "Standard cryptographic operation latency."
        libraries = ["liboqs", "OpenSSL 3.5+", "Bouncy Castle 1.78+"]
        approach = MigrationApproach.HYBRID
        guidance = "Plan migration to post-quantum standards."
        action_items = ["Audit primitive call sites", "Evaluate cipher agility"]

        # =====================================================================
        # 1. Asymmetric Key Exchange & Encryption (RSA / DH / ECDH / X25519)
        # =====================================================================
        if any(k in name_upper for k in ["DH", "DIFFIE-HELLMAN", "X25519"]) or (
            "RSA" in name_upper and any(t in str(artefact.metadata).lower() for t in ["kem", "encrypt", "oaep", "kex"])
        ):
            replacement = "ML-KEM-768 (NIST FIPS 203) / Hybrid X25519MLKEM768"
            effort = EffortLevel.MEDIUM
            size_impact = (
                "ML-KEM-768 public key is 1,184 bytes & ciphertext is 1,088 bytes (vs X25519 32 bytes). "
                "Handshake size increases by ~2.2 KB."
            )
            perf_note = (
                "Microsecond-level latency on modern CPUs with AVX2/NEON. Encapsulation/decapsulation "
                "is often faster than classical ECDH; ensure network buffers handle packets >1.5 KB without MTU fragmentation."
            )
            libraries = ["liboqs", "OpenSSL 3.5+", "BoringSSL", "aws-lc", "Bouncy Castle 1.78+", "python-oqs"]
            approach = MigrationApproach.HYBRID
            guidance = (
                "Deploy hybrid key agreement (X25519 + ML-KEM-768) per IETF drafts. "
                "Maintains classical FIPS 140-3 compliance while defending against Harvest Now, Decrypt Later."
            )
            action_items = [
                "Configure TLS / SSH termination proxies to negotiate X25519MLKEM768",
                "Verify MTU path size to prevent packet fragmentation during initial handshake",
                "Update cryptographic libraries to versions supporting NIST FIPS 203 (ML-KEM)",
            ]

        # =====================================================================
        # 2. Digital Signatures (RSA / ECDSA / DSA / Ed25519)
        # =====================================================================
        elif any(s in name_upper for s in ["ECDSA", "DSA", "ED25519", "SIGN"]) or (
            "RSA" in name_upper and any(t in str(artefact.metadata).lower() for t in ["sign", "pss", "cert", "hostkey", "token"])
        ) or ("RSA" in name_upper and artefact.type in {ArtefactType.CERTIFICATE, ArtefactType.KEY}):
            if lifetime == LifetimeClass.LONG or "root" in file_path.lower() or "ca" in file_path.lower():
                # Long-lived trust anchors: SLH-DSA hash-based hedge
                replacement = "SLH-DSA (NIST FIPS 205 / SPHINCS+) or ML-DSA-65 (NIST FIPS 204)"
                effort = EffortLevel.HIGH
                size_impact = (
                    "SLH-DSA signatures are 7,856 - 17,088 bytes; public key is 32 - 64 bytes. "
                    "ML-DSA-65 signature is 3,309 bytes; public key is 1,952 bytes (vs ECDSA 64 bytes)."
                )
                perf_note = (
                    "Stateless hash-based signatures (SLH-DSA) provide conservative mathematical security "
                    "with zero lattice assumptions, ideal for archival root CAs and firmware signing where verification is infrequent."
                )
                libraries = ["liboqs", "OpenSSL 3.5+", "Bouncy Castle 1.78+", "Botan 3.3+"]
                approach = MigrationApproach.HYBRID
                guidance = "Issue hybrid dual-signed certificates combining classical ECDSA/RSA with SLH-DSA or ML-DSA."
                action_items = [
                    "Evaluate certificate chain size limits across all client verification stacks",
                    "Pilot composite dual-signature X.509 certificates (ITU-T X.509 v3)",
                    "Establish cryptographic agility for automated root key rotation",
                ]
            else:
                # General signatures (JWTs, TLS authentication, API signing)
                replacement = "ML-DSA-65 (NIST FIPS 204 / Dilithium)"
                effort = EffortLevel.MEDIUM
                size_impact = (
                    "ML-DSA-65 public key is 1,952 bytes; signature is 3,309 bytes (vs ECDSA P-256 64 bytes; ~50x larger)."
                )
                perf_note = (
                    "Extremely fast signature verification (~30-50 microseconds). "
                    "HTTP Authorization headers carrying signed JWTs will increase in payload size."
                )
                libraries = ["liboqs", "OpenSSL 3.5+", "Bouncy Castle 1.78+", "aws-lc"]
                approach = MigrationApproach.HYBRID
                guidance = "Transition signing infrastructure to ML-DSA-65; support hybrid dual-signing during deprecation window."
                action_items = [
                    "Update JWT header parser to accommodate 3.3 KB signatures",
                    "Benchmark signature verification throughput on API gateway clusters",
                ]

        # =====================================================================
        # 3. Symmetric Ciphers (AES-128, 3DES, DES, RC4)
        # =====================================================================
        elif "AES-128" in name_upper or ("AES" in name_upper and artefact.key_size == 128):
            replacement = "AES-256 (NIST PQC Security Category 5)"
            effort = EffortLevel.LOW
            size_impact = "Key length increases from 16 bytes to 32 bytes; ciphertext length is unchanged."
            perf_note = (
                "Hardware AES-NI instructions maintain multi-gigabit throughput. "
                "Overhead is negligible (~14 rounds vs 10 rounds, ~10-15% CPU difference)."
            )
            libraries = ["Standard library", "cryptography", "OpenSSL", "Web Crypto API"]
            approach = MigrationApproach.CLASSICAL_UPGRADE
            guidance = "Grover's algorithm halves effective key strength to ~64 bits. Upgrade symmetric keys to AES-256."
            action_items = [
                "Re-generate data encryption keys with 256 bits of CSPRNG entropy",
                "Update key management service (AWS KMS, HashiCorp Vault) key templates to AES-256-GCM",
            ]

        elif any(c in name_upper for c in ["3DES", "DES", "RC4", "ARCFOUR"]):
            replacement = "AES-256-GCM (NIST SP 800-38D) or ChaCha20-Poly1305 (RFC 8439)"
            effort = EffortLevel.LOW
            size_impact = "256-bit key + 96-bit nonce + 128-bit authentication tag."
            perf_note = (
                "Dramatic performance improvement: AES-GCM runs at 10+ Gbps with AES-NI/PCLMULQDQ hardware acceleration, "
                "eliminating legacy software cipher bottlenecks."
            )
            libraries = ["Standard library", "cryptography", "OpenSSL", "Java javax.crypto"]
            approach = MigrationApproach.CLASSICAL_UPGRADE
            guidance = "Legacy cipher is classically broken and prohibited by modern standards. Migrate to AEAD cipher."
            action_items = [
                "Deprecate 3DES/DES/RC4 cipher suites immediately across all configurations",
                "Migrate legacy encrypted data using automated re-encryption pipelines",
            ]

        # =====================================================================
        # 4. Cryptographic Hash Functions (MD5, SHA-1)
        # =====================================================================
        elif any(h in name_upper for h in ["MD5", "SHA-1", "SHA1"]):
            replacement = "SHA-256 or SHA-3 (NIST FIPS 202) / SHA-384"
            effort = EffortLevel.LOW
            size_impact = "Digest size increases from 128/160 bits to 256/384 bits (32/48 bytes)."
            perf_note = (
                "Hardware-accelerated SHA extensions on modern Intel/AMD/ARM CPUs provide near line-rate hashing throughput."
            )
            libraries = ["Standard library hashlib", "crypto", "OpenSSL", "java.security.MessageDigest"]
            approach = MigrationApproach.CLASSICAL_UPGRADE
            guidance = "MD5 and SHA-1 suffer practical collision attacks. Replace with SHA-256 or sponge-based SHA-3."
            action_items = [
                "Replace legacy hash function calls across codebases with SHA-256 or SHA-384",
                "Recompute database checksums and password verifiers using modern algorithms (bcrypt/Argon2)",
            ]

        # =====================================================================
        # 5. Transport Protocols (TLS < 1.3, SSLv3, SSH KEX)
        # =====================================================================
        elif any(p in name_upper for p in ["TLS 1.0", "TLS 1.1", "TLS 1.2", "SSLV3", "SSL 3.0"]):
            replacement = "TLS 1.3 with Hybrid Post-Quantum Key Exchange (X25519MLKEM768)"
            effort = EffortLevel.MEDIUM
            size_impact = "ClientHello / ServerHello packets expand by ~1.2 KB for PQC key shares."
            perf_note = (
                "TLS 1.3 reduces handshake round trips to 1-RTT, delivering faster connection establishment "
                "overall despite slightly larger key shares."
            )
            libraries = ["OpenSSL 3.5+", "BoringSSL", "Nginx (built with OpenSSL 3.5+)", "HAProxy"]
            approach = MigrationApproach.HYBRID
            guidance = "Disable TLS 1.0/1.1; enforce TLS 1.3 with hybrid groups (x25519_mlkem768) as primary priority."
            action_items = [
                "Update Nginx/Apache configuration: ssl_protocols TLSv1.3;",
                "Enable PQC KEM curve groups in load balancers (e.g. ssl_ecdh_curve X25519MLKEM768:P-256;)",
            ]

        # =====================================================================
        # 6. Already Quantum-Safe Assets
        # =====================================================================
        elif q_status == QuantumStatus.QUANTUM_SAFE:
            replacement = "None needed (Already NIST Quantum-Resistant)"
            effort = EffortLevel.LOW
            size_impact = "No change needed."
            perf_note = "Operating at target post-quantum security specification."
            libraries = ["Current implementation"]
            approach = MigrationApproach.NOT_NEEDED
            guidance = "Asset already adheres to NIST Post-Quantum Cryptography standards."
            action_items = ["Maintain patch levels", "Monitor NIST PQC standardization updates"]

        return Recommendation(
            artefact_id=artefact.id,
            artefact_name=artefact.name,
            current_primitive=artefact.name + (f"-{artefact.key_size}" if artefact.key_size else ""),
            quantum_status=q_status.value if q_status else None,
            risk_score=assessment.risk_score,
            risk_level=assessment.risk_level,
            replacement=replacement,
            migration_effort=effort,
            size_impact=size_impact,
            performance_note=perf_note,
            library_suggestion=libraries,
            hybrid_vs_pure=approach,
            guidance=guidance,
            action_items=action_items,
        )

    @classmethod
    def recommend_for_scan(
        cls,
        artefacts: List[Artefact],
        assessments: Optional[List[MoscaAssessment]] = None,
        y: float = 3.0,
        z: float = 12.0,
        filter_at_risk: bool = False,
    ) -> List[Recommendation]:
        """
        Generate recommendations for all discovered artefacts in a scan.
        Ranks recommendations by risk_score descending so that the most urgent
        vulnerabilities appear first.
        """
        assess_map: Dict[str, MoscaAssessment] = {}
        if assessments:
            for a in assessments:
                assess_map[a.artefact_id] = a
        else:
            summary = RiskEngine.assess_artefacts(artefacts, default_y=y, default_z=z)
            for a in summary.assessments:
                assess_map[a.artefact_id] = a

        recommendations: List[Recommendation] = []
        for art in artefacts:
            ass = assess_map.get(art.id)
            if filter_at_risk and ass and not ass.is_at_risk:
                continue

            rec = cls.recommend_for_artefact(art, assessment=ass)
            recommendations.append(rec)

        # Rank recommendations descending by risk_score
        recommendations.sort(key=lambda r: r.risk_score, reverse=True)
        return recommendations


def generate_recommendations(
    artefacts: List[Artefact],
    y: float = 3.0,
    z: float = 12.0,
    filter_at_risk: bool = False,
) -> List[Recommendation]:
    """Convenience helper to generate ranked recommendations for a list of artefacts."""
    return RecommendationEngine.recommend_for_scan(artefacts, y=y, z=z, filter_at_risk=filter_at_risk)
