from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend.app.models.artefact import Artefact, ArtefactType, QuantumStatus
from backend.app.risk.mosca import MoscaAssessment, MoscaEngine

logger = logging.getLogger(__name__)

CYCLONEDX_1_6_SCHEMA = "http://cyclonedx.org/schema/bom-1.6.schema.json"


class CycloneDX16CBOMBuilder:
    """
    Exports cryptographic artefacts into CycloneDX v1.6 JSON Cryptographic Bill of Materials (CBOM).
    Implements cryptographic-asset component specifications with full cryptoProperties.
    """

    @classmethod
    def generate_cbom(
        cls,
        artefacts: List[Artefact],
        assessments: Optional[List[MoscaAssessment]] = None,
        target_name: str = "ECDAT Target",
        target_version: str = "1.0.0",
        serial_number: Optional[str] = None,
    ) -> Dict[str, Any]:
        now_iso = datetime.now(timezone.utc).isoformat()
        bom_serial = serial_number or f"urn:uuid:{uuid.uuid4()}"

        assess_map: Dict[str, MoscaAssessment] = {}
        if assessments:
            for a in assessments:
                assess_map[a.artefact_id] = a
        else:
            for art in artefacts:
                assess_map[art.id] = MoscaEngine.evaluate(art)

        components: List[Dict[str, Any]] = []
        for art in artefacts:
            ass = assess_map.get(art.id)
            comp = cls._artefact_to_cyclonedx_component(art, ass)
            components.append(comp)

        cbom = {
            "$schema": CYCLONEDX_1_6_SCHEMA,
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": bom_serial,
            "version": 1,
            "metadata": {
                "timestamp": now_iso,
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "name": "ECDAT",
                            "version": "1.0.0",
                            "description": "Enterprise Cryptographic Discovery & Analysis Tool",
                            "externalReferences": [
                                {
                                    "type": "website",
                                    "url": "https://github.com/rubbulu/ecdat",
                                }
                            ],
                        }
                    ]
                },
                "component": {
                    "type": "application",
                    "name": target_name,
                    "version": target_version,
                },
                "properties": [
                    {"name": "ecdat:total_crypto_assets", "value": str(len(artefacts))},
                    {
                        "name": "ecdat:at_risk_crypto_assets",
                        "value": str(sum(1 for a in assess_map.values() if a.is_at_risk)),
                    },
                ],
            },
            "components": components,
            "dependencies": [],
        }

        return cbom

    @classmethod
    def _artefact_to_cyclonedx_component(
        cls,
        art: Artefact,
        assessment: Optional[MoscaAssessment],
    ) -> Dict[str, Any]:
        bom_ref = f"crypto-asset-{art.id}"
        name = art.name
        q_status_val = art.quantum_status.value if art.quantum_status else "unclassified"
        risk_score = assessment.risk_score if assessment else 0.0

        # Map ECDAT ArtefactType to CycloneDX assetType
        # CycloneDX 1.6: algorithm | certificate | protocol | related-crypto-material
        if art.type == ArtefactType.CERTIFICATE:
            asset_type = "certificate"
        elif art.type == ArtefactType.PROTOCOL:
            asset_type = "protocol"
        elif art.type == ArtefactType.KEY:
            asset_type = "related-crypto-material"
        else:
            asset_type = "algorithm"

        crypto_props: Dict[str, Any] = {"assetType": asset_type}

        # 1. Algorithm Properties
        if asset_type == "algorithm":
            algo_props: Dict[str, Any] = {
                "primitive": cls._map_primitive(art.name, art.metadata.get("primitive")),
            }
            if art.key_size:
                algo_props["parameterSetIdentifier"] = str(art.key_size)
            if art.mode:
                algo_props["mode"] = art.mode.lower()

            curve = art.metadata.get("curve")
            if curve:
                algo_props["curve"] = curve

            # Classical & Quantum Security Levels
            classical_sec, quantum_sec = cls._derive_security_levels(art)
            if classical_sec is not None:
                algo_props["classicalSecurityLevel"] = classical_sec
            if quantum_sec is not None:
                algo_props["nistQuantumSecurityLevel"] = quantum_sec

            crypto_props["algorithmProperties"] = algo_props

        # 2. Certificate Properties
        elif asset_type == "certificate":
            meta = art.metadata
            cert_props: Dict[str, Any] = {
                "subjectName": meta.get("subject", art.name),
                "issuerName": meta.get("issuer", art.name),
            }
            if "not_before" in meta:
                cert_props["notValidBefore"] = meta["not_before"]
            if "not_after" in meta:
                cert_props["notValidAfter"] = meta["not_after"]
            if "signature_algorithm" in meta:
                cert_props["signatureAlgorithmRef"] = meta["signature_algorithm"]

            crypto_props["certificateProperties"] = cert_props

        # 3. Protocol Properties
        elif asset_type == "protocol":
            proto_type = "tls" if "TLS" in name.upper() or "SSL" in name.upper() else "ssh" if "SSH" in name.upper() else "other"
            proto_props: Dict[str, Any] = {
                "type": proto_type,
                "version": art.version or name,
            }
            ciphers = art.metadata.get("ciphers")
            if ciphers and isinstance(ciphers, list):
                proto_props["cipherSuites"] = [{"name": c} for c in ciphers]

            crypto_props["protocolProperties"] = proto_props

        # 4. Related Crypto Material Properties
        elif asset_type == "related-crypto-material":
            material_type = "private-key" if "private" in name.lower() or "pem" in name.lower() else "secret-key"
            mat_props: Dict[str, Any] = {
                "type": material_type,
            }
            if art.key_size:
                mat_props["size"] = art.key_size

            crypto_props["relatedCryptoMaterialProperties"] = mat_props

        # Custom properties for ECDAT quantum risk & discovery telemetry
        properties = [
            {"name": "ecdat:detection_method", "value": art.detection_method},
            {"name": "ecdat:quantum_status", "value": q_status_val},
            {"name": "ecdat:confidence", "value": str(art.confidence)},
            {"name": "ecdat:risk_score", "value": str(risk_score)},
        ]
        if assessment:
            properties.extend([
                {"name": "ecdat:risk_level", "value": assessment.risk_level},
                {"name": "ecdat:is_at_risk", "value": str(assessment.is_at_risk).lower()},
                {"name": "ecdat:mosca_x", "value": str(assessment.x)},
                {"name": "ecdat:mosca_y", "value": str(assessment.y)},
                {"name": "ecdat:mosca_z", "value": str(assessment.z)},
                {"name": "ecdat:explanation", "value": assessment.explanation},
            ])

        if art.nist_replacement:
            properties.append({"name": "ecdat:nist_replacement", "value": art.nist_replacement})

        if "container_layer" in art.metadata:
            properties.append({"name": "ecdat:container_layer", "value": str(art.metadata["container_layer"])})

        component: Dict[str, Any] = {
            "type": "cryptographic-asset",
            "bom-ref": bom_ref,
            "name": name,
            "cryptoProperties": crypto_props,
            "evidence": {
                "occurrences": [
                    {
                        "location": art.location.file,
                        "line": art.location.line,
                    }
                ]
            },
            "properties": properties,
        }

        if art.version:
            component["version"] = art.version

        return component

    @staticmethod
    def _map_primitive(name: str, raw_primitive: Optional[str]) -> str:
        n = name.upper()
        if any(h in n for h in ["SHA", "MD5", "HASH", "BLAKE"]):
            return "digest"
        elif any(s in n for s in ["ECDSA", "DSA", "ED25519", "SLH-DSA", "ML-DSA", "DILITHIUM"]):
            return "signature"
        elif any(k in n for k in ["DH", "DIFFIE", "X25519", "ECDH"]):
            return "key-agree"
        elif any(kem in n for kem in ["ML-KEM", "KYBER", "KEM"]):
            return "kem"
        elif any(b in n for b in ["AES", "DES", "3DES", "BLOWFISH"]):
            return "block-cipher"
        elif any(st in n for st in ["RC4", "CHACHA20", "SALSA"]):
            return "stream-cipher"
        elif "RSA" in n:
            return "pke"
        return "other"

    @staticmethod
    def _derive_security_levels(art: Artefact) -> Tuple[Optional[int], Optional[int]]:
        n = art.name.upper()
        ks = art.key_size
        q_status = art.quantum_status

        classical_sec: Optional[int] = None
        quantum_sec: Optional[int] = None

        if "AES-256" in n or ks == 256 and "AES" in n:
            classical_sec = 256
            quantum_sec = 5  # NIST Category 5
        elif "AES-192" in n or ks == 192 and "AES" in n:
            classical_sec = 192
            quantum_sec = 3  # NIST Category 3
        elif "AES-128" in n or ks == 128 and "AES" in n:
            classical_sec = 128
            quantum_sec = 1  # NIST Category 1
        elif "RSA" in n:
            if ks == 4096:
                classical_sec = 152
            elif ks == 3072:
                classical_sec = 128
            elif ks == 2048:
                classical_sec = 112
            else:
                classical_sec = 80
            quantum_sec = 0  # Broken by Shor
        elif "ECDSA" in n or "ECDH" in n:
            classical_sec = 128
            quantum_sec = 0  # Broken by Shor
        elif "ML-KEM" in n or "KYBER" in n:
            classical_sec = 256
            quantum_sec = 3
        elif "ML-DSA" in n or "DILITHIUM" in n:
            classical_sec = 256
            quantum_sec = 3
        elif "SLH-DSA" in n or "SPHINCS" in n:
            classical_sec = 256
            quantum_sec = 5
        elif any(b in n for b in ["DES", "3DES", "MD5", "SHA-1"]):
            classical_sec = 64
            quantum_sec = 0

        return classical_sec, quantum_sec


def export_cbom_json(
    artefacts: List[Artefact],
    assessments: Optional[List[MoscaAssessment]] = None,
    output_path: Optional[str | Path] = None,
    target_name: str = "ECDAT Target",
) -> str:
    """Generate and optionally save CycloneDX 1.6 CBOM JSON string."""
    cbom_dict = CycloneDX16CBOMBuilder.generate_cbom(
        artefacts=artefacts,
        assessments=assessments,
        target_name=target_name,
    )
    cbom_json = json.dumps(cbom_dict, indent=2)

    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(cbom_json, encoding="utf-8")
        logger.info(f"Exported CycloneDX 1.6 CBOM to {out}")

    return cbom_json
