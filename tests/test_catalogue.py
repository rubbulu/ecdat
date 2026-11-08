import json
from pathlib import Path
import pytest
from backend.app.models.artefact import Artefact, ArtefactType, QuantumStatus
from backend.app.services.catalogue_service import (
    CryptoCatalogueService,
    catalogue_service,
)

REQUIRED_ALGORITHMS = [
    "RSA",
    "DSA",
    "DH",
    "ECDH",
    "ECDSA",
    "Ed25519",
    "X25519",
    "AES-128",
    "AES-192",
    "AES-256",
    "3DES",
    "DES",
    "RC4",
    "MD5",
    "SHA-1",
    "SHA-256",
    "SHA-384",
    "SHA-512",
    "SHA-3",
    "HMAC",
    "ChaCha20",
    "TLS 1.0",
    "TLS 1.1",
    "TLS 1.2",
    "TLS 1.3",
    "SSLv3",
    "ML-KEM",
    "ML-DSA",
    "SLH-DSA",
    "Kyber",
    "Dilithium",
]


def test_catalogue_file_exists():
    path = Path("backend/data/crypto_catalogue.json")
    assert path.exists(), "Central crypto catalogue JSON must exist in backend/data/"


def test_all_required_algorithms_present():
    with open("backend/data/crypto_catalogue.json", "r", encoding="utf-8") as f:
        data = json.load(f)

    algorithms = data.get("algorithms", {})
    for algo in REQUIRED_ALGORITHMS:
        assert algo in algorithms, f"Missing required algorithm in catalogue: {algo}"


def test_algorithm_schema_compliance():
    with open("backend/data/crypto_catalogue.json", "r", encoding="utf-8") as f:
        data = json.load(f)

    valid_statuses = {
        "vulnerable_shor",
        "weakened_grover",
        "classically_broken",
        "quantum_safe",
    }

    for name, details in data["algorithms"].items():
        assert "family" in details and details["family"], f"{name} missing family"
        assert "primitive" in details and details["primitive"], f"{name} missing primitive"
        assert "quantum_status" in details, f"{name} missing quantum_status"
        assert details["quantum_status"] in valid_statuses, (
            f"{name} has invalid quantum_status: {details['quantum_status']}"
        )
        assert "nist_replacement" in details and details["nist_replacement"], (
            f"{name} missing nist_replacement"
        )
        assert "notes" in details, f"{name} missing notes"


def test_catalogue_service_lookups():
    # Canonical lookup
    match = catalogue_service.get_algorithm("RSA")
    assert match is not None
    canonical, entry = match
    assert canonical == "RSA"
    assert entry.quantum_status == QuantumStatus.VULNERABLE_SHOR

    # Case-insensitive alias lookup
    match = catalogue_service.get_algorithm("rsa-2048")
    assert match is not None
    canonical, _ = match
    assert canonical == "RSA"

    # Alias for Kyber
    match = catalogue_service.get_algorithm("crystals-kyber")
    assert match is not None
    assert match[1].quantum_status == QuantumStatus.QUANTUM_SAFE

    # 3DES classically broken
    match = catalogue_service.get_algorithm("triple-des")
    assert match is not None
    assert match[1].quantum_status == QuantumStatus.CLASSICALLY_BROKEN


def test_enrich_artefact():
    art = Artefact(
        type=ArtefactType.ALGORITHM,
        name="RSA-2048",
        location="backend/crypto.py:55",
        detection_method="ast_parser",
    )
    enriched = catalogue_service.enrich_artefact(art)
    assert enriched.quantum_status == QuantumStatus.VULNERABLE_SHOR
    assert "ML-KEM" in enriched.nist_replacement
    assert enriched.metadata.get("canonical_name") == "RSA"


def test_quantum_safe_filtering():
    safe_algos = catalogue_service.get_quantum_safe_algorithms()
    safe_names = [name for name, _ in safe_algos]
    assert "AES-256" in safe_names
    assert "ML-KEM" in safe_names
    assert "ML-DSA" in safe_names
    assert "SLH-DSA" in safe_names
    assert "RSA" not in safe_names
