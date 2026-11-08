import pytest
from pydantic import ValidationError
from backend.app.models.artefact import (
    Artefact,
    ArtefactType,
    Location,
    QuantumStatus,
    Scan,
    ScanStatus,
)


def test_location_from_string():
    loc = Location.from_str_or_dict("src/crypto/rsa.py:42:15")
    assert loc.file == "src/crypto/rsa.py"
    assert loc.line == 42
    assert loc.column == 15
    assert str(loc) == "src/crypto/rsa.py:42:15"


def test_location_from_dict():
    loc = Location.from_str_or_dict({"file": "main.py", "line": 10})
    assert loc.file == "main.py"
    assert loc.line == 10
    assert loc.column is None
    assert str(loc) == "main.py:10"


def test_artefact_creation_minimal():
    artefact = Artefact(
        type=ArtefactType.ALGORITHM,
        name="RSA",
        location="src/auth.py:25",
        detection_method="ast_parser",
    )
    assert artefact.name == "RSA"
    assert artefact.type == ArtefactType.ALGORITHM
    assert artefact.location.file == "src/auth.py"
    assert artefact.location.line == 25
    assert artefact.confidence == 1.0
    assert artefact.id is not None


def test_artefact_full_fields():
    artefact = Artefact(
        type="algorithm",
        name="AES-256",
        version="2.1",
        mode="GCM",
        key_size=256,
        location=Location(file="crypto.py", line=12, column=4),
        detection_method="regex_heuristic",
        evidence="cipher = AES.new(key, AES.MODE_GCM)",
        confidence=0.95,
        quantum_status="quantum_safe",
        nist_replacement="None needed",
        notes="Standard 256-bit AES",
        metadata={"library": "pycryptodome"},
    )
    assert artefact.type == ArtefactType.ALGORITHM
    assert artefact.mode == "GCM"
    assert artefact.key_size == 256
    assert artefact.confidence == 0.95
    assert artefact.quantum_status == QuantumStatus.QUANTUM_SAFE


def test_artefact_confidence_validation():
    # Confidence must be between 0.0 and 1.0
    with pytest.raises(ValidationError):
        Artefact(
            type=ArtefactType.KEY,
            name="PrivateKey",
            location="key.pem:1",
            detection_method="cert_parser",
            confidence=1.5,
        )

    with pytest.raises(ValidationError):
        Artefact(
            type=ArtefactType.KEY,
            name="PrivateKey",
            location="key.pem:1",
            detection_method="cert_parser",
            confidence=-0.1,
        )


def test_artefact_invalid_type():
    with pytest.raises(ValidationError):
        Artefact(
            type="invalid_type",
            name="TestCrypto",
            location="test.py:1",
            detection_method="manual",
        )


def test_scan_model():
    scan = Scan(target_path="/opt/app")
    assert scan.target_path == "/opt/app"
    assert scan.status == ScanStatus.PENDING
    assert scan.total_artefacts == 0
    assert scan.id is not None
    assert scan.created_at is not None
