import pytest
from backend.app.models.artefact import (
    Artefact,
    ArtefactType,
    Location,
    QuantumStatus,
    ScanStatus,
)
from backend.app.storage.db import DatabaseManager


@pytest.fixture
def test_db(tmp_path):
    db_file = tmp_path / "test_ecdat.db"
    return DatabaseManager(db_path=db_file)


def test_create_and_get_scan(test_db):
    scan = test_db.create_scan("/opt/sample_app", metadata={"trigger": "manual"})
    assert scan.target_path == "/opt/sample_app"
    assert scan.status == ScanStatus.PENDING
    assert scan.metadata.get("trigger") == "manual"

    fetched = test_db.get_scan(scan.id)
    assert fetched is not None
    assert fetched.id == scan.id
    assert fetched.target_path == "/opt/sample_app"


def test_save_and_retrieve_artefacts(test_db):
    scan = test_db.create_scan("/project/repo")

    artefacts = [
        Artefact(
            scan_id=scan.id,
            type=ArtefactType.ALGORITHM,
            name="RSA",
            version="2048",
            key_size=2048,
            location=Location(file="src/crypto.py", line=15, column=2),
            detection_method="ast_parser",
            evidence="from cryptography.hazmat.primitives.asymmetric import rsa",
            confidence=0.98,
            quantum_status=QuantumStatus.VULNERABLE_SHOR,
            nist_replacement="ML-KEM (FIPS 203)",
        ),
        Artefact(
            scan_id=scan.id,
            type=ArtefactType.ALGORITHM,
            name="AES-256",
            mode="GCM",
            key_size=256,
            location=Location(file="src/cipher.py", line=40),
            detection_method="ast_parser",
            evidence="AES.new(key, AES.MODE_GCM)",
            confidence=1.0,
            quantum_status=QuantumStatus.QUANTUM_SAFE,
            nist_replacement="None needed",
        ),
    ]

    saved_count = test_db.save_artefacts(scan.id, artefacts)
    assert saved_count == 2

    # Verify scan total count updated
    updated_scan = test_db.get_scan(scan.id)
    assert updated_scan.total_artefacts == 2

    # Query all artefacts
    retrieved = test_db.get_artefacts(scan.id)
    assert len(retrieved) == 2

    # Query by quantum status filter
    vulnerable = test_db.get_artefacts(scan.id, quantum_filter="vulnerable_shor")
    assert len(vulnerable) == 1
    assert vulnerable[0].name == "RSA"

    safe = test_db.get_artefacts(scan.id, quantum_filter="quantum_safe")
    assert len(safe) == 1
    assert safe[0].name == "AES-256"


def test_scan_summary_aggregation(test_db):
    scan = test_db.create_scan("/project/repo")
    artefacts = [
        Artefact(
            scan_id=scan.id,
            type=ArtefactType.ALGORITHM,
            name="RSA",
            location="file1.py:1",
            detection_method="regex",
            quantum_status=QuantumStatus.VULNERABLE_SHOR,
        ),
        Artefact(
            scan_id=scan.id,
            type=ArtefactType.PROTOCOL,
            name="TLS 1.0",
            location="server.conf:10",
            detection_method="config_parser",
            quantum_status=QuantumStatus.CLASSICALLY_BROKEN,
        ),
        Artefact(
            scan_id=scan.id,
            type=ArtefactType.ALGORITHM,
            name="ML-KEM",
            location="crypto.py:20",
            detection_method="ast_parser",
            quantum_status=QuantumStatus.QUANTUM_SAFE,
        ),
    ]
    test_db.save_artefacts(scan.id, artefacts)

    summary = test_db.get_scan_summary(scan.id)
    assert summary["total_artefacts"] == 3
    assert summary["by_quantum_status"]["vulnerable_shor"] == 1
    assert summary["by_quantum_status"]["classically_broken"] == 1
    assert summary["by_quantum_status"]["quantum_safe"] == 1
    assert summary["by_type"]["algorithm"] == 2
    assert summary["by_type"]["protocol"] == 1


def test_update_status_and_delete(test_db):
    scan = test_db.create_scan("/test/path")
    assert scan.status == ScanStatus.PENDING

    updated = test_db.update_scan_status(scan.id, ScanStatus.COMPLETED)
    assert updated.status == ScanStatus.COMPLETED

    deleted = test_db.delete_scan(scan.id)
    assert deleted is True
    assert test_db.get_scan(scan.id) is None
