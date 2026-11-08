import pytest
from backend.app.models.artefact import Artefact, ArtefactType, Location, QuantumStatus
from backend.app.risk.classifier import AssetClassifier, Criticality, LifetimeClass
from backend.app.risk.engine import RiskEngine, assess_scan_risk
from backend.app.risk.mosca import MoscaEngine


@pytest.fixture
def sample_rsa_artefact():
    return Artefact(
        type=ArtefactType.ALGORITHM,
        name="RSA",
        key_size=2048,
        location=Location(file="src/payment/encrypt.py", line=45),
        detection_method="ast_parser",
        quantum_status=QuantumStatus.VULNERABLE_SHOR,
        nist_replacement="ML-KEM (FIPS 203)",
    )


@pytest.fixture
def sample_mlkem_artefact():
    return Artefact(
        type=ArtefactType.ALGORITHM,
        name="ML-KEM",
        key_size=768,
        location=Location(file="src/auth/pqc.py", line=10),
        detection_method="ast_parser",
        quantum_status=QuantumStatus.QUANTUM_SAFE,
        nist_replacement="Standardized in NIST FIPS 203",
    )


@pytest.fixture
def sample_des_artefact():
    return Artefact(
        type=ArtefactType.ALGORITHM,
        name="DES",
        key_size=56,
        location=Location(file="legacy/crypto.py", line=100),
        detection_method="regex_rule",
        quantum_status=QuantumStatus.CLASSICALLY_BROKEN,
    )


def test_classifier_criticality_inference(sample_rsa_artefact):
    # 'src/payment/encrypt.py' has 'payment' keyword -> CRITICAL
    crit = AssetClassifier.infer_criticality(sample_rsa_artefact)
    assert crit == Criticality.CRITICAL

    # Test file path -> LOW
    test_art = Artefact(
        type=ArtefactType.ALGORITHM,
        name="AES",
        location=Location(file="tests/mock_crypto.py", line=5),
        detection_method="regex_rule",
    )
    assert AssetClassifier.infer_criticality(test_art) == Criticality.LOW

    # User override works
    assert AssetClassifier.infer_criticality(sample_rsa_artefact, override=Criticality.LOW) == Criticality.LOW


def test_classifier_lifetime_inference():
    session_art = Artefact(
        type=ArtefactType.KEY,
        name="session_token_key",
        location=Location(file="auth.py", line=10),
        detection_method="regex_rule",
        evidence="ephemeral session key",
    )
    assert AssetClassifier.infer_lifetime(session_art) == LifetimeClass.SHORT

    cert_art = Artefact(
        type=ArtefactType.CERTIFICATE,
        name="server_cert",
        location=Location(file="cert.pem", line=1),
        detection_method="x509_parser",
    )
    assert AssetClassifier.infer_lifetime(cert_art) == LifetimeClass.MEDIUM

    root_art = Artefact(
        type=ArtefactType.CERTIFICATE,
        name="root_ca",
        location=Location(file="root_ca.pem", line=1),
        detection_method="x509_parser",
        metadata={"self_signed": True},
    )
    assert AssetClassifier.infer_lifetime(root_art) == LifetimeClass.LONG


def test_mosca_inequality_at_risk_calculation(sample_rsa_artefact):
    # X=15 (long-term data), Y=3, Z=12 -> 15 + 3 = 18 > 12 -> AT RISK
    assessment = MoscaEngine.evaluate(sample_rsa_artefact, x_override=15.0, y=3.0, z=12.0)
    assert assessment.is_at_risk is True
    assert assessment.margin == 6.0
    assert assessment.risk_score >= 80.0
    assert assessment.risk_level == "critical"
    assert "RSA-2048 protects 15-year data; 15 + 3 > 12, so this is at risk from Shor's algorithm" in assessment.explanation


def test_mosca_inequality_safe_margin(sample_rsa_artefact):
    # Short-lived data: X=1, Y=2, Z=12 -> 1 + 2 = 3 <= 12 -> NOT AT RISK
    assessment = MoscaEngine.evaluate(sample_rsa_artefact, x_override=1.0, y=2.0, z=12.0)
    assert assessment.is_at_risk is False
    assert assessment.margin == -9.0
    assert assessment.risk_score < 70.0


def test_mosca_quantum_safe_algorithm(sample_mlkem_artefact):
    assessment = MoscaEngine.evaluate(sample_mlkem_artefact, x_override=20.0, y=3.0, z=12.0)
    assert assessment.is_at_risk is False
    assert assessment.risk_score <= 25.0
    assert "quantum-safe" in assessment.explanation


def test_mosca_classically_broken_algorithm(sample_des_artefact):
    assessment = MoscaEngine.evaluate(sample_des_artefact)
    assert assessment.is_at_risk is True
    assert assessment.risk_score >= 80.0
    assert "classically broken" in assessment.explanation


def test_risk_summary_aggregation(sample_rsa_artefact, sample_mlkem_artefact, sample_des_artefact):
    artefacts = [sample_rsa_artefact, sample_mlkem_artefact, sample_des_artefact]
    # Set X=15 for RSA artefact via overrides
    overrides = {sample_rsa_artefact.id: {"x": 15.0}}
    summary = assess_scan_risk(artefacts, y=3.0, z=12.0, overrides=overrides)

    assert summary.total_artefacts == 3
    assert summary.at_risk_count == 2  # RSA (X=15, 15+3 > 12) and DES (classically broken)
    assert summary.quantum_vulnerable_count == 1  # RSA is Shor-vulnerable
    assert summary.percent_quantum_vulnerable == 33.3

    assert len(summary.top_riskiest) == 3
    # Riskiest must be first
    assert summary.top_riskiest[0].risk_score >= summary.top_riskiest[1].risk_score >= summary.top_riskiest[2].risk_score
    assert summary.counts_by_risk_level["critical"] >= 1
