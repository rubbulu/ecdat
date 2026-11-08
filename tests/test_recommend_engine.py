import pytest
from backend.app.models.artefact import Artefact, ArtefactType, Location, QuantumStatus
from backend.app.recommend.engine import (
    EffortLevel,
    MigrationApproach,
    RecommendationEngine,
    generate_recommendations,
)


@pytest.fixture
def ecdh_artefact():
    return Artefact(
        type=ArtefactType.ALGORITHM,
        name="ECDH",
        key_size=256,
        location=Location(file="src/gateway/handshake.py", line=30),
        detection_method="ast_parser",
        quantum_status=QuantumStatus.VULNERABLE_SHOR,
    )


@pytest.fixture
def rsa_cert_artefact():
    return Artefact(
        type=ArtefactType.CERTIFICATE,
        name="RSA",
        key_size=2048,
        location=Location(file="certs/root_ca.pem", line=1),
        detection_method="x509_parser",
        quantum_status=QuantumStatus.VULNERABLE_SHOR,
        metadata={"self_signed": True},
    )


@pytest.fixture
def ecdsa_token_artefact():
    return Artefact(
        type=ArtefactType.ALGORITHM,
        name="ECDSA",
        key_size=256,
        location=Location(file="src/auth/jwt.py", line=15),
        detection_method="ast_parser",
        quantum_status=QuantumStatus.VULNERABLE_SHOR,
    )


@pytest.fixture
def aes128_artefact():
    return Artefact(
        type=ArtefactType.ALGORITHM,
        name="AES-128",
        key_size=128,
        mode="CBC",
        location=Location(file="src/db/storage.py", line=55),
        detection_method="regex_rule",
        quantum_status=QuantumStatus.WEAKENED_GROVER,
    )


@pytest.fixture
def des_artefact():
    return Artefact(
        type=ArtefactType.ALGORITHM,
        name="3DES",
        location=Location(file="legacy/pay.py", line=10),
        detection_method="regex_rule",
        quantum_status=QuantumStatus.CLASSICALLY_BROKEN,
    )


@pytest.fixture
def md5_artefact():
    return Artefact(
        type=ArtefactType.ALGORITHM,
        name="MD5",
        location=Location(file="src/hash.py", line=8),
        detection_method="ast_parser",
        quantum_status=QuantumStatus.CLASSICALLY_BROKEN,
    )


@pytest.fixture
def tls10_artefact():
    return Artefact(
        type=ArtefactType.PROTOCOL,
        name="TLS 1.0",
        location=Location(file="nginx.conf", line=12),
        detection_method="config_directive",
        quantum_status=QuantumStatus.CLASSICALLY_BROKEN,
    )


def test_key_exchange_recommendation(ecdh_artefact):
    rec = RecommendationEngine.recommend_for_artefact(ecdh_artefact)

    assert "ML-KEM" in rec.replacement
    assert "X25519MLKEM768" in rec.replacement
    assert rec.migration_effort == EffortLevel.MEDIUM
    assert rec.hybrid_vs_pure == MigrationApproach.HYBRID
    assert "1,184 bytes" in rec.size_impact
    assert any("OpenSSL" in lib for lib in rec.library_suggestion)
    assert any("liboqs" in lib for lib in rec.library_suggestion)


def test_root_signature_recommendation(rsa_cert_artefact):
    # Root CA with self-signed flag -> long-lived trust anchor -> recommends SLH-DSA / ML-DSA
    rec = RecommendationEngine.recommend_for_artefact(rsa_cert_artefact)

    assert "SLH-DSA" in rec.replacement or "ML-DSA" in rec.replacement
    assert rec.migration_effort == EffortLevel.HIGH
    assert rec.hybrid_vs_pure == MigrationApproach.HYBRID
    assert "hash-based" in rec.performance_note.lower()


def test_general_signature_recommendation(ecdsa_token_artefact):
    rec = RecommendationEngine.recommend_for_artefact(ecdsa_token_artefact)

    assert "ML-DSA-65" in rec.replacement
    assert "3,309 bytes" in rec.size_impact
    assert rec.migration_effort == EffortLevel.MEDIUM


def test_symmetric_and_hash_recommendations(aes128_artefact, des_artefact, md5_artefact):
    # AES-128 -> AES-256
    rec_aes = RecommendationEngine.recommend_for_artefact(aes128_artefact)
    assert "AES-256" in rec_aes.replacement
    assert rec_aes.migration_effort == EffortLevel.LOW
    assert rec_aes.hybrid_vs_pure == MigrationApproach.CLASSICAL_UPGRADE

    # 3DES -> AES-256-GCM
    rec_des = RecommendationEngine.recommend_for_artefact(des_artefact)
    assert "AES-256-GCM" in rec_des.replacement
    assert rec_des.hybrid_vs_pure == MigrationApproach.CLASSICAL_UPGRADE

    # MD5 -> SHA-256
    rec_md5 = RecommendationEngine.recommend_for_artefact(md5_artefact)
    assert "SHA-256" in rec_md5.replacement
    assert rec_md5.migration_effort == EffortLevel.LOW


def test_tls_recommendation(tls10_artefact):
    rec = RecommendationEngine.recommend_for_artefact(tls10_artefact)
    assert "TLS 1.3" in rec.replacement
    assert "Hybrid" in rec.replacement
    assert rec.hybrid_vs_pure == MigrationApproach.HYBRID


def test_recommendation_ranking_urgency(
    des_artefact,
    ecdh_artefact,
    aes128_artefact,
    tls10_artefact,
):
    artefacts = [aes128_artefact, ecdh_artefact, des_artefact, tls10_artefact]
    recommendations = generate_recommendations(artefacts, y=3.0, z=12.0)

    assert len(recommendations) == 4
    # Recommendations must be ranked strictly descending by risk_score
    scores = [r.risk_score for r in recommendations]
    assert scores == sorted(scores, reverse=True)

    # Classically broken (3DES / TLS 1.0) must be ranked above low-urgency AES-128
    first_two_names = [recommendations[0].artefact_name, recommendations[1].artefact_name]
    assert "3DES" in first_two_names or "TLS 1.0" in first_two_names
