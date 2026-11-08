import json
from pathlib import Path
import pytest
from backend.app.models.artefact import ArtefactType, QuantumStatus
from backend.app.scanners.base import ScannerRegistry
from backend.app.scanners.certificate_scanner import CertificateScanner
from backend.app.scanners.config_scanner import ConfigScanner
from backend.app.scanners.dependency_scanner import DependencyScanner
from backend.app.scanners.source_scanner import SourceScanner


@pytest.fixture
def vulnerable_dir():
    return Path(__file__).resolve().parent.parent / "sample_targets" / "vulnerable_app"


def test_certificate_scanner(vulnerable_dir):
    scanner = CertificateScanner()
    cert_file = vulnerable_dir / "server.crt"
    artefacts = scanner.scan(cert_file)

    assert len(artefacts) == 1
    cert_art = artefacts[0]
    assert cert_art.type == ArtefactType.CERTIFICATE
    assert cert_art.name == "RSA"
    assert cert_art.key_size == 2048
    assert cert_art.quantum_status == QuantumStatus.VULNERABLE_SHOR

    meta = cert_art.metadata
    assert "vulnerable-internal.corp" in meta["subject"]
    assert meta["self_signed"] is True
    assert "sha256" in meta["signature_algorithm"].lower()
    assert meta["days_until_expiry"] > 0


def test_dependency_scanner_python(vulnerable_dir):
    scanner = DependencyScanner()
    req_file = vulnerable_dir / "requirements.txt"
    artefacts = scanner.scan(req_file)

    names = {a.name for a in artefacts}
    assert "pycrypto" in names
    assert "cryptography" in names
    assert "pyOpenSSL" in names

    pycrypto_hit = next(a for a in artefacts if a.name == "pycrypto")
    assert pycrypto_hit.version == "2.6.1"
    assert pycrypto_hit.metadata["is_deprecated"] is True
    assert "Critical" in pycrypto_hit.notes


def test_dependency_scanner_node(vulnerable_dir):
    scanner = DependencyScanner()
    pkg_file = vulnerable_dir / "package.json"
    artefacts = scanner.scan(pkg_file)

    names = {a.name for a in artefacts}
    assert "crypto-js" in names
    assert "node-forge" in names

    crypto_js_hit = next(a for a in artefacts if a.name == "crypto-js")
    assert crypto_js_hit.metadata["is_deprecated"] is True


def test_dependency_scanner_java_and_go(vulnerable_dir):
    scanner = DependencyScanner()
    pom_file = vulnerable_dir / "pom.xml"
    pom_artefacts = scanner.scan(pom_file)

    assert any(a.name == "bouncycastle" for a in pom_artefacts)
    bc_hit = next(a for a in pom_artefacts if a.name == "bouncycastle")
    assert bc_hit.version == "1.60"

    go_file = vulnerable_dir / "go.mod"
    go_artefacts = scanner.scan(go_file)
    assert any("crypto" in a.name for a in go_artefacts)


def test_config_scanner_nginx(vulnerable_dir):
    scanner = ConfigScanner()
    nginx_file = vulnerable_dir / "nginx.conf"
    artefacts = scanner.scan(nginx_file)

    names = {a.name for a in artefacts}
    assert "TLS 1.0" in names
    assert "TLS 1.1" in names
    assert "RC4" in names
    assert "3DES" in names


def test_config_scanner_sshd_and_env(vulnerable_dir):
    scanner = ConfigScanner()
    sshd_file = vulnerable_dir / "sshd_config"
    sshd_artefacts = scanner.scan(sshd_file)

    names = {a.name for a in sshd_artefacts}
    assert "DH" in names
    assert "RSA" in names
    assert "3DES" in names

    env_file = vulnerable_dir / ".env"
    env_artefacts = scanner.scan(env_file)
    env_names = {a.name for a in env_artefacts}
    assert "TLS 1.0" in env_names
    assert "RC4" in env_names


def test_unified_scan_recall_against_ground_truth(vulnerable_dir):
    # Ensure all scanners are registered
    ScannerRegistry.register(SourceScanner)
    ScannerRegistry.register(CertificateScanner)
    ScannerRegistry.register(DependencyScanner)
    ScannerRegistry.register(ConfigScanner)

    all_artefacts = ScannerRegistry.scan_all(vulnerable_dir)
    assert len(all_artefacts) >= 20

    # Load ground truth
    gt_file = vulnerable_dir / "ground_truth.json"
    with open(gt_file, "r", encoding="utf-8") as f:
        gt_data = json.load(f)

    gt_items = gt_data["artefacts"]
    matched = 0

    for gt in gt_items:
        gt_file = gt["file"]
        gt_name = gt["name"].upper()

        found = any(
            Path(a.location.file).name == gt_file
            and (gt_name in a.name.upper() or a.name.upper() in gt_name)
            for a in all_artefacts
        )
        if found:
            matched += 1

    recall = matched / len(gt_items)
    assert recall >= 0.85, f"Overall recall {recall:.2%} must be at least 85% (matched {matched}/{len(gt_items)})"
