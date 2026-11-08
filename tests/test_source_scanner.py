import json
from pathlib import Path
import pytest
from backend.app.models.artefact import ArtefactType, QuantumStatus
from backend.app.scanners.source_scanner import SourceScanner


@pytest.fixture
def scanner():
    return SourceScanner()


@pytest.fixture
def vulnerable_dir():
    return Path(__file__).resolve().parent.parent / "sample_targets" / "vulnerable_app"


def test_rules_loading(scanner):
    assert len(scanner.rules) > 10, "Rules should load successfully from rules.yaml"


def test_scan_python_vulnerable_app(scanner, vulnerable_dir):
    app_file = vulnerable_dir / "app.py"
    artefacts = scanner.scan(app_file)
    assert len(artefacts) >= 6

    names = {a.name for a in artefacts}
    assert "MD5" in names
    assert "SHA-1" in names or "SHA1" in names
    assert any("AES" in a.name for a in artefacts)
    assert "RSA" in names
    assert "ECDSA" in names

    # Verify key size extraction on RSA
    rsa_hit = next(a for a in artefacts if a.name == "RSA")
    assert rsa_hit.key_size == 1024
    assert rsa_hit.quantum_status == QuantumStatus.VULNERABLE_SHOR

    # Verify mode on AES
    aes_hit = next(a for a in artefacts if "AES" in a.name)
    assert aes_hit.mode == "ECB"


def test_scan_js_vulnerable_app(scanner, vulnerable_dir):
    js_file = vulnerable_dir / "index.js"
    artefacts = scanner.scan(js_file)
    assert len(artefacts) >= 3

    names = {a.name for a in artefacts}
    assert "MD5" in names
    assert "aes-128-cbc" in names or "AES-128" in names
    assert "RSA" in names or "rsa" in names

    # Verify key size on RSA
    rsa_hit = next(a for a in artefacts if "RSA" in a.name.upper())
    assert rsa_hit.key_size == 2048


def test_scan_java_vulnerable_app(scanner, vulnerable_dir):
    java_file = vulnerable_dir / "CryptoService.java"
    artefacts = scanner.scan(java_file)
    assert len(artefacts) >= 4

    names = {a.name for a in artefacts}
    assert "RSA" in names
    assert "DSA" in names
    assert "SHA-1" in names or "SHA1" in names
    assert "DES" in names

    # Verify mode extraction on DES
    des_hits = [a for a in artefacts if a.name == "DES"]
    assert len(des_hits) >= 1
    assert any(a.mode == "CBC" for a in des_hits)
    assert any(a.quantum_status == QuantumStatus.CLASSICALLY_BROKEN for a in des_hits)


def test_ground_truth_recall(scanner, vulnerable_dir):
    ground_truth_file = vulnerable_dir / "ground_truth.json"
    with open(ground_truth_file, "r", encoding="utf-8") as f:
        gt_data = json.load(f)

    discovered = scanner.scan(vulnerable_dir)
    assert len(discovered) > 0

    # SourceScanner specifically benchmarks against source code files (.py, .js, .java)
    source_exts = {".py", ".js", ".java"}
    gt_artefacts = [gt for gt in gt_data["artefacts"] if Path(gt["file"]).suffix.lower() in source_exts]

    matched_gt = 0
    for gt in gt_artefacts:
        gt_file = gt["file"]
        gt_name = gt["name"].upper()

        found = any(
            Path(d.location.file).name == gt_file
            and (gt_name in d.name.upper() or d.name.upper() in gt_name)
            for d in discovered
        )
        if found:
            matched_gt += 1

    recall = matched_gt / len(gt_artefacts)
    assert recall >= 0.85, f"Recall {recall:.2%} must be at least 85% (matched {matched_gt}/{len(gt_artefacts)})"


def test_directory_skipping(scanner, tmp_path):
    # Create fake structure with node_modules and .git
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "crypto.py").write_text("import hashlib\nhashlib.md5(b'test')")

    node_modules = tmp_path / "node_modules"
    node_modules.mkdir()
    (node_modules / "dep.py").write_text("import hashlib\nhashlib.md5(b'ignored')")

    discovered = scanner.scan(tmp_path)
    # Should only scan src/crypto.py, NOT node_modules
    files_scanned = [Path(a.location.file).name for a in discovered]
    assert "crypto.py" in files_scanned
    assert "dep.py" not in files_scanned
