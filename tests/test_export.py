import csv
import io
import json
from pathlib import Path
import pytest

from backend.app.export.cbom_cyclonedx import export_cbom_json
from backend.app.export.report_csv import CSVReportGenerator
from backend.app.export.report_html import HTMLReportGenerator
from backend.app.export.report_pdf import PDFReportGenerator
from backend.app.models.artefact import Artefact, ArtefactType, Location, QuantumStatus
from backend.app.recommend.engine import generate_recommendations
from backend.app.risk.engine import assess_scan_risk


@pytest.fixture
def mock_artefacts():
    return [
        Artefact(
            type=ArtefactType.ALGORITHM,
            name="RSA",
            key_size=2048,
            location=Location(file="src/auth.py", line=12),
            detection_method="ast_parser",
            quantum_status=QuantumStatus.VULNERABLE_SHOR,
            nist_replacement="ML-KEM-768",
        ),
        Artefact(
            type=ArtefactType.CERTIFICATE,
            name="RSA",
            key_size=2048,
            location=Location(file="certs/server.crt", line=1),
            detection_method="x509_parser",
            quantum_status=QuantumStatus.VULNERABLE_SHOR,
            metadata={"subject": "CN=test.internal", "issuer": "CN=test.internal", "self_signed": True},
        ),
        Artefact(
            type=ArtefactType.PROTOCOL,
            name="TLS 1.0",
            location=Location(file="nginx.conf", line=5),
            detection_method="config_directive",
            quantum_status=QuantumStatus.CLASSICALLY_BROKEN,
        ),
        Artefact(
            type=ArtefactType.KEY,
            name="Hardcoded Secret Key",
            location=Location(file="app.py", line=8),
            detection_method="regex_rule",
            evidence="secret_key = 'abcdef123456...'",
        ),
    ]


def test_cbom_cyclonedx_export_structure(mock_artefacts):
    cbom_json = export_cbom_json(mock_artefacts, target_name="TestApp")
    cbom_data = json.loads(cbom_json)

    assert cbom_data["bomFormat"] == "CycloneDX"
    assert cbom_data["specVersion"] == "1.6"
    assert "serialNumber" in cbom_data
    assert cbom_data["metadata"]["component"]["name"] == "TestApp"

    components = cbom_data["components"]
    assert len(components) == len(mock_artefacts)

    for comp in components:
        assert comp["type"] == "cryptographic-asset"
        assert "cryptoProperties" in comp
        assert comp["cryptoProperties"]["assetType"] in {
            "algorithm",
            "certificate",
            "protocol",
            "related-crypto-material",
        }
        # Verify custom ecdat properties
        prop_names = {p["name"] for p in comp.get("properties", [])}
        assert "ecdat:quantum_status" in prop_names
        assert "ecdat:risk_score" in prop_names


def test_html_report_export(mock_artefacts, tmp_path):
    summary = assess_scan_risk(mock_artefacts)
    recommendations = generate_recommendations(mock_artefacts)

    out_file = tmp_path / "report.html"
    html_content = HTMLReportGenerator.generate_html(
        artefacts=mock_artefacts,
        summary=summary,
        recommendations=recommendations,
        target_name="TestApp",
        output_path=out_file,
    )

    assert "<!DOCTYPE html>" in html_content
    assert "ECDAT Quantum Cryptographic Risk Report" in html_content
    assert "Mosca's Theorem" in html_content
    assert "ML-KEM" in html_content
    assert out_file.exists()


def test_pdf_report_export(mock_artefacts, tmp_path):
    summary = assess_scan_risk(mock_artefacts)
    recommendations = generate_recommendations(mock_artefacts)

    out_file = tmp_path / "report.pdf"
    pdf_bytes = PDFReportGenerator.generate_pdf(
        artefacts=mock_artefacts,
        summary=summary,
        recommendations=recommendations,
        target_name="TestApp",
        output_path=out_file,
    )

    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 1000
    assert out_file.exists()


def test_csv_report_export(mock_artefacts, tmp_path):
    out_file = tmp_path / "artefacts.csv"
    csv_str = CSVReportGenerator.generate_csv(mock_artefacts, output_path=out_file)

    reader = csv.DictReader(io.StringIO(csv_str))
    rows = list(reader)

    assert len(rows) == len(mock_artefacts)
    assert "id" in reader.fieldnames
    assert "quantum_status" in reader.fieldnames
    assert "risk_score" in reader.fieldnames
    assert "is_at_risk" in reader.fieldnames
    assert out_file.exists()


def test_sample_output_files_exist():
    out_dir = Path("docs/sample_output")
    assert (out_dir / "cbom.json").exists()
    assert (out_dir / "report.html").exists()
    assert (out_dir / "report.pdf").exists()
    assert (out_dir / "artefacts.csv").exists()

    # Validate cbom.json content in sample_output
    cbom_data = json.loads((out_dir / "cbom.json").read_text(encoding="utf-8"))
    assert cbom_data["specVersion"] == "1.6"
    assert len(cbom_data["components"]) > 10
