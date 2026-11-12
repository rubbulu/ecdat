from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.main import app, _run_scan_job
from backend.app.storage.db import db
from backend.app.models.artefact import ScanStatus

client = TestClient(app)

SAMPLE_TARGET_DIR = Path(__file__).resolve().parent.parent / "sample_targets" / "vulnerable_app"


@pytest.fixture
def scanned_app():
    """Create and immediately execute a scan on vulnerable_app for API testing."""
    scan = db.create_scan(target_path=str(SAMPLE_TARGET_DIR))
    _run_scan_job(scan.id, str(SAMPLE_TARGET_DIR))
    return scan.id


def test_health_check():
    root_resp = client.get("/")
    assert root_resp.status_code == 200
    assert root_resp.json()["docs"] == "/docs"

    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "ECDAT API"

    resp_api = client.get("/api/health")
    assert resp_api.status_code == 200
    assert resp_api.json()["status"] == "ok"


def test_catalogue_endpoint():
    response = client.get("/api/catalogue")
    assert response.status_code == 200
    data = response.json()
    assert "total_algorithms" in data
    assert data["total_algorithms"] >= 25
    assert len(data["algorithms"]) >= 25


def test_create_scan_local_path():
    response = client.post(
        "/api/scans",
        json={"local_path": str(SAMPLE_TARGET_DIR)},
    )
    assert response.status_code == 202
    data = response.json()
    assert "id" in data
    assert data["status"] in {"pending", "running", "completed"}
    assert "message" in data


def test_create_scan_nonexistent_local_path():
    response = client.post(
        "/api/scans",
        json={"local_path": "C:/nonexistent/invalid/path/12345"},
    )
    assert response.status_code == 400
    assert "does not exist" in response.json()["detail"]


def test_create_scan_empty_payload():
    response = client.post("/api/scans", json={})
    assert response.status_code == 400
    assert "Must provide exactly one scan target" in response.json()["detail"]


def test_create_scan_zip_upload():
    # Build in-memory zip
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("test_crypto.py", "import hashlib\nh = hashlib.md5(b'test').hexdigest()\n")
    zip_bytes = zip_buffer.getvalue()

    response = client.post(
        "/api/scans",
        files={"file": ("test.zip", zip_bytes, "application/zip")},
    )
    assert response.status_code == 202
    data = response.json()
    assert "id" in data
    assert data["metadata"]["source_type"] == "zip_upload"


def test_create_scan_zip_slip_rejection():
    # Construct a malicious zip with directory traversal
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("../../evil.py", "print('malicious')\n")
    zip_bytes = zip_buffer.getvalue()

    response = client.post(
        "/api/scans",
        files={"file": ("malicious.zip", zip_bytes, "application/zip")},
    )
    assert response.status_code == 400
    assert "Zip-slip" in response.json()["detail"]


def test_list_scans(scanned_app):
    response = client.get("/api/scans")
    assert response.status_code == 200
    scans = response.json()
    assert isinstance(scans, list)
    assert any(s["id"] == scanned_app for s in scans)


def test_get_scan_by_id(scanned_app):
    response = client.get(f"/api/scans/{scanned_app}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == scanned_app
    assert data["status"] == "completed"
    assert data["total_artefacts"] > 0


def test_get_scan_not_found():
    response = client.get("/api/scans/non-existent-uuid-9999")
    assert response.status_code == 404


def test_get_scan_artefacts_with_filtering_and_pagination(scanned_app):
    # Unfiltered
    response = client.get(f"/api/scans/{scanned_app}/artefacts?limit=10&offset=0")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] > 0
    assert len(data["items"]) <= 10
    item = data["items"][0]
    assert "artefact" in item
    assert "risk" in item
    assert "recommendation" in item

    # Filter by type
    resp_type = client.get(f"/api/scans/{scanned_app}/artefacts?type=algorithm")
    assert resp_type.status_code == 200
    for it in resp_type.json()["items"]:
        assert it["artefact"]["type"] == "algorithm"

    # Filter by is_at_risk
    resp_at_risk = client.get(f"/api/scans/{scanned_app}/artefacts?is_at_risk=true")
    assert resp_at_risk.status_code == 200
    for it in resp_at_risk.json()["items"]:
        assert it["risk"]["is_at_risk"] is True


def test_get_scan_summary(scanned_app):
    response = client.get(f"/api/scans/{scanned_app}/summary")
    assert response.status_code == 200
    summary = response.json()
    assert summary["scan_id"] == scanned_app
    assert summary["total_artefacts"] > 0
    assert summary["at_risk_count"] > 0
    assert "counts_by_risk_level" in summary
    assert "counts_by_algorithm" in summary
    assert "RSA" in summary["counts_by_algorithm"]
    assert "top_10_riskiest" in summary
    assert len(summary["top_10_riskiest"]) <= 10
    assert "mosca_parameters" in summary


def test_override_artefact_posture(scanned_app):
    # Fetch an artefact
    resp = client.get(f"/api/scans/{scanned_app}/artefacts?limit=1")
    art_id = resp.json()["items"][0]["artefact"]["id"]

    # Perform override
    override_payload = {
        "lifetime": "long",
        "criticality": "critical",
        "x": 20.0,
    }
    put_resp = client.put(f"/api/artefacts/{art_id}/override", json=override_payload)
    assert put_resp.status_code == 200
    updated_data = put_resp.json()
    assert updated_data["risk"]["lifetime_class"] == "long"
    assert updated_data["risk"]["criticality"] == "critical"
    assert updated_data["risk"]["x"] == 20.0

    # Test invalid override
    bad_resp = client.put(f"/api/artefacts/{art_id}/override", json={"lifetime": "infinite"})
    assert bad_resp.status_code == 400


def test_update_scan_mosca_parameters(scanned_app):
    payload = {"y": 6.0, "z": 8.0}
    response = client.put(f"/api/scans/{scanned_app}/mosca", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["mosca_parameters"]["y"] == 6.0
    assert data["mosca_parameters"]["z"] == 8.0
    assert "summary" in data


def test_export_endpoints(scanned_app):
    # 1. CBOM JSON
    resp_cbom = client.get(f"/api/scans/{scanned_app}/export?format=cbom")
    assert resp_cbom.status_code == 200
    assert resp_cbom.headers["content-type"] == "application/json"
    cbom_data = resp_cbom.json()
    assert cbom_data["bomFormat"] == "CycloneDX"
    assert cbom_data["specVersion"] == "1.6"

    # 2. HTML Report
    resp_html = client.get(f"/api/scans/{scanned_app}/export?format=html")
    assert resp_html.status_code == 200
    assert "text/html" in resp_html.headers["content-type"]
    assert "<!DOCTYPE html>" in resp_html.text

    # 3. PDF Report
    resp_pdf = client.get(f"/api/scans/{scanned_app}/export?format=pdf")
    assert resp_pdf.status_code == 200
    assert "application/pdf" in resp_pdf.headers["content-type"]
    assert resp_pdf.content.startswith(b"%PDF")

    # 4. CSV Report
    resp_csv = client.get(f"/api/scans/{scanned_app}/export?format=csv")
    assert resp_csv.status_code == 200
    assert "text/csv" in resp_csv.headers["content-type"]
    assert "id,name,type" in resp_csv.text

    # 5. Unsupported format
    resp_bad = client.get(f"/api/scans/{scanned_app}/export?format=docx")
    assert resp_bad.status_code == 400


def test_cors_origins_env_parsing(monkeypatch):
    from backend.main import _parse_allowed_origins

    # Default when env vars unset
    monkeypatch.delenv("ALLOWED_ORIGINS", raising=False)
    monkeypatch.delenv("CORS_ORIGINS", raising=False)
    origins, creds = _parse_allowed_origins()
    assert origins == ["*"]
    assert creds is False

    # Configured Vercel URL (with trailing slash and spaces)
    monkeypatch.setenv("ALLOWED_ORIGINS", " https://ecdat-demo.vercel.app/ , https://preview.vercel.app ")
    origins, creds = _parse_allowed_origins()
    assert "https://ecdat-demo.vercel.app" in origins
    assert "https://preview.vercel.app" in origins
    assert "http://localhost:5173" in origins
    assert creds is True
