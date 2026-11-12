from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from fastapi import (
    BackgroundTasks,
    FastAPI,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

# Application imports
from backend.app.models.artefact import (
    Artefact,
    ArtefactType,
    QuantumStatus,
    Scan,
    ScanStatus,
)
from backend.app.storage.db import db
from backend.app.scanners.base import ScannerRegistry
# Ensure all scanners are registered
import backend.app.scanners  # noqa: F401
from backend.app.services.catalogue_service import catalogue_service
from backend.app.risk.classifier import Criticality, LifetimeClass
from backend.app.risk.mosca import MoscaAssessment, MoscaEngine
from backend.app.risk.engine import RiskEngine, RiskSummary, assess_scan_risk
from backend.app.recommend.engine import (
    Recommendation,
    RecommendationEngine,
    generate_recommendations,
)
from backend.app.export.cbom_cyclonedx import CycloneDX16CBOMBuilder
from backend.app.export.report_html import HTMLReportGenerator
from backend.app.export.report_pdf import PDFReportGenerator
from backend.app.export.report_csv import CSVReportGenerator

logger = logging.getLogger("ecdat.api")
logging.basicConfig(level=logging.INFO)

# Maximum upload file size: 50 MB
MAX_UPLOAD_SIZE = 50 * 1024 * 1024

app = FastAPI(
    title="ECDAT - Enterprise Cryptographic Discovery & Analysis Tool",
    description=(
        "Enterprise discovery engine for cryptographic assets, post-quantum risk modeling "
        "(Mosca's Inequality X + Y > Z), CycloneDX 1.6 CBOM generation, and NIST PQC migration advisory."
    ),
    version="1.0.0",
)

def _parse_allowed_origins() -> tuple[List[str], bool]:
    """
    Parse comma-separated CORS origins from ALLOWED_ORIGINS (or CORS_ORIGINS).
    Returns (origins, allow_credentials).
    """
    raw = (os.getenv("ALLOWED_ORIGINS") or os.getenv("CORS_ORIGINS") or "").strip()
    if not raw:
        return ["*"], False

    origins: List[str] = []
    for item in raw.split(","):
        cleaned = item.strip().rstrip("/")
        if cleaned:
            origins.append(cleaned)

    if "*" in origins or not origins:
        return ["*"], False

    for local_origin in (
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ):
        if local_origin not in origins:
            origins.append(local_origin)

    return origins, True


_cors_origins, _cors_credentials = _parse_allowed_origins()

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=_cors_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request & Response Schemas
# ---------------------------------------------------------------------------

class ScanCreateRequest(BaseModel):
    local_path: Optional[str] = Field(None, description="Local absolute or relative path to target folder or file")
    git_url: Optional[str] = Field(None, description="Remote Git repository URL to clone and scan")


class ArtefactOverrideRequest(BaseModel):
    lifetime: Optional[str] = Field(None, description="Override lifetime: 'short' (<2y), 'medium' (2-10y), 'long' (>10y)")
    criticality: Optional[str] = Field(None, description="Override criticality: 'low', 'medium', 'high', 'critical'")
    x: Optional[float] = Field(None, ge=0.0, description="Override confidentiality shelf-life in years")


class MoscaUpdateRequest(BaseModel):
    x: Optional[float] = Field(None, ge=0.0, description="Default confidentiality shelf life (years)")
    y: Optional[float] = Field(None, ge=0.0, description="Migration timeline (years)")
    z: Optional[float] = Field(None, ge=0.1, description="Years until cryptanalytically relevant quantum computer (CRQC)")


# ---------------------------------------------------------------------------
# Background Scan Worker
# ---------------------------------------------------------------------------

def _run_scan_job(scan_id: str, target_path: str, temp_dir: Optional[str] = None) -> None:
    """
    Synchronous scanning job executed in background thread pool.
    Orchestrates all scanners, enriches artefacts, persists to DB,
    and safely cleans up temporary extraction folders.
    """
    logger.info(f"Starting background scan job for scan_id: {scan_id} on {target_path}")
    try:
        db.update_scan_status(scan_id, ScanStatus.RUNNING)

        # Execute all registered scanners
        discovered_artefacts = ScannerRegistry.scan_all(target_path)
        logger.info(f"Discovered {len(discovered_artefacts)} artefacts for scan {scan_id}")

        # Associate each artefact with this scan
        for art in discovered_artefacts:
            art.scan_id = scan_id

        # Persist artefacts to SQLite
        db.save_artefacts(scan_id, discovered_artefacts)

        # Retrieve any scan-level Mosca parameters
        scan = db.get_scan(scan_id)
        mosca_meta = (scan.metadata or {}).get("mosca", {}) if scan else {}
        y = float(mosca_meta.get("y", 3.0))
        z = float(mosca_meta.get("z", 12.0))

        # Perform initial risk assessment
        summary = assess_scan_risk(discovered_artefacts, y=y, z=z)

        # Update scan status to COMPLETED with summary metrics in metadata
        scan_meta = scan.metadata if scan else {}
        scan_meta["summary"] = {
            "total_artefacts": summary.total_artefacts,
            "at_risk_count": summary.at_risk_count,
            "quantum_vulnerable_count": summary.quantum_vulnerable_count,
            "percent_quantum_vulnerable": summary.percent_quantum_vulnerable,
            "counts_by_risk_level": summary.counts_by_risk_level,
        }
        db.update_scan_metadata(scan_id, scan_meta)
        db.update_scan_status(
            scan_id,
            ScanStatus.COMPLETED,
            completed_at=datetime.now(timezone.utc),
            total_artefacts=len(discovered_artefacts),
        )
        logger.info(f"Completed scan job {scan_id} successfully.")

    except Exception as exc:
        logger.exception(f"Scan job {scan_id} encountered an error: {exc}")
        scan = db.get_scan(scan_id)
        scan_meta = scan.metadata if scan else {}
        scan_meta["error"] = str(exc)
        db.update_scan_metadata(scan_id, scan_meta)
        db.update_scan_status(scan_id, ScanStatus.FAILED, completed_at=datetime.now(timezone.utc))

    finally:
        # Guarantee cleanup of temporary zip or git clone folders
        if temp_dir and Path(temp_dir).exists():
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
                logger.info(f"Safely cleaned up temporary directory: {temp_dir}")
            except Exception as e:
                logger.warning(f"Failed to remove temp dir {temp_dir}: {e}")


# ---------------------------------------------------------------------------
# Security Helpers: Zip-Slip Protection & Git Validation
# ---------------------------------------------------------------------------

def _extract_zip_safely(zip_bytes: bytes, destination_dir: Path) -> Path:
    """
    Extracts a zip file with strict Zip-Slip path traversal protection.
    Ensures every extracted file path resides strictly inside destination_dir.
    """
    dest_resolved = destination_dir.resolve()
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for member in zf.infolist():
            # Check for illegal leading slashes or parent traversals
            filename = member.filename
            if filename.startswith("/") or filename.startswith("\\"):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Zip-slip attack detected: illegal absolute member path '{filename}'",
                )
            parts = Path(filename).parts
            if ".." in parts:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Zip-slip attack detected: illegal directory traversal in '{filename}'",
                )

            target_path = (destination_dir / filename).resolve()
            try:
                # Must be relative to destination_dir
                target_path.relative_to(dest_resolved)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Zip-slip path traversal attempt detected in '{filename}'",
                )

        # If all members are safe, perform extraction
        zf.extractall(path=destination_dir)

    return destination_dir


def _clone_git_repo_safely(git_url: str, destination_dir: Path) -> Path:
    """
    Clones a Git repository safely with shallow depth into destination_dir.
    """
    # URL validation: allow https://, http://, git@
    clean_url = git_url.strip()
    if not (clean_url.startswith("https://") or clean_url.startswith("http://") or clean_url.startswith("git@")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Git URL. Must start with http://, https://, or git@.",
        )
    # Check for shell metacharacters
    if re.search(r"[;&|`$<>]", clean_url):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Illegal characters detected in Git repository URL.",
        )

    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", clean_url, str(destination_dir)],
            check=True,
            capture_output=True,
            timeout=120,
            text=True,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=status.HTTP_408_REQUEST_TIMEOUT,
            detail="Git clone operation timed out after 120 seconds.",
        )
    except subprocess.CalledProcessError as exc:
        logger.error(f"Git clone failed: {exc.stderr}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to clone Git repository: {exc.stderr.strip()}",
        )
    return destination_dir


# ---------------------------------------------------------------------------
# REST Endpoints
# ---------------------------------------------------------------------------

@app.get("/", tags=["System"])
def root() -> Dict[str, str]:
    """Root service landing endpoint."""
    return {
        "service": "ECDAT API",
        "status": "ok",
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health", tags=["System"])
@app.get("/api/health", tags=["System"])
def health_check() -> Dict[str, Any]:
    """Service health and version status."""
    return {
        "status": "ok",
        "service": "ECDAT API",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/scans", status_code=status.HTTP_202_ACCEPTED, tags=["Scans"])
async def create_scan(
    request: Request,
    background_tasks: BackgroundTasks,
    file: Optional[UploadFile] = File(None),
    git_url: Optional[str] = Form(None),
    local_path: Optional[str] = Form(None),
) -> Dict[str, Any]:
    """
    Initiate a new cryptographic discovery scan.
    Accepts:
    1. A zipped codebase archive (`file` upload)
    2. A remote Git repository (`git_url`)
    3. A local filesystem directory or file (`local_path`)
    Can be submitted via multipart/form-data or application/json.
    """
    target_scan_path: Optional[str] = None
    temp_dir_to_clean: Optional[str] = None
    initial_metadata: Dict[str, Any] = {
        "mosca": {"x": 5.0, "y": 3.0, "z": 12.0},
    }

    content_type = request.headers.get("content-type", "")

    # Handle application/json payloads
    if "application/json" in content_type:
        try:
            body = await request.json()
            local_path = body.get("local_path")
            git_url = body.get("git_url")
        except Exception:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid JSON body")

    # Validate that at least one target was provided
    provided_inputs = [x for x in [file, git_url, local_path] if x]
    if not provided_inputs:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Must provide exactly one scan target: file upload, git_url, or local_path.",
        )

    # 1. Zip file upload
    if file is not None:
        file_bytes = await file.read()
        if len(file_bytes) > MAX_UPLOAD_SIZE:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Upload file exceeds maximum limit of {MAX_UPLOAD_SIZE // (1024 * 1024)}MB.",
            )
        if not file.filename.lower().endswith((".zip", ".tar", ".gz")):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file must be a .zip or archive file.",
            )

        temp_dir = tempfile.mkdtemp(prefix="ecdat_upload_")
        temp_dir_to_clean = temp_dir
        _extract_zip_safely(file_bytes, Path(temp_dir))
        target_scan_path = temp_dir
        initial_metadata["source_type"] = "zip_upload"
        initial_metadata["original_filename"] = file.filename

    # 2. Remote Git URL
    elif git_url:
        temp_dir = tempfile.mkdtemp(prefix="ecdat_git_")
        temp_dir_to_clean = temp_dir
        _clone_git_repo_safely(git_url, Path(temp_dir))
        target_scan_path = temp_dir
        initial_metadata["source_type"] = "git_repo"
        initial_metadata["git_url"] = git_url

    # 3. Local path
    elif local_path:
        p = Path(local_path).resolve()
        if not p.exists():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Target local path '{local_path}' does not exist on filesystem.",
            )
        target_scan_path = str(p)
        initial_metadata["source_type"] = "local_path"

    # Create scan record in database
    scan = db.create_scan(target_path=target_scan_path, metadata=initial_metadata)

    # Enqueue background scanning task
    background_tasks.add_task(
        _run_scan_job,
        scan_id=scan.id,
        target_path=target_scan_path,
        temp_dir=temp_dir_to_clean,
    )

    return {
        "id": scan.id,
        "status": scan.status.value,
        "target_path": scan.target_path,
        "created_at": scan.created_at.isoformat(),
        "metadata": scan.metadata,
        "message": "Cryptographic discovery scan scheduled in background.",
    }


@app.get("/api/scans", tags=["Scans"])
def list_scans() -> List[Dict[str, Any]]:
    """List all historical scans ordered by creation date descending."""
    scans = db.list_scans()
    return [
        {
            "id": s.id,
            "target_path": s.target_path,
            "status": s.status.value,
            "total_artefacts": s.total_artefacts,
            "created_at": s.created_at.isoformat(),
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "metadata": s.metadata,
        }
        for s in scans
    ]


@app.get("/api/scans/{scan_id}", tags=["Scans"])
def get_scan(scan_id: str) -> Dict[str, Any]:
    """Retrieve scan status, progress, and metadata by scan ID."""
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan '{scan_id}' not found.")
    return {
        "id": scan.id,
        "target_path": scan.target_path,
        "status": scan.status.value,
        "total_artefacts": scan.total_artefacts,
        "created_at": scan.created_at.isoformat(),
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "metadata": scan.metadata,
    }


@app.delete("/api/scans/{scan_id}", tags=["Scans"])
def delete_scan(scan_id: str) -> Dict[str, Any]:
    """Delete a scan and cascade delete all associated artefacts."""
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan '{scan_id}' not found.")
    db.delete_scan(scan_id)
    return {"message": f"Scan '{scan_id}' and all associated artefacts deleted successfully."}


@app.get("/api/scans/{scan_id}/artefacts", tags=["Artefacts"])
def get_scan_artefacts(
    scan_id: str,
    type: Optional[str] = Query(None, description="Filter by artefact type (algorithm, key, certificate, protocol, library)"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level (critical, high, medium, low)"),
    quantum_status: Optional[str] = Query(None, description="Filter by quantum status (vulnerable_shor, weakened_grover, etc.)"),
    scanner: Optional[str] = Query(None, description="Filter by scanner name or detection method"),
    is_at_risk: Optional[bool] = Query(None, description="Filter by Mosca inequality at-risk status"),
    limit: int = Query(50, ge=1, le=500, description="Pagination limit"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
) -> Dict[str, Any]:
    """
    Query discovered cryptographic artefacts for a given scan with multi-dimensional filters,
    composite risk scoring, and PQC migration recommendations.
    """
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan '{scan_id}' not found.")

    # Retrieve matching artefacts from DB
    raw_artefacts = db.get_artefacts(
        scan_id=scan_id,
        type_filter=type,
        quantum_filter=quantum_status,
        scanner_filter=scanner,
    )

    # Resolve scan Mosca parameters and per-artefact overrides
    mosca_meta = (scan.metadata or {}).get("mosca", {})
    y = float(mosca_meta.get("y", 3.0))
    z = float(mosca_meta.get("z", 12.0))
    default_x = float(mosca_meta.get("x", 5.0))

    enriched_items = []
    for art in raw_artefacts:
        art_overrides = (art.metadata or {}).get("overrides", {})
        x_val = art_overrides.get("x", default_x)
        lifetime_override = art_overrides.get("lifetime")
        criticality_override = art_overrides.get("criticality")

        assessment = MoscaEngine.evaluate(
            artefact=art,
            x_override=x_val,
            y=y,
            z=z,
            lifetime_override=lifetime_override,
            criticality_override=criticality_override,
        )

        # In-memory filter on risk_level
        if risk_level and assessment.risk_level.lower() != risk_level.lower():
            continue

        # In-memory filter on is_at_risk
        if is_at_risk is not None and assessment.is_at_risk != is_at_risk:
            continue

        # Generate recommendation
        rec = RecommendationEngine.recommend_for_artefact(art, assessment=assessment)

        enriched_items.append({
            "artefact": art.model_dump(),
            "risk": assessment.model_dump(),
            "recommendation": rec.model_dump(),
        })

    total_count = len(enriched_items)
    paginated_items = enriched_items[offset : offset + limit]

    return {
        "scan_id": scan_id,
        "total": total_count,
        "limit": limit,
        "offset": offset,
        "items": paginated_items,
    }


@app.get("/api/scans/{scan_id}/summary", tags=["Risk & Analytics"])
def get_scan_summary(scan_id: str) -> Dict[str, Any]:
    """
    Retrieve comprehensive risk posture summary:
    - Counts by risk level (Critical, High, Medium, Low)
    - Lifetime & business criticality breakdowns
    - Mosca inequality exposure metrics ($X + Y > Z$)
    - Top 10 riskiest cryptographic assets
    """
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan '{scan_id}' not found.")

    artefacts = db.get_artefacts(scan_id)
    mosca_meta = (scan.metadata or {}).get("mosca", {})
    y = float(mosca_meta.get("y", 3.0))
    z = float(mosca_meta.get("z", 12.0))
    default_x = float(mosca_meta.get("x", 5.0))
    x_custom = bool(mosca_meta.get("x_custom", False))

    # Build per-artefact overrides
    overrides: Dict[str, Dict[str, Any]] = {}
    algo_counts: Dict[str, int] = {}
    for art in artefacts:
        algo_counts[art.name] = algo_counts.get(art.name, 0) + 1
        art_ovr = dict((art.metadata or {}).get("overrides", {}))
        if x_custom and "x" not in art_ovr:
            art_ovr["x"] = default_x
        if art_ovr:
            overrides[art.id] = art_ovr

    sorted_algos = dict(sorted(algo_counts.items(), key=lambda kv: kv[1], reverse=True)[:10])

    summary = RiskEngine.assess_artefacts(
        artefacts,
        default_y=y,
        default_z=z,
        overrides=overrides,
    )

    return {
        "scan_id": scan.id,
        "target_path": scan.target_path,
        "status": scan.status.value,
        "total_artefacts": summary.total_artefacts,
        "at_risk_count": summary.at_risk_count,
        "quantum_vulnerable_count": summary.quantum_vulnerable_count,
        "percent_quantum_vulnerable": summary.percent_quantum_vulnerable,
        "counts_by_risk_level": summary.counts_by_risk_level,
        "counts_by_lifetime": summary.counts_by_lifetime,
        "counts_by_criticality": summary.counts_by_criticality,
        "counts_by_algorithm": sorted_algos,
        "top_10_riskiest": [a.model_dump() for a in summary.top_riskiest],
        "mosca_parameters": {
            "x_default": default_x,
            "y": y,
            "z": z,
        },
    }


@app.put("/api/artefacts/{artefact_id}/override", tags=["Artefacts"])
def override_artefact_posture(
    artefact_id: str,
    override: ArtefactOverrideRequest,
) -> Dict[str, Any]:
    """
    Override lifetime, criticality, or shelf-life for a specific artefact.
    Persists the override and immediately recalculates composite risk and PQC recommendations.
    """
    art = db.get_artefact(artefact_id)
    if not art:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Artefact '{artefact_id}' not found.")

    # Validate lifetime if provided
    if override.lifetime and override.lifetime.lower() not in {"short", "medium", "long"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Lifetime override must be one of: 'short', 'medium', 'long'.",
        )

    # Validate criticality if provided
    if override.criticality and override.criticality.lower() not in {"low", "medium", "high", "critical"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Criticality override must be one of: 'low', 'medium', 'high', 'critical'.",
        )

    # Update metadata
    existing_overrides = (art.metadata or {}).get("overrides", {})
    if override.lifetime is not None:
        existing_overrides["lifetime"] = override.lifetime.lower()
    if override.criticality is not None:
        existing_overrides["criticality"] = override.criticality.lower()
    if override.x is not None:
        existing_overrides["x"] = override.x

    updated_meta = {**art.metadata, "overrides": existing_overrides}
    updated_art = db.update_artefact_metadata(artefact_id, updated_meta)

    # Recalculate risk using scan Mosca params
    scan = db.get_scan(art.scan_id)
    mosca_meta = (scan.metadata or {}).get("mosca", {}) if scan else {}
    y = float(mosca_meta.get("y", 3.0))
    z = float(mosca_meta.get("z", 12.0))

    new_assessment = MoscaEngine.evaluate(
        artefact=updated_art,
        x_override=existing_overrides.get("x"),
        y=y,
        z=z,
        lifetime_override=existing_overrides.get("lifetime"),
        criticality_override=existing_overrides.get("criticality"),
    )
    new_recommendation = RecommendationEngine.recommend_for_artefact(updated_art, assessment=new_assessment)

    return {
        "message": f"Successfully updated risk overrides for artefact '{artefact_id}'.",
        "artefact": updated_art.model_dump(),
        "risk": new_assessment.model_dump(),
        "recommendation": new_recommendation.model_dump(),
    }


@app.put("/api/scans/{scan_id}/mosca", tags=["Risk & Analytics"])
def update_scan_mosca_parameters(
    scan_id: str,
    params: MoscaUpdateRequest,
) -> Dict[str, Any]:
    """
    Update Mosca's inequality parameters ($X$ shelf life, $Y$ migration years, $Z$ quantum horizon)
    for an entire scan and immediately recalculate risk exposure metrics.
    """
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan '{scan_id}' not found.")

    current_mosca = (scan.metadata or {}).get("mosca", {"x": 5.0, "y": 3.0, "z": 12.0})
    if params.x is not None:
        current_mosca["x"] = params.x
        current_mosca["x_custom"] = True
    if params.y is not None:
        current_mosca["y"] = params.y
    if params.z is not None:
        current_mosca["z"] = params.z

    updated_meta = {**scan.metadata, "mosca": current_mosca}
    db.update_scan_metadata(scan_id, updated_meta)

    # Recalculate summary with updated params
    artefacts = db.get_artefacts(scan_id)
    x_custom = bool(current_mosca.get("x_custom", False))
    default_x = float(current_mosca.get("x", 5.0))
    overrides: Dict[str, Dict[str, Any]] = {}
    for art in artefacts:
        art_ovr = dict((art.metadata or {}).get("overrides", {}))
        if x_custom and "x" not in art_ovr:
            art_ovr["x"] = default_x
        if art_ovr:
            overrides[art.id] = art_ovr

    summary = RiskEngine.assess_artefacts(
        artefacts,
        default_y=float(current_mosca["y"]),
        default_z=float(current_mosca["z"]),
        overrides=overrides,
    )

    return {
        "message": f"Updated Mosca parameters for scan '{scan_id}'.",
        "mosca_parameters": current_mosca,
        "summary": {
            "total_artefacts": summary.total_artefacts,
            "at_risk_count": summary.at_risk_count,
            "quantum_vulnerable_count": summary.quantum_vulnerable_count,
            "percent_quantum_vulnerable": summary.percent_quantum_vulnerable,
            "counts_by_risk_level": summary.counts_by_risk_level,
        },
    }


@app.get("/api/scans/{scan_id}/export", tags=["Export & Reporting"])
def export_scan_results(
    scan_id: str,
    format: str = Query(..., description="Export format: 'cbom', 'pdf', 'html', or 'csv'"),
) -> Response:
    """
    Export scan cryptographic discovery results into standard enterprise audit formats:
    - `cbom`: CycloneDX 1.6 Cryptographic Bill of Materials JSON
    - `pdf`: Printable executive cryptographic audit report
    - `html`: Interactive HTML scorecard with risk charts and recommendations
    - `csv`: Structured cryptographic asset spreadsheet
    """
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan '{scan_id}' not found.")

    fmt = format.lower().strip()
    if fmt not in {"cbom", "pdf", "html", "csv"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported export format '{format}'. Must be one of: cbom, pdf, html, csv.",
        )

    artefacts = db.get_artefacts(scan_id)
    mosca_meta = (scan.metadata or {}).get("mosca", {})
    y = float(mosca_meta.get("y", 3.0))
    z = float(mosca_meta.get("z", 12.0))

    overrides = {}
    for art in artefacts:
        if art.metadata and "overrides" in art.metadata:
            overrides[art.id] = art.metadata["overrides"]

    summary = RiskEngine.assess_artefacts(artefacts, default_y=y, default_z=z, overrides=overrides)
    recommendations = RecommendationEngine.recommend_for_scan(artefacts, assessments=summary.assessments)

    # 1. CycloneDX 1.6 CBOM JSON
    if fmt == "cbom":
        cbom_dict = CycloneDX16CBOMBuilder.generate_cbom(
            artefacts=artefacts,
            assessments=summary.assessments,
            target_name=Path(scan.target_path).name or "ECDAT Target",
        )
        content = json.dumps(cbom_dict, indent=2)
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="ecdat_cbom_{scan_id[:8]}.json"'},
        )

    # 2. HTML Report
    elif fmt == "html":
        html_content = HTMLReportGenerator.generate_html(
            artefacts=artefacts,
            summary=summary,
            recommendations=recommendations,
            target_name=Path(scan.target_path).name or "ECDAT Target",
            default_y=y,
            default_z=z,
        )
        return Response(
            content=html_content,
            media_type="text/html; charset=utf-8",
            headers={"Content-Disposition": f'inline; filename="ecdat_report_{scan_id[:8]}.html"'},
        )

    # 3. PDF Report
    elif fmt == "pdf":
        pdf_bytes = PDFReportGenerator.generate_pdf(
            artefacts=artefacts,
            summary=summary,
            recommendations=recommendations,
            target_name=Path(scan.target_path).name or "ECDAT Target",
            default_y=y,
            default_z=z,
        )
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="ecdat_report_{scan_id[:8]}.pdf"'},
        )

    # 4. CSV Spreadsheet
    elif fmt == "csv":
        csv_content = CSVReportGenerator.generate_csv(
            artefacts=artefacts,
            assessments=summary.assessments,
        )
        return Response(
            content=csv_content,
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="ecdat_artefacts_{scan_id[:8]}.csv"'},
        )


@app.get("/api/catalogue", tags=["Catalogue"])
def get_catalogue() -> Dict[str, Any]:
    """Retrieve the central cryptographic catalogue and algorithms dictionary."""
    algo_dict = catalogue_service.catalogue.algorithms
    return {
        "total_algorithms": len(algo_dict),
        "algorithms": [
            {"name": name, **entry.model_dump()}
            for name, entry in algo_dict.items()
        ],
    }
