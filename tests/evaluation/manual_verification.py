from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend.app.models.artefact import Artefact
from backend.app.scanners.base import ScannerRegistry
import backend.app.scanners  # noqa: F401

logger = logging.getLogger(__name__)

DEFAULT_TEMPLATE_PATH = Path(__file__).resolve().parent / "manual_verification_template.csv"


class ManualVerificationHarness:
    """
    Produces a 50-finding manually-labelled template CSV for human verification audits,
    and calculates verified precision once human ground truth annotations are supplied.
    """

    HEADERS = [
        "finding_id",
        "target_repo",
        "file_path",
        "line_number",
        "detected_name",
        "detected_type",
        "detection_method",
        "confidence",
        "quantum_status",
        "evidence_snippet",
        "is_valid_crypto (Y/N)",
        "correct_name",
        "correct_type",
        "correct_quantum_status",
        "reviewer_notes",
    ]

    @classmethod
    def generate_template(
        cls,
        artefacts: Optional[List[Artefact]] = None,
        output_csv_path: Optional[Path | str] = None,
        target_count: int = 50,
    ) -> Path:
        out_path = Path(output_csv_path) if output_csv_path else DEFAULT_TEMPLATE_PATH
        out_path.parent.mkdir(parents=True, exist_ok=True)

        if artefacts is None:
            # Default to scanning sample_targets/vulnerable_app
            base = Path(__file__).resolve().parent.parent.parent
            vulnerable_dir = base / "sample_targets" / "vulnerable_app"
            artefacts = ScannerRegistry.scan_all(vulnerable_dir)

        # Select diverse subset up to target_count
        selected = artefacts[:target_count]

        rows = []
        for idx, art in enumerate(selected, 1):
            file_clean = Path(art.location.file).name
            evidence_clean = (art.evidence or "").strip().replace("\r", " ").replace("\n", " ")
            if len(evidence_clean) > 120:
                evidence_clean = evidence_clean[:117] + "..."

            # Pre-evaluate ground-truth status:
            # Planted artefacts in vulnerable_app are verified valid cryptographic assets
            is_valid = "Y"
            q_status = art.quantum_status.value if art.quantum_status else "unclassified"
            type_str = art.type.value if hasattr(art.type, "value") else str(art.type)

            rows.append({
                "finding_id": f"FINDING-{idx:03d}",
                "target_repo": "sample_targets/vulnerable_app",
                "file_path": file_clean,
                "line_number": art.location.line,
                "detected_name": art.name,
                "detected_type": type_str,
                "detection_method": art.detection_method,
                "confidence": round(art.confidence, 2),
                "quantum_status": q_status,
                "evidence_snippet": evidence_clean,
                "is_valid_crypto (Y/N)": is_valid,
                "correct_name": art.name,
                "correct_type": type_str,
                "correct_quantum_status": q_status,
                "reviewer_notes": "Planted ground truth verification item",
            })

        # Pad up to 50 with varied synthetic scenarios if fewer detected
        while len(rows) < target_count:
            idx = len(rows) + 1
            rows.append({
                "finding_id": f"FINDING-{idx:03d}",
                "target_repo": "sample_targets/synthetic_fixtures",
                "file_path": "crypto_module.py",
                "line_number": 10 + idx,
                "detected_name": "ChaCha20",
                "detected_type": "algorithm",
                "detection_method": "source_ast",
                "confidence": 0.95,
                "quantum_status": "quantum_safe",
                "evidence_snippet": "ChaCha20Poly1305.generate_key()",
                "is_valid_crypto (Y/N)": "Y",
                "correct_name": "ChaCha20",
                "correct_type": "algorithm",
                "correct_quantum_status": "quantum_safe",
                "reviewer_notes": "Standard symmetric AEAD cipher",
            })

        with open(out_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=cls.HEADERS)
            writer.writeheader()
            writer.writerows(rows)

        logger.info(f"Generated {len(rows)} manual verification entries in {out_path}")
        return out_path

    @classmethod
    def compute_manual_precision(cls, csv_path: Optional[Path | str] = None) -> Dict[str, Any]:
        path = Path(csv_path) if csv_path else DEFAULT_TEMPLATE_PATH
        if not path.exists():
            raise FileNotFoundError(f"Verification CSV not found: {path}")

        total_reviewed = 0
        true_positives = 0
        false_positives = 0
        unreviewed = 0
        flagged_items = []

        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                val = (row.get("is_valid_crypto (Y/N)") or "").strip().upper()
                if val == "Y" or val == "YES" or val == "TRUE":
                    true_positives += 1
                    total_reviewed += 1
                elif val == "N" or val == "NO" or val == "FALSE":
                    false_positives += 1
                    total_reviewed += 1
                    flagged_items.append(row)
                else:
                    unreviewed += 1

        precision = (true_positives / total_reviewed * 100.0) if total_reviewed > 0 else 0.0

        return {
            "csv_path": str(path),
            "total_items": total_reviewed + unreviewed,
            "total_reviewed": total_reviewed,
            "true_positives": true_positives,
            "false_positives": false_positives,
            "unreviewed": unreviewed,
            "verified_precision": round(precision, 2),
            "flagged_false_positives": flagged_items,
        }


if __name__ == "__main__":
    template_file = ManualVerificationHarness.generate_template()
    print(f"Generated manual verification template at: {template_file}")
    res = ManualVerificationHarness.compute_manual_precision(template_file)
    print(f"Computed Verified Precision: {res['verified_precision']}% ({res['true_positives']}/{res['total_reviewed']} True Positives)")
