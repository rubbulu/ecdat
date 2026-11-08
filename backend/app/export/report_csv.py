from __future__ import annotations

import csv
import io
import logging
from pathlib import Path
from typing import Dict, List, Optional

from backend.app.models.artefact import Artefact
from backend.app.risk.mosca import MoscaAssessment, MoscaEngine

logger = logging.getLogger(__name__)


class CSVReportGenerator:
    """
    Exports full cryptographic asset inventory and quantum risk telemetry
    into structured CSV spreadsheets for enterprise compliance audits.
    """

    HEADERS = [
        "id",
        "name",
        "type",
        "key_size",
        "mode",
        "file",
        "line",
        "detection_method",
        "quantum_status",
        "lifetime_class",
        "criticality",
        "is_at_risk",
        "risk_score",
        "risk_level",
        "nist_replacement",
        "evidence",
        "notes",
    ]

    @classmethod
    def generate_csv(
        cls,
        artefacts: List[Artefact],
        assessments: Optional[List[MoscaAssessment]] = None,
        output_path: Optional[str | Path] = None,
    ) -> str:
        assess_map: Dict[str, MoscaAssessment] = {}
        if assessments:
            for a in assessments:
                assess_map[a.artefact_id] = a
        else:
            for art in artefacts:
                assess_map[art.id] = MoscaEngine.evaluate(art)

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=cls.HEADERS)
        writer.writeheader()

        for art in artefacts:
            ass = assess_map.get(art.id)
            row = {
                "id": art.id,
                "name": art.name,
                "type": art.type.value if hasattr(art.type, "value") else str(art.type),
                "key_size": art.key_size or "",
                "mode": art.mode or "",
                "file": art.location.file,
                "line": art.location.line,
                "detection_method": art.detection_method,
                "quantum_status": art.quantum_status.value if art.quantum_status else "",
                "lifetime_class": ass.lifetime_class.value if ass else "",
                "criticality": ass.criticality.value if ass else "",
                "is_at_risk": str(ass.is_at_risk).lower() if ass else "false",
                "risk_score": ass.risk_score if ass else 0.0,
                "risk_level": ass.risk_level if ass else "low",
                "nist_replacement": art.nist_replacement or "",
                "evidence": art.evidence.replace("\n", " ").strip(),
                "notes": art.notes or "",
            }
            writer.writerow(row)

        csv_str = output.getvalue()

        if output_path:
            out = Path(output_path)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(csv_str, encoding="utf-8")
            logger.info(f"Generated CSV export at {out}")

        return csv_str
