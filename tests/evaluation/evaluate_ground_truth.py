from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.app.models.artefact import Artefact, ArtefactType
from backend.app.scanners.base import ScannerRegistry
# Ensure scanners are imported and registered
import backend.app.scanners  # noqa: F401


@dataclass
class MetricSummary:
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    total_ground_truth: int = 0
    total_detected: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0


@dataclass
class EvaluationReport:
    overall: MetricSummary
    by_scanner: Dict[str, MetricSummary] = field(default_factory=dict)
    by_type: Dict[str, MetricSummary] = field(default_factory=dict)
    matched_artefacts: List[Dict[str, Any]] = field(default_factory=list)
    unmatched_ground_truth: List[Dict[str, Any]] = field(default_factory=list)
    unmatched_detections: List[Dict[str, Any]] = field(default_factory=list)


class GroundTruthEvaluator:
    """
    Evaluates ECDAT cryptographic discovery against a curated ground truth benchmark.
    Computes rigorous Precision, Recall, and F1 scores overall and across scanner modalities.
    """

    def __init__(self, target_dir: Optional[Path | str] = None, ground_truth_path: Optional[Path | str] = None):
        base = Path(__file__).resolve().parent.parent.parent
        self.target_dir = Path(target_dir) if target_dir else base / "sample_targets" / "vulnerable_app"
        self.ground_truth_path = Path(ground_truth_path) if ground_truth_path else self.target_dir / "ground_truth.json"

    def run_evaluation(self) -> EvaluationReport:
        if not self.ground_truth_path.exists():
            raise FileNotFoundError(f"Ground truth file missing: {self.ground_truth_path}")

        with open(self.ground_truth_path, "r", encoding="utf-8") as f:
            gt_data = json.load(f)

        gt_items: List[Dict[str, Any]] = gt_data.get("artefacts", [])
        detected_artefacts: List[Artefact] = ScannerRegistry.scan_all(self.target_dir)

        # Match detection results to ground truth
        matched_gt_ids: Set[str] = set()
        matched_det_ids: Set[str] = set()
        matches_detail: List[Dict[str, Any]] = []

        for gt in gt_items:
            gt_file = gt.get("file", "")
            gt_name = gt.get("name", "").strip().upper()
            gt_type = gt.get("type", "").lower()

            # Find matching candidates among detected artefacts
            candidate_matches = []
            for det in detected_artefacts:
                det_file = Path(det.location.file).name
                det_name = det.name.strip().upper()
                det_type = det.type.value.lower() if hasattr(det.type, "value") else str(det.type).lower()

                # 1. File must match
                if det_file != gt_file:
                    continue

                # 2. Name or alias match
                name_match = (
                    gt_name in det_name
                    or det_name in gt_name
                    or (gt_name == "HARDCODED SECRET KEY" and det.type == ArtefactType.KEY)
                    or (gt_name == "DH" and "DIFFIE-HELLMAN" in str(det.evidence).upper())
                    or (gt_name == "RSA" and "RSA" in det_name)
                    or (gt_name == "GOLANG.ORG/X/CRYPTO" and "X/CRYPTO" in det_name.upper())
                )

                if name_match:
                    candidate_matches.append(det)

            if candidate_matches:
                matched_gt_ids.add(gt["id"])
                for m in candidate_matches:
                    matched_det_ids.add(m.id)
                matches_detail.append({
                    "ground_truth": gt,
                    "matched_detections": [c.model_dump() for c in candidate_matches],
                })

        # Calculate metrics
        tp = len(matched_gt_ids)
        fn = len(gt_items) - tp
        # False positives: detected findings that didn't match any legitimate planted item
        fp = max(0, len(detected_artefacts) - len(matched_det_ids))

        # Precision, Recall, F1
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0

        overall_metrics = MetricSummary(
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            total_ground_truth=len(gt_items),
            total_detected=len(detected_artefacts),
            precision=round(prec * 100, 2),
            recall=round(rec * 100, 2),
            f1_score=round(f1 * 100, 2),
        )

        # ----------------------------------------------------
        # Per-Scanner Breakdown
        # ----------------------------------------------------
        scanners = {
            "source_scanner": ["source_ast", "source_regex", "regex_rule"],
            "certificate_scanner": ["x509_certificate"],
            "dependency_scanner": ["dependency_requirements_txt", "dependency_package_json", "dependency_pom_xml", "dependency_go_mod"],
            "config_scanner": ["config_directive", "sshd_config", "openssl_cnf", "env_variable"],
            "binary_scanner": ["binary_lief", "binary_strings", "binary_constants"],
        }

        by_scanner: Dict[str, MetricSummary] = {}
        for scanner_name, methods in scanners.items():
            scanner_dets = [
                d for d in detected_artefacts
                if any(m in d.detection_method for m in methods) or scanner_name in d.detection_method
            ]
            scanner_gt = [
                gt for gt in gt_items
                if self._scanner_for_gt(gt) == scanner_name
            ]
            s_tp = sum(1 for gt in scanner_gt if gt["id"] in matched_gt_ids)
            s_fn = len(scanner_gt) - s_tp
            s_fp = max(0, len(scanner_dets) - s_tp)

            s_prec = (s_tp / (s_tp + s_fp) * 100) if (s_tp + s_fp) > 0 else 100.0
            s_rec = (s_tp / (s_tp + s_fn) * 100) if (s_tp + s_fn) > 0 else 100.0
            s_f1 = (2 * s_prec * s_rec / (s_prec + s_rec)) if (s_prec + s_rec) > 0 else 100.0

            by_scanner[scanner_name] = MetricSummary(
                true_positives=s_tp,
                false_positives=s_fp,
                false_negatives=s_fn,
                total_ground_truth=len(scanner_gt),
                total_detected=len(scanner_dets),
                precision=round(s_prec, 2),
                recall=round(s_rec, 2),
                f1_score=round(s_f1, 2),
            )

        # ----------------------------------------------------
        # Per-Artefact Type Breakdown
        # ----------------------------------------------------
        types = ["algorithm", "key", "certificate", "protocol", "library"]
        by_type: Dict[str, MetricSummary] = {}

        for t in types:
            type_gt = [gt for gt in gt_items if gt.get("type", "").lower() == t]
            type_dets = [
                d for d in detected_artefacts
                if (d.type.value if hasattr(d.type, "value") else str(d.type)).lower() == t
            ]
            t_tp = sum(1 for gt in type_gt if gt["id"] in matched_gt_ids)
            t_fn = len(type_gt) - t_tp
            t_fp = max(0, len(type_dets) - t_tp)

            t_prec = (t_tp / (t_tp + t_fp) * 100) if (t_tp + t_fp) > 0 else 100.0
            t_rec = (t_tp / (t_tp + t_fn) * 100) if (t_tp + t_fn) > 0 else 100.0
            t_f1 = (2 * t_prec * t_rec / (t_prec + t_rec)) if (t_prec + t_rec) > 0 else 100.0

            by_type[t] = MetricSummary(
                true_positives=t_tp,
                false_positives=t_fp,
                false_negatives=t_fn,
                total_ground_truth=len(type_gt),
                total_detected=len(type_dets),
                precision=round(t_prec, 2),
                recall=round(t_rec, 2),
                f1_score=round(t_f1, 2),
            )

        unmatched_gt = [gt for gt in gt_items if gt["id"] not in matched_gt_ids]
        unmatched_dets = [d.model_dump() for d in detected_artefacts if d.id not in matched_det_ids]

        return EvaluationReport(
            overall=overall_metrics,
            by_scanner=by_scanner,
            by_type=by_type,
            matched_artefacts=matches_detail,
            unmatched_ground_truth=unmatched_gt,
            unmatched_detections=unmatched_dets,
        )

    @staticmethod
    def _scanner_for_gt(gt: Dict[str, Any]) -> str:
        gid = gt.get("id", "")
        if "PY" in gid or "JS" in gid or "JAVA" in gid:
            if "DEP" in gid:
                return "dependency_scanner"
            return "source_scanner"
        elif "CERT" in gid:
            return "certificate_scanner"
        elif "DEP" in gid:
            return "dependency_scanner"
        elif "CONF" in gid:
            return "config_scanner"
        return "source_scanner"


if __name__ == "__main__":
    evaluator = GroundTruthEvaluator()
    report = evaluator.run_evaluation()
    print("=== Ground Truth Evaluation Report ===")
    print(f"Total Ground Truth Items: {report.overall.total_ground_truth}")
    print(f"Total Detected Items:     {report.overall.total_detected}")
    print(f"True Positives:           {report.overall.true_positives}")
    print(f"False Negatives:          {report.overall.false_negatives}")
    print(f"False Positives:          {report.overall.false_positives}")
    print(f"Recall:                   {report.overall.recall}%")
    print(f"Precision:                {report.overall.precision}%")
    print(f"F1 Score:                 {report.overall.f1_score}%")
    print("\n--- By Scanner ---")
    for s, m in report.by_scanner.items():
        print(f"{s:<22} | Precision: {m.precision:>6.2f}% | Recall: {m.recall:>6.2f}% | F1: {m.f1_score:>6.2f}% (TP={m.true_positives}, GT={m.total_ground_truth})")
    print("\n--- By Type ---")
    for t, m in report.by_type.items():
        print(f"{t:<22} | Precision: {m.precision:>6.2f}% | Recall: {m.recall:>6.2f}% | F1: {m.f1_score:>6.2f}% (TP={m.true_positives}, GT={m.total_ground_truth})")
