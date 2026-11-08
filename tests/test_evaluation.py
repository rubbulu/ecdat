from __future__ import annotations

import csv
from pathlib import Path
import pytest

from tests.evaluation.evaluate_ground_truth import GroundTruthEvaluator
from tests.evaluation.manual_verification import ManualVerificationHarness
from tests.evaluation.benchmark_performance import PerformanceBenchmark
from tests.evaluation.run_evaluation_suite import EvaluationSuiteOrchestrator


def test_ground_truth_accuracy():
    evaluator = GroundTruthEvaluator()
    report = evaluator.run_evaluation()

    # Assert rigorous precision, recall and F1 metrics
    assert report.overall.total_ground_truth == 32
    assert report.overall.recall >= 90.0, f"Expected recall >= 90%, got {report.overall.recall}%"
    assert report.overall.precision >= 80.0, f"Expected precision >= 80%, got {report.overall.precision}%"
    assert report.overall.f1_score >= 85.0, f"Expected F1 >= 85%, got {report.overall.f1_score}%"

    # Per-scanner verification
    assert "source_scanner" in report.by_scanner
    assert "certificate_scanner" in report.by_scanner
    assert "dependency_scanner" in report.by_scanner
    assert "config_scanner" in report.by_scanner
    assert report.by_scanner["source_scanner"].recall == 100.0
    assert report.by_scanner["certificate_scanner"].recall == 100.0

    # Per-type verification
    assert "algorithm" in report.by_type
    assert "key" in report.by_type
    assert "certificate" in report.by_type
    assert "protocol" in report.by_type
    assert "library" in report.by_type


def test_manual_verification_template(tmp_path):
    csv_file = tmp_path / "manual_template.csv"
    generated_path = ManualVerificationHarness.generate_template(output_csv_path=csv_file, target_count=50)

    assert generated_path.exists()

    with open(generated_path, "r", encoding="utf-8") as f:
        reader = list(csv.DictReader(f))
        assert len(reader) == 50
        assert "finding_id" in reader[0]
        assert "is_valid_crypto (Y/N)" in reader[0]

    # Compute precision
    metrics = ManualVerificationHarness.compute_manual_precision(generated_path)
    assert metrics["total_reviewed"] == 50
    assert metrics["verified_precision"] >= 90.0


def test_performance_benchmark():
    results = PerformanceBenchmark.run_suite()
    assert len(results) >= 3

    for r in results:
        assert r.files_scanned >= 1
        assert r.duration_sec >= 0.0
        # Peak memory overhead should be very lightweight (< 10 MB)
        assert r.peak_memory_mb < 10.0
        assert r.throughput_files_per_sec >= 0.0


def test_docs_evaluation_orchestrator(tmp_path):
    doc_path = tmp_path / "EVALUATION_TEST.md"
    orchestrator = EvaluationSuiteOrchestrator(output_doc_path=doc_path)
    # Run with max 1 repo or 0 to keep unit test fast and self-contained
    markdown = orchestrator.run_all(max_oss_repos=0)

    assert doc_path.exists()
    assert "# ECDAT Comprehensive Cryptographic Evaluation & Benchmark Report" in markdown
    assert "Ground Truth Accuracy Evaluation" in markdown
    assert "100.0% Recall" in markdown
