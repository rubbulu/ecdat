from __future__ import annotations

import os
import time
import tracemalloc
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.app.scanners.base import ScannerRegistry
import backend.app.scanners  # noqa: F401


@dataclass
class PerformanceBenchmarkResult:
    target_name: str
    target_path: str
    files_scanned: int
    lines_of_code: int
    artefacts_found: int
    duration_sec: float
    throughput_files_per_sec: float
    throughput_loc_per_sec: float
    peak_memory_mb: float
    memory_delta_mb: float


class PerformanceBenchmark:
    """
    Measures scanning speed (files/sec, LOC/sec) and memory footprint (peak MB via tracemalloc).
    Evaluates multi-language scanning overhead across diverse repository scales.
    """

    @classmethod
    def benchmark_target(cls, target_path: Path | str, target_name: Optional[str] = None) -> PerformanceBenchmarkResult:
        path = Path(target_path)
        name = target_name or path.name

        # Count files and LOC beforehand
        files_count = 0
        loc_count = 0
        if path.is_file():
            files_count = 1
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    loc_count = sum(1 for _ in f)
            except Exception:
                pass
        else:
            for root, dirs, files in os.walk(path):
                if any(skip in root for skip in [".git", "node_modules", ".venv", "venv", "__pycache__"]):
                    continue
                for f in files:
                    fp = Path(root) / f
                    if fp.is_file():
                        files_count += 1
                        try:
                            if fp.stat().st_size < 1_000_000:
                                with open(fp, "r", encoding="utf-8", errors="ignore") as fl:
                                    loc_count += sum(1 for _ in fl)
                        except Exception:
                            pass

        # Reset & Start Memory & Time Profiling
        tracemalloc.start()
        start_snapshot = tracemalloc.take_snapshot()
        start_time = time.perf_counter()

        # Run Scan
        artefacts = ScannerRegistry.scan_all(path)

        end_time = time.perf_counter()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        duration = end_time - start_time
        peak_mb = peak / (1024 * 1024)
        delta_mb = current / (1024 * 1024)

        files_per_sec = (files_count / duration) if duration > 0 else 0.0
        loc_per_sec = (loc_count / duration) if duration > 0 else 0.0

        return PerformanceBenchmarkResult(
            target_name=name,
            target_path=str(path),
            files_scanned=files_count,
            lines_of_code=loc_count,
            artefacts_found=len(artefacts),
            duration_sec=round(duration, 4),
            throughput_files_per_sec=round(files_per_sec, 1),
            throughput_loc_per_sec=round(loc_per_sec, 1),
            peak_memory_mb=round(peak_mb, 2),
            memory_delta_mb=round(delta_mb, 2),
        )

    @classmethod
    def run_suite(cls) -> List[PerformanceBenchmarkResult]:
        base = Path(__file__).resolve().parent.parent.parent
        targets = [
            ("Single Python File (app.py)", base / "sample_targets" / "vulnerable_app" / "app.py"),
            ("Single Certificate (server.crt)", base / "sample_targets" / "vulnerable_app" / "server.crt"),
            ("Vulnerable App (Multi-Lang Suite)", base / "sample_targets" / "vulnerable_app"),
            ("ECDAT Backend Core (Python 3.11)", base / "backend" / "app"),
            ("Full Test Fixtures & Targets", base / "sample_targets"),
        ]

        results = []
        for name, p in targets:
            if p.exists():
                res = cls.benchmark_target(p, target_name=name)
                results.append(res)
        return results

    @staticmethod
    def render_markdown_table(results: List[PerformanceBenchmarkResult]) -> str:
        rows = [
            "| Target Workload | Files | Lines of Code | Assets Found | Duration (s) | Speed (Files/s) | Speed (LOC/s) | Peak Memory |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for r in results:
            rows.append(
                f"| **{r.target_name}** | {r.files_scanned:,} | {r.lines_of_code:,} | {r.artefacts_found} | {r.duration_sec:.4f}s | {r.throughput_files_per_sec:.1f} | {r.throughput_loc_per_sec:.1f} | `{r.peak_memory_mb:.2f} MB` |"
            )
        return "\n".join(rows)


if __name__ == "__main__":
    runner = PerformanceBenchmark()
    res = runner.run_suite()
    print("=== ECDAT Performance & Memory Benchmark Suite ===")
    print(runner.render_markdown_table(res))
