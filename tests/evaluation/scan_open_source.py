from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.app.models.artefact import Artefact, QuantumStatus
from backend.app.risk.engine import RiskEngine, assess_scan_risk
from backend.app.scanners.base import ScannerRegistry
import backend.app.scanners  # noqa: F401

logger = logging.getLogger("ecdat.evaluation.oss")
logging.basicConfig(level=logging.INFO)


@dataclass
class RepoScanResult:
    name: str
    owner: str
    language: str
    url: str
    description: str
    status: str  # 'success' | 'failed' | 'cached'
    files_scanned: int = 0
    total_lines: int = 0
    scan_time_sec: float = 0.0
    throughput_files_sec: float = 0.0
    total_artefacts: int = 0
    at_risk_count: int = 0
    quantum_vulnerable_count: int = 0
    percent_quantum_vulnerable: float = 0.0
    risk_breakdown: Dict[str, int] = field(default_factory=lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0})
    top_algorithms: List[str] = field(default_factory=list)
    error_message: Optional[str] = None


class OpenSourceBenchmarkRunner:
    """
    Clones and scans a diverse benchmark corpus of 10 open-source repositories.
    Evaluates real-world cryptographic density, scanning throughput, and post-quantum exposure.
    """

    def __init__(self, repos_config_path: Optional[Path | str] = None, max_repos: Optional[int] = None):
        base = Path(__file__).resolve().parent
        self.config_path = Path(repos_config_path) if repos_config_path else base / "repos.json"
        self.max_repos = max_repos

    def load_repo_configs(self) -> List[Dict[str, Any]]:
        with open(self.config_path, "r", encoding="utf-8") as f:
            repos = json.load(f)
        if self.max_repos:
            return repos[:self.max_repos]
        return repos

    def scan_repo(self, repo_info: Dict[str, Any], temp_root: Optional[Path] = None) -> RepoScanResult:
        name = repo_info["name"]
        url = repo_info["url"]
        lang = repo_info.get("language", "Unknown")
        owner = repo_info.get("owner", "")
        desc = repo_info.get("description", "")

        clone_dir = Path(tempfile.mkdtemp(prefix=f"ecdat_{name}_", dir=temp_root))
        logger.info(f"Cloning {url} into {clone_dir}...")

        start_time = time.perf_counter()
        try:
            # 1. Shallow clone with 30s timeout
            subprocess.run(
                ["git", "clone", "--depth", "1", url, str(clone_dir)],
                check=True,
                capture_output=True,
                timeout=45,
                text=True,
            )

            # 2. Count files & LOC
            file_count = 0
            loc_count = 0
            for root, dirs, files in os.walk(clone_dir):
                # Filter out .git
                if ".git" in dirs:
                    dirs.remove(".git")
                for f in files:
                    file_count += 1
                    fp = Path(root) / f
                    try:
                        if fp.is_file() and fp.stat().st_size < 1_000_000:
                            with open(fp, "r", encoding="utf-8", errors="ignore") as lines:
                                loc_count += sum(1 for _ in lines)
                    except Exception:
                        pass

            # 3. Execute Discovery Scan
            scan_start = time.perf_counter()
            artefacts = ScannerRegistry.scan_all(clone_dir)
            scan_duration = time.perf_counter() - scan_start

            throughput = round(file_count / scan_duration, 1) if scan_duration > 0 else 0.0

            # 4. Assess Risk
            summary = assess_scan_risk(artefacts, y=3.0, z=12.0)

            # Extract top algorithms
            algo_counts: Dict[str, int] = {}
            for a in artefacts:
                algo_counts[a.name] = algo_counts.get(a.name, 0) + 1
            sorted_algos = [f"{k} ({v})" for k, v in sorted(algo_counts.items(), key=lambda x: x[1], reverse=True)[:5]]

            return RepoScanResult(
                name=name,
                owner=owner,
                language=lang,
                url=url,
                description=desc,
                status="success",
                files_scanned=file_count,
                total_lines=loc_count,
                scan_time_sec=round(scan_duration, 3),
                throughput_files_sec=throughput,
                total_artefacts=len(artefacts),
                at_risk_count=summary.at_risk_count,
                quantum_vulnerable_count=summary.quantum_vulnerable_count,
                percent_quantum_vulnerable=summary.percent_quantum_vulnerable,
                risk_breakdown=summary.counts_by_risk_level,
                top_algorithms=sorted_algos,
            )

        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as git_err:
            logger.warning(f"Failed to clone {url}: {git_err}. Generating fallback benchmark entry.")
            return RepoScanResult(
                name=name,
                owner=owner,
                language=lang,
                url=url,
                description=desc,
                status="failed",
                error_message=f"Git clone error: {str(git_err)}",
            )
        except Exception as exc:
            logger.exception(f"Scan failed for {name}: {exc}")
            return RepoScanResult(
                name=name,
                owner=owner,
                language=lang,
                url=url,
                description=desc,
                status="failed",
                error_message=str(exc),
            )
        finally:
            if clone_dir.exists():
                shutil.rmtree(clone_dir, ignore_errors=True)

    def run_all(self) -> List[RepoScanResult]:
        repos = self.load_repo_configs()
        results: List[RepoScanResult] = []

        print(f"Starting benchmark evaluation across {len(repos)} open-source repositories...")
        for idx, repo in enumerate(repos, 1):
            print(f"[{idx}/{len(repos)}] Processing {repo['owner']}/{repo['name']} ({repo['language']})...")
            res = self.scan_repo(repo)
            results.append(res)
            print(f"    Done: {res.total_artefacts} crypto artefacts discovered in {res.scan_time_sec}s ({res.throughput_files_sec} files/s)")

        return results

    @staticmethod
    def render_markdown_table(results: List[RepoScanResult]) -> str:
        rows = [
            "| Repository | Lang | Files | Scan Time | Throughput | Assets | At-Risk | % Shor/Grover | Risk Breakdown (C/H/M/L) | Top Primitives |",
            "|---|---|---|---|---|---|---|---|---|---|",
        ]
        for r in results:
            if r.status == "success":
                rb = r.risk_breakdown
                rb_str = f"{rb.get('critical',0)}/{rb.get('high',0)}/{rb.get('medium',0)}/{rb.get('low',0)}"
                top_algo_str = ", ".join(r.top_algorithms[:3]) if r.top_algorithms else "None"
                rows.append(
                    f"| [{r.name}]({r.url}) | {r.language} | {r.files_scanned:,} | {r.scan_time_sec:.2f}s | {r.throughput_files_sec:.1f} f/s | **{r.total_artefacts}** | {r.at_risk_count} | {r.percent_quantum_vulnerable}% | `{rb_str}` | {top_algo_str} |"
                )
            else:
                rows.append(
                    f"| [{r.name}]({r.url}) | {r.language} | — | — | — | — | — | — | Clone Error | *{r.error_message[:40] if r.error_message else 'Failed'}* |"
                )
        return "\n".join(rows)


if __name__ == "__main__":
    runner = OpenSourceBenchmarkRunner()
    results = runner.run_all()
    print("\n" + runner.render_markdown_table(results))
