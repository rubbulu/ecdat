from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from jinja2 import Template

from backend.app.models.artefact import Artefact
from backend.app.recommend.engine import Recommendation, generate_recommendations
from backend.app.risk.engine import RiskSummary, assess_scan_risk

logger = logging.getLogger(__name__)

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ECDAT Executive Cryptographic & Post-Quantum Risk Report</title>
    <style>
        :root {
            --primary: #1e3a8a;
            --primary-light: #3b82f6;
            --danger: #dc2626;
            --warning: #f59e0b;
            --success: #10b981;
            --bg-card: #ffffff;
            --text-main: #1f2937;
            --text-muted: #6b7280;
            --border: #e5e7eb;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            color: var(--text-main);
            background: #f9fafb;
            line-height: 1.5;
            padding: 30px;
        }
        .container { max-width: 1200px; margin: 0 auto; background: #fff; padding: 40px; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); }
        .header { display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 2px solid var(--border); padding-bottom: 24px; margin-bottom: 30px; }
        .header-title h1 { font-size: 28px; color: var(--primary); font-weight: 800; }
        .header-title p { color: var(--text-muted); font-size: 14px; margin-top: 4px; }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 9999px; font-size: 12px; font-weight: 700; text-transform: uppercase; }
        .badge-danger { background: #fee2e2; color: #991b1b; }
        .badge-warning { background: #fef3c7; color: #92400e; }
        .badge-success { background: #d1fae5; color: #065f46; }
        .badge-info { background: #dbeafe; color: #1e40af; }
        
        .kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 35px; }
        .kpi-card { background: #f8fafc; border: 1px solid var(--border); border-radius: 8px; padding: 20px; text-align: center; }
        .kpi-value { font-size: 32px; font-weight: 800; color: var(--primary); }
        .kpi-value.danger { color: var(--danger); }
        .kpi-value.warning { color: var(--warning); }
        .kpi-label { font-size: 13px; color: var(--text-muted); font-weight: 600; text-transform: uppercase; margin-top: 4px; }

        .section { margin-bottom: 40px; }
        .section-title { font-size: 20px; font-weight: 700; color: var(--primary); margin-bottom: 16px; border-left: 4px solid var(--primary-light); padding-left: 10px; }

        .mosca-box { background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 8px; padding: 20px; margin-bottom: 24px; }
        .mosca-formula { font-size: 20px; font-family: monospace; font-weight: bold; color: var(--primary); text-align: center; margin: 12px 0; }

        table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
        th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); }
        th { background: #f8fafc; font-weight: 700; color: var(--text-muted); text-transform: uppercase; font-size: 11px; }
        tr:hover { background: #f1f5f9; }

        .score-pill { font-weight: 800; padding: 3px 8px; border-radius: 6px; }
        .score-crit { background: #fecaca; color: #b91c1c; }
        .score-high { background: #fed7aa; color: #c2410c; }
        .score-med { background: #fef08a; color: #854d0e; }
        .score-low { background: #bbf7d0; color: #15803d; }

        .progress-bar-bg { background: #e2e8f0; height: 10px; border-radius: 9999px; overflow: hidden; margin-top: 6px; }
        .progress-bar-fill { height: 100%; border-radius: 9999px; }

        @media print {
            body { padding: 0; background: #fff; }
            .container { box-shadow: none; border: none; padding: 10px; max-width: 100%; }
            tr { page-break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="header-title">
                <h1>ECDAT Quantum Cryptographic Risk Report</h1>
                <p>Enterprise Cryptographic Discovery & Analysis Tool | Threws Odyssey 2026</p>
                <p><strong>Target Analyzed:</strong> {{ target_name }} &bull; Generated: {{ generated_at }}</p>
            </div>
            <div>
                <span class="badge {% if summary.at_risk_count > 0 %}badge-danger{% else %}badge-success{% endif %}">
                    {% if summary.at_risk_count > 0 %}ACTION REQUIRED: QUANTUM EXPOSURE{% else %}POSTURE SECURE{% endif %}
                </span>
            </div>
        </div>

        <!-- KPI Executive Scorecard -->
        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-value">{{ summary.total_artefacts }}</div>
                <div class="kpi-label">Total Crypto Assets</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-value {% if summary.at_risk_count > 0 %}danger{% endif %}">{{ summary.at_risk_count }}</div>
                <div class="kpi-label">At Risk (Mosca X+Y>Z)</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-value {% if summary.percent_quantum_vulnerable > 0 %}warning{% endif %}">{{ summary.percent_quantum_vulnerable }}%</div>
                <div class="kpi-label">Quantum Vulnerable %</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-value danger">{{ summary.counts_by_risk_level.critical + summary.counts_by_risk_level.high }}</div>
                <div class="kpi-label">Critical / High Severity</div>
            </div>
        </div>

        <!-- Mosca Inequality Section -->
        <div class="section">
            <h2 class="section-title">Quantum Risk Horizon (Mosca's Theorem)</h2>
            <div class="mosca-box">
                <p>Mosca's Theorem establishes that cryptographic assets become compromised today under the <em>"Harvest Now, Decrypt Later"</em> threat model when the time required to migrate and retain confidentiality exceeds the quantum computer arrival horizon:</p>
                <div class="mosca-formula">Risk Alert Triggered If: X (Shelf-Life) + Y (Migration Time) > Z (CRQC Horizon)</div>
                <p><strong>Configured Assumptions:</strong> Migration timeline <strong>Y = {{ default_y }} years</strong> | Quantum collapse horizon <strong>Z = {{ default_z }} years</strong> (estimated ~2038).</p>
            </div>
        </div>

        <!-- Top Urgency Risks -->
        <div class="section">
            <h2 class="section-title">Top 10 Cryptographic Risks Requiring Immediate Remediation</h2>
            <table>
                <thead>
                    <tr>
                        <th>Asset Name</th>
                        <th>Risk Score</th>
                        <th>Criticality</th>
                        <th>Location</th>
                        <th>Plain-English Threat Analysis</th>
                    </tr>
                </thead>
                <tbody>
                    {% for item in summary.top_riskiest %}
                    <tr>
                        <td><strong>{{ item.artefact_name }}</strong></td>
                        <td>
                            <span class="score-pill {% if item.risk_score >= 80 %}score-crit{% elif item.risk_score >= 60 %}score-high{% elif item.risk_score >= 35 %}score-med{% else %}score-low{% endif %}">
                                {{ item.risk_score }} ({{ item.risk_level | upper }})
                            </span>
                        </td>
                        <td><span class="badge badge-info">{{ item.criticality | upper }}</span></td>
                        <td><code>{{ item.metadata.file }}:{{ item.metadata.line }}</code></td>
                        <td>{{ item.explanation }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <!-- PQC Migration Recommendations -->
        <div class="section">
            <h2 class="section-title">Prioritized Post-Quantum Migration Action Plan</h2>
            <table>
                <thead>
                    <tr>
                        <th>Current Primitive</th>
                        <th>Recommended Replacement</th>
                        <th>Approach</th>
                        <th>Effort</th>
                        <th>Size & Latency Impact</th>
                        <th>Recommended Implementations</th>
                    </tr>
                </thead>
                <tbody>
                    {% for rec in recommendations %}
                    <tr>
                        <td><strong>{{ rec.current_primitive }}</strong></td>
                        <td><strong style="color: var(--primary);">{{ rec.replacement }}</strong></td>
                        <td><span class="badge badge-warning">{{ rec.hybrid_vs_pure | upper }}</span></td>
                        <td>{{ rec.migration_effort | upper }}</td>
                        <td>{{ rec.size_impact }}</td>
                        <td>{{ rec.library_suggestion | join(', ') }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <!-- Full Inventory -->
        <div class="section">
            <h2 class="section-title">Complete Cryptographic Inventory (CBOM Components)</h2>
            <table>
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Name</th>
                        <th>Key / Param</th>
                        <th>Mode</th>
                        <th>Status</th>
                        <th>Location</th>
                        <th>Detection Method</th>
                    </tr>
                </thead>
                <tbody>
                    {% for art in artefacts %}
                    <tr>
                        <td><span class="badge badge-info">{{ art.type | upper }}</span></td>
                        <td><strong>{{ art.name }}</strong></td>
                        <td>{{ art.key_size or '-' }}</td>
                        <td>{{ art.mode or '-' }}</td>
                        <td>
                            {% if art.quantum_status == 'vulnerable_shor' %}
                                <span class="badge badge-danger">Shor Vulnerable</span>
                            {% elif art.quantum_status == 'classically_broken' %}
                                <span class="badge badge-danger">Classically Broken</span>
                            {% elif art.quantum_status == 'weakened_grover' %}
                                <span class="badge badge-warning">Grover Weakened</span>
                            {% elif art.quantum_status == 'quantum_safe' %}
                                <span class="badge badge-success">Quantum Safe</span>
                            {% else %}
                                <span class="badge badge-info">Unclassified</span>
                            {% endif %}
                        </td>
                        <td><code>{{ art.location.file }}:{{ art.location.line }}</code></td>
                        <td>{{ art.detection_method }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""


class HTMLReportGenerator:
    """
    Renders enterprise-ready, printable HTML audit reports with executive scorecards,
    Mosca risk matrices, prioritized PQC recommendations, and full CBOM inventories.
    """

    @classmethod
    def generate_html(
        cls,
        artefacts: List[Artefact],
        summary: Optional[RiskSummary] = None,
        recommendations: Optional[List[Recommendation]] = None,
        target_name: str = "ECDAT Target Application",
        default_y: float = 3.0,
        default_z: float = 12.0,
        output_path: Optional[str | Path] = None,
    ) -> str:
        if summary is None:
            summary = assess_scan_risk(artefacts, y=default_y, z=default_z)

        if recommendations is None:
            recommendations = generate_recommendations(artefacts, y=default_y, z=default_z)

        template = Template(HTML_TEMPLATE)
        rendered = template.render(
            target_name=target_name,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            summary=summary,
            recommendations=recommendations,
            artefacts=artefacts,
            default_y=default_y,
            default_z=default_z,
        )

        if output_path:
            out = Path(output_path)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(rendered, encoding="utf-8")
            logger.info(f"Generated HTML report at {out}")

        return rendered
