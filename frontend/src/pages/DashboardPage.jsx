import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Cpu,
  Clock,
  Download,
  FileCode,
  FileText,
  Table,
  Sliders,
  AlertTriangle,
  ArrowUpRight,
  TrendingUp,
} from 'lucide-react';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';
import { MetricCard } from '../components/MetricCard';
import { RiskBadge } from '../components/RiskBadge';
import { api } from '../api/client';

export function DashboardPage({ scan, summary, onUpdateSummary, onNavigateToArtefacts }) {
  if (!summary) {
    return (
      <div className="text-center py-20 text-slate-400">
        <p>No summary data available. Please select or run a scan.</p>
      </div>
    );
  }

  // Mosca parameters local state
  const initialMosca = summary.mosca_parameters || { x_default: 5.0, y: 3.0, z: 12.0 };
  const [xVal, setXVal] = useState(initialMosca.x_default || 5.0);
  const [yVal, setYVal] = useState(initialMosca.y || 3.0);
  const [zVal, setZVal] = useState(initialMosca.z || 12.0);
  const [updatingMosca, setUpdatingMosca] = useState(false);

  // Calculate live Mosca Inequality check
  const moscaSum = Number(xVal) + Number(yVal);
  const isMoscaAtRisk = moscaSum > Number(zVal);
  const moscaMargin = Number(zVal) - moscaSum;

  // Quantum readiness score: 100 - percent_quantum_vulnerable (with floor at 0)
  const readinessScore = Math.max(0, Math.round(100 - (summary.percent_quantum_vulnerable || 0)));

  // Risk Levels Donut Chart Data
  const riskData = [
    { name: 'Critical', value: summary.counts_by_risk_level?.critical || 0, color: '#ef4444' },
    { name: 'High', value: summary.counts_by_risk_level?.high || 0, color: '#f97316' },
    { name: 'Medium', value: summary.counts_by_risk_level?.medium || 0, color: '#f59e0b' },
    { name: 'Low', value: summary.counts_by_risk_level?.low || 0, color: '#10b981' },
  ].filter((d) => d.value > 0);

  // Group top algorithms from top_10_riskiest or summary
  const algoCounts = {};
  (summary.top_10_riskiest || []).forEach((item) => {
    const name = item.artefact_name || 'Unknown';
    algoCounts[name] = (algoCounts[name] || 0) + 1;
  });
  const barData = Object.entries(algoCounts).map(([name, count]) => ({
    name,
    count,
  }));

  const handleApplyMosca = async () => {
    if (!scan?.id) return;
    setUpdatingMosca(true);
    try {
      await api.updateMosca(scan.id, {
        x: parseFloat(xVal),
        y: parseFloat(yVal),
        z: parseFloat(zVal),
      });
      const freshSummary = await api.getSummary(scan.id);
      if (onUpdateSummary) onUpdateSummary(freshSummary);
    } catch (err) {
      console.error('Failed to update Mosca parameters:', err);
    } finally {
      setUpdatingMosca(false);
    }
  };

  const handleExport = (format) => {
    if (!scan?.id) return;
    window.open(api.getExportUrl(scan.id, format), '_blank');
  };

  return (
    <div className="space-y-8 pb-12">
      
      {/* Target Title & Export Toolbar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-white tracking-tight">Cryptographic Posture & Quantum Risk</h1>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-indigo-950 text-indigo-300 border border-indigo-800">
              {summary.status?.toUpperCase() || 'COMPLETED'}
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 font-mono truncate max-w-xl">
            Target: {summary.target_path}
          </p>
        </div>

        {/* Export Buttons */}
        <div className="flex items-center flex-wrap gap-2">
          <span className="text-xs font-medium text-slate-400 mr-1 flex items-center gap-1">
            <Download className="w-3.5 h-3.5" /> Export:
          </span>
          <button
            onClick={() => handleExport('cbom')}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors flex items-center gap-1.5"
            title="Download CycloneDX 1.6 Cryptographic Bill of Materials JSON"
          >
            <FileCode className="w-3.5 h-3.5 text-indigo-400" />
            CBOM JSON
          </button>
          <button
            onClick={() => handleExport('pdf')}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors flex items-center gap-1.5"
            title="Download Executive PDF Audit Report"
          >
            <FileText className="w-3.5 h-3.5 text-rose-400" />
            PDF Report
          </button>
          <button
            onClick={() => handleExport('html')}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors flex items-center gap-1.5"
            title="View Interactive HTML Audit Scorecard"
          >
            <TrendingUp className="w-3.5 h-3.5 text-amber-400" />
            HTML Report
          </button>
          <button
            onClick={() => handleExport('csv')}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors flex items-center gap-1.5"
            title="Download CSV Asset Spreadsheet"
          >
            <Table className="w-3.5 h-3.5 text-emerald-400" />
            CSV Export
          </button>
        </div>
      </div>

      {/* Top Key Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        <MetricCard
          title="Quantum Readiness"
          value={`${readinessScore}%`}
          subtitle={readinessScore > 70 ? 'High quantum resilience' : 'Immediate migration required'}
          icon={ShieldCheck}
          color={readinessScore > 70 ? 'emerald' : 'rose'}
        />
        <MetricCard
          title="Discovered Assets"
          value={summary.total_artefacts}
          subtitle="Algorithms, keys, certs, configs"
          icon={Cpu}
          color="indigo"
        />
        <MetricCard
          title="At Quantum Risk (Mosca)"
          value={summary.at_risk_count}
          subtitle={`X + Y > Z (Data exposed to Shor)`}
          icon={ShieldAlert}
          color={summary.at_risk_count > 0 ? 'rose' : 'emerald'}
        />
        <MetricCard
          title="Quantum Vulnerable"
          value={`${summary.percent_quantum_vulnerable}%`}
          subtitle={`${summary.quantum_vulnerable_count} of ${summary.total_artefacts} primitives vulnerable`}
          icon={AlertTriangle}
          color={summary.percent_quantum_vulnerable > 0 ? 'amber' : 'emerald'}
        />
      </div>

      {/* Charts Section: Donut of Risk Levels + Bar Chart of Primitives */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Risk Distribution Donut */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur-md shadow-xl">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-base font-bold text-white">Risk Severity Distribution</h2>
            <span className="text-xs text-slate-400">Total Classified Assets</span>
          </div>

          <div className="h-64 w-full">
            {riskData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={riskData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={85}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {riskData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px' }}
                    itemStyle={{ color: '#f8fafc' }}
                  />
                  <Legend verticalAlign="bottom" height={36} iconType="circle" />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-slate-500 text-sm">
                No risk data to display
              </div>
            )}
          </div>
        </div>

        {/* Algorithm Exposure Bar Chart */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur-md shadow-xl">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-base font-bold text-white">Top Discovered Cryptographic Primitives</h2>
            <span className="text-xs text-slate-400">Occurrences</span>
          </div>

          <div className="h-64 w-full">
            {barData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={barData} margin={{ top: 10, right: 10, left: -20, bottom: 20 }}>
                  <XAxis dataKey="name" stroke="#64748b" fontSize={11} interval={0} angle={-25} textAnchor="end" />
                  <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px' }}
                    itemStyle={{ color: '#f8fafc' }}
                  />
                  <Bar dataKey="count" fill="#6366f1" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-slate-500 text-sm">
                No algorithm data to display
              </div>
            )}
          </div>
        </div>

      </div>

      {/* Mosca's Inequality Live Simulator Card */}
      <div className="bg-gradient-to-br from-slate-900/90 via-slate-900/70 to-indigo-950/40 border border-slate-800 rounded-2xl p-6 shadow-2xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
          <div>
            <div className="flex items-center gap-2">
              <Clock className="w-5 h-5 text-indigo-400" />
              <h2 className="text-lg font-bold text-white">Mosca's Inequality Live Risk Simulator</h2>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Test your organization's exposure: Cryptography is <span className="text-rose-400 font-semibold">AT RISK</span> if <code className="text-indigo-300">X (Shelf-Life) + Y (Migration) &gt; Z (CRQC Arrival)</code>.
            </p>
          </div>

          {/* Live Mosca Status Banner */}
          <div className={`px-4 py-2 rounded-xl border flex items-center gap-3 ${
            isMoscaAtRisk
              ? 'bg-rose-950/60 border-rose-800/80 text-rose-300'
              : 'bg-emerald-950/60 border-emerald-800/80 text-emerald-300'
          }`}>
            <div className={`w-3 h-3 rounded-full ${isMoscaAtRisk ? 'bg-rose-500 animate-ping' : 'bg-emerald-500'}`} />
            <div>
              <div className="text-xs font-bold uppercase tracking-wider">
                {isMoscaAtRisk ? 'Vulnerable: Immediate Action Required' : 'Within Safety Margin'}
              </div>
              <div className="text-[11px] opacity-80">
                X + Y = {moscaSum.toFixed(1)} yrs vs Z = {Number(zVal).toFixed(1)} yrs ({moscaMargin < 0 ? `${Math.abs(moscaMargin).toFixed(1)} yr deficit` : `${moscaMargin.toFixed(1)} yr safety window`})
              </div>
            </div>
          </div>
        </div>

        {/* Sliders Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 bg-slate-950/60 p-5 rounded-xl border border-slate-800/80">
          
          {/* Slider X */}
          <div className="space-y-2">
            <div className="flex justify-between items-center text-xs">
              <span className="font-semibold text-slate-300">X: Data Shelf-Life</span>
              <span className="font-mono text-indigo-400 font-bold">{xVal} years</span>
            </div>
            <input
              type="range"
              min="0"
              max="25"
              step="0.5"
              value={xVal}
              onChange={(e) => setXVal(e.target.value)}
              className="w-full h-1.5 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-indigo-500"
            />
            <p className="text-[11px] text-slate-500">Duration data must remain confidential (HIPAA, PCI, trade secrets).</p>
          </div>

          {/* Slider Y */}
          <div className="space-y-2">
            <div className="flex justify-between items-center text-xs">
              <span className="font-semibold text-slate-300">Y: Migration Timeline</span>
              <span className="font-mono text-amber-400 font-bold">{yVal} years</span>
            </div>
            <input
              type="range"
              min="1"
              max="15"
              step="0.5"
              value={yVal}
              onChange={(e) => setYVal(e.target.value)}
              className="w-full h-1.5 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-amber-500"
            />
            <p className="text-[11px] text-slate-500">Years required to inventory, patch, test, and deploy PQC standards.</p>
          </div>

          {/* Slider Z */}
          <div className="space-y-2">
            <div className="flex justify-between items-center text-xs">
              <span className="font-semibold text-slate-300">Z: Quantum Arrival (CRQC)</span>
              <span className="font-mono text-cyan-400 font-bold">{zVal} years</span>
            </div>
            <input
              type="range"
              min="3"
              max="25"
              step="0.5"
              value={zVal}
              onChange={(e) => setZVal(e.target.value)}
              className="w-full h-1.5 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-cyan-500"
            />
            <p className="text-[11px] text-slate-500">Consensus timeline until Shor's algorithm breaks RSA & ECC (NIST estimate ~2035).</p>
          </div>

        </div>

        {/* Apply Button */}
        <div className="mt-4 flex justify-end">
          <button
            onClick={handleApplyMosca}
            disabled={updatingMosca}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-md transition-all disabled:opacity-50"
          >
            <Sliders className="w-3.5 h-3.5" />
            {updatingMosca ? 'Recalculating Risk...' : 'Recalculate Scan Posture'}
          </button>
        </div>
      </div>

      {/* Top 5 Riskiest Artefacts Preview */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur-md shadow-xl">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-base font-bold text-white">Top Vulnerable Cryptographic Assets</h2>
            <p className="text-xs text-slate-400">Ranked by composite quantum risk score (0-100)</p>
          </div>
          <button
            onClick={onNavigateToArtefacts}
            className="text-xs text-indigo-400 hover:text-indigo-300 font-semibold flex items-center gap-1"
          >
            View all {summary.total_artefacts} items <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Asset</th>
                <th className="py-3 px-4">Risk Level</th>
                <th className="py-3 px-4">Quantum Threat</th>
                <th className="py-3 px-4">Criticality</th>
                <th className="py-3 px-4">Mosca Posture</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {(summary.top_10_riskiest || []).slice(0, 5).map((item, idx) => (
                <tr key={idx} className="hover:bg-slate-800/40 transition-colors">
                  <td className="py-3 px-4 font-semibold text-white font-mono">
                    {item.artefact_name}
                  </td>
                  <td className="py-3 px-4">
                    <RiskBadge level={item.risk_level} />
                  </td>
                  <td className="py-3 px-4">
                    <RiskBadge level={item.is_at_risk ? 'vulnerable_shor' : 'quantum_safe'} type="quantum" />
                  </td>
                  <td className="py-3 px-4 capitalize">
                    {item.criticality}
                  </td>
                  <td className="py-3 px-4 font-mono text-[11px] text-slate-400">
                    Score: <span className="font-bold text-indigo-400">{item.risk_score}</span>/100
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
}
