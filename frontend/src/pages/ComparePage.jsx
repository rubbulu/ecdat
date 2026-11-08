import React, { useState, useEffect } from 'react';
import { GitCompare, ArrowRight, ShieldCheck, ShieldAlert, TrendingUp, TrendingDown, Minus } from 'lucide-react';
import { MetricCard } from '../components/MetricCard';
import { RiskBadge } from '../components/RiskBadge';
import { api } from '../api/client';

export function ComparePage({ scans = [] }) {
  const [scanAId, setScanAId] = useState(scans[1]?.id || scans[0]?.id || '');
  const [scanBId, setScanBId] = useState(scans[0]?.id || '');
  const [summaryA, setSummaryA] = useState(null);
  const [summaryB, setSummaryB] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!scanAId || !scanBId) return;
    setLoading(true);
    Promise.all([api.getSummary(scanAId), api.getSummary(scanBId)])
      .then(([a, b]) => {
        setSummaryA(a);
        setSummaryB(b);
      })
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  }, [scanAId, scanBId]);

  const scoreA = summaryA ? Math.max(0, Math.round(100 - (summaryA.percent_quantum_vulnerable || 0))) : 0;
  const scoreB = summaryB ? Math.max(0, Math.round(100 - (summaryB.percent_quantum_vulnerable || 0))) : 0;
  const scoreDelta = scoreB - scoreA;

  const atRiskA = summaryA?.at_risk_count || 0;
  const atRiskB = summaryB?.at_risk_count || 0;
  const atRiskDelta = atRiskB - atRiskA;

  const critA = (summaryA?.counts_by_risk_level?.critical || 0) + (summaryA?.counts_by_risk_level?.high || 0);
  const critB = (summaryB?.counts_by_risk_level?.critical || 0) + (summaryB?.counts_by_risk_level?.high || 0);
  const critDelta = critB - critA;

  return (
    <div className="space-y-8 pb-12">
      
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Cryptographic Migration Comparison</h1>
        <p className="text-xs text-slate-400 mt-1">
          Benchmark and verify quantum risk reduction between two scan snapshots (Baseline vs Post-Migration).
        </p>
      </div>

      {/* Scan Selector Controls */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 bg-slate-900/60 p-6 rounded-2xl border border-slate-800">
        <div>
          <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
            Baseline Scan A (Pre-Migration)
          </label>
          <select
            value={scanAId}
            onChange={(e) => setScanAId(e.target.value)}
            className="w-full bg-slate-950 border border-slate-700 text-slate-200 text-xs rounded-xl p-3 focus:outline-none focus:ring-1 focus:ring-indigo-500 font-mono"
          >
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                {s.target_path.split(/[\\/]/).pop()} — {new Date(s.created_at).toLocaleDateString()} ({s.id.slice(0, 8)})
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
            Target Scan B (Post-Migration Snapshot)
          </label>
          <select
            value={scanBId}
            onChange={(e) => setScanBId(e.target.value)}
            className="w-full bg-slate-950 border border-slate-700 text-slate-200 text-xs rounded-xl p-3 focus:outline-none focus:ring-1 focus:ring-indigo-500 font-mono"
          >
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                {s.target_path.split(/[\\/]/).pop()} — {new Date(s.created_at).toLocaleDateString()} ({s.id.slice(0, 8)})
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Delta Metrics Overview */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        
        {/* Readiness Improvement */}
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/60">
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            Quantum Readiness Delta
          </div>
          <div className="flex items-baseline gap-3 mt-3">
            <span className="text-3xl font-extrabold text-white">{scoreB}%</span>
            <span className={`text-sm font-bold flex items-center gap-1 ${
              scoreDelta > 0 ? 'text-emerald-400' : scoreDelta < 0 ? 'text-rose-400' : 'text-slate-400'
            }`}>
              {scoreDelta > 0 ? <TrendingUp className="w-4 h-4" /> : scoreDelta < 0 ? <TrendingDown className="w-4 h-4" /> : <Minus className="w-4 h-4" />}
              {scoreDelta > 0 ? `+${scoreDelta}%` : `${scoreDelta}%`}
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">From baseline {scoreA}%</p>
        </div>

        {/* At-Risk Assets Reduction */}
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/60">
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            Mosca At-Risk Asset Reduction
          </div>
          <div className="flex items-baseline gap-3 mt-3">
            <span className="text-3xl font-extrabold text-white">{atRiskB}</span>
            <span className={`text-sm font-bold flex items-center gap-1 ${
              atRiskDelta < 0 ? 'text-emerald-400' : atRiskDelta > 0 ? 'text-rose-400' : 'text-slate-400'
            }`}>
              {atRiskDelta < 0 ? <TrendingDown className="w-4 h-4" /> : atRiskDelta > 0 ? <TrendingUp className="w-4 h-4" /> : <Minus className="w-4 h-4" />}
              {atRiskDelta} items
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">From baseline {atRiskA} items</p>
        </div>

        {/* Critical & High Exposure Reduction */}
        <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/60">
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            Critical & High Severity Delta
          </div>
          <div className="flex items-baseline gap-3 mt-3">
            <span className="text-3xl font-extrabold text-white">{critB}</span>
            <span className={`text-sm font-bold flex items-center gap-1 ${
              critDelta < 0 ? 'text-emerald-400' : critDelta > 0 ? 'text-rose-400' : 'text-slate-400'
            }`}>
              {critDelta < 0 ? <TrendingDown className="w-4 h-4" /> : critDelta > 0 ? <TrendingUp className="w-4 h-4" /> : <Minus className="w-4 h-4" />}
              {critDelta} items
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">From baseline {critA} items</p>
        </div>

      </div>

      {/* Side-by-Side Detailed Posture Breakdown */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        
        {/* Baseline Card */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-base font-bold text-white">Baseline Posture (Scan A)</h3>
            <span className="text-xs font-mono text-slate-400">{summaryA?.scan_id?.slice(0, 8)}</span>
          </div>

          <div className="space-y-3 text-xs">
            <div className="flex justify-between py-1.5 border-b border-slate-800/60">
              <span className="text-slate-400">Total Discovered Assets:</span>
              <span className="font-bold text-white font-mono">{summaryA?.total_artefacts || 0}</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-slate-800/60">
              <span className="text-slate-400">Quantum Vulnerable %:</span>
              <span className="font-bold text-rose-400 font-mono">{summaryA?.percent_quantum_vulnerable || 0}%</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-slate-800/60">
              <span className="text-slate-400">Critical Risks:</span>
              <span className="font-bold text-red-400 font-mono">{summaryA?.counts_by_risk_level?.critical || 0}</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-slate-800/60">
              <span className="text-slate-400">High Risks:</span>
              <span className="font-bold text-orange-400 font-mono">{summaryA?.counts_by_risk_level?.high || 0}</span>
            </div>
            <div className="flex justify-between py-1.5">
              <span className="text-slate-400">Medium Risks:</span>
              <span className="font-bold text-amber-400 font-mono">{summaryA?.counts_by_risk_level?.medium || 0}</span>
            </div>
          </div>
        </div>

        {/* Migrated Card */}
        <div className="bg-slate-900/60 border border-indigo-900/50 rounded-2xl p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-indigo-900/40 pb-3">
            <h3 className="text-base font-bold text-indigo-300">Target Posture (Scan B)</h3>
            <span className="text-xs font-mono text-indigo-400">{summaryB?.scan_id?.slice(0, 8)}</span>
          </div>

          <div className="space-y-3 text-xs">
            <div className="flex justify-between py-1.5 border-b border-slate-800/60">
              <span className="text-slate-400">Total Discovered Assets:</span>
              <span className="font-bold text-white font-mono">{summaryB?.total_artefacts || 0}</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-slate-800/60">
              <span className="text-slate-400">Quantum Vulnerable %:</span>
              <span className="font-bold text-emerald-400 font-mono">{summaryB?.percent_quantum_vulnerable || 0}%</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-slate-800/60">
              <span className="text-slate-400">Critical Risks:</span>
              <span className="font-bold text-white font-mono">{summaryB?.counts_by_risk_level?.critical || 0}</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-slate-800/60">
              <span className="text-slate-400">High Risks:</span>
              <span className="font-bold text-white font-mono">{summaryB?.counts_by_risk_level?.high || 0}</span>
            </div>
            <div className="flex justify-between py-1.5">
              <span className="text-slate-400">Medium Risks:</span>
              <span className="font-bold text-white font-mono">{summaryB?.counts_by_risk_level?.medium || 0}</span>
            </div>
          </div>
        </div>

      </div>

    </div>
  );
}
