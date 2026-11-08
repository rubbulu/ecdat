import React, { useState, useEffect } from 'react';
import {
  Search,
  Filter,
  ChevronDown,
  ChevronRight,
  ShieldAlert,
  ArrowRight,
  Edit3,
  Check,
  X,
  Code2,
  FileCode2,
  Cpu,
  Layers,
  Sparkles,
} from 'lucide-react';
import { RiskBadge } from '../components/RiskBadge';
import { api } from '../api/client';

export function ArtefactsPage({ scanId }) {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [expandedId, setExpandedId] = useState(null);

  // Filters state
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedType, setSelectedType] = useState('');
  const [selectedRisk, setSelectedRisk] = useState('');
  const [selectedQuantum, setSelectedQuantum] = useState('');
  const [page, setPage] = useState(0);
  const limit = 25;

  // Inline override editing state
  const [editingId, setEditingId] = useState(null);
  const [editLifetime, setEditLifetime] = useState('long');
  const [editCriticality, setEditCriticality] = useState('high');
  const [editX, setEditX] = useState(10);
  const [savingOverride, setSavingOverride] = useState(false);

  const loadArtefacts = async () => {
    if (!scanId) return;
    setLoading(true);
    try {
      const data = await api.getArtefacts(scanId, {
        type: selectedType,
        risk_level: selectedRisk,
        quantum_status: selectedQuantum,
        limit,
        offset: page * limit,
      });
      setItems(data.items || []);
      setTotal(data.total || 0);
    } catch (err) {
      console.error('Failed to load artefacts:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    setPage(0);
  }, [scanId, selectedType, selectedRisk, selectedQuantum]);

  useEffect(() => {
    loadArtefacts();
  }, [scanId, selectedType, selectedRisk, selectedQuantum, page]);

  // Client-side search filtering
  const filteredItems = items.filter((item) => {
    if (!searchTerm.trim()) return true;
    const term = searchTerm.toLowerCase();
    const nameMatch = item.artefact.name?.toLowerCase().includes(term);
    const fileMatch = item.artefact.location?.file?.toLowerCase().includes(term);
    const typeMatch = item.artefact.type?.toLowerCase().includes(term);
    return nameMatch || fileMatch || typeMatch;
  });

  const toggleRow = (id) => {
    setExpandedId(expandedId === id ? null : id);
  };

  const startEdit = (item) => {
    setEditingId(item.artefact.id);
    setEditLifetime(item.risk.lifetime_class || 'medium');
    setEditCriticality(item.risk.criticality || 'medium');
    setEditX(item.risk.x || 5);
  };

  const cancelEdit = () => {
    setEditingId(null);
  };

  const saveOverride = async (artefactId) => {
    setSavingOverride(true);
    try {
      const updated = await api.overrideArtefact(artefactId, {
        lifetime: editLifetime,
        criticality: editCriticality,
        x: parseFloat(editX),
      });

      // Update state in place
      setItems((prev) =>
        prev.map((it) =>
          it.artefact.id === artefactId
            ? {
                ...it,
                artefact: updated.artefact,
                risk: updated.risk,
                recommendation: updated.recommendation,
              }
            : it
        )
      );
      setEditingId(null);
    } catch (err) {
      alert(`Failed to save override: ${err.message}`);
    } finally {
      setSavingOverride(false);
    }
  };

  return (
    <div className="space-y-6 pb-12">
      
      {/* Header & Search / Filter Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Cryptographic Artefact Explorer</h1>
          <p className="text-xs text-slate-400 mt-1">
            Browse discovered algorithms, keys, certificates, and code evidence across all scanner vectors.
          </p>
        </div>

        {/* Global Search Bar */}
        <div className="relative w-full md:w-80">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
          <input
            type="text"
            placeholder="Search by algorithm or file..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-slate-900 border border-slate-700 rounded-xl pl-9 pr-4 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          />
        </div>
      </div>

      {/* Filter Row */}
      <div className="flex flex-wrap items-center gap-3 bg-slate-900/60 p-3.5 rounded-xl border border-slate-800 text-xs">
        <div className="flex items-center gap-1.5 text-slate-400 font-semibold uppercase tracking-wider mr-2">
          <Filter className="w-3.5 h-3.5" /> Filters:
        </div>

        {/* Filter: Asset Type */}
        <select
          value={selectedType}
          onChange={(e) => setSelectedType(e.target.value)}
          className="bg-slate-950 border border-slate-700 text-slate-300 rounded-lg px-2.5 py-1.5 focus:outline-none"
        >
          <option value="">All Types</option>
          <option value="algorithm">Algorithm</option>
          <option value="key">Key</option>
          <option value="certificate">Certificate</option>
          <option value="protocol">Protocol</option>
          <option value="library">Library</option>
        </select>

        {/* Filter: Risk Level */}
        <select
          value={selectedRisk}
          onChange={(e) => setSelectedRisk(e.target.value)}
          className="bg-slate-950 border border-slate-700 text-slate-300 rounded-lg px-2.5 py-1.5 focus:outline-none"
        >
          <option value="">All Risk Levels</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>

        {/* Filter: Quantum Status */}
        <select
          value={selectedQuantum}
          onChange={(e) => setSelectedQuantum(e.target.value)}
          className="bg-slate-950 border border-slate-700 text-slate-300 rounded-lg px-2.5 py-1.5 focus:outline-none"
        >
          <option value="">All Quantum Statuses</option>
          <option value="vulnerable_shor">Vulnerable to Shor</option>
          <option value="weakened_grover">Weakened by Grover</option>
          <option value="classically_broken">Classically Broken</option>
          <option value="quantum_safe">Quantum Safe</option>
        </select>

        {(selectedType || selectedRisk || selectedQuantum || searchTerm) && (
          <button
            onClick={() => {
              setSelectedType('');
              setSelectedRisk('');
              setSelectedQuantum('');
              setSearchTerm('');
            }}
            className="text-indigo-400 hover:text-indigo-300 font-medium ml-auto"
          >
            Clear Filters
          </button>
        )}
      </div>

      {/* Main Table */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden shadow-2xl backdrop-blur-md">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-3 px-3 w-8"></th>
                <th className="py-3 px-4">Cryptographic Primitive</th>
                <th className="py-3 px-4">Asset Type</th>
                <th className="py-3 px-4">Location (File:Line)</th>
                <th className="py-3 px-4">Quantum Threat</th>
                <th className="py-3 px-4">Criticality</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {loading ? (
                <tr>
                  <td colSpan="8" className="text-center py-12 text-slate-500">
                    Loading cryptographic assets...
                  </td>
                </tr>
              ) : filteredItems.length === 0 ? (
                <tr>
                  <td colSpan="8" className="text-center py-12 text-slate-500">
                    No matching cryptographic artefacts found for the active filters.
                  </td>
                </tr>
              ) : (
                filteredItems.map(({ artefact, risk, recommendation }) => {
                  const isExpanded = expandedId === artefact.id;
                  const isEditing = editingId === artefact.id;

                  return (
                    <React.Fragment key={artefact.id}>
                      <tr
                        onClick={() => toggleRow(artefact.id)}
                        className={`hover:bg-slate-800/40 cursor-pointer transition-colors ${
                          isExpanded ? 'bg-slate-800/30' : ''
                        }`}
                      >
                        <td className="py-3 px-3 text-slate-500">
                          {isExpanded ? (
                            <ChevronDown className="w-4 h-4 text-indigo-400" />
                          ) : (
                            <ChevronRight className="w-4 h-4" />
                          )}
                        </td>
                        <td className="py-3 px-4 font-mono font-semibold text-white">
                          <div className="flex items-center gap-2">
                            <span>{artefact.name}</span>
                            {artefact.key_size && (
                              <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 font-sans">
                                {artefact.key_size} bit
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="py-3 px-4 capitalize text-slate-300">
                          {artefact.type}
                        </td>
                        <td className="py-3 px-4 font-mono text-[11px] text-slate-400 max-w-xs truncate" title={artefact.location?.file}>
                          {artefact.location?.file?.split(/[\\/]/).slice(-2).join('/')}:{artefact.location?.line}
                        </td>
                        <td className="py-3 px-4">
                          <RiskBadge level={artefact.quantum_status} type="quantum" />
                        </td>
                        <td className="py-3 px-4 capitalize">
                          <span className={`px-2 py-0.5 rounded text-[11px] font-medium ${
                            risk.criticality === 'critical' ? 'bg-red-950/60 text-red-300 border border-red-800' :
                            risk.criticality === 'high' ? 'bg-orange-950/60 text-orange-300 border border-orange-800' :
                            'bg-slate-800 text-slate-300'
                          }`}>
                            {risk.criticality}
                          </span>
                        </td>
                        <td className="py-3 px-4 font-mono">
                          <div className="flex items-center gap-1.5">
                            <RiskBadge level={risk.risk_level} />
                            <span className="text-[11px] font-bold text-slate-300">({risk.risk_score})</span>
                          </div>
                        </td>
                        <td className="py-3 px-4 text-right">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              startEdit({ artefact, risk });
                              setExpandedId(artefact.id);
                            }}
                            className="p-1 rounded text-slate-400 hover:text-indigo-400 hover:bg-slate-800"
                            title="Override asset risk parameters"
                          >
                            <Edit3 className="w-3.5 h-3.5" />
                          </button>
                        </td>
                      </tr>

                      {/* Row Drill-Down View */}
                      {isExpanded && (
                        <tr className="bg-slate-950/90 border-b border-indigo-900/30">
                          <td colSpan="8" className="p-6 space-y-5">
                            
                            {/* Threat Explanation Banner */}
                            <div className="flex items-start gap-3 p-4 rounded-xl bg-slate-900 border border-slate-800">
                              <ShieldAlert className="w-5 h-5 text-indigo-400 flex-shrink-0 mt-0.5" />
                              <div className="space-y-1">
                                <h4 className="text-xs font-bold uppercase tracking-wider text-indigo-300">
                                  Quantum Vulnerability Analysis
                                </h4>
                                <p className="text-xs text-slate-300 leading-relaxed font-sans">
                                  {risk.explanation}
                                </p>
                              </div>
                            </div>

                            {/* Two-Column Grid: Code Evidence & PQC Migration Advisory */}
                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                              
                              {/* 1. Code Evidence */}
                              <div className="space-y-2">
                                <div className="flex items-center justify-between text-xs text-slate-400">
                                  <span className="font-semibold flex items-center gap-1.5">
                                    <Code2 className="w-4 h-4 text-slate-400" />
                                    Detected Code Snippet & Context
                                  </span>
                                  <span className="font-mono text-[11px]">
                                    {artefact.detection_method} ({Math.round(artefact.confidence * 100)}% conf)
                                  </span>
                                </div>
                                <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 font-mono text-xs text-indigo-200 overflow-x-auto whitespace-pre">
                                  {artefact.evidence || 'No direct evidence snippet captured.'}
                                </div>
                                <p className="text-[11px] text-slate-500 font-mono">
                                  Exact Location: {artefact.location?.file} (line {artefact.location?.line})
                                </p>
                              </div>

                              {/* 2. NIST PQC Recommendation */}
                              <div className="space-y-2 bg-gradient-to-br from-indigo-950/30 to-purple-950/20 p-4 rounded-xl border border-indigo-900/40">
                                <div className="flex items-center justify-between">
                                  <span className="text-xs font-bold uppercase tracking-wider text-indigo-300 flex items-center gap-1.5">
                                    <Sparkles className="w-3.5 h-3.5 text-indigo-400" />
                                    NIST Migration Recommendation
                                  </span>
                                  <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                                    Effort: {recommendation?.migration_effort}
                                  </span>
                                </div>

                                <div className="flex items-center gap-2 mt-2">
                                  <span className="text-xs text-slate-400">Current:</span>
                                  <span className="font-mono text-xs text-rose-300 font-semibold">{artefact.name}</span>
                                  <ArrowRight className="w-3.5 h-3.5 text-slate-500" />
                                  <span className="text-xs text-slate-400">Upgrade:</span>
                                  <span className="font-mono text-xs text-emerald-400 font-bold bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800">
                                    {recommendation?.replacement || artefact.nist_replacement || 'PQC Primitive'}
                                  </span>
                                </div>

                                <p className="text-xs text-slate-300 leading-relaxed mt-2">
                                  {recommendation?.guidance || artefact.notes || 'Transition to quantum-resistant primitives compliant with NIST FIPS 203/204.'}
                                </p>

                                {recommendation?.size_impact && (
                                  <div className="text-[11px] text-slate-400 border-t border-slate-800/80 pt-2 mt-2">
                                    <span className="font-semibold text-slate-300">Size Impact:</span> {recommendation.size_impact}
                                  </div>
                                )}

                                {recommendation?.library_suggestion?.length > 0 && (
                                  <div className="flex items-center gap-1.5 text-[11px] text-slate-400 mt-1">
                                    <span className="font-semibold text-slate-300">Suggested Libraries:</span>
                                    {recommendation.library_suggestion.map((lib, i) => (
                                      <span key={i} className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 font-mono text-[10px] text-indigo-300">
                                        {lib}
                                      </span>
                                    ))}
                                  </div>
                                )}
                              </div>

                            </div>

                            {/* 3. Inline Risk Override Form */}
                            {isEditing && (
                              <div className="mt-4 p-4 rounded-xl bg-slate-900 border border-indigo-500/50 space-y-3">
                                <div className="flex items-center justify-between text-xs font-bold text-white uppercase tracking-wider">
                                  <span>Custom Posture Overrides for {artefact.name}</span>
                                  <button onClick={cancelEdit} className="text-slate-400 hover:text-white">
                                    <X className="w-4 h-4" />
                                  </button>
                                </div>

                                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
                                  <div>
                                    <label className="block text-slate-400 mb-1">Lifetime Class</label>
                                    <select
                                      value={editLifetime}
                                      onChange={(e) => setEditLifetime(e.target.value)}
                                      className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-slate-200"
                                    >
                                      <option value="short">Short (&lt;2 years, session)</option>
                                      <option value="medium">Medium (2-10 years, certs)</option>
                                      <option value="long">Long (&gt;10 years, root CA / archive)</option>
                                    </select>
                                  </div>

                                  <div>
                                    <label className="block text-slate-400 mb-1">Business Criticality</label>
                                    <select
                                      value={editCriticality}
                                      onChange={(e) => setEditCriticality(e.target.value)}
                                      className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-slate-200"
                                    >
                                      <option value="low">Low (Non-production, test)</option>
                                      <option value="medium">Medium (Internal standard)</option>
                                      <option value="high">High (Customer sensitive)</option>
                                      <option value="critical">Critical (Core auth, financial)</option>
                                    </select>
                                  </div>

                                  <div>
                                    <label className="block text-slate-400 mb-1">Data Shelf-Life X (Years)</label>
                                    <input
                                      type="number"
                                      min="0"
                                      max="50"
                                      step="1"
                                      value={editX}
                                      onChange={(e) => setEditX(e.target.value)}
                                      className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-slate-200 font-mono"
                                    />
                                  </div>
                                </div>

                                <div className="flex justify-end gap-2 pt-2">
                                  <button
                                    onClick={cancelEdit}
                                    className="px-3 py-1.5 rounded-lg text-xs bg-slate-800 text-slate-300 hover:bg-slate-700"
                                  >
                                    Cancel
                                  </button>
                                  <button
                                    onClick={() => saveOverride(artefact.id)}
                                    disabled={savingOverride}
                                    className="px-4 py-1.5 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white flex items-center gap-1.5 disabled:opacity-50"
                                  >
                                    <Check className="w-3.5 h-3.5" />
                                    {savingOverride ? 'Recalculating...' : 'Save & Recalculate'}
                                  </button>
                                </div>
                              </div>
                            )}

                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Footer */}
        <div className="flex items-center justify-between p-4 border-t border-slate-800 text-xs text-slate-400 bg-slate-950/60">
          <div>
            Showing {filteredItems.length} of {total} discovered artefacts
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage(Math.max(0, page - 1))}
              disabled={page === 0}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Previous
            </button>
            <span className="font-mono">
              Page {page + 1} of {Math.max(1, Math.ceil(total / limit))}
            </span>
            <button
              onClick={() => setPage(page + 1)}
              disabled={(page + 1) * limit >= total}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Next
            </button>
          </div>
        </div>
      </div>

    </div>
  );
}
