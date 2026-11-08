import React from 'react';
import { ShieldAlert, Compass, UploadCloud, GitCompare, FolderTree, RefreshCw, Layers } from 'lucide-react';

export function Navbar({ activeTab, setActiveTab, scans = [], selectedScanId, onSelectScan, onRefresh }) {
  const selectedScan = scans.find(s => s.id === selectedScanId);

  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-800 bg-slate-950/80 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex h-16 items-center justify-between gap-4">
          
          {/* Brand Logo & Name */}
          <div className="flex items-center gap-3 cursor-pointer" onClick={() => setActiveTab('dashboard')}>
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-indigo-500 via-indigo-600 to-purple-600 shadow-lg shadow-indigo-500/20 text-white font-black text-lg">
              Ψ
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-extrabold text-white text-lg tracking-tight">ECDAT</span>
                <span className="text-[10px] uppercase font-bold tracking-widest px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                  PQC 1.0
                </span>
              </div>
              <p className="text-[11px] text-slate-400 hidden sm:block">Post-Quantum Cryptographic Discovery</p>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="hidden md:flex items-center space-x-1">
            <button
              onClick={() => setActiveTab('dashboard')}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-medium transition-all ${
                activeTab === 'dashboard'
                  ? 'bg-indigo-600/20 text-indigo-300 border border-indigo-500/30 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Compass className="w-4 h-4" />
              Dashboard
            </button>

            <button
              onClick={() => setActiveTab('artefacts')}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-medium transition-all ${
                activeTab === 'artefacts'
                  ? 'bg-indigo-600/20 text-indigo-300 border border-indigo-500/30 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Layers className="w-4 h-4" />
              Artefacts
            </button>

            <button
              onClick={() => setActiveTab('location')}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-medium transition-all ${
                activeTab === 'location'
                  ? 'bg-indigo-600/20 text-indigo-300 border border-indigo-500/30 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <FolderTree className="w-4 h-4" />
              Risk Map
            </button>

            <button
              onClick={() => setActiveTab('compare')}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-medium transition-all ${
                activeTab === 'compare'
                  ? 'bg-indigo-600/20 text-indigo-300 border border-indigo-500/30 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <GitCompare className="w-4 h-4" />
              Compare Scans
            </button>

            <button
              onClick={() => setActiveTab('upload')}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-medium transition-all ${
                activeTab === 'upload'
                  ? 'bg-indigo-600 text-white shadow-md shadow-indigo-600/30'
                  : 'text-slate-300 bg-slate-800/80 hover:bg-slate-800 border border-slate-700/80'
              }`}
            >
              <UploadCloud className="w-4 h-4" />
              New Scan
            </button>
          </nav>

          {/* Right Action: Active Scan Selector & Refresh */}
          <div className="flex items-center gap-3">
            {scans.length > 0 && (
              <div className="relative">
                <select
                  value={selectedScanId || ''}
                  onChange={(e) => onSelectScan(e.target.value)}
                  className="bg-slate-900 border border-slate-700 text-slate-200 text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:ring-1 focus:ring-indigo-500 max-w-[200px] truncate"
                >
                  {scans.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.target_path.split(/[\\/]/).pop() || s.id.slice(0, 8)} ({s.total_artefacts} items)
                    </option>
                  ))}
                </select>
              </div>
            )}

            <button
              onClick={onRefresh}
              title="Refresh Data"
              className="p-2 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
          </div>

        </div>
      </div>
    </header>
  );
}
