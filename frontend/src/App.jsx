import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { DashboardPage } from './pages/DashboardPage';
import { ArtefactsPage } from './pages/ArtefactsPage';
import { LocationViewPage } from './pages/LocationViewPage';
import { ComparePage } from './pages/ComparePage';
import { UploadPage } from './pages/UploadPage';
import { api } from './api/client';
import { ShieldCheck, AlertCircle, RefreshCw } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [scans, setScans] = useState([]);
  const [selectedScanId, setSelectedScanId] = useState('');
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadScans = async (preferScanId = null) => {
    setLoading(true);
    setError(null);
    try {
      const scanList = await api.getScans();
      setScans(scanList || []);

      if (scanList && scanList.length > 0) {
        const targetId = preferScanId || selectedScanId || scanList[0].id;
        setSelectedScanId(targetId);
        const summ = await api.getSummary(targetId);
        setSummary(summ);
      } else {
        // No scans yet, switch to upload tab
        setActiveTab('upload');
      }
    } catch (err) {
      console.error('Failed to load scans:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadScans();
  }, []);

  const handleSelectScan = async (scanId) => {
    setSelectedScanId(scanId);
    setLoading(true);
    try {
      const summ = await api.getSummary(scanId);
      setSummary(summ);
    } catch (err) {
      console.error(err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleScanComplete = (newScanId) => {
    loadScans(newScanId);
    setActiveTab('dashboard');
  };

  const selectedScan = scans.find((s) => s.id === selectedScanId);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-indigo-500 selection:text-white">
      
      {/* Top Navbar */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        scans={scans}
        selectedScanId={selectedScanId}
        onSelectScan={handleSelectScan}
        onRefresh={() => loadScans(selectedScanId)}
      />

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 pt-8">
        {error && (
          <div className="mb-6 p-4 rounded-xl bg-rose-950/60 border border-rose-800 text-rose-300 text-xs flex items-center justify-between">
            <div className="flex items-center gap-2">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              <span>{error}</span>
            </div>
            <button
              onClick={() => loadScans(selectedScanId)}
              className="px-2.5 py-1 rounded bg-rose-900/80 hover:bg-rose-800 font-semibold flex items-center gap-1"
            >
              <RefreshCw className="w-3 h-3" /> Retry
            </button>
          </div>
        )}

        {/* Tab Pages */}
        {activeTab === 'upload' && (
          <UploadPage onScanComplete={handleScanComplete} />
        )}

        {activeTab === 'dashboard' && (
          <DashboardPage
            scan={selectedScan}
            summary={summary}
            onUpdateSummary={setSummary}
            onNavigateToArtefacts={() => setActiveTab('artefacts')}
          />
        )}

        {activeTab === 'artefacts' && (
          <ArtefactsPage scanId={selectedScanId} />
        )}

        {activeTab === 'location' && (
          <LocationViewPage
            scanId={selectedScanId}
            onSelectFile={() => setActiveTab('artefacts')}
          />
        )}

        {activeTab === 'compare' && (
          <ComparePage scans={scans} />
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/80 py-6 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="font-bold text-slate-400">ECDAT</span>
            <span>•</span>
            <span>Enterprise Cryptographic Discovery & Post-Quantum Analysis Tool</span>
          </div>
          <div>
            <span>Threws Odyssey 2026 Hackathon — Cybersecurity Track</span>
          </div>
        </div>
      </footer>

    </div>
  );
}
