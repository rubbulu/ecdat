import React, { useState, useRef } from 'react';
import { Upload, GitBranch, Folder, ArrowRight, CheckCircle2, AlertCircle, Loader2 } from 'lucide-react';
import { api } from '../api/client';

export function UploadPage({ onScanComplete }) {
  const [activeTab, setActiveTab] = useState('zip'); // 'zip' | 'git' | 'local'
  const [file, setFile] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const [gitUrl, setGitUrl] = useState('');
  const [localPath, setLocalPath] = useState('sample_targets/vulnerable_app');
  const [loading, setLoading] = useState(false);
  const [progressStatus, setProgressStatus] = useState('');
  const [errorMessage, setErrorMessage] = useState('');
  const fileInputRef = useRef(null);

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setFile(e.dataTransfer.files[0]);
    }
  };

  const pollScanStatus = async (scanId) => {
    setProgressStatus('Executing cryptographic discovery across source, certs, and configs...');
    const maxAttempts = 60;
    let attempts = 0;

    const interval = setInterval(async () => {
      attempts++;
      try {
        const scan = await api.getScan(scanId);
        if (scan.status === 'completed') {
          clearInterval(interval);
          setLoading(false);
          setProgressStatus('Scan complete!');
          if (onScanComplete) onScanComplete(scanId);
        } else if (scan.status === 'failed') {
          clearInterval(interval);
          setLoading(false);
          setErrorMessage(scan.metadata?.error || 'Scan failed to complete.');
        } else {
          setProgressStatus(`Analyzing target artefacts... (${attempts * 2}s)`);
        }
      } catch (err) {
        clearInterval(interval);
        setLoading(false);
        setErrorMessage(err.message);
      }

      if (attempts >= maxAttempts) {
        clearInterval(interval);
        setLoading(false);
        setErrorMessage('Scan timed out after 2 minutes.');
      }
    }, 2000);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMessage('');
    setLoading(true);
    setProgressStatus('Initializing discovery engine...');

    try {
      let result;
      if (activeTab === 'zip') {
        if (!file) throw new Error('Please select or drop a zip/archive file first.');
        result = await api.startScan({ file });
      } else if (activeTab === 'git') {
        if (!gitUrl.trim()) throw new Error('Please enter a valid Git repository URL.');
        result = await api.startScan({ git_url: gitUrl.trim() });
      } else if (activeTab === 'local') {
        if (!localPath.trim()) throw new Error('Please enter a local filesystem path.');
        result = await api.startScan({ local_path: localPath.trim() });
      }

      if (result && result.id) {
        pollScanStatus(result.id);
      }
    } catch (err) {
      setLoading(false);
      setErrorMessage(err.message);
    }
  };

  return (
    <div className="max-w-4xl mx-auto py-8 px-4">
      {/* Header */}
      <div className="text-center mb-10">
        <h1 className="text-3xl font-extrabold text-white tracking-tight sm:text-4xl">
          Scan Codebase for Cryptographic Assets
        </h1>
        <p className="mt-3 text-base text-slate-400 max-w-2xl mx-auto">
          Unpack repositories, container images, and archives to discover algorithms, keys, certificates,
          and evaluate exposure to quantum cryptanalysis via Mosca's inequality.
        </p>
      </div>

      {/* Target Source Tab Switcher */}
      <div className="flex border-b border-slate-800 mb-8 justify-center">
        <button
          onClick={() => setActiveTab('zip')}
          className={`flex items-center gap-2 py-3 px-6 text-sm font-semibold border-b-2 transition-colors ${
            activeTab === 'zip'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Upload className="w-4 h-4" />
          Archive Upload (Zip/Tar)
        </button>
        <button
          onClick={() => setActiveTab('git')}
          className={`flex items-center gap-2 py-3 px-6 text-sm font-semibold border-b-2 transition-colors ${
            activeTab === 'git'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <GitBranch className="w-4 h-4" />
          Git Repository URL
        </button>
        <button
          onClick={() => setActiveTab('local')}
          className={`flex items-center gap-2 py-3 px-6 text-sm font-semibold border-b-2 transition-colors ${
            activeTab === 'local'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Folder className="w-4 h-4" />
          Local Directory / Sample App
        </button>
      </div>

      {/* Main Upload Box */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-8 backdrop-blur-md shadow-2xl">
        <form onSubmit={handleSubmit}>

          {/* 1. Zip Drag and Drop */}
          {activeTab === 'zip' && (
            <div
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`border-2 border-dashed rounded-xl p-10 text-center cursor-pointer transition-all ${
                isDragging
                  ? 'border-indigo-500 bg-indigo-500/10'
                  : 'border-slate-700 hover:border-slate-600 bg-slate-950/40'
              }`}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".zip,.tar,.gz"
                className="hidden"
                onChange={(e) => e.target.files && setFile(e.target.files[0])}
              />
              <div className="flex flex-col items-center justify-center">
                <div className="p-4 rounded-full bg-indigo-600/20 text-indigo-400 mb-4">
                  <Upload className="w-8 h-8" />
                </div>
                {file ? (
                  <div>
                    <p className="text-sm font-semibold text-white">{file.name}</p>
                    <p className="text-xs text-slate-400 mt-1">{(file.size / 1024 / 1024).toFixed(2)} MB</p>
                    <span className="mt-3 inline-block text-xs font-semibold text-indigo-400 bg-indigo-950/60 px-3 py-1 rounded-full border border-indigo-800/40">
                      Click or drop another file to replace
                    </span>
                  </div>
                ) : (
                  <div>
                    <p className="text-base font-semibold text-slate-200">
                      Drop your codebase archive or Docker tarball here
                    </p>
                    <p className="text-xs text-slate-400 mt-1">
                      Supports .zip, .tar, .tar.gz (Max 50MB, Zip-Slip Protected)
                    </p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* 2. Git URL Input */}
          {activeTab === 'git' && (
            <div className="space-y-4">
              <label className="block text-sm font-medium text-slate-300">
                Git Repository Clone URL
              </label>
              <div className="relative">
                <input
                  type="text"
                  placeholder="https://github.com/org/crypto-service.git"
                  value={gitUrl}
                  onChange={(e) => setGitUrl(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-3.5 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 font-mono"
                />
              </div>
              <p className="text-xs text-slate-400">
                Will perform a shallow depth-1 clone into an isolated sandbox environment.
              </p>
            </div>
          )}

          {/* 3. Local Path Input */}
          {activeTab === 'local' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <label className="block text-sm font-medium text-slate-300">
                  Server Local Directory Path
                </label>
                <button
                  type="button"
                  onClick={() => setLocalPath('sample_targets/vulnerable_app')}
                  className="text-xs text-indigo-400 hover:text-indigo-300 font-medium underline"
                >
                  Use Built-in Vulnerable App
                </button>
              </div>
              <input
                type="text"
                placeholder="sample_targets/vulnerable_app"
                value={localPath}
                onChange={(e) => setLocalPath(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-3.5 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 font-mono"
              />
              <p className="text-xs text-slate-400">
                Directly scans an existing repository or target folder on disk.
              </p>
            </div>
          )}

          {/* Error Message */}
          {errorMessage && (
            <div className="mt-6 p-4 rounded-xl bg-rose-950/50 border border-rose-800/60 flex items-start gap-3 text-rose-300 text-sm">
              <AlertCircle className="w-5 h-5 flex-shrink-0 mt-0.5" />
              <div>{errorMessage}</div>
            </div>
          )}

          {/* Scanning Progress */}
          {loading && (
            <div className="mt-6 p-5 rounded-xl bg-indigo-950/30 border border-indigo-800/40">
              <div className="flex items-center gap-3 text-indigo-300 text-sm font-medium">
                <Loader2 className="w-5 h-5 animate-spin text-indigo-400" />
                <span>{progressStatus}</span>
              </div>
              <div className="w-full bg-slate-800 rounded-full h-1.5 mt-3 overflow-hidden">
                <div className="bg-indigo-500 h-1.5 rounded-full animate-pulse w-3/4"></div>
              </div>
            </div>
          )}

          {/* Submit Button */}
          <div className="mt-8 flex justify-end">
            <button
              type="submit"
              disabled={loading}
              className="flex items-center gap-2 px-6 py-3 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-sm transition-all shadow-lg shadow-indigo-600/30 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'Discovering Cryptography...' : 'Launch Cryptographic Scan'}
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>

        </form>
      </div>
    </div>
  );
}
