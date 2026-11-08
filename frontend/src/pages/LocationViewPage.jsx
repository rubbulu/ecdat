import React, { useState, useEffect } from 'react';
import { FolderTree, FileCode, Layers, ShieldAlert, AlertTriangle, ArrowRight, HardDrive } from 'lucide-react';
import { ResponsiveContainer, Treemap, Tooltip } from 'recharts';
import { RiskBadge } from '../components/RiskBadge';
import { api } from '../api/client';

export function LocationViewPage({ scanId, onSelectFile }) {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);

  useEffect(() => {
    if (!scanId) return;
    setLoading(true);
    api.getArtefacts(scanId, { limit: 200 })
      .then((data) => {
        setItems(data.items || []);
      })
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  }, [scanId]);

  // Group items by file path
  const fileGroups = {};
  items.forEach(({ artefact, risk, recommendation }) => {
    const filePath = artefact.location?.file || 'unknown';
    if (!fileGroups[filePath]) {
      fileGroups[filePath] = {
        path: filePath,
        fileName: filePath.split(/[\\/]/).pop(),
        dirName: filePath.split(/[\\/]/).slice(0, -1).join('/') || 'root',
        items: [],
        criticalCount: 0,
        highCount: 0,
        mediumCount: 0,
        lowCount: 0,
        maxScore: 0,
      };
    }
    fileGroups[filePath].items.push({ artefact, risk, recommendation });
    if (risk.risk_level === 'critical') fileGroups[filePath].criticalCount++;
    else if (risk.risk_level === 'high') fileGroups[filePath].highCount++;
    else if (risk.risk_level === 'medium') fileGroups[filePath].mediumCount++;
    else fileGroups[filePath].lowCount++;
    fileGroups[filePath].maxScore = Math.max(fileGroups[filePath].maxScore, risk.risk_score || 0);
  });

  const fileList = Object.values(fileGroups).sort((a, b) => b.maxScore - a.maxScore);

  // Prepare Treemap data
  const treemapData = [
    {
      name: 'Cryptographic Files',
      children: fileList.map((f) => ({
        name: f.fileName,
        size: f.items.length,
        criticalCount: f.criticalCount,
        maxScore: f.maxScore,
        fullPath: f.path,
      })),
    },
  ];

  const CustomTreemapContent = (props) => {
    const { x, y, width, height, name, maxScore, size } = props;
    if (width < 35 || height < 35) return null;

    let fill = '#10b981'; // green
    if (maxScore >= 80) fill = '#ef4444'; // red
    else if (maxScore >= 60) fill = '#f97316'; // orange
    else if (maxScore >= 35) fill = '#f59e0b'; // amber

    return (
      <g>
        <rect
          x={x}
          y={y}
          width={width}
          height={height}
          style={{
            fill,
            stroke: '#0f172a',
            strokeWidth: 2,
            strokeOpacity: 0.8,
            rx: 6,
            ry: 6,
            cursor: 'pointer',
          }}
          onClick={() => setSelectedFile(props.fullPath)}
        />
        {width > 60 && height > 40 && (
          <text
            x={x + 8}
            y={y + 18}
            fill="#ffffff"
            fontSize={11}
            fontWeight={600}
            fontFamily="monospace"
          >
            {name?.length > 14 ? name.slice(0, 12) + '..' : name}
          </text>
        )}
        {width > 60 && height > 55 && (
          <text
            x={x + 8}
            y={y + 34}
            fill="#cbd5e1"
            fontSize={10}
            opacity={0.9}
          >
            {size} assets
          </text>
        )}
      </g>
    );
  };

  const activeGroup = selectedFile ? fileGroups[selectedFile] : fileList[0];

  return (
    <div className="space-y-8 pb-12">
      
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Cryptographic Dependency & Location Map</h1>
        <p className="text-xs text-slate-400 mt-1">
          Visual risk heat-map across repository directory structures, source modules, and configuration layers.
        </p>
      </div>

      {/* Recharts Treemap Heatmap */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur-md shadow-xl">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-indigo-400" />
            <h2 className="text-sm font-bold text-white uppercase tracking-wider">
              Asset Risk Heatmap (Area = Count, Color = Severity)
            </h2>
          </div>
          <div className="flex items-center gap-3 text-xs">
            <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded bg-red-500"></span> Critical</span>
            <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded bg-orange-500"></span> High</span>
            <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded bg-amber-500"></span> Medium</span>
            <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded bg-emerald-500"></span> Low</span>
          </div>
        </div>

        <div className="h-64 w-full">
          {fileList.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <Treemap
                data={treemapData}
                dataKey="size"
                aspectRatio={4 / 3}
                stroke="#0f172a"
                content={<CustomTreemapContent />}
              >
                <Tooltip
                  formatter={(val, name, entry) => [
                    `${val} assets (Max Risk: ${entry.payload.maxScore}/100)`,
                    entry.payload.name,
                  ]}
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px' }}
                  itemStyle={{ color: '#f8fafc' }}
                />
              </Treemap>
            </ResponsiveContainer>
          ) : (
            <div className="h-full flex items-center justify-center text-slate-500 text-sm">
              Loading risk heatmap...
            </div>
          )}
        </div>
      </div>

      {/* Two-Pane File Explorer: File List on Left, Drill-down on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left: Files List */}
        <div className="lg:col-span-1 bg-slate-900/60 border border-slate-800 rounded-2xl p-4 space-y-2 max-h-[600px] overflow-y-auto">
          <div className="flex items-center justify-between px-2 py-1 text-xs font-bold text-slate-400 uppercase tracking-wider border-b border-slate-800 pb-2">
            <span>Discovered Files ({fileList.length})</span>
            <span>Assets</span>
          </div>

          {fileList.map((f) => {
            const isSelected = activeGroup?.path === f.path;
            return (
              <div
                key={f.path}
                onClick={() => setSelectedFile(f.path)}
                className={`p-3 rounded-xl cursor-pointer border transition-all ${
                  isSelected
                    ? 'bg-indigo-950/60 border-indigo-500/60 text-white'
                    : 'bg-slate-950/40 border-slate-800/80 text-slate-300 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 truncate">
                    <FileCode className={`w-4 h-4 flex-shrink-0 ${isSelected ? 'text-indigo-400' : 'text-slate-400'}`} />
                    <span className="font-mono text-xs font-semibold truncate">{f.fileName}</span>
                  </div>
                  <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 font-bold">
                    {f.items.length}
                  </span>
                </div>

                <div className="flex items-center gap-2 mt-2">
                  {f.criticalCount > 0 && (
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-rose-950 text-rose-300 border border-rose-800 font-bold">
                      {f.criticalCount} Critical
                    </span>
                  )}
                  {f.highCount > 0 && (
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-orange-950 text-orange-300 border border-orange-800 font-bold">
                      {f.highCount} High
                    </span>
                  )}
                  <span className="text-[10px] text-slate-500 ml-auto font-mono">
                    Score: {f.maxScore}
                  </span>
                </div>
              </div>
            );
          })}
        </div>

        {/* Right: Selected File Inspection */}
        <div className="lg:col-span-2 bg-slate-900/60 border border-slate-800 rounded-2xl p-6 space-y-5">
          {activeGroup ? (
            <div>
              {/* File Detail Header */}
              <div className="border-b border-slate-800 pb-4 mb-4 flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <FileCode className="w-5 h-5 text-indigo-400" />
                    <h3 className="text-base font-bold text-white font-mono">{activeGroup.fileName}</h3>
                  </div>
                  <p className="text-xs text-slate-400 mt-1 font-mono break-all">{activeGroup.path}</p>
                </div>
                <div className="text-right">
                  <span className="text-xs font-semibold text-slate-400">Concentrated Assets:</span>
                  <div className="text-xl font-extrabold text-white">{activeGroup.items.length}</div>
                </div>
              </div>

              {/* Items in this file */}
              <div className="space-y-3">
                {activeGroup.items.map(({ artefact, risk, recommendation }, idx) => (
                  <div
                    key={idx}
                    className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-2 hover:border-slate-700 transition-colors"
                  >
                    <div className="flex items-center justify-between text-xs">
                      <div className="flex items-center gap-2 font-mono font-bold text-white">
                        <span>{artefact.name}</span>
                        {artefact.key_size && (
                          <span className="text-[10px] px-1.5 rounded bg-slate-800 text-slate-300 font-normal">
                            {artefact.key_size}-bit
                          </span>
                        )}
                        <span className="text-[10px] text-slate-500 font-normal">
                          (Line {artefact.location?.line})
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        <RiskBadge level={risk.risk_level} />
                        <RiskBadge level={artefact.quantum_status} type="quantum" />
                      </div>
                    </div>

                    {artefact.evidence && (
                      <div className="bg-slate-900 border border-slate-800/80 rounded-lg p-2.5 font-mono text-[11px] text-indigo-200 overflow-x-auto whitespace-pre">
                        {artefact.evidence}
                      </div>
                    )}

                    <div className="flex items-center justify-between text-xs pt-1 text-slate-400">
                      <div className="flex items-center gap-1.5">
                        <span className="font-semibold text-slate-300">Replacement:</span>
                        <span className="text-emerald-400 font-mono font-semibold">
                          {recommendation?.replacement || artefact.nist_replacement || 'NIST PQC Standard'}
                        </span>
                      </div>
                      <span className="font-mono text-[11px]">
                        Detection: {artefact.detection_method}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="text-center py-20 text-slate-500 text-sm">
              Select a file to inspect its cryptographic assets.
            </div>
          )}
        </div>

      </div>

    </div>
  );
}
