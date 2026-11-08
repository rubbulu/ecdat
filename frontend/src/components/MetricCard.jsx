import React from 'react';

export function MetricCard({ title, value, subtitle, icon: Icon, badge, color = 'indigo' }) {
  const colorMap = {
    indigo: {
      bg: 'bg-indigo-950/30',
      border: 'border-indigo-800/40',
      iconBg: 'bg-indigo-600/20 text-indigo-400',
    },
    rose: {
      bg: 'bg-rose-950/30',
      border: 'border-rose-800/40',
      iconBg: 'bg-rose-600/20 text-rose-400',
    },
    amber: {
      bg: 'bg-amber-950/30',
      border: 'border-amber-800/40',
      iconBg: 'bg-amber-600/20 text-amber-400',
    },
    emerald: {
      bg: 'bg-emerald-950/30',
      border: 'border-emerald-800/40',
      iconBg: 'bg-emerald-600/20 text-emerald-400',
    },
    cyan: {
      bg: 'bg-cyan-950/30',
      border: 'border-cyan-800/40',
      iconBg: 'bg-cyan-600/20 text-cyan-400',
    },
  };

  const scheme = colorMap[color] || colorMap.indigo;

  return (
    <div className={`relative overflow-hidden rounded-xl border ${scheme.border} ${scheme.bg} p-5 backdrop-blur-sm shadow-lg transition-all hover:border-slate-600/60`}>
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">{title}</span>
        {Icon && (
          <div className={`p-2 rounded-lg ${scheme.iconBg}`}>
            <Icon className="w-5 h-5" />
          </div>
        )}
      </div>
      <div className="mt-3 flex items-baseline gap-2">
        <span className="text-3xl font-extrabold text-white tracking-tight">{value}</span>
        {badge && <span>{badge}</span>}
      </div>
      {subtitle && <p className="mt-1.5 text-xs text-slate-400 leading-relaxed">{subtitle}</p>}
    </div>
  );
}
