const CLASS_CONFIG = {
  Normal: {
    border: "border-emerald-500/20",
    bg:     "bg-emerald-500/5",
    text:   "text-emerald-400",
    bar:    "bg-emerald-500",
    glow:   "shadow-emerald-500/20",
  },
  DoS: {
    border: "border-red-500/20",
    bg:     "bg-red-500/5",
    text:   "text-red-400",
    bar:    "bg-red-500",
    glow:   "shadow-red-500/20",
  },
  Probe: {
    border: "border-blue-500/20",
    bg:     "bg-blue-500/5",
    text:   "text-blue-400",
    bar:    "bg-blue-500",
    glow:   "shadow-blue-500/20",
  },
  R2L: {
    border: "border-amber-500/20",
    bg:     "bg-amber-500/5",
    text:   "text-amber-400",
    bar:    "bg-amber-500",
    glow:   "shadow-amber-500/20",
  },
  U2R: {
    border: "border-pink-500/20",
    bg:     "bg-pink-500/5",
    text:   "text-pink-400",
    bar:    "bg-pink-500",
    glow:   "shadow-pink-500/20",
  },
}

const LABELS = {
  Normal: "Normal traffic",
  DoS:    "Denial of Service",
  Probe:  "Probe / Scan",
  R2L:    "Remote to Local",
  U2R:    "User to Root",
}

function StatCard({ label, count, total, cfg }) {
  const pct = total > 0 ? (count / total) * 100 : 0

  return (
    <div
      className={`rounded-xl border ${cfg.border} ${cfg.bg} p-4 flex flex-col gap-3 relative overflow-hidden group hover:border-opacity-40 transition-all duration-300`}
    >
      {/* Top row */}
      <div className="flex items-start justify-between">
        <div>
          <div className="text-[9px] font-semibold uppercase tracking-[0.12em] text-slate-500 mb-1">
            {label}
          </div>
          <div className="text-[10px] text-slate-600">{LABELS[label]}</div>
        </div>
        {/* Percentage badge */}
        <div className={`text-[11px] font-bold ${cfg.text} tabular-nums`}>
          {pct.toFixed(1)}%
        </div>
      </div>

      {/* Count */}
      <div
        className={`text-3xl font-black tabular-nums leading-none ${cfg.text}`}
        style={{ fontFamily: "'Syne', sans-serif" }}
      >
        {count.toLocaleString()}
      </div>

      {/* Progress bar */}
      <div className="h-1 w-full bg-white/5 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full ${cfg.bar} transition-all duration-700 ease-out`}
          style={{ width: `${Math.min(pct, 100)}%` }}
        />
      </div>
    </div>
  )
}

export default function StatCards({ classCounts }) {
  const total = Object.values(classCounts).reduce((a, b) => a + b, 0)

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
      {Object.entries(classCounts).map(([label, count]) => (
        <StatCard
          key={label}
          label={label}
          count={count}
          total={total}
          cfg={CLASS_CONFIG[label] || CLASS_CONFIG.Normal}
        />
      ))}
    </div>
  )
}
