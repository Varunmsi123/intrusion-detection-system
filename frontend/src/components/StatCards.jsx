const CLASS_CONFIG = {
  Normal: {
    border: "border-emerald-500/20",
    bg:     "bg-emerald-500/5",
    text:   "text-emerald-400",
    bar:    "bg-emerald-500",
    glow:   "shadow-emerald-500/20",
    ring:   "ring-emerald-500/40",
  },
  DoS: {
    border: "border-red-500/20",
    bg:     "bg-red-500/5",
    text:   "text-red-400",
    bar:    "bg-red-500",
    glow:   "shadow-red-500/20",
    ring:   "ring-red-500/40",
  },
  Probe: {
    border: "border-blue-500/20",
    bg:     "bg-blue-500/5",
    text:   "text-blue-400",
    bar:    "bg-blue-500",
    glow:   "shadow-blue-500/20",
    ring:   "ring-blue-500/40",
  },
  R2L: {
    border: "border-amber-500/20",
    bg:     "bg-amber-500/5",
    text:   "text-amber-400",
    bar:    "bg-amber-500",
    glow:   "shadow-amber-500/20",
    ring:   "ring-amber-500/40",
  },
  U2R: {
    border: "border-pink-500/20",
    bg:     "bg-pink-500/5",
    text:   "text-pink-400",
    bar:    "bg-pink-500",
    glow:   "shadow-pink-500/20",
    ring:   "ring-pink-500/40",
  },
}

const LABELS = {
  Normal: "Normal traffic",
  DoS:    "Denial of Service",
  Probe:  "Probe / Scan",
  R2L:    "Remote to Local",
  U2R:    "User to Root",
}

function StatCard({ label, count, total, cfg, isActive, onClick }) {
  const pct = total > 0 ? (count / total) * 100 : 0
  const isClickable = label !== "Normal"

  return (
    <div
      onClick={isClickable ? onClick : undefined}
      className={`rounded-xl border ${cfg.border} ${cfg.bg} p-4 flex flex-col gap-3 relative overflow-hidden
        transition-all duration-300
        ${isClickable ? "cursor-pointer select-none" : "cursor-default"}
        ${isActive ? `ring-2 ${cfg.ring} shadow-lg ${cfg.glow}` : "hover:border-opacity-50"}
      `}
    >
      {/* Active filter indicator */}
      {isActive && (
        <div className="absolute top-2 right-2">
          <span className={`text-[8px] font-bold uppercase tracking-widest px-1.5 py-0.5 rounded ${cfg.text} bg-white/5 border border-white/10`}>
            filtering ✓
          </span>
        </div>
      )}

      {/* Clickable hint for attack types */}
      {isClickable && !isActive && (
        <div className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity">
          <span className="text-[8px] text-slate-600 uppercase tracking-widest">click to filter</span>
        </div>
      )}

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

      {/* Filter hint label at bottom */}
      {isClickable && !isActive && (
        <div className="absolute bottom-0 left-0 right-0 h-0.5 opacity-0 hover:opacity-100 transition-opacity"
          style={{ background: `var(--tw-${cfg.bar.replace("bg-", "")})` }} />
      )}
    </div>
  )
}

export default function StatCards({ classCounts, filterType, setFilterType }) {
  const total = Object.values(classCounts).reduce((a, b) => a + b, 0)

  const handleCardClick = (label) => {
    if (label === "Normal") return
    setFilterType(filterType === label ? null : label)
  }

  return (
    <div>
      {setFilterType && filterType && (
        <div className="mb-2 flex items-center gap-2">
          <span className="text-[9px] text-slate-600 uppercase tracking-wider">Active filter:</span>
          <span className="text-[9px] font-bold text-slate-400">{filterType}</span>
          <button
            onClick={() => setFilterType(null)}
            className="text-[9px] text-slate-600 hover:text-red-400 border border-white/[0.06] hover:border-red-500/30 px-1.5 py-0.5 rounded transition-colors"
          >
            ✕ Clear filter
          </button>
        </div>
      )}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        {Object.entries(classCounts).map(([label, count]) => (
          <StatCard
            key={label}
            label={label}
            count={count}
            total={total}
            cfg={CLASS_CONFIG[label] || CLASS_CONFIG.Normal}
            isActive={filterType === label}
            onClick={() => handleCardClick(label)}
          />
        ))}
      </div>
      {setFilterType && (
        <p className="mt-1.5 text-[9px] text-slate-700 text-right">
          Click an attack-type card to filter the traffic table below
        </p>
      )}
    </div>
  )
}
