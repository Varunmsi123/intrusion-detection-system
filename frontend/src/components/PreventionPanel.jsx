import { useState } from "react"

const ACTION_STYLES = {
  ALLOW: {
    badge: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
    text: "text-emerald-400",
    dot: "bg-emerald-400",
  },
  RATE_LIMIT: {
    badge: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    text: "text-amber-400",
    dot: "bg-amber-400",
  },
  BLOCK: {
    badge: "bg-red-500/15 text-red-400 border-red-500/30",
    text: "text-red-400",
    dot: "bg-red-400",
  },
  DROP: {
    badge: "bg-purple-500/15 text-purple-400 border-purple-500/30",
    text: "text-purple-400",
    dot: "bg-purple-400",
  },
  UNBLOCK: {
    badge: "bg-blue-500/15 text-blue-400 border-blue-500/30",
    text: "text-blue-400",
    dot: "bg-blue-400",
  },
  RESET: {
    badge: "bg-pink-500/15 text-pink-400 border-pink-500/30",
    text: "text-pink-400",
    dot: "bg-pink-400",
  },
}

export default function PreventionPanel({ actions, onSimulateAttack }) {
  const [simulating, setSimulating] = useState(null)

  const handleSimulate = async (type) => {
    setSimulating(type)
    try {
      await onSimulateAttack(type)
    } finally {
      setTimeout(() => setSimulating(null), 600)
    }
  }

  return (
    <div className="rounded-xl border border-white/[0.06] bg-[#0b0e16] flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-3 border-b border-white/[0.05]">
        <div className="flex items-center gap-2">
          <span
            className="text-sm font-bold text-slate-200"
            style={{ fontFamily: "'Syne', sans-serif" }}
          >
            IPS Real-Time Prevention Stream
          </span>
          <span className="text-[10px] text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20 uppercase tracking-widest font-mono">
            Active Filter
          </span>
        </div>
        <span className="text-[10px] text-slate-500 font-mono">
          Decisions & Rate Limiting
        </span>
      </div>

      {/* Quick Attack Simulator Bar */}
      <div className="px-5 py-2.5 bg-white/[0.015] border-b border-white/[0.04] flex flex-wrap items-center justify-between gap-3 text-xs">
        <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold font-mono">
          Simulate Attack Flow:
        </span>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => handleSimulate("DoS")}
            disabled={simulating !== null}
            className="px-2.5 py-1 bg-red-500/15 hover:bg-red-500/25 text-red-400 border border-red-500/30 rounded font-mono text-[11px] transition-all cursor-pointer disabled:opacity-40"
          >
            {simulating === "DoS" ? "Simulating..." : "⚡ DoS Flood"}
          </button>
          <button
            onClick={() => handleSimulate("Probe")}
            disabled={simulating !== null}
            className="px-2.5 py-1 bg-blue-500/15 hover:bg-blue-500/25 text-blue-400 border border-blue-500/30 rounded font-mono text-[11px] transition-all cursor-pointer disabled:opacity-40"
          >
            {simulating === "Probe" ? "Simulating..." : "🔍 Port Probe"}
          </button>
          <button
            onClick={() => handleSimulate("R2L")}
            disabled={simulating !== null}
            className="px-2.5 py-1 bg-amber-500/15 hover:bg-amber-500/25 text-amber-400 border border-amber-500/30 rounded font-mono text-[11px] transition-all cursor-pointer disabled:opacity-40"
          >
            {simulating === "R2L" ? "Simulating..." : "🛡️ R2L Exploit"}
          </button>
          <button
            onClick={() => handleSimulate("U2R")}
            disabled={simulating !== null}
            className="px-2.5 py-1 bg-pink-500/15 hover:bg-pink-500/25 text-pink-400 border border-pink-500/30 rounded font-mono text-[11px] transition-all cursor-pointer disabled:opacity-40"
          >
            {simulating === "U2R" ? "Simulating..." : "🚨 U2R Privilege"}
          </button>
        </div>
      </div>

      {/* Stream List */}
      <div className="overflow-y-auto max-h-[260px] divide-y divide-white/[0.03]">
        {actions.length === 0 ? (
          <div className="py-8 text-center text-slate-600 text-xs font-mono">
            Awaiting packet flows and policy evaluations...
          </div>
        ) : (
          actions.slice(0, 30).map((act, idx) => {
            const style = ACTION_STYLES[act.action] || ACTION_STYLES.ALLOW
            return (
              <div key={idx} className="px-5 py-2 flex items-center justify-between gap-3 text-xs font-mono hover:bg-white/[0.015] transition-colors">
                <div className="flex items-center gap-2.5 min-w-0">
                  <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${style.dot}`} />
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase tracking-wider ${style.badge}`}>
                    {act.action}
                  </span>
                  <span className="text-slate-300 font-semibold truncate">
                    {act.ip || "System"}
                  </span>
                  {act.attack_type && (
                    <span className="text-[10px] text-slate-500">
                      [{act.attack_type}]
                    </span>
                  )}
                  <span className="text-[11px] text-slate-400 truncate max-w-[320px] hidden md:inline">
                    — {act.reason}
                  </span>
                </div>

                <div className="flex items-center gap-3 text-[10px] text-slate-500 flex-shrink-0">
                  {act.duration > 0 && (
                    <span className="text-red-400/80 bg-red-500/10 px-1.5 py-0.5 rounded border border-red-500/20">
                      {act.duration}s block
                    </span>
                  )}
                  <span>{act.timestamp}</span>
                </div>
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}
