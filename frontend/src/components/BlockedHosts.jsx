import { useState, useEffect } from "react"

const TYPE_COLORS = {
  DoS:   "bg-red-500/15 text-red-400 border-red-500/30",
  Probe: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  R2L:   "bg-amber-500/15 text-amber-400 border-amber-500/30",
  U2R:   "bg-pink-500/15 text-pink-400 border-pink-500/30",
  Manual:"bg-purple-500/15 text-purple-400 border-purple-500/30",
}

function formatCountdown(seconds) {
  if (seconds <= 0) return "Expiring..."
  const m = Math.floor(seconds / 60)
  const s = seconds % 60
  return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`
}

export default function BlockedHosts({ blockedHosts, onUnblock, onManualBlock }) {
  const [timers, setTimers] = useState({})
  const [unblockingIp, setUnblockingIp] = useState(null)
  const [manualIp, setManualIp] = useState("")
  const [manualDuration, setManualDuration] = useState("120")
  const [manualType, setManualType] = useState("DoS")
  const [isSubmitting, setIsSubmitting] = useState(false)

  // Initialize countdowns from incoming server TTLs
  useEffect(() => {
    const init = {}
    blockedHosts.forEach(h => {
      init[h.ip] = h.ttl_remaining !== undefined ? h.ttl_remaining : h.duration
    })
    setTimers(init)
  }, [blockedHosts])

  // Local 1-second countdown interval
  useEffect(() => {
    const interval = setInterval(() => {
      setTimers(prev => {
        const next = { ...prev }
        Object.keys(next).forEach(ip => {
          if (next[ip] > 0) next[ip] -= 1
        })
        return next
      })
    }, 1000)
    return () => clearInterval(interval)
  }, [])

  const handleUnblock = async (ip) => {
    setUnblockingIp(ip)
    try {
      await onUnblock(ip)
    } finally {
      setUnblockingIp(null)
    }
  }

  const handleManualSubmit = async (e) => {
    e.preventDefault()
    if (!manualIp.trim()) return
    setIsSubmitting(true)
    try {
      await onManualBlock(manualIp.trim(), parseInt(manualDuration) || 120, manualType)
      setManualIp("")
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <div className="rounded-xl border border-white/[0.06] bg-[#0b0e16] flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-3.5 border-b border-white/[0.05]">
        <div className="flex items-center gap-2.5">
          <div className="w-2.5 h-2.5 rounded-full bg-rose-500 animate-pulse" />
          <span
            className="text-sm font-bold text-slate-200 tracking-wide"
            style={{ fontFamily: "'Syne', sans-serif" }}
          >
            Active IPS Blocklist
          </span>
          <span className="text-[10px] text-slate-500 font-mono">
            ({blockedHosts.length} active)
          </span>
        </div>

        <span className="text-[10px] text-slate-500 font-mono">
          Auto-TTL Expiration Active
        </span>
      </div>

      {/* Manual Test Block Form */}
      <form onSubmit={handleManualSubmit} className="px-5 py-2.5 bg-white/[0.015] border-b border-white/[0.04] flex flex-wrap items-center gap-2 text-xs">
        <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">Test Block IP:</span>
        <input
          type="text"
          placeholder="e.g. 198.51.100.99"
          value={manualIp}
          onChange={(e) => setManualIp(e.target.value)}
          className="bg-black/40 border border-white/10 rounded px-2.5 py-1 text-slate-200 placeholder-slate-600 font-mono text-xs focus:outline-none focus:border-red-500/50 flex-1 min-w-[140px]"
        />
        <select
          value={manualType}
          onChange={(e) => setManualType(e.target.value)}
          className="bg-black/40 border border-white/10 rounded px-2 py-1 text-slate-300 font-mono text-xs focus:outline-none"
        >
          <option value="DoS">DoS</option>
          <option value="Probe">Probe</option>
          <option value="R2L">R2L</option>
          <option value="U2R">U2R</option>
        </select>
        <select
          value={manualDuration}
          onChange={(e) => setManualDuration(e.target.value)}
          className="bg-black/40 border border-white/10 rounded px-2 py-1 text-slate-300 font-mono text-xs focus:outline-none"
        >
          <option value="60">60s</option>
          <option value="120">120s</option>
          <option value="300">300s (5m)</option>
          <option value="600">600s (10m)</option>
        </select>
        <button
          type="submit"
          disabled={isSubmitting || !manualIp}
          className="px-3 py-1 bg-red-500/20 hover:bg-red-500/30 text-red-400 border border-red-500/30 rounded font-medium text-xs transition-colors disabled:opacity-40 cursor-pointer"
        >
          {isSubmitting ? "Blocking..." : "Block IP"}
        </button>
      </form>

      {/* Blocked List Table */}
      <div className="overflow-x-auto max-h-[320px] overflow-y-auto">
        {blockedHosts.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-10 text-slate-600 gap-2">
            <svg className="w-8 h-8 text-emerald-500/40" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            <span className="text-xs tracking-wider uppercase text-slate-500 font-mono">
              All systems clear • No active IP blocks
            </span>
            <span className="text-[11px] text-slate-700">
              Suspicious attack flows will automatically be contained and isolated here.
            </span>
          </div>
        ) : (
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-white/[0.04] text-[10px] text-slate-500 uppercase tracking-wider font-mono bg-white/[0.01]">
                <th className="px-5 py-2.5">Blocked IP</th>
                <th className="px-4 py-2.5">Attack Family</th>
                <th className="px-4 py-2.5">Reason / Trigger</th>
                <th className="px-4 py-2.5">TTL Remaining</th>
                <th className="px-5 py-2.5 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.03] text-xs font-mono">
              {blockedHosts.map((host) => {
                const ttl = timers[host.ip] ?? host.ttl_remaining ?? 0
                const typeStyle = TYPE_COLORS[host.attack_type] || TYPE_COLORS.DoS

                return (
                  <tr key={host.ip} className="hover:bg-white/[0.015] transition-colors">
                    <td className="px-5 py-3 text-slate-200 font-semibold">
                      <div className="flex items-center gap-2">
                        <span className="w-1.5 h-1.5 rounded-full bg-rose-500" />
                        {host.ip}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-[9px] font-bold px-2 py-0.5 rounded border uppercase tracking-wider ${typeStyle}`}>
                        {host.attack_type || "Attack"}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-400 text-[11px] max-w-[280px] truncate" title={host.reason}>
                      {host.reason || "Suspicious anomaly"}
                    </td>
                    <td className="px-4 py-3 tabular-nums">
                      <span className="text-amber-400 bg-amber-500/10 border border-amber-500/20 px-2 py-0.5 rounded text-[11px] font-semibold">
                        ⏱ {formatCountdown(ttl)}
                      </span>
                    </td>
                    <td className="px-5 py-3 text-right">
                      <button
                        onClick={() => handleUnblock(host.ip)}
                        disabled={unblockingIp === host.ip}
                        className="px-2.5 py-1 bg-white/[0.05] hover:bg-emerald-500/20 text-slate-300 hover:text-emerald-400 border border-white/10 hover:border-emerald-500/30 rounded text-[11px] font-medium transition-all cursor-pointer disabled:opacity-40"
                      >
                        {unblockingIp === host.ip ? "Releasing..." : "Unblock"}
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
