import { useRef, useEffect, useState } from "react"

const TYPE_CFG = {
  DoS: {
    badge:  "bg-red-500/15 text-red-400 border border-red-500/25",
    dot:    "bg-red-400",
    glow:   "border-l-red-500/50",
  },
  Probe: {
    badge:  "bg-blue-500/15 text-blue-400 border border-blue-500/25",
    dot:    "bg-blue-400",
    glow:   "border-l-blue-500/50",
  },
  R2L: {
    badge:  "bg-amber-500/15 text-amber-400 border border-amber-500/25",
    dot:    "bg-amber-400",
    glow:   "border-l-amber-500/50",
  },
  U2R: {
    badge:  "bg-pink-500/15 text-pink-400 border border-pink-500/25",
    dot:    "bg-pink-400",
    glow:   "border-l-pink-500/50",
  },
}

/* Confidence → color */
function confColor(c) {
  if (c >= 0.95) return "text-red-400"
  if (c >= 0.85) return "text-amber-400"
  return "text-slate-500"
}

/* Format bytes */
function fmtBytes(n) {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + " MB"
  if (n >= 1_000)     return (n / 1_000).toFixed(1) + " KB"
  return n + " B"
}

function AlertItem({ alert, isNew }) {
  const cfg = TYPE_CFG[alert.type] || TYPE_CFG.DoS

  return (
    <div
      className={`alert-enter border-b border-white/[0.04] border-l-2 ${cfg.glow}
        px-4 py-3 hover:bg-white/[0.018] transition-colors cursor-default`}
    >
      {/* Row 1: badge + time + confidence */}
      <div className="flex items-center gap-2 mb-1.5">
        {/* Live dot */}
        {isNew && (
          <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 blink ${cfg.dot}`} />
        )}
        {/* Type badge */}
        <span className={`text-[9px] font-bold tracking-widest uppercase px-2 py-0.5 rounded-full ${cfg.badge}`}>
          {alert.type}
        </span>
        {/* Timestamp */}
        <span className="text-[10px] text-slate-600 tabular-nums ml-auto">
          {alert.time}
        </span>
        {/* Confidence */}
        <span className={`text-[10px] font-semibold tabular-nums ${confColor(alert.confidence)}`}>
          {(alert.confidence * 100).toFixed(1)}%
        </span>
      </div>

      {/* Row 2: IP route */}
      <div className="text-[11px] text-slate-300 font-mono truncate mb-1">
        <span className="text-slate-500">src </span>{alert.src_ip}
        <span className="text-slate-600 mx-1.5">→</span>
        <span className="text-slate-500">dst </span>{alert.dst_ip}
      </div>

      {/* Row 3: meta chips */}
      <div className="flex flex-wrap gap-2 mt-1">
        {[
          alert.service   && { label: alert.service },
          alert.protocol  && { label: alert.protocol.toUpperCase() },
          alert.src_bytes && { label: `↑ ${fmtBytes(alert.src_bytes)}` },
          alert.dst_bytes && { label: `↓ ${fmtBytes(alert.dst_bytes)}` },
          alert.duration  !== undefined && { label: `${alert.duration}s` },
        ].filter(Boolean).map((chip, i) => (
          <span
            key={i}
            className="text-[9px] text-slate-600 bg-white/[0.04] px-1.5 py-0.5 rounded"
          >
            {chip.label}
          </span>
        ))}
      </div>
    </div>
  )
}

/* ── Summary bar at the bottom ─────────────────────── */
function SummaryBar({ alerts }) {
  const counts = alerts.reduce((acc, a) => {
    acc[a.type] = (acc[a.type] || 0) + 1
    return acc
  }, {})

  return (
    <div className="px-4 py-2 border-t border-white/[0.05] flex gap-4 text-[10px] text-slate-600 flex-shrink-0">
      {["DoS", "Probe", "R2L", "U2R"].map(t => (
        <span key={t}>
          {t}
          <strong className="ml-1 text-slate-400">{counts[t] || 0}</strong>
        </span>
      ))}
      <span className="ml-auto">total <strong className="text-slate-400">{alerts.length}</strong></span>
    </div>
  )
}

/* ── Main component ─────────────────────────────────── */
export default function AlertFeed({ alerts }) {
  const [newestId, setNewestId] = useState(null)

  /* Track newest alert for blink indicator */
  useEffect(() => {
    if (alerts.length > 0) {
      setNewestId(alerts[0].id)
      const t = setTimeout(() => setNewestId(null), 3000)
      return () => clearTimeout(t)
    }
  }, [alerts[0]?.id])

  return (
    <div className="rounded-xl border border-white/[0.06] bg-[#0b0e16] flex flex-col xl:h-[calc(100vh-8rem)] min-h-[500px]">

      {/* Header */}
      <div className="flex items-center justify-between px-5 py-3 border-b border-white/[0.05] flex-shrink-0">
        <span
          className="text-sm font-bold text-slate-200"
          style={{ fontFamily: "'Syne', sans-serif" }}
        >
          Live alerts
        </span>
        <div className="flex items-center gap-2">
          {alerts.length > 0 && (
            <span className="text-[9px] text-red-400 blink uppercase tracking-wider">
              ● live
            </span>
          )}
          <span
            className={`text-[10px] font-bold px-2.5 py-1 rounded-full ${
              alerts.length > 0
                ? "bg-red-500/15 text-red-400 border border-red-500/25"
                : "bg-white/5 text-slate-600"
            }`}
          >
            {alerts.length}
          </span>
        </div>
      </div>

      {/* Feed */}
      <div className="overflow-y-auto flex-1">
        {alerts.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-32 gap-3 text-slate-700">
            {/* Empty state icon */}
            <div className="relative">
              <div className="w-10 h-10 rounded-full border border-slate-800 flex items-center justify-center">
                <div className="w-2 h-2 rounded-full bg-slate-800" />
              </div>
            </div>
            <span className="text-xs tracking-wider uppercase">Monitoring traffic…</span>
          </div>
        ) : (
          alerts.map(alert => (
            <AlertItem
              key={alert.id}
              alert={alert}
              isNew={alert.id === newestId}
            />
          ))
        )}
      </div>

      {/* Summary footer */}
      {alerts.length > 0 && <SummaryBar alerts={alerts} />}
    </div>
  )
}
