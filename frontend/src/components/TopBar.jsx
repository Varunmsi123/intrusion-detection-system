function fmt(n) {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + "M"
  if (n >= 1_000)     return (n / 1_000).toFixed(1) + "K"
  return n.toLocaleString()
}

function fmtUptime(s) {
  const h   = Math.floor(s / 3600)
  const m   = Math.floor((s % 3600) / 60)
  const sec = s % 60
  return [h, m, sec].map(v => String(v).padStart(2, "0")).join(":")
}

const ITEMS = [
  { key: "total_packets",   label: "Packets",     color: "text-slate-300",   fmt: fmt },
  { key: "total_alerts",    label: "Alerts",      color: "text-red-400",     fmt: fmt },
  { key: "packets_per_sec", label: "Pkt/s",       color: "text-blue-400",    fmt: v => v },
  { key: "active_flows",    label: "Flows",       color: "text-amber-400",   fmt: fmt },
  { key: "uptime_seconds",  label: "Uptime",      color: "text-emerald-400", fmt: fmtUptime },
]

export default function TopBar({ stats }) {
  return (
    <div
      className="border-b border-white/[0.05] px-5 py-1.5 flex gap-6 overflow-x-auto"
      style={{ background: "rgba(10,13,20,0.85)" }}
    >
      {ITEMS.map(({ key, label, color, fmt: f }) => (
        <div key={key} className="flex items-center gap-2 whitespace-nowrap">
          <span className="text-[10px] text-slate-600 uppercase tracking-wider">{label}</span>
          <span className={`text-[11px] font-semibold tabular-nums ${color}`}>
            {f(stats[key] ?? 0)}
          </span>
        </div>
      ))}
    </div>
  )
}
