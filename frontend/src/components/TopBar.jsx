function fmt(n) {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + "M"
  if (n >= 1_000)     return (n / 1_000).toFixed(1) + "K"
  return (n || 0).toLocaleString()
}

function fmtUptime(s) {
  const h   = Math.floor(s / 3600)
  const m   = Math.floor((s % 3600) / 60)
  const sec = s % 60
  return [h, m, sec].map(v => String(v).padStart(2, "0")).join(":")
}

const ITEMS = [
  { key: "total_packets",   label: "Packets Scanned", color: "text-slate-300",   fmt: fmt },
  { key: "total_alerts",    label: "Attacks Detected",color: "text-red-400",     fmt: fmt },
  { key: "blocked_hosts",   label: "Active Blocks",   color: "text-rose-400",    fmt: fmt },
  { key: "packets_per_sec", label: "Packet Rate",     color: "text-blue-400",    fmt: v => `${v || 0} pkt/s` },
  { key: "active_flows",    label: "Active Flows",    color: "text-amber-400",   fmt: fmt },
  { key: "uptime_seconds",  label: "System Uptime",   color: "text-emerald-400", fmt: fmtUptime },
]

export default function TopBar({ stats }) {
  return (
    <div
      className="border-b border-white/[0.05] px-6 py-2 flex items-center gap-8 overflow-x-auto"
      style={{ background: "rgba(10,13,20,0.85)" }}
    >
      {ITEMS.map(({ key, label, color, fmt: f }) => (
        <div key={key} className="flex items-center gap-2 whitespace-nowrap font-mono">
          <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">{label}:</span>
          <span className={`text-[12px] font-bold tabular-nums ${color}`}>
            {f(stats[key] ?? 0)}
          </span>
        </div>
      ))}
    </div>
  )
}
