import { useEffect, useState } from "react"

export default function Header({
  connected,
  ipsMode = "simulate",
  redisConnected = false,
  onToggleMode,
  onEmergencyReset
}) {
  const [time, setTime] = useState("")
  const [isResetting, setIsResetting] = useState(false)

  useEffect(() => {
    const fmt = () => new Date().toLocaleTimeString("en-GB", { hour12: false })
    setTime(fmt())
    const id = setInterval(() => setTime(fmt()), 1000)
    return () => clearInterval(id)
  }, [])

  const handleReset = async () => {
    if (window.confirm("Emergency Flush: Clear all active IPS blocklists and reset isolated firewall tables?")) {
      setIsResetting(true)
      try {
        await onEmergencyReset()
      } finally {
        setIsResetting(false)
      }
    }
  }

  return (
    <header
      className="sticky top-0 z-50 h-16 px-6 flex items-center justify-between border-b border-white/[0.06]"
      style={{ background: "rgba(10,13,20,0.95)", backdropFilter: "blur(14px)" }}
    >
      {/* Logo & Brand */}
      <div className="flex items-center gap-3">
        <div className="relative w-10 h-10 flex items-center justify-center flex-shrink-0">
          <span
            className="pulse-ring absolute inset-0 rounded-full border border-red-500/50"
            style={{ animationDelay: "0s" }}
          />
          <span
            className="pulse-ring absolute inset-0 rounded-full border border-red-500/30"
            style={{ animationDelay: "0.5s" }}
          />
          <div className="relative w-5 h-5 rounded-full bg-red-500/20 border border-red-500/80 flex items-center justify-center">
            <div className="w-2 h-2 rounded-full bg-red-400 blink" />
          </div>
        </div>
        <div>
          <div
            className="text-[18px] tracking-tight leading-none text-white flex items-center gap-2"
            style={{ fontFamily: "'Syne', sans-serif", fontWeight: 800 }}
          >
            IPS<span className="text-red-400">Defender</span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-white/10 text-slate-300 font-normal">
              v2.0 Real-Time
            </span>
          </div>
          <div className="text-[9px] text-slate-500 tracking-widest uppercase mt-1 font-mono">
            Intrusion Prevention & Detection System
          </div>
        </div>
      </div>

      {/* Center / Right controls */}
      <div className="flex items-center gap-4">
        {/* Redis Status */}
        <div
          className={`flex items-center gap-2 px-3 py-1.5 rounded-full border text-[11px] font-mono ${
            redisConnected
              ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
              : "border-amber-500/30 bg-amber-500/10 text-amber-400"
          }`}
          title={redisConnected ? "Redis store connected (port 6379)" : "Operating on in-memory fallback store"}
        >
          <span className={`w-1.5 h-1.5 rounded-full ${redisConnected ? "bg-emerald-400" : "bg-amber-400"}`} />
          <span>{redisConnected ? "Redis 6379" : "Memory Store"}</span>
        </div>

        {/* IPS Mode Switcher */}
        <div className="flex items-center gap-2 bg-white/[0.03] border border-white/10 p-1 rounded-lg font-mono text-xs">
          <span className="text-[10px] text-slate-500 uppercase tracking-wider px-2">Mode:</span>
          <button
            onClick={() => onToggleMode("simulate")}
            className={`px-3 py-1 rounded text-[11px] font-semibold transition-all cursor-pointer ${
              ipsMode === "simulate"
                ? "bg-blue-500/20 text-blue-400 border border-blue-500/30 shadow-sm"
                : "text-slate-500 hover:text-slate-300"
            }`}
          >
            🛡️ Simulation (Safe)
          </button>
          <button
            onClick={() => onToggleMode("enforce")}
            className={`px-3 py-1 rounded text-[11px] font-semibold transition-all cursor-pointer ${
              ipsMode === "enforce"
                ? "bg-rose-500/20 text-rose-400 border border-rose-500/30 shadow-sm"
                : "text-slate-500 hover:text-slate-300"
            }`}
          >
            ⚡ Active Enforce
          </button>
        </div>

        {/* Emergency Reset Panic Button */}
        <button
          onClick={handleReset}
          disabled={isResetting}
          className="px-3 py-1.5 bg-red-500/15 hover:bg-red-500/25 text-red-400 border border-red-500/30 rounded-lg text-xs font-mono font-semibold transition-all cursor-pointer flex items-center gap-1.5 hover:shadow-red-500/10"
          title="Emergency Flush: Safely remove all IPS firewall drop rules and clear blocklists"
        >
          <span className="w-2 h-2 rounded-full bg-red-400" />
          {isResetting ? "Flushing..." : "Emergency Flush"}
        </button>

        {/* Live Status Badge */}
        <div
          className={`flex items-center gap-2 px-3 py-1.5 rounded-full border text-[11px] font-medium font-mono transition-all duration-500 ${
            connected
              ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
              : "border-slate-600/50 bg-slate-800/50 text-slate-500"
          }`}
        >
          <span
            className={`w-1.5 h-1.5 rounded-full ${
              connected ? "bg-emerald-400 blink" : "bg-slate-600"
            }`}
          />
          {connected ? "Socket Live" : "Disconnected"}
        </div>

        {/* Clock */}
        <div className="text-slate-500 text-xs tabular-nums font-mono hidden md:block">
          {time}
        </div>
      </div>
    </header>
  )
}
