import { useEffect, useState } from "react"

export default function Header({ connected }) {
  const [time, setTime] = useState("")

  useEffect(() => {
    const fmt = () =>
      new Date().toLocaleTimeString("en-GB", { hour12: false })
    setTime(fmt())
    const id = setInterval(() => setTime(fmt()), 1000)
    return () => clearInterval(id)
  }, [])

  return (
    <header
      className="sticky top-0 z-50 h-14 px-5 flex items-center justify-between border-b border-white/[0.06]"
      style={{ background: "rgba(10,13,20,0.95)", backdropFilter: "blur(12px)" }}
    >
      {/* Logo */}
      <div className="flex items-center gap-3">
        {/* Radar icon */}
        <div className="relative w-9 h-9 flex items-center justify-center flex-shrink-0">
          <span
            className="pulse-ring absolute inset-0 rounded-full border border-red-500/50"
            style={{ animationDelay: "0s" }}
          />
          <span
            className="pulse-ring absolute inset-0 rounded-full border border-red-500/30"
            style={{ animationDelay: "0.5s" }}
          />
          <div className="relative w-4 h-4 rounded-full bg-red-500/20 border border-red-500/80 flex items-center justify-center">
            <div className="w-1.5 h-1.5 rounded-full bg-red-400 blink" />
          </div>
        </div>
        <div>
          <div
            className="text-[17px] tracking-tight leading-none text-white"
            style={{ fontFamily: "'Syne', sans-serif", fontWeight: 800 }}
          >
            IDS<span className="text-red-400">Monitor</span>
          </div>
          <div className="text-[9px] text-slate-500 tracking-widest uppercase mt-0.5">
            Intrusion Detection System
          </div>
        </div>
      </div>

      {/* Right side */}
      <div className="flex items-center gap-4">
        {/* Status badge */}
        <div
          className={`flex items-center gap-2 px-3 py-1.5 rounded-full border text-[11px] font-medium transition-all duration-500 ${
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
          {connected ? "Live capture" : "Disconnected"}
        </div>

        {/* Clock */}
        <div className="text-slate-500 text-xs tabular-nums hidden sm:block">
          {time}
        </div>
      </div>
    </header>
  )
}
