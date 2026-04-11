import { useEffect, useState } from "react"

const SOCKET_URL = import.meta.env.VITE_API_URL || "http://localhost:5001"

export default function Header({ connected, isPaused }) {
  const [time, setTime] = useState("")

  useEffect(() => {
    const fmt = () =>
      new Date().toLocaleTimeString("en-GB", { hour12: false })
    setTime(fmt())
    const id = setInterval(() => setTime(fmt()), 1000)
    return () => clearInterval(id)
  }, [])

  const handleTogglePause = async () => {
    const endpoint = isPaused ? "/api/resume" : "/api/pause"
    try {
      await fetch(`${SOCKET_URL}${endpoint}`, { method: "POST" })
      // State will be updated from the 'capture_state' socket event
    } catch (e) {
      console.error("Failed to toggle capture:", e)
    }
  }

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
            className={`pulse-ring absolute inset-0 rounded-full border ${isPaused ? "border-slate-600/40" : "border-red-500/50"}`}
            style={{ animationDelay: "0s", animationPlayState: isPaused ? "paused" : "running" }}
          />
          <span
            className={`pulse-ring absolute inset-0 rounded-full border ${isPaused ? "border-slate-600/20" : "border-red-500/30"}`}
            style={{ animationDelay: "0.5s", animationPlayState: isPaused ? "paused" : "running" }}
          />
          <div className={`relative w-4 h-4 rounded-full flex items-center justify-center border transition-colors duration-300 ${
            isPaused
              ? "bg-slate-600/20 border-slate-600/60"
              : "bg-red-500/20 border-red-500/80"
          }`}>
            <div className={`w-1.5 h-1.5 rounded-full transition-colors duration-300 ${
              isPaused ? "bg-slate-500" : "bg-red-400 blink"
            }`} />
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
      <div className="flex items-center gap-3">

        {/* ── Active / Pause toggle ── */}
        <button
          onClick={handleTogglePause}
          disabled={!connected}
          className={`flex items-center gap-2 px-3.5 py-1.5 rounded-full border text-[11px] font-bold transition-all duration-300 select-none
            ${!connected ? "opacity-40 cursor-not-allowed border-slate-700 bg-slate-800/30 text-slate-600" :
            isPaused
              ? "border-amber-500/50 bg-amber-500/10 text-amber-400 hover:bg-amber-500/20 hover:border-amber-500/70"
              : "border-emerald-500/40 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 hover:border-emerald-500/60"
            }`}
          title={isPaused ? "Resume capture" : "Pause capture"}
        >
          {isPaused ? (
            <>
              {/* Play icon */}
              <svg className="w-3 h-3" viewBox="0 0 24 24" fill="currentColor">
                <path d="M8 5v14l11-7z" />
              </svg>
              Resume
            </>
          ) : (
            <>
              {/* Pause icon */}
              <svg className="w-3 h-3" viewBox="0 0 24 24" fill="currentColor">
                <path d="M6 19h4V5H6v14zm8-14v14h4V5h-4z" />
              </svg>
              Active
            </>
          )}
        </button>

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
