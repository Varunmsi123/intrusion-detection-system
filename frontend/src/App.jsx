import { useEffect, useState, useCallback } from "react"
import { io } from "socket.io-client"
import Header from "./components/Header"
import TopBar from "./components/TopBar"
import StatCards from "./components/StatCards"
import TimelineChart from "./components/TimelineChart"
import DonutChart from "./components/DonutChart"
import AlertFeed from "./components/AlertFeed"

const SOCKET_URL = import.meta.env.VITE_API_URL || "http://localhost:5000"

const INIT_STATS = {
  total_packets: 0,
  total_alerts: 0,
  packets_per_sec: 0,
  active_flows: 0,
  uptime_seconds: 0,
}
const INIT_COUNTS = { Normal: 0, DoS: 0, Probe: 0, R2L: 0, U2R: 0 }

export default function App() {
  const [connected,   setConnected]   = useState(false)
  const [stats,       setStats]       = useState(INIT_STATS)
  const [classCounts, setClassCounts] = useState(INIT_COUNTS)
  const [timeline,    setTimeline]    = useState([])
  const [alerts,      setAlerts]      = useState([])

  const addAlert = useCallback((alert) => {
    setAlerts(prev => [alert, ...prev].slice(0, 200))
  }, [])

  useEffect(() => {
    const socket = io(SOCKET_URL, {
      transports: ["websocket", "polling"],
      reconnectionDelay: 1000,
      reconnectionAttempts: 10,
    })

    socket.on("connect",    () => setConnected(true))
    socket.on("disconnect", () => setConnected(false))

    socket.on("stats_update", (data) => {
      setStats(data.stats)
      setClassCounts(data.class_counts)
      setTimeline(data.timeline || [])
    })

    socket.on("new_alert", addAlert)

    return () => socket.disconnect()
  }, [addAlert])

  return (
    <div className="min-h-screen bg-[#070a10] text-slate-200" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
      <Header connected={connected} />
      <TopBar stats={stats} />

      <main className="p-4 max-w-[1700px] mx-auto grid grid-cols-1 xl:grid-cols-[1fr_390px] gap-4">

        {/* Left column */}
        <div className="flex flex-col gap-4 min-w-0">
          <StatCards stats={stats} classCounts={classCounts} />
          <TimelineChart timeline={timeline} />
          <DonutChart classCounts={classCounts} />
        </div>

        {/* Right column */}
        <AlertFeed alerts={alerts} />

      </main>
    </div>
  )
}