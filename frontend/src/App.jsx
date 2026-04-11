import { useEffect, useState, useCallback } from "react"
import { io } from "socket.io-client"
import Header from "./components/Header"
import TopBar from "./components/TopBar"
import StatCards from "./components/StatCards"
import TimelineChart from "./components/TimelineChart"
import DonutChart from "./components/DonutChart"
import AlertFeed from "./components/AlertFeed"
import TrafficFeed from "./components/TrafficFeed"

const SOCKET_URL = import.meta.env.VITE_API_URL || "http://localhost:5005"

const INIT_STATS = {
  total_packets: 0,
  total_alerts: 0,
  packets_per_sec: 0,
  active_flows: 0,
  uptime_seconds: 0,
}
const INIT_COUNTS = { Normal: 0, DoS: 0, Probe: 0, R2L: 0, U2R: 0 }

export default function App() {
  const [connected, setConnected] = useState(false)
  const [stats, setStats] = useState(INIT_STATS)
  const [classCounts, setClassCounts] = useState(INIT_COUNTS)
  const [timeline, setTimeline] = useState([])
  const [alerts, setAlerts] = useState([])     // classified traffic (all types)
  const [rawPackets, setRawPackets] = useState([])     // raw / unclassified traffic
  const [isPaused, setIsPaused] = useState(false)
  const [filterType, setFilterType] = useState(null)   // null | "DoS" | "Probe" | "R2L" | "U2R"

  const addAlert = useCallback((alert) => {
    setAlerts(prev => [alert, ...prev].slice(0, 300))
  }, [])

  const addRawBatch = useCallback((batch) => {
    setRawPackets(prev => [...batch, ...prev].slice(0, 300))
  }, [])

  useEffect(() => {
    const socket = io(SOCKET_URL, {
      transports: ["websocket", "polling"],
      reconnectionDelay: 1000,
      reconnectionAttempts: 10,
    })

    socket.on("connect", () => setConnected(true))
    socket.on("disconnect", () => setConnected(false))

    socket.on("stats_update", (data) => {
      setStats(data.stats)
      setClassCounts(data.class_counts)
      setTimeline(data.timeline || [])
      // Sync paused state from backend stats too
      if (typeof data.stats?.is_paused === "boolean") {
        setIsPaused(data.stats.is_paused)
      }
    })

    socket.on("new_alert", addAlert)
    socket.on("raw_batch", addRawBatch)
    socket.on("capture_state", (data) => setIsPaused(data.is_paused))

    return () => socket.disconnect()
  }, [addAlert, addRawBatch])

  return (
    <div className="min-h-screen bg-[#070a10] text-slate-200" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
      <Header
        connected={connected}
        isPaused={isPaused}
      />
      <TopBar stats={stats} isPaused={isPaused} />

      <main className="p-4 max-w-[1700px] mx-auto grid grid-cols-1 xl:grid-cols-[1fr_370px] gap-4">

        {/* Left column */}
        <div className="flex flex-col gap-4 min-w-0">
          <StatCards
            stats={stats}
            classCounts={classCounts}
            filterType={filterType}
            setFilterType={setFilterType}
          />
          <TimelineChart timeline={timeline} />
          <DonutChart classCounts={classCounts} />

          {/* Traffic Feed with Raw + Classified tabs */}
          <TrafficFeed
            classified={alerts}
            raw={rawPackets}
            filterType={filterType}
            setFilterType={setFilterType}
          />
        </div>

        {/* Right column — Live alerts (attacks only) */}
        <AlertFeed alerts={alerts.filter(a => a.type !== "Normal")} />

      </main>
    </div>
  )
}