import { useEffect, useState, useCallback } from "react"
import { io } from "socket.io-client"
import Header from "./components/Header"
import TopBar from "./components/TopBar"
import StatCards from "./components/StatCards"
import TimelineChart from "./components/TimelineChart"
import DonutChart from "./components/DonutChart"
import AlertFeed from "./components/AlertFeed"
import BlockedHosts from "./components/BlockedHosts"
import PreventionPanel from "./components/PreventionPanel"

const SOCKET_URL = import.meta.env.VITE_API_URL || "http://localhost:5000"

const INIT_STATS = {
  total_packets:   0,
  total_alerts:    0,
  packets_per_sec: 0,
  active_flows:    0,
  uptime_seconds:  0,
  blocked_hosts:   0,
}
const INIT_COUNTS = { Normal: 0, DoS: 0, Probe: 0, R2L: 0, U2R: 0 }

export default function App() {
  const [connected,      setConnected]      = useState(false)
  const [stats,          setStats]          = useState(INIT_STATS)
  const [classCounts,    setClassCounts]    = useState(INIT_COUNTS)
  const [timeline,       setTimeline]       = useState([])
  const [alerts,         setAlerts]         = useState([])
  const [blockedHosts,   setBlockedHosts]   = useState([])
  const [ipsActions,     setIpsActions]     = useState([])
  const [ipsMode,        setIpsMode]        = useState("simulate")
  const [redisConnected, setRedisConnected] = useState(false)

  const addAlert = useCallback((alert) => {
    setAlerts(prev => [alert, ...prev].slice(0, 200))
  }, [])

  const addIpsAction = useCallback((action) => {
    setIpsActions(prev => [action, ...prev].slice(0, 200))
  }, [])

  // Initial fetch of blocked hosts & status
  useEffect(() => {
    fetch(`${SOCKET_URL}/api/ips/status`)
      .then(r => r.json())
      .then(data => {
        if (data.mode) setIpsMode(data.mode)
        if (data.redis_connected !== undefined) setRedisConnected(data.redis_connected)
      })
      .catch(() => {})

    fetch(`${SOCKET_URL}/api/ips/blocked`)
      .then(r => r.json())
      .then(data => {
        if (Array.isArray(data)) setBlockedHosts(data)
      })
      .catch(() => {})

    fetch(`${SOCKET_URL}/api/ips/actions?limit=30`)
      .then(r => r.json())
      .then(data => {
        if (Array.isArray(data)) setIpsActions(data)
      })
      .catch(() => {})
  }, [])

  // Socket.IO real-time connection
  useEffect(() => {
    const socket = io(SOCKET_URL, {
      transports: ["websocket", "polling"],
      reconnectionDelay: 1000,
      reconnectionAttempts: 10,
    })

    socket.on("connect", () => setConnected(true))
    socket.on("disconnect", () => setConnected(false))

    socket.on("stats_update", (data) => {
      if (data.stats) setStats(data.stats)
      if (data.class_counts) setClassCounts(data.class_counts)
      if (data.timeline) setTimeline(data.timeline)
      if (data.ips_mode) setIpsMode(data.ips_mode)
      if (data.redis_connected !== undefined) setRedisConnected(data.redis_connected)
    })

    socket.on("new_alert", addAlert)
    socket.on("ips_action", addIpsAction)

    socket.on("blocked_hosts_update", (hosts) => {
      if (Array.isArray(hosts)) setBlockedHosts(hosts)
    })

    socket.on("ips_mode_changed", (data) => {
      if (data.mode) setIpsMode(data.mode)
    })

    return () => socket.disconnect()
  }, [addAlert, addIpsAction])

  // Handler: Toggle IPS Mode
  const handleToggleMode = async (newMode) => {
    try {
      const res = await fetch(`${SOCKET_URL}/api/ips/mode`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode: newMode })
      })
      const data = await res.json()
      if (data.mode) setIpsMode(data.mode)
    } catch (err) {
      console.error("Failed to toggle mode:", err)
    }
  }

  // Handler: Unblock IP
  const handleUnblock = async (ip) => {
    try {
      const res = await fetch(`${SOCKET_URL}/api/ips/unblock`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip })
      })
      const data = await res.json()
      if (data.success) {
        setBlockedHosts(prev => prev.filter(h => h.ip !== ip))
      }
    } catch (err) {
      console.error("Failed to unblock:", err)
    }
  }

  // Handler: Manual Block
  const handleManualBlock = async (ip, duration, attackType) => {
    try {
      const res = await fetch(`${SOCKET_URL}/api/ips/block`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip, duration, attack_type: attackType })
      })
      const data = await res.json()
      if (data.error) {
        alert(data.error)
      }
    } catch (err) {
      console.error("Failed to block:", err)
    }
  }

  // Handler: Emergency Flush
  const handleEmergencyReset = async () => {
    try {
      const res = await fetch(`${SOCKET_URL}/api/ips/reset`, {
        method: "POST"
      })
      const data = await res.json()
      if (data.success) {
        setBlockedHosts([])
      }
    } catch (err) {
      console.error("Failed to reset:", err)
    }
  }

  // Handler: Simulate Attack Flow (Progressive 4-stage showcase that stops once blocked)
  const handleSimulateAttack = async (attackType) => {
    try {
      // Pick a sample non-whitelisted test IP
      const randomHost = Math.floor(Math.random() * 200) + 10
      const testIp = `198.51.100.${randomHost}`

      if (attackType === "DoS") {
        // Multi-wave DoS burst sequence: 4 waves -> triggers BLOCK -> 5th drops and stops!
        const waves = [
          { packets: 15, confidence: 0.72 },
          { packets: 25, confidence: 0.78 },
          { packets: 40, confidence: 0.85 },
          { packets: 75, confidence: 0.96 },
          { packets: 75, confidence: 0.96 },
        ]
        for (const w of waves) {
          await fetch(`${SOCKET_URL}/api/ips/simulate_attack`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              attack_type: "DoS",
              src_ip: testIp,
              dst_port: 80,
              packets: w.packets,
              confidence: w.confidence
            })
          })
          await new Promise(r => setTimeout(r, 650))
        }
      } else if (attackType === "Probe") {
        // Multi-port scan sequence: ports 21, 22, 80, 443 -> triggers BLOCK -> 5th drops and stops!
        const ports = [
          { port: 21, srv: "ftp", conf: 0.72 },
          { port: 22, srv: "ssh", conf: 0.78 },
          { port: 80, srv: "http", conf: 0.84 },
          { port: 443, srv: "https", conf: 0.92 },
          { port: 8080, srv: "http", conf: 0.96 },
        ]
        for (const p of ports) {
          await fetch(`${SOCKET_URL}/api/ips/simulate_attack`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              attack_type: "Probe",
              src_ip: testIp,
              dst_port: p.port,
              service: p.srv,
              confidence: p.conf
            })
          })
          await new Promise(r => setTimeout(r, 650))
        }
      } else {
        await fetch(`${SOCKET_URL}/api/ips/simulate_attack`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ attack_type: attackType, src_ip: testIp })
        })
      }
    } catch (err) {
      console.error("Failed to simulate attack:", err)
    }
  }

  return (
    <div className="min-h-screen bg-[#070a10] text-slate-200" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
      <Header
        connected={connected}
        ipsMode={ipsMode}
        redisConnected={redisConnected}
        onToggleMode={handleToggleMode}
        onEmergencyReset={handleEmergencyReset}
      />
      <TopBar stats={stats} />

      <main className="p-4 max-w-[1750px] mx-auto grid grid-cols-1 xl:grid-cols-[1fr_400px] gap-4">

        {/* Left column */}
        <div className="flex flex-col gap-4 min-w-0">
          <StatCards stats={stats} classCounts={classCounts} />

          {/* Active IPS Blocklist with TTL & Unblock */}
          <BlockedHosts
            blockedHosts={blockedHosts}
            onUnblock={handleUnblock}
            onManualBlock={handleManualBlock}
          />

          {/* Prevention Stream & Attack Simulator */}
          <PreventionPanel
            actions={ipsActions}
            onSimulateAttack={handleSimulateAttack}
          />

          {/* Timeline & Donut Analytics */}
          <div className="grid grid-cols-1 lg:grid-cols-[1fr_380px] gap-4">
            <TimelineChart timeline={timeline} />
            <DonutChart classCounts={classCounts} />
          </div>
        </div>

        {/* Right column: Live Alert Feed */}
        <AlertFeed alerts={alerts} />

      </main>
    </div>
  )
}