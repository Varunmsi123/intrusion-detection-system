import { useEffect, useRef, useCallback } from "react"
import {
  Chart,
  LineController,
  LineElement,
  PointElement,
  LinearScale,
  CategoryScale,
  Filler,
  Tooltip,
} from "chart.js"

Chart.register(LineController, LineElement, PointElement,
  LinearScale, CategoryScale, Filler, Tooltip)

const SERIES = [
  { key: "Normal", color: "#22c55e", label: "Normal" },
  { key: "DoS",    color: "#ef4444", label: "DoS" },
  { key: "Probe",  color: "#3b82f6", label: "Probe" },
  { key: "R2L",    color: "#f59e0b", label: "R2L" },
  { key: "U2R",    color: "#ec4899", label: "U2R" },
]

const CHART_OPTIONS = {
  responsive: true,
  maintainAspectRatio: false,
  animation: { duration: 0 },
  interaction: { intersect: false, mode: "index" },
  plugins: {
    legend: { display: false },
    tooltip: {
      backgroundColor: "rgba(10,13,20,0.95)",
      borderColor: "rgba(255,255,255,0.08)",
      borderWidth: 1,
      titleColor: "#64748b",
      bodyColor: "#e2e8f0",
      padding: 10,
      titleFont: { family: "'JetBrains Mono', monospace", size: 11 },
      bodyFont:  { family: "'JetBrains Mono', monospace", size: 11 },
      callbacks: {
        label: ctx => ` ${ctx.dataset.label}: ${ctx.parsed.y}`,
      },
    },
  },
  scales: {
    x: {
      ticks: {
        color: "#1e293b",
        font: { family: "'JetBrains Mono', monospace", size: 9 },
        maxTicksLimit: 10,
        maxRotation: 0,
      },
      grid: { color: "rgba(255,255,255,0.03)" },
      border: { color: "rgba(255,255,255,0.05)" },
    },
    y: {
      beginAtZero: true,
      ticks: {
        color: "#1e293b",
        font: { family: "'JetBrains Mono', monospace", size: 9 },
        maxTicksLimit: 6,
      },
      grid:   { color: "rgba(255,255,255,0.03)" },
      border: { color: "rgba(255,255,255,0.05)" },
    },
  },
}

export default function TimelineChart({ timeline }) {
  const canvasRef = useRef(null)
  const chartRef  = useRef(null)

  /* Init chart once */
  useEffect(() => {
    const ctx = canvasRef.current.getContext("2d")
    chartRef.current = new Chart(ctx, {
      type: "line",
      data: {
        labels: [],
        datasets: SERIES.map(s => ({
          label:           s.label,
          data:            [],
          borderColor:     s.color,
          backgroundColor: s.color + "14",
          fill:            true,
          tension:         0.4,
          pointRadius:     0,
          borderWidth:     1.5,
        })),
      },
      options: CHART_OPTIONS,
    })
    return () => chartRef.current?.destroy()
  }, [])

  /* Update on new data */
  useEffect(() => {
    const chart = chartRef.current
    if (!chart || !timeline.length) return
    chart.data.labels = timeline.map(t => t.time)
    SERIES.forEach((s, i) => {
      chart.data.datasets[i].data = timeline.map(t => t[s.key] ?? 0)
    })
    chart.update("none")
  }, [timeline])

  return (
    <div className="rounded-xl border border-white/[0.06] bg-[#0b0e16] overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-3 border-b border-white/[0.05]">
        <div>
          <span
            className="text-sm font-bold text-slate-200"
            style={{ fontFamily: "'Syne', sans-serif" }}
          >
            Traffic timeline
          </span>
          <span className="ml-3 text-[10px] text-slate-600">live · last 60s</span>
        </div>
        {/* Legend */}
        <div className="hidden sm:flex items-center gap-4">
          {SERIES.map(s => (
            <div key={s.key} className="flex items-center gap-1.5 text-[10px] text-slate-500">
              <span
                className="w-2.5 h-2.5 rounded-sm flex-shrink-0"
                style={{ background: s.color }}
              />
              {s.key}
            </div>
          ))}
        </div>
      </div>

      {/* Canvas */}
      <div className="p-4" style={{ height: "200px" }}>
        <canvas ref={canvasRef} />
      </div>
    </div>
  )
}
