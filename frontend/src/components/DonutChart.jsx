import { useEffect, useRef } from "react"
import { Chart, DoughnutController, ArcElement, Tooltip } from "chart.js"

Chart.register(DoughnutController, ArcElement, Tooltip)

const ORDER  = ["Normal", "DoS", "Probe", "R2L", "U2R"]
const COLORS = {
  Normal: "#22c55e",
  DoS:    "#ef4444",
  Probe:  "#3b82f6",
  R2L:    "#f59e0b",
  U2R:    "#ec4899",
}
const LABELS = {
  Normal: "Normal traffic",
  DoS:    "Denial of Service",
  Probe:  "Probe / Scan",
  R2L:    "Remote to Local",
  U2R:    "User to Root",
}

export default function DonutChart({ classCounts }) {
  const canvasRef = useRef(null)
  const chartRef  = useRef(null)

  /* Init */
  useEffect(() => {
    const ctx = canvasRef.current.getContext("2d")
    chartRef.current = new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: ORDER,
        datasets: [{
          data:            ORDER.map(() => 1),
          backgroundColor: ORDER.map(k => COLORS[k]),
          borderColor:     "#070a10",
          borderWidth:     3,
          hoverOffset:     8,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "72%",
        animation: { duration: 600 },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: "rgba(10,13,20,0.95)",
            borderColor:     "rgba(255,255,255,0.08)",
            borderWidth:     1,
            titleColor:      "#64748b",
            bodyColor:       "#e2e8f0",
            titleFont: { family: "'JetBrains Mono', monospace", size: 11 },
            bodyFont:  { family: "'JetBrains Mono', monospace", size: 11 },
            callbacks: {
              label: ctx => {
                const total = ctx.dataset.data.reduce((a, b) => a + b, 0) || 1
                const pct   = ((ctx.parsed / total) * 100).toFixed(1)
                return ` ${ctx.label}: ${ctx.parsed.toLocaleString()} (${pct}%)`
              },
            },
          },
        },
      },
    })
    return () => chartRef.current?.destroy()
  }, [])

  /* Update */
  useEffect(() => {
    const chart = chartRef.current
    if (!chart) return
    const vals = ORDER.map(k => classCounts[k] ?? 0)
    chart.data.datasets[0].data = vals.every(v => v === 0) ? ORDER.map(() => 1) : vals
    chart.update()
  }, [classCounts])

  const total = ORDER.reduce((a, k) => a + (classCounts[k] ?? 0), 0)

  return (
    <div className="rounded-xl border border-white/[0.06] bg-[#0b0e16] overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-3 border-b border-white/[0.05]">
        <span
          className="text-sm font-bold text-slate-200"
          style={{ fontFamily: "'Syne', sans-serif" }}
        >
          Attack distribution
        </span>
        <span className="text-[10px] text-slate-600">all-time totals</span>
      </div>

      {/* Body */}
      <div className="flex flex-col sm:flex-row items-center gap-6 p-5">
        {/* Donut */}
        <div className="relative w-36 h-36 flex-shrink-0">
          <canvas ref={canvasRef} />
          <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
            <div
              className="text-xl font-black text-white tabular-nums leading-none"
              style={{ fontFamily: "'Syne', sans-serif" }}
            >
              {total.toLocaleString()}
            </div>
            <div className="text-[9px] text-slate-600 mt-1 uppercase tracking-wider">
              classified
            </div>
          </div>
        </div>

        {/* Legend with bars */}
        <div className="flex-1 w-full flex flex-col gap-2.5">
          {ORDER.map(k => {
            const v   = classCounts[k] ?? 0
            const pct = total > 0 ? (v / total) * 100 : 0
            return (
              <div key={k} className="flex items-center gap-3">
                {/* Color dot */}
                <span
                  className="w-2 h-2 rounded-sm flex-shrink-0"
                  style={{ background: COLORS[k] }}
                />
                {/* Name */}
                <span className="text-[11px] text-slate-400 w-12 flex-shrink-0">{k}</span>
                {/* Bar track */}
                <div className="flex-1 h-1.5 bg-white/5 rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-700 ease-out"
                    style={{ width: `${pct}%`, background: COLORS[k] }}
                  />
                </div>
                {/* Count */}
                <span className="text-[11px] tabular-nums text-slate-400 w-10 text-right flex-shrink-0">
                  {v.toLocaleString()}
                </span>
                {/* Pct */}
                <span className="text-[10px] tabular-nums text-slate-600 w-9 text-right flex-shrink-0">
                  {pct.toFixed(1)}%
                </span>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
