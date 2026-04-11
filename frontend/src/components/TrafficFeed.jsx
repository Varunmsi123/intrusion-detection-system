import { useState } from "react"

const FEATURE_NAMES = [
  "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
  "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
  "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
  "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
  "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
  "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
  "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
  "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
  "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
  "dst_host_serror_rate", "dst_host_srv_serror_rate",
  "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
]

const TYPE_COLORS = {
  Normal: { label: "text-emerald-400", bg: "bg-emerald-500/10 border-emerald-500/30 text-emerald-400", accent: "#10b981", bar: "bg-emerald-500/20 border-l-emerald-500/50" },
  DoS:    { label: "text-red-400",     bg: "bg-red-500/10 border-red-500/30 text-red-400",             accent: "#ef4444", bar: "bg-red-500/5 border-l-red-500/50" },
  Probe:  { label: "text-blue-400",    bg: "bg-blue-500/10 border-blue-500/30 text-blue-400",           accent: "#3b82f6", bar: "bg-blue-500/5 border-l-blue-500/50" },
  R2L:    { label: "text-amber-400",   bg: "bg-amber-500/10 border-amber-500/30 text-amber-400",        accent: "#f59e0b", bar: "bg-amber-500/5 border-l-amber-500/50" },
  U2R:    { label: "text-pink-400",    bg: "bg-pink-500/10 border-pink-500/30 text-pink-400",           accent: "#ec4899", bar: "bg-pink-500/5 border-l-pink-500/50" },
}

/* ── Classified traffic row ──────────────────────────────────────────── */
function ClassifiedRow({ flow, isExpanded, onToggle }) {
  const cfg = TYPE_COLORS[flow.type] || TYPE_COLORS.DoS
  const isNormal = flow.type === "Normal"

  return (
    <>
      <tr
        className={`group cursor-pointer transition-all duration-150 border-b border-white/[0.04] ${
          isExpanded ? "bg-white/[0.05]" : "hover:bg-white/[0.03]"
        }`}
        onClick={onToggle}
      >
        <td className="px-4 py-2.5 text-[11px] tabular-nums text-slate-500 font-mono whitespace-nowrap">{flow.time}</td>
        <td className="px-4 py-2.5 text-[11px] font-mono text-slate-300">{flow.src_ip}</td>
        <td className="px-4 py-2.5 text-[11px] font-mono text-slate-300">{flow.dst_ip}</td>
        <td className="px-4 py-2.5">
          <span className="text-[9px] px-1.5 py-0.5 rounded bg-white/[0.04] border border-white/[0.08] text-slate-500 uppercase tracking-wider">
            {flow.service}
          </span>
        </td>
        <td className="px-4 py-2.5 text-[9px] text-slate-500 uppercase">{flow.protocol}</td>
        <td className="px-4 py-2.5">
          <span className={`text-[9px] font-bold uppercase tracking-widest px-2 py-0.5 rounded-full border ${cfg.bg}`}>
            {flow.type}
          </span>
        </td>
        <td className="px-4 py-2.5 text-[10px] font-mono text-slate-500">
          {flow.confidence != null ? (flow.confidence * 100).toFixed(1) + "%" : "—"}
        </td>
        <td className="px-3 py-2.5 text-right pr-4">
          <svg
            className={`w-3.5 h-3.5 text-slate-600 inline-block transition-transform duration-200 ${isExpanded ? "rotate-180" : ""}`}
            fill="none" viewBox="0 0 24 24" stroke="currentColor"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </td>
      </tr>

      {isExpanded && (
        <tr>
          <td colSpan="8" className={`px-5 py-5 border-b border-white/[0.06] border-l-2 ${cfg.bar}`}
            style={{ background: "rgba(0,0,0,0.35)" }}>
            <div className="max-w-5xl">
              {/* Header */}
              <div className="flex items-center gap-2 mb-4">
                <div className="w-1.5 h-4 rounded-full" style={{ background: cfg.accent }} />
                <span className="text-[10px] font-bold text-slate-300 tracking-widest uppercase">
                  NSL-KDD 41-Feature Vector
                </span>
                <span className={`ml-auto text-[9px] font-bold px-2 py-0.5 rounded-full border ${cfg.bg}`}>
                  {flow.type}
                </span>
              </div>

              {/* Feature grid */}
              {flow.features ? (
                <div className="grid grid-cols-3 sm:grid-cols-5 md:grid-cols-7 lg:grid-cols-9 gap-1.5 mb-5">
                  {flow.features.map((val, i) => (
                    <div
                      key={i}
                      className="flex flex-col p-1.5 rounded-lg border border-white/[0.05] bg-white/[0.02]"
                    >
                      <span className="text-[7.5px] text-slate-600 uppercase tracking-tight truncate" title={FEATURE_NAMES[i]}>
                        {FEATURE_NAMES[i] || `f${i + 1}`}
                      </span>
                      <span className={`text-[10px] font-mono mt-0.5 ${
                        val === 0 ? "text-slate-600" : "text-emerald-400 font-semibold"
                      }`}>
                        {typeof val === "number"
                          ? val % 1 === 0 ? val : val.toFixed(3).replace(/\.?0+$/, "")
                          : val}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-[11px] text-slate-600 italic mb-4">
                  Features not available for classified flows in this view.
                </div>
              )}

              {/* Insight panel */}
              <div
                className="p-3 rounded-xl border flex items-start gap-3"
                style={{
                  background: isNormal ? "rgba(16,185,129,0.04)" : `rgba(0,0,0,0.2)`,
                  borderColor: isNormal ? "rgba(16,185,129,0.15)" : `${cfg.accent}25`,
                }}
              >
                <div className="p-1.5 rounded-lg flex-shrink-0" style={{ background: `${cfg.accent}15` }}>
                  <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                    style={{ color: cfg.accent }}>
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                      d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </div>
                <div>
                  <div className="text-[9px] font-bold uppercase tracking-wider mb-1"
                    style={{ color: cfg.accent }}>
                    Analyzer Insight
                  </div>
                  <p className="text-[11px] text-slate-400 leading-relaxed">
                    {isNormal
                      ? "Pattern matches normal baseline characteristics. No immediate intervention required."
                      : `High-confidence ${flow.type} activity detected. Signature matches ${flow.service || "unknown"} service features. Protocol: ${flow.protocol || "n/a"}. Duration: ${flow.duration ?? 0}s.`}
                  </p>
                </div>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

/* ── Raw traffic row ──────────────────────────────────────────── */
function RawRow({ pkt, isExpanded, onToggle }) {
  return (
    <>
      <tr
        className={`group cursor-pointer transition-all duration-150 border-b border-white/[0.04] ${
          isExpanded ? "bg-white/[0.04]" : "hover:bg-white/[0.025]"
        }`}
        onClick={onToggle}
      >
        <td className="px-4 py-2.5 text-[11px] tabular-nums text-slate-500 font-mono whitespace-nowrap">{pkt.time}</td>
        <td className="px-4 py-2.5 text-[11px] font-mono text-slate-300">{pkt.src_ip}</td>
        <td className="px-4 py-2.5 text-[11px] font-mono text-slate-300">{pkt.dst_ip}</td>
        <td className="px-4 py-2.5 text-[10px] font-mono text-slate-400 tabular-nums">{pkt.src_port}</td>
        <td className="px-4 py-2.5 text-[10px] font-mono text-slate-400 tabular-nums">{pkt.dst_port}</td>
        <td className="px-4 py-2.5">
          <span className="text-[9px] px-1.5 py-0.5 rounded bg-white/[0.04] border border-white/[0.08] text-slate-500 uppercase tracking-wider">
            {pkt.service}
          </span>
        </td>
        <td className="px-4 py-2.5 text-[9px] text-slate-500 uppercase">{pkt.protocol}</td>
        <td className="px-4 py-2.5 text-[10px] font-mono text-slate-500 tabular-nums">{pkt.size}B</td>
        <td className="px-3 py-2.5 text-right pr-4">
          <svg
            className={`w-3.5 h-3.5 text-slate-600 inline-block transition-transform duration-200 ${isExpanded ? "rotate-180" : ""}`}
            fill="none" viewBox="0 0 24 24" stroke="currentColor"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </td>
      </tr>

      {isExpanded && (
        <tr>
          <td colSpan="9" className="px-5 py-5 border-b border-white/[0.06] border-l-2 border-l-slate-700/50"
            style={{ background: "rgba(0,0,0,0.3)" }}>
            <div className="max-w-3xl">
              <div className="flex items-center gap-2 mb-3">
                <div className="w-1.5 h-4 rounded-full bg-slate-600" />
                <span className="text-[10px] font-bold text-slate-400 tracking-widest uppercase">
                  Raw Packet Details
                </span>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2">
                {[
                  { label: "Source IP",    value: pkt.src_ip },
                  { label: "Destination",  value: pkt.dst_ip },
                  { label: "Src Port",     value: pkt.src_port },
                  { label: "Dst Port",     value: pkt.dst_port },
                  { label: "Protocol",     value: pkt.protocol?.toUpperCase() },
                  { label: "Service",      value: pkt.service },
                  { label: "Packet Size",  value: `${pkt.size} bytes` },
                  { label: "TCP Flags",    value: pkt.flags || "—" },
                  { label: "Timestamp",    value: pkt.timestamp?.replace("T", " ").slice(0, 19) || pkt.time },
                ].map(({ label, value }) => (
                  <div key={label} className="flex flex-col p-2 rounded-lg border border-white/[0.05] bg-white/[0.02]">
                    <span className="text-[8px] text-slate-600 uppercase tracking-wider mb-0.5">{label}</span>
                    <span className="text-[11px] font-mono text-slate-300">{value}</span>
                  </div>
                ))}
              </div>
              <div className="mt-4 p-3 rounded-xl border border-slate-700/30 bg-white/[0.02] flex items-start gap-3">
                <div className="p-1.5 rounded-lg bg-slate-700/30 flex-shrink-0">
                  <svg className="w-3.5 h-3.5 text-slate-500" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                      d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                </div>
                <div>
                  <div className="text-[9px] font-bold text-slate-500 uppercase tracking-wider mb-1">Raw Note</div>
                  <p className="text-[11px] text-slate-500 leading-relaxed">
                    This is an unclassified raw packet. It has not yet been analyzed by the ML model.
                    Classification occurs after the flow window ({">"}5s) expires.
                  </p>
                </div>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

/* ── Main TrafficFeed component ─────────────────────────────── */
export default function TrafficFeed({ classified, raw, filterType, setFilterType }) {
  const [tab, setTab] = useState("classified") // "classified" | "raw"
  const [expandedId, setExpandedId] = useState(null)

  const filteredClassified = filterType
    ? classified.filter(f => f.type === filterType)
    : classified

  const toggleExpand = (id) => setExpandedId(prev => prev === id ? null : id)

  return (
    <div className="flex flex-col gap-0 rounded-2xl border border-white/[0.06] overflow-hidden bg-[#0b0e16]">

      {/* Tab bar */}
      <div className="flex items-center border-b border-white/[0.06] bg-black/20 px-4 py-0 flex-shrink-0">
        <div className="flex gap-0">
          {[
            { id: "classified", label: "Classified Traffic", icon: "🔍" },
            { id: "raw",        label: "Raw Traffic",        icon: "📡" },
          ].map(({ id, label, icon }) => (
            <button
              key={id}
              onClick={() => { setTab(id); setExpandedId(null) }}
              className={`px-4 py-3 text-[10px] font-bold uppercase tracking-widest transition-all duration-200 border-b-2 ${
                tab === id
                  ? "border-red-500 text-red-400 bg-red-500/5"
                  : "border-transparent text-slate-600 hover:text-slate-400 hover:border-white/10"
              }`}
            >
              <span className="mr-1.5">{icon}</span>
              {label}
              <span className={`ml-2 text-[8px] px-1.5 py-0.5 rounded-full ${
                tab === id ? "bg-red-500/20 text-red-400" : "bg-white/5 text-slate-600"
              }`}>
                {id === "classified" ? filteredClassified.length : raw.length}
              </span>
            </button>
          ))}
        </div>

        {/* Filter indicator */}
        {tab === "classified" && filterType && (
          <div className="ml-auto flex items-center gap-2">
            <span className="text-[9px] text-slate-500">Filtered:</span>
            <span className={`text-[9px] font-bold px-2 py-0.5 rounded-full border ${
              TYPE_COLORS[filterType]?.bg || "bg-white/5 border-white/10 text-slate-400"
            }`}>
              {filterType}
            </span>
            <button
              onClick={() => setFilterType(null)}
              className="text-[9px] text-slate-600 hover:text-red-400 transition-colors px-1.5 py-0.5 rounded border border-white/[0.06] hover:border-red-500/30"
            >
              ✕ Clear
            </button>
          </div>
        )}

        <div className={`${tab === "classified" && filterType ? "" : "ml-auto"} text-[9px] text-slate-600 bg-white/[0.03] border border-white/[0.06] px-2 py-1 rounded-full`}>
          {tab === "classified"
            ? `${filteredClassified.length}/${classified.length} flows`
            : `${raw.length} packets`}
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto overflow-y-auto" style={{ maxHeight: "480px" }}>
        {tab === "classified" ? (
          <table className="w-full text-left border-collapse min-w-[700px]">
            <thead className="sticky top-0 z-10">
              <tr className="border-b border-white/[0.07] bg-[#0b0e16]">
                {["Time", "Source IP", "Destination IP", "Service", "Protocol", "Label", "Conf.", ""].map(h => (
                  <th key={h} className="px-4 py-2.5 text-[9px] font-bold text-slate-600 uppercase tracking-widest whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filteredClassified.length === 0 ? (
                <tr>
                  <td colSpan="8" className="px-4 py-16 text-center text-slate-700 italic text-xs">
                    {filterType ? `No ${filterType} traffic detected yet.` : "Waiting for classified flows…"}
                  </td>
                </tr>
              ) : (
                filteredClassified.map((flow) => (
                  <ClassifiedRow
                    key={flow.id}
                    flow={flow}
                    isExpanded={expandedId === flow.id}
                    onToggle={() => toggleExpand(flow.id)}
                  />
                ))
              )}
            </tbody>
          </table>
        ) : (
          <table className="w-full text-left border-collapse min-w-[700px]">
            <thead className="sticky top-0 z-10">
              <tr className="border-b border-white/[0.07] bg-[#0b0e16]">
                {["Time", "Source IP", "Destination IP", "Src Port", "Dst Port", "Service", "Protocol", "Size", ""].map(h => (
                  <th key={h} className="px-4 py-2.5 text-[9px] font-bold text-slate-600 uppercase tracking-widest whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {raw.length === 0 ? (
                <tr>
                  <td colSpan="9" className="px-4 py-16 text-center text-slate-700 italic text-xs">
                    No raw packets received yet…
                  </td>
                </tr>
              ) : (
                raw.map((pkt) => (
                  <RawRow
                    key={pkt.id}
                    pkt={pkt}
                    isExpanded={expandedId === `raw_${pkt.id}`}
                    onToggle={() => toggleExpand(`raw_${pkt.id}`)}
                  />
                ))
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
