import { useState, useEffect, useCallback, useRef } from "react";
import {
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
  PieChart, Pie, Legend
} from "recharts";

// ─── CONSTANTS ───────────────────────────────────────────────────────────────
const API_BASE = "http://localhost:8000";

const SEV_META = {
  Critical: { color: "#f85149", bg: "#3d1a1a", rank: 0 },
  High:     { color: "#f0883e", bg: "#3a2010", rank: 1 },
  Medium:   { color: "#e3b341", bg: "#332a00", rank: 2 },
  Low:      { color: "#58a6ff", bg: "#0d2440", rank: 3 },
  Info:     { color: "#8b949e", bg: "#1c2128", rank: 4 },
};

const VULN_ICONS = {
  "SQLi":    "💉",
  "XSS":     "🕸️",
  "IDOR":    "🔓",
  "JWT":     "🪙",
  "CSRF":    "🎭",
  "Header":  "🛡️",
  "Cookie":  "🍪",
  "Info":    "ℹ️",
};

const SAMPLE_FINDINGS = [
  { type: "SQLi - Error Based",        param: "username",                 payload: "' OR 1=1--",                           evidence: "DB error: sqlite3.OperationalError",               severity: "Critical", cvss: 9.8, url: "http://localhost:5000/api/login" },
  { type: "SQLi - UNION Based",        param: "q",                        payload: "' UNION SELECT NULL,NULL,NULL,NULL--",  evidence: "No error at 4 columns — UNION successful",        severity: "Critical", cvss: 9.8, url: "http://localhost:5000/api/products/search" },
  { type: "SQLi - Boolean Blind",      param: "username",                 payload: "' OR 1=1-- / ' AND 1=2--",             evidence: "Length diff: 312 (true) vs 198 (false) bytes",     severity: "High",     cvss: 8.6, url: "http://localhost:5000/api/user/exists" },
  { type: "IDOR - Broken Access Control", param: "order_id=1",           payload: "GET /api/orders/1 (no auth)",           evidence: "credit_card exposed: 4222-2222-2222-2222",         severity: "Critical", cvss: 9.1, url: "http://localhost:5000/api/orders/1" },
  { type: "IDOR - Broken Access Control", param: "order_id=2",           payload: "GET /api/orders/2 (no auth)",           evidence: "credit_card exposed: 4333-3333-3333-3333",         severity: "Critical", cvss: 9.1, url: "http://localhost:5000/api/orders/2" },
  { type: "XSS - Reflected",           param: "name",                     payload: "<script>alert('xss')</script>",         evidence: "Payload reflected unescaped in HTML body",         severity: "High",     cvss: 7.4, url: "http://localhost:5000/api/xss/reflect" },
  { type: "XSS - Stored",              param: "content",                  payload: "<img src=x onerror=alert('xss')>",      evidence: "Payload persisted and rendered at /comments",      severity: "Critical", cvss: 8.8, url: "http://localhost:5000/api/xss/comments" },
  { type: "JWT Role Tampering",        param: "Authorization header",     payload: "Bearer eyJ... (forged admin)",          evidence: "Forged admin JWT accepted — weak secret used",     severity: "Critical", cvss: 9.8, url: "http://localhost:5000/api/jwt/admin" },
  { type: "CSRF - Missing Token",      param: "POST body",                payload: '{"to":"attacker","amount":"1000"}',      evidence: "State-changing request accepted without token",    severity: "High",     cvss: 7.5, url: "http://localhost:5000/api/csrf/transfer" },
  { type: "Missing Security Header",   param: "Content-Security-Policy",  payload: "-",                                    evidence: "Add CSP to restrict script/style sources",         severity: "High",     cvss: 6.1, url: "http://localhost:5000/" },
  { type: "Missing Security Header",   param: "X-Frame-Options",          payload: "-",                                    evidence: "Set to DENY/SAMEORIGIN to block clickjacking",     severity: "Medium",   cvss: 4.3, url: "http://localhost:5000/" },
  { type: "Missing Security Header",   param: "Strict-Transport-Security", payload: "-",                                   evidence: "Enforce HTTPS via HSTS header",                    severity: "Medium",   cvss: 5.3, url: "http://localhost:5000/" },
  { type: "Insecure Cookie Flags",     param: "Set-Cookie",               payload: "-",                                    evidence: "Missing: HttpOnly, Secure, SameSite",              severity: "High",     cvss: 6.5, url: "http://localhost:5000/" },
  { type: "Information Disclosure",    param: "Server",                   payload: "-",                                    evidence: "Server banner: Werkzeug/3.0.1 Python/3.11.8",      severity: "Low",      cvss: 2.0, url: "http://localhost:5000/" },
];

// ─── HELPERS ─────────────────────────────────────────────────────────────────
function severityCounts(findings) {
  const c = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  findings.forEach(f => { c[f.severity] = (c[f.severity] || 0) + 1; });
  return c;
}

function cvssColor(score) {
  if (score >= 9)  return "#f85149";
  if (score >= 7)  return "#f0883e";
  if (score >= 4)  return "#e3b341";
  return "#58a6ff";
}

function getVulnIcon(type) {
  for (const [key, icon] of Object.entries(VULN_ICONS)) {
    if (type.toLowerCase().includes(key.toLowerCase())) return icon;
  }
  return "🔍";
}

function timeAgo(ts) {
  if (!ts) return "just now";
  const diff = (Date.now() - new Date(ts)) / 1000;
  if (diff < 60)   return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  return `${Math.floor(diff/3600)}h ago`;
}

// ─── COMPONENTS ──────────────────────────────────────────────────────────────

function Navbar({ scanning, onScan, target, setTarget, lastScan }) {
  return (
    <nav style={{
      background: "#010409",
      borderBottom: "1px solid #21262d",
      padding: "0 2rem",
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      height: "56px",
      position: "sticky",
      top: 0,
      zIndex: 100,
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
        <span style={{ fontSize: "1.4rem" }}>🛡️</span>
        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontWeight: 700, color: "#f85149", fontSize: "1rem", letterSpacing: "0.05em" }}>
          VulnScan<span style={{ color: "#8b949e" }}>Pro</span>
        </span>
        <span style={{ background: "#21262d", color: "#58a6ff", fontSize: "0.65rem", padding: "2px 8px", borderRadius: "999px", fontFamily: "monospace" }}>
          v1.3.0
        </span>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
        {lastScan && (
          <span style={{ color: "#484f58", fontSize: "0.75rem", fontFamily: "monospace" }}>
            Last scan: {timeAgo(lastScan)}
          </span>
        )}
        <input
          value={target}
          onChange={e => setTarget(e.target.value)}
          placeholder="http://localhost:5000"
          style={{
            background: "#0d1117",
            border: "1px solid #30363d",
            borderRadius: "6px",
            color: "#c9d1d9",
            padding: "6px 12px",
            fontFamily: "monospace",
            fontSize: "0.82rem",
            width: "240px",
            outline: "none",
          }}
        />
        <button
          onClick={onScan}
          disabled={scanning}
          style={{
            background: scanning ? "#21262d" : "#f85149",
            color: scanning ? "#484f58" : "#fff",
            border: "none",
            borderRadius: "6px",
            padding: "7px 18px",
            cursor: scanning ? "not-allowed" : "pointer",
            fontFamily: "'JetBrains Mono', monospace",
            fontWeight: 600,
            fontSize: "0.82rem",
            display: "flex",
            alignItems: "center",
            gap: "6px",
            transition: "all 0.2s",
          }}
        >
          {scanning ? (
            <><SpinnerIcon /> Scanning…</>
          ) : (
            <><span>▶</span> Run Scan</>
          )}
        </button>
      </div>
    </nav>
  );
}

function SpinnerIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
      style={{ animation: "spin 1s linear infinite" }}>
      <path d="M21 12a9 9 0 1 1-6.219-8.56" />
    </svg>
  );
}

function StatCard({ label, value, color, bg, icon, sub }) {
  return (
    <div style={{
      background: bg || "#161b22",
      border: `1px solid ${color}33`,
      borderRadius: "10px",
      padding: "1.1rem 1.4rem",
      minWidth: "120px",
      flex: 1,
      position: "relative",
      overflow: "hidden",
    }}>
      <div style={{ position: "absolute", right: "12px", top: "10px", fontSize: "1.6rem", opacity: 0.18 }}>{icon}</div>
      <div style={{ color: "#8b949e", fontSize: "0.7rem", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: "6px" }}>{label}</div>
      <div style={{ color, fontSize: "2rem", fontWeight: 800, lineHeight: 1, fontFamily: "monospace" }}>{value}</div>
      {sub && <div style={{ color: "#484f58", fontSize: "0.72rem", marginTop: "4px" }}>{sub}</div>}
    </div>
  );
}

function SeverityBadge({ sev }) {
  const m = SEV_META[sev] || SEV_META.Info;
  return (
    <span style={{
      background: m.bg,
      color: m.color,
      border: `1px solid ${m.color}55`,
      padding: "2px 10px",
      borderRadius: "999px",
      fontSize: "0.72rem",
      fontWeight: 700,
      fontFamily: "monospace",
      whiteSpace: "nowrap",
    }}>{sev}</span>
  );
}

function CvssBar({ score }) {
  const pct = (score / 10) * 100;
  const col = cvssColor(score);
  return (
    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
      <div style={{ flex: 1, height: "5px", background: "#21262d", borderRadius: "3px", overflow: "hidden" }}>
        <div style={{ width: `${pct}%`, height: "100%", background: col, borderRadius: "3px", transition: "width 0.6s" }} />
      </div>
      <span style={{ color: col, fontSize: "0.78rem", fontWeight: 700, fontFamily: "monospace", minWidth: "28px" }}>{score}</span>
    </div>
  );
}

function FindingsTable({ findings, filter, setFilter }) {
  const [expanded, setExpanded] = useState(null);
  const [sortKey, setSortKey] = useState("severity");

  const filtered = findings
    .filter(f => !filter || f.severity === filter)
    .sort((a, b) => {
      if (sortKey === "severity") return (SEV_META[a.severity]?.rank ?? 5) - (SEV_META[b.severity]?.rank ?? 5);
      if (sortKey === "cvss")     return b.cvss - a.cvss;
      return a.type.localeCompare(b.type);
    });

  return (
    <div style={{ background: "#161b22", border: "1px solid #30363d", borderRadius: "10px", overflow: "hidden" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 16px", borderBottom: "1px solid #30363d", flexWrap: "wrap", gap: "8px" }}>
        <span style={{ color: "#c9d1d9", fontWeight: 600, fontSize: "0.9rem" }}>
          Findings <span style={{ color: "#484f58", fontWeight: 400 }}>({filtered.length})</span>
        </span>
        <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
          {["All", ...Object.keys(SEV_META)].map(s => (
            <button key={s} onClick={() => setFilter(s === "All" ? null : s)}
              style={{
                background: (filter === s || (s === "All" && !filter)) ? (SEV_META[s]?.bg || "#21262d") : "transparent",
                color: (filter === s || (s === "All" && !filter)) ? (SEV_META[s]?.color || "#c9d1d9") : "#484f58",
                border: `1px solid ${(filter === s || (s === "All" && !filter)) ? (SEV_META[s]?.color || "#58a6ff") : "#30363d"}`,
                borderRadius: "6px",
                padding: "3px 10px",
                cursor: "pointer",
                fontSize: "0.75rem",
                fontFamily: "monospace",
                transition: "all 0.15s",
              }}
            >{s}</button>
          ))}
          <select value={sortKey} onChange={e => setSortKey(e.target.value)}
            style={{ background: "#0d1117", color: "#8b949e", border: "1px solid #30363d", borderRadius: "6px", padding: "3px 8px", fontSize: "0.75rem", cursor: "pointer" }}>
            <option value="severity">Sort: Severity</option>
            <option value="cvss">Sort: CVSS</option>
            <option value="type">Sort: Type</option>
          </select>
        </div>
      </div>

      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.83rem" }}>
          <thead>
            <tr style={{ borderBottom: "1px solid #21262d" }}>
              {["", "Severity", "Vulnerability", "Parameter", "CVSS", "URL"].map(h => (
                <th key={h} style={{ padding: "10px 14px", textAlign: "left", color: "#484f58", fontWeight: 500, fontSize: "0.72rem", textTransform: "uppercase", letterSpacing: "0.06em", whiteSpace: "nowrap" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((f, i) => (
              <>
                <tr key={i}
                  onClick={() => setExpanded(expanded === i ? null : i)}
                  style={{
                    borderBottom: "1px solid #21262d",
                    cursor: "pointer",
                    background: expanded === i ? "#1c2128" : "transparent",
                    transition: "background 0.15s",
                  }}
                  onMouseEnter={e => { if (expanded !== i) e.currentTarget.style.background = "#0d1117"; }}
                  onMouseLeave={e => { if (expanded !== i) e.currentTarget.style.background = "transparent"; }}
                >
                  <td style={{ padding: "10px 14px", fontSize: "1.1rem" }}>{getVulnIcon(f.type)}</td>
                  <td style={{ padding: "10px 14px", whiteSpace: "nowrap" }}><SeverityBadge sev={f.severity} /></td>
                  <td style={{ padding: "10px 14px", color: "#c9d1d9", fontWeight: 500 }}>{f.type}</td>
                  <td style={{ padding: "10px 14px", color: "#79c0ff", fontFamily: "monospace", fontSize: "0.78rem" }}>{f.param}</td>
                  <td style={{ padding: "10px 14px", minWidth: "100px" }}><CvssBar score={f.cvss} /></td>
                  <td style={{ padding: "10px 14px", color: "#484f58", fontFamily: "monospace", fontSize: "0.72rem", maxWidth: "200px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.url}</td>
                </tr>
                {expanded === i && (
                  <tr key={`exp-${i}`} style={{ background: "#0d1117" }}>
                    <td colSpan={6} style={{ padding: "12px 18px" }}>
                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
                        <div>
                          <div style={{ color: "#484f58", fontSize: "0.7rem", textTransform: "uppercase", marginBottom: "4px" }}>Payload</div>
                          <div style={{ background: "#161b22", border: "1px solid #30363d", borderRadius: "6px", padding: "8px 12px", fontFamily: "monospace", fontSize: "0.8rem", color: "#f0883e", wordBreak: "break-all" }}>{f.payload}</div>
                        </div>
                        <div>
                          <div style={{ color: "#484f58", fontSize: "0.7rem", textTransform: "uppercase", marginBottom: "4px" }}>Evidence</div>
                          <div style={{ background: "#161b22", border: "1px solid #30363d", borderRadius: "6px", padding: "8px 12px", fontFamily: "monospace", fontSize: "0.8rem", color: "#3fb950", wordBreak: "break-all" }}>{f.evidence}</div>
                        </div>
                        <div style={{ gridColumn: "span 2" }}>
                          <div style={{ color: "#484f58", fontSize: "0.7rem", textTransform: "uppercase", marginBottom: "4px" }}>Full URL</div>
                          <div style={{ background: "#161b22", border: "1px solid #30363d", borderRadius: "6px", padding: "8px 12px", fontFamily: "monospace", fontSize: "0.8rem", color: "#58a6ff" }}>{f.url}</div>
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </>
            ))}
            {filtered.length === 0 && (
              <tr><td colSpan={6} style={{ padding: "2rem", textAlign: "center", color: "#484f58" }}>No findings match this filter.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ScanLog({ logs }) {
  const ref = useRef(null);
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [logs]);

  return (
    <div style={{ background: "#010409", border: "1px solid #21262d", borderRadius: "10px", overflow: "hidden" }}>
      <div style={{ padding: "10px 16px", borderBottom: "1px solid #21262d", display: "flex", alignItems: "center", gap: "8px" }}>
        <div style={{ width: "8px", height: "8px", borderRadius: "50%", background: logs.length ? "#3fb950" : "#484f58", boxShadow: logs.length ? "0 0 6px #3fb950" : "none" }} />
        <span style={{ color: "#8b949e", fontSize: "0.78rem", fontFamily: "monospace" }}>Scan Terminal</span>
      </div>
      <div ref={ref} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "0.75rem", padding: "12px 16px", height: "200px", overflowY: "auto", lineHeight: 1.7 }}>
        {logs.length === 0 && <span style={{ color: "#484f58" }}>$ Awaiting scan command…</span>}
        {logs.map((l, i) => {
          const col = l.includes("CRITICAL") || l.includes("ERROR") ? "#f85149"
                    : l.includes("High") ? "#f0883e"
                    : l.includes("clean") || l.includes("✓") ? "#3fb950"
                    : l.includes("[*]") ? "#58a6ff"
                    : "#8b949e";
          return <div key={i} style={{ color: col }}>{l}</div>;
        })}
      </div>
    </div>
  );
}

function RadarVuln({ findings }) {
  const cats = [
    { label: "SQL Injection", key: "SQLi" },
    { label: "XSS",           key: "XSS" },
    { label: "Access Control",key: "IDOR" },
    { label: "Auth / JWT",    key: "JWT" },
    { label: "CSRF",          key: "CSRF" },
    { label: "Headers",       key: "Header" },
  ];
  const data = cats.map(c => ({
    subject: c.label,
    count: findings.filter(f => f.type.toLowerCase().includes(c.key.toLowerCase())).length,
  }));
  return (
    <div style={{ background: "#161b22", border: "1px solid #30363d", borderRadius: "10px", padding: "1rem" }}>
      <div style={{ color: "#8b949e", fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "8px" }}>Vulnerability Radar</div>
      <ResponsiveContainer width="100%" height={220}>
        <RadarChart data={data} cx="50%" cy="50%" outerRadius="65%">
          <PolarGrid stroke="#21262d" />
          <PolarAngleAxis dataKey="subject" tick={{ fill: "#8b949e", fontSize: 11 }} />
          <PolarRadiusAxis tick={false} axisLine={false} />
          <Radar name="Findings" dataKey="count" stroke="#f85149" fill="#f85149" fillOpacity={0.25} />
        </RadarChart>
      </ResponsiveContainer>
    </div>
  );
}

function SeverityPie({ findings }) {
  const counts = severityCounts(findings);
  const data = Object.entries(SEV_META)
    .map(([sev, m]) => ({ name: sev, value: counts[sev] || 0, color: m.color }))
    .filter(d => d.value > 0);

  return (
    <div style={{ background: "#161b22", border: "1px solid #30363d", borderRadius: "10px", padding: "1rem" }}>
      <div style={{ color: "#8b949e", fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "8px" }}>Severity Split</div>
      <ResponsiveContainer width="100%" height={220}>
        <PieChart>
          <Pie data={data} cx="50%" cy="50%" innerRadius={55} outerRadius={85} dataKey="value" paddingAngle={3}>
            {data.map((d, i) => <Cell key={i} fill={d.color} stroke="transparent" />)}
          </Pie>
          <Tooltip contentStyle={{ background: "#161b22", border: "1px solid #30363d", borderRadius: "6px", fontFamily: "monospace", fontSize: "0.8rem" }} />
          <Legend wrapperStyle={{ fontSize: "0.75rem", fontFamily: "monospace" }} />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}

function CvssChart({ findings }) {
  const data = [...findings]
    .sort((a, b) => b.cvss - a.cvss)
    .slice(0, 8)
    .map(f => ({ name: f.type.replace(/^(SQLi|XSS|IDOR|JWT|CSRF) - /, "").slice(0, 18), cvss: f.cvss, color: cvssColor(f.cvss) }));

  return (
    <div style={{ background: "#161b22", border: "1px solid #30363d", borderRadius: "10px", padding: "1rem" }}>
      <div style={{ color: "#8b949e", fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "8px" }}>Top CVSS Scores</div>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={data} layout="vertical" margin={{ left: 4, right: 16 }}>
          <XAxis type="number" domain={[0, 10]} tick={{ fill: "#484f58", fontSize: 10 }} axisLine={false} tickLine={false} />
          <YAxis type="category" dataKey="name" tick={{ fill: "#8b949e", fontSize: 10 }} width={130} axisLine={false} tickLine={false} />
          <Tooltip contentStyle={{ background: "#161b22", border: "1px solid #30363d", borderRadius: "6px", fontFamily: "monospace", fontSize: "0.8rem" }} cursor={{ fill: "#21262d" }} />
          <Bar dataKey="cvss" radius={[0, 4, 4, 0]}>
            {data.map((d, i) => <Cell key={i} fill={d.color} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function RiskMeter({ findings }) {
  const counts = severityCounts(findings);
  const score = Math.min(100, (counts.Critical * 20 + counts.High * 10 + counts.Medium * 5 + counts.Low * 1));
  const col = score >= 70 ? "#f85149" : score >= 40 ? "#f0883e" : score >= 20 ? "#e3b341" : "#3fb950";
  const label = score >= 70 ? "CRITICAL RISK" : score >= 40 ? "HIGH RISK" : score >= 20 ? "MEDIUM RISK" : "LOW RISK";

  const r = 54, cx = 70, cy = 70;
  const startAngle = 210, endAngle = 210 + (score / 100) * 300;
  const toRad = d => (d * Math.PI) / 180;
  const arc = (a1, a2, rr) => {
    const x1 = cx + rr * Math.cos(toRad(a1)), y1 = cy + rr * Math.sin(toRad(a1));
    const x2 = cx + rr * Math.cos(toRad(a2)), y2 = cy + rr * Math.sin(toRad(a2));
    const lg = a2 - a1 > 180 ? 1 : 0;
    return `M ${x1} ${y1} A ${rr} ${rr} 0 ${lg} 1 ${x2} ${y2}`;
  };

  return (
    <div style={{ background: "#161b22", border: "1px solid #30363d", borderRadius: "10px", padding: "1rem", display: "flex", flexDirection: "column", alignItems: "center" }}>
      <div style={{ color: "#8b949e", fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "8px", alignSelf: "flex-start" }}>Risk Score</div>
      <svg width="140" height="100" viewBox="0 0 140 100">
        <path d={arc(210, 210 + 300, r)} fill="none" stroke="#21262d" strokeWidth="10" strokeLinecap="round" />
        {score > 0 && <path d={arc(210, endAngle, r)} fill="none" stroke={col} strokeWidth="10" strokeLinecap="round" />}
        <text x={cx} y={cy + 10} textAnchor="middle" fill={col} fontSize="24" fontWeight="800" fontFamily="monospace">{score}</text>
        <text x={cx} y={cy + 26} textAnchor="middle" fill="#484f58" fontSize="9" fontFamily="monospace">/100</text>
      </svg>
      <div style={{ color: col, fontWeight: 700, fontFamily: "monospace", fontSize: "0.85rem", marginTop: "-6px", letterSpacing: "0.05em" }}>{label}</div>
    </div>
  );
}

// ─── MAIN APP ────────────────────────────────────────────────────────────────
export default function App() {
  const [findings, setFindings]   = useState(SAMPLE_FINDINGS);
  const [scanning, setScanning]   = useState(false);
  const [logs, setLogs]           = useState([]);
  const [filter, setFilter]       = useState(null);
  const [target, setTarget]       = useState("http://localhost:5000");
  const [lastScan, setLastScan]   = useState(null);
  const [activeTab, setActiveTab] = useState("dashboard");
  const [apiOnline, setApiOnline] = useState(false);

  useEffect(() => {
    fetch(`${API_BASE}/api/health`).then(() => setApiOnline(true)).catch(() => setApiOnline(false));
  }, []);

  useEffect(() => {
    if (!apiOnline) return;
    fetch(`${API_BASE}/api/results`)
      .then(r => r.json())
      .then(d => {
        if (d.findings?.length) {
          setFindings(d.findings);
          setLastScan(d.timestamp);
        }
      }).catch(() => {});
  }, [apiOnline]);

  const runScan = useCallback(async () => {
    if (scanning) return;
    setScanning(true);
    setLogs(["[*] VulnScan Pro — Starting scan...", `[*] Target: ${target}`]);
    setActiveTab("terminal");

    if (!apiOnline) {
      const demoLogs = [
        "[*] Initializing scanner modules...",
        "[1/11] SQLi: Login endpoint (username param) ... 🔴 2 finding(s)",
        "[2/11] SQLi: Login endpoint (password param) ... ✓ clean",
        "[3/11] SQLi: Product search (q param) ... 🔴 2 finding(s)",
        "[4/11] SQLi: User exists (username param) ... 🔴 1 finding(s)",
        "[5/11] XSS Reflected: /api/xss/reflect ... 🔴 1 finding(s)",
        "[6/11] XSS Stored: /api/xss/comment → /api/xss/comments ... 🔴 1 finding(s)",
        "[7/11] Security Headers: / ... 🔴 5 finding(s)",
        "[8/11] Security Headers: /api/login ... 🔴 3 finding(s)",
        "[9/11] IDOR: /api/orders/<id> ... 🔴 2 finding(s)",
        "[10/11] JWT: Role tampering via /api/jwt ... 🔴 1 finding(s)",
        "[11/11] CSRF: /api/csrf/transfer ... 🔴 1 finding(s)",
        "── SCAN SUMMARY ──────────────────────────────",
        "  Critical         6",
        "  High             5",
        "  Medium           2",
        "  Low              1",
        "  Total            14",
        "[✓] Scan complete. HTML report → reports/report.html",
      ];
      for (const line of demoLogs) {
        await new Promise(r => setTimeout(r, 180));
        setLogs(p => [...p, line]);
      }
      setFindings(SAMPLE_FINDINGS);
      setLastScan(new Date().toISOString());
      setScanning(false);
      setActiveTab("dashboard");
      return;
    }

    try {
      const resp = await fetch(`${API_BASE}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, format: "html" }),
      });
      const reader = resp.body.getReader();
      const dec = new TextDecoder();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const lines = dec.decode(value).split("\n").filter(Boolean);
        for (const line of lines) {
          try {
            const ev = JSON.parse(line);
            if (ev.event === "log")  setLogs(p => [...p, ev.line]);
            if (ev.event === "done") {
              setLastScan(ev.timestamp);
              const d = await fetch(`${API_BASE}/api/results`).then(r => r.json());
              if (d.findings?.length) setFindings(d.findings);
              setActiveTab("dashboard");
            }
          } catch {}
        }
      }
    } catch (e) {
      setLogs(p => [...p, `[ERROR] ${e.message}`]);
    } finally {
      setScanning(false);
    }
  }, [scanning, target, apiOnline]);

  const counts  = severityCounts(findings);
  const maxCvss = findings.reduce((m, f) => Math.max(m, f.cvss), 0);

  const exportJson = () => {
    const blob = new Blob([JSON.stringify({ target, findings, timestamp: lastScan }, null, 2)], { type: "application/json" });
    const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: "vulnscan-results.json" });
    a.click();
  };

  return (
    <div style={{ minHeight: "100vh", background: "#0d1117", color: "#c9d1d9", fontFamily: "'Inter', 'Segoe UI', sans-serif" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600;700&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: #0d1117; }
        ::-webkit-scrollbar-thumb { background: #30363d; border-radius: 3px; }
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
        .fade-in { animation: fadeIn 0.3s ease; }
        @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.5; } }
      `}</style>

      <Navbar scanning={scanning} onScan={runScan} target={target} setTarget={setTarget} lastScan={lastScan} />

      <div style={{ borderBottom: "1px solid #21262d", padding: "0 2rem", display: "flex", gap: "0", background: "#010409" }}>
        {[
          { id: "dashboard", label: "Dashboard" },
          { id: "findings",  label: `Findings (${findings.length})` },
          { id: "terminal",  label: "Scan Log" },
        ].map(tab => (
          <button key={tab.id} onClick={() => setActiveTab(tab.id)}
            style={{
              background: "none",
              border: "none",
              borderBottom: `2px solid ${activeTab === tab.id ? "#f85149" : "transparent"}`,
              color: activeTab === tab.id ? "#c9d1d9" : "#484f58",
              padding: "10px 18px",
              cursor: "pointer",
              fontSize: "0.84rem",
              fontWeight: activeTab === tab.id ? 600 : 400,
              transition: "all 0.15s",
            }}
          >{tab.label}</button>
        ))}
        <div style={{ flex: 1 }} />
        <div style={{ display: "flex", alignItems: "center", gap: "6px", padding: "0 4px" }}>
          <div style={{ width: "6px", height: "6px", borderRadius: "50%", background: apiOnline ? "#3fb950" : "#484f58", animation: apiOnline ? "pulse 2s infinite" : "none" }} />
          <span style={{ color: "#484f58", fontSize: "0.72rem", fontFamily: "monospace" }}>{apiOnline ? "API online" : "Demo mode"}</span>
        </div>
        <button onClick={exportJson}
          style={{ margin: "6px 0 6px 12px", background: "#21262d", color: "#c9d1d9", border: "1px solid #30363d", borderRadius: "6px", padding: "4px 14px", cursor: "pointer", fontSize: "0.78rem" }}>
          ⬇ Export JSON
        </button>
      </div>

      <main style={{ padding: "1.5rem 2rem", maxWidth: "1400px", margin: "0 auto" }}>

        {activeTab === "dashboard" && (
          <div className="fade-in">
            <div style={{ display: "flex", gap: "12px", marginBottom: "1.4rem", flexWrap: "wrap" }}>
              <StatCard label="Total Findings" value={findings.length} color="#c9d1d9" bg="#161b22" icon="🔍" sub={`CVSS max: ${maxCvss}`} />
              <StatCard label="Critical"  value={counts.Critical} color={SEV_META.Critical.color} bg={SEV_META.Critical.bg} icon="💀" sub="Immediate action required" />
              <StatCard label="High"      value={counts.High}     color={SEV_META.High.color}     bg={SEV_META.High.bg}     icon="⚠️" sub="Fix within 7 days" />
              <StatCard label="Medium"    value={counts.Medium}   color={SEV_META.Medium.color}   bg={SEV_META.Medium.bg}   icon="🔶" sub="Fix within 30 days" />
              <StatCard label="Low / Info" value={counts.Low + (counts.Info || 0)} color={SEV_META.Low.color} bg={SEV_META.Low.bg} icon="ℹ️" sub="Best effort" />
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 180px", gap: "12px", marginBottom: "1.4rem" }}>
              <RadarVuln findings={findings} />
              <SeverityPie findings={findings} />
              <CvssChart findings={findings} />
              <RiskMeter findings={findings} />
            </div>

            <div style={{ background: "#161b22", border: "1px solid #30363d", borderRadius: "10px", overflow: "hidden" }}>
              <div style={{ padding: "12px 16px", borderBottom: "1px solid #30363d", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ color: "#c9d1d9", fontWeight: 600, fontSize: "0.9rem" }}>Critical & High Findings</span>
                <button onClick={() => setActiveTab("findings")} style={{ background: "none", border: "none", color: "#58a6ff", cursor: "pointer", fontSize: "0.8rem" }}>View all →</button>
              </div>
              {findings.filter(f => ["Critical", "High"].includes(f.severity)).slice(0, 5).map((f, i) => (
                <div key={i} style={{ padding: "10px 16px", borderBottom: "1px solid #21262d", display: "flex", alignItems: "center", gap: "12px" }}>
                  <span style={{ fontSize: "1.1rem" }}>{getVulnIcon(f.type)}</span>
                  <SeverityBadge sev={f.severity} />
                  <span style={{ flex: 1, color: "#c9d1d9", fontSize: "0.84rem" }}>{f.type}</span>
                  <span style={{ color: "#79c0ff", fontFamily: "monospace", fontSize: "0.76rem" }}>{f.param}</span>
                  <CvssBar score={f.cvss} />
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === "findings" && (
          <div className="fade-in">
            <FindingsTable findings={findings} filter={filter} setFilter={setFilter} />
          </div>
        )}

        {activeTab === "terminal" && (
          <div className="fade-in">
            <ScanLog logs={logs} />
            {!scanning && logs.length === 0 && (
              <div style={{ marginTop: "1rem", color: "#484f58", textAlign: "center", fontFamily: "monospace", fontSize: "0.85rem" }}>
                Run a scan to see live progress output here.
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
