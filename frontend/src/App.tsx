import { CopilotKit, useCoAgent } from "@copilotkit/react-core";
import { CopilotSidebar } from "@copilotkit/react-ui";
import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from "react";
import * as THREE from "three";
import { threadLabel, useCyberRiskThreadIds } from "./hooks/useCyberRiskThreadIds";

const COPILOT_AGENT_ID = import.meta.env.VITE_LANGGRAPH_GRAPH_ID ?? "cyber_risk";

const MAX_VULN_SNAPSHOT_ROWS = 500;

type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "UNKNOWN";

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

interface Vulnerability {
  id: string;
  description: string;
  severity: Severity;
  riskScore: number;
  publishedDate: string;
  vendor: string;
}

interface CopilotDashboardState {
  severity_filter?: string;
  vendor_filter?: string;
  /** CVE rows for current filters (may be truncated for CopilotKit payload size). */
  vulnerability_table_snapshot?: Vulnerability[];
  vulnerability_table_total_count?: number;
}

interface StatsResponse {
  severityBreakdown: Record<string, number>;
  vendors: Array<{ vendor: string; count: number }>;
  total: number;
}

function scoreColor(score: number): string {
  if (score <= 30) return "green";
  if (score <= 60) return "yellow";
  if (score <= 80) return "orange";
  return "red";
}

function buildVulnQuery(severity: string, vendor: string): string {
  const params = new URLSearchParams();
  if (severity) params.set("severity", severity);
  if (vendor) params.set("vendor", vendor);
  const q = params.toString();
  return q ? `?${q}` : "";
}

async function readApiErrorMessage(res: Response, fallback: string): Promise<string> {
  const ct = res.headers.get("content-type") ?? "";
  if (!ct.includes("application/json")) {
    return `${fallback} (HTTP ${res.status})`;
  }
  try {
    const data = (await res.json()) as { error?: string; details?: string };
    if (data.details) {
      return data.error ? `${data.error}: ${data.details}` : data.details;
    }
    if (data.error) return data.error;
  } catch {
    /* ignore malformed JSON */
  }
  return `${fallback} (HTTP ${res.status})`;
}

function DashboardContent() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  /** Latest filters (updated every render) for stale-response checks after await. */
  const filtersRef = useRef({ sev: "", vend: "" });
  /** Concurrent fetches; only clear loading when the last one finishes. */
  const loadInFlightRef = useRef(0);
  const setStateRef = useRef<ReturnType<typeof useCoAgent<CopilotDashboardState>>["setState"] | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [vendorFilter, setVendorFilter] = useState<string>("");
  const { state, setState } = useCoAgent<CopilotDashboardState>({
    name: COPILOT_AGENT_ID,
    initialState: {
      severity_filter: "",
      vendor_filter: "",
      vulnerability_table_snapshot: [],
      vulnerability_table_total_count: 0
    }
  });
  setStateRef.current = setState;
  filtersRef.current = { sev: severityFilter, vend: vendorFilter };

  const [sortDesc, setSortDesc] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [rows, setRows] = useState<Vulnerability[]>([]);
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(50, 1, 0.1, 100);
    camera.position.z = 4;

    const geometry = new THREE.IcosahedronGeometry(1.3, 1);
    const material = new THREE.MeshStandardMaterial({
      color: 0x7dd3fc,
      emissive: 0x082f49,
      roughness: 0.32,
      metalness: 0.68,
      wireframe: true
    });
    const mesh = new THREE.Mesh(geometry, material);
    scene.add(mesh);

    scene.add(new THREE.AmbientLight(0x7dd3fc, 0.45));
    const keyLight = new THREE.DirectionalLight(0xffffff, 0.9);
    keyLight.position.set(3, 3, 5);
    scene.add(keyLight);

    const resize = () => {
      const width = canvas.clientWidth || 320;
      const height = canvas.clientHeight || 220;
      renderer.setSize(width, height, false);
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
    };
    resize();
    window.addEventListener("resize", resize);

    let frameId = 0;
    const animate = () => {
      frameId = requestAnimationFrame(animate);
      mesh.rotation.x += 0.003;
      mesh.rotation.y += 0.006;
      renderer.render(scene, camera);
    };
    animate();

    return () => {
      cancelAnimationFrame(frameId);
      window.removeEventListener("resize", resize);
      geometry.dispose();
      material.dispose();
      renderer.dispose();
    };
  }, []);

  const loadData = useCallback(async () => {
    const sev = severityFilter;
    const vend = vendorFilter;
    loadInFlightRef.current += 1;
    setLoading(true);
    setError("");
    const matchesRequest = () =>
      filtersRef.current.sev === sev && filtersRef.current.vend === vend;

    try {
      const q = buildVulnQuery(sev, vend);
      const [vulnRes, statsRes] = await Promise.all([
        fetch(`/api/vulnerabilities${q}`),
        fetch("/api/stats")
      ]);

      if (!matchesRequest()) {
        return;
      }

      if (!vulnRes.ok) {
        throw new Error(await readApiErrorMessage(vulnRes, "Failed to fetch vulnerabilities"));
      }
      if (!statsRes.ok) {
        throw new Error(await readApiErrorMessage(statsRes, "Failed to fetch stats"));
      }

      const vulnJson: Vulnerability[] = await vulnRes.json();
      const statsJson: StatsResponse = await statsRes.json();

      if (!matchesRequest()) {
        return;
      }

      setRows(vulnJson);
      setStats(statsJson);
      const patch = setStateRef.current;
      if (patch) {
        patch((prev) => ({
          ...prev,
          severity_filter: sev,
          vendor_filter: vend,
          vulnerability_table_total_count: vulnJson.length,
          vulnerability_table_snapshot: vulnJson.slice(0, MAX_VULN_SNAPSHOT_ROWS)
        }));
      }
    } catch (e) {
      if (!matchesRequest()) {
        return;
      }
      setError(e instanceof Error ? e.message : "Unexpected error");
    } finally {
      loadInFlightRef.current -= 1;
      if (loadInFlightRef.current === 0) {
        setLoading(false);
      }
    }
  }, [severityFilter, vendorFilter]);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  // Apply agent-driven filter changes only when those fields change — not on every coagent
  // snapshot update — so local filters are not fighting vulnerability_table_* refreshes.
  const agentSev = state?.severity_filter ?? "";
  const agentVendor = state?.vendor_filter ?? "";
  useEffect(() => {
    setSeverityFilter((prev) => (prev !== agentSev ? agentSev : prev));
    setVendorFilter((prev) => (prev !== agentVendor ? agentVendor : prev));
  }, [agentSev, agentVendor]);

  useEffect(() => {
    setExpandedIds(new Set());
  }, [severityFilter, vendorFilter]);

  const sortedRows = useMemo(
    () => [...rows].sort((a, b) => (sortDesc ? b.riskScore - a.riskScore : a.riskScore - b.riskScore)),
    [rows, sortDesc]
  );

  const severityEntries = useMemo(() => {
    if (!stats) return [];
    return SEVERITY_ORDER.filter((sev) => (stats.severityBreakdown[sev] ?? 0) > 0).map((sev) => [
      sev,
      stats.severityBreakdown[sev] ?? 0
    ] as const);
  }, [stats]);

  function toggleSeverityChip(sev: string) {
    const next = severityFilter === sev ? "" : sev;
    setSeverityFilter(next);
    setState((prev) => ({ ...prev, severity_filter: next }));
  }

  function toggleVendorFilter(vendor: string) {
    const next = vendorFilter === vendor ? "" : vendor;
    setVendorFilter(next);
    setState((prev) => ({ ...prev, vendor_filter: next }));
  }

  function toggleRowExpanded(id: string) {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function onRowKeyDown(e: React.KeyboardEvent, id: string) {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      toggleRowExpanded(id);
    }
  }

  return (
    <main className="container">
      <section className="hero">
        <div className="hero-copy">
          <h1>Vulnerability Risk Dashboard</h1>
          <p className="subtle">Risk = CVSS(60%) + exploitability(20%) + age(20%)</p>
          <div className="controls">
            <label>
              Severity filter:
              <select
                value={severityFilter}
                onChange={(e) => {
                  const v = e.target.value;
                  setSeverityFilter(v);
                  setState((prev) => ({ ...prev, severity_filter: v }));
                }}
              >
                <option value="">All</option>
                <option value="LOW">LOW</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="HIGH">HIGH</option>
                <option value="CRITICAL">CRITICAL</option>
                <option value="UNKNOWN">UNKNOWN</option>
              </select>
            </label>
            <label>
              Vendor filter:
              <select
                value={vendorFilter}
                onChange={(e) => {
                  const v = e.target.value;
                  setVendorFilter(v);
                  setState((prev) => ({ ...prev, vendor_filter: v }));
                }}
                disabled={!stats?.vendors?.length}
              >
                <option value="">All vendors</option>
                {stats?.vendors.map((v) => (
                  <option key={v.vendor} value={v.vendor}>
                    {v.vendor} ({v.count})
                  </option>
                ))}
              </select>
            </label>
            <button type="button" onClick={() => void loadData()}>
              Refresh
            </button>
            {(severityFilter || vendorFilter) && (
              <button
                type="button"
                className="clear-filters"
                onClick={() => {
                  setSeverityFilter("");
                  setVendorFilter("");
                  setState(() => ({ severity_filter: "", vendor_filter: "" }));
                }}
              >
                Clear filters
              </button>
            )}
          </div>
        </div>
        <canvas ref={canvasRef} className="hero-canvas" aria-hidden="true" />
      </section>

      {error && <p className="error">{error}</p>}
      {loading && <p className="status">Loading vulnerability data...</p>}

      {stats && (
        <section className="panel">
          <h2>Stats Panel</h2>
          <p>
            Total CVEs: {stats.total}
            {(severityFilter || vendorFilter) && (
              <span className="subtle"> · Showing {rows.length} matching the current filters</span>
            )}
          </p>
          <div className="stats-grid">
            {severityEntries.map(([sev, count]) => (
              <button
                key={sev}
                type="button"
                className={`chip chip-clickable${severityFilter === sev ? " chip-active" : ""}`}
                onClick={() => toggleSeverityChip(sev)}
              >
                {sev}: {count}
              </button>
            ))}
          </div>
          <h3>Vendors</h3>
          <p className="subtle vendor-hint">Click a vendor to filter the table (click again to clear).</p>
          <ul className="vendors vendors-scroll">
            {stats.vendors.map((v) => (
              <li key={v.vendor}>
                <button
                  type="button"
                  className={`vendor-row${vendorFilter === v.vendor ? " vendor-row-active" : ""}`}
                  onClick={() => toggleVendorFilter(v.vendor)}
                >
                  <span>{v.vendor}</span>
                  <strong>{v.count}</strong>
                </button>
              </li>
            ))}
          </ul>
        </section>
      )}

      <section className="panel">
        <h2>Vulnerability Table</h2>
        <p className="subtle table-hint">
          Click a row to expand or collapse the full description. The table loads up to 50 rows from the server; use
          the Risk Score column to re-sort the loaded rows.
        </p>
        <table>
          <thead>
            <tr>
              <th scope="col">CVE ID</th>
              <th scope="col">Vendor</th>
              <th scope="col">Description</th>
              <th scope="col">Severity</th>
              <th scope="col" aria-sort={sortDesc ? "descending" : "ascending"}>
                <button
                  type="button"
                  className="th-sort-btn"
                  onClick={() => setSortDesc((prev) => !prev)}
                  title={sortDesc ? "Highest risk first; click for lowest first" : "Lowest risk first; click for highest first"}
                >
                  Risk Score
                  <span className="th-sort-indicator" aria-hidden="true">
                    {sortDesc ? " ↓" : " ↑"}
                  </span>
                </button>
              </th>
              <th scope="col">Date</th>
            </tr>
          </thead>
          <tbody>
            {sortedRows.map((row) => {
              const expanded = expandedIds.has(row.id);
              const preview =
                row.description.length > 120 ? `${row.description.slice(0, 120)}...` : row.description;
              return (
                <Fragment key={row.id}>
                  <tr
                    className={`vuln-row${expanded ? " vuln-row-expanded" : ""}`}
                    onClick={() => toggleRowExpanded(row.id)}
                    onKeyDown={(e) => onRowKeyDown(e, row.id)}
                    tabIndex={0}
                    aria-expanded={expanded}
                  >
                    <td>{row.id}</td>
                    <td>{row.vendor || "—"}</td>
                    <td>{preview}</td>
                    <td>{row.severity}</td>
                    <td>
                      <span className={`badge ${scoreColor(row.riskScore)}`}>{row.riskScore}</span>
                    </td>
                    <td>{new Date(row.publishedDate).toLocaleDateString()}</td>
                  </tr>
                  {expanded && (
                    <tr className="vuln-detail-row" aria-label={`Full description for ${row.id}`}>
                      <td colSpan={6} className="vuln-detail-cell">
                        <div className="vuln-detail-label">Full description</div>
                        {row.description}
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </section>
    </main>
  );
}

export function App() {
  const { threadIds, threadId, setThreadId, addNewThread, hydrated } = useCyberRiskThreadIds();

  return (
    <>
      <header className="app-thread-bar" aria-label="Copilot conversation">
        <span className="app-thread-bar-label">Thread</span>
        <select
          className="app-thread-select"
          value={threadId}
          onChange={(e) => setThreadId(e.target.value)}
          disabled={!hydrated}
          aria-label="Select conversation thread"
        >
          {(threadIds.length > 0 ? threadIds : [threadId]).map((id) => (
            <option key={id} value={id}>
              {threadLabel(id)}
            </option>
          ))}
        </select>
        <button type="button" className="app-new-thread" onClick={() => addNewThread()}>
          New thread
        </button>
      </header>
      <CopilotKit
        runtimeUrl="/api/copilotkit"
        agent={COPILOT_AGENT_ID}
        threadId={threadId}
        key={threadId}
      >
        <DashboardContent />
        <CopilotSidebar
          defaultOpen={false}
          labels={{
            title: "Risk copilot",
            initial:
              'Try: "Show only critical CVEs", "Filter vendor to Microsoft", or "Clear all filters".'
          }}
          instructions={
            "You are the in-app assistant for the vulnerability risk dashboard. " +
            "Use tools to update dashboard filters. For summaries of the visible table, follow the agent flow: " +
            "set filters, refresh the vulnerability table snapshot into shared state, then summarize that data only."
          }
        />
      </CopilotKit>
    </>
  );
}
