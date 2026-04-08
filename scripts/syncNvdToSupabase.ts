/**
 * Sync CVEs from NVD into Supabase. Run: `npm run sync:nvd` (do not use plain `node` on this file).
 */
import dotenv from "dotenv";
import pg from "pg";
import { toVulnerabilityItem } from "../backend/src/risk";

dotenv.config();

const { Client } = pg;

const DEFAULT_RESULTS_PER_PAGE = 100;
const NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";

interface NvdResponse {
  totalResults: number;
  vulnerabilities: Array<{ cve: unknown }>;
}

function getRequiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function readPositiveIntEnv(name: string): number | undefined {
  const raw = process.env[name];
  if (!raw) return undefined;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer if provided`);
  }
  return parsed;
}

async function fetchNvdPage(startIndex: number, resultsPerPage: number): Promise<NvdResponse> {
  const params = new URLSearchParams({
    startIndex: String(startIndex),
    resultsPerPage: String(resultsPerPage)
  });
  const response = await fetch(`${NVD_BASE_URL}?${params.toString()}`);
  if (!response.ok) {
    throw new Error(`NVD API request failed (${response.status} ${response.statusText})`);
  }
  return (await response.json()) as NvdResponse;
}

async function ensureTable(client: pg.Client): Promise<void> {
  await client.query(`
    CREATE TABLE IF NOT EXISTS vulnerabilities (
      id TEXT PRIMARY KEY,
      description TEXT NOT NULL,
      severity TEXT NOT NULL,
      cvss_score DOUBLE PRECISION NOT NULL,
      exploitability_score DOUBLE PRECISION NOT NULL,
      published_date TIMESTAMPTZ NOT NULL,
      vendor TEXT NOT NULL,
      risk_score INTEGER NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}

async function upsertBatch(client: pg.Client, rawVulnerabilities: Array<{ cve: unknown }>): Promise<number> {
  if (!rawVulnerabilities.length) return 0;

  const mapped = rawVulnerabilities.map((entry) => toVulnerabilityItem(entry));
  const values: Array<string | number | Date> = [];

  const rowPlaceholders = mapped.map((item, index) => {
    const base = index * 8;
    values.push(
      item.id,
      item.description,
      item.severity,
      item.cvssScore,
      item.exploitabilityScore,
      new Date(item.publishedDate),
      item.vendor,
      item.riskScore
    );
    return `($${base + 1}, $${base + 2}, $${base + 3}, $${base + 4}, $${base + 5}, $${base + 6}, $${base + 7}, $${base + 8})`;
  });

  await client.query(
    `
      INSERT INTO vulnerabilities
      (id, description, severity, cvss_score, exploitability_score, published_date, vendor, risk_score)
      VALUES ${rowPlaceholders.join(", ")}
      ON CONFLICT (id) DO UPDATE SET
        description = EXCLUDED.description,
        severity = EXCLUDED.severity,
        cvss_score = EXCLUDED.cvss_score,
        exploitability_score = EXCLUDED.exploitability_score,
        published_date = EXCLUDED.published_date,
        vendor = EXCLUDED.vendor,
        risk_score = EXCLUDED.risk_score,
        updated_at = NOW();
    `,
    values
  );

  return mapped.length;
}

async function main(): Promise<void> {
  const connectionString = getRequiredEnv("SUPABASE_URL");
  const maxRecords = readPositiveIntEnv("NVD_MAX_RECORDS");
  const resultsPerPage = readPositiveIntEnv("NVD_RESULTS_PER_PAGE") ?? DEFAULT_RESULTS_PER_PAGE;

  const client = new Client({
    connectionString,
    ssl: { rejectUnauthorized: false }
  });

  await client.connect();
  try {
    await ensureTable(client);

    let startIndex = 0;
    let fetched = 0;
    let saved = 0;
    let totalResults = Number.POSITIVE_INFINITY;

    while (startIndex < totalResults && (maxRecords === undefined || fetched < maxRecords)) {
      const pageSize = maxRecords === undefined ? resultsPerPage : Math.min(resultsPerPage, maxRecords - fetched);
      const payload = await fetchNvdPage(startIndex, pageSize);
      const batch = payload.vulnerabilities ?? [];
      totalResults = payload.totalResults ?? fetched + batch.length;

      if (!batch.length) break;

      const persisted = await upsertBatch(client, batch);
      fetched += batch.length;
      saved += persisted;
      startIndex += batch.length;

      console.log(`Fetched ${fetched}/${Math.min(totalResults, maxRecords ?? totalResults)} | Upserted ${saved}`);
    }

    console.log(`Done. Upserted ${saved} vulnerabilities into Supabase.`);
  } finally {
    await client.end().catch(() => undefined);
  }
}

main().catch((error) => {
  console.error("syncNvdToSupabase failed:", error);
  process.exitCode = 1;
});
