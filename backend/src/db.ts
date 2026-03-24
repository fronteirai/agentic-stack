import dotenv from "dotenv";
import pg from "pg";
import type { Severity, VulnerabilityItem } from "./types";

dotenv.config();

const { Client } = pg;
const connectionString = process.env.SUPABASE_URL;

function createClient(): pg.Client {
  if (!connectionString) {
    throw new Error("SUPABASE_URL is not configured");
  }
  return new Client({
    connectionString,
    ssl: { rejectUnauthorized: false }
  });
}

export async function checkSupabaseConnection(): Promise<boolean> {
  if (!connectionString) return false;
  const client = createClient();

  try {
    await client.connect();
    await client.query("SELECT 1");
    return true;
  } catch {
    return false;
  } finally {
    await client.end().catch(() => undefined);
  }
}

function mapRowToVulnerability(row: any): VulnerabilityItem {
  return {
    id: row.id,
    description: row.description,
    severity: row.severity as Severity,
    cvssScore: Number(row.cvss_score ?? 0),
    exploitabilityScore: Number(row.exploitability_score ?? 0),
    publishedDate: new Date(row.published_date).toISOString(),
    vendor: row.vendor,
    riskScore: Number(row.risk_score ?? 0)
  };
}

export async function getVulnerabilitiesFromSupabase(
  severity?: Severity,
  vendor?: string
): Promise<VulnerabilityItem[]> {
  const client = createClient();
  try {
    await client.connect();
    const conditions: string[] = [];
    const params: unknown[] = [];
    let i = 1;
    if (severity) {
      conditions.push(`severity = $${i++}`);
      params.push(severity);
    }
    if (vendor) {
      conditions.push(`vendor = $${i++}`);
      params.push(vendor);
    }
    const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
    const result = await client.query(
      `
      SELECT id, description, severity, cvss_score, exploitability_score, published_date, vendor, risk_score
      FROM vulnerabilities
      ${where}
      ORDER BY risk_score DESC, published_date DESC
    `,
      params
    );
    return result.rows.map(mapRowToVulnerability);
  } finally {
    await client.end().catch(() => undefined);
  }
}

export async function getVulnerabilityByIdFromSupabase(id: string): Promise<VulnerabilityItem | null> {
  const client = createClient();
  try {
    await client.connect();
    const result = await client.query(
      `
      SELECT id, description, severity, cvss_score, exploitability_score, published_date, vendor, risk_score
      FROM vulnerabilities
      WHERE id = $1
      LIMIT 1
    `,
      [id]
    );
    return result.rows[0] ? mapRowToVulnerability(result.rows[0]) : null;
  } finally {
    await client.end().catch(() => undefined);
  }
}

export interface VulnerabilityStats {
  severityBreakdown: Record<string, number>;
  /** All vendors with CVE counts, highest count first */
  vendors: Array<{ vendor: string; count: number }>;
  total: number;
}

export async function getVulnerabilityStatsFromSupabase(
  severity?: Severity,
  vendor?: string
): Promise<VulnerabilityStats> {
  const client = createClient();
  try {
    await client.connect();
    const conditions: string[] = [];
    const params: unknown[] = [];
    let i = 1;
    if (severity) {
      conditions.push(`severity = $${i++}`);
      params.push(severity);
    }
    if (vendor) {
      conditions.push(`vendor = $${i++}`);
      params.push(vendor);
    }
    const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

    const [severityResult, vendorsResult, totalResult] = await Promise.all([
      client.query(
        `SELECT severity, COUNT(*)::int AS count FROM vulnerabilities ${where} GROUP BY severity`,
        params
      ),
      client.query(
        `SELECT vendor, COUNT(*)::int AS count FROM vulnerabilities ${where} GROUP BY vendor ORDER BY COUNT(*) DESC`,
        params
      ),
      client.query(`SELECT COUNT(*)::int AS total FROM vulnerabilities ${where}`, params)
    ]);

    const severityBreakdown = severityResult.rows.reduce<Record<string, number>>((acc, row: any) => {
      acc[row.severity] = Number(row.count);
      return acc;
    }, {});

    const vendors = vendorsResult.rows.map((row: any) => ({
      vendor: row.vendor,
      count: Number(row.count)
    }));

    return {
      severityBreakdown,
      vendors,
      total: Number(totalResult.rows[0]?.total ?? 0)
    };
  } finally {
    await client.end().catch(() => undefined);
  }
}
