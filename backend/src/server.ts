import cors from "cors";
import express from "express";
import {
  checkSupabaseConnection,
  getVulnerabilitiesFromSupabase,
  getVulnerabilityByIdFromSupabase,
  getVulnerabilityStatsFromSupabase
} from "./db";
import type { Severity } from "./types";

const app = express();
const PORT = Number(process.env.PORT || 3001);

app.use(cors());
app.use(express.json());

app.get("/api/health", async (_req, res) => {
  const supabaseConnected = await checkSupabaseConnection();
  res.json({ ok: true, supabaseConnected });
});

app.get("/api/vulnerabilities", async (req, res) => {
  try {
    const severity = (req.query.severity as string | undefined)?.toUpperCase() as Severity | undefined;
    const vendorRaw = req.query.vendor as string | undefined;
    const vendor = typeof vendorRaw === "string" && vendorRaw.trim() !== "" ? vendorRaw.trim() : undefined;
    const rows = await getVulnerabilitiesFromSupabase(severity, vendor);
    res.json(rows);
  } catch (error) {
    res.status(502).json({
      error: "Failed to fetch vulnerabilities from Supabase",
      details: error instanceof Error ? error.message : "Unknown error"
    });
  }
});

app.get("/api/vulnerabilities/:id", async (req, res) => {
  try {
    const found = await getVulnerabilityByIdFromSupabase(req.params.id);
    if (!found) {
      res.status(404).json({ error: "Vulnerability not found" });
      return;
    }
    res.json(found);
  } catch (error) {
    res.status(502).json({
      error: "Failed to fetch vulnerabilities from Supabase",
      details: error instanceof Error ? error.message : "Unknown error"
    });
  }
});

app.get("/api/stats", async (_req, res) => {
  try {
    const stats = await getVulnerabilityStatsFromSupabase();
    res.json(stats);
  } catch (error) {
    res.status(502).json({
      error: "Failed to compute stats from Supabase data",
      details: error instanceof Error ? error.message : "Unknown error"
    });
  }
});

app.listen(PORT, () => {
  console.log(`Backend listening on http://localhost:${PORT}`);
});
