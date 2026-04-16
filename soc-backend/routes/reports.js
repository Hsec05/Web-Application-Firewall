const express = require("express");
const router  = express.Router();
const db      = require("../database");
const { generatePDFReport } = require("../pdfGenerator");

function toCSV(rows, columns) {
  const header = columns.map(c => c.label).join(",");
  const lines  = rows.map(row => columns.map(c => {
    const val = c.key.split(".").reduce((o,k) => o?o[k]:"", row);
    return `"${String(val??'').replace(/"/g,'""')}"`;
  }).join(","));
  return [header, ...lines].join("\n");
}

router.post("/generate", async (req, res) => {
  const { type, dateRange, format = "json" } = req.body;
  if (!type || !dateRange) return res.status(400).json({ error: "type and dateRange are required" });

  try {
    const report = await db.getReportData(type, dateRange.start || dateRange.from, dateRange.end || dateRange.to);

    if (format === "csv") {
      const rows = report.events || report.profiles || report.criticalAlerts || [];
      const columns = [
        { label:"ID",          key:"id" },
        { label:"Timestamp",   key:"timestamp" },
        { label:"Attack Type", key:"attackType" },
        { label:"Source IP",   key:"sourceIP" },
        { label:"Target URL",  key:"targetURL" },
        { label:"Severity",    key:"severity" },
        { label:"Action",      key:"action" },
        { label:"Country",     key:"country" },
        { label:"OS",          key:"device.os" },
        { label:"Tool",        key:"device.browser" },
        { label:"Snort SIDs",  key:"matchedSIDs" },
      ];
      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", `attachment; filename="${type}-report.csv"`);
      return res.send(toCSV(rows, columns));
    }

    res.json(report);
  } catch (err) {
    console.error("Report error:", err.message);
    res.status(500).json({ error: "Failed to generate report" });
  }
});

router.post("/generate/pdf", async (req, res) => {
  const { type, dateRange } = req.body;
  if (!type || !dateRange) return res.status(400).json({ error: "type and dateRange are required" });

  try {
    const report     = await db.getReportData(type, dateRange.start || dateRange.from, dateRange.end || dateRange.to);
    const pdfBuffer  = await generatePDFReport(report, type);
    const from       = new Date(dateRange.start || dateRange.from);
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="waf-${type}-report-${from.toISOString().split("T")[0]}.pdf"`);
    res.setHeader("Content-Length", pdfBuffer.length);
    res.send(pdfBuffer);
  } catch (err) {
    console.error("PDF error:", err.message);
    res.status(500).json({ error: "Failed to generate PDF", details: err.message });
  }
});

router.get("/preview", async (req, res) => {
  const { from, to } = req.query;
  const fromDate = from ? new Date(from) : new Date(Date.now() - 7*24*60*60*1000);
  const toDate   = to   ? new Date(to)   : new Date();
  try {
    const report = await db.getReportData("daily", fromDate, toDate);
    res.json({
      totalEvents:    report.summary.totalEvents,
      uniqueIPs:      report.summary.uniqueAttackers,
      blockedThreats: report.summary.blocked,
      criticalAlerts: report.summary.criticalEvents,
      dateRange:      { from: fromDate, to: toDate },
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch preview" });
  }
});

module.exports = router;
