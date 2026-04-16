/**
 * PDF Report Generator — WAF SOC Dashboard
 *
 * Key fixes over previous version:
 *  - Zero emoji (PDFKit/Helvetica cannot render them — causes gibberish)
 *  - Dynamic page management: new pages only when content needs them
 *  - All icons drawn as geometric shapes with pdfkit primitives
 *  - Consistent Y-cursor tracking so nothing overlaps or leaves blank space
 */

const PDFDocument = require("pdfkit");

// ─── Design tokens ────────────────────────────────────────────────────────────

const C = {
  primary:    "#0f172a",
  accent:     "#3b82f6",
  accentDark: "#1d4ed8",
  accentMid:  "#60a5fa",

  critical:   "#ef4444",
  high:       "#f97316",
  medium:     "#eab308",
  low:        "#22c55e",
  info:       "#6b7280",

  white:      "#ffffff",
  lightGray:  "#f8fafc",
  midGray:    "#e2e8f0",
  darkGray:   "#64748b",
  text:       "#1e293b",
  textMuted:  "#94a3b8",
  border:     "#cbd5e1",

  chart: ["#3b82f6","#ef4444","#f97316","#eab308","#22c55e","#8b5cf6","#ec4899","#14b8a6","#f43f5e","#0ea5e9"],
};

const F = { bold: "Helvetica-Bold", regular: "Helvetica" };

const PAGE   = { width: 595, height: 842, margin: 40 };
const CW     = PAGE.width - PAGE.margin * 2;   // content width = 515
const HEADER = 80;                              // header height
const FOOTER = 40;                              // footer height
const BODY_T = HEADER + 20;                    // body starts at y=100
const BODY_B = PAGE.height - FOOTER - 10;      // body ends at y=792

// ─── Low-level drawing helpers ────────────────────────────────────────────────

function rect(doc, x, y, w, h, fill, radius = 0) {
  doc.save().roundedRect(x, y, w, h, radius).fill(fill).restore();
}

function border(doc, x, y, w, h, stroke, lw = 0.5, radius = 0) {
  doc.save().roundedRect(x, y, w, h, radius).strokeColor(stroke).lineWidth(lw).stroke().restore();
}

function line(doc, x1, y1, x2, y2, color = C.midGray, lw = 0.5) {
  doc.save().moveTo(x1, y1).lineTo(x2, y2).strokeColor(color).lineWidth(lw).stroke().restore();
}

function txt(doc, text, x, y, { font = F.regular, size = 9, color = C.text, width, align = "left", lineBreak = true } = {}) {
  doc.font(font).fontSize(size).fillColor(color);
  const opts = { lineBreak };
  if (width)  opts.width = width;
  if (align)  opts.align = align;
  doc.text(String(text ?? "—"), x, y, opts);
}

function sevColor(s) { return C[s?.toLowerCase()] ?? C.info; }

// ─── Icon primitives (NO emoji — all drawn with pdfkit shapes) ────────────────

function iconShield(doc, x, y, size, color) {
  // Simple shield: pentagon-ish
  const s = size / 2;
  doc.save()
    .moveTo(x,       y)
    .lineTo(x + s,   y)
    .lineTo(x + s,   y + s * 0.9)
    .lineTo(x + s/2, y + s * 1.35)
    .lineTo(x,       y + s * 0.9)
    .closePath().fill(color).restore();
}

function iconCircle(doc, x, y, r, color) {
  doc.save().circle(x + r, y + r, r).fill(color).restore();
}

function iconCross(doc, x, y, size, color, lw = 1.5) {
  const h = size / 2;
  doc.save()
    .moveTo(x + h, y).lineTo(x + h, y + size)
    .moveTo(x, y + h).lineTo(x + size, y + h)
    .strokeColor(color).lineWidth(lw).stroke().restore();
}

function iconTick(doc, x, y, size, color, lw = 1.5) {
  doc.save()
    .moveTo(x, y + size * 0.5)
    .lineTo(x + size * 0.38, y + size)
    .lineTo(x + size, y)
    .strokeColor(color).lineWidth(lw).stroke().restore();
}

function iconWarn(doc, x, y, size, color) {
  // Triangle
  const h = size * 0.866;
  doc.save()
    .moveTo(x + size / 2, y)
    .lineTo(x + size, y + h)
    .lineTo(x, y + h)
    .closePath().fill(color).restore();
  // Exclamation mark
  doc.save()
    .moveTo(x + size / 2, y + h * 0.3)
    .lineTo(x + size / 2, y + h * 0.65)
    .strokeColor(C.white).lineWidth(1.5).stroke()
    .restore();
  doc.save().circle(x + size / 2, y + h * 0.78, 1).fill(C.white).restore();
}

// ─── Page chrome ──────────────────────────────────────────────────────────────

function drawHeader(doc, subtitle, dateRange) {
  rect(doc, 0, 0, PAGE.width, HEADER, C.primary);
  rect(doc, 0, 0, 5, HEADER, C.accent);

  // Shield icon
  iconShield(doc, PAGE.margin + 2, 20, 20, C.accent);

  // Title
  txt(doc, "WAF Security Report", PAGE.margin + 30, 16, { font: F.bold, size: 17, color: C.white });
  txt(doc, subtitle || "", PAGE.margin + 30, 38, { size: 9, color: C.textMuted });

  // Date range
  const dr = `${formatDate(dateRange?.from)}  —  ${formatDate(dateRange?.to)}`;
  txt(doc, dr, PAGE.margin, 20, { size: 8, color: C.textMuted, width: CW, align: "right" });
  txt(doc, `Generated: ${new Date().toLocaleString()}`, PAGE.margin, 34, { size: 7.5, color: C.textMuted, width: CW, align: "right" });
}

function drawFooter(doc, pageNum) {
  const y = PAGE.height - 30;
  line(doc, PAGE.margin, y, PAGE.width - PAGE.margin, y, C.midGray, 0.5);
  txt(doc, "SOC Dashboard  —  Confidential Security Report", PAGE.margin, y + 7, { size: 7.5, color: C.textMuted });
  txt(doc, `Page ${pageNum}`, PAGE.margin, y + 7, { size: 7.5, color: C.textMuted, width: CW, align: "right" });
  txt(doc, "WAF Analytics Engine v2.0", PAGE.margin, y + 7, { size: 7.5, color: C.textMuted, width: CW, align: "center" });
}

// ─── Section heading ──────────────────────────────────────────────────────────

function sectionTitle(doc, title, y) {
  rect(doc, PAGE.margin, y, 4, 16, C.accent, 2);
  txt(doc, title.toUpperCase(), PAGE.margin + 10, y + 1, { font: F.bold, size: 10, color: C.text });
  return y + 26;
}

// ─── Y-cursor helper — adds a page when near the bottom ──────────────────────

function ensureSpace(doc, y, needed, { subtitle, dateRange, pageCounter }) {
  if (y + needed < BODY_B) return y;
  drawFooter(doc, pageCounter.n);
  doc.addPage();
  pageCounter.n++;
  drawHeader(doc, subtitle, dateRange);
  return BODY_T;
}

// ─── Summary cards (4 across) ────────────────────────────────────────────────

function summaryCards(doc, stats, y) {
  const cardW = (CW - 12) / 4;
  const cardH = 70;

  const cards = [
    { label: "Total Events",    value: (stats.totalEvents   || 0).toLocaleString(), color: C.accent,   iconFn: iconShield  },
    { label: "Blocked",         value: (stats.blocked       || 0).toLocaleString(), color: C.critical, iconFn: iconCross   },
    { label: "Unique Attackers",value: (stats.uniqueAttackers||0).toLocaleString(), color: C.high,     iconFn: iconWarn    },
    { label: "Critical Alerts", value: (stats.criticalEvents||0).toLocaleString(), color: C.medium,   iconFn: iconWarn    },
  ];

  cards.forEach((card, i) => {
    const cx = PAGE.margin + i * (cardW + 4);
    rect(doc, cx, y, cardW, cardH, C.lightGray, 6);
    rect(doc, cx, y, cardW, 3, card.color, 3);
    card.iconFn(doc, cx + 8, y + 10, 14, card.color);
    txt(doc, card.value, cx + 8, y + 30, { font: F.bold, size: 18, color: card.color, width: cardW - 16 });
    txt(doc, card.label, cx + 8, y + 52, { size: 7.5, color: C.darkGray, width: cardW - 16 });
  });

  return y + cardH + 12;
}

// ─── Block-rate bar ───────────────────────────────────────────────────────────

function blockRateBar(doc, rate, y) {
  const pct = Math.min(Math.max(parseFloat(rate) || 0, 0), 100);
  rect(doc, PAGE.margin, y, CW, 32, C.lightGray, 5);
  if (pct > 0) rect(doc, PAGE.margin, y, CW * (pct / 100), 32, `${C.accent}35`, 5);
  txt(doc, `Block Rate: ${pct.toFixed(1)}%`, PAGE.margin + 10, y + 10, { font: F.bold, size: 10, color: C.text });
  txt(doc, "Percentage of detected threats that were blocked", PAGE.margin + 180, y + 11, { size: 8, color: C.darkGray });
  return y + 42;
}

// ─── Vertical bar chart ───────────────────────────────────────────────────────

function barChart(doc, data, x, y, w, h) {
  if (!data?.length) return y;
  const maxVal = Math.max(...data.map(d => d.value), 1);
  const barAreaH = h - 28;
  const barW = Math.min(Math.floor((w - 36) / data.length) - 4, 36);

  rect(doc, x, y, w, h, C.lightGray, 5);

  // Grid lines
  for (let i = 0; i <= 4; i++) {
    const gy = y + 8 + (barAreaH * i) / 4;
    line(doc, x + 28, gy, x + w - 6, gy, C.midGray, 0.4);
    const gv = Math.round(maxVal * (1 - i / 4));
    txt(doc, gv, x + 2, gy - 4, { size: 5.5, color: C.textMuted, width: 24, align: "right" });
  }

  data.forEach((item, i) => {
    const bh = maxVal > 0 ? ((item.value / maxVal) * (barAreaH - 8)) : 0;
    const bx = x + 32 + i * (barW + 4);
    const by = y + 8 + barAreaH - bh;
    const color = item.color ?? C.chart[i % C.chart.length];

    // Shadow
    rect(doc, bx + 2, by + 2, barW, bh, "#00000010", 2);
    // Bar
    if (bh > 0) rect(doc, bx, by, barW, bh, color, 2);

    // Value on top
    if (item.value > 0) {
      txt(doc, item.value, bx, by - 9, { font: F.bold, size: 6, color: C.text, width: barW, align: "center" });
    }

    // Label below
    const lbl = item.label.length > 8 ? item.label.slice(0, 7) + "…" : item.label;
    txt(doc, lbl, bx - 2, y + h - 16, { size: 5.5, color: C.darkGray, width: barW + 4, align: "center" });
  });

  return y + h + 10;
}

// ─── Donut chart ──────────────────────────────────────────────────────────────

function donutChart(doc, data, cx, cy, radius) {
  if (!data?.length) return;
  const total = data.reduce((s, d) => s + d.value, 0);
  if (!total) return;

  let angle = -Math.PI / 2;
  data.forEach((item, i) => {
    const sweep = (item.value / total) * 2 * Math.PI;
    const end   = angle + sweep;
    const color = item.color ?? C.chart[i % C.chart.length];
    const steps = Math.max(12, Math.ceil(sweep * 12));

    doc.save().moveTo(cx, cy);
    for (let s = 0; s <= steps; s++) {
      const a = angle + (sweep * s) / steps;
      doc.lineTo(cx + Math.cos(a) * radius, cy + Math.sin(a) * radius);
    }
    doc.closePath().fill(color).restore();
    angle = end;
  });

  // Donut hole
  doc.save().circle(cx, cy, radius * 0.52).fill(C.lightGray).restore();

  // Center label
  const top = data[0];
  const pct = Math.round((top.value / total) * 100);
  txt(doc, `${pct}%`, cx - 16, cy - 9, { font: F.bold, size: 11, color: C.text, width: 32, align: "center" });
  txt(doc, top.label, cx - 20, cy + 2, { size: 6, color: C.darkGray, width: 40, align: "center" });

  // Legend
  const lx = cx + radius + 14;
  let   ly = cy - (data.length * 13) / 2;
  data.forEach((item, i) => {
    const color = item.color ?? C.chart[i % C.chart.length];
    rect(doc, lx, ly + 1, 7, 7, color, 1);
    txt(doc, `${item.label} (${item.value})`, lx + 10, ly, { size: 7.5, color: C.text });
    ly += 13;
  });
}

// ─── Horizontal bar chart ─────────────────────────────────────────────────────

function hBars(doc, data, x, y, w, maxRows = 8) {
  const rows     = data.slice(0, maxRows);
  const barH     = 15;
  const labelW   = 110;
  const barAreaW = w - labelW - 36;
  const maxVal   = Math.max(...rows.map(d => d.count || d.value || 0), 1);

  rows.forEach((item, i) => {
    const val   = item.count || item.value || 0;
    const bw    = (val / maxVal) * barAreaW;
    const by    = y + i * (barH + 4);
    const color = item.color ?? C.chart[i % C.chart.length];
    const label = String(item.ip || item.type || item.label || "Unknown").slice(0, 18);

    txt(doc, label, x, by + 3, { size: 7, color: C.text, width: labelW - 4 });
    rect(doc, x + labelW, by, barAreaW, barH, C.midGray, 3);
    if (bw > 0) rect(doc, x + labelW, by, bw, barH, color, 3);

    if (bw > 20) {
      txt(doc, val, x + labelW + 4, by + 3, { font: F.bold, size: 6.5, color: C.white });
    } else {
      txt(doc, val, x + labelW + barAreaW + 4, by + 3, { font: F.bold, size: 6.5, color: C.text });
    }
  });

  return y + rows.length * (barH + 4) + 8;
}

// ─── Trend line chart ─────────────────────────────────────────────────────────

function trendLine(doc, data, x, y, w, h) {
  if (!data?.length || data.length < 2) return y;
  const maxVal = Math.max(...data.map(d => d.total || d.count || 0), 1);
  const stepX  = (w - 40) / (data.length - 1);
  const plotX  = x + 30;
  const plotY  = y + 14;
  const plotH  = h - 22;

  rect(doc, x, y, w, h, C.lightGray, 5);

  // Grid
  for (let i = 0; i <= 3; i++) {
    const gy = plotY + (plotH * i) / 3;
    line(doc, plotX, gy, plotX + w - 40, gy, C.midGray, 0.4);
    txt(doc, Math.round(maxVal * (1 - i / 3)), x + 2, gy - 4, { size: 5.5, color: C.textMuted, width: 26, align: "right" });
  }

  const pts = data.map((d, i) => {
    const v = d.total || d.count || 0;
    return [plotX + i * stepX, plotY + plotH - (v / maxVal) * plotH];
  });

  // Fill
  doc.save()
    .moveTo(pts[0][0], plotY + plotH);
  pts.forEach(([px, py]) => doc.lineTo(px, py));
  doc.lineTo(pts[pts.length - 1][0], plotY + plotH)
    .closePath().fillColor(`${C.accent}28`).fill().restore();

  // Line
  doc.save().moveTo(pts[0][0], pts[0][1]);
  pts.slice(1).forEach(([px, py]) => doc.lineTo(px, py));
  doc.strokeColor(C.accent).lineWidth(1.8).stroke().restore();

  // Dots
  pts.forEach(([px, py]) => {
    doc.save().circle(px, py, 2.5).fill(C.accentDark).restore();
  });

  // X labels
  const step = Math.max(1, Math.floor(data.length / 7));
  data.forEach((d, i) => {
    if (i % step !== 0) return;
    const label = d.date ? String(d.date).slice(5) : `T${i + 1}`;
    txt(doc, label, plotX + i * stepX - 14, plotY + plotH + 4, { size: 5.5, color: C.darkGray, width: 28, align: "center" });
  });

  return y + h + 10;
}

// ─── Data table ───────────────────────────────────────────────────────────────

function dataTable(doc, rows, columns, y, pc) {
  const rowH    = 18;
  const headH   = 22;
  const maxRows = 20;
  const display = rows.slice(0, maxRows);

  // Header
  rect(doc, PAGE.margin, y, CW, headH, C.primary, 4);
  let cx = PAGE.margin + 6;
  columns.forEach(col => {
    txt(doc, col.header, cx, y + 6, { font: F.bold, size: 7.5, color: C.white, width: col.width - 8 });
    cx += col.width;
  });
  y += headH;

  display.forEach((row, i) => {
    // Page break check
    if (y + rowH > BODY_B) {
      drawFooter(doc, pc.n);
      doc.addPage();
      pc.n++;
      // Redraw header on new page
      rect(doc, PAGE.margin, BODY_T - 26, CW, headH, C.primary, 4);
      let hx = PAGE.margin + 6;
      columns.forEach(col => {
        txt(doc, col.header, hx, BODY_T - 26 + 6, { font: F.bold, size: 7.5, color: C.white, width: col.width - 8 });
        hx += col.width;
      });
      y = BODY_T - 4;
    }

    rect(doc, PAGE.margin, y, CW, rowH, i % 2 === 0 ? C.white : C.lightGray);

    let colX = PAGE.margin + 6;
    columns.forEach(col => {
      const raw = col.key.split(".").reduce((o, k) => o?.[k], row);
      const val = raw == null ? "—" : String(raw);

      if (col.key === "severity") {
        const sc = sevColor(val);
        rect(doc, colX, y + 4, 44, 10, sc + "25", 3);
        txt(doc, val.toUpperCase(), colX + 2, y + 5, { font: F.bold, size: 6, color: sc, width: 40 });
      } else if (col.key === "action") {
        const ac = val === "blocked" ? C.critical : C.low;
        rect(doc, colX, y + 4, 40, 10, ac + "25", 3);
        txt(doc, val.toUpperCase(), colX + 2, y + 5, { font: F.bold, size: 6, color: ac, width: 36 });
      } else {
        const disp = val.length > 28 ? val.slice(0, 27) + "…" : val;
        txt(doc, disp, colX, y + 4, { size: 7, color: C.text, width: col.width - 10 });
      }
      colX += col.width;
    });

    // Row border
    line(doc, PAGE.margin, y + rowH, PAGE.margin + CW, y + rowH, C.midGray, 0.3);
    y += rowH;
  });

  // Table outer border
  border(doc, PAGE.margin, y - display.length * rowH - headH, CW, headH + display.length * rowH, C.border, 0.5, 4);

  if (rows.length > maxRows) {
    txt(doc, `+ ${rows.length - maxRows} more rows — download CSV for full dataset`, PAGE.margin, y + 4, { size: 7.5, color: C.textMuted });
    y += 16;
  }

  return y + 8;
}

// ─── Recommendations ─────────────────────────────────────────────────────────

function drawRecommendations(doc, recs, y, pc, subtitle, dateRange) {
  const cardH = 48;

  recs.forEach((rec, i) => {
    y = ensureSpace(doc, y, cardH + 6, { subtitle, dateRange, pageCounter: pc });

    const sc = sevColor(rec.severity);
    rect(doc, PAGE.margin, y, CW, cardH, C.lightGray, 5);
    rect(doc, PAGE.margin, y, 4, cardH, sc, 3);

    // Severity badge
    rect(doc, PAGE.margin + 10, y + 8, 46, 12, sc + "30", 3);
    txt(doc, rec.severity.toUpperCase(), PAGE.margin + 12, y + 10, { font: F.bold, size: 7, color: sc, width: 42 });

    txt(doc, rec.title, PAGE.margin + 62, y + 8, { font: F.bold, size: 9, color: C.text, width: CW - 74 });
    txt(doc, rec.description, PAGE.margin + 10, y + 26, { size: 7.5, color: C.darkGray, width: CW - 20 });

    y += cardH + 6;
  });

  return y;
}

// ─── Shared page scaffolding ──────────────────────────────────────────────────

function initDoc(reportData, reportType) {
  const doc    = new PDFDocument({ size: "A4", margin: 0, bufferPages: true, autoFirstPage: true });
  const chunks = [];
  doc.on("data", c => chunks.push(c));

  const subtitle = reportData.reportType || reportType || "Security Report";
  const dr       = reportData.dateRange  || {};
  const pc       = { n: 1 };
  const summary  = {
    totalEvents:     reportData.summary?.totalEvents     || reportData.totalThreats || 0,
    blocked:         reportData.summary?.blocked         || 0,
    uniqueAttackers: reportData.summary?.uniqueAttackers || 0,
    criticalEvents:  reportData.summary?.criticalEvents  || reportData.criticalAlerts?.length || 0,
  };

  drawHeader(doc, subtitle, dr);

  return { doc, chunks, subtitle, dr, pc, summary };
}

function finishDoc(doc, pc, subtitle, dr, summary, chunks) {
  // Recommendations + metadata on final page
  const recs = buildRecommendations(summary, {});

  doc.addPage();
  pc.n++;
  drawHeader(doc, subtitle, dr);
  let y = BODY_T;

  y = sectionTitle(doc, "Security Recommendations", y);
  y = drawRecommendations(doc, recs, y, pc, subtitle, dr);

  y = ensureSpace(doc, y + 10, 100, { subtitle, dateRange: dr, pageCounter: pc });
  y = sectionTitle(doc, "Report Metadata", y);

  const metaH = 72;
  rect(doc, PAGE.margin, y, CW, metaH, C.lightGray, 5);
  border(doc, PAGE.margin, y, CW, metaH, C.border, 0.5, 5);
  const meta = [
    ["Report Type",           subtitle],
    ["Generated At",          new Date().toLocaleString()],
    ["Date Range",            `${formatDate(dr.from)}  to  ${formatDate(dr.to)}`],
    ["Total Events Analyzed", summary.totalEvents.toLocaleString()],
  ];
  meta.forEach(([label, value], i) => {
    const mx = i % 2 === 0 ? PAGE.margin + 10 : PAGE.margin + CW / 2 + 10;
    const my = y + Math.floor(i / 2) * 30 + 10;
    txt(doc, label + ":", mx, my, { font: F.bold, size: 8, color: C.darkGray });
    txt(doc, String(value), mx + 115, my, { size: 8, color: C.text, width: CW / 2 - 130 });
  });
  y += metaH + 14;

  y = ensureSpace(doc, y, 70, { subtitle, dateRange: dr, pageCounter: pc });
  y = sectionTitle(doc, "WAF Detection Engine", y);
  rect(doc, PAGE.margin, y, CW, 56, C.lightGray, 5);
  border(doc, PAGE.margin, y, CW, 56, C.border, 0.5, 5);
  txt(doc,
    "This report was generated by the WAF Security Analytics Engine, powered by a Snort-compatible " +
    "rule set covering SQLi, XSS, Path Traversal, RCE, CSRF, XXE, SSRF, NoSQLi, Open Redirect, " +
    "Prototype Pollution, HTTP Smuggling, JWT Tampering, and Recon detection.",
    PAGE.margin + 10, y + 10, { size: 8, color: C.darkGray, width: CW - 20 }
  );

  drawFooter(doc, pc.n);
  doc.end();

  return new Promise((resolve, reject) => {
    doc.on("end",   () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);
  });
}

// ─── Events table helper (shared by daily + threats) ─────────────────────────

function renderEventsTable(doc, events, y, pc, subtitle, dr, tableTitle = "Security Events Log") {
  if (!events?.length) return y;

  y = ensureSpace(doc, y, 60, { subtitle, dateRange: dr, pageCounter: pc });
  y = sectionTitle(doc, tableTitle, y);

  const columns = [
    { header: "Timestamp",   key: "timestamp",  width: 92 },
    { header: "Attack Type", key: "attackType", width: 82 },
    { header: "Source IP",   key: "sourceIP",   width: 82 },
    { header: "Target URL",  key: "targetURL",  width: 105 },
    { header: "Severity",    key: "severity",   width: 60 },
    { header: "Action",      key: "action",     width: 52 },
    { header: "Country",     key: "country",    width: 42 },
  ];

  const rows = events.map(e => ({
    ...e,
    timestamp: e.timestamp ? new Date(e.timestamp).toLocaleString() : "—",
  }));

  return dataTable(doc, rows, columns, y, pc);
}

// ─── Report type renderers ────────────────────────────────────────────────────

// ── 1. Daily Security Summary ─────────────────────────────────────────────────
function renderDaily(doc, reportData, summary, subtitle, dr, pc) {
  let y = BODY_T;

  // Executive summary cards
  y = sectionTitle(doc, "Executive Summary", y);
  y = summaryCards(doc, summary, y);

  // Attack type bar chart
  const attackDist = (reportData.topAttackTypes || [])
    .map((item, i) => ({ label: item.type || "Unknown", value: item.count || 0, color: C.chart[i % C.chart.length] }))
    .filter(d => d.value > 0);

  if (attackDist.length > 0) {
    y = ensureSpace(doc, y, 150, { subtitle, dateRange: dr, pageCounter: pc });
    y = sectionTitle(doc, "Attack Type Distribution", y);
    y = barChart(doc, attackDist, PAGE.margin, y, CW, 120);
  }

  // Donut + top IPs side by side
  if (attackDist.length > 0) {
    const halfW = (CW - 10) / 2;
    y = ensureSpace(doc, y, 175, { subtitle, dateRange: dr, pageCounter: pc });
    y = sectionTitle(doc, "Threat Breakdown", y);

    donutChart(doc, attackDist.slice(0, 6),
      PAGE.margin + Math.round(halfW * 0.38), y + 80, 55);

    txt(doc, "Top Categories by Volume", PAGE.margin + halfW + 10, y,
      { font: F.bold, size: 9, color: C.text });
    hBars(doc, attackDist, PAGE.margin + halfW + 10, y + 16, halfW, 6);
    y += 170;
  }

  drawFooter(doc, pc.n);

  // Page 2 — events log
  doc.addPage(); pc.n++;
  drawHeader(doc, subtitle, dr);
  y = BODY_T;
  y = renderEventsTable(doc, reportData.events, y, pc, subtitle, dr, "All Security Events");
  drawFooter(doc, pc.n);
}

// ── 2. Threat Analysis Report ─────────────────────────────────────────────────
function renderThreats(doc, reportData, summary, subtitle, dr, pc) {
  let y = BODY_T;

  y = sectionTitle(doc, "Executive Summary", y);
  y = summaryCards(doc, summary, y);

  // Attack patterns with blocked vs total side-by-side bars
  const patterns = (reportData.attackPatterns || [])
    .map((p, i) => ({
      label:   p.type || "Unknown",
      value:   p.count || 0,
      blocked: p.blocked || 0,
      color:   C.chart[i % C.chart.length],
    }))
    .filter(d => d.value > 0);

  if (patterns.length > 0) {
    y = ensureSpace(doc, y, 150, { subtitle, dateRange: dr, pageCounter: pc });
    y = sectionTitle(doc, "Attack Pattern Analysis", y);
    y = barChart(doc, patterns, PAGE.margin, y, CW, 120);

    // Blocked rate per type as horizontal bars
    y = ensureSpace(doc, y, 30 + patterns.length * 20, { subtitle, dateRange: dr, pageCounter: pc });
    y = sectionTitle(doc, "Block Rate by Attack Type", y);
    const blockRates = patterns.map((p, i) => ({
      label: p.label,
      count: p.value > 0 ? Math.round((p.blocked / p.value) * 100) : 0,
      color: C.chart[i % C.chart.length],
    }));
    y = hBars(doc, blockRates, PAGE.margin, y, CW, 8);
    // Label clarification
    txt(doc, "Values show % of requests blocked per attack type", PAGE.margin, y,
      { size: 7.5, color: C.textMuted });
    y += 14;
  }

  // Top attacking IPs
  const topThreats = (reportData.topThreats || []).slice(0, 10);
  if (topThreats.length > 0) {
    y = ensureSpace(doc, y, 30 + topThreats.length * 20, { subtitle, dateRange: dr, pageCounter: pc });
    y = sectionTitle(doc, "Top Attacking IPs", y);
    const ipBars = topThreats.map((t, i) => ({
      label: `${t.ip || "?"} (${t.country || "?"})`,
      count: t.count || 0,
      color: C.chart[i % C.chart.length],
    }));
    y = hBars(doc, ipBars, PAGE.margin, y, CW, 10);
  }

  drawFooter(doc, pc.n);

  // Page 2 — critical alerts table
  doc.addPage(); pc.n++;
  drawHeader(doc, subtitle, dr);
  y = BODY_T;

  const criticals = reportData.criticalAlerts || reportData.events?.filter(e => e.severity === "critical") || [];
  y = renderEventsTable(doc, criticals, y, pc, subtitle, dr, "Critical Alerts");

  // If room left, also show all events
  if (criticals.length === 0) {
    y = renderEventsTable(doc, reportData.events, y, pc, subtitle, dr, "All Security Events");
  }

  drawFooter(doc, pc.n);
}

// ── 3. IP Intelligence Report ─────────────────────────────────────────────────
function renderIPs(doc, reportData, summary, subtitle, dr, pc) {
  let y = BODY_T;

  // Summary cards — tweak labels for IP context
  const ipSummary = {
    ...summary,
    totalEvents: reportData.totalUniqueIPs || summary.uniqueAttackers || 0,
  };

  // Custom 4-card row for IP report
  const cardW = (CW - 12) / 4;
  const cardH = 70;
  const ipCards = [
    { label: "Unique IPs",        value: (reportData.totalUniqueIPs || 0).toLocaleString(),         color: C.accent,   iconFn: iconShield },
    { label: "Total Requests",    value: (summary.totalEvents || 0).toLocaleString(),                color: C.high,     iconFn: iconWarn   },
    { label: "Blocked IPs",       value: (summary.blocked || 0).toLocaleString(),                   color: C.critical, iconFn: iconCross  },
    { label: "Critical Events",   value: (summary.criticalEvents || 0).toLocaleString(),            color: C.medium,   iconFn: iconWarn   },
  ];
  ipCards.forEach((card, i) => {
    const cx = PAGE.margin + i * (cardW + 4);
    rect(doc, cx, y, cardW, cardH, C.lightGray, 6);
    rect(doc, cx, y, cardW, 3, card.color, 3);
    card.iconFn(doc, cx + 8, y + 10, 14, card.color);
    txt(doc, card.value, cx + 8, y + 30, { font: F.bold, size: 18, color: card.color, width: cardW - 16 });
    txt(doc, card.label, cx + 8, y + 52, { size: 7.5, color: C.darkGray, width: cardW - 16 });
  });
  y += cardH + 14;

  // Top IPs by request volume
  const profiles = (reportData.profiles || []).slice(0, 12);
  if (profiles.length > 0) {
    y = ensureSpace(doc, y, 30 + profiles.length * 20, { subtitle, dateRange: dr, pageCounter: pc });
    y = sectionTitle(doc, "Top Attacking IPs by Volume", y);
    const ipBars = profiles.map((p, i) => ({
      label: `${p.ip} (${p.country || "?"})`,
      count: p.totalRequests || 0,
      color: C.chart[i % C.chart.length],
    }));
    y = hBars(doc, ipBars, PAGE.margin, y, CW, 12);
  }

  // Attack type distribution for IP report
  const attackDist = (reportData.attackPatterns || [])
    .map((p, i) => ({ label: p.type || "Unknown", value: p.count || 0, color: C.chart[i % C.chart.length] }))
    .filter(d => d.value > 0);

  if (attackDist.length > 0) {
    y = ensureSpace(doc, y, 150, { subtitle, dateRange: dr, pageCounter: pc });
    y = sectionTitle(doc, "Attack Types Observed", y);
    y = barChart(doc, attackDist, PAGE.margin, y, CW, 110);
  }

  drawFooter(doc, pc.n);

  // Page 2 — IP detail table
  doc.addPage(); pc.n++;
  drawHeader(doc, subtitle, dr);
  y = BODY_T;

  if (profiles.length > 0) {
    y = sectionTitle(doc, "IP Profile Details", y);

    const ipColumns = [
      { header: "Source IP",     key: "ip",            width: 90  },
      { header: "Country",       key: "country",       width: 75  },
      { header: "Total Reqs",    key: "totalRequests", width: 60  },
      { header: "Blocked",       key: "blocked",       width: 52  },
      { header: "Risk Score",    key: "riskScore",     width: 55  },
      { header: "Attack Types",  key: "attackTypeStr", width: 100 },
      { header: "Last Seen",     key: "lastSeenStr",   width: 83  },
    ];

    const ipRows = profiles.map(p => ({
      ...p,
      attackTypeStr: (p.attackTypes || []).slice(0, 3).join(", "),
      lastSeenStr:   p.lastSeen ? new Date(p.lastSeen).toLocaleDateString() : "—",
    }));

    y = dataTable(doc, ipRows, ipColumns, y, pc);
  }

  drawFooter(doc, pc.n);
}

// ── 4. Security Trends Report ─────────────────────────────────────────────────
function renderTrends(doc, reportData, summary, subtitle, dr, pc) {
  let y = BODY_T;

  y = sectionTitle(doc, "Executive Summary", y);
  y = summaryCards(doc, summary, y);

  // Block rate progress bar
  if (reportData.overallBlockRate !== undefined) {
    y = blockRateBar(doc, reportData.overallBlockRate, y);
  }

  // Daily trend line chart (main feature of this report)
  const trend = reportData.dailyTrend || [];
  if (trend.length > 1) {
    y = ensureSpace(doc, y, 140, { subtitle, dateRange: dr, pageCounter: pc });
    y = sectionTitle(doc, "Daily Event Volume", y);
    y = trendLine(doc, trend, PAGE.margin, y, CW, 120);

    // Blocked-only trend line
    const blockedTrend = trend.map(d => ({ ...d, total: d.blocked || 0 }));
    if (blockedTrend.some(d => d.total > 0)) {
      y = ensureSpace(doc, y, 140, { subtitle, dateRange: dr, pageCounter: pc });
      y = sectionTitle(doc, "Daily Blocked Threats", y);
      y = trendLine(doc, blockedTrend, PAGE.margin, y, CW, 110);
    }
  }

  // Attack evolution (bar chart of attack types over period)
  const evolution = (reportData.attackEvolution || [])
    .map((item, i) => ({ label: item.type || "Unknown", value: item.total || item.count || 0, color: C.chart[i % C.chart.length] }))
    .filter(d => d.value > 0);

  if (evolution.length > 0) {
    y = ensureSpace(doc, y, 150, { subtitle, dateRange: dr, pageCounter: pc });
    y = sectionTitle(doc, "Attack Type Evolution", y);

    const halfW = (CW - 10) / 2;
    barChart(doc, evolution, PAGE.margin, y, halfW, 110);
    donutChart(doc, evolution.slice(0, 6),
      PAGE.margin + halfW + 10 + Math.round(halfW * 0.38), y + 70, 50);
    y += 120;
  }

  // Peak days table
  if (trend.length > 0) {
    const sorted = [...trend].sort((a, b) => (b.total || 0) - (a.total || 0)).slice(0, 7);
    y = ensureSpace(doc, y, 50 + sorted.length * 20, { subtitle, dateRange: dr, pageCounter: pc });
    y = sectionTitle(doc, "Highest Activity Days", y);

    const trendCols = [
      { header: "Date",            key: "date",        width: 100 },
      { header: "Total Events",    key: "total",       width: 100 },
      { header: "Blocked",         key: "blocked",     width: 100 },
      { header: "Critical",        key: "critical",    width: 100 },
      { header: "Allow Rate %",    key: "allowRateStr",width: 115 },
    ];

    const trendRows = sorted.map(d => ({
      date:         String(d.date || "").slice(0, 10),
      total:        d.total    || 0,
      blocked:      d.blocked  || 0,
      critical:     d.critical || 0,
      allowRateStr: d.total > 0
        ? `${(((d.total - (d.blocked || 0)) / d.total) * 100).toFixed(1)}%`
        : "0%",
    }));

    y = dataTable(doc, trendRows, trendCols, y, pc);
  }

  drawFooter(doc, pc.n);
}

// ─── Main export ──────────────────────────────────────────────────────────────

async function generatePDFReport(reportData, reportType) {
  const type = (reportType || reportData.reportType || "daily").toLowerCase()
    .replace("daily security summary",    "daily")
    .replace("threat analysis report",    "threats")
    .replace("ip intelligence report",    "ips")
    .replace("security trends report",    "trends");

  const { doc, chunks, subtitle, dr, pc, summary } = initDoc(reportData, reportType);

  // Route to the correct renderer
  switch (type) {
    case "threats": renderThreats(doc, reportData, summary, subtitle, dr, pc); break;
    case "ips":     renderIPs    (doc, reportData, summary, subtitle, dr, pc); break;
    case "trends":  renderTrends (doc, reportData, summary, subtitle, dr, pc); break;
    default:        renderDaily  (doc, reportData, summary, subtitle, dr, pc); break;
  }

  // Shared final page: recommendations + metadata
  return finishDoc(doc, pc, subtitle, dr, summary, chunks);
}

// ─── Recommendations engine ───────────────────────────────────────────────────

function buildRecommendations(summary, reportData) {
  const recs = [];

  if (summary.criticalEvents > 0) {
    recs.push({
      severity: "critical",
      title: "Immediate Action Required: Critical Events Detected",
      description: `${summary.criticalEvents} critical security event${summary.criticalEvents > 1 ? "s were" : " was"} logged. Review attack payloads and harden database query parameterization and input validation. Enable automatic IP blocking for repeat offenders.`,
    });
  }

  const blockRate = summary.totalEvents > 0 ? (summary.blocked / summary.totalEvents) * 100 : 0;
  if (blockRate < 70 && summary.totalEvents > 0) {
    recs.push({
      severity: "high",
      title: "Improve Block Rate",
      description: `Current block rate is ${blockRate.toFixed(1)}%. Review WAF rules and enable any disabled rules. Consider lowering thresholds for high-risk categories such as SQLi and RCE.`,
    });
  }

  if (summary.uniqueAttackers > 20) {
    recs.push({
      severity: "medium",
      title: "Distributed Attack Pattern Detected",
      description: `${summary.uniqueAttackers} unique source IPs detected. This may indicate a botnet or coordinated attack. Consider enabling geo-blocking for high-risk countries and CAPTCHA on public endpoints.`,
    });
  }

  recs.push({
    severity: "low",
    title: "Review Threshold Settings",
    description: "Ensure detection thresholds are tuned for your traffic volume. Rules with threshold > 1 will allow early probe requests through before blocking — lower thresholds increase sensitivity.",
  });

  recs.push({
    severity: "info",
    title: "Regular Rule Updates Recommended",
    description: "Snort rule signatures should be reviewed monthly to cover emerging CVEs. Current ruleset covers 15 attack categories. Consider integrating OWASP CRS or Emerging Threats rulesets.",
  });

  return recs.slice(0, 5);
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatDate(d) {
  if (!d) return "N/A";
  try {
    return new Date(d).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
  } catch {
    return String(d);
  }
}

module.exports = { generatePDFReport };
