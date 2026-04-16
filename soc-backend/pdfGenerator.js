/**
 * PDF Report Generator — SecureSOC WAF Platform  (Dark Edition)
 *
 * Changes from previous version:
 *  - Full dark theme: near-black page, dark cards, light text
 *  - Severity & Action: wider pill badges with high-contrast colors on dark rows
 *  - Country column: increased from 40px → 65px; all columns re-balanced to 523px total
 *  - Row height: 18 → 22px for better readability
 *  - Charts/trend lines adapted to dark backgrounds
 *  - Per-corner radius fix retained (PDFKit only accepts a number, not object)
 */

const PDFDocument = require("pdfkit");

// ─── Dark Design Tokens ───────────────────────────────────────────────────────

const C = {
  // Page layers
  pageBg:     "#0D1117",   // darkest — page background fill
  surface:    "#161B22",   // card / panel background
  surfaceAlt: "#1C2128",   // alternating table rows
  elevated:   "#21262D",   // borders, dividers, chart grids

  // Header / footer
  headerBg:   "#010409",   // near-black header
  accent:     "#58A6FF",   // bright blue — works on dark bg
  accentDim:  "#1F6FEB",   // deeper blue for gradients

  // Severity (vivid on dark)
  critical:   "#FF6B6B",
  high:       "#FF8C42",
  medium:     "#FFD166",
  low:        "#06D6A0",
  info:       "#8B949E",

  // Severity badge backgrounds (very dark tinted)
  criticalBg: "#2D0F0F",
  highBg:     "#2D1A0A",
  mediumBg:   "#2D2608",
  lowBg:      "#0A2D1A",
  infoBg:     "#1C2128",

  // Text
  textPrimary: "#E6EDF3",   // bright white-ish
  textSecond:  "#8B949E",   // muted slate
  textDim:     "#484F58",   // very muted

  // Chart palette (vivid, works on dark)
  chart: ["#58A6FF","#FF6B6B","#FF8C42","#FFD166","#06D6A0","#A78BFA","#F472B6","#22D3EE","#FB923C","#34D399"],
};

const F = { bold: "Helvetica-Bold", regular: "Helvetica" };

const PAGE   = { width: 595, height: 842, margin: 36 };
const CW     = PAGE.width - PAGE.margin * 2;   // 523
const HEADER = 82;
const FOOTER = 42;
const BODY_T = HEADER + 22;
const BODY_B = PAGE.height - FOOTER - 12;

// ─── Drawing Helpers ──────────────────────────────────────────────────────────

/**
 * Filled rectangle.
 * radius: number → PDFKit roundedRect
 * radius: object → per-corner {tl,tr,br,bl} via bezier (PDFKit limitation workaround)
 */
function rect(doc, x, y, w, h, fill, radius = 0) {
  if (typeof radius === "object") {
    const { tl = 0, tr = 0, br = 0, bl = 0 } = radius;
    doc.save()
      .moveTo(x + tl, y)
      .lineTo(x + w - tr, y)
      .quadraticCurveTo(x + w, y,     x + w, y + tr)
      .lineTo(x + w, y + h - br)
      .quadraticCurveTo(x + w, y + h, x + w - br, y + h)
      .lineTo(x + bl, y + h)
      .quadraticCurveTo(x, y + h,     x, y + h - bl)
      .lineTo(x, y + tl)
      .quadraticCurveTo(x, y,         x + tl, y)
      .closePath().fill(fill).restore();
  } else {
    doc.save().roundedRect(x, y, w, h, radius || 0).fill(fill).restore();
  }
}

function strokeRect(doc, x, y, w, h, stroke, lw = 0.5, radius = 0) {
  doc.save().roundedRect(x, y, w, h, radius).strokeColor(stroke).lineWidth(lw).stroke().restore();
}

function line(doc, x1, y1, x2, y2, color = C.elevated, lw = 0.5) {
  doc.save().moveTo(x1, y1).lineTo(x2, y2).strokeColor(color).lineWidth(lw).stroke().restore();
}

function dashedLine(doc, x1, y1, x2, y2, color = C.elevated, lw = 0.4) {
  doc.save().moveTo(x1, y1).lineTo(x2, y2).dash(3, { space: 4 }).strokeColor(color).lineWidth(lw).stroke().restore();
}

function txt(doc, text, x, y, {
  font = F.regular, size = 9, color = C.textPrimary,
  width, align = "left", lineBreak = true,
} = {}) {
  doc.font(font).fontSize(size).fillColor(color);
  const opts = { lineBreak };
  if (width) opts.width = width;
  if (align) opts.align = align;
  doc.text(String(text ?? "—"), x, y, opts);
}

function sevColor(s) {
  const map = { critical: C.critical, high: C.high, medium: C.medium, low: C.low, info: C.info };
  return map[s?.toLowerCase()] ?? C.info;
}

function sevBg(s) {
  const map = { critical: C.criticalBg, high: C.highBg, medium: C.mediumBg, low: C.lowBg, info: C.infoBg };
  return map[s?.toLowerCase()] ?? C.infoBg;
}

// ─── Icons (geometry only — no emoji) ────────────────────────────────────────

function logoSecureSOC(doc, x, y, size) {
  // Shield body in accent
  const s = size / 2, c = s * 0.12, p = s * 0.08;
  doc.save()
    .moveTo(x + c, y).lineTo(x + s - c, y)
    .lineTo(x + s + p, y + c * 1.5).lineTo(x + s + p, y + s - p)
    .lineTo(x + s / 2, y + s * 1.3).lineTo(x - p, y + s - p)
    .lineTo(x - p, y + c * 1.5).closePath().fill(C.accent).restore();

  // EKG line in dark
  const sw = size / 18;
  const ix = x + s * 0.08, iy = y + s * 0.32, iw = s * 0.84, ih = s * 0.44;
  doc.save()
    .moveTo(ix,           iy + ih * 0.5)
    .lineTo(ix + iw*0.12, iy + ih * 0.5)
    .lineTo(ix + iw*0.24, iy + ih * 0.2)
    .lineTo(ix + iw*0.36, iy + ih * 0.8)
    .lineTo(ix + iw*0.48, iy)
    .lineTo(ix + iw*0.60, iy + ih)
    .lineTo(ix + iw*0.72, iy + ih * 0.2)
    .lineTo(ix + iw*0.84, iy + ih * 0.5)
    .lineTo(ix + iw,      iy + ih * 0.5)
    .strokeColor(C.headerBg).lineWidth(sw).stroke().restore();
}

function iconShield(doc, x, y, size, color) {
  const s = size / 2;
  doc.save().moveTo(x, y).lineTo(x + s, y).lineTo(x + s, y + s * 0.85)
    .lineTo(x + s/2, y + s * 1.3).lineTo(x, y + s * 0.85).closePath().fill(color).restore();
}

function iconBlock(doc, x, y, size, color, lw = 1.8) {
  // X symbol for "blocked"
  const p = size * 0.2;
  doc.save()
    .moveTo(x + p, y + p).lineTo(x + size - p, y + size - p)
    .moveTo(x + size - p, y + p).lineTo(x + p, y + size - p)
    .strokeColor(color).lineWidth(lw).stroke().restore();
}

function iconWarn(doc, x, y, size, color) {
  const h = size * 0.866;
  doc.save().moveTo(x + size/2, y).lineTo(x + size, y + h).lineTo(x, y + h).closePath().fill(color).restore();
  doc.save().moveTo(x + size/2, y + h*0.28).lineTo(x + size/2, y + h*0.64)
    .strokeColor(C.pageBg).lineWidth(1.4).stroke().restore();
  doc.save().circle(x + size/2, y + h*0.78, 1.1).fill(C.pageBg).restore();
}

// ─── Page Chrome ──────────────────────────────────────────────────────────────

function drawHeader(doc, subtitle, dateRange) {
  // Full-bleed header
  rect(doc, 0, 0, PAGE.width, HEADER, C.headerBg);
  // Left accent bar
  rect(doc, 0, 0, 5, HEADER, C.accent);
  // Subtle bottom border
  line(doc, 0, HEADER, PAGE.width, HEADER, C.elevated, 1);

  logoSecureSOC(doc, PAGE.margin + 2, 20, 26);

  txt(doc, "SecureSOC", PAGE.margin + 38, 16, { font: F.bold, size: 21, color: C.textPrimary });
  txt(doc, subtitle || "WAF Security Report", PAGE.margin + 38, 40, { size: 10, color: C.textSecond });

  const dr = `${formatDate(dateRange?.from)}  —  ${formatDate(dateRange?.to)}`;
  txt(doc, dr, PAGE.margin, 22, { size: 8, color: C.textSecond, width: CW, align: "right" });
  txt(doc, `Generated: ${new Date().toLocaleString()}`, PAGE.margin, 36, { size: 7.5, color: C.textDim, width: CW, align: "right" });
}

function drawFooter(doc, pageNum) {
  const y = PAGE.height - 30;
  // Footer background strip
  rect(doc, 0, y - 8, PAGE.width, 38, C.headerBg);
  line(doc, 0, y - 8, PAGE.width, y - 8, C.elevated, 0.5);
  txt(doc, "SecureSOC WAF Platform  —  Confidential", PAGE.margin, y + 4, { size: 7.5, color: C.textDim });
  txt(doc, `Page ${pageNum}`, PAGE.margin, y + 4, { font: F.bold, size: 7.5, color: C.textSecond, width: CW, align: "right" });
  txt(doc, "SecureSOC Engine v3.1", PAGE.margin, y + 4, { size: 7.5, color: C.textDim, width: CW, align: "center" });
}

function sectionTitle(doc, title, y) {
  // Accent pill + label
  rect(doc, PAGE.margin, y + 2, 3, 14, C.accent, 2);
  txt(doc, title.toUpperCase(), PAGE.margin + 10, y + 2, { font: F.bold, size: 9.5, color: C.textPrimary });
  // Thin underline
  line(doc, PAGE.margin, y + 20, PAGE.margin + CW, y + 20, C.elevated, 0.4);
  return y + 30;
}

function ensureSpace(doc, y, needed, { subtitle, dateRange, pageCounter }) {
  if (y + needed < BODY_B) return y;
  drawFooter(doc, pageCounter.n);
  doc.addPage();
  pageCounter.n++;
  drawHeader(doc, subtitle, dateRange);
  return BODY_T;
}

// ─── Summary Cards ────────────────────────────────────────────────────────────

function summaryCards(doc, stats, y) {
  const cardW = (CW - 18) / 4;
  const cardH = 76;

  const cards = [
    { label: "Total Events",    value: (stats.totalEvents    || 0).toLocaleString(), color: C.accent,   iconFn: iconShield },
    { label: "Blocked Threats", value: (stats.blocked        || 0).toLocaleString(), color: C.critical, iconFn: iconBlock  },
    { label: "Unique Attackers",value: (stats.uniqueAttackers|| 0).toLocaleString(), color: C.high,     iconFn: iconWarn   },
    { label: "Critical Alerts", value: (stats.criticalEvents || 0).toLocaleString(), color: C.medium,   iconFn: iconWarn   },
  ];

  cards.forEach((card, i) => {
    const cx = PAGE.margin + i * (cardW + 6);

    rect(doc, cx, y, cardW, cardH, C.surface, 8);
    strokeRect(doc, cx, y, cardW, cardH, C.elevated, 0.6, 8);

    // Top colored accent bar (per-corner radius)
    rect(doc, cx, y, cardW, 3, card.color, { tl: 8, tr: 8, bl: 0, br: 0 });

    // Icon background circle
    rect(doc, cx + 10, y + 12, 22, 22, card.color + "22", 11);
    card.iconFn(doc, cx + 15, y + 17, 12, card.color);

    txt(doc, card.value, cx + 10, y + 38, { font: F.bold, size: 20, color: card.color, width: cardW - 20 });
    txt(doc, card.label, cx + 10, y + 61, { size: 7.5, color: C.textSecond, width: cardW - 20 });
  });

  return y + cardH + 18;
}

// ─── Bar Chart ────────────────────────────────────────────────────────────────

function barChart(doc, data, x, y, w, h) {
  if (!data?.length) return y;
  const maxVal   = Math.max(...data.map(d => d.value), 1);
  const barAreaH = h - 30;
  const barW     = Math.min(Math.floor((w - 44) / data.length) - 5, 36);

  rect(doc, x, y, w, h, C.surface, 6);
  strokeRect(doc, x, y, w, h, C.elevated, 0.5, 6);

  // Grid lines
  for (let i = 0; i <= 4; i++) {
    const gy = y + 12 + (barAreaH * i) / 4;
    dashedLine(doc, x + 36, gy, x + w - 8, gy);
    txt(doc, Math.round(maxVal * (1 - i / 4)), x + 4, gy - 4, { size: 6, color: C.textDim, width: 28, align: "right" });
  }

  data.forEach((item, i) => {
    const bh    = maxVal > 0 ? ((item.value / maxVal) * (barAreaH - 10)) : 0;
    const bx    = x + 42 + i * (barW + 5);
    const by    = y + 12 + barAreaH - bh;
    const color = item.color ?? C.chart[i % C.chart.length];

    if (bh > 0) {
      // Glow base
      rect(doc, bx - 1, by + 1, barW + 2, bh + 2, color + "18", 3);
      // Bar
      doc.save().roundedRect(bx, by, barW, bh, 3).fill(color).restore();
      doc.save().rect(bx, by + 3, barW, Math.max(bh - 3, 0)).fill(color).restore();
    }

    if (item.value > 0) {
      txt(doc, item.value, bx, by - 11, { font: F.bold, size: 6.5, color: C.textPrimary, width: barW, align: "center" });
    }

    const lbl = item.label.length > 9 ? item.label.slice(0, 8) + "…" : item.label;
    txt(doc, lbl, bx - 3, y + h - 13, { size: 6, color: C.textSecond, width: barW + 6, align: "center" });
  });

  return y + h + 14;
}

// ─── Donut Chart ──────────────────────────────────────────────────────────────

function donutChart(doc, data, cx, cy, radius) {
  if (!data?.length) return;
  const total = data.reduce((s, d) => s + d.value, 0);
  if (!total) return;

  let angle = -Math.PI / 2;
  data.forEach((item, i) => {
    const sweep = (item.value / total) * 2 * Math.PI;
    const color = item.color ?? C.chart[i % C.chart.length];
    const steps = Math.max(14, Math.ceil(sweep * 14));
    doc.save().moveTo(cx, cy);
    for (let s = 0; s <= steps; s++) {
      const a = angle + (sweep * s) / steps;
      doc.lineTo(cx + Math.cos(a) * radius, cy + Math.sin(a) * radius);
    }
    doc.closePath().fill(color)
       .strokeColor(C.surface).lineWidth(1.5).stroke().restore();
    angle += sweep;
  });

  // Donut hole — match surface color
  doc.save().circle(cx, cy, radius * 0.54).fill(C.surface).restore();

  // Center text
  const top = data[0];
  const pct = Math.round((top.value / total) * 100);
  txt(doc, `${pct}%`, cx - 18, cy - 11, { font: F.bold, size: 13, color: C.textPrimary, width: 36, align: "center" });
  txt(doc, top.label, cx - 22, cy + 4, { size: 6.5, color: C.textSecond, width: 44, align: "center" });

  // Legend
  const lx = cx + radius + 18;
  let   ly = cy - (data.length * 15) / 2;
  data.forEach((item, i) => {
    const color = item.color ?? C.chart[i % C.chart.length];
    rect(doc, lx, ly + 3, 8, 8, color, 2);
    txt(doc, `${item.label} (${item.value})`, lx + 13, ly + 3, { size: 8, color: C.textPrimary });
    ly += 16;
  });
}

// ─── Horizontal Bars ──────────────────────────────────────────────────────────

function hBars(doc, data, x, y, w, maxRows = 8) {
  const rows     = data.slice(0, maxRows);
  const barH     = 17;
  const labelW   = 120;
  const barAreaW = w - labelW - 44;
  const maxVal   = Math.max(...rows.map(d => d.count || d.value || 0), 1);

  rows.forEach((item, i) => {
    const val   = item.count || item.value || 0;
    const bw    = (val / maxVal) * barAreaW;
    const by    = y + i * (barH + 6);
    const color = item.color ?? C.chart[i % C.chart.length];
    const label = String(item.ip || item.type || item.label || "Unknown").slice(0, 20);

    txt(doc, label, x, by + 4, { size: 7.5, color: C.textPrimary, width: labelW - 4 });

    // Track background
    rect(doc, x + labelW, by, barAreaW, barH, C.elevated, 4);
    // Fill
    if (bw > 0) {
      rect(doc, x + labelW, by, barAreaW, barH, color + "18", 4); // glow
      rect(doc, x + labelW, by, bw, barH, color, 4);
    }

    const numStr = String(val);
    if (bw > 28) txt(doc, numStr, x + labelW + 6, by + 4, { font: F.bold, size: 7, color: C.pageBg });
    else         txt(doc, numStr, x + labelW + barAreaW + 6, by + 4, { font: F.bold, size: 7, color: C.textPrimary });
  });

  return y + rows.length * (barH + 6) + 8;
}

// ─── Trend Line Chart ─────────────────────────────────────────────────────────

function trendLine(doc, data, x, y, w, h) {
  if (!data?.length || data.length < 2) return y;
  const maxVal = Math.max(...data.map(d => d.total || d.count || 0), 1);
  const stepX  = (w - 46) / (data.length - 1);
  const plotX  = x + 36;
  const plotY  = y + 14;
  const plotH  = h - 26;

  rect(doc, x, y, w, h, C.surface, 6);
  strokeRect(doc, x, y, w, h, C.elevated, 0.5, 6);

  for (let i = 0; i <= 3; i++) {
    const gy = plotY + (plotH * i) / 3;
    dashedLine(doc, plotX, gy, plotX + w - 46, gy);
    txt(doc, Math.round(maxVal * (1 - i / 3)), x + 2, gy - 4, { size: 5.5, color: C.textDim, width: 30, align: "right" });
  }

  const pts = data.map((d, i) => [
    plotX + i * stepX,
    plotY + plotH - ((d.total || d.count || 0) / maxVal) * plotH,
  ]);

  // Gradient fill
  const grad = doc.linearGradient(plotX, plotY, plotX, plotY + plotH);
  grad.stop(0, C.accent, 0.25).stop(1, C.accent, 0);
  doc.save().moveTo(pts[0][0], plotY + plotH);
  pts.forEach(([px, py]) => doc.lineTo(px, py));
  doc.lineTo(pts[pts.length - 1][0], plotY + plotH).closePath().fill(grad).restore();

  // Line
  doc.save().moveTo(pts[0][0], pts[0][1]);
  pts.slice(1).forEach(([px, py]) => doc.lineTo(px, py));
  doc.strokeColor(C.accent).lineWidth(2).stroke().restore();

  // Dots
  pts.forEach(([px, py]) => {
    doc.save().circle(px, py, 3.5).fill(C.surface).strokeColor(C.accent).lineWidth(1.5).stroke().restore();
  });

  // X-axis labels
  const step = Math.max(1, Math.floor(data.length / 7));
  data.forEach((d, i) => {
    if (i % step !== 0) return;
    const lbl = d.date ? String(d.date).slice(5) : `T${i + 1}`;
    txt(doc, lbl, plotX + i * stepX - 16, plotY + plotH + 6, { size: 6, color: C.textSecond, width: 32, align: "center" });
  });

  return y + h + 14;
}

// ─── Data Table ───────────────────────────────────────────────────────────────

const ROW_H  = 22;  // increased from 18 for better readability
const HEAD_H = 26;

/**
 * Severity pill badge — wide enough for full text, vivid on dark background
 */
function severityBadge(doc, val, x, y) {
  const color = sevColor(val);
  const bg    = sevBg(val);
  const label = val.toUpperCase();
  const bw    = 56;  // wide enough for "CRITICAL"
  const bh    = 14;

  rect(doc, x, y + (ROW_H - bh) / 2, bw, bh, bg, 3);
  strokeRect(doc, x, y + (ROW_H - bh) / 2, bw, bh, color + "55", 0.6, 3);
  txt(doc, label, x, y + (ROW_H - bh) / 2 + 3,
    { font: F.bold, size: 6.5, color, width: bw, align: "center" });
}

/**
 * Action pill badge — BLOCKED = red, ALLOWED = green
 */
function actionBadge(doc, val, x, y) {
  const isBlocked = val === "blocked";
  const color = isBlocked ? C.critical : C.low;
  const bg    = isBlocked ? C.criticalBg : C.lowBg;
  const label = val.toUpperCase();
  const bw    = 52;
  const bh    = 14;

  rect(doc, x, y + (ROW_H - bh) / 2, bw, bh, bg, 3);
  strokeRect(doc, x, y + (ROW_H - bh) / 2, bw, bh, color + "55", 0.6, 3);
  txt(doc, label, x, y + (ROW_H - bh) / 2 + 3,
    { font: F.bold, size: 6.5, color, width: bw, align: "center" });
}

function redrawTableHeader(doc, columns, y) {
  rect(doc, PAGE.margin, y, CW, HEAD_H, C.elevated, { tl: 6, tr: 6, bl: 0, br: 0 });
  // Accent underline on header
  rect(doc, PAGE.margin, y + HEAD_H - 2, CW, 2, C.accent + "60");
  let cx = PAGE.margin + 8;
  columns.forEach(col => {
    txt(doc, col.header, cx, y + 8, { font: F.bold, size: 7.5, color: C.textPrimary, width: col.width - 10 });
    cx += col.width;
  });
}

function dataTable(doc, rows, columns, y, pc) {
  const maxRows = 20;
  const display = rows.slice(0, maxRows);

  // Draw header
  redrawTableHeader(doc, columns, y);
  y += HEAD_H;

  display.forEach((row, i) => {
    // Page break
    if (y + ROW_H > BODY_B) {
      drawFooter(doc, pc.n);
      doc.addPage(); pc.n++;
      redrawTableHeader(doc, columns, BODY_T - HEAD_H - 2);
      y = BODY_T - 2;
    }

    // Row background
    const rowBg = i % 2 === 0 ? C.pageBg : C.surfaceAlt;
    rect(doc, PAGE.margin, y, CW, ROW_H, rowBg);

    let colX = PAGE.margin + 8;
    columns.forEach(col => {
      const raw = col.key.split(".").reduce((o, k) => o?.[k], row);
      const val = raw == null ? "—" : String(raw);

      if (col.key === "severity") {
        severityBadge(doc, val, colX, y);
      } else if (col.key === "action") {
        actionBadge(doc, val, colX, y);
      } else {
        // Country gets extra chars since it has more width now
        const maxChars = col.key === "country" ? 18 : 26;
        const disp = val.length > maxChars ? val.slice(0, maxChars - 1) + "…" : val;
        txt(doc, disp, colX, y + 7, { size: 7.5, color: C.textPrimary, width: col.width - 10 });
      }
      colX += col.width;
    });

    // Row separator
    line(doc, PAGE.margin, y + ROW_H, PAGE.margin + CW, y + ROW_H, C.elevated, 0.3);
    y += ROW_H;
  });

  // Table outer border
  strokeRect(doc, PAGE.margin, y - display.length * ROW_H - HEAD_H, CW, HEAD_H + display.length * ROW_H, C.elevated, 0.6, 6);

  if (rows.length > maxRows) {
    txt(doc, `+ ${rows.length - maxRows} more rows  —  download CSV for the full dataset`,
      PAGE.margin, y + 7, { size: 7.5, color: C.textSecond });
    y += 20;
  }

  return y + 10;
}

// ─── Block Rate Bar ───────────────────────────────────────────────────────────

function blockRateBar(doc, rate, y) {
  const pct = Math.min(Math.max(parseFloat(rate) || 0, 0), 100);
  rect(doc, PAGE.margin, y, CW, 38, C.surface, 6);
  strokeRect(doc, PAGE.margin, y, CW, 38, C.elevated, 0.5, 6);

  // Track
  rect(doc, PAGE.margin + 6, y + 6, CW - 12, 26, C.elevated, 4);
  // Fill
  if (pct > 0) {
    rect(doc, PAGE.margin + 6, y + 6, (CW - 12) * (pct / 100), 26, C.accent + "40", 4);
    // Bright leading edge
    rect(doc, PAGE.margin + 6 + (CW - 12) * (pct / 100) - 3, y + 6, 3, 26, C.accent, 2);
  }

  txt(doc, `Block Rate:  ${pct.toFixed(1)}%`, PAGE.margin + 14, y + 13,
    { font: F.bold, size: 11, color: C.accent });
  txt(doc, "Percentage of detected threats successfully mitigated",
    PAGE.margin + 160, y + 15, { size: 8.5, color: C.textSecond });
  return y + 52;
}

// ─── Recommendations ─────────────────────────────────────────────────────────

function drawRecommendations(doc, recs, y, pc, subtitle, dateRange) {
  const cardH = 56;
  recs.forEach(rec => {
    y = ensureSpace(doc, y, cardH + 10, { subtitle, dateRange, pageCounter: pc });
    const sc = sevColor(rec.severity);
    const bg = sevBg(rec.severity);

    rect(doc, PAGE.margin, y, CW, cardH, C.surface, 6);
    strokeRect(doc, PAGE.margin, y, CW, cardH, C.elevated, 0.5, 6);
    // Left severity stripe
    rect(doc, PAGE.margin, y, 4, cardH, sc, { tl: 6, tr: 0, bl: 6, br: 0 });

    // Severity badge
    const bw = 54, bh = 15;
    rect(doc, PAGE.margin + 12, y + 11, bw, bh, bg, 3);
    strokeRect(doc, PAGE.margin + 12, y + 11, bw, bh, sc + "55", 0.5, 3);
    txt(doc, rec.severity.toUpperCase(), PAGE.margin + 12, y + 14,
      { font: F.bold, size: 7, color: sc, width: bw, align: "center" });

    txt(doc, rec.title, PAGE.margin + 74, y + 11,
      { font: F.bold, size: 9, color: C.textPrimary, width: CW - 86 });
    txt(doc, rec.description, PAGE.margin + 12, y + 32,
      { size: 7.5, color: C.textSecond, width: CW - 24 });

    y += cardH + 10;
  });
  return y;
}

// ─── Scaffolding ──────────────────────────────────────────────────────────────

function initDoc(reportData, reportType) {
  const doc    = new PDFDocument({ size: "A4", margin: 0, bufferPages: true, autoFirstPage: true });
  const chunks = [];
  doc.on("data", c => chunks.push(c));

  const typeMap = {
    "daily security summary": "Daily Security Summary",
    "threat analysis report": "Threat Analysis Report",
    "ip intelligence report": "IP Intelligence Report",
    "security trends report": "Security Trends Report",
  };
  const subtitle = typeMap[String(reportData.reportType || "").toLowerCase()]
    || reportType || "WAF Security Report";
  const dr      = reportData.dateRange || {};
  const pc      = { n: 1 };
  const summary = {
    totalEvents:     reportData.summary?.totalEvents     || reportData.totalThreats || 0,
    blocked:         reportData.summary?.blocked         || 0,
    uniqueAttackers: reportData.summary?.uniqueAttackers || 0,
    criticalEvents:  reportData.summary?.criticalEvents  || reportData.criticalAlerts?.length || 0,
  };

  // Page background
  rect(doc, 0, 0, PAGE.width, PAGE.height, C.pageBg);
  drawHeader(doc, subtitle, dr);
  return { doc, chunks, subtitle, dr, pc, summary };
}

function finishDoc(doc, pc, subtitle, dr, summary, chunks) {
  const recs = buildRecommendations(summary);

  doc.addPage();
  pc.n++;
  rect(doc, 0, 0, PAGE.width, PAGE.height, C.pageBg);
  drawHeader(doc, subtitle, dr);
  let y = BODY_T;

  y = sectionTitle(doc, "Security Recommendations", y);
  y = drawRecommendations(doc, recs, y, pc, subtitle, dr);

  y = ensureSpace(doc, y + 10, 100, { subtitle, dateRange: dr, pageCounter: pc });
  y = sectionTitle(doc, "Report Metadata", y);

  const metaH = 78;
  rect(doc, PAGE.margin, y, CW, metaH, C.surface, 6);
  strokeRect(doc, PAGE.margin, y, CW, metaH, C.elevated, 0.5, 6);
  [
    ["Report Type",           subtitle],
    ["Generated At",          new Date().toLocaleString()],
    ["Date Range",            `${formatDate(dr.from)}  to  ${formatDate(dr.to)}`],
    ["Total Events Analyzed", summary.totalEvents.toLocaleString()],
  ].forEach(([label, value], i) => {
    const mx = i % 2 === 0 ? PAGE.margin + 14 : PAGE.margin + CW / 2 + 14;
    const my = y + Math.floor(i / 2) * 30 + 12;
    txt(doc, label + ":", mx, my, { font: F.bold, size: 8, color: C.textSecond });
    txt(doc, String(value), mx + 120, my, { size: 8, color: C.textPrimary, width: CW / 2 - 140 });
  });
  y += metaH + 20;

  y = ensureSpace(doc, y, 72, { subtitle, dateRange: dr, pageCounter: pc });
  y = sectionTitle(doc, "Detection Engine Details", y);
  rect(doc, PAGE.margin, y, CW, 60, C.surface, 6);
  strokeRect(doc, PAGE.margin, y, CW, 60, C.elevated, 0.5, 6);
  txt(doc,
    "SecureSOC WAF Analytics Engine v3.1.  Detection signatures cover SQL Injection, XSS, " +
    "Remote Code Execution, Path Traversal, CSRF, XXE, SSRF, NoSQL Injection, Open Redirect, " +
    "Prototype Pollution, HTTP Request Smuggling, JWT Tampering, and Recon/Scanner fingerprinting.",
    PAGE.margin + 14, y + 12, { size: 8, color: C.textSecond, width: CW - 28 }
  );

  drawFooter(doc, pc.n);
  doc.end();

  return new Promise((resolve, reject) => {
    doc.on("end",   () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);
  });
}

// ─── Events Table Helper ──────────────────────────────────────────────────────

function renderEventsTable(doc, events, y, pc, subtitle, dr, tableTitle = "Security Events Log") {
  if (!events?.length) return y;
  y = ensureSpace(doc, y, 80, { subtitle, dateRange: dr, pageCounter: pc });
  y = sectionTitle(doc, tableTitle, y);

  // Redistributed column widths — total = 523
  // Country increased to 65 (was 40), all others trimmed proportionally
  const columns = [
    { header: "Timestamp",   key: "timestamp",  width: 88 },
    { header: "Attack Type", key: "attackType", width: 78 },
    { header: "Source IP",   key: "sourceIP",   width: 80 },
    { header: "Target URL",  key: "targetURL",  width: 94 },
    { header: "Severity",    key: "severity",   width: 64 },
    { header: "Action",      key: "action",     width: 54 },
    { header: "Country",     key: "country",    width: 65 },
  ];

  return dataTable(doc, events.map(e => ({
    ...e,
    timestamp: e.timestamp ? new Date(e.timestamp).toLocaleString() : "—",
  })), columns, y, pc);
}

// ─── Report Renderers ─────────────────────────────────────────────────────────

function addPageBg(doc) {
  rect(doc, 0, 0, PAGE.width, PAGE.height, C.pageBg);
}

function renderDaily(doc, reportData, summary, subtitle, dr, pc) {
  let y = BODY_T;
  y = sectionTitle(doc, "Executive Summary", y);
  y = summaryCards(doc, summary, y);

  const attackDist = (reportData.topAttackTypes || [])
    .map((item, i) => ({ label: item.type || "Unknown", value: item.count || 0, color: C.chart[i % C.chart.length] }))
    .filter(d => d.value > 0);

  if (attackDist.length > 0) {
    y = ensureSpace(doc, y, 160, { subtitle, dateRange: dr, pageCounter: pc });
    y = sectionTitle(doc, "Attack Type Distribution", y);
    y = barChart(doc, attackDist, PAGE.margin, y, CW, 130);

    const halfW = (CW - 14) / 2;
    y = ensureSpace(doc, y, 185, { subtitle, dateRange: dr, pageCounter: pc });
    y = sectionTitle(doc, "Threat Breakdown", y);
    donutChart(doc, attackDist.slice(0, 6), PAGE.margin + Math.round(halfW * 0.38), y + 80, 56);
    txt(doc, "Top Categories", PAGE.margin + halfW + 14, y, { font: F.bold, size: 9, color: C.textPrimary });
    hBars(doc, attackDist, PAGE.margin + halfW + 14, y + 16, halfW, 6);
    y += 180;
  }

  drawFooter(doc, pc.n);
  doc.addPage(); pc.n++; addPageBg(doc); drawHeader(doc, subtitle, dr);
  y = renderEventsTable(doc, reportData.events, BODY_T, pc, subtitle, dr, "All Security Events");
  drawFooter(doc, pc.n);
}

function renderThreats(doc, reportData, summary, subtitle, dr, pc) {
  let y = BODY_T;
  y = sectionTitle(doc, "Executive Summary", y);
  y = summaryCards(doc, summary, y);

  const patterns = (reportData.attackPatterns || [])
    .map((p, i) => ({ label: p.type || "Unknown", value: p.count || 0, blocked: p.blocked || 0, color: C.chart[i % C.chart.length] }))
    .filter(d => d.value > 0);

  if (patterns.length > 0) {
    y = ensureSpace(doc, y, 155, { subtitle, dateRange: dr, pageCounter: pc });
    y = sectionTitle(doc, "Attack Pattern Analysis", y);
    y = barChart(doc, patterns, PAGE.margin, y, CW, 130);

    y = ensureSpace(doc, y, 40 + patterns.length * 24, { subtitle, dateRange: dr, pageCounter: pc });
    y = sectionTitle(doc, "Block Rate by Attack Type", y);
    y = hBars(doc, patterns.map((p, i) => ({
      label: p.label,
      count: p.value > 0 ? Math.round((p.blocked / p.value) * 100) : 0,
      color: C.chart[i % C.chart.length],
    })), PAGE.margin, y, CW, 8);
    txt(doc, "Values show % of requests blocked per attack type", PAGE.margin, y,
      { size: 7.5, color: C.textSecond });
    y += 16;
  }

  const topThreats = (reportData.topThreats || []).slice(0, 10);
  if (topThreats.length > 0) {
    y = ensureSpace(doc, y, 40 + topThreats.length * 24, { subtitle, dateRange: dr, pageCounter: pc });
    y = sectionTitle(doc, "Top Attacking IPs", y);
    y = hBars(doc, topThreats.map((t, i) => ({
      label: `${t.ip || "?"} (${t.country || "?"})`, count: t.count || 0, color: C.chart[i % C.chart.length],
    })), PAGE.margin, y, CW, 10);
  }

  drawFooter(doc, pc.n);
  doc.addPage(); pc.n++; addPageBg(doc); drawHeader(doc, subtitle, dr);
  const criticals = reportData.criticalAlerts || reportData.events?.filter(e => e.severity === "critical") || [];
  y = renderEventsTable(doc, criticals, BODY_T, pc, subtitle, dr, "Critical Alerts");
  if (criticals.length === 0) y = renderEventsTable(doc, reportData.events, y, pc, subtitle, dr, "All Events");
  drawFooter(doc, pc.n);
}

function renderIPs(doc, reportData, summary, subtitle, dr, pc) {
  let y = BODY_T;
  const cardW = (CW - 18) / 4;
  const cardH = 76;

  [
    { label: "Unique IPs",      value: (reportData.totalUniqueIPs || 0).toLocaleString(), color: C.accent,   iconFn: iconShield },
    { label: "Total Requests",  value: (summary.totalEvents       || 0).toLocaleString(), color: C.high,     iconFn: iconWarn   },
    { label: "Blocked IPs",     value: (summary.blocked           || 0).toLocaleString(), color: C.critical, iconFn: iconBlock  },
    { label: "Critical Events", value: (summary.criticalEvents    || 0).toLocaleString(), color: C.medium,   iconFn: iconWarn   },
  ].forEach((card, i) => {
    const cx = PAGE.margin + i * (cardW + 6);
    rect(doc, cx, y, cardW, cardH, C.surface, 8);
    strokeRect(doc, cx, y, cardW, cardH, C.elevated, 0.6, 8);
    rect(doc, cx, y, cardW, 3, card.color, { tl: 8, tr: 8, bl: 0, br: 0 });
    rect(doc, cx + 10, y + 12, 22, 22, card.color + "22", 11);
    card.iconFn(doc, cx + 15, y + 17, 12, card.color);
    txt(doc, card.value, cx + 10, y + 38, { font: F.bold, size: 20, color: card.color, width: cardW - 20 });
    txt(doc, card.label, cx + 10, y + 61, { size: 7.5, color: C.textSecond, width: cardW - 20 });
  });
  y += cardH + 18;

  const profiles = (reportData.profiles || []).slice(0, 12);
  if (profiles.length > 0) {
    y = ensureSpace(doc, y, 40 + profiles.length * 24, { subtitle, dateRange: dr, pageCounter: pc });
    y = sectionTitle(doc, "Top Attacking IPs by Volume", y);
    y = hBars(doc, profiles.map((p, i) => ({
      label: `${p.ip} (${p.country || "?"})`, count: p.totalRequests || 0, color: C.chart[i % C.chart.length],
    })), PAGE.margin, y, CW, 12);
  }

  const attackDist = (reportData.attackPatterns || []).filter(d => d.count > 0)
    .map((p, i) => ({ label: p.type || "Unknown", value: p.count || 0, color: C.chart[i % C.chart.length] }));
  if (attackDist.length > 0) {
    y = ensureSpace(doc, y, 155, { subtitle, dateRange: dr, pageCounter: pc });
    y = sectionTitle(doc, "Attack Types Observed", y);
    y = barChart(doc, attackDist, PAGE.margin, y, CW, 120);
  }

  drawFooter(doc, pc.n);
  doc.addPage(); pc.n++; addPageBg(doc); drawHeader(doc, subtitle, dr);
  y = BODY_T;

  if (profiles.length > 0) {
    y = sectionTitle(doc, "IP Profile Details", y);
    y = dataTable(doc, profiles.map(p => ({
      ...p,
      attackTypeStr: (p.attackTypes || []).slice(0, 3).join(", "),
      lastSeenStr:   p.lastSeen ? new Date(p.lastSeen).toLocaleDateString() : "—",
    })), [
      { header: "Source IP",    key: "ip",            width: 90  },
      { header: "Country",      key: "country",       width: 80  },
      { header: "Total Reqs",   key: "totalRequests", width: 60  },
      { header: "Blocked",      key: "blocked",       width: 52  },
      { header: "Risk Score",   key: "riskScore",     width: 55  },
      { header: "Attack Types", key: "attackTypeStr", width: 106 },
      { header: "Last Seen",    key: "lastSeenStr",   width: 80  },
    ], y, pc);
  }
  drawFooter(doc, pc.n);
}

function renderTrends(doc, reportData, summary, subtitle, dr, pc) {
  let y = BODY_T;
  y = sectionTitle(doc, "Executive Summary", y);
  y = summaryCards(doc, summary, y);

  if (reportData.overallBlockRate !== undefined) y = blockRateBar(doc, reportData.overallBlockRate, y);

  const trend = reportData.dailyTrend || [];
  if (trend.length > 1) {
    y = ensureSpace(doc, y, 150, { subtitle, dateRange: dr, pageCounter: pc });
    y = sectionTitle(doc, "Daily Event Volume", y);
    y = trendLine(doc, trend, PAGE.margin, y, CW, 130);

    const blockedTrend = trend.map(d => ({ ...d, total: d.blocked || 0 }));
    if (blockedTrend.some(d => d.total > 0)) {
      y = ensureSpace(doc, y, 150, { subtitle, dateRange: dr, pageCounter: pc });
      y = sectionTitle(doc, "Daily Blocked Threats", y);
      y = trendLine(doc, blockedTrend, PAGE.margin, y, CW, 120);
    }
  }

  const evolution = (reportData.attackEvolution || [])
    .filter(d => (d.total || d.count || 0) > 0)
    .map((item, i) => ({ label: item.type || "Unknown", value: item.total || item.count || 0, color: C.chart[i % C.chart.length] }));
  if (evolution.length > 0) {
    y = ensureSpace(doc, y, 155, { subtitle, dateRange: dr, pageCounter: pc });
    y = sectionTitle(doc, "Attack Type Evolution", y);
    const halfW = (CW - 14) / 2;
    barChart(doc, evolution, PAGE.margin, y, halfW, 120);
    donutChart(doc, evolution.slice(0, 6), PAGE.margin + halfW + 14 + Math.round(halfW * 0.38), y + 72, 52);
    y += 130;
  }

  if (trend.length > 0) {
    const sorted = [...trend].sort((a, b) => (b.total || 0) - (a.total || 0)).slice(0, 7);
    y = ensureSpace(doc, y, 60 + sorted.length * 24, { subtitle, dateRange: dr, pageCounter: pc });
    y = sectionTitle(doc, "Highest Activity Days", y);
    y = dataTable(doc, sorted.map(d => ({
      date:         String(d.date || "").slice(0, 10),
      total:        d.total    || 0,
      blocked:      d.blocked  || 0,
      critical:     d.critical || 0,
      allowRateStr: d.total > 0 ? `${(((d.total - (d.blocked || 0)) / d.total) * 100).toFixed(1)}%` : "0%",
    })), [
      { header: "Date",         key: "date",        width: 105 },
      { header: "Total Events", key: "total",       width: 105 },
      { header: "Blocked",      key: "blocked",     width: 105 },
      { header: "Critical",     key: "critical",    width: 105 },
      { header: "Allow Rate",   key: "allowRateStr",width: 103 },
    ], y, pc);
  }
  drawFooter(doc, pc.n);
}

// ─── Entry Point ──────────────────────────────────────────────────────────────

async function generatePDFReport(reportData, reportType) {
  const type = (reportType || reportData.reportType || "daily").toLowerCase()
    .replace("daily security summary",  "daily")
    .replace("threat analysis report",  "threats")
    .replace("ip intelligence report",  "ips")
    .replace("security trends report",  "trends");

  const { doc, chunks, subtitle, dr, pc, summary } = initDoc(reportData, reportType);

  switch (type) {
    case "threats": renderThreats(doc, reportData, summary, subtitle, dr, pc); break;
    case "ips":     renderIPs    (doc, reportData, summary, subtitle, dr, pc); break;
    case "trends":  renderTrends (doc, reportData, summary, subtitle, dr, pc); break;
    default:        renderDaily  (doc, reportData, summary, subtitle, dr, pc); break;
  }

  return finishDoc(doc, pc, subtitle, dr, summary, chunks);
}

// ─── Recommendations ─────────────────────────────────────────────────────────

function buildRecommendations(summary) {
  const recs = [];
  if (summary.criticalEvents > 0) {
    recs.push({ severity: "critical", title: "Immediate Action Required: Critical Events Detected",
      description: `${summary.criticalEvents} critical event${summary.criticalEvents > 1 ? "s were" : " was"} logged. Review SQLi/RCE payloads and harden input validation. Enable automatic IP blocking for critical sources.` });
  }
  const blockRate = summary.totalEvents > 0 ? (summary.blocked / summary.totalEvents) * 100 : 0;
  if (blockRate < 70 && summary.totalEvents > 0) {
    recs.push({ severity: "high", title: "Improve Threat Block Rate",
      description: `Current block rate is ${blockRate.toFixed(1)}%. Review rules set to log-only and switch high-confidence signatures to block mode.` });
  }
  if (summary.uniqueAttackers > 20) {
    recs.push({ severity: "medium", title: "Distributed Attack Pattern Detected",
      description: `${summary.uniqueAttackers} unique source IPs detected. This suggests botnet activity. Consider geo-blocking and rate-limiting on sensitive endpoints.` });
  }
  recs.push({ severity: "low", title: "Review Detection Thresholds",
    description: "Ensure thresholds are tuned for your traffic volume. High thresholds allow low-and-slow probes through before triggering a block." });
  recs.push({ severity: "info", title: "Scheduled Rule Update Recommended",
    description: "Review signatures monthly for new CVEs. Integrate OWASP CRS updates and Emerging Threats rulesets." });
  return recs.slice(0, 5);
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatDate(d) {
  if (!d) return "N/A";
  try { return new Date(d).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" }); }
  catch { return String(d); }
}

module.exports = { generatePDFReport };
