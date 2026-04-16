#!/usr/bin/env python3
"""
SecureSOC WAF — Performance Statistics Evaluator
=================================================
Connects to the PostgreSQL database populated by the WAF simulator,
computes all 28 research-paper metrics, and prints a formatted report.

Ground-truth labelling convention (simulator-aware):
  Positive  = the request was an actual attack  (attack_type NOT IN ('None'))
  Negative  = the request was legitimate traffic (attack_type = 'None')

  TP  = attack  + blocked    (detected correctly)
  FN  = attack  + allowed    (evaded detection — e.g. below threshold)
  FP  = legit   + blocked    (false alarm)
  TN  = legit   + allowed    (correctly passed)

Usage:
  pip install psycopg2-binary tabulate
  python waf_stats_evaluator.py [--host HOST] [--port PORT] [--db DB]
                                [--user USER] [--password PASSWORD]
                                [--hours HOURS]

All arguments are optional; defaults match the project's .env file.
"""

import argparse
import sys
from datetime import datetime, timedelta, timezone
from collections import defaultdict

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    sys.exit("❌  psycopg2-binary not found. Run: pip install psycopg2-binary")

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False  # fall back to plain text

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak,
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False


# ─── CLI arguments ────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description="SecureSOC WAF Statistics Evaluator")
    p.add_argument("--host",     default="localhost")
    p.add_argument("--port",     type=int, default=5432)
    p.add_argument("--db",       default="waf_dashboard")
    p.add_argument("--user",     default="postgres")
    p.add_argument("--password", default="root")
    p.add_argument(
        "--hours",
        type=float,
        default=24,
        help="Evaluation window in hours (default: 24)",
    )
    p.add_argument(
        "--pdf",
        metavar="PATH",
        default=None,
        help="Generate a PDF report at the given path (e.g. waf_report.pdf). Requires: pip install reportlab",
    )
    return p.parse_args()


# ─── Database helpers ─────────────────────────────────────────────────────────

def connect(args):
    return psycopg2.connect(
        host=args.host, port=args.port,
        dbname=args.db, user=args.user, password=args.password,
    )


def fetch_alerts(conn, since: datetime):
    """Return all alert rows in the evaluation window."""
    sql = """
        SELECT
            id,
            timestamp,
            attack_type,
            source_ip,
            target_url,
            severity,
            action,
            country,
            country_code,
            user_agent
        FROM waf_alerts
        WHERE timestamp >= %s
        ORDER BY timestamp ASC
    """
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, (since,))
        return cur.fetchall()


# ─── Classification helpers ───────────────────────────────────────────────────

ATTACK_TYPES = {"SQLi", "XSS", "Brute Force", "Path Traversal", "RCE", "DDoS",
                "CSRF", "XXE", "SSRF", "Open Redirect", "NoSQLi",
                "Prototype Pollution", "HTTP Smuggling", "Auth", "Recon", "Other"}

NORMAL_LABELS = {"None", "none", "", None}

# Known attack-tool patterns in user-agent strings
TOOL_PATTERNS = [
    "sqlmap", "nikto", "masscan", "nmap", "dirbuster", "gobuster",
    "hydra", "metasploit", "acunetix", "burpsuite", "zgrab",
    "python-requests", "go-http-client", "curl/", "wget/",
    "scrapy",
]


def is_attack(row) -> bool:
    at = (row["attack_type"] or "").strip()
    return at not in NORMAL_LABELS and at != ""


def is_blocked(row) -> bool:
    return (row["action"] or "").lower() == "blocked"


def classify(row):
    """Return (is_positive_ground_truth, is_positive_prediction)."""
    return is_attack(row), is_blocked(row)


def is_tool_agent(ua: str) -> bool:
    if not ua:
        return False
    ua_lower = ua.lower()
    return any(tool in ua_lower for tool in TOOL_PATTERNS)


# ─── Statistics computation ───────────────────────────────────────────────────

def compute_stats(rows, window_hours: float) -> dict:
    if not rows:
        return {}

    # ── Confusion matrix ───────────────────────────────────────────────────
    TP = FP = FN = TN = 0
    fn_by_type = defaultdict(int)

    for row in rows:
        actual_pos, pred_pos = classify(row)
        if actual_pos and pred_pos:
            TP += 1
        elif actual_pos and not pred_pos:
            FN += 1
            fn_by_type[row["attack_type"]] += 1
        elif not actual_pos and pred_pos:
            FP += 1
        else:
            TN += 1

    total      = len(rows)
    n_attack   = TP + FN         # ground-truth positives
    n_normal   = FP + TN         # ground-truth negatives
    n_blocked  = TP + FP         # model predicted positive

    # ── Core metrics ──────────────────────────────────────────────────────
    recall    = TP / n_attack if n_attack > 0 else 0.0        # TPR / Sensitivity
    precision = TP / n_blocked if n_blocked > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)
    fpr       = FP / n_normal if n_normal > 0 else 0.0        # False Positive Rate
    accuracy  = (TP + TN) / total if total > 0 else 0.0
    block_rate = n_blocked / total if total > 0 else 0.0

    # ── Throughput ─────────────────────────────────────────────────────────
    timestamps = [row["timestamp"] for row in rows]
    t_min = min(timestamps)
    t_max = max(timestamps)
    elapsed_minutes = max((t_max - t_min).total_seconds() / 60, 1)
    throughput_rpm  = total / elapsed_minutes
    elapsed_hours   = elapsed_minutes / 60

    # ── Per-category block rates ───────────────────────────────────────────
    cat_total   = defaultdict(int)
    cat_blocked = defaultdict(int)

    for row in rows:
        if is_attack(row):
            cat = row["attack_type"]
            cat_total[cat] += 1
            if is_blocked(row):
                cat_blocked[cat] += 1

    per_cat = {}
    for cat, cnt in cat_total.items():
        blocked_cnt = cat_blocked.get(cat, 0)
        per_cat[cat] = {
            "total":      cnt,
            "blocked":    blocked_cnt,
            "allowed":    cnt - blocked_cnt,
            "block_rate": blocked_cnt / cnt if cnt > 0 else 0.0,
        }

    # ── Geographic stats ───────────────────────────────────────────────────
    country_counts = defaultdict(int)
    unique_ips     = set()
    for row in rows:
        unique_ips.add(row["source_ip"])
        if row["country"]:
            country_counts[row["country"]] += 1

    top_country     = max(country_counts, key=country_counts.get) if country_counts else "N/A"
    top_country_cnt = country_counts.get(top_country, 0)
    top_country_pct = top_country_cnt / total * 100 if total > 0 else 0.0

    # ── User-agent / tool fingerprinting ──────────────────────────────────
    tool_count   = sum(1 for r in rows if is_tool_agent(r.get("user_agent", "")))
    normal_agent = sum(1 for r in rows if not is_tool_agent(r.get("user_agent", "")))

    tool_pct          = tool_count   / total * 100 if total > 0 else 0.0
    normal_agent_pct  = normal_agent / total * 100 if total > 0 else 0.0

    tool_name_counts = defaultdict(int)
    for row in rows:
        ua = (row.get("user_agent") or "").lower()
        for tool in TOOL_PATTERNS:
            if tool in ua:
                tool_name_counts[tool] += 1
                break

    top_tool = max(tool_name_counts, key=tool_name_counts.get) if tool_name_counts else "N/A"

    # ── Severity distribution ─────────────────────────────────────────────
    sev_counts = defaultdict(int)
    for row in rows:
        sev_counts[(row.get("severity") or "info").lower()] += 1

    critical_pct   = sev_counts["critical"] / total * 100 if total > 0 else 0.0
    most_common_sev = max(sev_counts, key=sev_counts.get) if sev_counts else "N/A"

    # ── Attack type distribution (labelled attacks only) ──────────────────
    attack_type_counts = defaultdict(int)
    for row in rows:
        if is_attack(row):
            attack_type_counts[row["attack_type"]] += 1

    most_freq_attack  = max(attack_type_counts, key=attack_type_counts.get, default="N/A")
    least_freq_attack = min(attack_type_counts, key=attack_type_counts.get, default="N/A")

    # ── Hourly traffic ─────────────────────────────────────────────────────
    hourly_total    = defaultdict(int)
    hourly_detected = defaultdict(int)   # blocked OR attack that was correctly blocked

    for row in rows:
        hour = row["timestamp"].replace(minute=0, second=0, microsecond=0)
        # Normalise to naive UTC for consistent keys
        if hour.tzinfo is not None:
            hour = hour.astimezone(timezone.utc).replace(tzinfo=None)
        hourly_total[hour] += 1
        if is_attack(row) and is_blocked(row):
            hourly_detected[hour] += 1

    hourly_detect_rate = {}
    for h, cnt in hourly_total.items():
        det = hourly_detected.get(h, 0)
        hourly_detect_rate[h] = (det, cnt, det / cnt if cnt > 0 else 0.0)

    busiest_hour = max(hourly_total, key=hourly_total.get) if hourly_total else None
    busiest_hour_detect_rate = (
        hourly_detect_rate[busiest_hour][2] if busiest_hour else 0.0
    )

    perfect_hours = [
        (h, data[1])
        for h, data in hourly_detect_rate.items()
        if data[2] == 1.0 and data[0] > 0
    ]

    return {
        # Confusion matrix
        "TP": TP, "FP": FP, "FN": FN, "TN": TN,
        "total": total,
        "n_attack": n_attack,
        "n_normal": n_normal,
        "fn_by_type": dict(fn_by_type),
        # Core metrics
        "recall":     recall,
        "precision":  precision,
        "f1":         f1,
        "fpr":        fpr,
        "accuracy":   accuracy,
        "block_rate": block_rate,
        "throughput_rpm": throughput_rpm,
        # Time
        "t_min": t_min, "t_max": t_max,
        "elapsed_minutes": elapsed_minutes,
        "elapsed_hours": elapsed_hours,
        # Per-category
        "per_cat": per_cat,
        # Geo
        "unique_ips":       len(unique_ips),
        "n_countries":      len(country_counts),
        "top_country":      top_country,
        "top_country_pct":  top_country_pct,
        "top_country_cnt":  top_country_cnt,
        # Tools
        "tool_pct":          tool_pct,
        "top_tool":          top_tool,
        "normal_agent_pct":  normal_agent_pct,
        # Severity
        "sev_counts":      dict(sev_counts),
        "critical_pct":    critical_pct,
        "most_common_sev": most_common_sev,
        # Attack types
        "attack_type_counts": dict(attack_type_counts),
        "most_freq_attack":   most_freq_attack,
        "least_freq_attack":  least_freq_attack,
        # Hourly
        "hourly_total":           dict(hourly_total),
        "hourly_detect_rate":     hourly_detect_rate,
        "busiest_hour":           busiest_hour,
        "busiest_hour_req":       hourly_total.get(busiest_hour, 0) if busiest_hour else 0,
        "busiest_hour_det_rate":  busiest_hour_detect_rate,
        "perfect_hours":          perfect_hours,
    }


# ─── Report printer ───────────────────────────────────────────────────────────

SEPARATOR = "─" * 72

def pct(v, decimals=2):
    return f"{v * 100:.{decimals}f}%"

def fmt_float(v, decimals=4):
    return f"{v:.{decimals}f}"


def print_report(s: dict, window_hours: float):
    print()
    print("=" * 72)
    print("  SecureSOC WAF — Performance Evaluation Report")
    print(f"  Evaluation window : {s['t_min'].strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"                    → {s['t_max'].strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  Window duration   : {s['elapsed_hours']:.2f} h  "
          f"({s['elapsed_minutes']:.1f} min)")
    print("=" * 72)

    # ── 1. Confusion Matrix ────────────────────────────────────────────────
    print(f"\n{'CONFUSION MATRIX':^72}")
    print(SEPARATOR)
    cm_rows = [
        ["",             "Predicted BLOCK", "Predicted ALLOW", "Row Total"],
        ["Actual ATTACK", f"TP = {s['TP']:,}",   f"FN = {s['FN']:,}",   f"{s['n_attack']:,}"],
        ["Actual NORMAL", f"FP = {s['FP']:,}",   f"TN = {s['TN']:,}",   f"{s['n_normal']:,}"],
        ["Col Total",     f"{s['TP']+s['FP']:,}", f"{s['FN']+s['TN']:,}", f"{s['total']:,}"],
    ]
    if HAS_TABULATE:
        print(tabulate(cm_rows, tablefmt="grid"))
    else:
        for row in cm_rows:
            print("  " + " | ".join(f"{c:<18}" for c in row))
    print()

    # ── 2. Core Performance Metrics ───────────────────────────────────────
    print(f"\n{'CORE PERFORMANCE METRICS':^72}")
    print(SEPARATOR)
    metrics = [
        (" Q1  Recall (True Positive Rate / Sensitivity)", pct(s['recall'])),
        (" Q2  Precision",                                  pct(s['precision'])),
        (" Q3  F1-Score",                                   fmt_float(s['f1'])),
        (" Q4  False Positive Rate (FPR / Fall-out)",       pct(s['fpr'])),
        (" Q5  Overall Accuracy",                           pct(s['accuracy'])),
        (" Q6  Block Rate (fraction of all requests)",      pct(s['block_rate'])),
        (" Q7  Average Throughput",                         f"{s['throughput_rpm']:.1f} req/min"),
    ]
    for label, value in metrics:
        print(f"  {label:<50}  {value}")

    # ── 3. Confusion Matrix Detail ────────────────────────────────────────
    print(f"\n{'CONFUSION MATRIX DETAIL':^72}")
    print(SEPARATOR)
    print(f"  Q8   True Positives  (TP)  : {s['TP']:>8,}   (attacks correctly blocked)")
    print(f"  Q9   False Positives (FP)  : {s['FP']:>8,}   (legit traffic blocked — false alarms)")
    print(f"  Q10  False Negatives (FN)  : {s['FN']:>8,}   (attacks that evaded detection)")
    print(f"  Q11  True Negatives  (TN)  : {s['TN']:>8,}   (legit traffic correctly allowed)")
    print(f"  Q12  Total Requests        : {s['total']:>8,}")
    if s['fn_by_type']:
        print(f"\n  FN breakdown by attack category (threshold not yet met):")
        for atype, cnt in sorted(s['fn_by_type'].items(), key=lambda x: -x[1]):
            print(f"    • {atype:<25} {cnt:>5,} undetected requests")

    # ── 4. Per-Category Block Rates ───────────────────────────────────────
    print(f"\n{'PER-CATEGORY BLOCK RATES':^72}")
    print(SEPARATOR)
    cat_rows = []
    for cat, d in sorted(s['per_cat'].items(), key=lambda x: -x[1]['block_rate']):
        br = pct(d['block_rate'])
        miss_note = ""
        if d['block_rate'] < 1.0:
            miss_note = f"  ← {d['allowed']:,} allowed (threshold not met)"
        cat_rows.append([cat, d['total'], d['blocked'], d['allowed'], br, miss_note])

    if HAS_TABULATE:
        print(tabulate(
            cat_rows,
            headers=["Attack Type", "Total", "Blocked", "Allowed", "Block Rate", "Note"],
            tablefmt="simple",
        ))
    else:
        print(f"  {'Attack Type':<22} {'Total':>7} {'Blocked':>8} {'Allowed':>8} {'Block%':>9}")
        for r in cat_rows:
            print(f"  {r[0]:<22} {r[1]:>7,} {r[2]:>8,} {r[3]:>8,} {r[4]:>9}{r[5]}")

    perfect = [c for c, d in s['per_cat'].items() if d['block_rate'] == 1.0]
    print(f"\n  Q13  Perfect block-rate categories  : {', '.join(perfect) if perfect else 'None'}")

    xss = s['per_cat'].get('XSS', {})
    print(f"\n  Q14  XSS block rate   : {pct(xss.get('block_rate', 0))}"
          + (f"  ({xss.get('allowed',0):,} misses — below threshold before block)" if xss.get('allowed', 0) else ""))

    bf = s['per_cat'].get('Brute Force', {})
    print(f"  Q15  Brute Force block rate : {pct(bf.get('block_rate', 0))}"
          + (f"  ({bf.get('allowed',0):,} misses — WAF threshold = 5; hits 1-4 pass through)" if bf.get('allowed', 0) else ""))

    # ── 5. Dataset & Geographic Stats ─────────────────────────────────────
    print(f"\n{'DATASET & GEOGRAPHIC STATISTICS':^72}")
    print(SEPARATOR)
    h  = int(s['elapsed_hours'])
    m  = int((s['elapsed_hours'] - h) * 60)
    print(f"  Q16  Evaluation window        : {h}h {m}m  ({s['elapsed_minutes']:.0f} min total)")
    print(f"  Q17  Unique source IPs         : {s['unique_ips']:,}")
    print(f"  Q18  Countries of origin       : {s['n_countries']}")
    print(f"  Q19  Top source country        : {s['top_country']}"
          f"  ({s['top_country_cnt']:,} requests, {s['top_country_pct']:.1f}% of total)")

    # ── 6. Attack-Tool Fingerprinting ─────────────────────────────────────
    print(f"\n{'ATTACK-TOOL FINGERPRINTING':^72}")
    print(SEPARATOR)
    print(f"  Q20  Traffic from known attack tools  : {s['tool_pct']:.1f}%")
    print(f"  Q21  Most frequent attack tool        : {s['top_tool']}")
    print(f"  Q22  Browser-like / unidentified UA   : {s['normal_agent_pct']:.1f}%")

    # ── 7. Severity Distribution ──────────────────────────────────────────
    print(f"\n{'SEVERITY DISTRIBUTION':^72}")
    print(SEPARATOR)
    for sev in ["critical", "high", "medium", "low", "info"]:
        cnt = s['sev_counts'].get(sev, 0)
        bar = "█" * int(cnt / max(s['sev_counts'].values(), default=1) * 30)
        print(f"  {sev:<10}  {cnt:>7,}  ({cnt/s['total']*100:5.1f}%)  {bar}")
    print(f"\n  Q23  Critical severity requests : {s['critical_pct']:.1f}%")
    print(f"  Q24  Most common severity level : {s['most_common_sev']}")

    # ── 8. Attack Type Distribution ───────────────────────────────────────
    print(f"\n{'ATTACK TYPE DISTRIBUTION (labelled attacks only)':^72}")
    print(SEPARATOR)
    for atype, cnt in sorted(s['attack_type_counts'].items(), key=lambda x: -x[1]):
        bar = "█" * int(cnt / max(s['attack_type_counts'].values(), default=1) * 30)
        print(f"  {atype:<22}  {cnt:>7,}  {bar}")
    print(f"\n  Q25  Most  frequent attack type : {s['most_freq_attack']}")
    print(f"  Q26  Least frequent attack type : {s['least_freq_attack']}")

    # ── 9. Hourly Traffic ─────────────────────────────────────────────────
    print(f"\n{'HOURLY TRAFFIC ANALYSIS':^72}")
    print(SEPARATOR)
    if HAS_TABULATE:
        hour_rows = []
        for h_ts in sorted(s['hourly_total'].keys()):
            cnt = s['hourly_total'][h_ts]
            det, _, dr = s['hourly_detect_rate'].get(h_ts, (0, cnt, 0.0))
            hour_rows.append([
                h_ts.strftime("%Y-%m-%d %H:%M"),
                cnt, det, pct(dr),
                "★ 100%" if dr == 1.0 and det > 0 else ""
            ])
        print(tabulate(
            hour_rows,
            headers=["Hour (UTC)", "Requests", "Detected", "Detect Rate", ""],
            tablefmt="simple",
        ))
    else:
        print(f"  {'Hour (UTC)':<18} {'Requests':>10} {'Detected':>10} {'Detect %':>10}")
        for h_ts in sorted(s['hourly_total'].keys()):
            cnt = s['hourly_total'][h_ts]
            det, _, dr = s['hourly_detect_rate'].get(h_ts, (0, cnt, 0.0))
            flag = " ★" if dr == 1.0 and det > 0 else ""
            print(f"  {h_ts.strftime('%Y-%m-%d %H:%M'):<18} {cnt:>10,} {det:>10,} {pct(dr):>10}{flag}")

    if s['busiest_hour']:
        print(f"\n  Q27  Busiest hour          : {s['busiest_hour'].strftime('%Y-%m-%d %H:00 UTC')}"
              f"  ({s['busiest_hour_req']:,} requests, {pct(s['busiest_hour_det_rate'])} detection rate)")
    if s['perfect_hours']:
        ph = s['perfect_hours'][0]
        print(f"  Q28  First 100% detect hour: {ph[0].strftime('%Y-%m-%d %H:00 UTC')}"
              f"  ({ph[1]:,} requests)")
    else:
        print("  Q28  No hour achieved 100% detection rate in this window.")

    print()
    print("=" * 72)
    print("  END OF REPORT")
    print("=" * 72)
    print()


# ─── PDF Report Generator ─────────────────────────────────────────────────────

def generate_pdf_report(s: dict, window_hours: float, output_path: str = "waf_report.pdf"):
    """Generate a formatted PDF report from the computed WAF statistics."""
    if not HAS_REPORTLAB:
        print("⚠️  reportlab not installed — skipping PDF. Run: pip install reportlab")
        return

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm,  bottomMargin=2 * cm,
    )

    # ── Colour palette ─────────────────────────────────────────────────────
    DARK_BLUE  = colors.HexColor("#1A2B4A")
    MED_BLUE   = colors.HexColor("#2E5FA3")
    LIGHT_BLUE = colors.HexColor("#D6E4F7")
    RED        = colors.HexColor("#C0392B")
    GREEN      = colors.HexColor("#1E8449")
    GREY_BG    = colors.HexColor("#F4F6F8")
    GREY_LINE  = colors.HexColor("#BDC3C7")

    styles = getSampleStyleSheet()

    def S(name, **kw):
        """Quick style factory."""
        return ParagraphStyle(name, parent=styles["Normal"], **kw)

    title_style   = S("ReportTitle",  fontSize=20, leading=26,
                      textColor=DARK_BLUE, alignment=TA_CENTER, fontName="Helvetica-Bold")
    subtitle_style= S("Subtitle",     fontSize=10, leading=14,
                      textColor=MED_BLUE,  alignment=TA_CENTER)
    section_style = S("SectionHead",  fontSize=13, leading=17,
                      textColor=DARK_BLUE, fontName="Helvetica-Bold", spaceAfter=4)
    label_style   = S("Label",        fontSize=9,  leading=13, textColor=colors.black)
    value_style   = S("Value",        fontSize=9,  leading=13,
                      textColor=MED_BLUE, fontName="Helvetica-Bold")
    note_style    = S("Note",         fontSize=8,  leading=11, textColor=colors.grey)
    table_hdr     = S("TblHdr",       fontSize=8,  leading=11,
                      textColor=colors.white, fontName="Helvetica-Bold", alignment=TA_CENTER)
    table_cell    = S("TblCell",      fontSize=8,  leading=11, alignment=TA_CENTER)
    table_left    = S("TblLeft",      fontSize=8,  leading=11, alignment=TA_LEFT)

    def hr():
        return HRFlowable(width="100%", thickness=0.5, color=GREY_LINE, spaceAfter=6)

    def section(title):
        return [Spacer(1, 10), Paragraph(title, section_style), hr()]

    def kv_table(rows):
        """Two-column key→value table."""
        data = [[Paragraph(k, label_style), Paragraph(v, value_style)] for k, v in rows]
        t = Table(data, colWidths=["60%", "40%"])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), GREY_BG),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, GREY_BG]),
            ("GRID", (0, 0), (-1, -1), 0.3, GREY_LINE),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",  (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ]))
        return t

    def grid_table(headers, data_rows, col_widths=None):
        """Multi-column grid table."""
        hdr = [Paragraph(h, table_hdr) for h in headers]
        body = []
        for row in data_rows:
            body.append([Paragraph(str(c), table_cell) if i > 0
                         else Paragraph(str(c), table_left)
                         for i, c in enumerate(row)])
        t = Table([hdr] + body, colWidths=col_widths, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, 0),  MED_BLUE),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, GREY_BG]),
            ("GRID",         (0, 0), (-1, -1),  0.3, GREY_LINE),
            ("VALIGN",       (0, 0), (-1, -1),  "MIDDLE"),
            ("TOPPADDING",   (0, 0), (-1, -1),  3),
            ("BOTTOMPADDING",(0, 0), (-1, -1),  3),
            ("LEFTPADDING",  (0, 0), (-1, -1),  5),
        ]))
        return t

    story = []

    # ── Cover / header ──────────────────────────────────────────────────────
    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph("SecureSOC WAF", title_style))
    story.append(Paragraph("Performance Evaluation Report", title_style))
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph(
        f"Evaluation window: {s['t_min'].strftime('%Y-%m-%d %H:%M:%S')} UTC "
        f"→ {s['t_max'].strftime('%Y-%m-%d %H:%M:%S')} UTC "
        f"({s['elapsed_hours']:.2f} h / {s['elapsed_minutes']:.0f} min)",
        subtitle_style,
    ))
    story.append(Paragraph(
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        subtitle_style,
    ))
    story.append(Spacer(1, 0.4 * cm))
    story.append(HRFlowable(width="100%", thickness=2, color=MED_BLUE, spaceAfter=10))

    # ── 1. Confusion Matrix ─────────────────────────────────────────────────
    story += section("1 · Confusion Matrix")
    cm_data = [
        ["", "Predicted BLOCK", "Predicted ALLOW", "Row Total"],
        ["Actual ATTACK", f"TP = {s['TP']:,}", f"FN = {s['FN']:,}", f"{s['n_attack']:,}"],
        ["Actual NORMAL", f"FP = {s['FP']:,}", f"TN = {s['TN']:,}", f"{s['n_normal']:,}"],
        ["Col Total",     f"{s['TP']+s['FP']:,}", f"{s['FN']+s['TN']:,}", f"{s['total']:,}"],
    ]
    cm_table = Table(
        [[Paragraph(cell, table_hdr if i == 0 else (table_left if j == 0 else table_cell))
          for j, cell in enumerate(row)]
         for i, row in enumerate(cm_data)],
        colWidths=["25%", "25%", "25%", "25%"],
    )
    cm_table.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0),  MED_BLUE),
        ("BACKGROUND",   (0, 0), (0, -1),  DARK_BLUE),
        ("TEXTCOLOR",    (0, 0), (0, -1),  colors.white),
        ("BACKGROUND",   (1, 1), (1, 1),  colors.HexColor("#D5F5E3")),  # TP green
        ("BACKGROUND",   (2, 2), (2, 2),  colors.HexColor("#D5F5E3")),  # TN green
        ("BACKGROUND",   (1, 2), (1, 2),  colors.HexColor("#FADBD8")),  # FP red
        ("BACKGROUND",   (2, 1), (2, 1),  colors.HexColor("#FADBD8")),  # FN red
        ("GRID",         (0, 0), (-1, -1), 0.5, GREY_LINE),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN",        (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING",   (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
        ("FONTNAME",     (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTNAME",     (0, 0), (0, -1),  "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 9),
    ]))
    story.append(cm_table)

    if s['fn_by_type']:
        story.append(Spacer(1, 6))
        story.append(Paragraph("False Negatives by attack category:", label_style))
        fn_rows = sorted(s['fn_by_type'].items(), key=lambda x: -x[1])
        fn_table = grid_table(
            ["Attack Type", "Undetected"],
            fn_rows,
            col_widths=["70%", "30%"],
        )
        story.append(fn_table)

    # ── 2. Core Performance Metrics ─────────────────────────────────────────
    story += section("2 · Core Performance Metrics")
    metrics_rows = [
        ("Q1  Recall (TPR / Sensitivity)",          pct(s['recall'])),
        ("Q2  Precision",                           pct(s['precision'])),
        ("Q3  F1-Score",                            fmt_float(s['f1'])),
        ("Q4  False Positive Rate (FPR)",           pct(s['fpr'])),
        ("Q5  Overall Accuracy",                    pct(s['accuracy'])),
        ("Q6  Block Rate (all requests)",           pct(s['block_rate'])),
        ("Q7  Average Throughput",                  f"{s['throughput_rpm']:.1f} req/min"),
        ("Q8  True Positives  (TP)",                f"{s['TP']:,}  — attacks correctly blocked"),
        ("Q9  False Positives (FP)",                f"{s['FP']:,}  — legit traffic blocked"),
        ("Q10 False Negatives (FN)",                f"{s['FN']:,}  — attacks that evaded"),
        ("Q11 True Negatives  (TN)",                f"{s['TN']:,}  — legit traffic allowed"),
        ("Q12 Total Requests",                      f"{s['total']:,}"),
    ]
    story.append(kv_table(metrics_rows))

    # ── 3. Per-Category Block Rates ─────────────────────────────────────────
    story += section("3 · Per-Category Block Rates  (Q13–Q15)")
    cat_rows = []
    for cat, d in sorted(s['per_cat'].items(), key=lambda x: -x[1]['block_rate']):
        note = f"{d['allowed']:,} allowed" if d['block_rate'] < 1.0 else "—"
        cat_rows.append([cat, f"{d['total']:,}", f"{d['blocked']:,}",
                         f"{d['allowed']:,}", pct(d['block_rate']), note])
    story.append(grid_table(
        ["Attack Type", "Total", "Blocked", "Allowed", "Block Rate", "Note"],
        cat_rows,
        col_widths=["22%", "12%", "13%", "13%", "15%", "25%"],
    ))

    perfect = [c for c, d in s['per_cat'].items() if d['block_rate'] == 1.0]
    xss = s['per_cat'].get('XSS', {})
    bf  = s['per_cat'].get('Brute Force', {})
    story.append(Spacer(1, 6))
    story.append(kv_table([
        ("Q13  Perfect block-rate categories",  ", ".join(perfect) if perfect else "None"),
        ("Q14  XSS block rate",                 pct(xss.get('block_rate', 0))),
        ("Q15  Brute Force block rate",         pct(bf.get('block_rate', 0))),
    ]))

    # ── 4. Dataset & Geographic Statistics ──────────────────────────────────
    story += section("4 · Dataset & Geographic Statistics  (Q16–Q19)")
    h_val = int(s['elapsed_hours'])
    m_val = int((s['elapsed_hours'] - h_val) * 60)
    story.append(kv_table([
        ("Q16  Evaluation window",   f"{h_val}h {m_val}m  ({s['elapsed_minutes']:.0f} min)"),
        ("Q17  Unique source IPs",   f"{s['unique_ips']:,}"),
        ("Q18  Countries of origin", f"{s['n_countries']}"),
        ("Q19  Top source country",  f"{s['top_country']}  "
                                     f"({s['top_country_cnt']:,} reqs, "
                                     f"{s['top_country_pct']:.1f}%)"),
    ]))

    # ── 5. Attack-Tool Fingerprinting ────────────────────────────────────────
    story += section("5 · Attack-Tool Fingerprinting  (Q20–Q22)")
    story.append(kv_table([
        ("Q20  Traffic from known attack tools", f"{s['tool_pct']:.1f}%"),
        ("Q21  Most frequent attack tool",       s['top_tool']),
        ("Q22  Browser-like / unidentified UA",  f"{s['normal_agent_pct']:.1f}%"),
    ]))

    # ── 6. Severity Distribution ─────────────────────────────────────────────
    story += section("6 · Severity Distribution  (Q23–Q24)")
    sev_total = s['total']
    sev_rows = []
    for sev in ["critical", "high", "medium", "low", "info"]:
        cnt = s['sev_counts'].get(sev, 0)
        sev_rows.append([sev.capitalize(), f"{cnt:,}", f"{cnt/sev_total*100:.1f}%" if sev_total else "0.0%"])
    story.append(grid_table(["Severity", "Count", "% of Total"], sev_rows,
                             col_widths=["40%", "30%", "30%"]))
    story.append(Spacer(1, 6))
    story.append(kv_table([
        ("Q23  Critical severity requests", f"{s['critical_pct']:.1f}%"),
        ("Q24  Most common severity level", s['most_common_sev'].capitalize()),
    ]))

    # ── 7. Attack Type Distribution ──────────────────────────────────────────
    story += section("7 · Attack Type Distribution  (Q25–Q26)")
    atk_rows = sorted(s['attack_type_counts'].items(), key=lambda x: -x[1])
    story.append(grid_table(
        ["Attack Type", "Count"],
        [[k, f"{v:,}"] for k, v in atk_rows],
        col_widths=["65%", "35%"],
    ))
    story.append(Spacer(1, 6))
    story.append(kv_table([
        ("Q25  Most frequent attack type",  s['most_freq_attack']),
        ("Q26  Least frequent attack type", s['least_freq_attack']),
    ]))

    # ── 8. Hourly Traffic Analysis ───────────────────────────────────────────
    story.append(PageBreak())
    story += section("8 · Hourly Traffic Analysis  (Q27–Q28)")
    hour_rows = []
    for h_ts in sorted(s['hourly_total'].keys()):
        cnt = s['hourly_total'][h_ts]
        det, _, dr = s['hourly_detect_rate'].get(h_ts, (0, cnt, 0.0))
        flag = "★" if dr == 1.0 and det > 0 else ""
        hour_rows.append([h_ts.strftime("%Y-%m-%d %H:%M"), f"{cnt:,}", f"{det:,}", pct(dr), flag])
    story.append(grid_table(
        ["Hour (UTC)", "Requests", "Detected", "Detect Rate", ""],
        hour_rows,
        col_widths=["30%", "17%", "17%", "17%", "9%"],
    ))
    story.append(Spacer(1, 8))

    bh_str = (s['busiest_hour'].strftime('%Y-%m-%d %H:00 UTC')
              if s['busiest_hour'] else "N/A")
    ph_str = (s['perfect_hours'][0][0].strftime('%Y-%m-%d %H:00 UTC')
              if s['perfect_hours'] else "None in this window")
    story.append(kv_table([
        ("Q27  Busiest hour",              f"{bh_str}  ({s['busiest_hour_req']:,} requests, "
                                           f"{pct(s['busiest_hour_det_rate'])} detect rate)"),
        ("Q28  First 100% detect hour",    ph_str),
    ]))

    # ── Footer note ─────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.6 * cm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=GREY_LINE))
    story.append(Paragraph(
        "SecureSOC WAF — Performance Statistics Evaluator  |  Report auto-generated",
        note_style,
    ))

    doc.build(story)
    print(f"📄  PDF report saved → {output_path}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    args  = parse_args()
    since = datetime.now(timezone.utc) - timedelta(hours=args.hours)

    print(f"\n🔌  Connecting to PostgreSQL at {args.host}:{args.port}/{args.db} ...")
    try:
        conn = connect(args)
    except Exception as e:
        sys.exit(f"❌  Connection failed: {e}")

    print(f"✅  Connected.  Fetching alerts since {since.strftime('%Y-%m-%d %H:%M:%S UTC')} ...")
    rows = fetch_alerts(conn, since)
    conn.close()

    if not rows:
        sys.exit("⚠️   No alert rows found in this time window. "
                 "Run the simulator first, or increase --hours.")

    print(f"📊  Loaded {len(rows):,} alert rows.  Computing statistics ...")
    stats = compute_stats(rows, args.hours)

    if not stats:
        sys.exit("⚠️   Statistics computation returned empty results.")

    print_report(stats, args.hours)

    if args.pdf:
        generate_pdf_report(stats, args.hours, args.pdf)
    elif HAS_REPORTLAB:
        generate_pdf_report(stats, args.hours, "waf_report.pdf")


if __name__ == "__main__":
    main()