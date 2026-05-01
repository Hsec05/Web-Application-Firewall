#!/usr/bin/env python3
"""
SecureSOC WAF — Performance Statistics Evaluator  (v3 — attack-only DB aware)
==============================================================================

WHY THIS VERSION IS DIFFERENT FROM v2
--------------------------------------
Your WAF only writes a row to waf_alerts when it detects an attack.
Normal (clean) requests that pass through are never stored. This creates a
fundamental stats problem:

    From the DB alone you can calculate:
      ✅  TP  — attacks that were blocked
      ✅  FN  — attacks that were allowed (below threshold)
      ✅  Recall  = TP / (TP + FN)
      ❌  FP  — legit requests wrongly blocked  → 0 in DB (no legit rows stored)
      ❌  TN  — legit requests correctly allowed → 0 in DB
      ❌  Precision, FPR, Accuracy → all wrong without FP / TN

    To get the full confusion matrix you need TWO extra inputs:
      1. --total-requests   Total HTTP requests the WAF processed in the window
                            (attacks + normal). Read from your WAF middleware
                            counter, Express access-log wc -l, or nginx log.
      2. --fp-count         How many of those blocked requests were false alarms.
                            Can be 0 (ideal), or obtained from your FalsePositive
                            session tracking / manual review.

    When --total-requests IS provided the evaluator computes the full matrix.
    When it is NOT provided the evaluator prints attack-only metrics with a
    clear warning showing which numbers are unavailable.

USAGE
-----
    pip install psycopg2-binary tabulate reportlab

    # Minimal — attack-only metrics (Recall, F1 approximation, per-category rates)
    python waf_stats_evaluator.py

    # Full confusion matrix (adds Precision, FPR, Accuracy, TN)
    python waf_stats_evaluator.py --total-requests 14400 --fp-count 90

    # Custom window / DB connection
    python waf_stats_evaluator.py --hours 1 --total-requests 5000

    # Also generate a PDF
    python waf_stats_evaluator.py --total-requests 14400 --fp-count 90 --pdf waf_report.pdf

GROUND-TRUTH CONVENTION
------------------------
  Positive (attack)  : attack_type NOT NULL and NOT IN ('None', 'none', '')
  Negative (legit)   : not stored in DB — counted via --total-requests

  TP  = attack   + blocked    (correctly caught)
  FN  = attack   + allowed    (evaded, below threshold)
  FP  = legit    + blocked    (false alarm — requires --fp-count)
  TN  = legit    + allowed    (correctly passed — derived from --total-requests)
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
    HAS_TABULATE = False

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
    p = argparse.ArgumentParser(
        description="SecureSOC WAF Statistics Evaluator (attack-only DB aware)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python waf_stats_evaluator.py
  python waf_stats_evaluator.py --total-requests 14400 --fp-count 90
  python waf_stats_evaluator.py --hours 1 --total-requests 5000 --pdf report.pdf
        """,
    )
    p.add_argument("--host",     default="localhost")
    p.add_argument("--port",     type=int, default=5432)
    p.add_argument("--db",       default="waf_dashboard")
    p.add_argument("--user",     default="postgres")
    p.add_argument("--password", default="root")
    p.add_argument(
        "--hours", type=float, default=24,
        help="Evaluation window in hours (default: 24)",
    )

    # ── New in v3: required for full confusion matrix ──────────────────────
    p.add_argument(
        "--total-requests",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Total HTTP requests processed by the WAF in the evaluation window "
            "(attacks + normal combined). Read from your Express/Nginx access log "
            "or WAF request counter. WITHOUT this, Precision / FPR / Accuracy / TN "
            "cannot be computed because normal traffic is not stored in the DB."
        ),
    )
    p.add_argument(
        "--fp-count",
        type=int,
        default=0,
        metavar="N",
        help=(
            "Number of false positives (legitimate requests that were wrongly blocked). "
            "Default: 0. Set this if you track FP sessions separately "
            "(e.g., from the FalsePositiveSession in the traffic simulator)."
        ),
    )
    p.add_argument(
        "--pdf",
        metavar="PATH",
        default=None,
        help="Generate a PDF report at this path. Requires: pip install reportlab",
    )
    return p.parse_args()


# ─── Database helpers ─────────────────────────────────────────────────────────

def connect(args):
    return psycopg2.connect(
        host=args.host, port=args.port,
        dbname=args.db, user=args.user, password=args.password,
    )


def fetch_alerts(conn, since: datetime):
    """Return all alert rows in the evaluation window (attacks only — by design)."""
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

NORMAL_LABELS = {"None", "none", "", None}

TOOL_PATTERNS = [
    "sqlmap", "nikto", "masscan", "nmap", "dirbuster", "gobuster",
    "hydra", "metasploit", "acunetix", "burpsuite", "zgrab",
    "python-requests", "go-http-client", "curl/", "wget/", "scrapy",
]


def is_attack(row) -> bool:
    at = (row["attack_type"] or "").strip()
    return at not in NORMAL_LABELS and at != ""


def is_blocked(row) -> bool:
    return (row["action"] or "").lower() == "blocked"


def is_tool_agent(ua: str) -> bool:
    if not ua:
        return False
    ua_lower = ua.lower()
    return any(tool in ua_lower for tool in TOOL_PATTERNS)


# ─── Statistics computation ───────────────────────────────────────────────────

def compute_stats(rows, window_hours: float,
                  total_requests_arg: int | None = None,
                  fp_count_arg: int = 0) -> dict:
    """
    Compute all WAF performance metrics.

    Parameters
    ----------
    rows               : DB rows from waf_alerts (attacks only)
    window_hours       : evaluation window length
    total_requests_arg : total HTTP requests processed (attacks + normal).
                         If None, normal-traffic metrics are unavailable.
    fp_count_arg       : number of known false positives (default 0)
    """
    if not rows:
        return {}

    # ── Step 1: Attack-side confusion matrix (always computable) ──────────
    #
    # Since only attacks are in the DB:
    #   Every row is a genuine attack (ground truth = Positive)
    #   blocked  → TP (correctly blocked attack)
    #   allowed  → FN (missed attack, below threshold)
    #
    TP_from_db = 0
    FN_from_db = 0
    fn_by_type = defaultdict(int)

    for row in rows:
        if is_attack(row):          # always True for attack-only DB
            if is_blocked(row):
                TP_from_db += 1
            else:
                FN_from_db += 1
                fn_by_type[row["attack_type"]] += 1

    n_attack_db = TP_from_db + FN_from_db   # total logged attack requests

    # ── Step 2: Normal-traffic side (requires --total-requests) ───────────
    #
    # With total_requests we know how many requests were NOT attacks.
    # We can then reconstruct TN and validate FP.
    #
    has_full_matrix = total_requests_arg is not None

    if has_full_matrix:
        total_requests = total_requests_arg

        # Sanity check: total_requests must be >= n_attack_db
        if total_requests < n_attack_db:
            print(
                f"⚠️  WARNING: --total-requests ({total_requests:,}) is less than "
                f"the number of attack rows in the DB ({n_attack_db:,}). "
                f"Using {n_attack_db:,} as total (no normal traffic)."
            )
            total_requests = n_attack_db

        FP = max(fp_count_arg, 0)
        n_normal = total_requests - n_attack_db   # estimated normal request count
        TN = max(n_normal - FP, 0)               # legit requests correctly allowed

        # Final confusion matrix
        TP = TP_from_db
        FN = FN_from_db
        total = total_requests

    else:
        # Attack-only mode: FP and TN are unknown
        TP = TP_from_db
        FN = FN_from_db
        FP = None    # unknown — can't derive without total_requests
        TN = None    # unknown
        n_normal = None
        total = n_attack_db  # only attacks are counted

    n_blocked = TP + (FP if FP is not None else 0)

    # ── Step 3: Core performance metrics ──────────────────────────────────

    # Recall / Sensitivity / TPR — valid even without normal traffic
    recall = TP / n_attack_db if n_attack_db > 0 else 0.0

    # Precision — valid only when we know FP
    if FP is not None:
        n_predicted_positive = TP + FP
        precision = TP / n_predicted_positive if n_predicted_positive > 0 else 0.0
    else:
        n_predicted_positive = TP   # lower bound (ignores unknown FP)
        precision = None            # not reliable without FP count

    # F1 — computable but note precision caveat when FP unknown
    if precision is not None and recall > 0:
        f1 = 2 * precision * recall / (precision + recall)
    elif precision is None:
        # F1 lower bound using precision = 1.0 (overestimates)
        f1 = None
    else:
        f1 = 0.0

    # FPR = FP / (FP + TN) = FP / n_normal
    if FP is not None and n_normal is not None and n_normal > 0:
        fpr = FP / n_normal
    else:
        fpr = None

    # Accuracy = (TP + TN) / total
    if TN is not None:
        accuracy = (TP + TN) / total if total > 0 else 0.0
    else:
        accuracy = None

    # Block rate = n_blocked / total (attack-only: blocked / all_db_rows)
    block_rate = n_blocked / total if total > 0 else 0.0

    # ── Step 4: Throughput ────────────────────────────────────────────────
    timestamps = [row["timestamp"] for row in rows]
    t_min = min(timestamps)
    t_max = max(timestamps)
    elapsed_minutes = max((t_max - t_min).total_seconds() / 60, 1)
    throughput_rpm  = (total_requests_arg or n_attack_db) / elapsed_minutes
    elapsed_hours   = elapsed_minutes / 60

    # ── Step 5: Per-category block rates ──────────────────────────────────
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

    # ── Step 6: Geographic stats ──────────────────────────────────────────
    country_counts = defaultdict(int)
    unique_ips     = set()
    for row in rows:
        unique_ips.add(row["source_ip"])
        if row["country"]:
            country_counts[row["country"]] += 1

    top_country     = max(country_counts, key=country_counts.get) if country_counts else "N/A"
    top_country_cnt = country_counts.get(top_country, 0)
    top_country_pct = top_country_cnt / n_attack_db * 100 if n_attack_db > 0 else 0.0

    # ── Step 7: User-agent / tool fingerprinting ──────────────────────────
    tool_count   = sum(1 for r in rows if is_tool_agent(r.get("user_agent", "")))
    normal_agent = sum(1 for r in rows if not is_tool_agent(r.get("user_agent", "")))
    tool_pct         = tool_count   / n_attack_db * 100 if n_attack_db > 0 else 0.0
    normal_agent_pct = normal_agent / n_attack_db * 100 if n_attack_db > 0 else 0.0

    tool_name_counts = defaultdict(int)
    for row in rows:
        ua = (row.get("user_agent") or "").lower()
        for tool in TOOL_PATTERNS:
            if tool in ua:
                tool_name_counts[tool] += 1
                break

    top_tool = max(tool_name_counts, key=tool_name_counts.get) if tool_name_counts else "N/A"

    # ── Step 8: Severity distribution ────────────────────────────────────
    sev_counts = defaultdict(int)
    for row in rows:
        sev_counts[(row.get("severity") or "info").lower()] += 1

    critical_pct    = sev_counts["critical"] / n_attack_db * 100 if n_attack_db > 0 else 0.0
    most_common_sev = max(sev_counts, key=sev_counts.get) if sev_counts else "N/A"

    # ── Step 9: Attack type distribution ─────────────────────────────────
    attack_type_counts = defaultdict(int)
    for row in rows:
        if is_attack(row):
            attack_type_counts[row["attack_type"]] += 1

    most_freq_attack  = max(attack_type_counts, key=attack_type_counts.get, default="N/A")
    least_freq_attack = min(attack_type_counts, key=attack_type_counts.get, default="N/A")

    # ── Step 10: Hourly traffic ───────────────────────────────────────────
    hourly_total    = defaultdict(int)
    hourly_detected = defaultdict(int)

    for row in rows:
        hour = row["timestamp"].replace(minute=0, second=0, microsecond=0)
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
        "n_attack_db":    n_attack_db,
        "n_normal":       n_normal,
        "total":          total,
        "has_full_matrix": has_full_matrix,
        "fn_by_type":     dict(fn_by_type),
        # Core metrics
        "recall":    recall,
        "precision": precision,   # None when FP unknown
        "f1":        f1,          # None when FP unknown
        "fpr":       fpr,         # None when FP unknown
        "accuracy":  accuracy,    # None when FP unknown
        "block_rate": block_rate,
        "throughput_rpm": throughput_rpm,
        # Time
        "t_min": t_min, "t_max": t_max,
        "elapsed_minutes": elapsed_minutes,
        "elapsed_hours": elapsed_hours,
        # Per-category
        "per_cat": per_cat,
        # Geo
        "unique_ips":      len(unique_ips),
        "n_countries":     len(country_counts),
        "top_country":     top_country,
        "top_country_pct": top_country_pct,
        "top_country_cnt": top_country_cnt,
        # Tools
        "tool_pct":         tool_pct,
        "top_tool":         top_tool,
        "normal_agent_pct": normal_agent_pct,
        # Severity
        "sev_counts":      dict(sev_counts),
        "critical_pct":    critical_pct,
        "most_common_sev": most_common_sev,
        # Attack types
        "attack_type_counts": dict(attack_type_counts),
        "most_freq_attack":   most_freq_attack,
        "least_freq_attack":  least_freq_attack,
        # Hourly
        "hourly_total":          dict(hourly_total),
        "hourly_detect_rate":    hourly_detect_rate,
        "busiest_hour":          busiest_hour,
        "busiest_hour_req":      hourly_total.get(busiest_hour, 0) if busiest_hour else 0,
        "busiest_hour_det_rate": busiest_hour_detect_rate,
        "perfect_hours":         perfect_hours,
    }


# ─── Formatting helpers ───────────────────────────────────────────────────────

SEPARATOR = "─" * 72

def pct(v, decimals=2):
    if v is None:
        return "N/A  (need --total-requests)"
    return f"{v * 100:.{decimals}f}%"

def fmt_float(v, decimals=4):
    if v is None:
        return "N/A  (need --total-requests)"
    return f"{v:.{decimals}f}"

def fmt_int(v):
    if v is None:
        return "N/A  (need --total-requests)"
    return f"{v:,}"


# ─── Report printer ───────────────────────────────────────────────────────────

def print_report(s: dict, window_hours: float):
    print()
    print("=" * 72)
    print("  SecureSOC WAF — Performance Evaluation Report")
    print(f"  Evaluation window : {s['t_min'].strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"                    → {s['t_max'].strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  Window duration   : {s['elapsed_hours']:.2f} h  ({s['elapsed_minutes']:.1f} min)")
    print(f"  Attack rows in DB : {s['n_attack_db']:,}")
    if s['has_full_matrix']:
        print(f"  Total requests    : {s['total']:,}  (provided via --total-requests)")
        print(f"  Normal requests   : {s['n_normal']:,}  (derived: total - attacks)")
        print(f"  False positives   : {s['FP']:,}  (provided via --fp-count)")
    else:
        print()
        print("  ⚠️  PARTIAL METRICS MODE")
        print("  Normal traffic is NOT stored in your DB. The following metrics")
        print("  are UNAVAILABLE without --total-requests:")
        print("    Precision, FPR, Accuracy, TN, FP")
        print()
        print("  HOW TO GET --total-requests:")
        print("    • Express access log:  wc -l access.log")
        print("    • Nginx log count:     awk 'END{print NR}' /var/log/nginx/access.log")
        print("    • WAF middleware counter (add a req_counter in your wafMiddleware)")
        print()
        print("  Run with:  python waf_stats_evaluator.py --total-requests N")
    print("=" * 72)

    # ── 1. Confusion Matrix ────────────────────────────────────────────────
    print(f"\n{'CONFUSION MATRIX':^72}")
    print(SEPARATOR)

    if s['has_full_matrix']:
        cm_rows = [
            ["",             "Predicted BLOCK",      "Predicted ALLOW",       "Row Total"],
            ["Actual ATTACK", f"TP = {s['TP']:,}",   f"FN = {s['FN']:,}",     f"{s['n_attack_db']:,}"],
            ["Actual NORMAL", f"FP = {s['FP']:,}",   f"TN = {s['TN']:,}",     f"{s['n_normal']:,}"],
            ["Col Total",     f"{s['TP']+s['FP']:,}", f"{s['FN']+s['TN']:,}", f"{s['total']:,}"],
        ]
    else:
        cm_rows = [
            ["",             "Predicted BLOCK",      "Predicted ALLOW",    "Row Total"],
            ["Actual ATTACK", f"TP = {s['TP']:,}",   f"FN = {s['FN']:,}",  f"{s['n_attack_db']:,}"],
            ["Actual NORMAL", "FP = ❓",              "TN = ❓",            "❓ (not stored)"],
            ["Col Total",     f"≥ {s['TP']:,}",       f"≥ {s['FN']:,}",    f"≥ {s['n_attack_db']:,}"],
        ]

    if HAS_TABULATE:
        print(tabulate(cm_rows, tablefmt="grid"))
    else:
        for row in cm_rows:
            print("  " + " | ".join(f"{c:<20}" for c in row))
    print()

    # ── 2. Core Performance Metrics ───────────────────────────────────────
    print(f"\n{'CORE PERFORMANCE METRICS':^72}")
    print(SEPARATOR)
    metrics = [
        (" Q1  Recall  (True Positive Rate / Sensitivity) ✅",  pct(s['recall'])),
        (" Q2  Precision" + (" ✅" if s['has_full_matrix'] else " ❌"),
         pct(s['precision'])),
        (" Q3  F1-Score" + (" ✅" if s['has_full_matrix'] else " ❌"),
         fmt_float(s['f1'])),
        (" Q4  False Positive Rate (FPR)" + (" ✅" if s['has_full_matrix'] else " ❌"),
         pct(s['fpr'])),
        (" Q5  Overall Accuracy" + (" ✅" if s['has_full_matrix'] else " ❌"),
         pct(s['accuracy'])),
        (" Q6  Block Rate  (fraction of all requests)  ✅",
         f"{s['block_rate']*100:.2f}%"),
        (" Q7  Average Throughput  ✅",
         f"{s['throughput_rpm']:.1f} req/min"),
    ]
    for label, value in metrics:
        print(f"  {label:<55}  {value}")

    # ── 3. Confusion Matrix Detail ────────────────────────────────────────
    print(f"\n{'CONFUSION MATRIX DETAIL':^72}")
    print(SEPARATOR)
    print(f"  Q8   True Positives  (TP) ✅ : {s['TP']:>8,}   (attacks correctly blocked)")
    print(f"  Q9   False Positives (FP) {'✅' if s['has_full_matrix'] else '❌'} : {fmt_int(s['FP']):>8}   (legit traffic blocked — false alarms)")
    print(f"  Q10  False Negatives (FN) ✅ : {s['FN']:>8,}   (attacks that evaded detection)")
    print(f"  Q11  True Negatives  (TN) {'✅' if s['has_full_matrix'] else '❌'} : {fmt_int(s['TN']):>8}   (legit traffic correctly allowed)")
    print(f"  Q12  Attack requests in DB   : {s['n_attack_db']:>8,}")
    if s['has_full_matrix']:
        print(f"       Total requests (all)   : {s['total']:>8,}")

    if s['fn_by_type']:
        print(f"\n  FN breakdown by category (threshold not yet met when session ended):")
        for atype, cnt in sorted(s['fn_by_type'].items(), key=lambda x: -x[1]):
            print(f"    • {atype:<25} {cnt:>5,} undetected requests")

    # ── 4. Per-Category Block Rates ───────────────────────────────────────
    print(f"\n{'PER-CATEGORY BLOCK RATES  (always valid — attack-only)':^72}")
    print(SEPARATOR)
    cat_rows = []
    for cat, d in sorted(s['per_cat'].items(), key=lambda x: -x[1]['block_rate']):
        br = f"{d['block_rate']*100:.2f}%"
        miss_note = ""
        if d['block_rate'] < 1.0:
            miss_note = f"  ← {d['allowed']:,} allowed (below threshold)"
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
    print(f"\n  Q14  XSS block rate   : {xss.get('block_rate', 0)*100:.2f}%"
          + (f"  ({xss.get('allowed',0):,} misses — threshold not exceeded)" if xss.get('allowed', 0) else ""))

    bf = s['per_cat'].get('Brute Force', {})
    print(f"  Q15  Brute Force rate : {bf.get('block_rate', 0)*100:.2f}%"
          + (f"  ({bf.get('allowed',0):,} misses — below rate threshold)" if bf.get('allowed', 0) else ""))

    # ── 5. Dataset & Geographic Stats ─────────────────────────────────────
    print(f"\n{'DATASET & GEOGRAPHIC STATISTICS':^72}")
    print(SEPARATOR)
    h  = int(s['elapsed_hours'])
    m  = int((s['elapsed_hours'] - h) * 60)
    print(f"  Q16  Evaluation window        : {h}h {m}m  ({s['elapsed_minutes']:.0f} min total)")
    print(f"  Q17  Unique source IPs         : {s['unique_ips']:,}")
    print(f"  Q18  Countries of origin       : {s['n_countries']}")
    print(f"  Q19  Top source country        : {s['top_country']}"
          f"  ({s['top_country_cnt']:,} requests, {s['top_country_pct']:.1f}% of attack traffic)")

    # ── 6. Attack-Tool Fingerprinting ─────────────────────────────────────
    print(f"\n{'ATTACK-TOOL FINGERPRINTING':^72}")
    print(SEPARATOR)
    print(f"  Q20  Traffic from known attack tools  : {s['tool_pct']:.1f}%")
    print(f"  Q21  Most frequent attack tool        : {s['top_tool']}")
    print(f"  Q22  Browser-like / unidentified UA   : {s['normal_agent_pct']:.1f}%")

    # ── 7. Severity Distribution ──────────────────────────────────────────
    print(f"\n{'SEVERITY DISTRIBUTION':^72}")
    print(SEPARATOR)
    total_for_sev = s['n_attack_db']
    for sev in ["critical", "high", "medium", "low", "info"]:
        cnt = s['sev_counts'].get(sev, 0)
        bar = "█" * int(cnt / max(s['sev_counts'].values(), default=1) * 30)
        print(f"  {sev:<10}  {cnt:>7,}  ({cnt/total_for_sev*100:5.1f}%)  {bar}")
    print(f"\n  Q23  Critical severity requests : {s['critical_pct']:.1f}%")
    print(f"  Q24  Most common severity level : {s['most_common_sev']}")

    # ── 8. Attack Type Distribution ───────────────────────────────────────
    print(f"\n{'ATTACK TYPE DISTRIBUTION':^72}")
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
                cnt, det, f"{dr*100:.2f}%",
                "★ 100%" if dr == 1.0 and det > 0 else ""
            ])
        print(tabulate(
            hour_rows,
            headers=["Hour (UTC)", "Attack Reqs", "Detected", "Detect Rate", ""],
            tablefmt="simple",
        ))
    else:
        print(f"  {'Hour (UTC)':<18} {'Attack Reqs':>12} {'Detected':>10} {'Detect %':>10}")
        for h_ts in sorted(s['hourly_total'].keys()):
            cnt = s['hourly_total'][h_ts]
            det, _, dr = s['hourly_detect_rate'].get(h_ts, (0, cnt, 0.0))
            flag = " ★" if dr == 1.0 and det > 0 else ""
            print(f"  {h_ts.strftime('%Y-%m-%d %H:%M'):<18} {cnt:>12,} {det:>10,} {dr*100:>9.2f}%{flag}")

    if s['busiest_hour']:
        print(f"\n  Q27  Busiest hour          : {s['busiest_hour'].strftime('%Y-%m-%d %H:00 UTC')}"
              f"  ({s['busiest_hour_req']:,} attack requests, {s['busiest_hour_det_rate']*100:.2f}% detect rate)")
    if s['perfect_hours']:
        ph = s['perfect_hours'][0]
        print(f"  Q28  First 100% detect hour: {ph[0].strftime('%Y-%m-%d %H:00 UTC')}"
              f"  ({ph[1]:,} requests)")
    else:
        print("  Q28  No hour achieved 100% detection rate in this window.")

    # ── Summary banner ────────────────────────────────────────────────────
    print()
    print("=" * 72)
    if s['has_full_matrix']:
        print("  ✅  FULL confusion matrix computed.")
        print(f"      Recall={pct(s['recall'])}  Precision={pct(s['precision'])}  "
              f"F1={fmt_float(s['f1'])}  FPR={pct(s['fpr'])}")
    else:
        print("  ⚠️  PARTIAL metrics — normal traffic not stored in DB.")
        print(f"      Recall (valid) = {pct(s['recall'])}")
        print("      For Precision, FPR, Accuracy: rerun with --total-requests N")
        print("      Example: python waf_stats_evaluator.py --total-requests 14400 --fp-count 0")
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

    DARK_BLUE  = colors.HexColor("#1A2B4A")
    MED_BLUE   = colors.HexColor("#2E5FA3")
    LIGHT_BLUE = colors.HexColor("#D6E4F7")
    GREY_BG    = colors.HexColor("#F4F6F8")
    GREY_LINE  = colors.HexColor("#BDC3C7")
    WARN_BG    = colors.HexColor("#FFF3CD")

    styles = getSampleStyleSheet()

    def S(name, **kw):
        return ParagraphStyle(name, parent=styles["Normal"], **kw)

    title_style    = S("T",  fontSize=20, leading=26, textColor=DARK_BLUE, alignment=TA_CENTER, fontName="Helvetica-Bold")
    subtitle_style = S("Su", fontSize=10, leading=14, textColor=MED_BLUE,  alignment=TA_CENTER)
    section_style  = S("Se", fontSize=13, leading=17, textColor=DARK_BLUE, fontName="Helvetica-Bold", spaceAfter=4)
    label_style    = S("L",  fontSize=9,  leading=13, textColor=colors.black)
    value_style    = S("V",  fontSize=9,  leading=13, textColor=MED_BLUE, fontName="Helvetica-Bold")
    warn_style     = S("W",  fontSize=8,  leading=12, textColor=colors.HexColor("#856404"))
    table_hdr      = S("TH", fontSize=8,  leading=11, textColor=colors.white, fontName="Helvetica-Bold", alignment=TA_CENTER)
    table_cell     = S("TC", fontSize=8,  leading=11, alignment=TA_CENTER)
    table_left     = S("TL", fontSize=8,  leading=11, alignment=TA_LEFT)

    def hr():
        return HRFlowable(width="100%", thickness=0.5, color=GREY_LINE, spaceAfter=6)

    def section(title):
        return [Spacer(1, 10), Paragraph(title, section_style), hr()]

    def kv_table(rows):
        data = [[Paragraph(k, label_style), Paragraph(v, value_style)] for k, v in rows]
        t = Table(data, colWidths=["60%", "40%"])
        t.setStyle(TableStyle([
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, GREY_BG]),
            ("GRID", (0, 0), (-1, -1), 0.3, GREY_LINE),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ]))
        return t

    def grid_table(headers, data_rows, col_widths=None):
        hdr  = [Paragraph(h, table_hdr) for h in headers]
        body = [
            [Paragraph(str(c), table_cell) if i > 0
             else Paragraph(str(c), table_left)
             for i, c in enumerate(row)]
            for row in data_rows
        ]
        t = Table([hdr] + body, colWidths=col_widths, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  MED_BLUE),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, GREY_BG]),
            ("GRID",          (0, 0), (-1, -1),  0.3, GREY_LINE),
            ("VALIGN",        (0, 0), (-1, -1),  "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1),  3),
            ("BOTTOMPADDING", (0, 0), (-1, -1),  3),
            ("LEFTPADDING",   (0, 0), (-1, -1),  5),
        ]))
        return t

    story = []

    # Cover
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
    story.append(Spacer(1, 0.2 * cm))

    # Warning banner if partial matrix
    if not s['has_full_matrix']:
        warn_data = [[Paragraph(
            "⚠️  PARTIAL METRICS: Normal traffic is not stored in the DB. "
            "Precision, FPR, Accuracy and TN are unavailable. "
            "Re-run with --total-requests N to compute the full confusion matrix.",
            warn_style,
        )]]
        wt = Table(warn_data, colWidths=["100%"])
        wt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), WARN_BG),
            ("BOX",        (0, 0), (-1, -1), 1, colors.HexColor("#FFC107")),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ]))
        story.append(wt)

    story.append(Spacer(1, 0.4 * cm))
    story.append(HRFlowable(width="100%", thickness=2, color=MED_BLUE, spaceAfter=10))

    # 1. Confusion Matrix
    story += section("1 · Confusion Matrix")
    if s['has_full_matrix']:
        cm_data = [
            ["",             "Predicted BLOCK",      "Predicted ALLOW",       "Row Total"],
            ["Actual ATTACK", f"TP = {s['TP']:,}",   f"FN = {s['FN']:,}",     f"{s['n_attack_db']:,}"],
            ["Actual NORMAL", f"FP = {s['FP']:,}",   f"TN = {s['TN']:,}",     f"{s['n_normal']:,}"],
            ["Col Total",     f"{s['TP']+s['FP']:,}", f"{s['FN']+s['TN']:,}", f"{s['total']:,}"],
        ]
    else:
        cm_data = [
            ["",             "Predicted BLOCK", "Predicted ALLOW", "Row Total"],
            ["Actual ATTACK", f"TP = {s['TP']:,}", f"FN = {s['FN']:,}", f"{s['n_attack_db']:,}"],
            ["Actual NORMAL", "FP = N/A",          "TN = N/A",          "Not stored"],
            ["Col Total",     f"≥ {s['TP']:,}",   f"≥ {s['FN']:,}",    f"≥ {s['n_attack_db']:,}"],
        ]

    cm_table = Table(
        [[Paragraph(cell, table_hdr if i == 0 else (table_left if j == 0 else table_cell))
          for j, cell in enumerate(row)]
         for i, row in enumerate(cm_data)],
        colWidths=["25%", "25%", "25%", "25%"],
    )
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), MED_BLUE),
        ("BACKGROUND", (0, 0), (0, -1), DARK_BLUE),
        ("TEXTCOLOR",  (0, 0), (0, -1), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, GREY_LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN",  (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]
    if s['has_full_matrix']:
        style_cmds += [
            ("BACKGROUND", (1, 1), (1, 1), colors.HexColor("#D5F5E3")),  # TP
            ("BACKGROUND", (2, 2), (2, 2), colors.HexColor("#D5F5E3")),  # TN
            ("BACKGROUND", (1, 2), (1, 2), colors.HexColor("#FADBD8")),  # FP
            ("BACKGROUND", (2, 1), (2, 1), colors.HexColor("#FADBD8")),  # FN
        ]
    cm_table.setStyle(TableStyle(style_cmds))
    story.append(cm_table)

    if s['fn_by_type']:
        story.append(Spacer(1, 6))
        story.append(Paragraph("False Negatives by attack category (evaded — below threshold):", label_style))
        fn_rows = sorted(s['fn_by_type'].items(), key=lambda x: -x[1])
        story.append(grid_table(["Attack Type", "Undetected"], fn_rows, col_widths=["70%", "30%"]))

    # 2. Core Metrics
    story += section("2 · Core Performance Metrics")
    metrics_kv = [
        ("Q1  Recall (TPR / Sensitivity) ✅",    pct(s['recall'])),
        ("Q2  Precision " + ("✅" if s['has_full_matrix'] else "❌  need --total-requests"),
         pct(s['precision'])),
        ("Q3  F1-Score " + ("✅" if s['has_full_matrix'] else "❌"),
         fmt_float(s['f1'])),
        ("Q4  False Positive Rate (FPR) " + ("✅" if s['has_full_matrix'] else "❌"),
         pct(s['fpr'])),
        ("Q5  Overall Accuracy " + ("✅" if s['has_full_matrix'] else "❌"),
         pct(s['accuracy'])),
        ("Q6  Block Rate (all requests) ✅",       f"{s['block_rate']*100:.2f}%"),
        ("Q7  Average Throughput ✅",              f"{s['throughput_rpm']:.1f} req/min"),
        ("Q8  True Positives  (TP) ✅",            f"{s['TP']:,}  — attacks correctly blocked"),
        ("Q9  False Positives (FP) " + ("✅" if s['has_full_matrix'] else "❌"),
         fmt_int(s['FP']) + ("  — legit traffic blocked" if s['FP'] is not None else "")),
        ("Q10 False Negatives (FN) ✅",            f"{s['FN']:,}  — attacks that evaded"),
        ("Q11 True Negatives  (TN) " + ("✅" if s['has_full_matrix'] else "❌"),
         fmt_int(s['TN']) + ("  — legit traffic allowed" if s['TN'] is not None else "")),
        ("Q12 Attack rows in DB ✅",               f"{s['n_attack_db']:,}"),
    ]
    if s['has_full_matrix']:
        metrics_kv.append(("     Total requests (all) ✅", f"{s['total']:,}"))
    story.append(kv_table(metrics_kv))

    # 3. Per-Category Block Rates
    story += section("3 · Per-Category Block Rates  (Q13–Q15)  ✅")
    cat_rows = []
    for cat, d in sorted(s['per_cat'].items(), key=lambda x: -x[1]['block_rate']):
        note = f"{d['allowed']:,} allowed" if d['block_rate'] < 1.0 else "—"
        cat_rows.append([cat, f"{d['total']:,}", f"{d['blocked']:,}",
                         f"{d['allowed']:,}", f"{d['block_rate']*100:.2f}%", note])
    story.append(grid_table(
        ["Attack Type", "Total", "Blocked", "Allowed", "Block Rate", "Note"],
        cat_rows, col_widths=["22%", "12%", "13%", "13%", "15%", "25%"],
    ))
    perfect = [c for c, d in s['per_cat'].items() if d['block_rate'] == 1.0]
    xss = s['per_cat'].get('XSS', {})
    bf  = s['per_cat'].get('Brute Force', {})
    story.append(Spacer(1, 6))
    story.append(kv_table([
        ("Q13  Perfect block-rate categories", ", ".join(perfect) if perfect else "None"),
        ("Q14  XSS block rate",                f"{xss.get('block_rate', 0)*100:.2f}%"),
        ("Q15  Brute Force block rate",         f"{bf.get('block_rate', 0)*100:.2f}%"),
    ]))

    # 4. Geographic / Dataset
    story += section("4 · Dataset & Geographic Statistics  (Q16–Q19)")
    h_val = int(s['elapsed_hours'])
    m_val = int((s['elapsed_hours'] - h_val) * 60)
    story.append(kv_table([
        ("Q16  Evaluation window",   f"{h_val}h {m_val}m  ({s['elapsed_minutes']:.0f} min)"),
        ("Q17  Unique source IPs",   f"{s['unique_ips']:,}"),
        ("Q18  Countries of origin", f"{s['n_countries']}"),
        ("Q19  Top source country",  f"{s['top_country']}  ({s['top_country_cnt']:,} reqs, {s['top_country_pct']:.1f}%)"),
    ]))

    # 5. Tool Fingerprinting
    story += section("5 · Attack-Tool Fingerprinting  (Q20–Q22)")
    story.append(kv_table([
        ("Q20  Traffic from known attack tools", f"{s['tool_pct']:.1f}%"),
        ("Q21  Most frequent attack tool",       s['top_tool']),
        ("Q22  Browser-like / unidentified UA",  f"{s['normal_agent_pct']:.1f}%"),
    ]))

    # 6. Severity
    story += section("6 · Severity Distribution  (Q23–Q24)")
    total_for_sev = s['n_attack_db']
    sev_rows = [
        [sev.capitalize(), f"{s['sev_counts'].get(sev,0):,}",
         f"{s['sev_counts'].get(sev,0)/total_for_sev*100:.1f}%" if total_for_sev else "0.0%"]
        for sev in ["critical", "high", "medium", "low", "info"]
    ]
    story.append(grid_table(["Severity", "Count", "% of Attack Traffic"], sev_rows,
                              col_widths=["40%", "30%", "30%"]))
    story.append(Spacer(1, 6))
    story.append(kv_table([
        ("Q23  Critical severity requests", f"{s['critical_pct']:.1f}%"),
        ("Q24  Most common severity level", s['most_common_sev'].capitalize()),
    ]))

    # 7. Attack Types
    story += section("7 · Attack Type Distribution  (Q25–Q26)")
    atk_rows = sorted(s['attack_type_counts'].items(), key=lambda x: -x[1])
    story.append(grid_table(["Attack Type", "Count"],
                              [[k, f"{v:,}"] for k, v in atk_rows],
                              col_widths=["65%", "35%"]))
    story.append(Spacer(1, 6))
    story.append(kv_table([
        ("Q25  Most  frequent attack type", s['most_freq_attack']),
        ("Q26  Least frequent attack type", s['least_freq_attack']),
    ]))

    # 8. Hourly
    story.append(PageBreak())
    story += section("8 · Hourly Traffic Analysis  (Q27–Q28)")
    hour_rows = []
    for h_ts in sorted(s['hourly_total'].keys()):
        cnt = s['hourly_total'][h_ts]
        det, _, dr = s['hourly_detect_rate'].get(h_ts, (0, cnt, 0.0))
        flag = "★" if dr == 1.0 and det > 0 else ""
        hour_rows.append([h_ts.strftime("%Y-%m-%d %H:%M"), f"{cnt:,}", f"{det:,}", f"{dr*100:.2f}%", flag])
    story.append(grid_table(
        ["Hour (UTC)", "Attack Reqs", "Detected", "Detect Rate", ""],
        hour_rows, col_widths=["30%", "17%", "17%", "17%", "9%"],
    ))
    story.append(Spacer(1, 8))
    bh_str = s['busiest_hour'].strftime('%Y-%m-%d %H:00 UTC') if s['busiest_hour'] else "N/A"
    ph_str = (s['perfect_hours'][0][0].strftime('%Y-%m-%d %H:00 UTC')
              if s['perfect_hours'] else "None in this window")
    story.append(kv_table([
        ("Q27  Busiest hour",           f"{bh_str}  ({s['busiest_hour_req']:,} attack reqs, {s['busiest_hour_det_rate']*100:.2f}%)"),
        ("Q28  First 100% detect hour", ph_str),
    ]))

    # Footer
    story.append(Spacer(1, 0.6 * cm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=GREY_LINE))
    story.append(Paragraph(
        "SecureSOC WAF — Performance Statistics Evaluator v3  |  Report auto-generated",
        S("foot", fontSize=7, leading=10, textColor=colors.grey),
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

    print(f"✅  Connected. Fetching alerts since {since.strftime('%Y-%m-%d %H:%M:%S UTC')} ...")
    rows = fetch_alerts(conn, since)
    conn.close()

    if not rows:
        sys.exit(
            "⚠️   No alert rows found in this time window. "
            "Run the simulator first, or increase --hours."
        )

    print(f"📊  Loaded {len(rows):,} attack rows. Computing statistics ...")

    if args.total_requests is None:
        print(
            "\n💡  TIP: Your DB only stores attacks — normal traffic is not logged.\n"
            "    Pass --total-requests N (total HTTP requests processed by WAF)\n"
            "    to compute Precision, FPR, Accuracy, TN, and FP.\n"
            "    Example: python waf_stats_evaluator.py --total-requests 14400 --fp-count 90\n"
        )

    stats = compute_stats(
        rows,
        window_hours    = args.hours,
        total_requests_arg = args.total_requests,
        fp_count_arg    = args.fp_count,
    )

    if not stats:
        sys.exit("⚠️   Statistics computation returned empty results.")

    print_report(stats, args.hours)

    if args.pdf:
        generate_pdf_report(stats, args.hours, args.pdf)
    elif HAS_REPORTLAB:
        generate_pdf_report(stats, args.hours, "waf_report.pdf")


if __name__ == "__main__":
    main()
