import { useState, useEffect, useCallback } from "react";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { useAuth } from "@/context/AuthContext";
import {
  Shield, ClipboardList, User, Calendar, Filter, RefreshCw,
  ChevronLeft, ChevronRight, CheckCircle, XCircle, Search,
  Download, Clock, AlertTriangle, Settings, LogIn, FileText,
  Trash2, Edit3, UserPlus, Lock, Unlock, Activity,
} from "lucide-react";
import { cn } from "@/lib/utils";

// ─── Types ────────────────────────────────────────────────────────────────────

interface AuditEntry {
  id:         number;
  timestamp:  string;
  username:   string;
  role:       string;
  action:     string;
  category:   string;
  target:     string | null;
  target_id:  string | null;
  detail:     Record<string, unknown> | null;
  ip_address: string | null;
  outcome:    "success" | "failure";
}

interface AuditResponse {
  data:  AuditEntry[];
  total: number;
  page:  number;
  limit: number;
  pages: number;
  stats: { success_count: string; failure_count: string; unique_users: string; last_24h: string };
}

// ─── Icon / color helpers ──────────────────────────────────────────────────────

const CATEGORY_META: Record<string, { icon: React.ElementType; color: string; bg: string; label: string }> = {
  auth:         { icon: LogIn,     color: "text-blue-400",   bg: "bg-blue-500/10",   label: "Auth" },
  rule:         { icon: Shield,    color: "text-purple-400", bg: "bg-purple-500/10", label: "WAF Rules" },
  incident:     { icon: AlertTriangle, color: "text-yellow-400", bg: "bg-yellow-500/10", label: "Incidents" },
  user:         { icon: User,      color: "text-cyan-400",   bg: "bg-cyan-500/10",   label: "Users" },
  settings:     { icon: Settings,  color: "text-orange-400", bg: "bg-orange-500/10", label: "Settings" },
  report:       { icon: FileText,  color: "text-green-400",  bg: "bg-green-500/10",  label: "Reports" },
  ip:           { icon: Lock,      color: "text-red-400",    bg: "bg-red-500/10",    label: "IP Mgmt" },
  general:      { icon: Activity,  color: "text-slate-400",  bg: "bg-slate-500/10",  label: "General" },
};

function getCategoryMeta(cat: string) {
  return CATEGORY_META[cat] ?? CATEGORY_META.general;
}

const ACTION_ICONS: Record<string, React.ElementType> = {
  login:   LogIn, logout: LogIn, register: UserPlus,
  create:  Edit3, update: Edit3, delete: Trash2,
  block:   Lock,  unblock: Unlock, generate: FileText,
  toggle:  Settings, view: ClipboardList,
};

function getActionIcon(action: string): React.ElementType {
  for (const [key, icon] of Object.entries(ACTION_ICONS)) {
    if (action.toLowerCase().includes(key)) return icon;
  }
  return Activity;
}

// ─── Stat Card ────────────────────────────────────────────────────────────────

function StatCard({ label, value, icon: Icon, color }: { label: string; value: string | number; icon: React.ElementType; color: string }) {
  return (
    <div className="bg-[#0d1421]/80 border border-white/8 rounded-xl p-4 flex items-center gap-3">
      <div className={cn("w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0", color.replace("text-", "bg-").replace("400", "500/10").replace("500", "500/10"))}>
        <Icon className={cn("h-4.5 w-4.5", color)} />
      </div>
      <div>
        <p className="text-xl font-bold text-white font-mono">{value}</p>
        <p className="text-xs text-white/40">{label}</p>
      </div>
    </div>
  );
}

// ─── Row ──────────────────────────────────────────────────────────────────────

function AuditRow({ entry }: { entry: AuditEntry }) {
  const [expanded, setExpanded] = useState(false);
  const meta = getCategoryMeta(entry.category);
  const CatIcon = meta.icon;
  const ActionIcon = getActionIcon(entry.action);

  const ts = new Date(entry.timestamp);
  const dateStr = ts.toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" });
  const timeStr = ts.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" });

  return (
    <>
      <tr
        className={cn("border-b border-white/4 hover:bg-white/[0.02] cursor-pointer transition-colors", expanded && "bg-white/[0.03]")}
        onClick={() => setExpanded(e => !e)}
      >
        {/* Timestamp */}
        <td className="py-3 pl-4 pr-3 whitespace-nowrap">
          <div className="flex items-center gap-1.5">
            <Clock className="h-3 w-3 text-white/25 flex-shrink-0" />
            <div>
              <div className="text-xs font-mono text-white/80">{timeStr}</div>
              <div className="text-[10px] text-white/35">{dateStr}</div>
            </div>
          </div>
        </td>

        {/* User */}
        <td className="py-3 px-3">
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 rounded-full bg-gradient-to-br from-blue-500/20 to-purple-500/20 border border-white/10 flex items-center justify-center flex-shrink-0">
              <User className="h-3 w-3 text-white/60" />
            </div>
            <div>
              <div className="text-xs font-medium text-white">{entry.username || "—"}</div>
              <div className="text-[10px] text-white/35 capitalize">{entry.role || "—"}</div>
            </div>
          </div>
        </td>

        {/* Category */}
        <td className="py-3 px-3">
          <span className={cn("inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-medium", meta.bg, meta.color)}>
            <CatIcon className="h-3 w-3" />
            {meta.label}
          </span>
        </td>

        {/* Action */}
        <td className="py-3 px-3">
          <div className="flex items-center gap-1.5">
            <ActionIcon className="h-3.5 w-3.5 text-white/40 flex-shrink-0" />
            <span className="text-xs text-white/80">{entry.action}</span>
          </div>
        </td>

        {/* Target */}
        <td className="py-3 px-3">
          <span className="text-xs text-white/50 font-mono truncate max-w-[180px] block">
            {entry.target || "—"}
            {entry.target_id ? <span className="text-white/25"> #{entry.target_id}</span> : ""}
          </span>
        </td>

        {/* IP */}
        <td className="py-3 px-3">
          <span className="text-xs font-mono text-white/40">{entry.ip_address || "—"}</span>
        </td>

        {/* Outcome */}
        <td className="py-3 pl-3 pr-4">
          {entry.outcome === "success"
            ? <span className="inline-flex items-center gap-1 text-[10px] font-medium text-green-400"><CheckCircle className="h-3 w-3" /> OK</span>
            : <span className="inline-flex items-center gap-1 text-[10px] font-medium text-red-400"><XCircle className="h-3 w-3" /> Failed</span>
          }
        </td>
      </tr>

      {/* Expanded detail row */}
      {expanded && entry.detail && (
        <tr className="bg-[#060b14]">
          <td colSpan={7} className="py-2 px-6 pb-3">
            <pre className="text-[10px] font-mono text-white/40 bg-white/[0.02] border border-white/6 rounded-lg p-3 overflow-x-auto">
              {JSON.stringify(entry.detail, null, 2)}
            </pre>
          </td>
        </tr>
      )}
    </>
  );
}

// ─── Page ────────────────────────────────────────────────────────────────────

export default function AuditLogs() {
  const { token, user } = useAuth();

  const [data,     setData]     = useState<AuditEntry[]>([]);
  const [stats,    setStats]    = useState<AuditResponse["stats"] | null>(null);
  const [total,    setTotal]    = useState(0);
  const [pages,    setPages]    = useState(1);
  const [page,     setPage]     = useState(1);
  const [loading,  setLoading]  = useState(false);

  // Filters
  const [search,   setSearch]   = useState("");
  const [category, setCategory] = useState("");
  const [outcome,  setOutcome]  = useState("");
  const [from,     setFrom]     = useState("");
  const [to,       setTo]       = useState("");

  const LIMIT = 50;

  const fetchLogs = useCallback(async (p = 1) => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ page: String(p), limit: String(LIMIT) });
      if (search)   params.set("username", search);
      if (category) params.set("category", category);
      if (outcome)  params.set("outcome",  outcome);
      if (from)     params.set("from",     from);
      if (to)       params.set("to",       to);

      const res = await fetch(`/api/audit-logs?${params}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error();
      const json: AuditResponse = await res.json();
      setData(json.data);
      setTotal(json.total);
      setPages(json.pages);
      setStats(json.stats);
      setPage(p);
    } catch {
      // silently fail — table may not exist yet
    } finally {
      setLoading(false);
    }
  }, [token, search, category, outcome, from, to]);

  useEffect(() => { fetchLogs(1); }, [fetchLogs]);

  // Export CSV
  const handleExport = () => {
    const headers = ["timestamp", "username", "role", "action", "category", "target", "ip_address", "outcome"];
    const rows    = data.map(e => headers.map(h => JSON.stringify((e as never)[h] ?? "")).join(","));
    const csv     = [headers.join(","), ...rows].join("\n");
    const blob    = new Blob([csv], { type: "text/csv" });
    const url     = URL.createObjectURL(blob);
    const a       = document.createElement("a");
    a.href        = url;
    a.download    = `audit-log-${new Date().toISOString().slice(0,10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Admin guard
  if (user?.role !== "admin") {
    return (
      <DashboardLayout>
        <div className="flex items-center justify-center min-h-[60vh] flex-col gap-3 text-white/30">
          <Shield className="h-12 w-12 opacity-30" />
          <p className="text-sm">Admin access required to view audit logs.</p>
        </div>
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout>
      <div className="px-6 py-6 space-y-6">

        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-violet-500/10 border border-violet-500/20 flex items-center justify-center">
              <ClipboardList className="h-5 w-5 text-violet-400" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">Audit Logs</h1>
              <p className="text-xs text-white/40 mt-0.5">SOC compliance trail — every action recorded</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => fetchLogs(page)}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg border border-white/10 text-white/50 hover:text-white hover:border-white/20 text-xs transition-all"
            >
              <RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
              Refresh
            </button>
            <button
              onClick={handleExport}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-violet-600 hover:bg-violet-500 text-white text-xs font-medium transition-all shadow-[0_0_15px_rgba(139,92,246,0.25)]"
            >
              <Download className="h-3.5 w-3.5" />
              Export CSV
            </button>
          </div>
        </div>

        {/* Stats */}
        {stats && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <StatCard label="Total Events"    value={total}                   icon={ClipboardList} color="text-violet-400" />
            <StatCard label="Last 24 Hours"   value={stats.last_24h}          icon={Clock}         color="text-blue-400" />
            <StatCard label="Unique Users"    value={stats.unique_users}       icon={User}          color="text-cyan-400" />
            <StatCard label="Failed Actions"  value={stats.failure_count}      icon={XCircle}       color="text-red-400" />
          </div>
        )}

        {/* Filters */}
        <div className="bg-[#0d1421]/80 border border-white/8 rounded-xl p-4">
          <div className="flex items-center gap-2 mb-3">
            <Filter className="h-3.5 w-3.5 text-white/30" />
            <span className="text-xs font-medium text-white/40 uppercase tracking-wide">Filters</span>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-white/25" />
              <input
                type="text"
                placeholder="Username…"
                value={search}
                onChange={e => setSearch(e.target.value)}
                style={{ color: "#fff", backgroundColor: "rgba(255,255,255,0.04)" }}
                className="w-full border border-white/10 rounded-lg pl-8 pr-3 py-2 text-xs outline-none focus:border-violet-500/50 transition-all"
              />
            </div>

            <select
              value={category}
              onChange={e => setCategory(e.target.value)}
              style={{ color: category ? "#fff" : "rgba(255,255,255,0.3)", backgroundColor: "rgba(255,255,255,0.04)" }}
              className="border border-white/10 rounded-lg px-3 py-2 text-xs outline-none focus:border-violet-500/50 transition-all"
            >
              <option value="">All Categories</option>
              {Object.entries(CATEGORY_META).map(([k, v]) => (
                <option key={k} value={k} style={{ color: "#fff", backgroundColor: "#0d1421" }}>{v.label}</option>
              ))}
            </select>

            <select
              value={outcome}
              onChange={e => setOutcome(e.target.value)}
              style={{ color: outcome ? "#fff" : "rgba(255,255,255,0.3)", backgroundColor: "rgba(255,255,255,0.04)" }}
              className="border border-white/10 rounded-lg px-3 py-2 text-xs outline-none focus:border-violet-500/50 transition-all"
            >
              <option value="">All Outcomes</option>
              <option value="success" style={{ color: "#fff", backgroundColor: "#0d1421" }}>Success</option>
              <option value="failure" style={{ color: "#fff", backgroundColor: "#0d1421" }}>Failure</option>
            </select>

            <input
              type="date"
              value={from}
              onChange={e => setFrom(e.target.value)}
              style={{ color: from ? "#fff" : "rgba(255,255,255,0.3)", backgroundColor: "rgba(255,255,255,0.04)" }}
              className="border border-white/10 rounded-lg px-3 py-2 text-xs outline-none focus:border-violet-500/50 transition-all"
            />
            <input
              type="date"
              value={to}
              onChange={e => setTo(e.target.value)}
              style={{ color: to ? "#fff" : "rgba(255,255,255,0.3)", backgroundColor: "rgba(255,255,255,0.04)" }}
              className="border border-white/10 rounded-lg px-3 py-2 text-xs outline-none focus:border-violet-500/50 transition-all"
            />
          </div>
        </div>

        {/* Table */}
        <div className="bg-[#0d1421]/80 border border-white/8 rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-white/8 bg-white/[0.02]">
                  <th className="text-left py-3 pl-4 pr-3 text-[10px] font-semibold text-white/30 uppercase tracking-wider w-36">Timestamp</th>
                  <th className="text-left py-3 px-3 text-[10px] font-semibold text-white/30 uppercase tracking-wider">User</th>
                  <th className="text-left py-3 px-3 text-[10px] font-semibold text-white/30 uppercase tracking-wider">Category</th>
                  <th className="text-left py-3 px-3 text-[10px] font-semibold text-white/30 uppercase tracking-wider">Action</th>
                  <th className="text-left py-3 px-3 text-[10px] font-semibold text-white/30 uppercase tracking-wider">Target</th>
                  <th className="text-left py-3 px-3 text-[10px] font-semibold text-white/30 uppercase tracking-wider">IP Address</th>
                  <th className="text-left py-3 pl-3 pr-4 text-[10px] font-semibold text-white/30 uppercase tracking-wider">Outcome</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan={7} className="py-16 text-center">
                    <div className="flex flex-col items-center gap-3 text-white/25">
                      <div className="w-5 h-5 border-2 border-violet-500/30 border-t-violet-500 rounded-full animate-spin" />
                      <span className="text-xs">Loading audit records…</span>
                    </div>
                  </td></tr>
                ) : data.length === 0 ? (
                  <tr><td colSpan={7} className="py-16 text-center">
                    <div className="flex flex-col items-center gap-3 text-white/20">
                      <ClipboardList className="h-8 w-8 opacity-30" />
                      <span className="text-xs">No audit records found.<br/>Actions will appear here once users interact with the dashboard.</span>
                    </div>
                  </td></tr>
                ) : (
                  data.map(entry => <AuditRow key={entry.id} entry={entry} />)
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {pages > 1 && (
            <div className="flex items-center justify-between px-4 py-3 border-t border-white/6">
              <span className="text-xs text-white/30">
                Showing {((page - 1) * LIMIT) + 1}–{Math.min(page * LIMIT, total)} of {total} records
              </span>
              <div className="flex items-center gap-1">
                <button
                  onClick={() => fetchLogs(page - 1)}
                  disabled={page <= 1}
                  className="p-1.5 rounded-lg border border-white/10 text-white/40 hover:text-white hover:border-white/20 disabled:opacity-30 transition-all"
                >
                  <ChevronLeft className="h-3.5 w-3.5" />
                </button>
                <span className="text-xs text-white/40 px-2 font-mono">{page} / {pages}</span>
                <button
                  onClick={() => fetchLogs(page + 1)}
                  disabled={page >= pages}
                  className="p-1.5 rounded-lg border border-white/10 text-white/40 hover:text-white hover:border-white/20 disabled:opacity-30 transition-all"
                >
                  <ChevronRight className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Compliance note */}
        <p className="text-[10px] text-white/20 text-center">
          Audit logs are immutable and retained for compliance. SOC 2 Type II · ISO 27001 · GDPR Article 30
        </p>
      </div>
    </DashboardLayout>
  );
}
