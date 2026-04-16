import { useState, useEffect, useCallback } from "react";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { useAuth } from "@/context/AuthContext";
import { useNavigate } from "react-router-dom";
import {
  Users, Shield, UserPlus, Edit3, CheckCircle, XCircle,
  AlertCircle, Loader2, RefreshCw, Search, ToggleLeft,
  ToggleRight, Clock, ChevronDown,
} from "lucide-react";
import { cn } from "@/lib/utils";

// ─── Types ────────────────────────────────────────────────────────────────────

interface SocUser {
  id:         number;
  username:   string;
  email:      string;
  role:       "admin" | "analyst" | "viewer";
  is_active:  boolean;
  last_login: string | null;
  created_at: string;
  updated_at: string;
}

// ─── Role badge ───────────────────────────────────────────────────────────────

const ROLE_STYLES: Record<string, string> = {
  admin:   "bg-red-500/10 text-red-400 border-red-500/20",
  analyst: "bg-blue-500/10 text-blue-400 border-blue-500/20",
  viewer:  "bg-slate-500/10 text-slate-400 border-slate-500/20",
};

function RoleBadge({ role }: { role: string }) {
  return (
    <span className={cn("inline-flex items-center px-2 py-0.5 rounded-md text-[10px] font-semibold border capitalize", ROLE_STYLES[role] ?? ROLE_STYLES.viewer)}>
      {role}
    </span>
  );
}

// ─── Editable row ─────────────────────────────────────────────────────────────

function UserRow({ u, currentUserId, onUpdated }: { u: SocUser; currentUserId: number; onUpdated: () => void }) {
  const { token } = useAuth();
  const [editing,  setEditing]  = useState(false);
  const [role,     setRole]     = useState(u.role);
  const [saving,   setSaving]   = useState(false);
  const [err,      setErr]      = useState("");

  const isSelf = u.id === currentUserId;

  const save = async () => {
    setSaving(true); setErr("");
    try {
      const res = await fetch(`/api/users/${u.id}`, {
        method:  "PATCH",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body:    JSON.stringify({ role }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setEditing(false);
      onUpdated();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : "Update failed");
    } finally {
      setSaving(false);
    }
  };

  const toggleActive = async () => {
    setSaving(true); setErr("");
    try {
      const res = await fetch(`/api/users/${u.id}`, {
        method:  "PATCH",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body:    JSON.stringify({ is_active: !u.is_active }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      onUpdated();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : "Toggle failed");
    } finally {
      setSaving(false);
    }
  };

  return (
    <tr className={cn("border-b border-white/4 hover:bg-white/[0.02] transition-colors", !u.is_active && "opacity-50")}>
      {/* Avatar + name */}
      <td className="py-3.5 pl-4 pr-3">
        <div className="flex items-center gap-3">
          <div className={cn(
            "w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold uppercase flex-shrink-0",
            u.is_active ? "bg-gradient-to-br from-blue-500/20 to-purple-500/20 text-white/70 border border-white/10"
                        : "bg-white/5 text-white/25 border border-white/5"
          )}>
            {u.username.slice(0, 2)}
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <span className="text-sm font-medium text-white">{u.username}</span>
              {isSelf && <span className="text-[9px] bg-white/5 border border-white/10 rounded px-1.5 py-0.5 text-white/30">You</span>}
            </div>
            <div className="text-[11px] text-white/35 font-mono">{u.email}</div>
          </div>
        </div>
      </td>

      {/* Role */}
      <td className="py-3.5 px-3">
        {editing ? (
          <select
            value={role}
            onChange={e => setRole(e.target.value as SocUser["role"])}
            style={{ color: "#fff", backgroundColor: "#0d1421" }}
            className="border border-white/10 rounded-lg px-2 py-1 text-xs outline-none focus:border-blue-500/50"
          >
            <option value="viewer"  style={{ backgroundColor: "#0d1421" }}>Viewer</option>
            <option value="analyst" style={{ backgroundColor: "#0d1421" }}>Analyst</option>
            <option value="admin"   style={{ backgroundColor: "#0d1421" }}>Admin</option>
          </select>
        ) : (
          <RoleBadge role={u.role} />
        )}
      </td>

      {/* Status */}
      <td className="py-3.5 px-3">
        {u.is_active
          ? <span className="inline-flex items-center gap-1 text-[10px] text-green-400"><CheckCircle className="h-3 w-3" /> Active</span>
          : <span className="inline-flex items-center gap-1 text-[10px] text-white/30"><XCircle className="h-3 w-3" /> Inactive</span>
        }
      </td>

      {/* Last login */}
      <td className="py-3.5 px-3">
        <span className="text-xs text-white/35 font-mono">
          {u.last_login
            ? new Date(u.last_login).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" })
            : "Never"}
        </span>
      </td>

      {/* Created */}
      <td className="py-3.5 px-3">
        <div className="flex items-center gap-1 text-[11px] text-white/30">
          <Clock className="h-3 w-3" />
          {new Date(u.created_at).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" })}
        </div>
      </td>

      {/* Actions */}
      <td className="py-3.5 pl-3 pr-4">
        {err && <div className="text-[10px] text-red-400 mb-1">{err}</div>}
        <div className="flex items-center gap-1.5">
          {editing ? (
            <>
              <button onClick={save} disabled={saving}
                className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-[11px] font-medium transition-all disabled:opacity-60">
                {saving ? <Loader2 className="h-3 w-3 animate-spin" /> : <CheckCircle className="h-3 w-3" />}
                Save
              </button>
              <button onClick={() => { setEditing(false); setRole(u.role); }}
                className="px-2.5 py-1 rounded-lg border border-white/10 text-white/40 hover:text-white text-[11px] transition-all">
                Cancel
              </button>
            </>
          ) : (
            <>
              <button onClick={() => setEditing(true)}
                className="flex items-center gap-1 px-2.5 py-1 rounded-lg border border-white/10 text-white/40 hover:text-white hover:border-white/20 text-[11px] transition-all">
                <Edit3 className="h-3 w-3" /> Edit Role
              </button>
              {!isSelf && (
                <button onClick={toggleActive} disabled={saving}
                  className={cn(
                    "flex items-center gap-1 px-2.5 py-1 rounded-lg text-[11px] transition-all disabled:opacity-60",
                    u.is_active
                      ? "border border-red-500/20 text-red-400 hover:bg-red-500/10"
                      : "border border-green-500/20 text-green-400 hover:bg-green-500/10"
                  )}>
                  {saving
                    ? <Loader2 className="h-3 w-3 animate-spin" />
                    : u.is_active ? <ToggleLeft className="h-3 w-3" /> : <ToggleRight className="h-3 w-3" />
                  }
                  {u.is_active ? "Deactivate" : "Reactivate"}
                </button>
              )}
            </>
          )}
        </div>
      </td>
    </tr>
  );
}

// ─── Page ────────────────────────────────────────────────────────────────────

export default function UserManagement() {
  const { token, user } = useAuth();
  const navigate = useNavigate();

  const [users,   setUsers]   = useState<SocUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [search,  setSearch]  = useState("");
  const [roleFilter, setRoleFilter] = useState("");

  const fetchUsers = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/users", { headers: { Authorization: `Bearer ${token}` } });
      if (!res.ok) throw new Error();
      const json = await res.json();
      setUsers(json.data || []);
    } catch {
      // silently fail
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => { fetchUsers(); }, [fetchUsers]);

  if (user?.role !== "admin") {
    return (
      <DashboardLayout>
        <div className="flex items-center justify-center min-h-[60vh] flex-col gap-3 text-white/30">
          <Shield className="h-12 w-12 opacity-30" />
          <p className="text-sm">Admin access required to manage users.</p>
        </div>
      </DashboardLayout>
    );
  }

  const filtered = users.filter(u => {
    const matchSearch = !search || u.username.toLowerCase().includes(search.toLowerCase()) || u.email.toLowerCase().includes(search.toLowerCase());
    const matchRole   = !roleFilter || u.role === roleFilter;
    return matchSearch && matchRole;
  });

  // Summary counts
  const counts = { total: users.length, admin: 0, analyst: 0, viewer: 0, inactive: 0 };
  for (const u of users) {
    if (u.role === "admin")   counts.admin++;
    if (u.role === "analyst") counts.analyst++;
    if (u.role === "viewer")  counts.viewer++;
    if (!u.is_active)         counts.inactive++;
  }

  return (
    <DashboardLayout>
      <div className="px-6 py-6 space-y-6">

        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center">
              <Users className="h-5 w-5 text-cyan-400" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">User Management</h1>
              <p className="text-xs text-white/40 mt-0.5">Manage dashboard accounts, roles, and access</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={fetchUsers}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg border border-white/10 text-white/50 hover:text-white hover:border-white/20 text-xs transition-all"
            >
              <RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
              Refresh
            </button>
            <button
              onClick={() => navigate("/add-user")}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium transition-all shadow-[0_0_15px_rgba(6,182,212,0.25)]"
            >
              <UserPlus className="h-4 w-4" /> Add User
            </button>
          </div>
        </div>

        {/* Summary cards */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          {[
            { label: "Total Users",  value: counts.total,    color: "text-white/60"   },
            { label: "Admins",       value: counts.admin,    color: "text-red-400"    },
            { label: "Analysts",     value: counts.analyst,  color: "text-blue-400"   },
            { label: "Viewers",      value: counts.viewer,   color: "text-slate-400"  },
            { label: "Inactive",     value: counts.inactive, color: "text-white/30"   },
          ].map(({ label, value, color }) => (
            <div key={label} className="bg-[#0d1421]/80 border border-white/8 rounded-xl p-4 text-center">
              <p className={cn("text-2xl font-bold font-mono", color)}>{value}</p>
              <p className="text-[11px] text-white/30 mt-1">{label}</p>
            </div>
          ))}
        </div>

        {/* Filters */}
        <div className="flex items-center gap-3">
          <div className="relative flex-1 max-w-xs">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-white/25" />
            <input
              type="text"
              placeholder="Search username or email…"
              value={search}
              onChange={e => setSearch(e.target.value)}
              style={{ color: "#fff", backgroundColor: "rgba(255,255,255,0.04)" }}
              className="w-full border border-white/10 rounded-lg pl-8 pr-3 py-2 text-xs outline-none focus:border-cyan-500/50 transition-all"
            />
          </div>
          <select
            value={roleFilter}
            onChange={e => setRoleFilter(e.target.value)}
            style={{ color: roleFilter ? "#fff" : "rgba(255,255,255,0.3)", backgroundColor: "rgba(255,255,255,0.04)" }}
            className="border border-white/10 rounded-lg px-3 py-2 text-xs outline-none focus:border-cyan-500/50 transition-all"
          >
            <option value="" style={{ color: "#fff", backgroundColor: "#0d1421" }}>All Roles</option>
            <option value="admin"   style={{ color: "#fff", backgroundColor: "#0d1421" }}>Admin</option>
            <option value="analyst" style={{ color: "#fff", backgroundColor: "#0d1421" }}>Analyst</option>
            <option value="viewer"  style={{ color: "#fff", backgroundColor: "#0d1421" }}>Viewer</option>
          </select>
        </div>

        {/* Table */}
        <div className="bg-[#0d1421]/80 border border-white/8 rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-white/8 bg-white/[0.02]">
                  <th className="text-left py-3 pl-4 pr-3 text-[10px] font-semibold text-white/30 uppercase tracking-wider">User</th>
                  <th className="text-left py-3 px-3 text-[10px] font-semibold text-white/30 uppercase tracking-wider">Role</th>
                  <th className="text-left py-3 px-3 text-[10px] font-semibold text-white/30 uppercase tracking-wider">Status</th>
                  <th className="text-left py-3 px-3 text-[10px] font-semibold text-white/30 uppercase tracking-wider">Last Login</th>
                  <th className="text-left py-3 px-3 text-[10px] font-semibold text-white/30 uppercase tracking-wider">Created</th>
                  <th className="text-left py-3 pl-3 pr-4 text-[10px] font-semibold text-white/30 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan={6} className="py-16 text-center">
                    <div className="flex flex-col items-center gap-3 text-white/25">
                      <div className="w-5 h-5 border-2 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin" />
                      <span className="text-xs">Loading users…</span>
                    </div>
                  </td></tr>
                ) : filtered.length === 0 ? (
                  <tr><td colSpan={6} className="py-16 text-center">
                    <div className="flex flex-col items-center gap-3 text-white/20">
                      <Users className="h-8 w-8 opacity-30" />
                      <span className="text-xs">{search || roleFilter ? "No users match your filters." : "No users found."}</span>
                    </div>
                  </td></tr>
                ) : (
                  filtered.map(u => (
                    <UserRow key={u.id} u={u} currentUserId={user!.id} onUpdated={fetchUsers} />
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Role matrix legend */}
        <div className="bg-[#0d1421]/50 border border-white/6 rounded-xl p-4">
          <p className="text-[10px] font-semibold text-white/25 uppercase tracking-wider mb-3">Role Permissions Summary</p>
          <div className="grid grid-cols-3 gap-3 text-[11px]">
            {[
              { role: "Viewer",  color: "text-slate-400",  perms: ["Dashboard", "Threat Map", "Attack Logs", "Analytics", "Reports (read)"] },
              { role: "Analyst", color: "text-blue-400",   perms: ["+ IP Intelligence", "+ Incidents (create/update)", "+ WAF Rules (view/suggest)", "+ Reports (generate)"] },
              { role: "Admin",   color: "text-red-400",    perms: ["+ User Management", "+ Audit Logs", "+ System Settings", "+ WAF Rules (deploy)", "+ Reports (schedule)"] },
            ].map(({ role, color, perms }) => (
              <div key={role} className="space-y-1.5">
                <div className={cn("font-semibold", color)}>{role}</div>
                {perms.map(p => <div key={p} className="text-white/30 flex items-start gap-1"><span className="mt-0.5 text-white/15">›</span>{p}</div>)}
              </div>
            ))}
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
