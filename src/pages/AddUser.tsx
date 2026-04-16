import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { UserPlus, Shield, Eye, EyeOff, CheckCircle, AlertCircle, Loader2 } from "lucide-react";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { useAuth } from "@/context/AuthContext";

export default function AddUser() {
  const { token, user } = useAuth();
  const navigate = useNavigate();

  const [form, setForm] = useState({ username: "", email: "", password: "", role: "analyst" });
  const [showPass, setShowPass]   = useState(false);
  const [loading, setLoading]     = useState(false);
  const [success, setSuccess]     = useState("");
  const [error, setError]         = useState("");

  // Only admins can access this page
  if (user?.role !== "admin") {
    return (
      <DashboardLayout>
        <div className="flex items-center justify-center h-full min-h-[60vh] text-white/40 flex-col gap-3">
          <Shield className="h-12 w-12 opacity-30" />
          <p className="text-sm">Admin access required to add users.</p>
        </div>
      </DashboardLayout>
    );
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(""); setSuccess("");
    if (!form.username || !form.email || !form.password) {
      setError("All fields are required."); return;
    }
    if (form.password.length < 8) {
      setError("Password must be at least 8 characters."); return;
    }
    setLoading(true);
    try {
      const res = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify(form),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Registration failed");
      setSuccess(`User "${data.user.username}" created successfully!`);
      setForm({ username: "", email: "", password: "", role: "analyst" });
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to create user");
    } finally {
      setLoading(false);
    }
  };

  const field = (label: string, name: keyof typeof form, type = "text", placeholder = "") => (
    <div>
      <label className="block text-xs font-medium text-white/50 mb-1.5 uppercase tracking-wide">{label}</label>
      {name === "password" ? (
        <div className="relative">
          <input
            type={showPass ? "text" : "password"}
            value={form.password}
            onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
            placeholder={placeholder}
            style={{ color: "#fff", backgroundColor: "rgba(255,255,255,0.04)" }}
            className="w-full border border-white/10 rounded-xl px-4 py-2.5 pr-10 text-sm outline-none focus:border-blue-500/50 transition-all"
          />
          <button type="button" onClick={() => setShowPass(v => !v)}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-white/30 hover:text-white/60">
            {showPass ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
          </button>
        </div>
      ) : (
        <input
          type={type}
          value={form[name]}
          onChange={e => setForm(f => ({ ...f, [name]: e.target.value }))}
          placeholder={placeholder}
          style={{ color: "#fff", backgroundColor: "rgba(255,255,255,0.04)" }}
          className="w-full border border-white/10 rounded-xl px-4 py-2.5 text-sm outline-none focus:border-blue-500/50 transition-all"
        />
      )}
    </div>
  );

  return (
    <DashboardLayout>
      <div className="max-w-lg mx-auto py-10 px-4">
        <div className="flex items-center gap-3 mb-8">
          <div className="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center">
            <UserPlus className="h-5 w-5 text-blue-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">Add New User</h1>
            <p className="text-sm text-white/40 mt-0.5">Create a login account for the SOC dashboard</p>
          </div>
        </div>

        <div className="bg-[#0d1421]/95 border border-white/8 rounded-2xl p-8 shadow-xl">
          {error && (
            <div className="flex items-start gap-2.5 bg-red-500/10 border border-red-500/20 rounded-xl px-4 py-3 mb-5 text-red-400 text-sm">
              <AlertCircle className="h-4 w-4 flex-shrink-0 mt-0.5" /><span>{error}</span>
            </div>
          )}
          {success && (
            <div className="flex items-start gap-2.5 bg-green-500/10 border border-green-500/20 rounded-xl px-4 py-3 mb-5 text-green-400 text-sm">
              <CheckCircle className="h-4 w-4 flex-shrink-0 mt-0.5" /><span>{success}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {field("Username", "username", "text", "e.g. john_doe")}
            {field("Email", "email", "email", "e.g. john@company.com")}
            {field("Password", "password", "password", "Min. 8 characters")}

            <div>
              <label className="block text-xs font-medium text-white/50 mb-1.5 uppercase tracking-wide">Role</label>
              <select
                value={form.role}
                onChange={e => setForm(f => ({ ...f, role: e.target.value }))}
                style={{ color: "#fff", backgroundColor: "#0d1421" }}
                className="w-full border border-white/10 rounded-xl px-4 py-2.5 text-sm outline-none focus:border-blue-500/50 transition-all"
              >
                <option value="analyst">Analyst</option>
                <option value="admin">Admin</option>
                <option value="viewer">Viewer</option>
              </select>
            </div>

            <div className="flex gap-3 pt-2">
              <button type="submit" disabled={loading}
                className="flex-1 py-2.5 rounded-xl font-semibold text-sm bg-blue-600 text-white hover:bg-blue-500 disabled:opacity-60 transition-all shadow-[0_0_20px_rgba(59,130,246,0.3)]">
                {loading
                  ? <span className="flex items-center justify-center gap-2"><Loader2 className="h-4 w-4 animate-spin" />Creating…</span>
                  : <span className="flex items-center justify-center gap-2"><UserPlus className="h-4 w-4" />Create User</span>}
              </button>
              <button type="button" onClick={() => navigate(-1)}
                className="px-5 py-2.5 rounded-xl font-semibold text-sm border border-white/10 text-white/50 hover:text-white hover:border-white/20 transition-all">
                Cancel
              </button>
            </div>
          </form>
        </div>

        <p className="text-xs text-white/25 text-center mt-4">
          Created users can log in immediately with their credentials.
        </p>
      </div>
    </DashboardLayout>
  );
}
