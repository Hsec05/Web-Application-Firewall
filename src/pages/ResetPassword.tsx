import { useState, useEffect } from "react";
import { useSearchParams, Link, useNavigate } from "react-router-dom";
import {
  Shield, Eye, EyeOff, CheckCircle2, AlertCircle,
  Loader2, XCircle, ArrowLeft, KeyRound,
} from "lucide-react";
import { cn } from "@/lib/utils";

type Stage = "validating" | "invalid" | "form" | "success";

function StrengthBar({ password }: { password: string }) {
  const checks = [
    password.length >= 8,
    /[A-Z]/.test(password),
    /[0-9]/.test(password),
    /[^A-Za-z0-9]/.test(password),
  ];
  const score = checks.filter(Boolean).length;
  const colors = ["", "bg-red-500", "bg-orange-500", "bg-yellow-500", "bg-green-500"];
  const labels = ["", "Weak", "Fair", "Good", "Strong"];

  if (!password) return null;

  return (
    <div className="mt-2">
      <div className="flex gap-1 mb-1">
        {[1, 2, 3, 4].map(i => (
          <div
            key={i}
            className={cn(
              "flex-1 h-1 rounded-full transition-all duration-300",
              i <= score ? colors[score] : "bg-white/10"
            )}
          />
        ))}
      </div>
      <p className={cn("text-[10px] font-medium", score >= 3 ? "text-green-400" : "text-white/40")}>
        {labels[score]} password
      </p>
    </div>
  );
}

export default function ResetPassword() {
  const [params]      = useSearchParams();
  const navigate      = useNavigate();
  const token         = params.get("token") ?? "";

  const [stage,       setStage]       = useState<Stage>("validating");
  const [password,    setPassword]    = useState("");
  const [confirm,     setConfirm]     = useState("");
  const [showPwd,     setShowPwd]     = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [error,       setError]       = useState("");
  const [loading,     setLoading]     = useState(false);

  // Validate token on mount
  useEffect(() => {
    if (!token) { setStage("invalid"); return; }
    fetch(`/api/auth/verify-token?token=${encodeURIComponent(token)}`)
      .then(r => r.json())
      .then(d => setStage(d.valid ? "form" : "invalid"))
      .catch(() => setStage("invalid"));
  }, [token]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (password.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }
    if (password !== confirm) {
      setError("Passwords don't match.");
      return;
    }

    setLoading(true);
    try {
      const res  = await fetch("/api/auth/reset-password", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ token, newPassword: password }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Reset failed");
      setStage("success");
      setTimeout(() => navigate("/login"), 3000);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Something went wrong.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#070b13] flex items-center justify-center relative overflow-hidden">
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          backgroundImage: `
            linear-gradient(rgba(59,130,246,0.03) 1px, transparent 1px),
            linear-gradient(90deg, rgba(59,130,246,0.03) 1px, transparent 1px)
          `,
          backgroundSize: "60px 60px",
        }}
      />
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[500px] h-[500px]
                      rounded-full bg-blue-600/4 blur-[100px] pointer-events-none" />

      <div className="relative z-10 w-full max-w-md mx-4">
        <div className="absolute -inset-px rounded-2xl bg-gradient-to-b from-blue-500/15 to-transparent pointer-events-none" />

        <div className="bg-[#0d1421]/95 backdrop-blur-xl border border-white/8 rounded-2xl p-8 shadow-2xl">

          {/* ── VALIDATING ──────────────────────────────────────────────── */}
          {stage === "validating" && (
            <div className="flex flex-col items-center gap-3 py-8 text-white/50">
              <Loader2 className="h-8 w-8 animate-spin text-blue-400" />
              <p className="text-sm">Verifying reset link…</p>
            </div>
          )}

          {/* ── INVALID ─────────────────────────────────────────────────── */}
          {stage === "invalid" && (
            <div className="flex flex-col items-center gap-4 py-4">
              <div className="w-14 h-14 rounded-2xl bg-red-500/10 border border-red-500/20
                              flex items-center justify-center">
                <XCircle className="h-7 w-7 text-red-400" />
              </div>
              <h2 className="text-lg font-bold text-white">Link expired or invalid</h2>
              <p className="text-sm text-white/40 text-center leading-relaxed">
                This reset link has expired or has already been used.
                Reset links are valid for 1 hour and can only be used once.
              </p>
              <Link
                to="/forgot-password"
                className="w-full py-2.5 rounded-xl text-sm font-semibold text-center
                           bg-blue-600 text-white hover:bg-blue-500 transition-all duration-200
                           shadow-[0_0_20px_rgba(59,130,246,0.3)]"
              >
                Request a new link
              </Link>
            </div>
          )}

          {/* ── FORM ────────────────────────────────────────────────────── */}
          {stage === "form" && (
            <>
              <div className="flex flex-col items-center mb-8">
                <div className="w-14 h-14 rounded-2xl bg-blue-500/10 border border-blue-500/20
                                flex items-center justify-center mb-3">
                  <KeyRound className="h-7 w-7 text-blue-400" />
                </div>
                <h1 className="text-xl font-bold text-white">Set a new password</h1>
                <p className="text-sm text-white/40 mt-1 text-center">
                  Choose something strong and unique.
                </p>
              </div>

              {error && (
                <div className="flex items-start gap-2.5 bg-red-500/10 border border-red-500/20
                                rounded-xl px-4 py-3 mb-5 text-red-400 text-sm">
                  <AlertCircle className="h-4 w-4 flex-shrink-0 mt-0.5" />
                  <span>{error}</span>
                </div>
              )}

              <form onSubmit={handleSubmit} className="space-y-4">
                {/* New password */}
                <div>
                  <label className="block text-xs font-medium text-white/50 mb-1.5 uppercase tracking-wide">
                    New Password
                  </label>
                  <div className="relative">
                    <input
                      type={showPwd ? "text" : "password"}
                      value={password}
                      onChange={e => setPassword(e.target.value)}
                      placeholder="At least 8 characters"
                      autoFocus
                      className="soc-input w-full border border-white/10 rounded-xl px-4 py-2.5 pr-10
                                 text-sm outline-none focus:border-blue-500/50 transition-all duration-200"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPwd(v => !v)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-white/30 hover:text-white/60"
                    >
                      {showPwd ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                  <StrengthBar password={password} />
                </div>

                {/* Confirm password */}
                <div>
                  <label className="block text-xs font-medium text-white/50 mb-1.5 uppercase tracking-wide">
                    Confirm Password
                  </label>
                  <div className="relative">
                    <input
                      type={showConfirm ? "text" : "password"}
                      value={confirm}
                      onChange={e => setConfirm(e.target.value)}
                      placeholder="Repeat your password"
                      className={cn(
                        "soc-input w-full border rounded-xl px-4 py-2.5 pr-10",
                        "text-sm outline-none transition-all duration-200",
                        confirm && confirm !== password
                          ? "border-red-500/50"
                          : confirm && confirm === password
                          ? "border-green-500/50"
                          : "border-white/10 focus:border-blue-500/50"
                      )}
                    />
                    <button
                      type="button"
                      onClick={() => setShowConfirm(v => !v)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-white/30 hover:text-white/60"
                    >
                      {showConfirm ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                  {confirm && confirm !== password && (
                    <p className="text-[11px] text-red-400 mt-1">Passwords don't match</p>
                  )}
                </div>

                {/* Requirements */}
                <div className="bg-white/3 border border-white/6 rounded-xl p-3 space-y-1.5">
                  {[
                    [password.length >= 8,        "At least 8 characters"],
                    [/[A-Z]/.test(password),       "One uppercase letter"],
                    [/[0-9]/.test(password),       "One number"],
                    [/[^A-Za-z0-9]/.test(password),"One special character (optional)"],
                  ].map(([met, label]) => (
                    <div key={label as string} className="flex items-center gap-2">
                      <div className={cn(
                        "w-1.5 h-1.5 rounded-full transition-colors duration-300",
                        met ? "bg-green-400" : "bg-white/20"
                      )} />
                      <span className={cn("text-[11px] transition-colors duration-300",
                        met ? "text-green-400" : "text-white/30"
                      )}>
                        {label as string}
                      </span>
                    </div>
                  ))}
                </div>

                <button
                  type="submit"
                  disabled={loading || !password || !confirm}
                  className={cn(
                    "w-full py-2.5 rounded-xl font-semibold text-sm transition-all duration-200",
                    "bg-blue-600 text-white hover:bg-blue-500 active:scale-[0.98]",
                    "shadow-[0_0_20px_rgba(59,130,246,0.3)]",
                    "disabled:opacity-50 disabled:cursor-not-allowed"
                  )}
                >
                  {loading ? (
                    <span className="flex items-center justify-center gap-2">
                      <Loader2 className="h-4 w-4 animate-spin" /> Updating…
                    </span>
                  ) : (
                    "Update Password"
                  )}
                </button>
              </form>
            </>
          )}

          {/* ── SUCCESS ─────────────────────────────────────────────────── */}
          {stage === "success" && (
            <div className="flex flex-col items-center gap-4 py-4">
              <div className="w-14 h-14 rounded-2xl bg-green-500/10 border border-green-500/20
                              flex items-center justify-center shadow-[0_0_30px_rgba(34,197,94,0.2)]">
                <CheckCircle2 className="h-7 w-7 text-green-400" />
              </div>
              <h2 className="text-lg font-bold text-white">Password updated!</h2>
              <p className="text-sm text-white/40 text-center leading-relaxed">
                Your password has been changed successfully.
                Redirecting you to sign in…
              </p>
              <div className="w-full bg-white/5 rounded-full h-1 mt-2">
                <div className="h-1 rounded-full bg-green-500 animate-[grow_3s_linear_forwards]" />
              </div>
              <Link
                to="/login"
                className="flex items-center gap-1.5 text-sm text-blue-400 hover:text-blue-300 transition-colors"
              >
                Go to Sign In now
              </Link>
            </div>
          )}

          {/* Back link */}
          {(stage === "form" || stage === "validating") && (
            <div className="mt-6 pt-5 border-t border-white/6 text-center">
              <Link
                to="/login"
                className="inline-flex items-center gap-1.5 text-sm text-white/30
                           hover:text-white/60 transition-colors"
              >
                <ArrowLeft className="h-3.5 w-3.5" />
                Back to Sign In
              </Link>
            </div>
          )}
        </div>
      </div>

      <style>{`
        @keyframes grow { from { width: 0% } to { width: 100% } }
        .soc-input { color: #ffffff !important; caret-color: #ffffff; background-color: rgba(255,255,255,0.04); }
        .soc-input::placeholder { color: rgba(255,255,255,0.22) !important; }
      `}</style>
    </div>
  );
}
