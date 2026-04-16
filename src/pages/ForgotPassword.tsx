import { useState } from "react";
import { Link } from "react-router-dom";
import { Shield, Mail, ArrowLeft, CheckCircle2, AlertCircle, Loader2, ExternalLink } from "lucide-react";
import { cn } from "@/lib/utils";

type Stage = "form" | "sent";

export default function ForgotPassword() {
  const [email,   setEmail]   = useState("");
  const [stage,   setStage]   = useState<Stage>("form");
  const [error,   setError]   = useState("");
  const [loading, setLoading] = useState(false);
  // DEV: backend returns the link so you can test without email infra
  const [devLink, setDevLink] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (!email.trim() || !email.includes("@")) {
      setError("Please enter a valid email address.");
      return;
    }

    setLoading(true);
    try {
      const res  = await fetch("/api/auth/forgot-password", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ email: email.trim().toLowerCase() }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Request failed");

      if (data._devResetLink) setDevLink(data._devResetLink);
      setStage("sent");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Something went wrong. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#070b13] flex items-center justify-center relative overflow-hidden">
      <style>{`
        .soc-input { color: #ffffff !important; caret-color: #ffffff; background-color: rgba(255,255,255,0.04); }
        .soc-input::placeholder { color: rgba(255,255,255,0.22) !important; }
      `}</style>
      {/* Background */}
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

          {/* Header */}
          <div className="flex flex-col items-center mb-8">
            <div className="w-14 h-14 rounded-2xl bg-blue-500/10 border border-blue-500/20
                            flex items-center justify-center shadow-[0_0_30px_rgba(59,130,246,0.15)] mb-3">
              {stage === "sent"
                ? <CheckCircle2 className="h-7 w-7 text-green-400" />
                : <Mail className="h-7 w-7 text-blue-400" />
              }
            </div>
            <h1 className="text-xl font-bold text-white tracking-tight">
              {stage === "sent" ? "Check your inbox" : "Reset your password"}
            </h1>
            <p className="text-sm text-white/40 mt-1 text-center leading-relaxed">
              {stage === "sent"
                ? "We've sent a reset link to your email address."
                : "Enter your email and we'll send you a link to create a new password."}
            </p>
          </div>

          {/* ── FORM STAGE ─────────────────────────────────────────────── */}
          {stage === "form" && (
            <>
              {error && (
                <div className="flex items-start gap-2.5 bg-red-500/10 border border-red-500/20
                                rounded-xl px-4 py-3 mb-5 text-red-400 text-sm">
                  <AlertCircle className="h-4 w-4 flex-shrink-0 mt-0.5" />
                  <span>{error}</span>
                </div>
              )}

              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <label className="block text-xs font-medium text-white/50 mb-1.5 uppercase tracking-wide">
                    Email address
                  </label>
                  <input
                    type="email"
                    value={email}
                    onChange={e => setEmail(e.target.value)}
                    placeholder="you@company.com"
                    autoFocus
                    autoComplete="email"
                    className="soc-input w-full border border-white/10 rounded-xl px-4 py-2.5
                               text-sm outline-none focus:border-blue-500/50 transition-all duration-200
                               hover:border-white/20"
                  />
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className={cn(
                    "w-full py-2.5 rounded-xl font-semibold text-sm transition-all duration-200",
                    "bg-blue-600 text-white hover:bg-blue-500 active:scale-[0.98]",
                    "shadow-[0_0_20px_rgba(59,130,246,0.3)]",
                    "disabled:opacity-60 disabled:cursor-not-allowed"
                  )}
                >
                  {loading ? (
                    <span className="flex items-center justify-center gap-2">
                      <Loader2 className="h-4 w-4 animate-spin" /> Sending…
                    </span>
                  ) : (
                    "Send Reset Link"
                  )}
                </button>
              </form>
            </>
          )}

          {/* ── SENT STAGE ─────────────────────────────────────────────── */}
          {stage === "sent" && (
            <div className="space-y-4">
              {/* Info box */}
              <div className="bg-white/3 border border-white/8 rounded-xl p-4 space-y-2.5 text-sm text-white/60">
                <div className="flex items-start gap-2">
                  <span className="text-blue-400 mt-0.5">✓</span>
                  <span>The link is valid for <strong className="text-white/80">1 hour</strong>.</span>
                </div>
                <div className="flex items-start gap-2">
                  <span className="text-blue-400 mt-0.5">✓</span>
                  <span>It can only be used <strong className="text-white/80">once</strong>.</span>
                </div>
                <div className="flex items-start gap-2">
                  <span className="text-blue-400 mt-0.5">✓</span>
                  <span>Check your spam folder if you don't see it.</span>
                </div>
              </div>

              {/* DEV-only: show the reset link so devs can test without real email */}
              {devLink && (
                <div className="bg-yellow-500/8 border border-yellow-500/20 rounded-xl p-4">
                  <p className="text-[11px] text-yellow-400/80 font-semibold mb-2 uppercase tracking-wide">
                    🔧 Dev Mode — Email not sent
                  </p>
                  <p className="text-[11px] text-white/40 mb-2.5 leading-relaxed">
                    In production, the link below would be emailed. For now, use it directly:
                  </p>
                  <a
                    href={devLink}
                    className="flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300
                               font-mono break-all hover:underline transition-colors"
                  >
                    <ExternalLink className="h-3 w-3 flex-shrink-0" />
                    {devLink}
                  </a>
                </div>
              )}

              <button
                onClick={() => { setStage("form"); setEmail(""); setDevLink(null); }}
                className="w-full py-2.5 rounded-xl text-sm font-medium
                           bg-white/5 border border-white/10 text-white/60
                           hover:bg-white/8 hover:text-white transition-all duration-200"
              >
                Use a different email
              </button>
            </div>
          )}

          {/* Back to login */}
          <div className="mt-6 pt-5 border-t border-white/6 text-center">
            <Link
              to="/login"
              className="inline-flex items-center gap-1.5 text-sm text-white/40
                         hover:text-white/70 transition-colors"
            >
              <ArrowLeft className="h-3.5 w-3.5" />
              Back to Sign In
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
