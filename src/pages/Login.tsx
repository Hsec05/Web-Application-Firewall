import { useState, useEffect } from "react";
import { useNavigate, Link } from "react-router-dom";
import { Shield, Activity, Eye, EyeOff, AlertCircle, Loader2 } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import DirectionCaptcha from "../components/DirectionCaptcha";
import { cn } from "@/lib/utils";

function Particles() {
  return (
    <div className="absolute inset-0 overflow-hidden pointer-events-none">
      {Array.from({ length: 20 }).map((_, i) => (
        <div
          key={i}
          className="absolute w-px bg-gradient-to-b from-blue-500/30 to-transparent"
          style={{
            left: `${(i * 5.2 + 2) % 100}%`,
            height: `${60 + (i * 13) % 140}px`,
            top: `${(i * 7.3) % 80}%`,
            animationDelay: `${(i * 0.4) % 3}s`,
            animationDuration: `${3 + (i * 0.3) % 4}s`,
            animation: "float-particle 4s ease-in-out infinite alternate",
            opacity: 0.4 + (i % 3) * 0.15,
          }}
        />
      ))}
      <style>{`
        @keyframes float-particle {
          from { transform: translateY(0) scaleY(1); opacity: 0.3; }
          to   { transform: translateY(-30px) scaleY(1.4); opacity: 0.7; }
        }
        input:-webkit-autofill,
        input:-webkit-autofill:hover,
        input:-webkit-autofill:focus {
          -webkit-text-fill-color: #ffffff !important;
          -webkit-box-shadow: 0 0 0px 1000px #0d1421 inset !important;
          box-shadow: 0 0 0px 1000px #0d1421 inset !important;
          transition: background-color 5000s ease-in-out 0s;
          caret-color: #ffffff;
        }
        .soc-input { color: #ffffff !important; caret-color: #ffffff; background-color: rgba(255,255,255,0.04); }
        .soc-input::placeholder { color: rgba(255,255,255,0.22) !important; }
      `}</style>
    </div>
  );
}

const CAPTCHA_SESSION_KEY = "soc_captcha_verified";

export default function Login() {
  const navigate = useNavigate();
  const { login, isAuthenticated } = useAuth();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  // CAPTCHA: never persisted — always starts unsolved on page load
  const [captchaDone, setCaptchaDone] = useState(false);
  const [showCaptcha, setShowCaptcha] = useState(true); // show immediately on page load
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [loginAttempts, setLoginAttempts] = useState(0);

  useEffect(() => {
    // Clear any stale captcha key from sessionStorage on mount
    sessionStorage.removeItem(CAPTCHA_SESSION_KEY);
  }, []);

  useEffect(() => {
    if (isAuthenticated) navigate("/", { replace: true });
  }, [isAuthenticated, navigate]);

  const handleCaptchaVerified = () => {
    setCaptchaDone(true);
    // Do NOT persist to sessionStorage — captcha is only valid for this login attempt
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    if (!username.trim() || !password) { setError("Please enter your username and password."); return; }
    if (!captchaDone) { setError("Please complete the security check first."); setShowCaptcha(true); return; }
    setLoading(true);
    try {
      await login(username.trim(), password);
      navigate("/", { replace: true });
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Login failed");
      // Reset CAPTCHA after every failed attempt — user must solve it again
      setCaptchaDone(false);
      setShowCaptcha(true);
      setLoginAttempts(n => n + 1);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#070b13] flex items-center justify-center relative overflow-hidden">
      <Particles />
      <div className="absolute inset-0 pointer-events-none" style={{
        backgroundImage: `linear-gradient(rgba(59,130,246,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(59,130,246,0.03) 1px, transparent 1px)`,
        backgroundSize: "60px 60px",
      }} />
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[600px] h-[600px] rounded-full bg-blue-600/5 blur-[120px] pointer-events-none" />

      <div className="relative z-10 w-full max-w-md mx-4">
        <div className="absolute -inset-px rounded-2xl bg-gradient-to-b from-blue-500/20 to-transparent pointer-events-none" />
        <div className="bg-[#0d1421]/95 backdrop-blur-xl border border-white/8 rounded-2xl p-8 shadow-2xl">

          <div className="flex flex-col items-center mb-8">
            <div className="relative mb-3">
              <div className="w-14 h-14 rounded-2xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center shadow-[0_0_30px_rgba(59,130,246,0.2)]">
                <Shield className="h-7 w-7 text-blue-400" />
              </div>
              <Activity className="absolute -top-1.5 -right-1.5 h-4 w-4 text-blue-400 animate-pulse" />
            </div>
            <h1 className="text-2xl font-bold text-white tracking-tight">SecureSOC</h1>
            <p className="text-sm text-white/40 mt-0.5">Sign in to your security console</p>
          </div>

          {error && (
            <div className="flex items-start gap-2.5 bg-red-500/10 border border-red-500/20 rounded-xl px-4 py-3 mb-5 text-red-400 text-sm">
              <AlertCircle className="h-4 w-4 flex-shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-white/50 mb-1.5 uppercase tracking-wide">Username or Email</label>
              <input
                type="text" value={username} onChange={e => setUsername(e.target.value)}
                placeholder="admin" autoComplete="username"
                className="soc-input w-full border border-white/10 rounded-xl px-4 py-2.5 text-sm outline-none focus:border-blue-500/50 transition-all duration-200 hover:border-white/20"
              />
            </div>

            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-xs font-medium text-white/50 uppercase tracking-wide">Password</label>
                <Link to="/forgot-password" className="text-xs text-blue-400/80 hover:text-blue-400 transition-colors">Forgot password?</Link>
              </div>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"} value={password} onChange={e => setPassword(e.target.value)}
                  placeholder="••••••••" autoComplete="current-password"
                  className="soc-input w-full border border-white/10 rounded-xl px-4 py-2.5 pr-10 text-sm outline-none focus:border-blue-500/50 transition-all duration-200 hover:border-white/20"
                />
                <button type="button" onClick={() => setShowPassword(v => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-white/30 hover:text-white/60 transition-colors">
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            {showCaptcha && !captchaDone && (
              <div className="pt-1">
                <DirectionCaptcha onVerified={handleCaptchaVerified} />
              </div>
            )}

            {captchaDone && (
              <div className="flex items-center gap-2 bg-green-500/8 border border-green-500/20 rounded-xl px-4 py-2.5 text-green-400 text-sm">
                <svg className="h-4 w-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
                Security check passed
              </div>
            )}

            <button type="submit" disabled={loading}
              className={cn("w-full py-2.5 rounded-xl font-semibold text-sm transition-all duration-200 mt-2",
                "bg-blue-600 text-white hover:bg-blue-500 active:scale-[0.98]",
                "shadow-[0_0_20px_rgba(59,130,246,0.3)] hover:shadow-[0_0_30px_rgba(59,130,246,0.5)]",
                "disabled:opacity-60 disabled:cursor-not-allowed disabled:scale-100")}>
              {loading ? <span className="flex items-center justify-center gap-2"><Loader2 className="h-4 w-4 animate-spin" /> Signing in…</span> : "Sign In"}
            </button>
          </form>

          <div className="mt-6 pt-5 border-t border-white/6 text-center">
            <p className="text-[11px] text-white/20">SecureSOC · Web Application Firewall Dashboard</p>
            <p className="text-[10px] text-white/15 mt-0.5">Default: admin / admin123</p>
          </div>
        </div>
      </div>
    </div>
  );
}
