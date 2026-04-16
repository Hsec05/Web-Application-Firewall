import { useState, useEffect, useCallback } from "react";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { useAuth } from "@/context/AuthContext";
import {
  Settings, Shield, Bell, FileText, Save,
  Plus, Trash2, CheckCircle, AlertCircle, Loader2,
  ChevronDown, ChevronUp,
  Sliders, Mail, Webhook, Clock,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Switch } from "@/components/ui/switch";

// ─── Types ────────────────────────────────────────────────────────────────────

interface SettingEntry {
  value:       unknown;
  description: string;
  updated_at:  string;
  updated_by:  string | null;
}

type SettingsGroup = Record<string, Record<string, SettingEntry>>;

// ─── Section wrapper ──────────────────────────────────────────────────────────

function Section({
  title, icon: Icon, iconColor, iconBg, children, defaultOpen = true,
}: {
  title: string; icon: React.ElementType; iconColor: string; iconBg: string;
  children: React.ReactNode; defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="bg-[#0d1421]/80 border border-white/8 rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-5 py-4 hover:bg-white/[0.02] transition-colors"
      >
        <div className="flex items-center gap-3">
          <div className={cn("w-8 h-8 rounded-lg flex items-center justify-center", iconBg)}>
            <Icon className={cn("h-4 w-4", iconColor)} />
          </div>
          <span className="font-semibold text-sm text-white">{title}</span>
        </div>
        {open ? <ChevronUp className="h-4 w-4 text-white/30" /> : <ChevronDown className="h-4 w-4 text-white/30" />}
      </button>
      {open && <div className="px-5 pb-5 pt-1 space-y-4 border-t border-white/6">{children}</div>}
    </div>
  );
}

// ─── Field helpers ────────────────────────────────────────────────────────────

function FieldRow({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4 py-2">
      <div className="flex-1 min-w-0">
        <div className="text-sm text-white/80">{label}</div>
        {hint && <div className="text-[11px] text-white/35 mt-0.5">{hint}</div>}
      </div>
      <div className="flex-shrink-0">{children}</div>
    </div>
  );
}

function NumInput({ value, onChange, min, max, step }: { value: number; onChange: (v: number) => void; min?: number; max?: number; step?: number }) {
  return (
    <input
      type="number" value={value} min={min} max={max} step={step}
      onChange={e => onChange(Number(e.target.value))}
      style={{ color: "#fff", backgroundColor: "rgba(255,255,255,0.04)" }}
      className="w-24 border border-white/10 rounded-lg px-3 py-1.5 text-sm text-right font-mono outline-none focus:border-blue-500/50 transition-all"
    />
  );
}

function TextInput({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder?: string }) {
  return (
    <input
      type="text" value={value} placeholder={placeholder}
      onChange={e => onChange(e.target.value)}
      style={{ color: "#fff", backgroundColor: "rgba(255,255,255,0.04)" }}
      className="w-64 border border-white/10 rounded-lg px-3 py-1.5 text-sm font-mono outline-none focus:border-blue-500/50 transition-all placeholder-white/20"
    />
  );
}

function SelectInput({ value, onChange, options }: { value: string; onChange: (v: string) => void; options: { value: string; label: string }[] }) {
  return (
    <select
      value={value}
      onChange={e => onChange(e.target.value)}
      style={{ color: "#fff", backgroundColor: "#0d1421" }}
      className="border border-white/10 rounded-lg px-3 py-1.5 text-sm outline-none focus:border-blue-500/50 transition-all"
    >
      {options.map(o => <option key={o.value} value={o.value} style={{ backgroundColor: "#0d1421" }}>{o.label}</option>)}
    </select>
  );
}

// ─── Whitelist IP manager ─────────────────────────────────────────────────────

function WhitelistManager({ ips, onChange }: { ips: string[]; onChange: (ips: string[]) => void }) {
  const [input, setInput] = useState("");
  const [err,   setErr]   = useState("");

  const add = () => {
    const trimmed = input.trim();
    if (!trimmed) return;
    // Basic IP / CIDR validation
    const ipv4    = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
    const ipv6    = /^[0-9a-fA-F:]+$/;
    if (!ipv4.test(trimmed) && !ipv6.test(trimmed)) {
      setErr("Invalid IP or CIDR (e.g. 10.0.0.1 or 10.0.0.0/8)"); return;
    }
    if (ips.includes(trimmed)) { setErr("Already in whitelist"); return; }
    setErr("");
    setInput("");
    onChange([...ips, trimmed]);
  };

  return (
    <div className="space-y-2">
      <div className="flex gap-2">
        <input
          type="text"
          placeholder="10.0.0.1 or 192.168.0.0/24"
          value={input}
          onChange={e => { setInput(e.target.value); setErr(""); }}
          onKeyDown={e => e.key === "Enter" && add()}
          style={{ color: "#fff", backgroundColor: "rgba(255,255,255,0.04)" }}
          className="flex-1 border border-white/10 rounded-lg px-3 py-1.5 text-sm font-mono outline-none focus:border-blue-500/50 transition-all placeholder-white/20"
        />
        <button
          onClick={add}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600/80 hover:bg-blue-500 text-white text-xs font-medium transition-all"
        >
          <Plus className="h-3.5 w-3.5" /> Add
        </button>
      </div>
      {err && <p className="text-[11px] text-red-400">{err}</p>}
      {ips.length === 0
        ? <p className="text-[11px] text-white/25 italic">No whitelisted IPs — all traffic is inspected.</p>
        : (
          <div className="flex flex-wrap gap-2 mt-1">
            {ips.map(ip => (
              <span key={ip} className="inline-flex items-center gap-1.5 bg-white/5 border border-white/10 rounded-lg px-2.5 py-1 text-xs font-mono text-white/70">
                {ip}
                <button onClick={() => onChange(ips.filter(x => x !== ip))} className="text-white/30 hover:text-red-400 transition-colors">
                  <Trash2 className="h-3 w-3" />
                </button>
              </span>
            ))}
          </div>
        )
      }
    </div>
  );
}

// ─── Page ────────────────────────────────────────────────────────────────────

export default function SystemSettings() {
  const { token, user } = useAuth();

  const [settings, setSettings] = useState<SettingsGroup>({});
  const [loading,  setLoading]  = useState(true);
  const [saving,   setSaving]   = useState(false);
  const [saved,    setSaved]    = useState(false);
  const [error,    setError]    = useState("");

  // Local state for each setting value
  const [vals, setVals] = useState<Record<string, unknown>>({});

  const get = (key: string) => (vals[key] !== undefined ? vals[key] : settings?.thresholds?.[key]?.value ?? settings?.whitelist?.[key]?.value ?? settings?.alerts?.[key]?.value ?? settings?.integrations?.[key]?.value ?? settings?.reports?.[key]?.value);
  const set = (key: string, val: unknown) => setVals(v => ({ ...v, [key]: val }));

  const fetchSettings = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/settings", { headers: { Authorization: `Bearer ${token}` } });
      if (!res.ok) throw new Error();
      const json = await res.json();
      setSettings(json.settings || {});

      // Hydrate local values
      const flat: Record<string, unknown> = {};
      for (const group of Object.values(json.settings || {})) {
        for (const [k, v] of Object.entries(group as Record<string, SettingEntry>)) {
          flat[k] = v.value;
        }
      }
      setVals(flat);
    } catch {
      setError("Failed to load settings. Ensure the backend is running.");
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => { fetchSettings(); }, [fetchSettings]);

  const handleSave = async () => {
    setSaving(true); setError(""); setSaved(false);
    try {
      const res = await fetch("/api/settings", {
        method:  "PATCH",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body:    JSON.stringify({ updates: vals }),
      });
      if (!res.ok) throw new Error();
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch {
      setError("Failed to save settings.");
    } finally {
      setSaving(false);
    }
  };

  // Admin guard
  if (user?.role !== "admin") {
    return (
      <DashboardLayout>
        <div className="flex items-center justify-center min-h-[60vh] flex-col gap-3 text-white/30">
          <Shield className="h-12 w-12 opacity-30" />
          <p className="text-sm">Admin access required to view system settings.</p>
        </div>
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout>
      <div className="px-6 py-6 space-y-6 max-w-4xl">

        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-orange-500/10 border border-orange-500/20 flex items-center justify-center">
              <Settings className="h-5 w-5 text-orange-400" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">System Settings</h1>
              <p className="text-xs text-white/40 mt-0.5">WAF configuration, thresholds, and integrations</p>
            </div>
          </div>
          <button
            onClick={handleSave}
            disabled={saving}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-orange-600 hover:bg-orange-500 text-white text-sm font-medium transition-all disabled:opacity-60 shadow-[0_0_20px_rgba(249,115,22,0.25)]"
          >
            {saving
              ? <><Loader2 className="h-4 w-4 animate-spin" /> Saving…</>
              : saved
              ? <><CheckCircle className="h-4 w-4" /> Saved!</>
              : <><Save className="h-4 w-4" /> Save All Changes</>}
          </button>
        </div>

        {error && (
          <div className="flex items-center gap-2 bg-red-500/10 border border-red-500/20 rounded-xl px-4 py-3 text-red-400 text-sm">
            <AlertCircle className="h-4 w-4 flex-shrink-0" />{error}
          </div>
        )}

        {loading ? (
          <div className="flex items-center justify-center py-20">
            <div className="flex flex-col items-center gap-3 text-white/25">
              <div className="w-5 h-5 border-2 border-orange-500/30 border-t-orange-500 rounded-full animate-spin" />
              <span className="text-xs">Loading settings…</span>
            </div>
          </div>
        ) : (
          <>
            {/* ── WAF Thresholds ─────────────────────────────────────────────── */}
            <Section title="WAF Thresholds" icon={Sliders} iconColor="text-orange-400" iconBg="bg-orange-500/10">
              <FieldRow
                label="Sensitivity Level"
                hint="Overall WAF aggressiveness — affects how many rules are active"
              >
                <SelectInput
                  value={String(get("waf.sensitivity") ?? "medium")}
                  onChange={v => set("waf.sensitivity", v)}
                  options={[
                    { value: "low",     label: "Low — Permissive" },
                    { value: "medium",  label: "Medium — Balanced" },
                    { value: "high",    label: "High — Strict" },
                    { value: "paranoid",label: "Paranoid — Maximum" },
                  ]}
                />
              </FieldRow>
              <div className="border-t border-white/6" />
              <FieldRow label="Auto-Block Threshold" hint="Rule match count before an IP is automatically blocked">
                <NumInput value={Number(get("waf.block_threshold") ?? 5)} onChange={v => set("waf.block_threshold", v)} min={1} max={50} />
              </FieldRow>
              <FieldRow label="Log-Only Threshold" hint="Below this, events are logged but IP not blocked">
                <NumInput value={Number(get("waf.log_threshold") ?? 2)} onChange={v => set("waf.log_threshold", v)} min={1} max={20} />
              </FieldRow>
              <FieldRow label="Global Rate Limit (req/min)" hint="Maximum requests per IP per minute before throttling">
                <NumInput value={Number(get("waf.rate_limit_rpm") ?? 300)} onChange={v => set("waf.rate_limit_rpm", v)} min={10} max={10000} step={50} />
              </FieldRow>
              <FieldRow label="Auto-Block Duration (min)" hint="How long an IP is blocked — set 0 for permanent block">
                <NumInput value={Number(get("waf.block_duration_min") ?? 60)} onChange={v => set("waf.block_duration_min", v)} min={0} max={10080} step={15} />
              </FieldRow>
            </Section>

            {/* ── Whitelisted IPs ────────────────────────────────────────────── */}
            <Section title="Whitelisted IPs / CIDRs" icon={Shield} iconColor="text-green-400" iconBg="bg-green-500/10">
              <p className="text-xs text-white/35 -mt-1">Traffic from these addresses bypasses WAF inspection entirely. Use for trusted internal networks only.</p>
              <WhitelistManager
                ips={Array.isArray(get("waf.whitelist_ips")) ? get("waf.whitelist_ips") as string[] : []}
                onChange={v => set("waf.whitelist_ips", v)}
              />
            </Section>

            {/* ── Alert Notifications ────────────────────────────────────────── */}
            <Section title="Alert Notifications" icon={Bell} iconColor="text-yellow-400" iconBg="bg-yellow-500/10">
              <FieldRow label="Minimum Alert Severity" hint="Only send alerts for events at or above this severity">
                <SelectInput
                  value={String(get("alerts.severity_min") ?? "high")}
                  onChange={v => set("alerts.severity_min", v)}
                  options={[
                    { value: "low",      label: "Low+" },
                    { value: "medium",   label: "Medium+" },
                    { value: "high",     label: "High+" },
                    { value: "critical", label: "Critical only" },
                  ]}
                />
              </FieldRow>

              <div className="border-t border-white/6" />

              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Mail className="h-4 w-4 text-white/40" />
                  <span className="text-sm text-white/80">Email Alerts</span>
                </div>
                <Switch
                  checked={Boolean(get("alerts.email_enabled"))}
                  onCheckedChange={v => set("alerts.email_enabled", v)}
                />
              </div>
              {Boolean(get("alerts.email_enabled")) && (
                <FieldRow label="Recipients" hint="Comma-separated list of email addresses">
                  <TextInput
                    value={String(get("alerts.email_to") ?? "")}
                    onChange={v => set("alerts.email_to", v)}
                    placeholder="soc@company.com, ciso@company.com"
                  />
                </FieldRow>
              )}

              <div className="border-t border-white/6" />

              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Webhook className="h-4 w-4 text-white/40" />
                  <span className="text-sm text-white/80">Webhook Alerts</span>
                </div>
                <Switch
                  checked={Boolean(get("alerts.webhook_enabled"))}
                  onCheckedChange={v => set("alerts.webhook_enabled", v)}
                />
              </div>
              {Boolean(get("alerts.webhook_enabled")) && (
                <FieldRow label="Webhook URL" hint="POST request sent on every qualifying alert">
                  <TextInput
                    value={String(get("alerts.webhook_url") ?? "")}
                    onChange={v => set("alerts.webhook_url", v)}
                    placeholder="https://hooks.example.com/..."
                  />
                </FieldRow>
              )}
            </Section>

            {/* ── Scheduled Reports ──────────────────────────────────────────── */}
            <Section title="Scheduled Reports" icon={FileText} iconColor="text-violet-400" iconBg="bg-violet-500/10" defaultOpen={false}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Clock className="h-4 w-4 text-white/40" />
                  <span className="text-sm text-white/80">Automated Report Delivery</span>
                </div>
                <Switch
                  checked={Boolean(get("reports.schedule_enabled"))}
                  onCheckedChange={v => set("reports.schedule_enabled", v)}
                />
              </div>
              {Boolean(get("reports.schedule_enabled")) && (
                <>
                  <FieldRow label="Report Type" hint="Which report to auto-generate">
                    <SelectInput
                      value={String(get("reports.schedule_type") ?? "weekly")}
                      onChange={v => set("reports.schedule_type", v)}
                      options={[
                        { value: "daily",   label: "Daily Summary" },
                        { value: "weekly",  label: "Weekly Summary" },
                        { value: "threats", label: "Threat Report" },
                        { value: "ips",     label: "IP Report" },
                        { value: "trends",  label: "Trend Analysis" },
                      ]}
                    />
                  </FieldRow>
                  <FieldRow label="Cron Schedule" hint="Standard cron expression (server timezone)">
                    <TextInput
                      value={String(get("reports.schedule_cron") ?? "0 8 * * 1")}
                      onChange={v => set("reports.schedule_cron", v)}
                      placeholder="0 8 * * 1"
                    />
                  </FieldRow>
                  <FieldRow label="Send Report To" hint="Comma-separated email recipients">
                    <TextInput
                      value={String(get("reports.schedule_email") ?? "")}
                      onChange={v => set("reports.schedule_email", v)}
                      placeholder="management@company.com"
                    />
                  </FieldRow>
                </>
              )}
            </Section>

            {/* Save reminder */}
            <div className="flex justify-end pb-4">
              <button
                onClick={handleSave}
                disabled={saving}
                className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-orange-600 hover:bg-orange-500 text-white text-sm font-semibold transition-all disabled:opacity-60 shadow-[0_0_20px_rgba(249,115,22,0.25)]"
              >
                {saving
                  ? <><Loader2 className="h-4 w-4 animate-spin" /> Saving…</>
                  : saved
                  ? <><CheckCircle className="h-4 w-4" /> Saved!</>
                  : <><Save className="h-4 w-4" /> Save All Changes</>}
              </button>
            </div>
          </>
        )}
      </div>
    </DashboardLayout>
  );
}
