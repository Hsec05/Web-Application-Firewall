import { useState, useEffect } from 'react';
import { DashboardLayout } from '@/components/layout/DashboardLayout';
import { getRules, toggleRule, updateRule, type SecurityRule } from '@/lib/api';
import { SeverityBadge } from '@/components/dashboard/SeverityBadge';
import { Switch } from '@/components/ui/switch';
import { Slider } from '@/components/ui/slider';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription } from '@/components/ui/sheet';
import {
  Settings2, Shield, Clock, CheckCircle, RefreshCw,
  Database, Code2, Globe, Zap, Lock, AlertTriangle,
  FileSearch, Server, Bug, ArrowRightLeft, KeyRound,
  ScanSearch, Activity,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { formatTimestamp } from '@/lib/securityUtils';

// ─── Per-category config ──────────────────────────────────────────────────────

interface CategoryConfig {
  icon:           React.ElementType;
  color:          string;
  bg:             string;
  sliderMax:      number;
  sliderStep:     number;
  thresholdLabel: (v: number) => string;
}

const CATEGORY_CONFIG: Record<string, CategoryConfig> = {
  "SQLi":                { icon: Database,      color: "text-red-400",    bg: "bg-red-500/10",    sliderMax: 10,   sliderStep: 1,  thresholdLabel: v => `Block after ${v} SQL injection attempt${v > 1 ? 's' : ''}` },
  "XSS":                 { icon: Code2,         color: "text-orange-400", bg: "bg-orange-500/10", sliderMax: 10,   sliderStep: 1,  thresholdLabel: v => `Block after ${v} XSS payload match${v > 1 ? 'es' : ''}` },
  "Brute Force":         { icon: Lock,          color: "text-yellow-400", bg: "bg-yellow-500/10", sliderMax: 20,   sliderStep: 1,  thresholdLabel: v => `Block after ${v} failed login attempt${v > 1 ? 's' : ''}` },
  "DDoS":                { icon: Activity,      color: "text-blue-400",   bg: "bg-blue-500/10",   sliderMax: 2000, sliderStep: 50, thresholdLabel: v => `Rate-limit at ${v} requests per minute` },
  "Path Traversal":      { icon: FileSearch,    color: "text-amber-400",  bg: "bg-amber-500/10",  sliderMax: 10,   sliderStep: 1,  thresholdLabel: v => `Block after ${v} traversal attempt${v > 1 ? 's' : ''}` },
  "RCE":                 { icon: Zap,           color: "text-red-500",    bg: "bg-red-600/10",    sliderMax: 10,   sliderStep: 1,  thresholdLabel: v => `Block after ${v} execution pattern match${v > 1 ? 'es' : ''}` },
  "CSRF":                { icon: ArrowRightLeft, color: "text-purple-400", bg: "bg-purple-500/10", sliderMax: 10,   sliderStep: 1,  thresholdLabel: v => `Block after ${v} forged request${v > 1 ? 's' : ''} detected` },
  "XXE":                 { icon: Server,        color: "text-red-400",    bg: "bg-red-500/10",    sliderMax: 10,   sliderStep: 1,  thresholdLabel: v => `Block after ${v} XXE payload match${v > 1 ? 'es' : ''}` },
  "SSRF":                { icon: Globe,         color: "text-red-500",    bg: "bg-red-600/10",    sliderMax: 10,   sliderStep: 1,  thresholdLabel: v => `Block after ${v} internal request attempt${v > 1 ? 's' : ''}` },
  "Open Redirect":       { icon: ArrowRightLeft, color: "text-yellow-500", bg: "bg-yellow-500/10", sliderMax: 10,   sliderStep: 1,  thresholdLabel: v => `Block after ${v} suspicious redirect${v > 1 ? 's' : ''}` },
  "NoSQLi":              { icon: Database,      color: "text-green-400",  bg: "bg-green-500/10",  sliderMax: 10,   sliderStep: 1,  thresholdLabel: v => `Block after ${v} NoSQL operator injection${v > 1 ? 's' : ''}` },
  "Prototype Pollution": { icon: Bug,           color: "text-pink-400",   bg: "bg-pink-500/10",   sliderMax: 10,   sliderStep: 1,  thresholdLabel: v => `Block after ${v} prototype manipulation attempt${v > 1 ? 's' : ''}` },
  "HTTP Smuggling":      { icon: AlertTriangle, color: "text-red-400",    bg: "bg-red-500/10",    sliderMax: 10,   sliderStep: 1,  thresholdLabel: v => `Block after ${v} malformed header${v > 1 ? 's' : ''} detected` },
  "Auth":                { icon: KeyRound,      color: "text-red-500",    bg: "bg-red-600/10",    sliderMax: 10,   sliderStep: 1,  thresholdLabel: v => `Block after ${v} tampered token${v > 1 ? 's' : ''} detected` },
  "Recon":               { icon: ScanSearch,    color: "text-sky-400",    bg: "bg-sky-500/10",    sliderMax: 20,   sliderStep: 1,  thresholdLabel: v => `Block after ${v} scanner or probe request${v > 1 ? 's' : ''}` },
};

const DEFAULT_CONFIG: CategoryConfig = {
  icon: Shield, color: "text-muted-foreground", bg: "bg-muted/30",
  sliderMax: 20, sliderStep: 1, thresholdLabel: v => `Trigger after ${v} match${v > 1 ? 'es' : ''}`,
};

function getCfg(category: string): CategoryConfig {
  return CATEGORY_CONFIG[category] ?? DEFAULT_CONFIG;
}

const CATEGORY_ORDER = [
  "SQLi", "XSS", "Brute Force", "DDoS",
  "Path Traversal", "RCE", "CSRF",
  "XXE", "SSRF", "NoSQLi",
  "Open Redirect", "Prototype Pollution", "HTTP Smuggling",
  "Auth", "Recon",
];

const Rules = () => {
  const [rules,            setRules]            = useState<SecurityRule[]>([]);
  const [loading,          setLoading]          = useState(true);
  const [saving,           setSaving]           = useState<string | null>(null);
  const [selectedRule,     setSelectedRule]     = useState<SecurityRule | null>(null);
  const [pendingThreshold, setPendingThreshold] = useState<number | null>(null);
  const [saved,            setSaved]            = useState(false);
  

  const fetchRules = async () => {
    setLoading(true);
    try {
      const result = await getRules();
      setRules(result.data);
    } catch (err) {
      console.error('Failed to fetch rules:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchRules(); }, []);

  const handleToggle = async (ruleId: string, e?: React.MouseEvent) => {
    e?.stopPropagation();
    try {
      const updated = await toggleRule(ruleId);
      setRules(prev => prev.map(r => r.id === ruleId ? updated : r));
      if (selectedRule?.id === ruleId) setSelectedRule(updated);
    } catch (err) {
      console.error('Failed to toggle rule:', err);
    }
  };

  const handleSaveThreshold = async () => {
    if (!selectedRule || pendingThreshold === null) return;
    setSaving(selectedRule.id);
    try {
      const updated = await updateRule(selectedRule.id, { threshold: pendingThreshold });
      setRules(prev => prev.map(r => r.id === selectedRule.id ? updated : r));
      setSelectedRule(updated);
      setPendingThreshold(null);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (err) {
      console.error('Failed to update rule:', err);
    } finally {
      setSaving(null);
    }
  };

  // Sort by canonical order, unknowns fall to end
  const sortedRules = [...rules].sort((a, b) => {
    const ai = CATEGORY_ORDER.indexOf(a.category);
    const bi = CATEGORY_ORDER.indexOf(b.category);
    if (ai !== -1 && bi !== -1) return ai - bi;
    if (ai !== -1) return -1;
    if (bi !== -1) return 1;
    return a.category.localeCompare(b.category);
  });

  const currentThreshold = selectedRule ? (pendingThreshold ?? selectedRule.threshold) : 0;
  const selectedCfg      = selectedRule ? getCfg(selectedRule.category) : null;
  const SelectedIcon      = selectedCfg?.icon ?? Shield;

  return (
    <DashboardLayout>
      <div className="space-y-6">

        {/* ── Header ── */}
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div>
            <h1 className="text-2xl font-bold">Rule Management</h1>
            <p className="text-muted-foreground text-sm mt-1">
              Configure WAF rules and detection thresholds —{' '}
              <span className="text-foreground font-medium">{rules.length} rules</span> across{' '}
              <span className="text-foreground font-medium">
                {new Set(rules.map(r => r.category)).size} categories
              </span>
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant="secondary" className="bg-severity-safe/10 text-severity-safe border border-severity-safe/20">
              <Shield className="h-3 w-3 mr-1" />{rules.filter(r => r.enabled).length} Active
            </Badge>
            <Badge variant="secondary" className="bg-muted text-muted-foreground">
              {rules.filter(r => !r.enabled).length} Disabled
            </Badge>
            <Button variant="ghost" size="sm" onClick={fetchRules} disabled={loading}>
              <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
            </Button>
          </div>
        </div>

        {/* ── Rule grid ── */}
        {loading ? (
          <div className="flex items-center justify-center h-40">
            <div className="animate-spin h-6 w-6 border-2 border-primary border-t-transparent rounded-full" />
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {sortedRules.map((rule) => {
              const cfg  = getCfg(rule.category);
              const Icon = cfg.icon;
              return (
                <div
                  key={rule.id}
                  className={cn("soc-panel transition-all cursor-pointer hover:border-primary/30", !rule.enabled && "opacity-60")}
                  onClick={() => { setSelectedRule(rule); setPendingThreshold(null); setSaved(false); }}
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <div className={cn("p-1.5 rounded-md flex-shrink-0", cfg.bg)}>
                          <Icon className={cn("h-4 w-4", cfg.color)} />
                        </div>
                        <h3 className="font-semibold">{rule.name}</h3>
                      </div>
                      <p className="text-sm text-muted-foreground mb-3">{rule.description}</p>
                      <div className="flex items-center gap-2 flex-wrap">
                        <Badge variant="secondary" className={cn("font-mono text-xs", cfg.bg, cfg.color)}>
                          {rule.category}
                        </Badge>
                        <SeverityBadge severity={rule.severity as any} />
                        <Badge
                          variant="secondary"
                          className={cn(
                            "text-xs",
                            rule.action === "blocked"
                              ? "bg-red-500/10 text-red-400 border-red-500/20"
                              : "bg-green-500/10 text-green-400 border-green-500/20"
                          )}
                        >
                          {rule.action.toUpperCase()}
                        </Badge>
                      </div>
                    </div>
                    <div className="flex-shrink-0" onClick={(e) => handleToggle(rule.id, e)}>
                      <Switch checked={rule.enabled} />
                    </div>
                  </div>
                  <div className="mt-4 pt-4 border-t border-border">
                    <div className="flex items-center justify-between text-sm mb-2">
                      <span className="text-muted-foreground">Threshold</span>
                      <span className="font-mono font-bold">{rule.threshold}</span>
                    </div>
                    <div onClick={(e) => e.stopPropagation()} className="px-1">
                      <Slider
                        value={[rule.threshold]}
                        max={cfg.sliderMax}
                        min={1}
                        step={cfg.sliderStep}
                        disabled
                        className="opacity-50"
                      />
                    </div>
                    <p className="text-xs text-muted-foreground mt-1.5">
                      {cfg.thresholdLabel(rule.threshold)}
                    </p>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* ── Detail sheet ── */}
        <Sheet open={!!selectedRule} onOpenChange={() => setSelectedRule(null)}>
          <SheetContent className="w-[500px] sm:max-w-[500px] bg-card border-border overflow-y-auto">
            {selectedRule && selectedCfg && (
              <>
                <SheetHeader>
                  <div className="flex items-center gap-3">
                    <div className={cn("p-2 rounded-lg", selectedCfg.bg)}>
                      <SelectedIcon className={cn("h-5 w-5", selectedCfg.color)} />
                    </div>
                    <Badge variant="secondary" className={cn("font-mono", selectedCfg.bg, selectedCfg.color)}>
                      {selectedRule.category}
                    </Badge>
                    <SeverityBadge severity={selectedRule.severity as any} />
                  </div>
                  <SheetTitle className="text-xl mt-2">{selectedRule.name}</SheetTitle>
                  <SheetDescription className="font-mono text-xs">{selectedRule.id}</SheetDescription>
                </SheetHeader>

                <div className="mt-6 space-y-6">
                  <div>
                    <div className="text-xs text-muted-foreground uppercase tracking-wide mb-2">Description</div>
                    <p className="text-sm">{selectedRule.description}</p>
                  </div>

                  <div className="flex items-center justify-between p-4 bg-muted/30 rounded-lg">
                    <div>
                      <div className="font-medium">Rule Status</div>
                      <div className="text-sm text-muted-foreground">
                        {selectedRule.enabled ? 'Active and enforcing' : 'Disabled — attacks will pass through'}
                      </div>
                    </div>
                    <Switch checked={selectedRule.enabled} onCheckedChange={() => handleToggle(selectedRule.id)} />
                  </div>

                  <div>
                    <div className="flex items-center justify-between mb-3">
                      <div className="text-xs text-muted-foreground uppercase tracking-wide">Detection Threshold</div>
                      <span className="font-mono font-bold text-lg">{currentThreshold}</span>
                    </div>
                    <Slider
                      value={[currentThreshold]}
                      onValueChange={([v]) => setPendingThreshold(v)}
                      max={selectedCfg.sliderMax}
                      min={1}
                      step={selectedCfg.sliderStep}
                      disabled={!selectedRule.enabled}
                    />
                    <p className="text-xs text-muted-foreground mt-2">
                      {selectedCfg.thresholdLabel(currentThreshold)}
                    </p>
                  </div>

                  <div>
                    <div className="text-xs text-muted-foreground uppercase tracking-wide mb-2">Action</div>
                    <Badge
                      variant="secondary"
                      className={cn(
                        selectedRule.action === "blocked"
                          ? "bg-status-blocked/20 text-status-blocked border-status-blocked/30"
                          : "bg-status-allowed/20 text-status-allowed border-status-allowed/30"
                      )}
                    >
                      {selectedRule.action.toUpperCase()}
                    </Badge>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div className="soc-panel">
                      <div className="text-xs text-muted-foreground uppercase tracking-wide mb-1 flex items-center gap-1">
                        <Clock className="h-3 w-3" />Created
                      </div>
                      <div className="text-sm font-mono">{formatTimestamp(new Date(selectedRule.createdAt))}</div>
                    </div>
                    <div className="soc-panel">
                      <div className="text-xs text-muted-foreground uppercase tracking-wide mb-1 flex items-center gap-1">
                        <Clock className="h-3 w-3" />Updated
                      </div>
                      <div className="text-sm font-mono">{formatTimestamp(new Date(selectedRule.updatedAt))}</div>
                    </div>
                  </div>

                  <Button
                    className="w-full"
                    disabled={!selectedRule.enabled || saving === selectedRule.id || pendingThreshold === null}
                    onClick={handleSaveThreshold}
                  >
                    {saving === selectedRule.id ? (
                      <><div className="animate-spin h-4 w-4 border-2 border-current border-t-transparent rounded-full mr-2" />Saving...</>
                    ) : saved ? (
                      <><CheckCircle className="h-4 w-4 mr-2" />Saved!</>
                    ) : (
                      <><Settings2 className="h-4 w-4 mr-2" />Save Changes</>
                    )}
                  </Button>
                </div>
              </>
            )}
          </SheetContent>
        </Sheet>
      </div>
    </DashboardLayout>
  );
};

export default Rules;
