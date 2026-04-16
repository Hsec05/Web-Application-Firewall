/**
 * ThreatMap.tsx — Flat map + 3D Globe with animated attack arcs
 *
 * ─── Changes from original ────────────────────────────────────────────────────
 *  1. Two map modes: "flat" (Leaflet) and "globe" (react-globe.gl)
 *  2. Arcs no longer replay on page reload (session-start gate)
 *  3. Each new attack spawns 5 staggered arcs so single hits look impactful
 */

import { useEffect, useRef, useState, useCallback, lazy, Suspense } from "react";
import { MapContainer, TileLayer, CircleMarker, Popup, useMap } from "react-leaflet";
import "leaflet/dist/leaflet.css";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { Badge } from "@/components/ui/badge";
import { getThreatMapSummary, getThreatMapEvents, type ThreatMapEvent, type ThreatMapCountry, } from "@/lib/api";
import { Shield, Globe, Activity, AlertTriangle, Clock, Wifi, WifiOff, ChevronDown, ChevronUp, Server, Map, } from "lucide-react";
import { cn } from "@/lib/utils";

const GlobeView = lazy(() =>
  import("../pages/ThreatMapGlobe").catch(() => ({
    default: () => (
      <div className="flex items-center justify-center h-full text-white/40 text-sm flex-col gap-3">
        <Globe className="h-10 w-10 opacity-30" />
        <p>Globe view requires: <code className="bg-white/10 px-2 py-0.5 rounded">npm install react-globe.gl</code></p>
      </div>
    ),
  }))
);

const SERVER_LAT = 22.3828;
const SERVER_LNG = 73.1469;

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#eab308",
  low:      "#3b82f6",
  info:     "#6b7280",
};

const ATTACK_ICONS: Record<string, string> = {
  "SQLi":           "💉",
  "XSS":            "📝",
  "Brute Force":    "🔑",
  "DDoS":           "🌊",
  "Path Traversal": "📂",
  "RCE":            "⚡",
  "CSRF":           "🔄",
  "Other":          "⚠️",
};

const TILE_URL         = "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png";
const POLL_MS          = 6000;
const ARC_DURATION     = 2200;
const ARC_LINGER_MS    = 800;
const ARC_POOL_MAX     = 120;
const ARC_REPEAT_COUNT = 5;
const ARC_REPEAT_GAP   = ARC_DURATION + ARC_LINGER_MS + 200;
// Only animate events newer than (sessionStart - this value)
const SESSION_BUFFER_MS = 30_000;

interface Arc {
  id:         string;
  evtId:      string;
  srcLat:     number;
  srcLng:     number;
  dstLat:     number;
  dstLng:     number;
  color:      string;
  startedAt:  number;
  severity:   string;
  attackType: string;
  country:    string;
}

function ArcCanvas({ arcs }: { arcs: Arc[] }) {
  const map       = useMap();
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const rafRef    = useRef<number>(0);
  const arcsRef   = useRef<Arc[]>(arcs);
  arcsRef.current = arcs;

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const resize = () => {
      const c = map.getContainer();
      canvas.width = c.clientWidth;
      canvas.height = c.clientHeight;
    };
    resize();
    map.on("resize moveend zoomend", resize);

    const draw = () => {
      const ctx = canvas.getContext("2d");
      if (!ctx) { rafRef.current = requestAnimationFrame(draw); return; }
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      const now = performance.now();

      for (const arc of arcsRef.current) {
        const elapsed = now - arc.startedAt;
        if (elapsed < 0) continue;
        const total = ARC_DURATION + ARC_LINGER_MS;
        if (elapsed > total) continue;

        const sp  = map.latLngToContainerPoint([arc.srcLat, arc.srcLng]);
        const dp  = map.latLngToContainerPoint([arc.dstLat, arc.dstLng]);
        const src = { x: sp.x, y: sp.y };
        const dst = { x: dp.x, y: dp.y };

        const mx   = (src.x + dst.x) / 2;
        const my   = (src.y + dst.y) / 2;
        const dist = Math.hypot(dst.x - src.x, dst.y - src.y);
        const lift = Math.max(dist * 0.38, 50);
        const cpx  = mx;
        const cpy  = my - lift;

        const travelT = Math.min(elapsed / ARC_DURATION, 1);
        const lingerT = elapsed > ARC_DURATION ? (elapsed - ARC_DURATION) / ARC_LINGER_MS : 0;
        const alpha   = 1 - lingerT;

        // ── Source ripple circle (pulses while arc is traveling) ──────────
        if (travelT < 1) {
          const srcRippleR = 6 + travelT * 10;
          const srcRippleAlpha = (1 - travelT) * 0.6 * alpha;
          ctx.beginPath();
          ctx.arc(src.x, src.y, srcRippleR, 0, Math.PI * 2);
          ctx.strokeStyle = arc.color;
          ctx.lineWidth = 1.5;
          ctx.globalAlpha = srcRippleAlpha;
          ctx.stroke();
          // solid dot at source
          ctx.beginPath();
          ctx.arc(src.x, src.y, 3, 0, Math.PI * 2);
          ctx.fillStyle = arc.color;
          ctx.globalAlpha = alpha * 0.8;
          ctx.fill();
          ctx.globalAlpha = 1;
        }

        // ── Solid continuous arc line ─────────────────────────────────────
        ctx.save();
        ctx.globalAlpha = 0.55 * alpha;
        ctx.strokeStyle = arc.color;
        ctx.lineWidth   = 1.5;
        ctx.setLineDash([]); // solid — no dashes
        ctx.beginPath();
        let started = false;
        const steps = Math.round(60 * travelT);
        for (let i = 0; i <= steps; i++) {
          const t  = i / 60;
          const bx = (1-t)*(1-t)*src.x + 2*(1-t)*t*cpx + t*t*dst.x;
          const by = (1-t)*(1-t)*src.y + 2*(1-t)*t*cpy + t*t*dst.y;
          if (!started) { ctx.moveTo(bx, by); started = true; } else { ctx.lineTo(bx, by); }
        }
        ctx.stroke();
        ctx.restore();

        // ── Moving glow dot along arc ─────────────────────────────────────
        if (travelT < 1) {
          const t  = travelT;
          const px = (1-t)*(1-t)*src.x + 2*(1-t)*t*cpx + t*t*dst.x;
          const py = (1-t)*(1-t)*src.y + 2*(1-t)*t*cpy + t*t*dst.y;
          const glow = ctx.createRadialGradient(px, py, 0, px, py, 12);
          glow.addColorStop(0, arc.color + "cc");
          glow.addColorStop(0.4, arc.color + "44");
          glow.addColorStop(1, arc.color + "00");
          ctx.beginPath();
          ctx.arc(px, py, 12, 0, Math.PI * 2);
          ctx.fillStyle = glow;
          ctx.globalAlpha = alpha;
          ctx.fill();
          ctx.beginPath();
          ctx.arc(px, py, 2.5, 0, Math.PI * 2);
          ctx.fillStyle = "#ffffff";
          ctx.globalAlpha = alpha;
          ctx.fill();
          ctx.globalAlpha = 1;
        }

        // ── Destination impact ripple (only during linger, removed with arc) ─
        if (travelT >= 1 && lingerT < 1) {
          // expanding ring that fades with the arc linger
          const ringR = lingerT * 35;
          const ringAlpha = (1 - lingerT) * 0.7;
          ctx.beginPath();
          ctx.arc(dst.x, dst.y, ringR, 0, Math.PI * 2);
          ctx.strokeStyle = arc.color;
          ctx.lineWidth = 2;
          ctx.globalAlpha = ringAlpha;
          ctx.stroke();
          // second slower ring
          const ring2R = lingerT * 20;
          ctx.beginPath();
          ctx.arc(dst.x, dst.y, ring2R, 0, Math.PI * 2);
          ctx.globalAlpha = ringAlpha * 0.5;
          ctx.stroke();
          ctx.globalAlpha = 1;
        }

        if (travelT >= 1 && lingerT < 0.35) {
          const flashAlpha = (1 - lingerT / 0.35) * 0.55;
          const impact = ctx.createRadialGradient(dst.x, dst.y, 0, dst.x, dst.y, 20);
          impact.addColorStop(0, arc.color + "ff");
          impact.addColorStop(0.5, arc.color + "33");
          impact.addColorStop(1, arc.color + "00");
          ctx.beginPath();
          ctx.arc(dst.x, dst.y, 20, 0, Math.PI * 2);
          ctx.fillStyle = impact;
          ctx.globalAlpha = flashAlpha;
          ctx.fill();
          ctx.globalAlpha = 1;
        }
      }
      rafRef.current = requestAnimationFrame(draw);
    };

    rafRef.current = requestAnimationFrame(draw);
    return () => {
      cancelAnimationFrame(rafRef.current);
      map.off("resize moveend zoomend", resize);
    };
  }, [map]);

  return (
    <canvas ref={canvasRef} style={{
      position: "absolute", top: 0, left: 0,
      width: "100%", height: "100%",
      pointerEvents: "none", zIndex: 500,
    }} />
  );
}

function ServerMarker() {
  return (
    <CircleMarker center={[SERVER_LAT, SERVER_LNG]} radius={10}
      pathOptions={{ color: "#22d3ee", fillColor: "#0ea5e9", fillOpacity: 0.9, weight: 2 }}>
      <Popup>
        <div className="text-sm font-semibold">🖥️ Your Server</div>
        <div className="text-xs text-gray-400 mt-0.5">
          Attack destination · {SERVER_LAT.toFixed(2)}, {SERVER_LNG.toFixed(2)}
        </div>
      </Popup>
    </CircleMarker>
  );
}

function CountryMarker({ country }: { country: ThreatMapCountry }) {
  const dominant = country.critical > 0 ? "critical" : country.high > 0 ? "high" : "medium";
  const color    = SEVERITY_COLORS[dominant];
  const radius   = Math.min(4 + Math.log2(country.total + 1) * 4, 22);
  return (
    <CircleMarker center={[country.latitude, country.longitude]} radius={radius}
      pathOptions={{ color, fillColor: color, fillOpacity: 0.3, weight: 1.5 }}>
      <Popup>
        <div style={{ minWidth: 190, fontFamily: "sans-serif" }}>
          <div style={{ fontWeight: 700, fontSize: 14, color: "#1e293b", marginBottom: 8 }}>
            {country.country}
            <span style={{ fontWeight: 400, fontSize: 11, color: "#64748b", marginLeft: 6 }}>
              ({country.countryCode})
            </span>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "4px 12px", marginBottom: 10 }}>
            <span style={{ fontSize: 11, color: "#64748b" }}>Total</span>
            <span style={{ fontSize: 11, fontWeight: 700, color: "#1e293b", fontFamily: "monospace" }}>{country.total.toLocaleString()}</span>
            <span style={{ fontSize: 11, color: "#64748b" }}>Blocked</span>
            <span style={{ fontSize: 11, fontWeight: 700, color: "#ef4444", fontFamily: "monospace" }}>{country.blocked.toLocaleString()}</span>
            <span style={{ fontSize: 11, color: "#64748b" }}>Critical</span>
            <span style={{ fontSize: 11, fontWeight: 700, color: "#ef4444", fontFamily: "monospace" }}>{country.critical}</span>
            <span style={{ fontSize: 11, color: "#64748b" }}>High</span>
            <span style={{ fontSize: 11, fontWeight: 700, color: "#f97316", fontFamily: "monospace" }}>{country.high}</span>
          </div>
          {country.attackTypes?.length > 0 && (
            <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
              {country.attackTypes.slice(0, 5).map(t => (
                <span key={t} style={{ fontSize: 10, background: "#f1f5f9", color: "#334155", padding: "2px 6px", borderRadius: 4, border: "1px solid #e2e8f0" }}>
                  {ATTACK_ICONS[t] ?? "⚠️"} {t}
                </span>
              ))}
            </div>
          )}
        </div>
      </Popup>
    </CircleMarker>
  );
}

function FeedItem({ event }: { event: ThreatMapEvent }) {
  const ago    = Math.round((Date.now() - new Date(event.timestamp).getTime()) / 1000);
  const agoStr = ago < 60 ? `${ago}s ago` : `${Math.round(ago / 60)}m ago`;
  return (
    <div className="flex items-start gap-2 px-3 py-2 border-b border-white/5 last:border-0 hover:bg-white/5 transition-colors">
      <span className="text-sm mt-0.5 flex-shrink-0">{ATTACK_ICONS[event.attackType] ?? "⚠️"}</span>
      <div className="min-w-0 flex-1">
        <div className="flex items-center justify-between gap-1">
          <span className="text-xs font-semibold truncate text-white/90">{event.attackType}</span>
          <span className="text-[10px] text-white/40 flex-shrink-0">{agoStr}</span>
        </div>
        <div className="text-[11px] font-mono text-white/50 truncate">{event.sourceIP}</div>
        <div className="flex items-center gap-1.5 mt-0.5">
          <span className="text-[10px] text-white/40 truncate">{event.country}</span>
          <span className="ml-auto text-[10px] font-bold flex-shrink-0"
            style={{ color: SEVERITY_COLORS[event.severity] ?? "#6b7280" }}>
            {event.severity.toUpperCase()}
          </span>
          {event.action === "blocked" && (
            <span className="text-[9px] bg-red-500/20 text-red-400 px-1 py-px rounded flex-shrink-0">BLK</span>
          )}
        </div>
      </div>
    </div>
  );
}

type MapMode = "flat" | "globe";

export default function ThreatMap() {
  const [countries,   setCountries]   = useState<ThreatMapCountry[]>([]);
  const [events,      setEvents]      = useState<ThreatMapEvent[]>([]);
  const [arcs,        setArcs]        = useState<Arc[]>([]);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [isLive,      setIsLive]      = useState(true);
  const [minutes,     setMinutes]     = useState(60);
  const [loading,     setLoading]     = useState(true);
  const [feedOpen,    setFeedOpen]    = useState(true);
  const [mapMode,     setMapMode]     = useState<MapMode>("flat");

  const intervalRef      = useRef<ReturnType<typeof setInterval> | null>(null);
  const cleanupRef       = useRef<ReturnType<typeof setInterval> | null>(null);
  const seenIdsRef       = useRef<Set<string>>(new Set());
  const sessionStartRef  = useRef<number>(Date.now());

  const totals = {
    attacks:   countries.reduce((s, c) => s + c.total,    0),
    blocked:   countries.reduce((s, c) => s + c.blocked,  0),
    countries: countries.length,
    critical:  countries.reduce((s, c) => s + c.critical, 0),
  };

  const spawnArcs = useCallback((newEvents: ThreatMapEvent[]) => {
    const now   = performance.now();
    const fresh: Arc[] = [];

    for (const evt of newEvents) {
      if (seenIdsRef.current.has(evt.id)) continue;
      if (evt.latitude == null || evt.longitude == null) continue;

      // ── Only animate truly NEW events (not historical ones loaded on mount)
      const evtTime = new Date(evt.timestamp).getTime();
      if (evtTime < sessionStartRef.current - SESSION_BUFFER_MS) continue;

      seenIdsRef.current.add(evt.id);
      const color = SEVERITY_COLORS[evt.severity] ?? SEVERITY_COLORS.info;

      // ── Spawn ARC_REPEAT_COUNT copies with staggered start times
      for (let i = 0; i < ARC_REPEAT_COUNT; i++) {
        fresh.push({
          id:         `${evt.id}-r${i}`,
          evtId:      evt.id,
          srcLat:     evt.latitude,
          srcLng:     evt.longitude,
          dstLat:     SERVER_LAT,
          dstLng:     SERVER_LNG,
          color,
          startedAt:  now + i * ARC_REPEAT_GAP,
          severity:   evt.severity,
          attackType: evt.attackType,
          country:    evt.country,
        });
      }
    }

    if (!fresh.length) return;
    setArcs(prev => [...fresh, ...prev].slice(0, ARC_POOL_MAX));
  }, []);

  const fetchData = useCallback(async () => {
    try {
      const [sum, evts] = await Promise.all([
        getThreatMapSummary({ minutes }),
        getThreatMapEvents({ minutes, limit: 60 }),
      ]);
      setCountries(sum.countries);
      setEvents(evts.events);
      setLastUpdated(new Date());
      setLoading(false);
      spawnArcs(evts.events);
    } catch {
      setLoading(false);
    }
  }, [minutes, spawnArcs]);

  useEffect(() => {
    seenIdsRef.current      = new Set();
    sessionStartRef.current = Date.now();
    fetchData();
    if (intervalRef.current) clearInterval(intervalRef.current);
    if (isLive) intervalRef.current = setInterval(fetchData, POLL_MS);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [fetchData, isLive]);

  useEffect(() => {
    cleanupRef.current = setInterval(() => {
      const cutoff = performance.now() - ((ARC_REPEAT_COUNT - 1) * ARC_REPEAT_GAP + ARC_DURATION + ARC_LINGER_MS + 500);
      setArcs(prev => prev.filter(a => a.startedAt > cutoff));
    }, 2000);
    return () => { if (cleanupRef.current) clearInterval(cleanupRef.current); };
  }, []);

  const globeArcs = arcs.map(arc => ({
    startLat: arc.srcLat, startLng: arc.srcLng,
    endLat:   arc.dstLat, endLng:   arc.dstLng,
    color:    [arc.color + "cc", "#22d3eeaa"] as [string, string],
    id:       arc.id,
  }));

  const globePoints = countries.map(c => ({
    lat:   c.latitude, lng: c.longitude,
    size:  Math.min(0.25 + Math.log2(c.total + 1) * 0.06, 0.8),
    color: c.critical > 0 ? SEVERITY_COLORS.critical : c.high > 0 ? SEVERITY_COLORS.high : SEVERITY_COLORS.medium,
    label: `${c.country}: ${c.total} attacks`,
  }));

  return (
    <DashboardLayout>
      <div className="relative w-full h-[calc(100vh-0px)] overflow-hidden bg-[#0d0d14]">

        {/* MAP / GLOBE */}
        {mapMode === "flat" ? (
          <MapContainer center={[20, 10]} zoom={2} minZoom={1.5} maxZoom={7}
            style={{ height: "100%", width: "100%", background: "#0d0d14" }}
            zoomControl={true} attributionControl={false} worldCopyJump={false}>
            <TileLayer url={TILE_URL} attribution="" />
            <ArcCanvas arcs={arcs} />
            {countries.map(c => <CountryMarker key={c.countryCode} country={c} />)}
            <ServerMarker />
          </MapContainer>
        ) : (
          <div className="w-full h-full flex items-center justify-center bg-[#02050e]">
            <Suspense fallback={
              <div className="flex items-center gap-3 text-white/40">
                <Activity className="h-5 w-5 animate-spin" />
                <span className="text-sm">Loading globe…</span>
              </div>
            }>
              <GlobeView arcs={globeArcs} points={globePoints} serverLat={SERVER_LAT} serverLng={SERVER_LNG} />
            </Suspense>
          </div>
        )}

        {loading && (
          <div className="absolute inset-0 z-[2000] flex items-center justify-center bg-[#0d0d14]/80 backdrop-blur-sm">
            <div className="flex items-center gap-3 text-white/60">
              <Activity className="h-5 w-5 animate-spin" />
              <span className="text-sm">Loading threat data…</span>
            </div>
          </div>
        )}

        {/* TOP BAR */}
        <div className="absolute top-0 left-0 right-0 z-[1000] flex items-center justify-between px-4 py-2.5
                        bg-gradient-to-b from-black/80 to-transparent pointer-events-none">
          <div className="flex items-center gap-2 pointer-events-auto">
            <Globe className="h-5 w-5 text-blue-400" />
            <span className="font-bold text-white text-base">Live Threat Map</span>
            {isLive && (
              <span className="flex items-center gap-1 text-[11px] text-green-400 bg-green-400/10 border border-green-400/20 px-2 py-0.5 rounded-full">
                <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
                LIVE
              </span>
            )}
            <span className="text-[11px] text-white/30 ml-1">{arcs.length} arc{arcs.length !== 1 ? "s" : ""} active</span>
          </div>

          <div className="flex items-center gap-2 pointer-events-auto">
            {/* Map Mode Toggle */}
            <div className="flex items-center bg-black/60 border border-white/20 rounded-lg overflow-hidden backdrop-blur-sm">
              <button onClick={() => setMapMode("flat")} className={cn(
                "flex items-center gap-1.5 px-3 py-1 text-xs transition-colors",
                mapMode === "flat" ? "bg-blue-500/30 text-blue-300 font-semibold" : "text-white/50 hover:text-white/80"
              )}>
                <Map className="h-3 w-3" /> Flat
              </button>
              <div className="w-px h-5 bg-white/10" />
              <button onClick={() => setMapMode("globe")} className={cn(
                "flex items-center gap-1.5 px-3 py-1 text-xs transition-colors",
                mapMode === "globe" ? "bg-blue-500/30 text-blue-300 font-semibold" : "text-white/50 hover:text-white/80"
              )}>
                <Globe className="h-3 w-3" /> Globe
              </button>
            </div>

            <select value={minutes} onChange={e => setMinutes(Number(e.target.value))}
              className="text-xs bg-black/60 border border-white/20 rounded px-2 py-1 text-white backdrop-blur-sm">
              <option value={15}>Last 15 min</option>
              <option value={60}>Last 1 hour</option>
              <option value={360}>Last 6 hours</option>
              <option value={1440}>Last 24 hours</option>
            </select>

            <button onClick={() => setIsLive(l => !l)} className={cn(
              "flex items-center gap-1.5 text-xs px-3 py-1 rounded border transition-colors backdrop-blur-sm",
              isLive ? "bg-green-400/10 border-green-400/30 text-green-400" : "bg-black/40 border-white/20 text-white/50"
            )}>
              {isLive ? <Wifi className="h-3 w-3" /> : <WifiOff className="h-3 w-3" />}
              {isLive ? "Live" : "Paused"}
            </button>
          </div>
        </div>

        {/* STATS */}
        <div className="absolute bottom-20 left-3 z-[1000] flex flex-col gap-1.5">
          {[
            { icon: Activity,      label: "Attacks",   value: totals.attacks,   color: "text-blue-400"   },
            { icon: Shield,        label: "Blocked",   value: totals.blocked,   color: "text-red-400"    },
            { icon: Globe,         label: "Countries", value: totals.countries, color: "text-yellow-400" },
            { icon: AlertTriangle, label: "Critical",  value: totals.critical,  color: "text-red-500"    },
          ].map(({ icon: Icon, label, value, color }) => (
            <div key={label} className="flex items-center gap-2 bg-black/70 backdrop-blur-sm border border-white/10 rounded-lg px-3 py-1.5 min-w-[130px]">
              <Icon className={cn("h-3.5 w-3.5 flex-shrink-0", color)} />
              <span className="text-[11px] text-white/50">{label}</span>
              <span className="ml-auto text-xs font-mono font-bold text-white">{value.toLocaleString()}</span>
            </div>
          ))}
        </div>

        {/* LEGEND */}
        <div className="absolute bottom-3 left-3 z-[1000] bg-black/70 backdrop-blur-sm border border-white/10 rounded-lg px-3 py-2 flex flex-wrap gap-x-3 gap-y-1">
          {Object.entries(SEVERITY_COLORS).map(([sev, color]) => (
            <div key={sev} className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full" style={{ background: color }} />
              <span className="text-[10px] text-white/60 capitalize">{sev}</span>
            </div>
          ))}
          <div className="flex items-center gap-1">
            <Server className="h-2.5 w-2.5 text-cyan-400" />
            <span className="text-[10px] text-white/60">Your Server</span>
          </div>
        </div>

        {/* TIMESTAMP */}
        {lastUpdated && (
          <div className="absolute bottom-3 right-3 z-[1000] flex items-center gap-1.5 text-[10px] text-white/40 bg-black/50 px-2 py-1 rounded backdrop-blur-sm">
            <Clock className="h-3 w-3" />
            Updated {lastUpdated.toLocaleTimeString()}
          </div>
        )}

        {/* LIVE FEED PANEL */}
        <div className="absolute top-12 right-3 z-[1000] w-72 flex flex-col bg-black/75 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden max-h-[calc(100vh-120px)]">
          <button onClick={() => setFeedOpen(o => !o)}
            className="flex items-center justify-between px-3 py-2.5 border-b border-white/10 hover:bg-white/5 transition-colors w-full">
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-blue-400" />
              <span className="text-xs font-semibold text-white">Live Attack Feed</span>
              <Badge className="text-[10px] font-mono bg-white/10 text-white/70 border-0 px-1.5">{events.length}</Badge>
            </div>
            {feedOpen ? <ChevronUp className="h-3.5 w-3.5 text-white/40" /> : <ChevronDown className="h-3.5 w-3.5 text-white/40" />}
          </button>

          {feedOpen && (
            <div className="overflow-y-auto flex-1 overscroll-contain" style={{ maxHeight: "calc(100vh - 200px)" }}>
              {events.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-28 gap-2 text-white/30">
                  <Globe className="h-6 w-6" />
                  <span className="text-xs">No events in this window</span>
                </div>
              ) : events.map(evt => <FeedItem key={evt.id} event={evt} />)}
            </div>
          )}

          {feedOpen && countries.length > 0 && (
            <div className="border-t border-white/10 px-3 py-2.5">
              <div className="text-[10px] text-white/40 mb-1.5 font-semibold uppercase tracking-wide">Top Countries</div>
              <div className="space-y-1.5">
                {countries.slice(0, 5).map((c, i) => (
                  <div key={c.countryCode} className="flex items-center gap-2 text-[11px]">
                    <span className="text-white/30 font-mono w-3">{i + 1}</span>
                    <span className="text-white/70 truncate flex-1">{c.country}</span>
                    <span className="font-mono font-bold flex-shrink-0" style={{
                      color: c.critical > 0 ? SEVERITY_COLORS.critical : c.high > 0 ? SEVERITY_COLORS.high : SEVERITY_COLORS.medium,
                    }}>{c.total}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </DashboardLayout>
  );
}
