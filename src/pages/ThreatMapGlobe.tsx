/**
 * ThreatMapGlobe.tsx — Dark stylized 3D globe (no realistic earth texture)
 * - Custom dark canvas globe with glowing grid lines
 * - Solid continuous arcs (no dash gaps)
 * - Ripple rings on both source and server impact
 */

import { useRef, useEffect, useCallback, useState } from "react";
import Globe, { GlobeMethods } from "react-globe.gl";

interface GlobeArc {
  startLat: number;
  startLng: number;
  endLat:   number;
  endLng:   number;
  color:    [string, string];
  id:       string;
}

interface GlobePoint {
  lat:   number;
  lng:   number;
  size:  number;
  color: string;
  label: string;
}

interface RingPoint {
  lat:   number;
  lng:   number;
  color: string;
  maxR:  number;
  speed: number;
}

interface Props {
  arcs:      GlobeArc[];
  points:    GlobePoint[];
  serverLat: number;
  serverLng: number;
}

export default function ThreatMapGlobe({ arcs, points, serverLat, serverLng }: Props) {
  const globeRef = useRef<GlobeMethods | undefined>(undefined);
  const [size, setSize] = useState({ w: window.innerWidth - 280, h: window.innerHeight });
  const [countries, setCountries] = useState<{ features: object[] }>({ features: [] });

  useEffect(() => {
    // Fetch country GeoJSON directly (pre-converted, no topojson dep needed)
    fetch("https://raw.githubusercontent.com/holtzy/D3-graph-gallery/master/DATA/world.geojson")
      .then(r => r.json())
      .then(data => setCountries(data))
      .catch(() => {});
  }, []);

  useEffect(() => {
    const onResize = () => setSize({ w: window.innerWidth - 280, h: window.innerHeight });
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  // Auto-rotate setup
  useEffect(() => {
    const g = globeRef.current;
    if (!g) return;
    g.controls().autoRotate      = true;
    g.controls().autoRotateSpeed = 0.4;
    g.controls().enableZoom      = true;
    g.pointOfView({ lat: serverLat, lng: serverLng, altitude: 2.2 }, 1000);
  }, [serverLat, serverLng]);

  // Build rings: always show server ring + rings at active arc sources
  const rings: RingPoint[] = [
    { lat: serverLat, lng: serverLng, color: "#22d3ee", maxR: 4, speed: 1.8 },
    ...arcs
      .filter((a, i, self) => self.findIndex(b => b.startLat === a.startLat && b.startLng === a.startLng) === i)
      .map(a => ({ lat: a.startLat, lng: a.startLng, color: a.color[0], maxR: 2.5, speed: 1.2 })),
  ];

  const serverPoint = [{
    lat:   serverLat,
    lng:   serverLng,
    size:  0.6,
    color: "#22d3ee",
    label: "🖥️ Your Server",
  }];

  const allPoints = [...serverPoint, ...points];
  const arcColor  = useCallback((arc: object) => (arc as GlobeArc).color, []);

  return (
    <Globe
      ref={globeRef}

      // ── Dark stylized globe with country borders ────────────────────────
      globeImageUrl="//unpkg.com/three-globe/example/img/earth-dark.jpg"
      backgroundColor="#02050e"
      atmosphereColor="#1e3a5f"
      atmosphereAltitude={0.15}
      showGraticules={true}

      // Country polygons for borders
      polygonsData={countries.features}
      polygonCapColor={() => "rgba(10, 22, 40, 0.6)"}
      polygonSideColor={() => "rgba(30, 80, 140, 0.15)"}
      polygonStrokeColor={() => "#1e4a7a"}
      polygonAltitude={0.002}

      // ── Solid continuous arcs ────────────────────────────────────────────
      arcsData={arcs}
      arcStartLat={(d) => (d as GlobeArc).startLat}
      arcStartLng={(d) => (d as GlobeArc).startLng}
      arcEndLat={(d)   => (d as GlobeArc).endLat}
      arcEndLng={(d)   => (d as GlobeArc).endLng}
      arcColor={arcColor}
      arcAltitude={0.25}
      arcStroke={0.8}
      arcDashLength={1}       // full arc — no gaps
      arcDashGap={0}          // no gap between dashes
      arcDashAnimateTime={2200}
      arcLabel={(d) => `${(d as GlobeArc).id.split("-")[0]} attack`}

      // ── Points ──────────────────────────────────────────────────────────
      pointsData={allPoints}
      pointLat={(d)    => (d as GlobePoint).lat}
      pointLng={(d)    => (d as GlobePoint).lng}
      pointColor={(d)  => (d as GlobePoint).color}
      pointAltitude={0.01}
      pointRadius={(d) => (d as GlobePoint).size}
      pointsMerge={false}
      pointLabel={(d)  => (d as GlobePoint).label}

      // ── Rings: server pulse + source ripples ─────────────────────────────
      ringsData={rings}
      ringColor={(d)              => (d as RingPoint).color}
      ringMaxRadius={(d)          => (d as RingPoint).maxR}
      ringPropagationSpeed={(d)   => (d as RingPoint).speed}
      ringRepeatPeriod={1000}

      // ── Size ────────────────────────────────────────────────────────────
      width={size.w}
      height={size.h}
    />
  );
}
