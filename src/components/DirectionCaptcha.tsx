/**
 * DirectionCaptcha — rotate-the-arrow challenge (similar to Microsoft's verification)
 *
 * The user is shown a compass wheel with an arrow and a target direction.
 * They click the rotate buttons until the arrow points in the required direction.
 * Tolerance: ±22.5° (half of one 45° step).
 */

import { useState, useEffect, useCallback } from "react";
import { RotateCcw, RotateCw, CheckCircle2, ShieldCheck } from "lucide-react";
import { cn } from "@/lib/utils";

// ── Directions ─────────────────────────────────────────────────────────────────

const DIRECTIONS = [
  { label: "North",      symbol: "↑", angle: 0   },
  { label: "North-East", symbol: "↗", angle: 45  },
  { label: "East",       symbol: "→", angle: 90  },
  { label: "South-East", symbol: "↘", angle: 135 },
  { label: "South",      symbol: "↓", angle: 180 },
  { label: "South-West", symbol: "↙", angle: 225 },
  { label: "West",       symbol: "←", angle: 270 },
  { label: "North-West", symbol: "↖", angle: 315 },
];

function pickRandom<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function angleDiff(a: number, b: number): number {
  const d = Math.abs((a - b + 360) % 360);
  return Math.min(d, 360 - d);
}

// ── Props ──────────────────────────────────────────────────────────────────────

interface Props {
  onVerified: () => void;
}

// ── Component ──────────────────────────────────────────────────────────────────

export default function DirectionCaptcha({ onVerified }: Props) {
  const [target,   setTarget]   = useState(() => pickRandom(DIRECTIONS));
  const [current,  setCurrent]  = useState(() => pickRandom(DIRECTIONS).angle);
  const [verified, setVerified] = useState(false);
  const [shake,    setShake]    = useState(false);
  const [rotating, setRotating] = useState<"cw" | "ccw" | null>(null);

  // Reset to a new random challenge
  const reset = useCallback(() => {
    const newTarget = pickRandom(DIRECTIONS.filter(d => d.angle !== target.angle));
    // Start at a different random angle so user must actually rotate
    const startAngles = DIRECTIONS.map(d => d.angle).filter(a => angleDiff(a, newTarget.angle) >= 90);
    setTarget(newTarget);
    setCurrent(pickRandom(startAngles));
    setVerified(false);
  }, [target.angle]);

  // Initialise with a proper start angle (not pointing at target)
  useEffect(() => {
    const startAngles = DIRECTIONS.map(d => d.angle).filter(a => angleDiff(a, target.angle) >= 90);
    setCurrent(pickRandom(startAngles));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const rotate = (dir: "cw" | "ccw") => {
    setRotating(dir);
    setTimeout(() => setRotating(null), 150);

    const delta = dir === "cw" ? 45 : -45;
    const next  = (current + delta + 360) % 360;
    setCurrent(next);

    if (angleDiff(next, target.angle) <= 22) {
      // Challenge passed — verified
      setTimeout(onVerified, 600);
      setVerified(true);
    }
  };

  const triggerShake = () => {
    setShake(true);
    setTimeout(() => setShake(false), 500);
  };

  return (
    <div className="bg-[#0f1623] border border-white/10 rounded-2xl p-5 select-none">
      {/* Header */}
      <div className="flex items-center gap-2 mb-4">
        <ShieldCheck className="h-4 w-4 text-blue-400" />
        <span className="text-xs font-semibold text-white/70 tracking-wide uppercase">
            Security Check
          </span>
      </div>

      {/* Instructions */}
      <p className="text-sm text-white/60 mb-5 leading-relaxed">
        Rotate the arrow until it points{" "}
        <span className="text-white font-semibold">
          {target.label} {target.symbol}
        </span>
        , then click{" "}
        <span className="text-blue-400 font-semibold">Confirm</span>.
      </p>

      {/* Compass wheel */}
      <div className="flex flex-col items-center gap-5">
        {/* Dial */}
        <div className="relative">
          {/* Outer ring */}
          <div className="w-[130px] h-[130px] rounded-full border-2 border-white/10 bg-[#0a0f1a]
                          flex items-center justify-center relative shadow-[0_0_30px_rgba(59,130,246,0.08)]">
            {/* Cardinal tick marks */}
            {[0, 45, 90, 135, 180, 225, 270, 315].map((a) => (
              <div
                key={a}
                className="absolute inset-0 flex justify-center"
                style={{ transform: `rotate(${a}deg)` }}
              >
                <div
                  className={cn(
                    "w-px mt-1 rounded-full",
                    angleDiff(a, target.angle) < 1
                      ? "h-4 bg-blue-400"
                      : "h-2.5 bg-white/20"
                  )}
                />
              </div>
            ))}

            {/* Target dot */}
            <div
              className="absolute inset-0 flex justify-center"
              style={{ transform: `rotate(${target.angle}deg)` }}
            >
              <div className="w-2 h-2 rounded-full bg-blue-500/80 mt-[-1px] shadow-[0_0_8px_rgba(59,130,246,0.8)]" />
            </div>

            {/* Rotating arrow */}
            <div
              className={cn(
                "absolute inset-0 flex justify-center items-start transition-all duration-200",
                shake && "animate-[shake_0.4s_ease]"
              )}
              style={{ transform: `rotate(${current}deg)` }}
            >
              <svg
                width="16"
                height="52"
                viewBox="0 0 16 52"
                fill="none"
                className="mt-2"
              >
                {/* Arrow shaft */}
                <rect x="7" y="18" width="2" height="30" rx="1" fill="rgba(255,255,255,0.5)" />
                {/* Arrow head */}
                <polygon
                  points="8,2 15,22 8,16 1,22"
                  fill={verified ? "#22c55e" : "#3b82f6"}
                  className="transition-colors duration-300"
                />
              </svg>
            </div>

            {/* Centre dot */}
            <div className="w-3 h-3 rounded-full bg-white/20 border border-white/30 z-10" />
          </div>

          {/* Verified overlay */}
          {verified && (
            <div className="absolute inset-0 rounded-full bg-green-500/10 border-2 border-green-500/50
                            flex items-center justify-center transition-all duration-300">
              <CheckCircle2 className="h-8 w-8 text-green-400" />
            </div>
          )}
        </div>

        {/* Buttons */}
        <div className="flex items-center gap-3">
          <button
            type="button"
            onMouseDown={() => rotate("ccw")}
            onKeyDown={(e) => e.key === "ArrowLeft" && rotate("ccw")}
            disabled={verified}
            className={cn(
              "flex items-center gap-1.5 px-4 py-2 rounded-xl text-sm font-medium",
              "bg-white/5 border border-white/10 text-white/70",
              "hover:bg-white/10 hover:text-white active:scale-95 transition-all duration-150",
              "disabled:opacity-40 disabled:cursor-not-allowed",
              rotating === "ccw" && "scale-95 bg-white/10"
            )}
          >
            <RotateCcw className="h-3.5 w-3.5" /> Left
          </button>

          <button
            type="button"
            onClick={() => {
              if (!verified) triggerShake();
            }}
            disabled={!verified}
            className={cn(
              "px-5 py-2 rounded-xl text-sm font-semibold transition-all duration-200",
              verified
                ? "bg-green-500 text-white hover:bg-green-400 active:scale-95 shadow-[0_0_20px_rgba(34,197,94,0.4)]"
                : "bg-white/5 border border-white/10 text-white/30 cursor-not-allowed"
            )}
          >
            Confirm ✓
          </button>

          <button
            type="button"
            onMouseDown={() => rotate("cw")}
            onKeyDown={(e) => e.key === "ArrowRight" && rotate("cw")}
            disabled={verified}
            className={cn(
              "flex items-center gap-1.5 px-4 py-2 rounded-xl text-sm font-medium",
              "bg-white/5 border border-white/10 text-white/70",
              "hover:bg-white/10 hover:text-white active:scale-95 transition-all duration-150",
              "disabled:opacity-40 disabled:cursor-not-allowed",
              rotating === "cw" && "scale-95 bg-white/10"
            )}
          >
            Right <RotateCw className="h-3.5 w-3.5" />
          </button>
        </div>

        <p className="text-[10px] text-white/25 text-center">
          Use the buttons above to rotate the arrow · keyboard ← → also works
        </p>
      </div>
    </div>
  );
}
