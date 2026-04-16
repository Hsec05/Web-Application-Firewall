#!/usr/bin/env node
/**
 * start.js — Start everything with one command:
 *   node start.js
 *
 * Starts:
 *   1. SOC Backend  (soc-backend/server.js)  → port 5000
 *   2. Vite Frontend (npm run dev)            → port 8080
 *   3. Target Site   (target-site)            → port 3000
 *
 * Ctrl+C kills all three cleanly.
 */

const { spawn } = require("child_process");
const path = require("path");

const ROOT = __dirname;

// ── ANSI color helpers ───────────────────────────────────────────────────────
const C = {
  reset:  "\x1b[0m",
  bold:   "\x1b[1m",
  red:    "\x1b[31m",
  green:  "\x1b[32m",
  yellow: "\x1b[33m",
  blue:   "\x1b[34m",
  cyan:   "\x1b[36m",
};

function tag(label, color) {
  return `${color}${C.bold}[${label}]${C.reset} `;
}

// ── Process definitions ──────────────────────────────────────────────────────
const processes = [
  {
    name:    "BACKEND",
    color:   C.cyan,
    cwd:     path.join(ROOT, "soc-backend"),
    cmd:     "node",
    args:    ["server.js"],
  },
  {
    name:    "FRONTEND",
    color:   C.green,
    cwd:     ROOT,
    cmd:     "npm",
    args:    ["run", "dev"],
  },
  {
    name:    "TARGET",
    color:   C.yellow,
    cwd:     path.join(ROOT, "target-site"),
    cmd:     "npm",
    args:    ["start"],
    optional: true,   // won't kill everything if target-site folder is missing
  },
];

const children = [];

function startProcess({ name, color, cwd, cmd, args, optional }) {
  const fs = require("fs");
  if (!fs.existsSync(cwd)) {
    if (optional) {
      console.log(`${tag(name, C.yellow)}Directory not found (${cwd}) — skipping.`);
      return null;
    }
    console.error(`${tag(name, C.red)}Directory not found: ${cwd}`);
    process.exit(1);
  }

  const prefix = tag(name, color);
  console.log(`${prefix}Starting: ${cmd} ${args.join(" ")} in ${cwd}`);

  const child = spawn(cmd, args, {
    cwd,
    stdio: "pipe",
    shell: true,
  });

  child.stdout.on("data", (d) =>
    d.toString().split("\n").filter(Boolean).forEach((l) => console.log(`${prefix}${l}`))
  );
  child.stderr.on("data", (d) =>
    d.toString().split("\n").filter(Boolean).forEach((l) => console.error(`${prefix}${C.red}${l}${C.reset}`))
  );
  child.on("exit", (code, signal) => {
    if (signal !== "SIGTERM" && signal !== "SIGINT") {
      console.error(`${prefix}${C.red}Exited unexpectedly (code=${code}, signal=${signal})${C.reset}`);
    }
  });

  return child;
}

// ── Boot ─────────────────────────────────────────────────────────────────────
console.log(`\n${C.bold}${C.blue}🛡️  SOC Dashboard — Starting all services${C.reset}\n`);

for (const def of processes) {
  const child = startProcess(def);
  if (child) children.push(child);
}

console.log(`\n${C.bold}Press Ctrl+C to stop all services.${C.reset}\n`);

// ── Graceful shutdown ────────────────────────────────────────────────────────
function shutdown() {
  console.log(`\n${C.yellow}${C.bold}Shutting down all services…${C.reset}`);
  for (const child of children) {
    try { child.kill("SIGTERM"); } catch { /* already dead */ }
  }
  setTimeout(() => process.exit(0), 800);
}

process.on("SIGINT",  shutdown);
process.on("SIGTERM", shutdown);
