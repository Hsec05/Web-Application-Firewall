# 🛡️ Web Application Firewall — SOC Dashboard

<div align="center">

![WAF](https://img.shields.io/badge/WAF-Active-brightgreen?style=for-the-badge&logo=shield)
![Node.js](https://img.shields.io/badge/Node.js-18%2B-339933?style=for-the-badge&logo=node.js)
![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15%2B-336791?style=for-the-badge&logo=postgresql)
![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6?style=for-the-badge&logo=typescript)

**A full-stack, production-grade Web Application Firewall with a real-time SOC (Security Operations Center) dashboard.**

Detect, block, and analyze web attacks in real time — powered by Snort-compatible rules, PostgreSQL persistence, and a rich React UI.

</div>

---

## 📖 Table of Contents

- [What Is This Project?](#-what-is-this-project)
- [Architecture Overview](#-architecture-overview)
- [Features](#-features)
- [Project Structure](#-project-structure)
- [Prerequisites](#-prerequisites)
- [Installation & Setup](#-installation--setup)
  - [Step 1 — Clone the Repository](#step-1--clone-the-repository)
  - [Step 2 — Set Up PostgreSQL](#step-2--set-up-postgresql)
  - [Step 3 — Configure Environment Variables](#step-3--configure-environment-variables)
  - [Step 4 — Install Dependencies](#step-4--install-dependencies)
  - [Step 5 — Start Everything](#step-5--start-everything)
- [Default Login Credentials](#-default-login-credentials)
- [Port Reference](#-port-reference)
- [How It Works — Under the Hood](#-how-it-works--under-the-hood)
  - [The WAF Middleware](#the-waf-middleware)
  - [Snort Rules Engine](#snort-rules-engine)
  - [Incident Engine](#incident-engine)
  - [WAF Configuration & Sensitivity](#waf-configuration--sensitivity)
- [Dashboard Pages](#-dashboard-pages)
- [API Reference](#-api-reference)
- [Database Schema](#-database-schema)
- [Traffic Simulator](#-traffic-simulator)
- [Running Tests](#-running-tests)
- [Environment Variables Reference](#-environment-variables-reference)
- [Troubleshooting](#-troubleshooting)
- [Tech Stack](#-tech-stack)

---

## 🔍 What Is This Project?

This project is a **three-tier web security system** that simulates a real-world deployment of a Web Application Firewall (WAF):

```
[ Internet / Attacker ]
         ↓
[ WAF + SOC Backend ]   ← Port 5000  — inspects every request
         ↓
[  Target Web App   ]   ← Port 3000  — "NexMart" e-commerce site (protected)
         ↑
[ SOC Dashboard UI  ]   ← Port 8080  — real-time monitoring & management
```

- The **Target Site** (`NexMart`) is a deliberately vulnerable mock e-commerce site that acts as the protected application.
- The **WAF** sits in front of it, inspects every HTTP request using Snort-compatible rules, and either logs, monitors, challenges, or blocks the request.
- The **SOC Dashboard** gives security analysts a full-featured UI to monitor threats, manage rules, investigate incidents, and generate PDF reports.

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│                   SOC Dashboard (React)             │
│   Dashboard | Logs | Incidents | Rules | Reports    │
│   ThreatMap | Analytics | IP Intel | Settings       │
│              http://localhost:8080                  │
└──────────────────────┬──────────────────────────────┘
                       │ REST API (JSON)
                       ▼
┌─────────────────────────────────────────────────────┐
│              SOC Backend (Express.js)               │
│                                                     │
│  ┌────────────┐  ┌──────────────┐  ┌─────────────┐ │
│  │ WAF Middle-│  │ Snort Rules  │  │  Incident   │ │
│  │    ware    │→ │   Engine     │  │   Engine    │ │
│  └────────────┘  └──────────────┘  └─────────────┘ │
│  ┌────────────┐  ┌──────────────┐  ┌─────────────┐ │
│  │  GeoIP     │  │  PDF Report  │  │  Traffic    │ │
│  │  Resolver  │  │  Generator   │  │  Simulator  │ │
│  └────────────┘  └──────────────┘  └─────────────┘ │
│              http://localhost:5000                  │
└──────────────────────┬──────────────────────────────┘
                       │ pg driver
                       ▼
┌─────────────────────────────────────────────────────┐
│              PostgreSQL Database                    │
│  waf_alerts | waf_incidents | waf_rules             │
│  waf_blocked_ips | soc_users | soc_settings         │
│              localhost:5432/waf_dashboard           │
└─────────────────────────────────────────────────────┘
                       │ reverse proxy / forward
                       ▼
┌─────────────────────────────────────────────────────┐
│          Target Site — NexMart (Express.js)         │
│   /  /products  /login  /cart  /contact             │
│              http://localhost:3000                  │
└─────────────────────────────────────────────────────┘
```

---

## ✨ Features

### 🔒 WAF Engine
- **Snort-compatible rule engine** — rules written in Snort syntax with PCRE pattern matching
- **14+ attack categories** detected: SQLi, XSS, RCE, Path Traversal, Brute Force, CSRF, DDoS, XXE, SSRF, SSTI, NoSQLi, JWT Tampering, HTTP Smuggling, Open Redirect
- **Device fingerprinting** — detects OS, browser, and attack tools (sqlmap, Nikto, Nmap, Burp Suite, Metasploit, etc.)
- **GeoIP resolution** — maps attacker IPs to countries in real time
- **Four action modes** per rule: `log`, `monitor`, `challenge`, `block`
- **Configurable sensitivity** — Low / Medium / High / Paranoid thresholds
- **IP Whitelisting** — CIDR-range aware whitelist from the UI
- **Automatic IP blocking** with configurable duration (or permanent)

### 📊 SOC Dashboard
- **Real-time Dashboard** with live attack feed, metric cards, and charts
- **Attack Logs** — searchable, filterable log of every WAF event
- **Incidents** — auto-generated and manually created incidents with lifecycle management (Open → Investigating → Resolved)
- **IP Intelligence** — per-IP attack history, AbuseIPDB integration, manual block/unblock
- **Threat Map** — interactive globe + 2D Leaflet map showing attack origins by country
- **Analytics** — time-series request charts, attack type distribution
- **Rules Manager** — full CRUD on WAF rules with enable/disable toggle
- **Reports** — generate and download PDF security reports
- **Audit Logs** — every admin action logged with user, timestamp, and details
- **User Management** — role-based access (admin / analyst), add/remove users
- **System Settings** — live WAF configuration without server restarts

### 🔐 Authentication & Security
- JWT-based authentication with 24-hour token expiry
- Bcrypt password hashing
- Forgot-password / reset-password flow (token-based)
- **Role-Based Access Control (RBAC)** — three distinct roles: `admin`, `analyst`, `viewer`
- Role enforcement on both frontend (sidebar nav filtering) and backend (`requireAdmin` middleware)
- Account deactivation / reactivation without deletion
- Direction-based CAPTCHA challenge for suspicious IPs

---

---

## ✅ Prerequisites

Before you begin, make sure the following are installed on your machine:

| Tool | Version | How to check | Download |
|------|---------|-------------|----------|
| **Node.js** | 18 or higher | `node --version` | [nodejs.org](https://nodejs.org) |
| **npm** | 8 or higher | `npm --version` | Comes with Node.js |
| **PostgreSQL** | 13 or higher | `psql --version` | [postgresql.org](https://www.postgresql.org/download/) |
| **pgAdmin 4** | Any | — | [pgadmin.org](https://www.pgadmin.org/download/) |
| **Git** | Any | `git --version` | [git-scm.com](https://git-scm.com) |

> 💡 **Tip:** If you're on Windows, we recommend using [nvm-windows](https://github.com/coreybutler/nvm-windows) to manage Node versions.

---

## 🚀 Installation & Setup

### Step 1 — Clone the Repository

```bash
git clone https://github.com/Hsec05/Web-Application-Firewall.git
cd Web-Application-Firewall
```

---

### Step 2 — Set Up PostgreSQL

You need to create one empty database. The app will automatically create all tables on first startup.

#### Option A: Using pgAdmin (Recommended for Beginners)

1. Open **pgAdmin 4**
2. In the left panel, expand your server → right-click **Databases** → **Create** → **Database**
3. Set **Database name** to: `waf_dashboard`
4. Set **Owner** to: `postgres` (or your username)
5. Click **Save**

#### Option B: Using the command line

```bash
# Connect to PostgreSQL
psql -U postgres

# Create the database
CREATE DATABASE waf_dashboard;

# Exit
\q
```

> ✅ That's all — the app creates all 6 tables automatically when the backend starts for the first time.

---

### Step 3 — Configure Environment Variables

There are **two** `.env` files that need to be configured.

#### 3a. Backend — `soc-backend/.env`

Open `soc-backend/.env` and update your PostgreSQL credentials:

```env
# ── PostgreSQL Connection ──────────────────────────────────────────
# Option A — Single connection string (recommended):
DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/waf_dashboard

# Option B — Individual fields:
DB_HOST=localhost
DB_PORT=5432
DB_NAME=waf_dashboard
DB_USER=postgres
DB_PASSWORD=YOUR_PASSWORD        # ← Replace with your actual PostgreSQL password

# ── App Settings ────────────────────────────────────────────────────
PORT=5000
FRONTEND_URL=http://localhost:8080
TARGET_SITE=http://localhost:3000

# ── Optional: AbuseIPDB Integration ─────────────────────────────────
# Get a free API key at https://www.abuseipdb.com/api
ABUSEIPDB_API_KEY=your_key_here
```

> 🔑 **Finding your PostgreSQL password:** Open pgAdmin → right-click your server → **Properties** → **Connection** tab.

#### 3b. Frontend — `.env` (root folder)

```env
VITE_API_URL=http://localhost:5000
```

> This file already exists in the repo. Only edit it if you change the backend port.

---

### Step 4 — Install Dependencies

Install dependencies for all three services:

```bash
# 1. Frontend dependencies (from the project root)
npm install

# 2. Backend dependencies
cd soc-backend
npm install
cd ..

# 3. Target site dependencies
cd target-site
npm install
cd ..
```

---

### Step 5 — Start Everything

You have two options:

#### ✅ Option A: One Command (Recommended)

Start all three services simultaneously with a single command from the project root:

```bash
node start.cjs
```

This launches:
- 🟦 **[BACKEND]** → SOC API at `http://localhost:5000`
- 🟩 **[FRONTEND]** → Dashboard UI at `http://localhost:8080`
- 🟨 **[TARGET]** → NexMart e-commerce at `http://localhost:3000`

Press **Ctrl+C** to cleanly stop all three services.

#### Option B: Start Each Service Manually

In three separate terminal windows:

```bash
# Terminal 1 — Backend
cd soc-backend
npm run dev          # Uses nodemon for auto-reload
```

```bash
# Terminal 2 — Frontend
npm run dev          # Starts Vite on port 8080
```

```bash
# Terminal 3 — Target Site
cd target-site
npm start            # Starts NexMart on port 3000
```

---

### ✅ Verify It's Working

Once started, you should see this in the backend logs:

```
✅  PostgreSQL: Schema ready — loaded 0 blocked IPs
✅  PostgreSQL: Seeded 7 WAF rules
🔐  Default admin created  →  admin / admin123
🛡️  SOC Dashboard (PostgreSQL) running
   ✅ http://localhost:5000
   🗄️  Database: waf_dashboard @ localhost
```

Now open your browser and go to: **http://localhost:8080**

---

## 🔑 Default Login Credentials

| Username | Password | Role |
|----------|----------|------|
| `admin` | `admin123` | Admin (full access) |

> ⚠️ **Security Note:** Change the admin password immediately after your first login in a production deployment.

---

## 🌐 Port Reference

| Service | URL | Description |
|---------|-----|-------------|
| SOC Dashboard (UI) | `http://localhost:8080` | React frontend — main interface |
| SOC Backend (API) | `http://localhost:5000` | Express REST API + WAF middleware |
| Target Site | `http://localhost:3000` | NexMart mock e-commerce app |
| PostgreSQL | `localhost:5432` | Database |
| Health Check | `http://localhost:5000/health` | Backend status endpoint |

---

## ⚙️ How It Works — Under the Hood

### The WAF Middleware

Every HTTP request to the backend passes through `wafMiddleware.js` before reaching any route handler. The middleware performs these checks in order:

1. **Extract real IP** — reads `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP` headers (proxy-aware)
2. **Check whitelist** — if the IP is whitelisted in settings, pass through immediately
3. **Check blocked IPs** — if the IP is in `waf_blocked_ips`, return HTTP 403
4. **Rate limiting** — enforces per-IP requests-per-minute cap (configurable)
5. **Snort rule matching** — runs the request payload, headers, URL, and query string through all enabled rules
6. **Device fingerprinting** — detects OS, browser, and attack tools from the User-Agent
7. **GeoIP resolution** — maps the IP to a country
8. **Action enforcement** — based on the matched rule's action: `log`, `monitor`, `challenge`, or `block`
9. **Persist alert** — writes to both the in-memory store (for live feed) and PostgreSQL (for history)

### Snort Rules Engine

The rules engine (`snortRules.js`) implements a Snort-compatible rule syntax. Each rule contains:

```javascript
{
  sid: 1000001,               // Unique rule ID
  rev: 4,                     // Revision number
  action: "alert",            // log | monitor | challenge | block
  category: "SQLi",           // Attack category
  severity: "critical",       // critical | high | medium | low
  priority: 1,                // Rule priority (1 = highest)
  pcre: /UNION.*SELECT/i,     // The PCRE detection pattern
  msg: "SQLi - UNION SELECT", // Human-readable alert message
  reference: "OWASP-SQLi-001" // External reference
}
```

**Supported attack categories out-of-the-box:**

| Category | Examples Detected |
|----------|-------------------|
| SQLi | UNION SELECT, Boolean blind, DROP TABLE, stacked queries |
| XSS | `<script>`, `onerror=`, `javascript:`, DOM-based XSS |
| RCE | `exec()`, `eval()`, shell metacharacters, PHP injections |
| Path Traversal | `../`, `..%2F`, `/etc/passwd`, Windows path traversal |
| Brute Force | Rapid repeated login attempts |
| CSRF | Cross-origin forged form submissions |
| DDoS | Traffic flood patterns |
| XXE | XML External Entity injection |
| SSRF | Internal network access attempts (`169.254.x.x`, `metadata.google`) |
| SSTI | Template injection (`{{7*7}}`, `${7*7}`) |
| NoSQLi | MongoDB operator injection (`$where`, `$gt`) |
| JWT Tampering | `alg:none`, algorithm confusion attacks |
| HTTP Smuggling | `Transfer-Encoding: chunked` desync |
| Open Redirect | `//evil.com`, `/\evil.com` redirects |

### Incident Engine

The incident engine (`incidentEngine.js`) runs automatically every 5 minutes. It:

1. Looks back at the last **60 minutes** of WAF alerts
2. Groups alerts by **attack type**
3. If a group has ≥ 5 alerts, it auto-creates an **Incident** in the database
4. Incident severity is mapped from attack type (e.g., SQLi → Critical, Brute Force → Medium)
5. Incidents can be manually updated through the dashboard (Open → Investigating → Resolved)

### WAF Configuration & Sensitivity

The WAF configuration is stored in `soc_settings` (PostgreSQL) and refreshed every 30 seconds without needing a server restart. Configurable settings include:

| Setting | Default | Description |
|---------|---------|-------------|
| `waf.sensitivity` | `medium` | Rule threshold multiplier (low / medium / high / paranoid) |
| `waf.block_threshold` | `5` | Hits before auto-blocking an IP |
| `waf.log_threshold` | `2` | Hits before escalating from log to monitor |
| `waf.rate_limit_rpm` | `300` | Max requests per minute per IP |
| `waf.block_duration_min` | `60` | Auto-block duration in minutes (0 = permanent) |
| `waf.whitelist_ips` | `[]` | IP addresses / CIDR ranges to always allow |

**Sensitivity multipliers:**

| Level | Multiplier | Effect |
|-------|-----------|--------|
| `low` | 3.0× | Rules need 3× more hits to trigger |
| `medium` | 1.0× | Baseline behavior |
| `high` | 0.5× | Rules trigger at half the threshold |
| `paranoid` | 0.25× | Rules trigger at quarter threshold (minimum 1 hit) |

---

## 📱 Dashboard Pages

| Page | Route | Description |
|------|-------|-------------|
| Dashboard | `/` | Live metrics, attack type chart, recent alerts, top attacking IPs |
| Attack Logs | `/logs` | Full searchable/filterable WAF alert history |
| IP Intelligence | `/ip-intel` | Per-IP deep-dive: history, reputation, block/unblock |
| Analytics | `/analytics` | Request volume over time, attack distribution charts |
| Incidents | `/incidents` | Auto-generated + manual incidents with lifecycle tracking |
| Threat Map | `/threat-map` | Interactive globe & 2D map of attack origins |
| Rules | `/rules` | WAF rule list with enable/disable toggle and full CRUD |
| Reports | `/reports` | Generate & download PDF security reports |
| Audit Logs | `/audit-logs` | Immutable log of every admin action |
| Users | `/users` | User management (admin only) |
| System Settings | `/system-settings` | Live WAF configuration |

---

## 🔐 Role-Based Access Control (RBAC)

The system implements a three-tier RBAC model enforced at both the **backend API level** (JWT middleware) and the **frontend UI level** (sidebar navigation filtering).

### Roles

| Role | Description | Who Gets It |
|------|-------------|-------------|
| `admin` | Full system access — can manage users, change settings, view audit logs | System administrator |
| `analyst` | Operational access — can investigate incidents, manage rules, block IPs | SOC analyst / security engineer |
| `viewer` | Read-only access — can view dashboards, logs, analytics, and reports | Security viewer / management |

### Permission Matrix

| Feature / Page | `admin` | `analyst` | `viewer` |
|----------------|:-------:|:---------:|:--------:|
| Dashboard (`/`) | ✅ | ✅ | ✅ |
| Threat Map (`/threat-map`) | ✅ | ✅ | ✅ |
| Attack Logs (`/logs`) | ✅ | ✅ | ✅ |
| Analytics (`/analytics`) | ✅ | ✅ | ✅ |
| Reports (`/reports`) | ✅ | ✅ | ✅ |
| IP Intelligence (`/ip-intel`) | ✅ | ✅ | ❌ |
| Incidents (`/incidents`) | ✅ | ✅ | ❌ |
| Rules (`/rules`) | ✅ | ✅ | ❌ |
| Users (`/users`) | ✅ | ❌ | ❌ |
| Audit Logs (`/audit-logs`) | ✅ | ❌ | ❌ |
| System Settings (`/system-settings`) | ✅ | ❌ | ❌ |

### How It Is Enforced

**Backend — `requireAdmin` middleware** (in `routes/users.js`, `routes/auditLogs.js`, `routes/settings.js`):

```js
function requireAdmin(req, res, next) {
  const payload = jwt.verify(token, JWT_SECRET);
  if (payload.role !== "admin") return res.status(403).json({ error: "Admin access required" });
  req.authUser = payload;
  next();
}
```

Routes guarded by `requireAdmin`:
- `GET/PATCH/DELETE /api/users` — user management
- `GET /api/audit-logs` — audit trail
- `GET/PATCH /api/settings` — WAF configuration
- `PUT /api/settings/whitelist` — IP whitelist management

**Frontend — Sidebar navigation filtering** (in `src/components/layout/AppSidebar.tsx`):

```ts
// Admin-only pages — only injected into nav when role === 'admin'
...(user?.role === 'admin' ? [
  { title: 'Users',           href: '/users'           },
  { title: 'Audit Logs',      href: '/audit-logs'      },
  { title: 'System Settings', href: '/system-settings' },
] : []),

// Viewer role — restricted to read-only pages only
const viewerAllowedHrefs = new Set(['/', '/threat-map', '/logs', '/analytics', '/reports']);
const navItems = user?.role === 'viewer'
  ? allNavItems.filter(item => viewerAllowedHrefs.has(item.href))
  : allNavItems;
```

### Valid Roles & Default

The backend validates roles on registration and update. Any unrecognised value defaults to `analyst`:

```js
const VALID_ROLES = ["admin", "analyst", "viewer"];
const assignedRole = VALID_ROLES.includes(role) ? role : "analyst";
```

### Account Lifecycle

Accounts can be deactivated without deletion (soft-disable via `is_active = false`). A deactivated user's login attempt is rejected and written to the audit log with `outcome: "failure"`. Admins cannot deactivate or delete their own account.

---

## 🗺️ Use Case Diagram

The diagram below maps every actor to the system use cases they can trigger, including the internal `«includes»` relationships for the WAF core.

```
Actors & their use cases
─────────────────────────────────────────────────────────────────────
Web User          →  Process HTTP Request
Malicious User    →  Process HTTP Request

Security Viewer   →  Generate Reports
                  →  View Dashboard

Security Analyst  →  Generate Reports
                  →  View Dashboard
                  →  Manage WAF Rules
                  →  Review Security Logs

Security Admin    →  Generate Reports
                  →  View Dashboard
                  →  Manage WAF Rules
                  →  Review Security Logs

Internal «includes» relationships (triggered by Process HTTP Request)
─────────────────────────────────────────────────────────────────────
Process HTTP Request  «includes»  Correlate Threats       (incidentEngine.js)
Process HTTP Request  «includes»  Inspect Payloads (Snort) (snortRules.js)
Process HTTP Request  «includes»  Analyze IP Risk          (geoip.js + ipIntelligence)
```

### Actor Descriptions

| Actor | Maps To | Description |
|-------|---------|-------------|
| **Web User** | Anonymous browser | Legitimate traffic passing through the WAF to the target site |
| **Malicious User** | Attacker / scanner | Any source sending attack payloads; WAF detects, logs, and optionally blocks |
| **Security Viewer** | `viewer` role | Read-only observer — views dashboards and reports |
| **Security Analyst** | `analyst` role | Active SOC operator — manages rules, investigates logs and incidents |
| **Security Admin** | `admin` role | Full system control — users, settings, audit trail, all analyst capabilities |

---
---

## 🎭 Traffic Simulator

The project includes a realistic traffic simulator that generates fake attack and normal traffic so you can see the dashboard in action immediately without needing real attackers.

**Start the simulator:**
```bash
# Via the API
curl -X POST http://localhost:5000/api/admin/simulator/start

# Or via the Admin panel in System Settings
```

**Stop the simulator:**
```bash
curl -X POST http://localhost:5000/api/admin/simulator/stop
```

The simulator generates a mix of:
- Normal HTTP requests (to keep the signal-to-noise ratio realistic)
- SQLi attempts
- XSS payloads
- Brute force login attempts
- Path traversal probes
- Scanner user-agent strings (Nikto, sqlmap, etc.)

---

---

## 🌍 Environment Variables Reference

### `soc-backend/.env` (Backend)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | ✅ Yes | — | Full PostgreSQL connection string |
| `DB_HOST` | Alternative | `localhost` | Used if `DATABASE_URL` not set |
| `DB_PORT` | Alternative | `5432` | PostgreSQL port |
| `DB_NAME` | Alternative | `waf_dashboard` | Database name |
| `DB_USER` | Alternative | `postgres` | DB username |
| `DB_PASSWORD` | Alternative | — | DB password |
| `PORT` | No | `5000` | Backend server port |
| `FRONTEND_URL` | No | `http://localhost:8080` | Allowed CORS origin |
| `TARGET_SITE` | No | `http://localhost:3000` | URL the WAF proxies to |
| `JWT_SECRET` | No | *(hardcoded fallback)* | ⚠️ **Change in production!** |
| `JWT_EXPIRES` | No | `24h` | JWT token expiry |
| `ABUSEIPDB_API_KEY` | No | — | For IP reputation lookups |

### `.env` (Frontend / Root)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VITE_API_URL` | Yes | `http://localhost:5000` | Backend API base URL |

---

## 🔧 Troubleshooting

### `password authentication failed for user "postgres"`
Your PostgreSQL password in `.env` doesn't match. Open pgAdmin → right-click server → Properties → Connection to find your password.

### `database "waf_dashboard" does not exist`
You skipped Step 2. Create the database in pgAdmin first, then restart the backend.

### `ECONNREFUSED 127.0.0.1:5432`
PostgreSQL isn't running.
- **Windows:** Search "Services" → find `postgresql-x64-XX` → Start
- **macOS:** `brew services start postgresql`
- **Linux:** `sudo systemctl start postgresql`

### `relation "waf_alerts" does not exist`
Tables haven't been created yet. Make sure the backend started successfully and printed `✅ PostgreSQL: Schema ready`. If the error persists, check your `DATABASE_URL` is pointing to the correct database.

### Frontend shows "Network Error" or blank data
Check that the backend is running on port 5000 and that `VITE_API_URL` in the root `.env` is set to `http://localhost:5000`.

### Port already in use
```bash
# Find and kill the process using port 5000 (Linux/macOS)
lsof -ti:5000 | xargs kill

# Windows
netstat -ano | findstr :5000
taskkill /PID <PID> /F
```

### `node start.cjs` fails on Windows
If you see a permissions error, try running the terminal as Administrator, or use the manual startup method (Option B in Step 5).

---

## 🧰 Tech Stack

### Frontend
| Technology | Purpose |
|-----------|---------|
| React 18 | UI framework |
| TypeScript 5 | Type-safe JavaScript |
| Vite 5 | Build tool & dev server |
| Tailwind CSS 3 | Utility-first styling |
| shadcn/ui + Radix UI | Accessible component library |
| React Router v6 | Client-side routing |
| TanStack Query | Server state & caching |
| Recharts | Charts & data visualization |
| React Globe.gl | 3D threat globe |
| React Leaflet | 2D threat map |
| React Hook Form + Zod | Form handling & validation |

### Backend
| Technology | Purpose |
|-----------|---------|
| Node.js + Express | HTTP server & REST API |
| PostgreSQL + pg driver | Primary database |
| bcryptjs | Password hashing |
| jsonwebtoken | JWT authentication |
| pdfkit | PDF report generation |
| express-rate-limit | Request rate limiting |
| nodemon | Dev auto-reload |
| uuid | Unique ID generation |

---

<div align="center">

Built with ❤️ for security education and SOC simulation.

**[⬆ Back to Top](#-web-application-firewall--soc-dashboard)**

</div>
