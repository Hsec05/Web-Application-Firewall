# PostgreSQL Integration Guide — WAF SOC Dashboard

## Step 1: Create the Database in pgAdmin

Open **pgAdmin 4**, then:

1. In the left panel, right-click **Databases** → **Create** → **Database**
2. Set **Database name** to: `waf_dashboard`
3. Set **Owner** to: `postgres` (or your username)
4. Click **Save**

That's it — the app will create all tables automatically when it starts.

---

## Step 2: Configure Your `.env` File

Open `soc-backend/.env` and fill in your credentials:

```env
# Replace YOUR_PASSWORD with your actual pgAdmin/PostgreSQL password
DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/waf_dashboard
```

**Common pgAdmin passwords:** Whatever you set when you installed PostgreSQL.  
If you forgot it, open pgAdmin → right-click your server → **Properties** → **Connection** tab.

---

## Step 3: Install Dependencies

```bash
cd soc-backend
npm install
```

This installs `pg` (the PostgreSQL driver) along with all existing packages.

---

## Step 4: Start the Server

```bash
npm run dev
```

On first startup you'll see:
```
✅  PostgreSQL: Schema ready — loaded 0 blocked IPs
✅  PostgreSQL: Seeded 7 WAF rules
🛡️  SOC Dashboard (PostgreSQL) running
   ✅ http://localhost:5000
   🗄️  Database: waf_dashboard @ localhost
```

The app auto-creates all 5 tables on first run. You can verify in pgAdmin under:  
`waf_dashboard` → **Schemas** → **public** → **Tables**

---

## What Gets Stored Where

| Table | What it stores | Replaces |
|---|---|---|
| `waf_alerts` | Every attack event with device info, Snort SIDs | `store.alerts[]` array |
| `waf_incidents` | Security incidents (open/investigating/resolved) | `store.incidents[]` array |
| `waf_rules` | WAF detection rules, toggles, thresholds | `store.securityRules[]` array |
| `waf_blocked_ips` | Permanently blocked IPs (survives restarts) | `store.blockedIPs` Set |

---

## Viewing Your Data in pgAdmin

After the server runs for a few seconds, open pgAdmin and run these queries:

```sql
-- See latest attacks
SELECT timestamp, attack_type, source_ip, severity, action, device_os, device_browser
FROM waf_alerts
ORDER BY timestamp DESC
LIMIT 20;

-- Attack summary by type
SELECT attack_type, COUNT(*) as total,
       COUNT(*) FILTER (WHERE action = 'blocked') as blocked
FROM waf_alerts
GROUP BY attack_type
ORDER BY total DESC;

-- Top attacking IPs
SELECT source_ip, country, COUNT(*) as attacks,
       COUNT(DISTINCT device_fingerprint) as unique_devices
FROM waf_alerts
GROUP BY source_ip, country
ORDER BY attacks DESC
LIMIT 10;

-- See blocked IPs
SELECT * FROM waf_blocked_ips ORDER BY blocked_at DESC;

-- See all rules
SELECT id, name, enabled, action, severity FROM waf_rules;
```

---

## Troubleshooting

**"password authentication failed"**  
→ Double-check `DB_PASSWORD` in `.env`. It must match your PostgreSQL password.

**"database waf_dashboard does not exist"**  
→ You skipped Step 1. Create the database in pgAdmin first.

**"ECONNREFUSED"**  
→ PostgreSQL isn't running. Open Services (Windows) or run `pg_ctl start`.

**"relation waf_alerts does not exist"**  
→ The tables haven't been created yet. Make sure `initDatabase()` ran (check server startup logs).

---

## How the Integration Works (Technical)

```
Browser Request
     ↓
wafMiddleware.js         ← Detects attack with Snort rules
     ↓
  Logs alert to:
  ├── store.alerts[]     ← In-memory cache (fast, for live feed)
  └── database.js        ← PostgreSQL (persistent, for reports/history)
     ↓
routes/dashboard.js      ← Reads from PostgreSQL with SQL aggregations
routes/alerts.js         ← Queries waf_alerts table with filters
routes/reports.js        ← Uses SQL GROUP BY for charts & PDF data
routes/rules.js          ← CRUD on waf_rules table
routes/incidents.js      ← CRUD on waf_incidents table
routes/ipIntelligence.js ← Reads waf_blocked_ips + queries by IP
```

The in-memory `store.alerts[]` is kept as a small 500-item cache for the live feed widget (so it stays fast). Everything else reads from PostgreSQL.
