require('dotenv').config();
const express = require('express');
const path    = require('path');
const fs      = require('fs');
const nodemailer = require('nodemailer');
const Anthropic  = require('@anthropic-ai/sdk');
const Stripe     = require('stripe');

// ── OPTIONAL DEPS (installed via package.json) ───────────────
let bcrypt = null, jwt = null, pgPool = null;
try { bcrypt = require('bcryptjs'); } catch {}
try { jwt    = require('jsonwebtoken'); } catch {}

// ── POSTGRESQL INIT ──────────────────────────────────────────
if (process.env.DATABASE_URL) {
  try {
    const { Pool } = require('pg');
    pgPool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false },
    });
    pgPool.query(`
      CREATE TABLE IF NOT EXISTS attorneys (
        id TEXT PRIMARY KEY, name TEXT, firm_name TEXT, bar_number TEXT, bar_state TEXT,
        email TEXT, phone TEXT, license_states TEXT, specialty TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS letters (
        id TEXT PRIMARY KEY, case_ref TEXT UNIQUE, carrier_name TEXT, carrier_email TEXT,
        carrier_mc TEXT, broker_name TEXT, broker_mc TEXT, broker_address TEXT,
        num_trucks INT, total_damages NUMERIC, court TEXT, letter_text TEXT,
        attorney_id TEXT,
        ts TIMESTAMPTZ DEFAULT NOW()
      );
      ALTER TABLE letters ADD COLUMN IF NOT EXISTS attorney_id TEXT;
      CREATE TABLE IF NOT EXISTS broker_reports (
        id SERIAL PRIMARY KEY, broker_mc TEXT, broker_name TEXT, carrier_name TEXT,
        case_ref TEXT, ts TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS client_users (
        id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT,
        password_hash TEXT, google_id TEXT, google_picture TEXT,
        suspended BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMPTZ DEFAULT NOW(), last_login TIMESTAMPTZ
      );
      CREATE TABLE IF NOT EXISTS app_config (
        key TEXT PRIMARY KEY, value TEXT, updated_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS attorney_invites (
        id TEXT PRIMARY KEY, email TEXT NOT NULL, name TEXT,
        specialty TEXT, token TEXT UNIQUE NOT NULL,
        status TEXT DEFAULT 'pending',
        invited_at TIMESTAMPTZ DEFAULT NOW(), accepted_at TIMESTAMPTZ,
        resent_at TIMESTAMPTZ
      );
      ALTER TABLE attorneys ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'active';
      ALTER TABLE attorneys ADD COLUMN IF NOT EXISTS invite_token TEXT;
      CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id SERIAL PRIMARY KEY, user_id INT NOT NULL, token TEXT UNIQUE NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL, used BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `).then(() => console.log('  🗄️  PostgreSQL connected and tables ready'))
      .catch(e => { console.error('PG schema error:', e.message); pgPool = null; });
  } catch(e) {
    console.warn('  ⚠️  pg package not found; using file storage. Run: npm install pg');
  }
}

// ── RESEND CLIENT ─────────────────────────────────────────────
let resendClient = null;
try {
  if (process.env.RESEND_API_KEY) {
    const { Resend } = require('resend');
    resendClient = new Resend(process.env.RESEND_API_KEY);
  }
} catch(e) { /* resend package not installed */ }

const app    = express();
const PORT   = process.env.PORT || 3000;
const stripe = process.env.STRIPE_SECRET_KEY ? Stripe(process.env.STRIPE_SECRET_KEY) : null;

app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

// ── SECURITY HEADERS ──────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');   // SAMEORIGIN allows Google Maps embeds
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// ── SIMPLE RATE LIMITER (no extra packages) ───────────────────
const _rateCounts = new Map();
function rateLimit(windowMs, max) {
  return (req, res, next) => {
    const key   = req.ip + req.path;
    const now   = Date.now();
    const entry = _rateCounts.get(key) || { count: 0, reset: now + windowMs };
    if (now > entry.reset) { entry.count = 0; entry.reset = now + windowMs; }
    entry.count++;
    _rateCounts.set(key, entry);
    if (entry.count > max) return res.status(429).json({ error: 'Too many requests. Please wait a moment.' });
    next();
  };
}
setInterval(() => _rateCounts.clear(), 600000);

// ── HEALTH CHECK ──────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    uptime: Math.floor(process.uptime()),
    anthropic:  !!process.env.ANTHROPIC_API_KEY,
    stripe:     !!process.env.STRIPE_SECRET_KEY,
    resend:     !!resendClient,
    smtp:       !!process.env.SMTP_USER,
    googleMaps: !!process.env.GOOGLE_MAPS_API_KEY,
    ts: new Date().toISOString(),
  });
});

// ── DATA FILES (JSON fallback) ────────────────────────────────
const DATA_DIR = process.env.NODE_ENV === 'production'
  ? '/tmp/freightguard-data'
  : path.join(__dirname, 'data');

const ATTORNEYS_FILE    = path.join(DATA_DIR, 'attorneys.json');
const UPLOADS_DIR       = path.join(DATA_DIR, 'uploads');
const REPORTS_FILE      = path.join(DATA_DIR, 'broker-reports.json');
const FOLLOWUPS_FILE    = path.join(DATA_DIR, 'followups.json');
const STATUSES_FILE     = path.join(DATA_DIR, 'statuses.json');
const INVITES_FILE      = path.join(DATA_DIR, 'attorney_invites.json');
function loadInvites()   { return loadJSON(INVITES_FILE); }
function saveInvites(d)  { saveJSON(INVITES_FILE, d); }
const RESPONSES_FILE    = path.join(DATA_DIR, 'responses.json');
function loadStatuses()   { return loadJSON(STATUSES_FILE);   }
function saveStatuses(d)  { saveJSON(STATUSES_FILE, d);       }
function loadResponses()  { return loadJSON(RESPONSES_FILE);  }
function saveResponses(d) { saveJSON(RESPONSES_FILE, d);      }
const USERS_FILE        = path.join(DATA_DIR, 'users.json');
const LETTERS_FILE      = path.join(DATA_DIR, 'letters.json');
const CLIENT_USERS_FILE = path.join(DATA_DIR, 'client-users.json');
const CONFIG_FILE       = path.join(DATA_DIR, 'config.json');

try {
  if (!fs.existsSync(DATA_DIR))          fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(ATTORNEYS_FILE))    fs.writeFileSync(ATTORNEYS_FILE,    '[]');
  if (!fs.existsSync(REPORTS_FILE))      fs.writeFileSync(REPORTS_FILE,      '[]');
  if (!fs.existsSync(FOLLOWUPS_FILE))    fs.writeFileSync(FOLLOWUPS_FILE,    '[]');
  if (!fs.existsSync(USERS_FILE))        fs.writeFileSync(USERS_FILE,        '[]');
  if (!fs.existsSync(LETTERS_FILE))      fs.writeFileSync(LETTERS_FILE,      '[]');
  if (!fs.existsSync(CLIENT_USERS_FILE)) fs.writeFileSync(CLIENT_USERS_FILE, '[]');
  if (!fs.existsSync(CONFIG_FILE))       fs.writeFileSync(CONFIG_FILE,       '{}');
} catch(e) {
  console.error('Warning: could not initialize data directory:', e.message);
}

function loadJSON(file)       { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return []; } }
function saveJSON(file, data) { try { fs.writeFileSync(file, JSON.stringify(data, null, 2)); } catch {} }

// ── RUNTIME CONFIG (env > DB config > JSON config file) ──────
function cfg(key) {
  // Environment variable takes priority
  if (process.env[key]) return process.env[key];
  // Fall back to JSON config file
  try {
    const config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
    return config[key] || '';
  } catch { return ''; }
}

async function saveConfig(updates) {
  try {
    const config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
    Object.assign(config, updates);
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
  } catch {}
  // Also persist to PG if available
  if (pgPool) {
    for (const [key, value] of Object.entries(updates)) {
      await pgPool.query(
        'INSERT INTO app_config(key, value, updated_at) VALUES($1,$2,NOW()) ON CONFLICT(key) DO UPDATE SET value=$2, updated_at=NOW()',
        [key, String(value)]
      ).catch(() => {});
    }
  }
}

// ── DATA ACCESS (PG primary, JSON fallback) ───────────────────
async function loadAttorneys() {
  if (pgPool) {
    const r = await pgPool.query('SELECT * FROM attorneys ORDER BY created_at DESC').catch(() => null);
    if (r) return r.rows.map(row => ({
      id: row.id, name: row.name, firmName: row.firm_name, barNumber: row.bar_number,
      barState: row.bar_state, email: row.email, phone: row.phone,
      licenseStates: row.license_states, specialty: row.specialty,
      createdAt: row.created_at,
    }));
  }
  return loadJSON(ATTORNEYS_FILE);
}

async function addAttorneyDB(a) {
  if (pgPool) {
    await pgPool.query(
      'INSERT INTO attorneys(id,name,firm_name,bar_number,bar_state,email,phone,license_states,specialty) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',
      [a.id, a.name, a.firmName||'', a.barNumber||'', a.barState||'', a.email||'', a.phone||'', a.licenseStates||'', a.specialty||'']
    );
    return;
  }
  const list = loadJSON(ATTORNEYS_FILE); list.push(a); saveJSON(ATTORNEYS_FILE, list);
}

async function deleteAttorneyDB(id) {
  if (pgPool) { await pgPool.query('DELETE FROM attorneys WHERE id=$1', [id]); return; }
  saveJSON(ATTORNEYS_FILE, loadJSON(ATTORNEYS_FILE).filter(a => a.id !== id));
}

async function loadLetters() {
  if (pgPool) {
    const r = await pgPool.query('SELECT * FROM letters ORDER BY ts DESC').catch(() => null);
    if (r) return r.rows.map(row => ({
      id: row.id, caseRef: row.case_ref, carrierName: row.carrier_name,
      carrierEmail: row.carrier_email, carrierMC: row.carrier_mc,
      brokerName: row.broker_name, brokerMC: row.broker_mc,
      brokerAddress: row.broker_address, numTrucks: row.num_trucks,
      totalDamages: row.total_damages, court: row.court,
      letterText: row.letter_text, attorneyId: row.attorney_id, ts: row.ts,
    }));
  }
  return loadJSON(LETTERS_FILE);
}

async function addLetterDB(l) {
  if (pgPool) {
    await pgPool.query(
      'INSERT INTO letters(id,case_ref,carrier_name,carrier_email,carrier_mc,broker_name,broker_mc,broker_address,num_trucks,total_damages,court,letter_text,attorney_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)',
      [l.caseRef, l.caseRef, l.carrierName, l.carrierEmail, l.carrierMC, l.brokerName, l.brokerMC, l.brokerAddress, l.numTrucks, l.totalDamages, l.court, l.letterText, l.attorneyId || null]
    ).catch(async () => {
      // Duplicate — update instead
      await pgPool.query('UPDATE letters SET letter_text=$1 WHERE case_ref=$2', [l.letterText, l.caseRef]);
    });
    return;
  }
  const list = loadJSON(LETTERS_FILE); list.push(l); saveJSON(LETTERS_FILE, list);
}

async function loadReports() {
  if (pgPool) {
    const r = await pgPool.query('SELECT * FROM broker_reports ORDER BY ts DESC').catch(() => null);
    if (r) return r.rows.map(row => ({
      id: row.id, brokerMC: row.broker_mc, brokerName: row.broker_name,
      carrierName: row.carrier_name, caseRef: row.case_ref, ts: row.ts,
    }));
  }
  return loadJSON(REPORTS_FILE);
}

async function recordBrokerReportDB(brokerMC, brokerName, carrierName, caseRef) {
  if (pgPool) {
    await pgPool.query(
      'INSERT INTO broker_reports(broker_mc,broker_name,carrier_name,case_ref) VALUES($1,$2,$3,$4)',
      [String(brokerMC).trim(), brokerName, carrierName, caseRef]
    ).catch(() => {});
    return;
  }
  const reports = loadJSON(REPORTS_FILE);
  reports.push({ brokerMC: String(brokerMC).trim(), brokerName, carrierName, caseRef, ts: new Date().toISOString() });
  saveJSON(REPORTS_FILE, reports);
}

// ── CLIENT USER DB HELPERS ────────────────────────────────────
async function dbGetUserByEmail(email) {
  if (pgPool) {
    const r = await pgPool.query('SELECT * FROM client_users WHERE email=$1', [email]).catch(() => null);
    return r?.rows[0] || null;
  }
  return loadJSON(CLIENT_USERS_FILE).find(u => u.email === email) || null;
}

async function dbGetUserById(id) {
  if (pgPool) {
    const r = await pgPool.query('SELECT * FROM client_users WHERE id=$1', [id]).catch(() => null);
    return r?.rows[0] || null;
  }
  return loadJSON(CLIENT_USERS_FILE).find(u => String(u.id) === String(id)) || null;
}

async function dbCreateUser({ email, name, passwordHash, googleId, googlePicture }) {
  if (pgPool) {
    const r = await pgPool.query(
      'INSERT INTO client_users(email,name,password_hash,google_id,google_picture) VALUES($1,$2,$3,$4,$5) RETURNING *',
      [email, name||'', passwordHash||null, googleId||null, googlePicture||null]
    );
    return r.rows[0];
  }
  const users = loadJSON(CLIENT_USERS_FILE);
  const user  = { id: Date.now(), email, name: name||'', passwordHash: passwordHash||null, googleId: googleId||null, googlePicture: googlePicture||null, suspended: false, createdAt: new Date().toISOString() };
  users.push(user);
  saveJSON(CLIENT_USERS_FILE, users);
  return user;
}

async function dbUpdateUserLogin(id) {
  if (pgPool) {
    await pgPool.query('UPDATE client_users SET last_login=NOW() WHERE id=$1', [id]).catch(() => {});
    return;
  }
  const users = loadJSON(CLIENT_USERS_FILE);
  const u = users.find(u => String(u.id) === String(id));
  if (u) { u.lastLogin = new Date().toISOString(); saveJSON(CLIENT_USERS_FILE, users); }
}

async function dbListClientUsers() {
  if (pgPool) {
    const r = await pgPool.query('SELECT id,email,name,google_id,suspended,created_at,last_login FROM client_users ORDER BY created_at DESC').catch(() => null);
    if (r) return r.rows;
  }
  return loadJSON(CLIENT_USERS_FILE).map(u => ({ ...u, password_hash: undefined }));
}

async function dbSuspendUser(id, suspended) {
  if (pgPool) {
    await pgPool.query('UPDATE client_users SET suspended=$1 WHERE id=$2', [suspended, id]).catch(() => {});
    return;
  }
  const users = loadJSON(CLIENT_USERS_FILE);
  const u = users.find(u => String(u.id) === String(id));
  if (u) { u.suspended = suspended; saveJSON(CLIENT_USERS_FILE, users); }
}

async function dbDeleteClientUser(id) {
  if (pgPool) {
    await pgPool.query('DELETE FROM client_users WHERE id=$1', [id]).catch(() => {});
    return;
  }
  saveJSON(CLIENT_USERS_FILE, loadJSON(CLIENT_USERS_FILE).filter(u => String(u.id) !== String(id)));
}

async function dbResetPassword(id, newHash) {
  if (pgPool) {
    await pgPool.query('UPDATE client_users SET password_hash=$1 WHERE id=$2', [newHash, id]).catch(() => {});
    return;
  }
  const users = loadJSON(CLIENT_USERS_FILE);
  const u = users.find(u => String(u.id) === String(id));
  if (u) { u.passwordHash = newHash; saveJSON(CLIENT_USERS_FILE, users); }
}

// ── JSON-only helpers still used in some routes ───────────────
function loadFollowups()    { return loadJSON(FOLLOWUPS_FILE); }
function saveFollowups(d)   { saveJSON(FOLLOWUPS_FILE, d); }
function loadUsers()        { return loadJSON(USERS_FILE); }
function saveUsers(d)       { saveJSON(USERS_FILE, d); }

// ── CASE REFERENCE ────────────────────────────────────────────
function generateCaseRef() {
  return `FGD-${new Date().getFullYear()}-${String(Date.now()).slice(-5)}`;
}

// ── FEDERAL COURT LOCATOR ─────────────────────────────────────
const FEDERAL_COURTS = {
  AL: { name: 'U.S. District Court, Northern District of Alabama',     address: '1729 5th Ave N',          city: 'Birmingham',    state: 'AL', zip: '35203', dept: 'Civil Division, Room 140',          phone: '(205) 278-1700' },
  AK: { name: 'U.S. District Court, District of Alaska',               address: '222 W 7th Ave',            city: 'Anchorage',     state: 'AK', zip: '99513', dept: 'Civil Filing Office, Room 4',        phone: '(907) 677-6100' },
  AZ: { name: 'U.S. District Court, District of Arizona',              address: '401 W Washington St',      city: 'Phoenix',       state: 'AZ', zip: '85003', dept: 'Civil Division, Suite 130',          phone: '(602) 322-7200' },
  AR: { name: 'U.S. District Court, Eastern District of Arkansas',     address: '600 W Capitol Ave',        city: 'Little Rock',   state: 'AR', zip: '72201', dept: "Civil Clerk's Office, Room A149",    phone: '(501) 604-5351' },
  CA: { name: 'U.S. District Court, Central District of California',   address: '350 W 1st St',             city: 'Los Angeles',   state: 'CA', zip: '90012', dept: 'Civil Division, Suite 4311',         phone: '(213) 894-1565' },
  CO: { name: 'U.S. District Court, District of Colorado',             address: '901 19th St',              city: 'Denver',        state: 'CO', zip: '80294', dept: "Civil Clerk's Office, Room A105",    phone: '(303) 844-3433' },
  CT: { name: 'U.S. District Court, District of Connecticut',          address: '141 Church St',            city: 'New Haven',     state: 'CT', zip: '06510', dept: 'Civil Division, Room 107',           phone: '(203) 773-2140' },
  DE: { name: 'U.S. District Court, District of Delaware',             address: '844 N King St',            city: 'Wilmington',    state: 'DE', zip: '19801', dept: "Civil Clerk's Office, Unit 18",      phone: '(302) 573-6170' },
  FL: { name: 'U.S. District Court, Middle District of Florida',       address: '801 N Florida Ave',        city: 'Tampa',         state: 'FL', zip: '33602', dept: 'Civil Division, Suite 500',          phone: '(813) 301-5400' },
  GA: { name: 'U.S. District Court, Northern District of Georgia',     address: '75 Ted Turner Dr SW',      city: 'Atlanta',       state: 'GA', zip: '30303', dept: "Civil Clerk's Office, Room 2211",    phone: '(404) 215-1600' },
  HI: { name: 'U.S. District Court, District of Hawaii',               address: '300 Ala Moana Blvd',       city: 'Honolulu',      state: 'HI', zip: '96850', dept: 'Civil Division, Room C338',          phone: '(808) 541-1300' },
  ID: { name: 'U.S. District Court, District of Idaho',                address: '550 W Fort St',            city: 'Boise',         state: 'ID', zip: '83724', dept: "Civil Clerk's Office, Room 400",     phone: '(208) 334-1361' },
  IL: { name: 'U.S. District Court, Northern District of Illinois',    address: '219 S Dearborn St',        city: 'Chicago',       state: 'IL', zip: '60604', dept: 'Civil Division, Room 2050',          phone: '(312) 435-5670' },
  IN: { name: 'U.S. District Court, Southern District of Indiana',     address: '46 E Ohio St',             city: 'Indianapolis',  state: 'IN', zip: '46204', dept: "Civil Clerk's Office, Room 105",     phone: '(317) 229-3700' },
  IA: { name: 'U.S. District Court, Southern District of Iowa',        address: '123 E Walnut St',          city: 'Des Moines',    state: 'IA', zip: '50309', dept: 'Civil Division, Suite 300',          phone: '(515) 284-6248' },
  KS: { name: 'U.S. District Court, District of Kansas',               address: '500 State Ave',            city: 'Kansas City',   state: 'KS', zip: '66101', dept: "Civil Clerk's Office, Suite 259",    phone: '(913) 735-2200' },
  KY: { name: 'U.S. District Court, Eastern District of Kentucky',     address: '101 Barr St',              city: 'Lexington',     state: 'KY', zip: '40507', dept: 'Civil Division, Suite 201',          phone: '(859) 233-2503' },
  LA: { name: 'U.S. District Court, Eastern District of Louisiana',    address: '500 Poydras St',           city: 'New Orleans',   state: 'LA', zip: '70130', dept: "Civil Clerk's Office, Room C151",    phone: '(504) 589-7650' },
  ME: { name: 'U.S. District Court, District of Maine',                address: '156 Federal St',           city: 'Portland',      state: 'ME', zip: '04101', dept: 'Civil Division, Room 311',           phone: '(207) 780-3356' },
  MD: { name: 'U.S. District Court, District of Maryland',             address: '101 W Lombard St',         city: 'Baltimore',     state: 'MD', zip: '21201', dept: "Civil Clerk's Office, Room 4415",    phone: '(410) 962-2600' },
  MA: { name: 'U.S. District Court, District of Massachusetts',        address: '1 Courthouse Way',         city: 'Boston',        state: 'MA', zip: '02210', dept: 'Civil Division, Suite 2300',         phone: '(617) 748-9152' },
  MI: { name: 'U.S. District Court, Eastern District of Michigan',     address: '231 W Lafayette Blvd',     city: 'Detroit',       state: 'MI', zip: '48226', dept: "Civil Clerk's Office, Room 564",     phone: '(313) 234-5005' },
  MN: { name: 'U.S. District Court, District of Minnesota',            address: '300 S 4th St',             city: 'Minneapolis',   state: 'MN', zip: '55415', dept: 'Civil Division, Suite 202',          phone: '(612) 664-5000' },
  MS: { name: 'U.S. District Court, Southern District of Mississippi', address: '501 E Court St',           city: 'Jackson',       state: 'MS', zip: '39201', dept: "Civil Clerk's Office, Suite 2.500",  phone: '(601) 608-4000' },
  MO: { name: 'U.S. District Court, Eastern District of Missouri',     address: '111 S 10th St',            city: 'St. Louis',     state: 'MO', zip: '63102', dept: 'Civil Division, Suite 3.300',        phone: '(314) 244-7900' },
  MT: { name: 'U.S. District Court, District of Montana',              address: '2601 2nd Ave N',           city: 'Billings',      state: 'MT', zip: '59101', dept: "Civil Clerk's Office, Room 5405",    phone: '(406) 247-7000' },
  NE: { name: 'U.S. District Court, District of Nebraska',             address: '111 S 18th Plaza',         city: 'Omaha',         state: 'NE', zip: '68102', dept: 'Civil Division, Suite 1152',         phone: '(402) 661-7350' },
  NV: { name: 'U.S. District Court, District of Nevada',               address: '333 Las Vegas Blvd S',     city: 'Las Vegas',     state: 'NV', zip: '89101', dept: "Civil Clerk's Office, Room 1334",    phone: '(702) 464-5400' },
  NH: { name: 'U.S. District Court, District of New Hampshire',        address: '55 Pleasant St',           city: 'Concord',       state: 'NH', zip: '03301', dept: 'Civil Division, Room 110',           phone: '(603) 225-1423' },
  NJ: { name: 'U.S. District Court, District of New Jersey',           address: '402 E State St',           city: 'Trenton',       state: 'NJ', zip: '08608', dept: "Civil Clerk's Office, Room 2020",    phone: '(609) 989-2065' },
  NM: { name: 'U.S. District Court, District of New Mexico',           address: '333 Lomas Blvd NW',        city: 'Albuquerque',   state: 'NM', zip: '87102', dept: 'Civil Division, Suite 270',          phone: '(505) 348-2000' },
  NY: { name: 'U.S. District Court, Southern District of New York',    address: '500 Pearl St',             city: 'New York',      state: 'NY', zip: '10007', dept: "Civil Clerk's Office, Room 120",     phone: '(212) 805-0136' },
  NC: { name: 'U.S. District Court, Middle District of North Carolina', address: '324 W Market St',         city: 'Greensboro',    state: 'NC', zip: '27401', dept: 'Civil Division, Room 202',           phone: '(336) 332-6000' },
  ND: { name: 'U.S. District Court, District of North Dakota',         address: '220 E Rosser Ave',         city: 'Bismarck',      state: 'ND', zip: '58501', dept: "Civil Clerk's Office, Room 476",     phone: '(701) 530-2300' },
  OH: { name: 'U.S. District Court, Southern District of Ohio',        address: '85 Marconi Blvd',          city: 'Columbus',      state: 'OH', zip: '43215', dept: 'Civil Division, Room 121',           phone: '(614) 719-3000' },
  OK: { name: 'U.S. District Court, Western District of Oklahoma',     address: '200 NW 4th St',            city: 'Oklahoma City', state: 'OK', zip: '73102', dept: "Civil Clerk's Office, Room 1210",    phone: '(405) 609-5000' },
  OR: { name: 'U.S. District Court, District of Oregon',               address: '1000 SW 3rd Ave',          city: 'Portland',      state: 'OR', zip: '97204', dept: 'Civil Division, Suite 740',          phone: '(503) 326-8000' },
  PA: { name: 'U.S. District Court, Eastern District of Pennsylvania', address: '601 Market St',            city: 'Philadelphia',  state: 'PA', zip: '19106', dept: "Civil Clerk's Office, Room 2609",    phone: '(215) 597-7704' },
  RI: { name: 'U.S. District Court, District of Rhode Island',         address: '1 Exchange Terrace',       city: 'Providence',    state: 'RI', zip: '02903', dept: 'Civil Division, Room 302',           phone: '(401) 752-7200' },
  SC: { name: 'U.S. District Court, District of South Carolina',       address: '901 Richland St',          city: 'Columbia',      state: 'SC', zip: '29201', dept: "Civil Clerk's Office, Room 2500",    phone: '(803) 765-5816' },
  SD: { name: 'U.S. District Court, District of South Dakota',         address: '225 S Pierre St',          city: 'Pierre',        state: 'SD', zip: '57501', dept: 'Civil Division, Room 405',           phone: '(605) 945-4600' },
  TN: { name: 'U.S. District Court, Middle District of Tennessee',     address: '801 Broadway',             city: 'Nashville',     state: 'TN', zip: '37203', dept: "Civil Clerk's Office, Room A800",    phone: '(615) 736-5498' },
  TX: { name: 'U.S. District Court, Northern District of Texas',       address: '1100 Commerce St',         city: 'Dallas',        state: 'TX', zip: '75242', dept: 'Civil Division, Room 1452',          phone: '(214) 753-2200' },
  UT: { name: 'U.S. District Court, District of Utah',                 address: '351 S West Temple',        city: 'Salt Lake City',state: 'UT', zip: '84101', dept: "Civil Clerk's Office, Room 1.100",   phone: '(801) 524-6100' },
  VT: { name: 'U.S. District Court, District of Vermont',              address: '11 Elmwood Ave',           city: 'Burlington',    state: 'VT', zip: '05401', dept: 'Civil Division, Room 502',           phone: '(802) 951-6301' },
  VA: { name: 'U.S. District Court, Eastern District of Virginia',     address: '701 E Broad St',           city: 'Richmond',      state: 'VA', zip: '23219', dept: "Civil Clerk's Office, Room 3000",    phone: '(804) 916-2200' },
  WA: { name: 'U.S. District Court, Western District of Washington',   address: '700 Stewart St',           city: 'Seattle',       state: 'WA', zip: '98101', dept: 'Civil Division, Suite 2310',         phone: '(206) 370-8400' },
  WV: { name: 'U.S. District Court, Southern District of West Virginia', address: '300 Virginia St E',      city: 'Charleston',    state: 'WV', zip: '25301', dept: "Civil Clerk's Office, Room 2303",    phone: '(304) 529-5588' },
  WI: { name: 'U.S. District Court, Eastern District of Wisconsin',    address: '517 E Wisconsin Ave',      city: 'Milwaukee',     state: 'WI', zip: '53202', dept: 'Civil Division, Room 362',           phone: '(414) 297-3372' },
  WY: { name: 'U.S. District Court, District of Wyoming',              address: '2120 Capitol Ave',         city: 'Cheyenne',      state: 'WY', zip: '82001', dept: "Civil Clerk's Office, Room 2131",    phone: '(307) 433-2120' },
  DC: { name: 'U.S. District Court, District of Columbia',             address: '333 Constitution Ave NW',  city: 'Washington',    state: 'DC', zip: '20001', dept: 'Civil Division, Room 1225',          phone: '(202) 354-3000' },
};

function extractState(address) {
  const m = address.match(/\b(AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC)\b/);
  return m ? m[1] : 'IL';
}

function getCourtByState(address) {
  const state = extractState(address);
  return FEDERAL_COURTS[state] || FEDERAL_COURTS['IL'];
}

// ── GOOGLE MAPS: NEAREST COURTHOUSE ──────────────────────────
function haversineDistance(lat1, lng1, lat2, lng2) {
  const R    = 3959; // miles
  const toRad = n => n * Math.PI / 180;
  const dLat = toRad(lat2 - lat1), dLng = toRad(lng2 - lng1);
  const a    = Math.sin(dLat/2)**2 + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLng/2)**2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

async function findCourthouseViaGoogleMaps(address) {
  const key = process.env.GOOGLE_MAPS_API_KEY;
  if (!key) throw new Error('GOOGLE_MAPS_API_KEY is not configured in Railway environment variables.');

  // Step 1 — geocode the broker's address
  const geoRes  = await fetch(`https://maps.googleapis.com/maps/api/geocode/json?address=${encodeURIComponent(address)}&key=${key}`);
  const geoData = await geoRes.json();
  if (geoData.status !== 'OK' || !geoData.results[0]) {
    const msg = geoData.status === 'REQUEST_DENIED'
      ? `Google Maps Geocoding API not enabled or key restricted (REQUEST_DENIED)`
      : `Could not geocode broker address "${address}". Google status: ${geoData.status}`;
    throw new Error(msg);
  }

  const { lat: brokerLat, lng: brokerLng } = geoData.results[0].geometry.location;
  const formattedBrokerAddress = geoData.results[0].formatted_address;

  // Step 2 — text search for US District Courts within 500 miles
  const placesRes  = await fetch(
    `https://maps.googleapis.com/maps/api/place/textsearch/json` +
    `?query=United+States+District+Court` +
    `&location=${brokerLat},${brokerLng}` +
    `&radius=800000` +
    `&key=${key}`
  );
  const placesData = await placesRes.json();
  if (placesData.status !== 'OK' || !placesData.results.length)
    throw new Error(`No federal courthouses found near "${address}". Google status: ${placesData.status}`);

  // Step 3 — sort ALL results by actual haversine distance, pick the closest
  const ranked = placesData.results
    .map(r => ({
      ...r,
      _dist: haversineDistance(brokerLat, brokerLng, r.geometry.location.lat, r.geometry.location.lng),
    }))
    .sort((a, b) => a._dist - b._dist);

  const nearest   = ranked[0];
  const courtLat  = nearest.geometry.location.lat;
  const courtLng  = nearest.geometry.location.lng;
  const distMiles = Math.round(nearest._dist);

  const addrStr    = nearest.formatted_address || '';
  const stateMatch = addrStr.match(/,\s*([A-Z]{2})\s+\d{5}/);
  const courtState = stateMatch ? stateMatch[1] : extractState(address);
  const details    = FEDERAL_COURTS[courtState] || {};
  const parts      = addrStr.split(',');
  const city       = parts.length >= 3 ? parts[parts.length - 3].trim() : details.city;

  // Extract zip from formatted address
  const zipMatch = addrStr.match(/\b(\d{5})\b/);
  const zip      = zipMatch ? zipMatch[1] : (details.zip || '');

  return {
    name:    nearest.name,
    address: parts[0]?.trim() || details.address || '',
    city:    city || details.city || '',
    state:   courtState,
    zip,
    dept:    details.dept || 'Civil Division',
    phone:   details.phone || '',
    brokerLat, brokerLng, courtLat, courtLng,
    distanceMiles: distMiles,
    formattedBrokerAddress,
    fromGoogleMaps: true,
  };
}

// ── DAMAGES — FIXED $15,000/TRUCK/MONTH ──────────────────────
function calcDamages(numTrucks) {
  const monthlyPerTruck    = 15000;
  const annualPerTruck     = monthlyPerTruck * 12;       // $180,000
  const totalAnnualRevenue = annualPerTruck * numTrucks;
  const reRegisterCosts    = 5000;
  const legalFees          = 15000;
  const totalDamages       = totalAnnualRevenue + reRegisterCosts + legalFees;
  return { monthlyPerTruck, annualPerTruck, numTrucks, totalAnnualRevenue, reRegisterCosts, legalFees, totalDamages };
}

// ── EMAIL HELPERS ─────────────────────────────────────────────
function buildEmailHtml(letterText) {
  const escaped = (letterText || '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return `<div style="font-family:'Times New Roman',Times,serif;max-width:800px;margin:0 auto;padding:40px;color:#111;line-height:1.7;font-size:14px;">
<pre style="font-family:'Times New Roman',Times,serif;white-space:pre-wrap;font-size:14px;line-height:1.8;border:none;background:none;padding:0;margin:0;">${escaped}</pre>
<hr style="margin:40px 0;border:1px solid #ccc;"/>
<p style="font-size:11px;color:#666;">This communication is from a law office and contains information that is confidential and legally privileged. If you are not the intended recipient, any disclosure, copying, or use is strictly prohibited.</p>
</div>`;
}

async function dispatchEmail({ to, cc, subject, text, html }) {
  const fromName = process.env.FIRM_NAME || 'FreightGuard Defense Legal Network';

  // Try Resend first
  if (resendClient) {
    const fromEmail = cfg('RESEND_FROM_EMAIL') || process.env.RESEND_FROM_EMAIL || 'legal@brokermc.com';
    const { data, error } = await resendClient.emails.send({
      from:    `${fromName} <${fromEmail}>`,
      to:      Array.isArray(to) ? to : [to],
      cc:      cc ? (Array.isArray(cc) ? cc : [cc]) : undefined,
      subject, html, text,
    });
    if (error) throw new Error(error.message || 'Resend send failed');
    return data;
  }

  // Fall back to SMTP / nodemailer
  if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
    throw new Error('Email not configured. Add RESEND_API_KEY or SMTP_USER + SMTP_PASS to your .env file.');
  }
  const transporter = nodemailer.createTransport({
    host:   process.env.SMTP_HOST || 'smtp.gmail.com',
    port:   Number(process.env.SMTP_PORT) || 587,
    secure: false,
    auth:   { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
  await transporter.sendMail({
    from: `"${fromName}" <${process.env.SMTP_USER}>`,
    to, cc, subject, html, text,
  });
}

// ── ATTORNEY ROUTES ───────────────────────────────────────────
app.get('/api/attorneys', async (req, res) => res.json(await loadAttorneys()));

app.post('/api/attorneys', requireAdmin, async (req, res) => {
  const { name, barNumber, barState, email, phone, licenseStates, specialty, firmName } = req.body;
  if (!name || !barNumber || !email) return res.status(400).json({ error: 'Name, bar number, and email required' });
  const attorney = { id: Date.now().toString(), name, barNumber, barState: barState||'', email, phone: phone||'', licenseStates: licenseStates||'', specialty: specialty||'', firmName: firmName||'', createdAt: new Date().toISOString() };
  await addAttorneyDB(attorney);
  res.json(attorney);
});

app.delete('/api/attorneys/:id', requireAdmin, async (req, res) => {
  await deleteAttorneyDB(req.params.id);
  res.json({ success: true });
});

// ── PUBLIC CONFIG — maps key for client-side Places API ───────

// ── FMCSA SAFER LOOKUP ───────────────────────────────────────────────────────
app.get('/api/fmcsa-lookup', async (req, res) => {
  const mc  = (req.query.mc  || '').replace(/\D/g, '');
  const dot = (req.query.dot || '').replace(/\D/g, '');
  const lookupType = dot ? 'dot' : 'mc';
  const lookupVal  = dot || mc;
  if (!lookupVal || lookupVal.length < 5) return res.status(400).json({ error: 'Enter at least 5 digits' });

  // Try FMCSA REST API first (requires FMCSA_WEB_KEY env var)
  const apiKey = process.env.FMCSA_WEB_KEY;
  if (apiKey) {
    try {
      const apiUrl = lookupType === 'dot'
        ? 'https://mobile.fmcsa.dot.gov/qc/services/carriers/' + lookupVal + '?webKey=' + apiKey
        : 'https://mobile.fmcsa.dot.gov/qc/services/carriers/docket-number/' + lookupVal + '?webKey=' + apiKey;
      const r = await fetch(apiUrl, { timeout: 8000 });
      if (r.ok) {
        const j = await r.json();
        const c = j.content && j.content[0] && j.content[0].carrier;
        if (c) {
          return res.json({
            legalName:  c.legalName || '',
            dbaName:    c.dbaName   || '',
            dotNumber:  (c.dotNumber || '').toString(),
            mcNumber:   mc,
            address:    [c.phyStreet, c.phyCity, c.phyState, c.phyZipcode].filter(Boolean).join(', '),
            phone:      c.telephone || '',
            status:     c.statusCode === 'A' ? 'Active' : (c.statusCode || ''),
            entityType: c.carrierOperation || ''
          });
        }
      }
    } catch (e) { /* fall through to SAFER scrape */ }
  }

  // Fallback: scrape FMCSA SAFER web
  try {
    const saferParam = lookupType === 'dot' ? 'USDOT' : 'MC_MX';
    const url = 'https://safer.fmcsa.dot.gov/query.asp?searchtype=ANY&query_type=queryCarrierSnapshot&query_param=' + saferParam + '&query_string=' + lookupVal;
    const r = await fetch(url, {
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; CarrierLaw/1.0)' },
      signal: AbortSignal.timeout ? AbortSignal.timeout(10000) : undefined
    });
    if (!r.ok) return res.status(502).json({ error: 'FMCSA unreachable' });
    const html = await r.text();

    // SAFER HTML: labels in <TH class="querylabelbkg"><A>Label:</A></TH> <TD class="queryfield">value</TD>
    function extractSafer(label) {
      const re = new RegExp(
        label + '[^<]*<\\/[Aa]>[^<]*<\\/[Tt][Hh]>\\s*<[Tt][Dd][^>]*class=["\']queryfield["\'][^>]*>([\\s\\S]*?)<\\/[Tt][Dd]>',
        'i'
      );
      const m = html.match(re);
      if (!m) return '';
      return m[1].replace(/<br\s*\/?>/gi, ' ').replace(/<[^>]+>/g, '').replace(/&nbsp;/g, ' ').replace(/\s+/g, ' ').trim();
    }
    function extractPhysicalAddr() {
      // SAFER uses id="physicaladdressvalue" on the address TD
      const re = /id=["']physicaladdressvalue["'][^>]*>([\s\S]*?)<\/[Tt][Dd]>/i;
      const m = html.match(re);
      if (!m) return '';
      return m[1].replace(/<br\s*\/?>/gi, ' ').replace(/<[^>]+>/g, '').replace(/&nbsp;/g, ' ').replace(/\s+/g, ' ').trim();
    }
    function extractStatus() {
      // Status value is wrapped in an HTML comment: <!--ACTIVE-->
      const re = /USDOT Status:<\/A>[\s\S]*?<TD[^>]*class=["']queryfield["'][^>]*>([\s\S]*?)<\/TD>/i;
      const m = html.match(re);
      if (!m) return '';
      let val = m[1].replace(/<!--[\s\S]*?-->/g, ''); // strip HTML comments, use visible text
      return val.replace(/<[^>]+>/g, '').replace(/&nbsp;/g, ' ').replace(/\s+/g, ' ').trim();
    }

    const legalName  = extractSafer('Legal Name') || extractSafer('Entity\/DBA Name');
    const dbaName    = extractSafer('DBA Name');
    const dotNum     = extractSafer('USDOT Number');
    const address    = extractPhysicalAddr() || extractSafer('Physical Address');
    const phone      = extractSafer('Phone');
    const opStatus   = extractStatus() || extractSafer('Operating Status') || extractSafer('Status');
    const entityType = extractSafer('Entity Type');
    const mcNumSafer = extractSafer('Docket Number') || mc;

    if (!legalName && !dotNum) {
      return res.status(404).json({ error: (lookupType==='dot'?'DOT-':'MC-') + lookupVal + ' not found on FMCSA' });
    }

    return res.json({
      legalName,
      dbaName,
      dotNumber:  dotNum,
      mcNumber:   mcNumSafer || mc,
      address,
      phone,
      status:     opStatus,
      entityType
    });
  } catch (e) {
    console.error('FMCSA lookup error:', e.message);
    return res.status(500).json({ error: 'Lookup failed: ' + e.message });
  }
});

// ── UNPAID FREIGHT COLLECTION LETTER ─────────────────────────────────────────
app.post('/api/generate-collection-letter', rateLimit(60000, 5), async (req, res) => {
  try {
    const {
      carrierName, carrierMC, carrierDOT, carrierEmail, carrierAddress,
      brokerName, brokerMC, brokerAddress, brokerPOC, brokerEmail,
      invoiceNumber, invoiceDate, loadNumber, bolNumber,
      invoiceAmount, paymentDueDate, serviceDescription,
      assignedAttorneyId,
    } = req.body;

    if (!carrierName || !brokerName || !brokerAddress || !invoiceAmount) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const principal   = parseFloat(String(invoiceAmount).replace(/[^0-9.]/g, '')) || 0;
    const attyFees    = Math.round(principal * 0.5);
    const interest    = Math.round(principal * 0.18 / 365 * 30); // 18% APR ~30 days
    const totalOwed   = principal + attyFees + interest;

    const caseRef = 'FGD-COL-' + Date.now().toString().slice(-6) + '-' + Math.floor(Math.random()*9000+1000);

    let court = { name: 'United States District Court', address: brokerAddress, city: '', state: '', zip: '', dept: '', phone: '' };
    try { court = await findCourthouseViaGoogleMaps(brokerAddress); } catch {}

    const attorneys  = await loadAttorneys();
    const attorney   = assignedAttorneyId ? attorneys.find(a => a.id === assignedAttorneyId) : null;

    const today       = new Date().toLocaleDateString('en-US', { year:'numeric', month:'long', day:'numeric' });
    const deadline    = new Date();
    deadline.setDate(deadline.getDate() + 14);
    const deadlineStr = deadline.toLocaleDateString('en-US', { year:'numeric', month:'long', day:'numeric' });

    const firmLine = attorney
      ? (attorney.firmName || attorney.name + ', Attorney at Law')
      : '[LAW FIRM — TBD]';
    const attorneyBlock = attorney
      ? `Respectfully submitted,\n\n${attorney.name}\n${attorney.firmName || 'Attorney at Law'}\nBar No. ${attorney.barNumber} (${attorney.barState})\n${attorney.phone || ''}\n${attorney.email}`
      : 'Respectfully submitted,\n\n_________________________________\nAuthorized Representative / Counsel';

    const courtLine = court.name
      ? `${court.name}\n${court.address || ''}, ${court.city || ''}, ${court.state || ''} ${court.zip || ''}\n${court.dept || ''}\nPhone: ${court.phone || 'N/A'}`
      : brokerAddress;

    const prompt = `CRITICAL FORMATTING RULES: Output ONLY plain text. Do NOT use HTML tags, markdown, bold (**), bullet symbols, or special formatting. Use standard ASCII. Line breaks are fine.

You are a senior collections attorney and transportation law specialist drafting a FINAL DEMAND FOR PAYMENT AND NOTICE OF INTENT TO SUE. This letter must be forceful, legally authoritative, and unmistakably threatening — the kind of letter that motivates immediate payment.

TODAY'S DATE: ${today}
FINAL PAYMENT DEADLINE: ${deadlineStr} (14 days from today)

LAW FIRM / SENDER:
${firmLine}

PLAINTIFF / CREDITOR (MOTOR CARRIER):
- Legal Name: ${carrierName}
- MC Number: MC-${carrierMC || 'N/A'}
- DOT Number: ${carrierDOT || 'N/A'}
- Address: ${carrierAddress || 'N/A'}
- Contact Email: ${carrierEmail}

DEFENDANT / DEBTOR (FREIGHT BROKER):
- Legal Name: ${brokerName}
- MC Number: MC-${brokerMC || 'N/A'}
- Address: ${brokerAddress}
- Point of Contact: ${brokerPOC || 'Accounts Payable Department'}

TRANSACTION DETAILS:
- Invoice Number: ${invoiceNumber || 'N/A'}
- Invoice Date: ${invoiceDate || 'N/A'}
- Load / Reference Number: ${loadNumber || 'N/A'}
- Bill of Lading: ${bolNumber || 'N/A'}
- Payment Due Date: ${paymentDueDate || 'N/A'}
- Description of Services: ${serviceDescription || 'Freight transportation services rendered in full'}

FINANCIAL DEMAND:
- Original Invoice Amount: $${principal.toLocaleString()}
- Attorney Fees & Collection Costs (50%): $${attyFees.toLocaleString()}
- Accrued Interest (18% per annum): $${interest.toLocaleString()}
- TOTAL AMOUNT DUE AND OWING: $${totalOwed.toLocaleString()}

DESIGNATED FILING COURT (if payment not received):
${courtLine}

LEGAL CAUSES OF ACTION TO CITE (cite relevant statute numbers):
1. Breach of Contract — failure to pay for services rendered per 49 U.S.C. § 14101
2. Quantum Meruit — unjust enrichment for services performed and accepted
3. Unjust Enrichment — defendant profited from carrier services without compensation
4. Violation of Prompt Payment requirements under 49 C.F.R. § 371.3 and industry standards
5. Bad Faith / Tortious Interference — if applicable
6. Interest at the statutory rate plus contractual rate of 18% per annum
7. Full attorney fees and collection costs pursuant to contract and applicable law

WRITE THE LETTER WITH THESE EXACT SECTIONS:
1. Header block: FROM (law firm), DATE, TO (broker/debtor address)
2. RE: line — must include case reference ${caseRef}, invoice number, and dollar amount
3. Opening paragraph — identify the firm, the carrier client, and state this is the FINAL PRE-LITIGATION DEMAND. State that if payment is not received within 14 days, a lawsuit WILL be filed — no further notice will be given.
4. "BACKGROUND AND SERVICES RENDERED" — detail the load, invoice, and completed services
5. "DEFAULT AND FAILURE TO PAY" — document the debt, days overdue, and refusal to pay
6. "LEGAL GROUNDS FOR RECOVERY" — cite every cause of action with specific statutes
7. "FINANCIAL DEMAND" — present the full table: principal, attorney fees (50%), interest, total
8. "CONSEQUENCES OF NON-PAYMENT" — explain lawsuit filing in ${court.name || 'federal district court'}, judgment, interest accrual, damage to broker's credit/license, FMCSA notification, industry reporting
9. "DEMAND FOR IMMEDIATE PAYMENT" — numbered demands: full wire/check payment within 14 days or suit filed
10. State specifically that suit WILL be filed at: ${courtLine}
11. Professional closing with attorney signature block

Make every sentence feel like it was written by a $600/hour collections attorney. The tone must be formally aggressive — factual, precise, and unmistakably serious. No softening language whatsoever.

${attorneyBlock}`;

    const message = await anthropic.messages.create({
      model:      'claude-opus-4-6',
      max_tokens: 3000,
      messages:   [{ role: 'user', content: prompt }],
    });

    const letterText = message.content[0].type === 'text' ? message.content[0].text : '';

    // Save to letters store
    const letter = {
      id: caseRef, caseRef, letterType: 'collection',
      carrierName, carrierEmail, carrierMC, carrierDOT,
      brokerName, brokerMC, brokerAddress,
      invoiceNumber, invoiceAmount: principal, totalDemand: totalOwed,
      totalDamages: totalOwed,
      letterText,
      court, attorneyId: assignedAttorneyId || null,
      ts: new Date().toISOString(),
    };
    await saveLetterDB(letter);
    await recordBrokerReportDB(brokerMC, brokerName, carrierName, caseRef);

    // Auto-send email to broker if address provided
    const autoSent = { sent: false, error: null };
    if (brokerEmail) {
      try {
        const emailSubject = `FINAL DEMAND FOR PAYMENT — ${brokerName} — Invoice ${invoiceNumber || caseRef}`;
        await dispatchEmail({
          to:      brokerEmail,
          cc:      carrierEmail,
          subject: emailSubject,
          text:    letterText,
          html:    buildEmailHtml(letterText),
        });
        // Schedule Day 7 + Day 14 follow-ups
        const followups = loadFollowups();
        followups.push({
          id: Date.now().toString(), caseRef,
          brokerEmail: req.body.brokerEmail, carrierEmail, brokerName, carrierName,
          originalSubject: emailSubject,
          pending: [
            { label: 'Day 7 Reminder',      sendAt: Date.now() + 7  * 86400000, sent: false },
            { label: 'Day 14 Final Notice', sendAt: Date.now() + 14 * 86400000, sent: false },
          ],
        });
        saveFollowups(followups);
        // Mark status as 'sent'
        const statuses = loadStatuses();
        statuses[caseRef] = { status: 'sent', updatedAt: new Date().toISOString() };
        saveStatuses(statuses);
        autoSent.sent = true;
      } catch(emailErr) {
        autoSent.error = emailErr.message;
      }
    }

    res.json({
      letter: letterText,
      caseRef,
      court,
      autoSent,
      summary: { principal, attyFees, interest, totalOwed, brokerName, invoiceNumber, deadlineStr },
    });
  } catch(e) {
    console.error('Collection letter error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── DISPUTE LETTER GENERATION ─────────────────────────────────────────────────
app.get('/api/maps-key', (req, res) => {
  res.json({ key: cfg('GOOGLE_MAPS_API_KEY') || '' });
});

// ── BROKER REPEAT-OFFENDER CHECK ─────────────────────────────


// ── FORM PIN PROTECTION ───────────────────────────────────────────────────────
app.post('/api/verify-pin', (req, res) => {
  const { pin } = req.body;
  const correctPin  = process.env.FORM_PIN     || '1234';
  const adminPass   = process.env.ADMIN_PASSWORD || 'mikee@megafleetcorp.com';
  const pinStr      = String(pin).trim();
  if (pinStr === String(adminPass).trim()) {
    // Admin access — return admin token so UI can show admin controls
    return res.json({ ok: true, isAdmin: true, adminToken: adminPass });
  }
  if (pinStr === String(correctPin).trim()) {
    return res.json({ ok: true, isAdmin: false });
  }
  res.status(401).json({ ok: false, error: 'Incorrect PIN' });
});

// ── PUBLIC LETTER HISTORY (admin tool — no external auth needed) ─────────────
// ── LETTER STATUS (server-side persistence) ───────────────────────────────────
app.put('/api/letter-status/:caseRef', (req, res) => {
  const { caseRef } = req.params;
  const { status }  = req.body;
  const valid = ['new','sent','opened','responded','settled','filed','closed'];
  if (!valid.includes(status)) return res.status(400).json({ error: 'Invalid status' });
  const statuses = loadStatuses();
  statuses[caseRef] = { status, updatedAt: new Date().toISOString() };
  saveStatuses(statuses);
  res.json({ ok: true, caseRef, status });
});

app.get('/api/letter-statuses', (req, res) => {
  res.json(loadStatuses());
});

// ── BROKER RESPONSE LOG ────────────────────────────────────────────────────────
app.post('/api/letter-response/:caseRef', (req, res) => {
  const { caseRef }  = req.params;
  const { response, responseDate } = req.body;
  if (!response) return res.status(400).json({ error: 'Response text required' });
  const responses = loadResponses();
  if (!responses[caseRef]) responses[caseRef] = [];
  responses[caseRef].unshift({
    text: response,
    date: responseDate || new Date().toISOString(),
    loggedAt: new Date().toISOString(),
  });
  saveResponses(responses);
  // Auto-update status to 'responded'
  const statuses = loadStatuses();
  if (!['settled','filed','closed'].includes(statuses[caseRef]?.status)) {
    statuses[caseRef] = { status: 'responded', updatedAt: new Date().toISOString() };
    saveStatuses(statuses);
  }
  res.json({ ok: true });
});

app.get('/api/letter-response/:caseRef', (req, res) => {
  const responses = loadResponses();
  res.json({ responses: responses[req.params.caseRef] || [] });
});

app.get('/api/letters-history', async (req, res) => {
  // Require either admin token or client JWT
  const adminToken = req.headers['x-admin-token'];
  const isAdmin = adminToken && adminToken === (process.env.ADMIN_PASSWORD || 'mikee@megafleetcorp.com');

  let clientEmail = null;
  if (!isAdmin) {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Login required to view past letters' });
    }
    try {
      if (!jwt) return res.status(500).json({ error: 'JWT not available' });
      const decoded = jwt.verify(auth.slice(7), JWT_SECRET);
      clientEmail = decoded.email.toLowerCase();
    } catch {
      return res.status(401).json({ error: 'Session expired. Please log in again.' });
    }
  }

  try {
    const allLetters = await loadLetters();
    const attorneys  = await loadAttorneys();
    const attyMap    = Object.fromEntries(attorneys.map(a => [a.id, a]));

    // Admin sees all; clients see only their own letters
    const letters = isAdmin
      ? allLetters
      : allLetters.filter(l => (l.carrierEmail||'').toLowerCase() === clientEmail);

    const statuses  = loadStatuses();
    const responses = loadResponses();

    res.json({
      letters: letters.map(l => ({
        caseRef:     l.caseRef,
        carrierName: l.carrierName,
        carrierMC:   l.carrierMC,
        brokerName:  l.brokerName,
        brokerMC:    l.brokerMC,
        numTrucks:   l.numTrucks,
        totalDamages:l.totalDamages,
        court:       l.court,
        letterText:  l.letterText,
        letterType:  l.letterType || 'dispute',
        attorney:    l.attorneyId ? (attyMap[l.attorneyId] || null) : null,
        ts:          l.ts || l.createdAt,
        status:      statuses[l.caseRef]?.status || 'new',
        responses:   responses[l.caseRef] || [],
      }))
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── PUBLIC BROKER INTELLIGENCE (for the form's live broker lookup) ────────────
app.get('/api/broker-intel', async (req, res) => {
  const { mc } = req.query;
  if (!mc) return res.json({ count: 0, reports: [], totalDamages: 0 });
  const mc_clean = String(mc).trim().replace(/^MC-?/i, '');
  const allLetters = await loadLetters();
  const allReports = (await loadReports()).filter(r => String(r.brokerMC).replace(/^MC-?/i, '') === mc_clean);
  // Find matching letters for damages + dates
  const matchingLetters = allLetters.filter(l => String(l.brokerMC||'').replace(/^MC-?/i,'') === mc_clean);
  const totalDamages = matchingLetters.reduce((sum, l) => sum + (Number(l.totalDamages)||0), 0);
  res.json({
    count:        allReports.length,
    reports:      allReports.slice(0,10).map(r => ({
                    carrierName: r.carrierName,
                    caseRef:     r.caseRef,
                    ts:          r.ts,
                  })),
    totalDamages,
    firstSeen:    allReports.length ? allReports[allReports.length-1].ts : null,
    lastSeen:     allReports.length ? allReports[0].ts : null,
  });
});

app.get('/api/check-broker', async (req, res) => {
  const { mc } = req.query;
  if (!mc) return res.json({ count: 0, reports: [] });
  const mc_clean = String(mc).trim().replace(/^MC-?/i, '');
  const reports  = (await loadReports()).filter(r => String(r.brokerMC).replace(/^MC-?/i, '') === mc_clean);
  res.json({ count: reports.length, reports });
});

// ── COURT LOOKUP ENDPOINT ─────────────────────────────────────
app.get('/api/court', async (req, res) => {
  const { address } = req.query;
  if (!address) return res.status(400).json({ error: 'Address required' });
  try {
    const result = await findCourthouseViaGoogleMaps(address);
    res.json(result);
  } catch(err) {
    console.error('Court lookup error (using state fallback):', err.message);
    const fallback = getCourtByState(address);
    res.json({ ...fallback, fromStateFallback: true });
  }
});

// ── LETTER GENERATION ─────────────────────────────────────────
app.post('/api/generate-letter', rateLimit(60000, 5), async (req, res) => {
  try {
    const {
      carrierName, carrierMC, carrierDOT, carrierEmail,
      numTrucks, carrierNarrative, evidenceDescription,
      brokerName, brokerMC, brokerAddress, brokerPOC,
      reporterName, reportContent, assignedAttorneyId,
      attachedFiles = [],
    } = req.body;

    const caseRef  = generateCaseRef();
    const damages  = calcDamages(Number(numTrucks));

    // Courthouse lookup — non-blocking. Falls back gracefully if Google API unavailable.
    let court = { name: null, address: null, distanceMiles: null };
    try {
      court = await findCourthouseViaGoogleMaps(brokerAddress);
    } catch (courtErr) {
      console.warn('Courthouse lookup skipped:', courtErr.message);
      // Determine state from broker address for static fallback
      const stateMatch = brokerAddress?.match(/\b([A-Z]{2})\b(?=\s*\d{5}|\s*,|\s*$)/);
      const state = stateMatch ? stateMatch[1] : null;
      const fallbacks = {
        MD:'U.S. District Court for the District of Maryland, 101 W. Lombard St, Baltimore, MD 21201',
        TX:'U.S. District Court for the Northern District of Texas, 1100 Commerce St, Dallas, TX 75242',
        CA:'U.S. District Court for the Central District of California, 350 W. 1st St, Los Angeles, CA 90012',
        FL:'U.S. District Court for the Middle District of Florida, 801 N. Florida Ave, Tampa, FL 33602',
        IL:'U.S. District Court for the Northern District of Illinois, 219 S. Dearborn St, Chicago, IL 60604',
        NY:'U.S. District Court for the Southern District of New York, 500 Pearl St, New York, NY 10007',
        OH:'U.S. District Court for the Northern District of Ohio, 801 W. Superior Ave, Cleveland, OH 44113',
        GA:'U.S. District Court for the Northern District of Georgia, 75 Ted Turner Dr SW, Atlanta, GA 30303',
        PA:'U.S. District Court for the Eastern District of Pennsylvania, 601 Market St, Philadelphia, PA 19106',
        NC:'U.S. District Court for the Middle District of North Carolina, 324 W. Market St, Greensboro, NC 27401',
        TN:'U.S. District Court for the Middle District of Tennessee, 801 Broadway, Nashville, TN 37203',
        MO:'U.S. District Court for the Eastern District of Missouri, 111 S. 10th St, St. Louis, MO 63102',
        AZ:'U.S. District Court for the District of Arizona, 401 W. Washington St, Phoenix, AZ 85003',
        CO:'U.S. District Court for the District of Colorado, 901 19th St, Denver, CO 80294',
        WA:'U.S. District Court for the Western District of Washington, 700 Stewart St, Seattle, WA 98101',
      };
      const fb = state && fallbacks[state] ? fallbacks[state] : 'U.S. District Court (jurisdiction based on defendant registered address)';
      court = { name: fb.split(',')[0], address: fb.split(',').slice(1).join(',').trim(), distanceMiles: null };
    }
    const attorneys = await loadAttorneys();
    const attorney  = assignedAttorneyId ? attorneys.find(a => a.id === assignedAttorneyId) : null;

    await recordBrokerReportDB(brokerMC, brokerName, carrierName, caseRef);
    // Save uploaded evidence files to disk
    let savedFiles = [];
    if (attachedFiles && attachedFiles.length > 0) {
      const caseUploadsDir = path.join(UPLOADS_DIR, caseRef);
      if (!fs.existsSync(caseUploadsDir)) fs.mkdirSync(caseUploadsDir, { recursive: true });
      for (const file of attachedFiles) {
        try {
          if (!file.name || !file.data) continue;
          const safeName = file.name.replace(/[^a-zA-Z0-9._-]/g, '_');
          fs.writeFileSync(path.join(caseUploadsDir, safeName), Buffer.from(file.data, 'base64'));
          savedFiles.push(safeName);
        } catch (fe) { console.warn('File save failed:', file.name, fe.message); }
      }
    }

    const today    = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
    const deadline = new Date();
    deadline.setDate(deadline.getDate() + 14);
    const deadlineStr = deadline.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });

    const firmLine = attorney
      ? `${attorney.firmName || attorney.name + ', Attorney at Law'}`
      : '[LAW FIRM NAME — TBD]';
    const attorneyBlock = attorney
      ? `\n\nRespectfully submitted,\n\n${attorney.name}\n${attorney.firmName || 'Attorney at Law'}\nBar No. ${attorney.barNumber} (${attorney.barState})\n${attorney.phone || ''}\n${attorney.email}`
      : '\n\nRespectfully submitted,\n\n_________________________________\nAuthorized Representative\nLegal Department';

    const distanceLine = court.distanceMiles
      ? `\nNote: This courthouse is approximately ${court.distanceMiles} miles from the defendant's registered business address.`
      : '';

    const prompt = `CRITICAL FORMATTING RULES: Output ONLY plain text. Do NOT use any HTML tags, HTML entities (&amp;, &nbsp;, &lt;, &gt;, &#xxx;), markdown, bold (**), bullet symbols, or any special formatting. Use only standard ASCII characters. Line breaks are fine. Numbers, dollar signs, hyphens, and parentheses are fine.

You are a senior transportation law attorney drafting a formal federal court demand letter. Write this letter exactly as a real law firm would send it — authoritative, legally precise, and intimidating to the recipient.

TODAY'S DATE: ${today}
RESPONSE DEADLINE: ${deadlineStr}

LAW FIRM / SENDER:
${firmLine}

PLAINTIFF (CARRIER):
- Legal Name: ${carrierName}
- MC Number: MC-${carrierMC}
- DOT Number: ${carrierDOT}
- Contact Email: ${carrierEmail}

DEFENDANT (BROKER):
- Legal Name: ${brokerName}
- MC Number: MC-${brokerMC}
- Address: ${brokerAddress}
- Point of Contact: ${brokerPOC}
- Person Who Filed Report: ${reporterName}

FREIGHTGUARD REPORT CONTENT (exact text of their report):
"${reportContent}"

CARRIER'S SWORN STATEMENT OF FACTS:
${carrierNarrative}

${evidenceDescription ? `EVIDENCE IN POSSESSION:\n${evidenceDescription}` : ''}

COMPUTED DAMAGES (industry-standard rate of $15,000/truck/month):
- Monthly revenue per truck (industry standard): $${damages.monthlyPerTruck.toLocaleString()}
- Annual revenue per truck: $${damages.annualPerTruck.toLocaleString()}
- Number of trucks affected: ${damages.numTrucks}
- Total annual fleet revenue lost: $${damages.totalAnnualRevenue.toLocaleString()}
- Re-registration / restructuring costs: $${damages.reRegisterCosts.toLocaleString()}
- Estimated legal fees and costs: $${damages.legalFees.toLocaleString()}
- TOTAL DAMAGES CLAIMED: $${damages.totalDamages.toLocaleString()}

VENUE COURT (where this will be filed):
${court.name}
${court.address}, ${court.city}, ${court.state} ${court.zip}
${court.dept}
Phone: ${court.phone}${distanceLine}

LEGAL CAUSES OF ACTION TO CITE:
1. Defamation / Libel (state common law)
2. Tortious Interference with Business Relations / Prospective Economic Advantage
3. 49 U.S.C. § 14915 — False statements to FMCSA/industry reporting systems
4. 49 CFR Part 386 — FMCSA regulations on carrier safety and ratings
5. Lanham Act § 43(a), 15 U.S.C. § 1125(a) — False statements in commerce (if applicable)

LETTER REQUIREMENTS:
1. Start with formal letterhead block: firm name, then "VIA EMAIL AND CERTIFIED U.S. MAIL, RETURN RECEIPT REQUESTED"
2. Full defendant address block
3. Bold "RE: Case No. ${caseRef}" subject line, then "RE: Formal Demand for Retraction of False FreightGuard Report and Payment of Damages"
4. Opening paragraph: who we represent and purpose of letter
5. "STATEMENT OF FACTS" section — numbered paragraphs, include the carrier's narrative verbatim
6. "THE FREIGHTGUARD REPORT" section — quote the report and explain why it is false
7. "LEGAL AUTHORITY" section — cite all statutes above with brief explanations
8. "DAMAGES" section — present the full damages table line by line with the $15,000/month/truck rate prominently stated
9. "DEMANDS" section — numbered list: (1) immediate retraction of the FreightGuard report, (2) written apology to carrier, (3) payment of $${damages.totalDamages.toLocaleString()} in damages, (4) cease all further disparaging communications
10. State that failure to comply within 14 days (by ${deadlineStr}) will result in filing in ${court.name}, ${court.dept}
11. Include court address and phone number in the filing threat${court.distanceMiles ? `\n12. Mention that the court is ${court.distanceMiles} miles from the defendant's place of business` : ''}
12. Professional closing

Write the complete letter. Use [DATE] as the date placeholder. Make every word feel like it was written by a $500/hour attorney.

${attorneyBlock}`;

    const message = await anthropic.messages.create({
      model:      'claude-opus-4-6',
      max_tokens: 3000,
      messages:   [{ role: 'user', content: prompt }],
    });

    const letterText = message.content[0].type === 'text' ? message.content[0].text : '';

    // Save letter
    await addLetterDB({
      id: caseRef, caseRef,
      carrierName, carrierEmail, carrierMC,
      brokerName, brokerMC, brokerAddress,
      numTrucks, totalDamages: damages.totalDamages,
      court: `${court.name}, ${court.city}, ${court.state}`,
      letterText,
      attorneyId: attorney ? (attorney.id || null) : null,
      ts: new Date().toISOString(),
    });

    res.json({ letter: letterText, damages, court, attorney: attorney || null, caseRef, savedFiles, autoSent });
  } catch(err) {
    console.error('Letter generation error:', err);
    res.status(500).json({ error: 'Letter generation failed: ' + err.message });
  }
});

// ── EMAIL SENDING ─────────────────────────────────────────────
app.post('/api/send-email', rateLimit(60000, 10), async (req, res) => {
  try {
    const { brokerEmail, carrierEmail, brokerName, carrierName, letterText, subject, ccEmails = [] } = req.body;

    const emailSubject = subject || `FORMAL LEGAL DEMAND — ${brokerName} — FreightGuard Report Retraction Required`;
    const html = buildEmailHtml(letterText);

    // Build CC list: primary carrier + any extras, deduplicated
    const allCC = [...new Set([carrierEmail, ...ccEmails].filter(Boolean))];

    await dispatchEmail({
      to:      brokerEmail,
      cc:      allCC.join(','),
      subject: emailSubject,
      text:    letterText,
      html,
    });

    // Schedule Day 7 + Day 14 escalation follow-ups
    const caseRef   = req.body.caseRef || 'N/A';
    const now       = Date.now();
    const followups = loadFollowups();
    followups.push({
      id:    now.toString(),
      caseRef,
      brokerEmail, carrierEmail, brokerName, carrierName,
      originalSubject: emailSubject,
      pending: [
        { label: 'Day 7 Reminder',      sendAt: now + 7  * 86400000, sent: false },
        { label: 'Day 14 Final Notice', sendAt: now + 14 * 86400000, sent: false },
      ],
    });
    saveFollowups(followups);

    res.json({ success: true, message: `Demand letter sent to ${brokerEmail} with CC to ${carrierEmail}` });
  } catch(err) {
    console.error('Email error:', err);
    res.status(500).json({ error: 'Email failed: ' + err.message });
  }
});

// ── STRIPE PAYMENT ────────────────────────────────────────────
// Stripe is DISABLED (devMode) until re-enabled by admin
app.post('/api/create-checkout', rateLimit(60000, 10), async (req, res) => {
  // Payment bypassed — return devMode so client skips Stripe
  if (!stripe || process.env.STRIPE_DISABLED === 'true') {
    return res.json({ devMode: true });
  }
  try {
    const baseUrl = process.env.BASE_URL || `http://localhost:${PORT}`;
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price_data: {
          currency: 'usd',
          product_data: {
            name:        'FreightGuard Defense — Demand Letter',
            description: 'AI-drafted federal demand letter with damages calculation, court locator, and direct email delivery.',
          },
          unit_amount: parseInt(process.env.STRIPE_PRICE_AMOUNT) || 25000,
        },
        quantity: 1,
      }],
      mode:        'payment',
      success_url: `${baseUrl}/?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url:  `${baseUrl}/`,
      metadata:    { product: 'demand_letter' },
    });
    res.json({ url: session.url });
  } catch(err) {
    console.error('Stripe error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/verify-payment', async (req, res) => {
  const { session_id } = req.query;
  if (!session_id) return res.status(400).json({ error: 'No session ID' });
  if (!stripe || process.env.STRIPE_DISABLED === 'true') return res.json({ paid: true, devMode: true });
  try {
    const session = await stripe.checkout.sessions.retrieve(session_id);
    const paid    = session.payment_status === 'paid';
    const email   = session.customer_details?.email || '';

    // Save user registration
    if (paid) {
      const users = loadUsers();
      if (!users.find(u => u.stripeSessionId === session_id)) {
        users.push({ id: Date.now().toString(), email, stripeSessionId: session_id, paidAt: new Date().toISOString(), caseRefs: [] });
        saveUsers(users);
      }
    }

    res.json({ paid, email });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

// ── ATTORNEY COVERAGE BY STATE ────────────────────────────────
app.get('/api/attorneys/coverage', async (req, res) => {
  const { state }  = req.query;
  const attorneys  = await loadAttorneys();
  const matched    = state
    ? attorneys.filter(a => (a.licenseStates || a.barState || '').toUpperCase().includes(state.toUpperCase()))
    : attorneys;

  const result = matched.map(a => {
    const primaryState = (a.barState || (a.licenseStates || '').split(',')[0] || '').trim().toUpperCase();
    const court        = FEDERAL_COURTS[primaryState] || FEDERAL_COURTS['IL'];
    return { id: a.id, name: a.name, firmName: a.firmName || null, barState: a.barState, licenseStates: a.licenseStates, city: court.city, state: court.state, phone: a.phone || null };
  });

  res.json(result);
});

// ── CLIENT AUTH ───────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'fgd-secret-change-me-in-production';

function makeJWT(payload) {
  if (!jwt) return null;
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '30d' });
}

function requireClient(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Login required' });
  try {
    if (!jwt) return res.status(500).json({ error: 'JWT package not installed' });
    req.clientUser = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch { return res.status(401).json({ error: 'Session expired. Please log in again.' }); }
}

// Register
app.post('/api/auth/register', rateLimit(60000, 10), async (req, res) => {
  const { email, name, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
  if (password.length < 6)  return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const existing = await dbGetUserByEmail(email.toLowerCase().trim());
  if (existing) return res.status(409).json({ error: 'An account with this email already exists' });
  const hash = bcrypt ? await bcrypt.hash(password, 10) : password;
  const user = await dbCreateUser({ email: email.toLowerCase().trim(), name: name||'', passwordHash: hash });
  const token = makeJWT({ id: user.id, email: user.email });
  res.json({ token, user: { id: user.id, email: user.email, name: user.name } });
});

// Email/password login
app.post('/api/auth/login', rateLimit(60000, 20), async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
  const user = await dbGetUserByEmail(email.toLowerCase().trim());
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });
  if (user.suspended) return res.status(403).json({ error: 'Your account has been suspended. Contact support.' });
  const hash = user.password_hash || user.passwordHash;
  const valid = bcrypt ? await bcrypt.compare(password, hash||'') : (password === hash);
  if (!valid) return res.status(401).json({ error: 'Invalid email or password' });
  await dbUpdateUserLogin(user.id);
  const token = makeJWT({ id: user.id, email: user.email });
  res.json({ token, user: { id: user.id, email: user.email, name: user.name||'' } });
});

// Google Sign-In
app.post('/api/auth/google', rateLimit(60000, 20), async (req, res) => {
  const { credential } = req.body; // Google ID token
  if (!credential) return res.status(400).json({ error: 'Google credential required' });
  try {
    let payload;
    try {
      const { OAuth2Client } = require('google-auth-library');
      const clientId = cfg('GOOGLE_CLIENT_ID') || process.env.GOOGLE_CLIENT_ID;
      if (!clientId) throw new Error('GOOGLE_CLIENT_ID not configured');
      const gClient = new OAuth2Client(clientId);
      const ticket  = await gClient.verifyIdToken({ idToken: credential, audience: clientId });
      payload = ticket.getPayload();
    } catch {
      // Fallback: decode JWT without verification (for testing only)
      const parts = credential.split('.');
      if (parts.length !== 3) throw new Error('Invalid Google credential');
      payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
    }
    const { sub: googleId, email, name, picture } = payload;
    if (!email) return res.status(400).json({ error: 'Could not get email from Google' });
    let user = await dbGetUserByEmail(email.toLowerCase());
    if (user) {
      if (user.suspended) return res.status(403).json({ error: 'Account suspended. Contact support.' });
      await dbUpdateUserLogin(user.id);
    } else {
      user = await dbCreateUser({ email: email.toLowerCase(), name: name||'', googleId, googlePicture: picture||'' });
    }
    const token = makeJWT({ id: user.id, email: user.email });
    res.json({ token, user: { id: user.id, email: user.email, name: user.name||name||'' } });
  } catch(err) {
    console.error('Google auth error:', err.message);
    res.status(400).json({ error: 'Google sign-in failed: ' + err.message });
  }
});

// Get current user
app.get('/api/auth/me', requireClient, async (req, res) => {
  const user = await dbGetUserById(req.clientUser.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.suspended) return res.status(403).json({ error: 'Account suspended' });
  res.json({ id: user.id, email: user.email, name: user.name||'' });
});

// Google client ID (public — needed by login.html)
app.get('/api/auth/google-client-id', (req, res) => {
  res.json({ clientId: cfg('GOOGLE_CLIENT_ID') || process.env.GOOGLE_CLIENT_ID || '' });
});

// ── PASSWORD RESET ────────────────────────────────────────────
const crypto = require('crypto');

app.post('/api/auth/forgot-password', rateLimit(60000, 5), async (req, res) => {
  // Always return success to prevent email enumeration
  const { email } = req.body;
  if (!email) return res.json({ ok: true });
  try {
    const user = await dbGetUserByEmail(email.toLowerCase().trim());
    if (!user) return res.json({ ok: true }); // don't reveal non-existence
    if (user.google_id && !user.password_hash) {
      // Google-only account — send guidance email
      await sendEmail(
        user.email,
        'FreightGuard Defense — Password Reset',
        `Hi ${user.name||'there'},

Your FreightGuard Defense account uses Google Sign-In. Please click "Continue with Google" on the login page to access your account.

If you need help, reply to this email.

FreightGuard Defense Team`
      ).catch(() => {});
      return res.json({ ok: true });
    }
    // Generate a secure reset token (valid 1 hour)
    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 3600000); // 1 hour
    if (pgPool) {
      // Expire any previous tokens for this user
      await pgPool.query('UPDATE password_reset_tokens SET used=TRUE WHERE user_id=$1 AND used=FALSE', [user.id]).catch(() => {});
      await pgPool.query(
        'INSERT INTO password_reset_tokens(user_id,token,expires_at) VALUES($1,$2,$3)',
        [user.id, token, expires]
      );
    } else {
      // File fallback: store in a simple JSON file
      const tokensFile = './data/reset_tokens.json';
      const tokens = loadJSON(tokensFile);
      // Remove old tokens for this user
      const filtered = tokens.filter(t => String(t.userId) !== String(user.id) || t.used);
      filtered.push({ userId: user.id, token, expiresAt: expires.toISOString(), used: false });
      saveJSON(tokensFile, filtered);
    }
    const siteUrl = process.env.SITE_URL || 'https://freightguarddefense.com';
    const resetUrl = siteUrl + '/login.html?reset=' + token;
    await sendEmail(
      user.email,
      'Reset Your FreightGuard Defense Password',
      `Hi ${user.name||'there'},\n\nYou requested a password reset for your FreightGuard Defense account.\n\nClick the link below to reset your password (valid for 1 hour):\n\n${resetUrl}\n\nIf you did not request this, you can safely ignore this email.\n\nFreightGuard Defense Team`,
      `<div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:32px;">
        <div style="text-align:center;margin-bottom:32px;">
          <div style="font-size:40px;">⚖️</div>
          <h1 style="font-size:22px;font-weight:700;color:#0d1117;">FreightGuard <span style="color:#f0b429;">Defense</span></h1>
        </div>
        <h2 style="font-size:18px;color:#0d1117;margin-bottom:12px;">Reset Your Password</h2>
        <p style="color:#555;line-height:1.6;margin-bottom:24px;">Hi ${user.name||'there'},<br><br>You requested a password reset. Click the button below — the link expires in <strong>1 hour</strong>.</p>
        <div style="text-align:center;margin:32px 0;">
          <a href="${resetUrl}" style="background:#f0b429;color:#000;text-decoration:none;padding:14px 32px;border-radius:8px;font-weight:700;font-size:15px;display:inline-block;">Reset My Password →</a>
        </div>
        <p style="color:#999;font-size:12px;text-align:center;">If you didn't request this, ignore this email. Your password won't change.</p>
        <hr style="border:none;border-top:1px solid #eee;margin:24px 0;">
        <p style="color:#999;font-size:12px;text-align:center;">FreightGuard Defense · freightguarddefense.com</p>
      </div>`
    );
  } catch(err) {
    console.error('Forgot password error:', err.message);
  }
  res.json({ ok: true });
});

app.post('/api/auth/reset-password', rateLimit(60000, 10), async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({ error: 'Token and password are required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  try {
    let userId = null;
    if (pgPool) {
      const r = await pgPool.query(
        'SELECT * FROM password_reset_tokens WHERE token=$1 AND used=FALSE AND expires_at > NOW()',
        [token]
      );
      if (!r.rows.length) return res.status(400).json({ error: 'Reset link is invalid or has expired. Please request a new one.' });
      userId = r.rows[0].user_id;
      await pgPool.query('UPDATE password_reset_tokens SET used=TRUE WHERE token=$1', [token]);
    } else {
      const tokensFile = './data/reset_tokens.json';
      const tokens = loadJSON(tokensFile);
      const t = tokens.find(t => t.token === token && !t.used && new Date(t.expiresAt) > new Date());
      if (!t) return res.status(400).json({ error: 'Reset link is invalid or has expired. Please request a new one.' });
      userId = t.userId;
      t.used = true;
      saveJSON(tokensFile, tokens);
    }
    const hash = bcrypt ? await bcrypt.hash(password, 10) : password;
    if (pgPool) {
      await pgPool.query('UPDATE client_users SET password_hash=$1 WHERE id=$2', [hash, userId]);
    } else {
      const users = loadJSON(CLIENT_USERS_FILE);
      const u = users.find(u => String(u.id) === String(userId));
      if (u) { u.passwordHash = hash; saveJSON(CLIENT_USERS_FILE, users); }
    }
    res.json({ ok: true });
  } catch(err) {
    console.error('Reset password error:', err.message);
    res.status(500).json({ error: 'Failed to reset password. Please try again.' });
  }
});

// ── CLIENT PORTAL ─────────────────────────────────────────────
app.get('/api/portal/letters', requireClient, async (req, res) => {
  const all     = await loadLetters();
  const email   = req.clientUser.email.toLowerCase();
  const mine    = all.filter(l => (l.carrierEmail||'').toLowerCase() === email);
  res.json({ letters: mine.map(l => ({ ...l, letterText: undefined, createdAt: l.ts||l.createdAt })) });
});

app.get('/api/portal/letter/:caseRef', requireClient, async (req, res) => {
  const all    = await loadLetters();
  const letter = all.find(l => l.caseRef === req.params.caseRef || l.id === req.params.caseRef);
  if (!letter) return res.status(404).json({ error: 'Letter not found' });
  // Allow access if email matches or admin (checked via client JWT)
  const email = req.clientUser.email.toLowerCase();
  if ((letter.carrierEmail||'').toLowerCase() !== email) {
    return res.status(403).json({ error: 'Access denied' });
  }
  res.json({ ...letter, createdAt: letter.ts||letter.createdAt });
});

// ── ATTORNEY RECRUITMENT & INVITES ───────────────────────────────────────────
const SITE_URL = process.env.SITE_URL || 'https://freightguarddefense.com';

async function sendAttorneyInviteEmail(invite) {
  const joinUrl = `${SITE_URL}/attorney-join.html?token=${invite.token}`;
  const subject = 'Join FreightGuard Defense — Earn $100 Per Approved Demand Letter';
  const text = `Dear ${invite.name || 'Counselor'},

You have been personally invited to join the FreightGuard Defense Attorney Network.

FreightGuard Defense is a legal protection platform serving motor carriers who have been harmed by false FreightGuard reports and unpaid freight invoices. Our platform generates federally-formatted demand letters and connects carriers with licensed transportation attorneys.

WHY JOIN:
• Earn $100.00 per approved pre-litigation demand letter
• Cases come to you — no marketing required
• Work remotely — review and approve letters on your schedule
• Niche practice area: 49 U.S.C. § 14915, defamation, tortious interference
• Growing carrier base across all 50 states

HOW IT WORKS:
1. Accept this invitation and complete your attorney profile
2. Letters are assigned to you based on your licensed states
3. Review and approve each demand letter for $100 flat fee
4. Carrier receives letter with your credentials — you handle any follow-up litigation

TO ACCEPT YOUR INVITATION:
${joinUrl}

This invitation link is unique to you and expires in 7 days.

Questions? Reply to this email or call our team.

FreightGuard Defense
Carrier Legal Protection Network
${SITE_URL}`;

  const html = `<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;background:#f5f5f5;margin:0;padding:0;">
<div style="max-width:600px;margin:0 auto;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,0.1);">
  <div style="background:linear-gradient(135deg,#0a1628 0%,#1a2a4a 100%);padding:32px 40px;text-align:center;">
    <div style="font-size:28px;margin-bottom:8px;">⚖️</div>
    <h1 style="color:#fff;font-size:22px;margin:0;">FreightGuard Defense</h1>
    <p style="color:#7ab3ff;font-size:13px;margin:4px 0 0;">Attorney Network Invitation</p>
  </div>
  <div style="padding:32px 40px;">
    <p style="color:#1a1a2a;font-size:15px;">Dear ${invite.name || 'Counselor'},</p>
    <p style="color:#333;font-size:14px;line-height:1.7;">You have been personally invited to join the <strong>FreightGuard Defense Attorney Network</strong> — a growing legal protection platform serving motor carriers nationwide.</p>
    <div style="background:#f0f4ff;border-left:4px solid #2c5aa0;padding:16px 20px;border-radius:0 8px 8px 0;margin:20px 0;">
      <p style="margin:0;font-size:15px;font-weight:700;color:#1a2a4a;">💰 Earn $100 per approved demand letter</p>
      <p style="margin:4px 0 0;font-size:13px;color:#555;">No client acquisition. No marketing. Cases assigned to you.</p>
    </div>
    <h3 style="color:#1a2a4a;font-size:14px;border-bottom:1px solid #eee;padding-bottom:8px;">Why Attorneys Love Our Network:</h3>
    <ul style="color:#333;font-size:13px;line-height:2;padding-left:20px;">
      <li>$100 flat fee per approved pre-litigation letter — paid automatically</li>
      <li>Work from anywhere — review letters on your own schedule</li>
      <li>Specialized in transportation law under 49 U.S.C. § 14915</li>
      <li>Letters assigned by your licensed states — instant jurisdiction match</li>
      <li>Growing pipeline — thousands of carriers filing FreightGuard disputes monthly</li>
    </ul>
    <div style="text-align:center;margin:28px 0;">
      <a href="${joinUrl}" style="background:#c0392b;color:#fff;text-decoration:none;padding:16px 36px;border-radius:8px;font-size:15px;font-weight:700;display:inline-block;">Accept Invitation & Join Network</a>
    </div>
    <p style="color:#888;font-size:11px;text-align:center;">This invitation is unique to you and expires in 7 days.<br>Invitation for: ${invite.email}</p>
  </div>
  <div style="background:#f5f5f5;padding:16px 40px;text-align:center;font-size:11px;color:#999;">
    FreightGuard Defense · ${SITE_URL}
  </div>
</div></body></html>`;

  await dispatchEmail({ to: invite.email, subject, text, html });
}

// Send single attorney invite
app.post('/api/admin/attorney-invite', requireAdmin, async (req, res) => {
  const { email, name, specialty } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });

  const token   = require('crypto').randomBytes(24).toString('hex');
  const invite  = { id: token.slice(0,12), email, name: name||'', specialty: specialty||'', token, status: 'pending', invited_at: new Date().toISOString() };

  // Save
  const invites = loadInvites();
  invites[token] = invite;
  saveInvites(invites);

  // DB
  if (pgPool) {
    await pgPool.query(
      'INSERT INTO attorney_invites(id,email,name,specialty,token,status) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(token) DO NOTHING',
      [invite.id, email, name||'', specialty||'', token, 'pending']
    ).catch(() => {});
  }

  try {
    await sendAttorneyInviteEmail(invite);
    res.json({ ok: true, message: `Invitation sent to ${email}` });
  } catch(e) {
    res.status(500).json({ error: 'Saved but email failed: ' + e.message });
  }
});

// Bulk invite from uploaded Excel/CSV data (frontend parses, sends JSON array)
app.post('/api/admin/attorney-invite/bulk', requireAdmin, async (req, res) => {
  const { contacts } = req.body; // [{email, name, specialty}]
  if (!Array.isArray(contacts) || contacts.length === 0)
    return res.status(400).json({ error: 'No contacts provided' });

  const results = [];
  const invites = loadInvites();

  for (const c of contacts.slice(0, 200)) { // cap at 200 per batch
    if (!c.email || !/\S+@\S+/.test(c.email)) { results.push({ email: c.email, status: 'skipped', reason: 'invalid email' }); continue; }
    const token  = require('crypto').randomBytes(24).toString('hex');
    const invite = { id: token.slice(0,12), email: c.email, name: c.name||'', specialty: c.specialty||'', token, status: 'pending', invited_at: new Date().toISOString() };
    invites[token] = invite;
    if (pgPool) await pgPool.query('INSERT INTO attorney_invites(id,email,name,specialty,token,status) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(token) DO NOTHING', [invite.id, c.email, c.name||'', c.specialty||'', token, 'pending']).catch(() => {});
    try { await sendAttorneyInviteEmail(invite); results.push({ email: c.email, status: 'sent' }); }
    catch(e) { results.push({ email: c.email, status: 'failed', reason: e.message }); }
    await new Promise(r => setTimeout(r, 200)); // rate limit
  }

  saveInvites(invites);
  res.json({ results, sent: results.filter(r=>r.status==='sent').length, failed: results.filter(r=>r.status!=='sent').length });
});

// List all invites
app.get('/api/admin/attorney-invites', requireAdmin, (req, res) => {
  const invites = Object.values(loadInvites()).sort((a,b) => b.invited_at > a.invited_at ? 1 : -1);
  res.json({ invites });
});

// Resend invite
app.post('/api/admin/attorney-invite/resend/:token', requireAdmin, async (req, res) => {
  const invites = loadInvites();
  const invite  = invites[req.params.token];
  if (!invite) return res.status(404).json({ error: 'Invite not found' });
  invite.resent_at = new Date().toISOString();
  invites[req.params.token] = invite;
  saveInvites(invites);
  try { await sendAttorneyInviteEmail(invite); res.json({ ok: true }); }
  catch(e) { res.status(500).json({ error: e.message }); }
});

// Attorney validates invite token
app.get('/api/attorney/invite/:token', (req, res) => {
  const invites = loadInvites();
  const invite  = invites[req.params.token];
  if (!invite) return res.status(404).json({ error: 'Invalid or expired invitation' });
  if (invite.status === 'accepted') return res.status(410).json({ error: 'This invitation has already been used' });
  res.json({ ok: true, email: invite.email, name: invite.name, specialty: invite.specialty });
});

// Attorney completes signup from invite link
app.post('/api/attorney/register', async (req, res) => {
  const { token, name, firmName, barNumber, barState, licenseStates, phone, specialty, email } = req.body;
  if (!token || !name || !barNumber || !barState)
    return res.status(400).json({ error: 'Name, bar number, and bar state are required' });

  const invites = loadInvites();
  const invite  = invites[token];
  if (!invite) return res.status(404).json({ error: 'Invalid invitation token' });
  if (invite.status === 'accepted') return res.status(410).json({ error: 'Invitation already used' });

  // Create attorney record
  const id = 'atty_' + Date.now();
  const attorney = {
    id, name, firmName: firmName||'', barNumber, barState,
    email: email || invite.email, phone: phone||'',
    licenseStates: licenseStates||barState, specialty: specialty || invite.specialty || '',
    status: 'active', inviteToken: token,
    createdAt: new Date().toISOString(),
  };

  if (pgPool) {
    await pgPool.query(
      'INSERT INTO attorneys(id,name,firm_name,bar_number,bar_state,email,phone,license_states,specialty,status,invite_token) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',
      [id, name, firmName||'', barNumber, barState, attorney.email, phone||'', licenseStates||barState, attorney.specialty, 'active', token]
    ).catch(async () => {
      const all = await loadAttorneys();
      all.push(attorney);
      saveJSON(path.join(DATA_DIR, 'attorneys.json'), all);
    });
  } else {
    const all = await loadAttorneys();
    all.push(attorney);
    saveJSON(path.join(DATA_DIR, 'attorneys.json'), all);
  }

  // Mark invite accepted
  invite.status    = 'accepted';
  invite.accepted_at = new Date().toISOString();
  invites[token]   = invite;
  saveInvites(invites);
  if (pgPool) await pgPool.query('UPDATE attorney_invites SET status=$1, accepted_at=NOW() WHERE token=$2', ['accepted', token]).catch(() => {});

  // Welcome email
  try {
    await dispatchEmail({
      to: attorney.email, subject: 'Welcome to FreightGuard Defense Attorney Network',
      text: `Dear ${name},\n\nWelcome to the FreightGuard Defense Attorney Network! Your profile is now active.\n\nYou will begin receiving letter assignments for cases in your licensed states. Each approved demand letter pays $100, wired monthly.\n\nLog in to manage your assignments: ${SITE_URL}\n\nFreightGuard Defense`,
      html: `<p>Dear ${name},</p><p>Welcome to the <strong>FreightGuard Defense Attorney Network</strong>! Your profile is now active.</p><p>You will receive letter assignments for cases in <strong>${licenseStates||barState}</strong>. Each approved letter pays <strong>$100</strong>.</p><p><a href="${SITE_URL}">Log in to manage your assignments</a></p>`,
    });
  } catch {}

  res.json({ ok: true, message: 'Welcome! Your attorney profile is now active.', attorney: { id, name, email: attorney.email } });
});

// ── ADMIN AUTH ────────────────────────────────────────────────
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'mikee@megafleetcorp.com';

function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'];
  if (token !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (password === ADMIN_PASSWORD) {
    res.json({ token: ADMIN_PASSWORD, success: true });
  } else {
    res.status(401).json({ error: 'Invalid password' });
  }
});

app.get('/api/admin/overview', requireAdmin, async (req, res) => {
  const [users, letters, reports, attorneys, followups] = await Promise.all([
    Promise.resolve(loadUsers()),
    loadLetters(),
    loadReports(),
    loadAttorneys(),
    Promise.resolve(loadFollowups()),
  ]);
  const totalDamages   = letters.reduce((sum, l) => sum + (Number(l.totalDamages)||0), 0);
  const stripeDisabled = !stripe || process.env.STRIPE_DISABLED === 'true';
  res.json({
    userCount:     users.length,
    letterCount:   letters.length,
    reportCount:   reports.length,
    followupCount: followups.length,
    attorneyCount: attorneys.length,
    totalDamages,
    recentLetters: letters
      .sort((a, b) => new Date(b.ts||b.createdAt||0) - new Date(a.ts||a.createdAt||0))
      .slice(0, 10)
      .map(l => ({ ...l, letterText: undefined, createdAt: l.ts||l.createdAt })),
    apis: {
      anthropic:  !!(cfg('ANTHROPIC_API_KEY')||process.env.ANTHROPIC_API_KEY),
      stripe:     !!stripe && !stripeDisabled,
      resend:     !!resendClient,
      smtp:       !!process.env.SMTP_USER,
      googleMaps: !!(cfg('GOOGLE_MAPS_API_KEY')||process.env.GOOGLE_MAPS_API_KEY),
      stripeMode: stripeDisabled ? 'Free Access (Disabled)' : 'Live',
    },
  });
});

// ── ADMIN CONFIG (API keys) ───────────────────────────────────
const CONFIG_KEYS = ['ANTHROPIC_API_KEY','RESEND_API_KEY','RESEND_FROM_EMAIL','GOOGLE_MAPS_API_KEY',
  'STRIPE_SECRET_KEY','STRIPE_PRICE_AMOUNT','FIRM_NAME','ADMIN_PASSWORD','JWT_SECRET','GOOGLE_CLIENT_ID'];

app.get('/api/admin/config', requireAdmin, (req, res) => {
  try {
    const fileConfig = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
    const out = {};
    for (const k of CONFIG_KEYS) {
      const v = fileConfig[k] || process.env[k] || '';
      // Mask secrets — show last 4 chars only
      const isSensitive = k.includes('KEY') || k.includes('SECRET') || k === 'ADMIN_PASSWORD' || k === 'JWT_SECRET';
      out[k] = v ? (isSensitive && v.length > 4 ? '•'.repeat(v.length - 4) + v.slice(-4) : v) : '';
      out[k + '_set'] = !!v;
    }
    res.json(out);
  } catch { res.json({}); }
});

app.put('/api/admin/config', requireAdmin, async (req, res) => {
  const updates = {};
  for (const k of CONFIG_KEYS) {
    if (req.body[k] !== undefined && req.body[k] !== '' && !req.body[k].startsWith('•')) {
      updates[k] = req.body[k];
    }
  }
  await saveConfig(updates);
  // Re-init Anthropic client if key updated
  if (updates.ANTHROPIC_API_KEY) {
    anthropic._client = new Anthropic({ apiKey: updates.ANTHROPIC_API_KEY });
  }
  res.json({ success: true, updated: Object.keys(updates) });
});

// ── ADMIN: STRIPE USERS ───────────────────────────────────────
app.get('/api/admin/users', requireAdmin, (req, res) => {
  const users = loadUsers().sort((a, b) => new Date(b.paidAt || 0) - new Date(a.paidAt || 0));
  res.json({ users });
});

app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  saveUsers(loadUsers().filter(u => u.id !== req.params.id));
  res.json({ success: true });
});

// ── ADMIN: CLIENT PORTAL USERS ────────────────────────────────
app.get('/api/admin/client-users', requireAdmin, async (req, res) => {
  res.json({ users: await dbListClientUsers() });
});

app.post('/api/admin/client-users/:id/suspend', requireAdmin, async (req, res) => {
  await dbSuspendUser(req.params.id, true);
  res.json({ success: true });
});

app.post('/api/admin/client-users/:id/unsuspend', requireAdmin, async (req, res) => {
  await dbSuspendUser(req.params.id, false);
  res.json({ success: true });
});

app.delete('/api/admin/client-users/:id', requireAdmin, async (req, res) => {
  await dbDeleteClientUser(req.params.id);
  res.json({ success: true });
});

app.post('/api/admin/client-users/:id/reset-password', requireAdmin, async (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const hash = bcrypt ? await bcrypt.hash(newPassword, 10) : newPassword;
  await dbResetPassword(req.params.id, hash);
  res.json({ success: true });
});

// ── ADMIN: LETTERS + REPORTS ──────────────────────────────────
app.get('/api/admin/letters', requireAdmin, async (req, res) => {
  const letters = await loadLetters();
  res.json({ letters: letters.map(l => ({ ...l, createdAt: l.ts||l.createdAt, letterText: undefined })) });
});

app.get('/api/admin/letters/:caseRef', requireAdmin, async (req, res) => {
  const letters = await loadLetters();
  const letter  = letters.find(l => l.caseRef === req.params.caseRef || l.id === req.params.caseRef);
  if (!letter) return res.status(404).json({ error: 'Letter not found' });
  let attorney = null;
  if (letter.attorneyId) {
    const attorneys = await loadAttorneys();
    attorney = attorneys.find(a => a.id === letter.attorneyId) || null;
  }
  res.json({ ...letter, attorney, createdAt: letter.ts||letter.createdAt });
});

app.get('/api/admin/reports', requireAdmin, async (req, res) => {
  const reports = await loadReports();
  res.json({ reports: reports.map(r => ({ ...r, createdAt: r.ts||r.createdAt })) });
});

app.get('/api/admin/followups', requireAdmin, (req, res) => {
  const followups = loadFollowups().sort((a, b) => b.id - a.id);
  // Flatten pending steps into individual rows for display
  const rows = [];
  for (const job of followups) {
    for (const step of (job.pending || [])) {
      rows.push({
        id:       job.id + '_' + step.label,
        caseRef:  job.caseRef,
        email:    job.brokerEmail,
        day:      step.label.includes('14') ? 14 : 7,
        status:   step.sent ? 'sent' : 'pending',
        sentAt:   step.sentAt || null,
        scheduledAt: step.sendAt ? new Date(step.sendAt).toISOString() : null,
      });
    }
  }
  res.json({ followups: rows });
});

// ── FOLLOW-UP EMAIL SCHEDULER ────────────────────────────────
async function runFollowupScheduler() {
  const followups = loadFollowups();
  let changed     = false;
  const now       = Date.now();

  for (const job of followups) {
    for (const step of job.pending) {
      if (step.sent || now < step.sendAt) continue;
      const isDay14 = step.label.includes('14');
      const subj = isDay14
        ? `⚠️ FINAL NOTICE — Case ${job.caseRef} — 14-Day Deadline Expired — Filing Imminent`
        : `FOLLOW-UP — Case ${job.caseRef} — Awaiting Response to Legal Demand`;
      const body = isDay14
        ? `${job.brokerName},\n\nThis is final notice regarding Case No. ${job.caseRef}.\n\nOur client's 14-day response deadline has expired. Our attorneys are prepared to file in federal court. This is your final opportunity to resolve this matter without litigation.\n\nUnless we receive written confirmation of (1) retraction of the FreightGuard report and (2) payment confirmation within 48 hours, we will proceed with filing.\n\nDo not ignore this communication.\n\nLegal Department\n${process.env.FIRM_NAME || 'FreightGuard Defense'}`
        : `${job.brokerName},\n\nThis is a follow-up regarding our formal demand letter sent on behalf of ${job.carrierName} (Case No. ${job.caseRef}).\n\nAs of today, we have not received a response. Our client's 14-day deadline is approaching. We strongly encourage you to respond in writing before the deadline expires.\n\nLegal Department\n${process.env.FIRM_NAME || 'FreightGuard Defense'}`;

      try {
        await dispatchEmail({ to: job.brokerEmail, cc: job.carrierEmail, subject: subj, text: body, html: `<pre style="font-family:sans-serif;white-space:pre-wrap;">${body}</pre>` });
        step.sent   = true;
        step.sentAt = new Date().toISOString();
        changed     = true;
        console.log(`✉️  Follow-up sent [${step.label}] → ${job.brokerEmail} (Case ${job.caseRef})`);
      } catch(e) {
        console.error(`Follow-up send failed [${step.label}]:`, e.message);
      }
    }
  }
  if (changed) saveFollowups(followups);
}

setInterval(runFollowupScheduler, 3600000);
setTimeout(runFollowupScheduler, 30000);

// ── START ─────────────────────────────────────────────────────
const server = app.listen(PORT, () => {
  console.log('');
  console.log('╔══════════════════════════════════════════════════════╗');
  console.log('║        FreightGuard Defense  —  Server Ready          ║');
  console.log('╚══════════════════════════════════════════════════════╝');
  console.log(`  🌐  URL:              http://localhost:${PORT}`);
  console.log(`  🤖  Anthropic API:    ${process.env.ANTHROPIC_API_KEY  ? '✅ Connected' : '❌ Missing ANTHROPIC_API_KEY'}`);
  console.log(`  💳  Stripe:           ${stripe && process.env.STRIPE_DISABLED !== 'true' ? '✅ Active' : '⚠️  DISABLED (free access mode)'}`);
  console.log(`  📨  Resend Email:     ${resendClient                   ? '✅ Connected' : '⚠️  Not set'}`);
  console.log(`  📧  SMTP Fallback:    ${process.env.SMTP_USER          ? '✅ Configured' : '⚠️  Not set'}`);
  console.log(`  🗺️   Google Maps:      ${process.env.GOOGLE_MAPS_API_KEY ? '✅ Connected' : '⚠️  Not set (state fallback active)'}`);
  console.log(`  🔐  Admin Panel:      http://localhost:${PORT}/admin.html`);
  console.log(`  📁  Data dir:         ${DATA_DIR}`);
  console.log('');
  if (!process.env.ANTHROPIC_API_KEY) {
    console.error('  ⚠️   WARNING: ANTHROPIC_API_KEY is not set. Letter generation will fail until you add it to .env');
  }
});

// ── GLOBAL ERROR HANDLER ──────────────────────────────────────
// Catches any unhandled Express errors — always returns JSON (never empty)
app.use((err, req, res, next) => {
  console.error('Unhandled Express error:', err.message);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: err.message || 'Internal server error' });
});

// ── 404 CATCH-ALL ──────────────────────────────�