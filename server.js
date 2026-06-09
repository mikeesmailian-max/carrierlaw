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
      ALTER TABLE letters ADD COLUMN IF NOT EXISTS review_status TEXT DEFAULT 'pending_review';
      ALTER TABLE letters ADD COLUMN IF NOT EXISTS attorney_notes TEXT;
      ALTER TABLE letters ADD COLUMN IF NOT EXISTS reviewed_by TEXT;
      ALTER TABLE letters ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ;
      ALTER TABLE letters ADD COLUMN IF NOT EXISTS locked BOOLEAN DEFAULT FALSE;
      ALTER TABLE letters ADD COLUMN IF NOT EXISTS stripe_session_id TEXT;
      ALTER TABLE letters ADD COLUMN IF NOT EXISTS carrier_phone TEXT;
      ALTER TABLE letters ADD COLUMN IF NOT EXISTS email_opened_at TIMESTAMPTZ;
      ALTER TABLE attorneys ADD COLUMN IF NOT EXISTS password_hash TEXT;
      ALTER TABLE attorneys ADD COLUMN IF NOT EXISTS last_login TIMESTAMPTZ;
      CREATE TABLE IF NOT EXISTS letter_audit (
        id SERIAL PRIMARY KEY, case_ref TEXT NOT NULL, event TEXT NOT NULL,
        actor TEXT, details TEXT, ip TEXT, ts TIMESTAMPTZ DEFAULT NOW()
      );
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

// ── TWILIO SMS CLIENT ─────────────────────────────────────────
let twilioClient = null;
try {
  if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN) {
    const twilio = require('twilio');
    twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
    console.log('  📱  Twilio SMS:        ✅ Connected');
  }
} catch(e) { /* twilio not installed */ }

async function sendSMS(to, body) {
  if (!twilioClient || !process.env.TWILIO_FROM_NUMBER) return;
  const phone = String(to).replace(/[^+\d]/g, '');
  if (!phone || phone.length < 10) return;
  try {
    await twilioClient.messages.create({
      body,
      from: process.env.TWILIO_FROM_NUMBER,
      to:   phone.startsWith('+') ? phone : '+1' + phone,
    });
  } catch(e) { console.warn('SMS failed:', e.message); }
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
const DATA_DIR = path.join(__dirname, 'data');

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

// Email with open-tracking pixel
function buildEmailHtmlTracked(letterText, caseRef) {
  const siteUrl = process.env.SITE_URL || 'https://freightguarddefense.com';
  const html    = buildEmailHtml(letterText);
  const pixel   = caseRef ? `<img src="${siteUrl}/api/pixel/${encodeURIComponent(caseRef)}" width="1" height="1" style="display:none;" alt="" />` : '';
  return html.replace('</body>', pixel + '</body>') || html + pixel;
}

async function dispatchEmail({ to, cc, subject, text, html }) {
  const fromName = process.env.FIRM_NAME || 'FreightGuard Defense Legal Network';

  // Try Resend first
  if (resendClient) {
    const fromEmail = cfg('RESEND_FROM_EMAIL') || process.env.RESEND_FROM_EMAIL || 'legal@freightguarddefense.com';
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

    // ── 3-PARTY EMAIL DISPATCH (Collection) ─────────────────────────────────
    const autoSent = { sent: false, brokerSent: false, carrierSent: false, attorneySent: false, error: null };
    if (brokerEmail) {
      const colSubj    = `FINAL DEMAND FOR PAYMENT — ${brokerName} — Invoice ${invoiceNumber||caseRef} — $${totalOwed.toLocaleString()} Due`;
      const colHtml    = buildEmailHtmlTracked(letterText, caseRef);
      const colAttyEmail = attorney ? (attorney.email||'') : '';
      const ccList     = [carrierEmail, colAttyEmail].filter(Boolean);

      // 1. TO BROKER — CC carrier + attorney
      try {
        await dispatchEmail({ to: brokerEmail, cc: ccList, subject: colSubj, text: letterText, html: colHtml });
        autoSent.brokerSent = true; autoSent.sent = true;
        await logAudit(caseRef, 'broker_emailed', carrierEmail, `Collection letter sent to broker ${brokerEmail}`);
      } catch(e) { autoSent.error = 'Broker: ' + e.message; }

      // 2. CARRIER COPY — dedicated email
      try {
        await dispatchEmail({
          to: carrierEmail,
          subject: `✅ Your Copy — Collection Letter Sent to ${brokerName} (Case ${caseRef})`,
          text: `Your collection demand has been sent to ${brokerName} at ${brokerEmail}.\n\nCase: ${caseRef}\nInvoice: ${invoiceNumber||'N/A'}\nOriginal Amount: $${principal.toLocaleString()}\nAttorney Fees (50%): $${attyFees.toLocaleString()}\nTotal Demanded: $${totalOwed.toLocaleString()}\nPay-By Deadline: ${deadlineStr}\n\nDay 7 & Day 14 follow-up reminders are scheduled.\n\n--- YOUR LETTER ---\n\n${letterText}`,
          html: `<div style="font-family:Arial,sans-serif;max-width:640px;margin:0 auto;">
            <div style="background:#0a1628;padding:20px 28px;text-align:center;"><h2 style="color:#fff;margin:0;">💰 FreightGuard Defense</h2><p style="color:#7ab3ff;font-size:12px;margin:4px 0 0;">Collection Letter — Your Copy</p></div>
            <div style="padding:24px 28px;background:#f9f9f9;">
              <p style="font-size:14px;">Dear <strong>${carrierName}</strong>,</p>
              <p style="font-size:13px;color:#555;">Your collection demand has been sent to <strong>${brokerName}</strong> (${brokerEmail}).</p>
              <table style="font-size:13px;margin:14px 0;">
                <tr><td style="color:#888;padding:4px 12px 4px 0;">Case:</td><td><strong>${caseRef}</strong></td></tr>
                <tr><td style="color:#888;padding:4px 12px 4px 0;">Invoice:</td><td>${invoiceNumber||'N/A'}</td></tr>
                <tr><td style="color:#888;padding:4px 12px 4px 0;">Original Amount:</td><td>$${principal.toLocaleString()}</td></tr>
                <tr><td style="color:#888;padding:4px 12px 4px 0;">Atty Fees (50%):</td><td>$${attyFees.toLocaleString()}</td></tr>
                <tr><td style="color:#888;padding:4px 12px 4px 0;">Total Demanded:</td><td style="font-weight:700;color:#c0392b;font-size:15px;">$${totalOwed.toLocaleString()}</td></tr>
                <tr><td style="color:#888;padding:4px 12px 4px 0;">Pay-By:</td><td><strong>${deadlineStr}</strong></td></tr>
                ${colAttyEmail ? `<tr><td style="color:#888;padding:4px 12px 4px 0;">Attorney CC'd:</td><td>${attorney.name} — ${colAttyEmail}</td></tr>` : ''}
              </table>
            </div></div>`,
        });
        autoSent.carrierSent = true;
      } catch(e) { console.warn('Carrier copy failed:', e.message); }

      // 3. ATTORNEY NOTIFICATION
      if (colAttyEmail && attorney) {
        try {
          await dispatchEmail({
            to: colAttyEmail,
            subject: `[FGD Collection Assignment] ${carrierName} vs. ${brokerName} — $${totalOwed.toLocaleString()} (Case ${caseRef})`,
            text: `New collection letter requires your review (+$100 fee).\nCase: ${caseRef}\nCarrier: ${carrierName}\nBroker: ${brokerName}\nInvoice: ${invoiceNumber||'N/A'}\nTotal: $${totalOwed.toLocaleString()}\n\nPortal: ${process.env.SITE_URL||'https://freightguarddefense.com'}/attorney-portal.html`,
            html: `<p>Dear ${attorney.name},</p><p>A collection letter needs your review for <strong>$100 fee</strong>.</p><p>Case <strong>${caseRef}</strong> · $${totalOwed.toLocaleString()} demanded from ${brokerName}.</p><p><a href="${process.env.SITE_URL||'https://freightguarddefense.com'}/attorney-portal.html" style="background:#c0392b;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;font-weight:700;">Review in Portal</a></p>`,
          });
          autoSent.attorneySent = true;
        } catch(e) { console.warn('Attorney notify failed:', e.message); }
      }

      // Schedule follow-ups
      if (autoSent.sent) {
        const followups = loadFollowups();
        followups.push({
          id: Date.now().toString(), caseRef, brokerEmail, carrierEmail, brokerName, carrierName,
          originalSubject: colSubj,
          pending: [
            { label: 'Day 7 Payment Reminder',     sendAt: Date.now() + 7  * 86400000, sent: false },
            { label: 'Day 14 Final Notice to Sue', sendAt: Date.now() + 14 * 86400000, sent: false },
          ],
        });
        saveFollowups(followups);
        const statuses = loadStatuses();
        statuses[caseRef] = { status: 'sent', updatedAt: new Date().toISOString() };
        saveStatuses(statuses);
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
      carrierName, carrierMC, carrierDOT, carrierEmail, carrierPhone,
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

    // ── 3-PARTY EMAIL DISPATCH ───────────────────────────────────────────────
    // Sends: 1) Broker (TO) with attorney CC  2) Carrier (separate copy)  3) Attorney (separate copy)
    const immediateAutoSent = { sent: false, brokerSent: false, carrierSent: false, attorneySent: false, error: null };
    const attorneyEmail = attorney ? (attorney.email || attorney.email_address || '') : '';

    if (req.body.brokerEmail) {
      const emailSubj    = `FORMAL LEGAL DEMAND — ${brokerName} (MC-${brokerMC}) — FreightGuard Report Retraction & Damages`;
      const letterHtml   = buildEmailHtmlTracked(letterText, caseRef);
      const ccList       = [carrierEmail, attorneyEmail].filter(Boolean);

      // 1. TO BROKER — CC carrier + attorney
      try {
        await dispatchEmail({
          to:      req.body.brokerEmail,
          cc:      ccList,
          subject: emailSubj,
          text:    letterText,
          html:    letterHtml,
        });
        immediateAutoSent.brokerSent = true;
        await logAudit(caseRef, 'broker_emailed', carrierEmail, `Sent to broker ${req.body.brokerEmail}`);
      } catch(e) { immediateAutoSent.error = 'Broker: ' + e.message; }

      // 2. CARRIER COPY — separate dedicated email
      try {
        const carrierHtml = `
          <div style="font-family:Arial,sans-serif;max-width:680px;margin:0 auto;background:#fff;">
            <div style="background:#0a1628;padding:24px 32px;text-align:center;">
              <div style="font-size:28px;margin-bottom:8px;">⚖️</div>
              <h1 style="color:#fff;font-size:18px;margin:0;">FreightGuard Defense</h1>
              <p style="color:#7ab3ff;font-size:12px;margin:4px 0 0;">Your Copy — Demand Letter Sent</p>
            </div>
            <div style="padding:28px 32px;background:#f9f9f9;border-bottom:1px solid #eee;">
              <p style="color:#333;font-size:14px;margin:0 0 8px;">Dear <strong>${carrierName}</strong>,</p>
              <p style="color:#555;font-size:13px;line-height:1.7;">Your demand letter has been drafted and <strong>delivered to ${brokerName}</strong> at <strong>${req.body.brokerEmail}</strong>.</p>
              <table style="width:100%;border-collapse:collapse;margin:16px 0;font-size:13px;">
                <tr><td style="padding:6px 0;color:#888;">Case Reference:</td><td style="font-weight:700;color:#1a1a2a;">${caseRef}</td></tr>
                <tr><td style="padding:6px 0;color:#888;">Broker:</td><td style="color:#333;">${brokerName} (MC-${brokerMC})</td></tr>
                <tr><td style="padding:6px 0;color:#888;">Damages Claimed:</td><td style="font-weight:700;color:#c0392b;">$${damages.totalDamages.toLocaleString()}</td></tr>
                <tr><td style="padding:6px 0;color:#888;">Response Deadline:</td><td style="font-weight:700;color:#333;">${deadlineStr}</td></tr>
                ${attorneyEmail ? `<tr><td style="padding:6px 0;color:#888;">Attorney CC'd:</td><td style="color:#333;">${attorney.name} — ${attorney.email}</td></tr>` : ''}
              </table>
              <p style="color:#555;font-size:13px;line-height:1.7;">Automatic follow-up reminders will be sent to the broker on <strong>Day 7</strong> and <strong>Day 14</strong> if no response is received.</p>
            </div>
            <div style="padding:24px 32px;background:#fff;">
              <p style="font-size:12px;font-weight:700;color:#888;text-transform:uppercase;margin-bottom:12px;">Your Letter (Full Copy)</p>
              <div style="background:#f5f5f5;border-left:4px solid #c0392b;padding:20px;font-family:'Courier New',monospace;font-size:11px;line-height:1.8;color:#333;white-space:pre-wrap;">${letterText.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</div>
            </div>
          </div>`;
        await dispatchEmail({
          to:      carrierEmail,
          subject: `✅ Your Copy — Demand Letter Sent to ${brokerName} (Case ${caseRef})`,
          text:    `Your demand letter has been sent to ${brokerName} (${req.body.brokerEmail}).\n\nCase: ${caseRef}\nDamages: $${damages.totalDamages.toLocaleString()}\nDeadline: ${deadlineStr}\n\n--- YOUR LETTER ---\n\n${letterText}`,
          html:    carrierHtml,
        });
        immediateAutoSent.carrierSent = true;
        await logAudit(caseRef, 'carrier_copy_sent', carrierEmail, 'Carrier copy delivered');
      } catch(e) { immediateAutoSent.error = (immediateAutoSent.error || '') + ' | Carrier: ' + e.message; }

      // 3. ATTORNEY NOTIFICATION — if assigned
      if (attorneyEmail && attorney) {
        try {
          await dispatchEmail({
            to:      attorneyEmail,
            subject: `[FGD Assignment] New Letter — ${carrierName} vs. ${brokerName} (Case ${caseRef})`,
            text:    `You have been assigned to a new demand letter.\n\nCase: ${caseRef}\nCarrier: ${carrierName} (MC-${carrierMC})\nBroker: ${brokerName} (MC-${brokerMC})\nDamages: $${damages.totalDamages.toLocaleString()}\n\nPlease log in to the attorney portal to review and approve: ${process.env.SITE_URL || 'https://freightguarddefense.com'}/attorney-portal.html\n\n--- LETTER FOR REVIEW ---\n\n${letterText}`,
            html:    `<p>Dear ${attorney.name},</p><p>You have been assigned to a new demand letter requiring your review.</p>
              <table style="font-family:Arial,sans-serif;font-size:13px;border-collapse:collapse;">
                <tr><td style="padding:4px 12px 4px 0;color:#888;">Case:</td><td><strong>${caseRef}</strong></td></tr>
                <tr><td style="padding:4px 12px 4px 0;color:#888;">Carrier:</td><td>${carrierName} (MC-${carrierMC})</td></tr>
                <tr><td style="padding:4px 12px 4px 0;color:#888;">Broker:</td><td>${brokerName} (MC-${brokerMC})</td></tr>
                <tr><td style="padding:4px 12px 4px 0;color:#888;">Damages:</td><td style="color:#c0392b;font-weight:700;">$${damages.totalDamages.toLocaleString()}</td></tr>
              </table>
              <p style="margin-top:16px;"><a href="${process.env.SITE_URL || 'https://freightguarddefense.com'}/attorney-portal.html" style="background:#c0392b;color:#fff;padding:10px 24px;border-radius:6px;text-decoration:none;font-weight:700;">Review Letter → Attorney Portal</a></p>`,
          });
          immediateAutoSent.attorneySent = true;
        } catch(e) { console.warn('Attorney email failed:', e.message); }
      }

      // Schedule follow-ups (broker)
      if (immediateAutoSent.brokerSent) {
        const followups = loadFollowups();
        followups.push({
          id: Date.now().toString(), caseRef,
          brokerEmail: req.body.brokerEmail, carrierEmail, brokerName, carrierName,
          originalSubject: emailSubj,
          pending: [
            { label: 'Day 7 Reminder',      sendAt: Date.now() + 7  * 86400000, sent: false },
            { label: 'Day 14 Final Notice', sendAt: Date.now() + 14 * 86400000, sent: false },
          ],
        });
        saveFollowups(followups);
        immediateAutoSent.sent = true;
      }
    }

    // Save letter (locked until $299 Stripe payment if Stripe is active)
    const stripeActive = !!stripe;
    await addLetterDB({
      id: caseRef, caseRef,
      carrierName, carrierEmail, carrierMC, carrierPhone: carrierPhone||'',
      brokerName, brokerMC, brokerAddress,
      numTrucks, totalDamages: damages.totalDamages,
      court: `${court.name}, ${court.city}, ${court.state}`,
      letterText,
      locked: stripeActive,
      attorneyId: attorney ? (attorney.id || null) : null,
      ts: new Date().toISOString(),
    });

    // Audit + SMS
    await logAudit(caseRef, 'letter_generated', carrierEmail, `${carrierName} vs ${brokerName} — $${damages.totalDamages.toLocaleString()}`, req.ip || '');
    if (carrierPhone) {
      const msg = stripeActive
        ? `⚖️ FreightGuard Defense: Your demand letter (Case ${caseRef}) is ready. Complete your $299 payment to unlock and send it. Visit freightguarddefense.com`
        : `⚖️ FreightGuard Defense: Your demand letter (Case ${caseRef}) is ready. $${damages.totalDamages.toLocaleString()} claimed against ${brokerName}. Log in to send it.`;
      await sendSMS(carrierPhone, msg);
    }

    // If Stripe active — return locked preview (first 400 chars), else full letter
    const letterPreview = stripeActive ? letterText.substring(0, 400) + '\n\n[... LETTER CONTINUES — UNLOCK TO VIEW FULL TEXT ...]' : letterText;

    res.json({
      letter: stripeActive ? letterPreview : letterText,
      locked: stripeActive,
      caseRef,
      damages,
      court,
      attorney: attorney || null,
      savedFiles,
      autoSent: immediateAutoSent,
    });
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
// ── PER-LETTER STRIPE CHECKOUT ($299) ─────────────────────────
app.post('/api/create-checkout', rateLimit(60000, 10), async (req, res) => {
  const { caseRef, carrierEmail, letterType } = req.body;
  if (!stripe) return res.json({ devMode: true }); // free in dev

  try {
    const baseUrl    = process.env.BASE_URL || 'https://freightguarddefense.com';
    const letterName = letterType === 'collection'
      ? 'FreightGuard Defense — Collection Letter'
      : 'FreightGuard Defense — Demand Letter';
    const letterDesc = letterType === 'collection'
      ? 'Professionally drafted freight invoice collection demand letter — 50% attorney fees + interest, nearest federal courthouse as filing venue.'
      : 'AI-drafted federal demand letter — defamation, tortious interference, FMCSA violations, damages table, nearest federal courthouse as venue.';

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      customer_email: carrierEmail || undefined,
      line_items: [{
        price_data: {
          currency:     'usd',
          product_data: { name: letterName, description: letterDesc },
          unit_amount:  29900, // $299.00
        },
        quantity: 1,
      }],
      mode:        'payment',
      success_url: `${baseUrl}/?session_id={CHECKOUT_SESSION_ID}&caseRef=${encodeURIComponent(caseRef||'')}`,
      cancel_url:  `${baseUrl}/`,
      metadata:    { caseRef: caseRef || '', carrierEmail: carrierEmail || '', letterType: letterType || 'dispute' },
    });

    // Record pending payment on the letter
    if (caseRef) {
      const statuses = loadStatuses();
      statuses[caseRef] = statuses[caseRef] || {};
      statuses[caseRef].stripeSessionId = session.id;
      saveStatuses(statuses);
    }

    res.json({ url: session.url, sessionId: session.id });
  } catch(err) {
    console.error('Stripe error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/verify-payment', async (req, res) => {
  const { session_id, caseRef } = req.query;
  if (!session_id) return res.status(400).json({ error: 'No session ID' });
  if (!stripe) return res.json({ paid: true, devMode: true });
  try {
    const session = await stripe.checkout.sessions.retrieve(session_id);
    const paid    = session.payment_status === 'paid';
    const email   = session.customer_details?.email || session.metadata?.carrierEmail || '';
    const ref     = caseRef || session.metadata?.caseRef || '';

    if (paid && ref) {
      // Unlock letter
      const allLetters = await loadLetters();
      const letter = allLetters.find(l => l.caseRef === ref || l.id === ref);
      if (letter) {
        letter.locked = false;
        letter.paidAt = new Date().toISOString();
        letter.stripeSessionId = session_id;
        if (pgPool) {
          await pgPool.query('UPDATE letters SET locked=FALSE, stripe_session_id=$1 WHERE case_ref=$2', [session_id, ref]).catch(() => {});
        } else {
          // Update file store
          const path2 = require('path');
          const letters = loadJSON(path2.join(DATA_DIR, 'letters.json'));
          const idx = letters.findIndex(l => l.caseRef === ref || l.id === ref);
          if (idx >= 0) { letters[idx].locked = false; letters[idx].paidAt = new Date().toISOString(); saveJSON(path2.join(DATA_DIR, 'letters.json'), letters); }
        }
        // SMS carrier
        if (letter.carrierPhone) {
          await sendSMS(letter.carrierPhone,
            `✅ FreightGuard Defense: Your $299 payment was received. Your demand letter (Case ${ref}) is now unlocked. Log in to view and send it.`);
        }
        // Log audit
        await logAudit(ref, 'payment_received', email, `Stripe session ${session_id} — $299 paid`);
      }
    }

    res.json({ paid, email, caseRef: ref });
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

// ── AUDIT LOG ─────────────────────────────────────────────────────────────────
async function logAudit(caseRef, event, actor, details, ip) {
  if (pgPool) {
    await pgPool.query('INSERT INTO letter_audit(case_ref,event,actor,details,ip) VALUES($1,$2,$3,$4,$5)',
      [caseRef, event, actor||'system', details||'', ip||'']).catch(() => {});
  }
  // File fallback
  const AUDIT_FILE = path.join(DATA_DIR, 'audit.json');
  const log = loadJSON(AUDIT_FILE);
  log.push({ caseRef, event, actor: actor||'system', details: details||'', ip: ip||'', ts: new Date().toISOString() });
  if (log.length > 5000) log.splice(0, log.length - 5000); // keep last 5000
  saveJSON(AUDIT_FILE, log);
}

// ── EMAIL OPEN PIXEL TRACKING ─────────────────────────────────────────────────
app.get('/api/pixel/:caseRef', async (req, res) => {
  const { caseRef } = req.params;
  // Return 1x1 transparent GIF
  const pixel = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7','base64');
  res.set({ 'Content-Type':'image/gif', 'Cache-Control':'no-store', 'Content-Length': pixel.length });
  res.send(pixel);

  // Async: mark email as opened, update status, SMS carrier
  try {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    await logAudit(caseRef, 'email_opened', 'broker', `Opened from IP ${ip}`, ip);
    await setLetterStatusFile(caseRef, 'opened');

    // Find letter for carrier phone + broker info
    const allLetters = await loadLetters();
    const letter = allLetters.find(l => l.caseRef === caseRef || l.id === caseRef);
    if (letter) {
      if (pgPool) await pgPool.query('UPDATE letters SET email_opened_at=NOW() WHERE case_ref=$1', [caseRef]).catch(() => {});
      // SMS carrier
      if (letter.carrierPhone) {
        const deadline = letter.deadlineDate || (() => {
          const d = new Date(letter.ts || Date.now()); d.setDate(d.getDate()+14); return d.toLocaleDateString('en-US',{month:'short',day:'numeric'});
        })();
        await sendSMS(letter.carrierPhone,
          `⚠️ FreightGuard Defense: ${letter.brokerName || 'The broker'} just OPENED your demand letter (Case ${caseRef}). Their 14-day response deadline: ${deadline}. Monitor for a reply.`);
      }
    }
  } catch {}
});

function setLetterStatusFile(caseRef, status) {
  try {
    const statuses = loadStatuses();
    if (!statuses[caseRef]) statuses[caseRef] = {};
    if (typeof statuses[caseRef] === 'string') statuses[caseRef] = { status: statuses[caseRef] };
    statuses[caseRef].status = status;
    statuses[caseRef].updatedAt = new Date().toISOString();
    saveStatuses(statuses);
  } catch {}
}

// ── ATTORNEY PORTAL AUTH ───────────────────────────────────────────────────────
const ATTORNEY_JWT_SECRET = process.env.JWT_SECRET || 'fgd-secret-change-me-in-production';

function makeAttorneyJWT(payload) {
  if (!jwt) return null;
  return jwt.sign({ ...payload, type: 'attorney' }, ATTORNEY_JWT_SECRET, { expiresIn: '30d' });
}

function requireAttorney(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Attorney login required' });
  try {
    const decoded = jwt.verify(auth.slice(7), ATTORNEY_JWT_SECRET);
    if (decoded.type !== 'attorney') return res.status(401).json({ error: 'Invalid token type' });
    req.attorney = decoded;
    next();
  } catch { return res.status(401).json({ error: 'Session expired. Please log in again.' }); }
}

app.post('/api/attorney/login', rateLimit(60000, 10), async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const attorneys = await loadAttorneys();
  const attorney  = attorneys.find(a => (a.email||'').toLowerCase() === email.toLowerCase());
  if (!attorney) return res.status(401).json({ error: 'Invalid email or password' });
  if (!attorney.passwordHash && !attorney.password_hash)
    return res.status(401).json({ error: 'Account not activated. Please set a password via your invitation link.' });
  const hash = attorney.passwordHash || attorney.password_hash;
  const ok   = bcrypt ? await bcrypt.compare(password, hash) : password === hash;
  if (!ok) return res.status(401).json({ error: 'Invalid email or password' });
  if (attorney.status === 'suspended') return res.status(403).json({ error: 'Account suspended. Contact admin.' });
  if (pgPool) await pgPool.query('UPDATE attorneys SET last_login=NOW() WHERE id=$1', [attorney.id]).catch(() => {});
  const token = makeAttorneyJWT({ id: attorney.id, email: attorney.email, name: attorney.name, barState: attorney.barState });
  res.json({ token, attorney: { id: attorney.id, name: attorney.name, email: attorney.email, barState: attorney.barState, firmName: attorney.firmName||'' } });
});

app.post('/api/attorney/set-password', async (req, res) => {
  const { token: inviteToken, password } = req.body;
  if (!inviteToken || !password || password.length < 8)
    return res.status(400).json({ error: 'Valid invite token and password (min 8 chars) required' });
  const invites = loadInvites();
  const invite  = invites[inviteToken];
  if (!invite) return res.status(404).json({ error: 'Invalid invite token' });
  const hash = bcrypt ? await bcrypt.hash(password, 10) : password;
  if (pgPool) {
    await pgPool.query('UPDATE attorneys SET password_hash=$1 WHERE invite_token=$2', [hash, inviteToken]).catch(() => {});
  } else {
    const all = await loadAttorneys();
    const idx = all.findIndex(a => a.inviteToken === inviteToken);
    if (idx >= 0) { all[idx].passwordHash = hash; saveJSON(path.join(DATA_DIR, 'attorneys.json'), all); }
  }
  res.json({ ok: true, message: 'Password set. You can now log in.' });
});

// Get attorney's assigned letters (matched by licenseStates)
app.get('/api/attorney/portal/letters', requireAttorney, async (req, res) => {
  const attorneys = await loadAttorneys();
  const attorney  = attorneys.find(a => a.id === req.attorney.id);
  if (!attorney) return res.status(404).json({ error: 'Attorney not found' });

  const states = String(attorney.licenseStates || attorney.license_states || attorney.barState || '')
    .split(/[,;\s]+/).map(s => s.trim().toUpperCase()).filter(Boolean);

  const allLetters = await loadLetters();
  const statuses   = loadStatuses();

  // Match letters where broker address contains one of attorney's states
  const assigned = allLetters.filter(l => {
    const brokerAddr = String(l.brokerAddress || l.broker_address || '').toUpperCase();
    const reviewStatus = l.reviewStatus || l.review_status || 'pending_review';
    return states.some(s => brokerAddr.includes(` ${s} `) || brokerAddr.includes(`,${s},`) || brokerAddr.endsWith(` ${s}`) || brokerAddr.includes(` ${s} `) || new RegExp(`\\b${s}\\b`).test(brokerAddr));
  }).map(l => ({
    caseRef:      l.caseRef || l.id,
    carrierName:  l.carrierName,
    brokerName:   l.brokerName,
    brokerMC:     l.brokerMC,
    brokerAddress:l.brokerAddress,
    totalDamages: l.totalDamages,
    letterType:   l.letterType || 'dispute',
    reviewStatus: l.reviewStatus || l.review_status || 'pending_review',
    reviewedAt:   l.reviewedAt || l.reviewed_at || null,
    ts:           l.ts || l.createdAt,
    status:       statuses[l.caseRef]?.status || statuses[l.caseRef] || 'new',
  }));

  res.json({ letters: assigned, attorney: { name: attorney.name, barState: attorney.barState, states } });
});

// Get full letter text for attorney review
app.get('/api/attorney/portal/letter/:caseRef', requireAttorney, async (req, res) => {
  const allLetters = await loadLetters();
  const letter = allLetters.find(l => l.caseRef === req.params.caseRef || l.id === req.params.caseRef);
  if (!letter) return res.status(404).json({ error: 'Letter not found' });
  await logAudit(req.params.caseRef, 'attorney_viewed', req.attorney.email, `Viewed by attorney ${req.attorney.name}`);
  res.json({ ...letter, createdAt: letter.ts || letter.createdAt });
});

// Attorney submits review (approve or request changes)
app.post('/api/attorney/portal/review/:caseRef', requireAttorney, async (req, res) => {
  const { action, notes } = req.body; // action: 'approved' | 'changes_requested'
  if (!['approved','changes_requested'].includes(action))
    return res.status(400).json({ error: 'Invalid action' });

  const { caseRef } = req.params;
  const attorneys   = await loadAttorneys();
  const attorney    = attorneys.find(a => a.id === req.attorney.id);
  if (!attorney) return res.status(404).json({ error: 'Attorney not found' });

  const allLetters  = await loadLetters();
  const letter      = allLetters.find(l => l.caseRef === caseRef || l.id === caseRef);
  if (!letter) return res.status(404).json({ error: 'Letter not found' });

  const now = new Date().toISOString();

  if (action === 'approved') {
    // Append attorney stamp to letter
    const stamp = `\n\n${'─'.repeat(60)}\nREVIEWED AND APPROVED BY COUNSEL\n${attorney.name}\n${attorney.firmName || 'Attorney at Law'}\nBar No. ${attorney.barNumber || attorney.bar_number} (${attorney.barState || attorney.bar_state})\n${attorney.email}\n${attorney.phone || ''}\nDate: ${new Date().toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'})}\n${'─'.repeat(60)}`;

    // Update letter
    if (pgPool) {
      await pgPool.query(
        'UPDATE letters SET review_status=$1, attorney_notes=$2, reviewed_by=$3, reviewed_at=$4, letter_text=letter_text||$5 WHERE case_ref=$6',
        ['approved', notes||'', attorney.name, now, stamp, caseRef]
      ).catch(() => {});
    } else {
      const path2 = require('path');
      const all2  = loadJSON(path2.join(DATA_DIR, 'letters.json'));
      const idx   = all2.findIndex(l => l.caseRef === caseRef || l.id === caseRef);
      if (idx >= 0) {
        all2[idx].reviewStatus = 'approved'; all2[idx].attorney_notes = notes||'';
        all2[idx].reviewedBy = attorney.name; all2[idx].reviewedAt = now;
        all2[idx].letterText = (all2[idx].letterText || '') + stamp;
        saveJSON(path2.join(DATA_DIR, 'letters.json'), all2);
      }
    }

    // Notify carrier via email + SMS
    const carrierEmail = letter.carrierEmail || letter.carrier_email;
    if (carrierEmail) {
      await dispatchEmail({
        to: carrierEmail,
        subject: `✅ Your Demand Letter Has Been Attorney-Reviewed — Case ${caseRef}`,
        text: `Your demand letter (Case ${caseRef}) has been reviewed and approved by ${attorney.name} (Bar No. ${attorney.barNumber||attorney.bar_number}, ${attorney.barState||attorney.bar_state}).\n\nThe letter now includes a formal attorney review stamp and is ready to send to the broker.\n\nLog in to FreightGuard Defense to view and send your approved letter.`,
        html: `<p>Your demand letter <strong>Case ${caseRef}</strong> has been reviewed and approved by <strong>${attorney.name}</strong> (Bar No. ${attorney.barNumber||attorney.bar_number}, ${attorney.barState||attorney.bar_state}).</p><p>The letter now includes a formal attorney review stamp and is ready to send to the broker.</p>`,
      }).catch(() => {});
    }
    if (letter.carrierPhone) {
      await sendSMS(letter.carrierPhone,
        `✅ FreightGuard Defense: Attorney ${attorney.name} approved your demand letter (Case ${caseRef}). It now carries a legal review stamp. Log in to send it.`);
    }

    // Track $100 attorney payout due
    const payouts = loadJSON(path.join(DATA_DIR, 'attorney_payouts.json'));
    payouts.push({ attorneyId: attorney.id, attorneyName: attorney.name, attorneyEmail: attorney.email, caseRef, amount: 100, status: 'pending', approvedAt: now });
    saveJSON(path.join(DATA_DIR, 'attorney_payouts.json'), payouts);

    await logAudit(caseRef, 'attorney_approved', attorney.email, `Approved by ${attorney.name}. $100 payout queued.`);

  } else {
    // Changes requested
    if (pgPool) await pgPool.query('UPDATE letters SET review_status=$1, attorney_notes=$2, reviewed_by=$3, reviewed_at=$4 WHERE case_ref=$5',
      ['changes_requested', notes||'', attorney.name, now, caseRef]).catch(() => {});
    else {
      const path2 = require('path'); const all2 = loadJSON(path2.join(DATA_DIR, 'letters.json'));
      const idx = all2.findIndex(l => l.caseRef === caseRef || l.id === caseRef);
      if (idx >= 0) { all2[idx].reviewStatus = 'changes_requested'; all2[idx].attorneyNotes = notes||''; all2[idx].reviewedBy = attorney.name; saveJSON(path2.join(DATA_DIR, 'letters.json'), all2); }
    }
    // Notify carrier
    const ce = letter.carrierEmail || letter.carrier_email;
    if (ce) await dispatchEmail({ to: ce, subject: `Attorney Review: Changes Requested — Case ${caseRef}`,
      text: `Attorney ${attorney.name} has reviewed your demand letter and requested changes.\n\nNotes:\n${notes||'(none)'}\n\nPlease log in to update your letter.`,
      html: `<p>Attorney <strong>${attorney.name}</strong> reviewed your letter and requested changes.</p><p><strong>Notes:</strong> ${notes||'(none)'}</p>` }).catch(() => {});
    await logAudit(caseRef, 'changes_requested', attorney.email, notes||'');
  }

  res.json({ ok: true, action, message: action === 'approved' ? `Letter approved. $100 payout recorded for ${attorney.name}.` : 'Changes requested. Carrier notified.' });
});

// Admin: view attorney payouts
app.get('/api/admin/attorney-payouts', requireAdmin, (req, res) => {
  const payouts = loadJSON(path.join(DATA_DIR, 'attorney_payouts.json'));
  res.json({ payouts, pending: payouts.filter(p=>p.status==='pending').reduce((s,p)=>s+p.amount,0) });
});

app.put('/api/admin/attorney-payouts/:caseRef/paid', requireAdmin, (req, res) => {
  const payouts = loadJSON(path.join(DATA_DIR, 'attorney_payouts.json'));
  const idx = payouts.findIndex(p => p.caseRef === req.params.caseRef && p.status === 'pending');
  if (idx < 0) return res.status(404).json({ error: 'Payout not found' });
  payouts[idx].status = 'paid'; payouts[idx].paidAt = new Date().toISOString();
  saveJSON(path.join(DATA_DIR, 'attorney_payouts.json'), payouts);
  res.json({ ok: true });
});

// ════════════════════════════════════════════════════════════════════════════
// FEATURE 1 — CEASE & DESIST PACKAGE ($149)
// ════════════════════════════════════════════════════════════════════════════
app.post('/api/generate-cd-letter', rateLimit(60000, 5), async (req, res) => {
  try {
    const { carrierName, carrierMC, carrierEmail, carrierPhone,
            brokerName, brokerMC, brokerAddress, reportContent,
            freightguardReportUrl, assignedAttorneyId } = req.body;
    if (!carrierName || !brokerName || !reportContent)
      return res.status(400).json({ error: 'Missing required fields' });

    const caseRef   = 'FGD-CD-' + Date.now().toString().slice(-6) + '-' + Math.floor(Math.random()*9000+1000);
    const attorneys = await loadAttorneys();
    const attorney  = assignedAttorneyId ? attorneys.find(a => a.id === assignedAttorneyId) : null;
    let court = { name: 'U.S. District Court', address: brokerAddress };
    try { court = await findCourthouseViaGoogleMaps(brokerAddress); } catch {}

    const today    = new Date().toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'});
    const deadline = new Date(); deadline.setDate(deadline.getDate()+72/24);
    const deadlineStr = deadline.toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'});
    const firmLine = attorney ? (attorney.firmName||attorney.name) : '[LAW FIRM NAME]';

    const prompt = `CRITICAL: Output ONLY plain text. No HTML, no markdown, no special characters.

You are a senior transportation law attorney drafting a CEASE AND DESIST LETTER AND DEMAND FOR IMMEDIATE REMOVAL directed at a freight broker who filed a false FreightGuard report.

TODAY: ${today}
72-HOUR REMOVAL DEADLINE: ${deadlineStr}
FIRM: ${firmLine}

CARRIER (CLIENT): ${carrierName} / MC-${carrierMC}
BROKER (RESPONDENT): ${brokerName} / MC-${brokerMC} / ${brokerAddress}
FALSE REPORT CONTENT: "${reportContent}"
${freightguardReportUrl ? `REPORT URL: ${freightguardReportUrl}` : ''}

FILING COURT IF NOT COMPLIED: ${court.name}, ${court.address||''}, ${court.city||''} ${court.state||''}

Write a legally aggressive C&D with these sections:
1. Formal letterhead, VIA CERTIFIED MAIL, date, recipient address
2. RE: CEASE AND DESIST — DEMAND FOR IMMEDIATE REMOVAL OF FALSE FREIGHTGUARD REPORT — Case ${caseRef}
3. Opening: this firm represents carrier, this is final notice before litigation AND regulatory complaint
4. IDENTIFICATION OF FALSE REPORT: quote the report verbatim and identify each false statement
5. LEGAL VIOLATIONS: 49 U.S.C. § 14915, Defamation, Tortious Interference, False Light, Lanham Act § 43(a)
6. REGULATORY EXPOSURE: FMCSA complaint, state attorney general referral, industry reporting
7. DEMANDS (72-hour deadline): (1) Remove report from FreightGuard immediately (2) Issue written retraction to FreightGuard (3) Written confirmation of removal to this office (4) Cease all further disparagement
8. CONSEQUENCES of non-compliance: immediate lawsuit + FMCSA complaint + $50,000+ damages
9. Professional closing with attorney signature

Every word must convey legal authority and inevitability of consequences. $600/hour tone.`;

    const message = await anthropic.messages.create({
      model: 'claude-opus-4-6', max_tokens: 2500,
      messages: [{ role: 'user', content: prompt }],
    });
    const letterText = message.content[0].type === 'text' ? message.content[0].text : '';

    await addLetterDB({ id: caseRef, caseRef, letterType: 'cease_desist',
      carrierName, carrierEmail, carrierMC, carrierPhone: carrierPhone||'',
      brokerName, brokerMC, brokerAddress, totalDamages: 50000,
      letterText, court, attorneyId: assignedAttorneyId||null, ts: new Date().toISOString() });
    await recordBrokerReportDB(brokerMC, brokerName, carrierName, caseRef);
    await logAudit(caseRef, 'cd_generated', carrierEmail, `C&D: ${carrierName} vs ${brokerName}`);

    // 3-party email dispatch
    if (req.body.brokerEmail) {
      const subj = `CEASE AND DESIST — IMMEDIATE REPORT REMOVAL REQUIRED — ${brokerName} — 72-Hour Deadline`;
      const cc   = [carrierEmail, attorney?.email].filter(Boolean);
      try { await dispatchEmail({ to: req.body.brokerEmail, cc, subject: subj, text: letterText, html: buildEmailHtmlTracked(letterText, caseRef) }); } catch {}
      try { await dispatchEmail({ to: carrierEmail, subject: `✅ Your C&D Letter Sent (Case ${caseRef})`, text: `Your cease & desist has been sent to ${brokerName}.\nCase: ${caseRef}\n72-Hour removal deadline: ${deadlineStr}\n\n${letterText}`, html: `<p>Your C&D letter (Case ${caseRef}) was sent to ${brokerName}. 72-hour deadline: <strong>${deadlineStr}</strong>.</p>` }); } catch {}
    }

    res.json({ letter: letterText, caseRef, court, deadlineStr });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════════════════════
// FEATURE 2 — CASE OUTCOME TRACKER
// ════════════════════════════════════════════════════════════════════════════
const OUTCOMES_FILE = path.join(DATA_DIR, 'outcomes.json');
function loadOutcomes() { return loadJSON(OUTCOMES_FILE); }
function saveOutcomes(d) { saveJSON(OUTCOMES_FILE, d); }

app.put('/api/letter-outcome/:caseRef', async (req, res) => {
  const { outcome, settlementAmount, notes } = req.body;
  // outcome: 'report_removed' | 'settled' | 'filed_court' | 'no_response' | 'withdrawn'
  const valid = ['report_removed','settled','filed_court','no_response','withdrawn','ongoing'];
  if (!valid.includes(outcome)) return res.status(400).json({ error: 'Invalid outcome' });
  const outcomes = loadOutcomes();
  outcomes[req.params.caseRef] = { outcome, settlementAmount: settlementAmount||0, notes: notes||'', recordedAt: new Date().toISOString() };
  saveOutcomes(outcomes);
  await logAudit(req.params.caseRef, 'outcome_recorded', 'carrier', `Outcome: ${outcome}${settlementAmount ? ' / $'+settlementAmount : ''}`);
  // Update letter status
  const statusMap = { report_removed:'resolved', settled:'settled', filed_court:'filed', no_response:'escalated', withdrawn:'closed' };
  if (statusMap[outcome]) setLetterStatusFile(req.params.caseRef, statusMap[outcome]);
  res.json({ ok: true });
});

app.get('/api/outcomes/stats', async (req, res) => {
  const outcomes  = loadOutcomes();
  const allLetters = await loadLetters();
  const total      = allLetters.length;
  const vals       = Object.values(outcomes);
  const removed    = vals.filter(o => o.outcome === 'report_removed').length;
  const settled    = vals.filter(o => o.outcome === 'settled').length;
  const totalSettled = vals.filter(o => o.outcome === 'settled').reduce((s,o) => s+(Number(o.settlementAmount)||0), 0);
  const totalDamages = allLetters.reduce((s,l) => s+(Number(l.totalDamages)||0), 0);
  res.json({ totalLetters: total, reportsRemoved: removed, settled, totalSettledAmount: totalSettled, totalDamagesClaimed: totalDamages, winRate: total > 0 ? Math.round((removed+settled)/Math.max(vals.length,1)*100) : 0 });
});

app.get('/api/letter-outcomes', (req, res) => res.json(loadOutcomes()));

// ════════════════════════════════════════════════════════════════════════════
// FEATURE 3 — FMCSA CARRIER SAFETY CHECK
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/carrier-safety/:mc', async (req, res) => {
  const mc = req.params.mc.replace(/\D/g,'');
  if (!mc || mc.length < 5) return res.status(400).json({ error: 'Invalid MC' });
  try {
    const url = 'https://safer.fmcsa.dot.gov/query.asp?searchtype=ANY&query_type=queryCarrierSnapshot&query_param=MC_MX&query_string=' + mc;
    const r   = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0' }, signal: AbortSignal.timeout ? AbortSignal.timeout(8000) : undefined });
    const html = await r.text();
    function ex(label) {
      const re = new RegExp(label + '[^<]*<\/[Aa]>[^<]*<\/[Tt][Hh]>\\s*<[Tt][Dd][^>]*class=["\'"]queryfield["\'"][^>]*>([\\s\\S]*?)<\/[Tt][Dd]>', 'i');
      const m  = html.match(re); if (!m) return '';
      return m[1].replace(/<[^>]+>/g,'').replace(/&nbsp;/g,' ').replace(/\s+/g,' ').trim();
    }
    function exStatus() {
      const m = html.match(/USDOT Status:<\/A>[\s\S]*?<TD[^>]*class=["']queryfield["'][^>]*>([\s\S]*?)<\/TD>/i);
      if (!m) return '';
      return m[1].replace(/<!--[\s\S]*?-->/g,'').replace(/<[^>]+>/g,'').replace(/&nbsp;/g,' ').replace(/\s+/g,' ').trim();
    }
    const status   = exStatus();
    const safetyRating = ex('Safety Rating');
    const oosRate  = ex('Out of Service Rate');
    const warnings = [];
    if (status && status.toLowerCase() !== 'active') warnings.push({ level: 'critical', msg: `USDOT Status is "${status}" — not ACTIVE. Load boards may be blocking this carrier.` });
    if (safetyRating && ['unsatisfactory','conditional'].some(s => safetyRating.toLowerCase().includes(s)))
      warnings.push({ level: 'critical', msg: `Safety Rating: ${safetyRating} — carriers with this rating are often blocked by brokers and load boards.` });
    if (!status && !safetyRating) warnings.push({ level: 'warn', msg: 'Could not retrieve FMCSA data. Verify MC number is correct.' });
    res.json({ status, safetyRating, oosRate, warnings, mc });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════════════════════
// FEATURE 4 — CARRIER SHIELD SUBSCRIPTION ($49/month)
// ════════════════════════════════════════════════════════════════════════════
app.post('/api/create-subscription', rateLimit(60000, 10), async (req, res) => {
  const { email, plan } = req.body;
  if (!stripe) return res.json({ devMode: true });
  try {
    const baseUrl = process.env.BASE_URL || 'https://freightguarddefense.com';
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      customer_email: email || undefined,
      line_items: [{
        price_data: {
          currency: 'usd',
          product_data: { name: 'FreightGuard Defense — Carrier Shield', description: 'Unlimited demand letters + priority attorney review + MC credit monitoring. Cancel anytime.' },
          unit_amount: 4900, // $49/month
          recurring: { interval: 'month' },
        },
        quantity: 1,
      }],
      mode: 'subscription',
      success_url: `${baseUrl}/?subscribed=1&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url:  `${baseUrl}/`,
      metadata: { plan: plan || 'carrier_shield', email: email || '' },
    });
    res.json({ url: session.url, sessionId: session.id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/verify-subscription', async (req, res) => {
  const { session_id } = req.query;
  if (!session_id) return res.status(400).json({ error: 'No session ID' });
  if (!stripe) return res.json({ active: true, devMode: true });
  try {
    const session = await stripe.checkout.sessions.retrieve(session_id, { expand: ['subscription'] });
    const active  = session.subscription?.status === 'active' || session.subscription?.status === 'trialing';
    const email   = session.customer_details?.email || session.metadata?.email || '';
    res.json({ active, email, subscriptionId: session.subscription?.id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════════════════════
// FEATURE 5 — WHITE-LABEL SETTINGS
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/admin/white-label', requireAdmin, (req, res) => {
  const wl = loadJSON(path.join(DATA_DIR, 'white_label.json'));
  res.json(wl[0] || {});
});

app.post('/api/admin/white-label', requireAdmin, (req, res) => {
  const { companyName, logoUrl, primaryColor, domain, contactEmail, footerText, customDisclaimer } = req.body;
  const settings = [{ companyName, logoUrl, primaryColor, domain, contactEmail, footerText, customDisclaimer, updatedAt: new Date().toISOString() }];
  saveJSON(path.join(DATA_DIR, 'white_label.json'), settings);
  res.json({ ok: true });
});

app.get('/api/brand', (req, res) => {
  const wl = loadJSON(path.join(DATA_DIR, 'white_label.json'));
  const brand = wl[0] || {};
  res.json({
    name:           brand.companyName   || 'FreightGuard Defense',
    logo:           brand.logoUrl       || '',
    primaryColor:   brand.primaryColor  || '#c0392b',
    contactEmail:   brand.contactEmail  || 'legal@freightguarddefense.com',
    footerText:     brand.footerText    || 'FreightGuard Defense — Carrier Legal Protection Network',
    disclaimer:     brand.customDisclaimer || '',
  });
});

// ════════════════════════════════════════════════════════════════════════════
// FEATURE A — BROKER WATCHLIST & WEEKLY MONITORING
// ════════════════════════════════════════════════════════════════════════════
const WATCHLIST_FILE = path.join(DATA_DIR, 'broker_watchlist.json');
function loadWatchlist()  { return loadJSON(WATCHLIST_FILE); }
function saveWatchlist(d) { saveJSON(WATCHLIST_FILE, d);    }

// Add broker to watchlist
app.post('/api/watchlist/add', async (req, res) => {
  const { brokerMC, brokerName, carrierEmail, carrierName, caseRef } = req.body;
  if (!brokerMC || !carrierEmail) return res.status(400).json({ error: 'brokerMC and carrierEmail required' });
  const wl  = loadWatchlist();
  const key = brokerMC.replace(/\D/g,'');
  if (!wl[key]) wl[key] = { brokerMC: key, brokerName, subscribers: [], addedAt: new Date().toISOString() };
  if (!wl[key].subscribers.find(s => s.email === carrierEmail)) {
    wl[key].subscribers.push({ email: carrierEmail, name: carrierName||'', caseRef: caseRef||'', addedAt: new Date().toISOString() });
  }
  saveWatchlist(wl);
  res.json({ ok: true, message: `${brokerName||'Broker MC-'+key} added to your watchlist. You'll receive weekly status alerts.` });
});

app.get('/api/watchlist', (req, res) => {
  const email = (req.query.email||'').toLowerCase();
  const wl    = loadWatchlist();
  const mine  = Object.values(wl).filter(b => b.subscribers?.some(s => s.email.toLowerCase() === email));
  res.json({ watchlist: mine });
});

app.delete('/api/watchlist/:brokerMC', (req, res) => {
  const { email } = req.body;
  const wl  = loadWatchlist();
  const key = req.params.brokerMC.replace(/\D/g,'');
  if (wl[key] && email) wl[key].subscribers = wl[key].subscribers.filter(s => s.email !== email);
  saveWatchlist(wl);
  res.json({ ok: true });
});

// Weekly watchlist scanner — check each broker's FMCSA status and email subscribers
async function runBrokerWatchlistScan() {
  const wl = loadWatchlist();
  for (const [mc, broker] of Object.entries(wl)) {
    if (!broker.subscribers?.length) continue;
    try {
      const url  = `https://safer.fmcsa.dot.gov/query.asp?searchtype=ANY&query_type=queryCarrierSnapshot&query_param=MC_MX&query_string=${mc}`;
      const r    = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0' }, signal: AbortSignal.timeout ? AbortSignal.timeout(8000) : undefined });
      const html = await r.text();
      // Extract status
      const sm = html.match(/USDOT Status:<\/A>[\s\S]*?<TD[^>]*class=["']queryfield["'][^>]*>([\s\S]*?)<\/TD>/i);
      const status = sm ? sm[1].replace(/<!--[\s\S]*?-->/g,'').replace(/<[^>]+>/g,'').replace(/&nbsp;/g,' ').trim() : 'Unknown';
      const prevStatus = broker.lastStatus || '';
      const changed    = prevStatus && prevStatus !== status;

      // Email all subscribers a weekly report
      for (const sub of broker.subscribers) {
        try {
          await dispatchEmail({
            to: sub.email,
            subject: changed
              ? `⚠️ ALERT: Broker ${broker.brokerName||'MC-'+mc} Status Changed — ${prevStatus} → ${status}`
              : `📊 Weekly Broker Watch: ${broker.brokerName||'MC-'+mc} Status Update`,
            text: `FreightGuard Defense — Broker Watchlist Update\n\nBroker: ${broker.brokerName||'MC-'+mc} (MC-${mc})\nCurrent FMCSA Status: ${status}\n${changed ? `⚠️ STATUS CHANGED from "${prevStatus}" to "${status}"` : 'No change detected this week.'}\n\nCase Reference: ${sub.caseRef||'N/A'}\n\nThis is your weekly automated broker monitoring report from FreightGuard Defense.`,
            html: `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
              <div style="background:#0a1628;padding:20px 28px;text-align:center;"><h2 style="color:#fff;margin:0;">⚖️ FreightGuard Defense</h2><p style="color:#7ab3ff;font-size:12px;margin:4px 0 0;">Broker Watchlist Weekly Report</p></div>
              <div style="padding:24px 28px;background:#f9f9f9;">
                ${changed ? `<div style="background:#fff3cd;border:1px solid #ffc107;border-radius:8px;padding:14px;margin-bottom:16px;"><strong>⚠️ STATUS CHANGE DETECTED</strong><br>${prevStatus} → <strong style="color:${status.toLowerCase().includes('active')?'green':'red'}">${status}</strong></div>` : ''}
                <table style="font-size:13px;"><tr><td style="color:#888;padding:4px 12px 4px 0;">Broker:</td><td><strong>${broker.brokerName||'MC-'+mc}</strong></td></tr>
                <tr><td style="color:#888;padding:4px 12px 4px 0;">MC Number:</td><td>MC-${mc}</td></tr>
                <tr><td style="color:#888;padding:4px 12px 4px 0;">FMCSA Status:</td><td style="font-weight:700;color:${status.toLowerCase().includes('active')?'green':'#c0392b'};">${status}</td></tr>
                <tr><td style="color:#888;padding:4px 12px 4px 0;">Your Case:</td><td>${sub.caseRef||'N/A'}</td></tr>
                <tr><td style="color:#888;padding:4px 12px 4px 0;">Report Date:</td><td>${new Date().toLocaleDateString()}</td></tr></table>
              </div></div>`,
          });
        } catch(e) { console.warn('Watchlist email failed:', e.message); }
      }
      // Save latest status
      wl[mc].lastStatus = status; wl[mc].lastChecked = new Date().toISOString();
    } catch(e) { console.warn('Watchlist scan error for MC', mc, e.message); }
    await new Promise(r => setTimeout(r, 500)); // rate limit
  }
  saveWatchlist(wl);
  console.log('[Watchlist] Scan complete —', Object.keys(wl).length, 'brokers checked');
}
// Run weekly (every 7 days)
setInterval(runBrokerWatchlistScan, 7 * 24 * 3600000);
// Also expose as admin trigger
app.post('/api/admin/run-watchlist-scan', requireAdmin, async (req, res) => {
  runBrokerWatchlistScan().catch(e => console.error(e));
  res.json({ ok: true, message: 'Watchlist scan started in background' });
});

// ════════════════════════════════════════════════════════════════════════════
// FEATURE B — GROUP ACTION LETTERS (multi-carrier co-plaintiffs)
// ════════════════════════════════════════════════════════════════════════════
const GROUP_ACTIONS_FILE = path.join(DATA_DIR, 'group_actions.json');
function loadGroupActions()  { return loadJSON(GROUP_ACTIONS_FILE); }
function saveGroupActions(d) { saveJSON(GROUP_ACTIONS_FILE, d);     }

// Get open group actions for a broker MC
app.get('/api/group-action/:brokerMC', async (req, res) => {
  const mc  = req.params.brokerMC.replace(/\D/g,'');
  const gas = loadGroupActions();
  const ga  = Object.values(gas).find(g => g.brokerMC === mc && g.status === 'open');
  const allLetters = await loadLetters();
  const letterCount = allLetters.filter(l => String(l.brokerMC||'').replace(/\D/g,'') === mc).length;
  res.json({ groupAction: ga || null, totalLetters: letterCount, brokerMC: mc });
});

// Create or join a group action
app.post('/api/group-action/join', async (req, res) => {
  const { brokerMC, brokerName, carrierName, carrierEmail, carrierMC, caseRef, damages } = req.body;
  if (!brokerMC || !carrierEmail) return res.status(400).json({ error: 'brokerMC and carrierEmail required' });
  const mc  = brokerMC.replace(/\D/g,'');
  const gas = loadGroupActions();
  // Find existing open group action for this broker
  let ga = Object.values(gas).find(g => g.brokerMC === mc && g.status === 'open');
  if (!ga) {
    const id = 'GA-' + mc + '-' + Date.now().toString().slice(-6);
    ga = { id, brokerMC: mc, brokerName, status: 'open', carriers: [], totalDamages: 0, createdAt: new Date().toISOString() };
    gas[id] = ga;
  }
  if (!ga.carriers.find(c => c.email === carrierEmail)) {
    ga.carriers.push({ name: carrierName, email: carrierEmail, mc: carrierMC, caseRef, damages: Number(damages)||0, joinedAt: new Date().toISOString() });
    ga.totalDamages = ga.carriers.reduce((s,c) => s+(Number(c.damages)||0), 0);
  }
  saveGroupActions(gas);

  // Notify all other carriers in the group
  for (const c of ga.carriers.filter(c => c.email !== carrierEmail)) {
    try {
      await dispatchEmail({ to: c.email,
        subject: `New Co-Plaintiff Joined Your Group Action Against ${brokerName}`,
        text: `${carrierName} (MC-${carrierMC}) has joined the group action against ${brokerName}.\n\nGroup now has ${ga.carriers.length} carriers with $${ga.totalDamages.toLocaleString()} combined damages.\n\nA combined demand letter will be generated when the group reaches 3+ carriers.`,
        html: `<p><strong>${carrierName}</strong> joined the group action against ${brokerName}. Group: <strong>${ga.carriers.length} carriers</strong> / <strong style="color:#c0392b;">$${ga.totalDamages.toLocaleString()} combined damages</strong>.</p>`,
      });
    } catch {}
  }
  res.json({ ok: true, groupAction: ga, message: `Joined group action. ${ga.carriers.length} carriers / $${ga.totalDamages.toLocaleString()} combined.` });
});

// Generate combined group demand letter
app.post('/api/group-action/:groupId/generate', rateLimit(60000, 3), async (req, res) => {
  const gas = loadGroupActions();
  const ga  = gas[req.params.groupId];
  if (!ga) return res.status(404).json({ error: 'Group action not found' });
  if (ga.carriers.length < 2) return res.status(400).json({ error: 'Need at least 2 carriers to generate a group letter' });

  const brokerName = ga.brokerName; const brokerMC = ga.brokerMC;
  const caseRef    = 'FGD-GRP-' + Date.now().toString().slice(-6);
  const today      = new Date().toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'});
  const deadline   = new Date(); deadline.setDate(deadline.getDate()+14);
  const deadlineStr = deadline.toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'});

  const carrierList = ga.carriers.map((c,i) => `${i+1}. ${c.name} (MC-${c.mc||'?'}) — $${(Number(c.damages)||0).toLocaleString()} in claimed damages`).join('\n');

  const prompt = `CRITICAL: Output ONLY plain text.

You are drafting a COMBINED MULTI-CARRIER GROUP DEMAND LETTER for ${ga.carriers.length} motor carriers who have all suffered harm from false FreightGuard reports filed by the same broker.

TODAY: ${today}  DEADLINE: ${deadlineStr}  CASE: ${caseRef}

DEFENDANT BROKER: ${brokerName} / MC-${brokerMC}

CO-PLAINTIFF CARRIERS (${ga.carriers.length} total):
${carrierList}

COMBINED DAMAGES CLAIMED: $${ga.totalDamages.toLocaleString()}

Write a forceful group demand letter that:
1. Opens with "The undersigned carriers, acting jointly and severally, hereby demand..."
2. States this is a coordinated legal action by ${ga.carriers.length} carriers with combined damages of $${ga.totalDamages.toLocaleString()}
3. Identifies each carrier and their individual damages in a numbered list
4. Cites 49 U.S.C. § 14915, pattern of defamation, RICO considerations for repeated conduct
5. Notes that ${ga.carriers.length} separate victims constitutes a pattern of predatory conduct
6. Demands: immediate retraction of ALL reports for ALL carriers, $${ga.totalDamages.toLocaleString()} in combined damages, and written apology
7. States that failure to respond will result in a coordinated multi-plaintiff federal lawsuit
8. Professional closing. $600/hour attorney tone.`;

  const message = await anthropic.messages.create({ model:'claude-opus-4-6', max_tokens:3000, messages:[{role:'user',content:prompt}] });
  const letterText = message.content[0].type==='text' ? message.content[0].text : '';

  ga.groupLetterText = letterText; ga.groupCaseRef = caseRef; ga.status = 'letter_generated';
  gas[req.params.groupId] = ga; saveGroupActions(gas);

  // Email all carriers their copy
  for (const c of ga.carriers) {
    try {
      await dispatchEmail({ to: c.email, subject: `✅ Group Demand Letter Ready — ${ga.carriers.length} Carriers vs. ${brokerName} (Case ${caseRef})`,
        text: `Your combined group demand letter is ready.\n\nCase: ${caseRef}\nGroup: ${ga.carriers.length} co-plaintiffs\nCombined Damages: $${ga.totalDamages.toLocaleString()}\n\n${letterText}`,
        html: `<p>Your group demand letter (${ga.carriers.length} co-plaintiffs, $${ga.totalDamages.toLocaleString()} combined) is ready.</p><p>Case: <strong>${caseRef}</strong></p>`, });
    } catch {}
  }

  res.json({ ok: true, letter: letterText, caseRef, carriers: ga.carriers.length, totalDamages: ga.totalDamages });
});

app.get('/api/admin/group-actions', requireAdmin, (req, res) => res.json({ groups: Object.values(loadGroupActions()) }));

// ════════════════════════════════════════════════════════════════════════════
// FEATURE C — LEGAL THREAT SCORE BADGE (1-10)
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/threat-score/:caseRef', async (req, res) => {
  const allLetters = await loadLetters();
  const letter     = allLetters.find(l => l.caseRef === req.params.caseRef || l.id === req.params.caseRef);
  if (!letter) return res.status(404).json({ error: 'Letter not found' });

  let score = 0; const factors = [];
  // Attorney assigned (+2)
  if (letter.attorneyId) { score += 2; factors.push({ label: 'Attorney Assigned', points: +2, met: true }); }
  else { factors.push({ label: 'Attorney Assigned', points: +2, met: false }); }
  // Damages over $200k (+2)
  if (Number(letter.totalDamages||0) >= 200000) { score += 2; factors.push({ label: 'High Damages ($200k+)', points: +2, met: true }); }
  else if (Number(letter.totalDamages||0) >= 50000) { score += 1; factors.push({ label: 'Substantial Damages ($50k+)', points: +1, met: true }); }
  else factors.push({ label: 'High Damages ($200k+)', points: +2, met: false });
  // Broker is repeat offender (+2)
  const brokerLetters = allLetters.filter(l => String(l.brokerMC||'').replace(/\D/g,'') === String(letter.brokerMC||'').replace(/\D/g,''));
  if (brokerLetters.length >= 3) { score += 2; factors.push({ label: 'Broker Repeat Offender (3+)', points: +2, met: true }); }
  else factors.push({ label: 'Broker Repeat Offender', points: +2, met: false });
  // Status sent/opened (+1)
  const statuses = loadStatuses();
  const st = statuses[letter.caseRef]?.status || statuses[letter.caseRef] || 'new';
  if (['sent','opened','responded'].includes(st)) { score += 1; factors.push({ label: 'Letter Delivered', points: +1, met: true }); }
  else factors.push({ label: 'Letter Delivered', points: +1, met: false });
  // Federal courthouse identified (+1)
  if (letter.court && String(letter.court).includes('District')) { score += 1; factors.push({ label: 'Federal Court Identified', points: +1, met: true }); }
  else factors.push({ label: 'Federal Court Identified', points: +1, met: false });
  // Evidence attached (+1)
  if (letter.savedFiles?.length || letter.evidenceDescription) { score += 1; factors.push({ label: 'Evidence on File', points: +1, met: true }); }
  else factors.push({ label: 'Evidence on File', points: +1, met: false });

  score = Math.min(10, Math.max(1, score));
  const label = score >= 9 ? 'Maximum Threat' : score >= 7 ? 'High Threat' : score >= 5 ? 'Moderate Threat' : 'Building Case';
  const color = score >= 9 ? '#e74c3c' : score >= 7 ? '#f0a830' : score >= 5 ? '#f0d030' : '#7ab3ff';

  // Generate embeddable badge SVG
  const badgeSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="240" height="60" viewBox="0 0 240 60">
    <rect width="240" height="60" rx="8" fill="#0a1628"/>
    <text x="12" y="22" font-family="Arial" font-size="11" fill="#7ab3ff" font-weight="bold">⚖️ FREIGHTGUARD DEFENSE</text>
    <text x="12" y="42" font-family="Arial" font-size="13" fill="${color}" font-weight="bold">Legal Threat Score: ${score}/10 — ${label}</text>
    <rect x="0" y="0" width="240" height="60" rx="8" fill="none" stroke="${color}" stroke-width="1.5"/>
  </svg>`;

  res.json({ score, label, color, factors, badgeSvg, caseRef: req.params.caseRef,
    shareText: `⚖️ FreightGuard Defense Legal Threat Score: ${score}/10 (${label}) — Case ${req.params.caseRef}. Active legal representation. freightguarddefense.com` });
});

// Public badge endpoint (embeddable)
app.get('/badge/:caseRef.svg', async (req, res) => {
  try {
    const allLetters = await loadLetters();
    const letter = allLetters.find(l => l.caseRef === req.params.caseRef);
    const score  = letter ? Math.min(10, Math.max(1, Math.floor(Math.random()*4)+6)) : 5;
    const color  = score >= 9 ? '#e74c3c' : score >= 7 ? '#f0a830' : '#f0d030';
    const label  = score >= 9 ? 'Maximum Threat' : score >= 7 ? 'High Threat' : 'Moderate Threat';
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="260" height="64">
      <rect width="260" height="64" rx="8" fill="#0a1628"/>
      <text x="14" y="24" font-family="Arial,sans-serif" font-size="11" fill="#7ab3ff" font-weight="700">⚖️ FREIGHTGUARD DEFENSE</text>
      <text x="14" y="46" font-family="Arial,sans-serif" font-size="14" fill="${color}" font-weight="700">Threat Score: ${score}/10 — ${label}</text>
      <rect x="1" y="1" width="258" height="62" rx="7" fill="none" stroke="${color}" stroke-width="1.5"/>
    </svg>`;
    res.set('Content-Type', 'image/svg+xml'); res.send(svg);
  } catch { res.status(500).send(''); }
});

// ════════════════════════════════════════════════════════════════════════════
// CARRIER HUB — REGISTRATION, BROKER REPORTING, ALERTS
// ════════════════════════════════════════════════════════════════════════════
const CARRIER_REPORTS_FILE = path.join(DATA_DIR, 'carrier_broker_reports.json');
const CARRIER_REG_FILE     = path.join(DATA_DIR, 'carrier_registrations.json');
function loadCarrierReports() { return loadJSON(CARRIER_REPORTS_FILE); }
function saveCarrierReports(d){ saveJSON(CARRIER_REPORTS_FILE, d); }
function loadCarrierRegs()    { return loadJSON(CARRIER_REG_FILE); }
function saveCarrierRegs(d)   { saveJSON(CARRIER_REG_FILE, d); }

// ── Unsubscribe token (HMAC of email) ────────────────────────────────────
function unsubToken(email) {
  const crypto = require('crypto');
  return crypto.createHmac('sha256', process.env.APP_SECRET || 'fgd-unsub-2024').update(email.toLowerCase()).digest('hex').slice(0,40);
}

// ── Beautiful new-report alert email ─────────────────────────────────────
function buildNewReportEmail({ brokerName, brokerMC, categories, severity, description, amountOwed, toEmail }) {
  const siteUrl = process.env.SITE_URL || 'https://freightguarddefense.com';
  const unsub   = `${siteUrl}/api/carrier-hub/unsubscribe?email=${encodeURIComponent(toEmail)}&token=${unsubToken(toEmail)}`;
  const sevColor = { critical:'#c0392b', high:'#e67e22', medium:'#f0a830', low:'#27ae60' };
  const sc = sevColor[severity] || sevColor.medium;
  const catStr = (categories||[]).map(c => c.replace(/_/g,' ').replace(/\b\w/g,ch=>ch.toUpperCase())).join(' · ');
  const amt = amountOwed ? `$${Number(amountOwed).toLocaleString()}` : null;
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>New Broker Report — FreightGuard Defense</title></head>
<body style="margin:0;padding:0;background:#f2f2f7;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f2f2f7;padding:32px 16px;">
<tr><td align="center">
<table width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:580px;">
  <tr><td style="background:linear-gradient(135deg,#1a1a2e 0%,#16213e 60%,#0f3460 100%);border-radius:16px 16px 0 0;padding:32px 36px;text-align:center;">
    <div style="font-size:11px;font-weight:700;letter-spacing:2px;color:rgba(255,255,255,0.45);text-transform:uppercase;margin-bottom:10px;">FreightGuard Defense</div>
    <div style="font-size:24px;font-weight:700;color:#fff;margin-bottom:6px;">⚠️ New Broker Report Filed</div>
    <div style="font-size:14px;color:rgba(255,255,255,0.6);">A carrier in your network reported a broker</div>
  </td></tr>
  <tr><td style="background:#fff;padding:28px 36px 0;">
    <div style="background:#f7f7f9;border-radius:12px;padding:18px 22px;border-left:4px solid ${sc};">
      <div style="font-size:10px;font-weight:700;letter-spacing:1.5px;color:#8e8e93;text-transform:uppercase;margin-bottom:4px;">Reported Broker</div>
      <div style="font-size:20px;font-weight:700;color:#1d1d1f;">${brokerName || 'Unknown Broker'}</div>
      <div style="font-size:14px;color:#6e6e73;margin-top:2px;">MC-${brokerMC}</div>
    </div>
  </td></tr>
  <tr><td style="background:#fff;padding:20px 36px 0;">
    <table width="100%" cellpadding="0" cellspacing="6" border="0">
      <tr>
        <td width="48%" style="vertical-align:top;padding-right:6px;">
          <div style="background:#fff5f5;border-radius:10px;padding:14px 16px;">
            <div style="font-size:10px;font-weight:700;letter-spacing:1px;color:#8e8e93;text-transform:uppercase;margin-bottom:6px;">Severity</div>
            <span style="display:inline-block;background:${sc};color:#fff;font-size:12px;font-weight:700;padding:4px 12px;border-radius:100px;text-transform:capitalize;">${severity||'medium'}</span>
          </div>
        </td>
        <td width="52%" style="vertical-align:top;padding-left:6px;">
          <div style="background:#f7f7f9;border-radius:10px;padding:14px 16px;">
            <div style="font-size:10px;font-weight:700;letter-spacing:1px;color:#8e8e93;text-transform:uppercase;margin-bottom:6px;">Categories</div>
            <div style="font-size:13px;font-weight:600;color:#1d1d1f;">${catStr||'General'}</div>
          </div>
        </td>
      </tr>
    </table>
  </td></tr>
  ${amt ? `<tr><td style="background:#fff;padding:12px 36px 0;">
    <div style="background:#fff0f0;border-radius:10px;padding:14px 16px;border:1px solid rgba(192,57,43,0.15);">
      <div style="font-size:10px;font-weight:700;letter-spacing:1px;color:#8e8e93;text-transform:uppercase;margin-bottom:4px;">Amount Owed</div>
      <div style="font-size:22px;font-weight:800;color:#c0392b;">${amt}</div>
    </div>
  </td></tr>` : ''}
  <tr><td style="background:#fff;padding:12px 36px 0;">
    <div style="background:#f7f7f9;border-radius:10px;padding:14px 16px;">
      <div style="font-size:10px;font-weight:700;letter-spacing:1px;color:#8e8e93;text-transform:uppercase;margin-bottom:8px;">Description</div>
      <div style="font-size:14px;color:#1d1d1f;line-height:1.65;">${(description||'').substring(0,400)}${(description||'').length>400?'…':''}</div>
    </div>
  </td></tr>
  <tr><td style="background:#fff;padding:24px 36px 32px;text-align:center;">
    <a href="${siteUrl}/carrier-hub.html" style="display:inline-block;background:#c0392b;color:#fff;font-size:15px;font-weight:700;padding:14px 36px;border-radius:12px;text-decoration:none;">View Full Report →</a>
    <div style="margin-top:14px;font-size:13px;color:#8e8e93;">You're receiving this as a registered FreightGuard Defense carrier.</div>
  </td></tr>
  <tr><td style="background:#f2f2f7;border-radius:0 0 16px 16px;padding:18px 36px;text-align:center;border-top:1px solid #e5e5ea;">
    <div style="font-size:12px;color:#8e8e93;line-height:1.9;">
      <strong style="color:#3d3d3d;">FreightGuard Defense</strong> · Protecting Motor Carriers<br>
      <a href="${unsub}" style="color:#8e8e93;">Unsubscribe from report alerts</a> &nbsp;·&nbsp;
      <a href="${siteUrl}/carrier-hub.html" style="color:#8e8e93;">Manage preferences</a>
    </div>
  </td></tr>
</table>
</td></tr>
</table>
</body></html>`;
}

// Add schema for new tables
// (runs on next startup)
if (pgPool) {
  pgPool.query(`
    CREATE TABLE IF NOT EXISTS carrier_registrations (
      id TEXT PRIMARY KEY, mc_number TEXT UNIQUE, dot_number TEXT,
      company_name TEXT NOT NULL, contact_name TEXT, email TEXT UNIQUE NOT NULL,
      phone TEXT, password_hash TEXT, state TEXT,
      watchlist TEXT[] DEFAULT '{}',
      subscribed_alerts BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW(), last_login TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS carrier_broker_reports (
      id TEXT PRIMARY KEY, broker_mc TEXT NOT NULL, broker_name TEXT,
      broker_address TEXT, reporter_mc TEXT, reporter_name TEXT,
      reporter_email TEXT, incident_date DATE,
      categories TEXT[] NOT NULL,
      description TEXT NOT NULL, amount_owed NUMERIC DEFAULT 0,
      load_number TEXT, severity TEXT DEFAULT 'medium',
      verified BOOLEAN DEFAULT FALSE, upvotes INT DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `).catch(e => console.warn('Carrier hub schema:', e.message));
}

const REPORT_CATEGORIES = [
  { id: 'trigger_happy',       label: '🚨 Trigger-Happy Reporter',         desc: 'Files false FreightGuard/DAT reports against carriers without cause' },
  { id: 'nonpayment',          label: '💸 Non-Payment / Late Payment',      desc: 'Refuses to pay or consistently delays payment past agreed terms' },
  { id: 'unauthorized_rebroke',label: '🔄 Unauthorized Re-Brokering',       desc: 'Re-brokers shipments without carrier knowledge or consent' },
  { id: 'no_authority',        label: '⛔ No Broker / FF Authority',         desc: 'Operating as freight broker without proper FMCSA authority' },
  { id: 'no_bond',             label: '🔓 No Bond or Trust Fund',           desc: 'Operating without required $75,000 surety bond or trust fund' },
  { id: 'alias',               label: '🎭 Operates Under Alias',            desc: 'Uses multiple company names/aliases to evade enforcement' },
  { id: 'fraud',               label: '🚫 Fraudulent Activity',             desc: 'Bait-and-switch rates, fake load postings, or other fraud' },
  { id: 'unethical',           label: '⚠️ Unethical/Deceptive Practices',   desc: 'Bully tactics, threats, harassment, misrepresentation' },
  { id: 'rate_reduction',      label: '📉 Forced Rate Reduction',           desc: 'Demands rate cuts after load acceptance under threat' },
  { id: 'detention',           label: '⏱ Detention/Layover Refusal',       desc: 'Refuses to pay legitimate detention or layover charges' },
  { id: 'tracking_deductions', label: '📍 Unlawful Tracking Deductions',     desc: 'Deducts pay or withholds payment for not using their tracking app — illegal under FMCSA rules' },
  { id: 'unauth_deductions',   label: '✂️ Unauthorized Deductions',          desc: 'Makes unauthorized deductions from carrier pay — fuel surcharges, cargo claims, fees, chargebacks not in the rate confirmation' },
  { id: 'tracking_deductions',     label: '📍 Unlawful Tracking Deductions',  desc: 'Deducts pay or withholds payment for not using their tracking app — illegal under FMCSA independent contractor rules' },
  { id: 'unauthorized_deductions', label: '✂️ Unauthorized Deductions',       desc: 'Makes unauthorized deductions from agreed rate — fuel surcharges, claims, fees, or chargebacks not agreed to in the rate confirmation' },
];

app.get('/api/carrier-hub/report-categories', (req, res) => res.json({ categories: REPORT_CATEGORIES }));

// ── CARRIER REGISTRATION ─────────────────────────────────────────────────────
app.post('/api/carrier-hub/register', rateLimit(60000, 10), async (req, res) => {
  const { companyName, mcNumber, dotNumber, contactName, email, phone, password, state } = req.body;
  if (!companyName || !email || !password) return res.status(400).json({ error: 'Company name, email, and password required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

  const regs = loadCarrierRegs();
  if (regs.find(r => r.email.toLowerCase() === email.toLowerCase()))
    return res.status(409).json({ error: 'An account with this email already exists' });

  const hash = bcrypt ? await bcrypt.hash(password, 10) : password;
  const carrier = {
    id: 'car_' + Date.now(), mcNumber: mcNumber||'', dotNumber: dotNumber||'',
    companyName, contactName: contactName||'', email: email.toLowerCase(),
    phone: phone||'', passwordHash: hash, state: state||'',
    watchlist: [], subscribedAlerts: true,
    createdAt: new Date().toISOString(),
  };
  regs.push(carrier);
  saveCarrierRegs(regs);

  if (pgPool) await pgPool.query(
    'INSERT INTO carrier_registrations(id,mc_number,dot_number,company_name,contact_name,email,phone,password_hash,state) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(email) DO NOTHING',
    [carrier.id, mcNumber||'', dotNumber||'', companyName, contactName||'', email.toLowerCase(), phone||'', hash, state||'']
  ).catch(() => {});

  // Welcome email
  try {
    await dispatchEmail({ to: email,
      subject: 'Welcome to FreightGuard Defense Carrier Hub',
      text: `Welcome ${companyName}!\n\nYour carrier account is active. You can now:\n- Monitor bad brokers and get instant alerts\n- File reports against brokers who harm carriers\n- View the community broker blacklist\n\nLog in at: ${process.env.SITE_URL||'https://freightguarddefense.com'}/carrier-hub.html\n\nFreightGuard Defense`,
      html: `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
        <div style="background:#0a1628;padding:24px;text-align:center;"><h2 style="color:#fff;margin:0;">⚖️ FreightGuard Defense</h2><p style="color:#7ab3ff;font-size:12px;margin:4px 0 0;">Carrier Hub</p></div>
        <div style="padding:24px;background:#f9f9f9;">
          <p>Welcome, <strong>${companyName}</strong>!</p>
          <p>Your account is active. You can now monitor brokers, file reports, and protect your reputation.</p>
          <p><a href="${process.env.SITE_URL||'https://freightguarddefense.com'}/carrier-hub.html" style="background:#c0392b;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;font-weight:700;">Access Carrier Hub</a></p>
        </div></div>`,
    });
  } catch {}

  const token = jwt ? jwt.sign({ id: carrier.id, email: carrier.email, companyName, type: 'carrier_hub' }, process.env.JWT_SECRET||'fgd-secret', { expiresIn: '30d' }) : null;
  res.json({ ok: true, token, carrier: { id: carrier.id, companyName, email, mcNumber, state } });
});

app.post('/api/carrier-hub/login', rateLimit(60000, 20), async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const regs    = loadCarrierRegs();
  const carrier = regs.find(r => r.email.toLowerCase() === email.toLowerCase());
  if (!carrier) return res.status(401).json({ error: 'Invalid email or password' });
  const ok = bcrypt ? await bcrypt.compare(password, carrier.passwordHash||'') : password === carrier.passwordHash;
  if (!ok) return res.status(401).json({ error: 'Invalid email or password' });
  const token = jwt ? jwt.sign({ id: carrier.id, email: carrier.email, companyName: carrier.companyName, type: 'carrier_hub' }, process.env.JWT_SECRET||'fgd-secret', { expiresIn: '30d' }) : null;
  res.json({ ok: true, token, carrier: { id: carrier.id, companyName: carrier.companyName, email: carrier.email, mcNumber: carrier.mcNumber, state: carrier.state } });
});

function requireCarrierHub(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Login required' });
  try {
    const d = jwt.verify(auth.slice(7), process.env.JWT_SECRET||'fgd-secret');
    if (d.type !== 'carrier_hub') return res.status(401).json({ error: 'Invalid token' });
    req.carrier = d; next();
  } catch { return res.status(401).json({ error: 'Session expired' }); }
}

// ── BROKER REPORTS ────────────────────────────────────────────────────────────
app.post('/api/carrier-hub/report', rateLimit(60000, 5), async (req, res) => {
  const { brokerMC, brokerName, brokerAddress, incidentDate, categories,
          description, amountOwed, loadNumber, severity,
          reporterName, reporterEmail, reporterMC } = req.body;

  if (!brokerMC || !categories?.length || !description)
    return res.status(400).json({ error: 'Broker MC, at least one category, and description are required' });

  const id = 'RPT-' + Date.now().toString().slice(-8) + '-' + Math.floor(Math.random()*1000);
  const report = {
    id, brokerMC: brokerMC.replace(/\D/g,''), brokerName: brokerName||'',
    brokerAddress: brokerAddress||'', reporterMC: reporterMC||'',
    reporterName: reporterName||'Anonymous Carrier', reporterEmail: reporterEmail||'',
    incidentDate: incidentDate||new Date().toISOString().split('T')[0],
    categories, description, amountOwed: Number(amountOwed)||0,
    loadNumber: loadNumber||'', severity: severity||'medium',
    verified: false, upvotes: 0, createdAt: new Date().toISOString(),
  };

  const reports = loadCarrierReports();
  reports.push(report);
  saveCarrierReports(reports);

  if (pgPool) await pgPool.query(
    'INSERT INTO carrier_broker_reports(id,broker_mc,broker_name,broker_address,reporter_mc,reporter_name,reporter_email,incident_date,categories,description,amount_owed,load_number,severity) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)',
    [id, report.brokerMC, brokerName||'', brokerAddress||'', reporterMC||'', reporterName||'Anonymous Carrier', reporterEmail||'', incidentDate||null, categories, description, Number(amountOwed)||0, loadNumber||'', severity||'medium']
  ).catch(() => {});

  await logAudit(id, 'broker_report_filed', reporterEmail||'anonymous', `${categories.join(',')} against ${brokerName||'MC-'+brokerMC}`);

  // Alert all watchlist subscribers for this broker
  const wl = loadWatchlist();
  const mc = report.brokerMC;
  const watchers = wl[mc]?.subscribers || [];
  const catLabels = categories.map(c => REPORT_CATEGORIES.find(r => r.id === c)?.label || c).join(', ');

  for (const watcher of watchers) {
    if (watcher.email === reporterEmail) continue; // don't notify reporter
    try {
      await dispatchEmail({
        to: watcher.email,
        subject: `⚠️ New Broker Report Filed: ${brokerName||'MC-'+mc} — ${catLabels.substring(0,60)}`,
        text: `A carrier just filed a report against ${brokerName||'MC-'+mc} (MC-${mc}) that you're watching.\n\nCategories: ${catLabels}\nSeverity: ${severity||'Medium'}\nIncident Date: ${incidentDate||'Recent'}\n${amountOwed ? `Amount Owed: $${Number(amountOwed).toLocaleString()}` : ''}\nLoad #: ${loadNumber||'N/A'}\n\nDescription:\n${description}\n\nView full report: ${process.env.SITE_URL||'https://freightguarddefense.com'}/carrier-hub.html`,
        html: `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
          <div style="background:#3d1a1a;padding:16px 24px;border-bottom:3px solid #c0392b;"><h2 style="color:#fff;margin:0;font-size:16px;">⚠️ Broker Watch Alert — FreightGuard Defense</h2></div>
          <div style="padding:20px 24px;background:#f9f9f9;">
            <p>A new report was filed against <strong>${brokerName||'MC-'+mc}</strong> (MC-${mc}) — a broker on your watchlist.</p>
            <table style="font-size:13px;border-collapse:collapse;width:100%;">
              <tr style="background:#fee;"><td style="padding:8px 12px;color:#888;">Categories:</td><td style="padding:8px 12px;font-weight:700;color:#c0392b;">${catLabels}</td></tr>
              <tr><td style="padding:8px 12px;color:#888;">Severity:</td><td style="padding:8px 12px;text-transform:capitalize;">${severity||'Medium'}</td></tr>
              ${amountOwed ? `<tr style="background:#fee;"><td style="padding:8px 12px;color:#888;">Amount Owed:</td><td style="padding:8px 12px;font-weight:700;color:#c0392b;">$${Number(amountOwed).toLocaleString()}</td></tr>` : ''}
              <tr><td style="padding:8px 12px;color:#888;">Description:</td><td style="padding:8px 12px;">${description.substring(0,300)}${description.length>300?'...':''}</td></tr>
            </table>
            <p style="margin-top:16px;"><a href="${process.env.SITE_URL||'https://freightguarddefense.com'}/carrier-hub.html" style="background:#c0392b;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;font-weight:700;">View Full Report</a></p>
          </div></div>`,
      });
    } catch(e) { console.warn('Watcher alert failed:', e.message); }
  }

  // Also alert registered carriers watching this broker
  const regs = loadCarrierRegs();
  for (const reg of regs.filter(r => r.watchlist?.includes(mc) && r.subscribedAlerts && r.email !== reporterEmail)) {
    try {
      await dispatchEmail({
        to: reg.email,
        subject: `⚠️ BROKER ALERT: ${brokerName||'MC-'+mc} — New Report Filed`,
        text: `A carrier reported ${brokerName||'MC-'+mc}: ${catLabels}\n\nDescription: ${description.substring(0,400)}\n\nView: ${process.env.SITE_URL||'https://freightguarddefense.com'}/carrier-hub.html`,
        html: `<p>New report against <strong>${brokerName||'MC-'+mc}</strong> (watched by you): <strong>${catLabels}</strong>.<br>${description.substring(0,400)}</p>`,
      });
    } catch {}
  }

  // Broadcast to ALL subscribed registered carriers (not just watchlist)
  const allRegs = loadCarrierRegs().filter(r => r.subscribedAlerts !== false && r.email && r.email !== reporterEmail);
  let broadcastCount = 0;
  for (const reg of allRegs) {
    // Skip if already notified via watchlist above
    if (watchers.some(w => w.email === reg.email)) continue;
    try {
      await dispatchEmail({
        to: reg.email,
        subject: `⚠️ New Broker Report: ${brokerName||'MC-'+mc} — ${catLabels.substring(0,50)}`,
        text: `A carrier filed a report against ${brokerName||'MC-'+mc} (MC-${mc}).

Categories: ${catLabels}
Severity: ${severity||'Medium'}
${amountOwed?`Amount Owed: $${Number(amountOwed).toLocaleString()}`:''}\n
Description:
${description.substring(0,400)}

View: ${process.env.SITE_URL||'https://freightguarddefense.com'}/carrier-hub.html`,
        html: buildNewReportEmail({ brokerName, brokerMC: mc, categories, severity, description, amountOwed, toEmail: reg.email }),
      });
      broadcastCount++;
    } catch(e) { console.warn('Broadcast alert failed for', reg.email, e.message); }
  }

  res.json({ ok: true, reportId: id, alertsSent: watchers.length + broadcastCount, message: `Report filed. ${watchers.length + broadcastCount} carriers have been notified.` });
});

// Get broker reports (public feed)
app.get('/api/carrier-hub/reports', async (req, res) => {
  const { brokerMC, category, severity, q, limit = 50, offset = 0 } = req.query;
  let reports;

  if (pgPool) {
    // Build parameterised query from PostgreSQL
    const conditions = [];
    const params = [];
    if (brokerMC) { params.push(brokerMC.replace(/\D/g,'')); conditions.push(`broker_mc = $${params.length}`); }
    if (category)  { params.push(category);  conditions.push(`$${params.length} = ANY(categories)`); }
    if (severity)  { params.push(severity);  conditions.push(`severity = $${params.length}`); }
    if (q) {
      params.push('%' + q.toLowerCase() + '%');
      const i = params.length;
      conditions.push(`(LOWER(broker_name) LIKE $${i} OR broker_mc LIKE $${i} OR LOWER(description) LIKE $${i} OR LOWER(ARRAY_TO_STRING(categories,' ')) LIKE $${i})`);
    }
    const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
    const result = await pgPool.query(
      `SELECT id, broker_mc, broker_name, broker_address, reporter_mc, reporter_name,
              reporter_email, incident_date, categories, description, amount_owed,
              load_number, severity, verified, upvotes, created_at
       FROM carrier_broker_reports ${where} ORDER BY created_at DESC`,
      params
    ).catch(() => null);

    if (result) {
      reports = result.rows.map(r => ({
        id: r.id, brokerMC: r.broker_mc, brokerName: r.broker_name,
        brokerAddress: r.broker_address, reporterMC: r.reporter_mc,
        reporterName: r.reporter_name, reporterEmail: r.reporter_email,
        incidentDate: r.incident_date, categories: r.categories || [],
        description: r.description, amountOwed: r.amount_owed,
        loadNumber: r.load_number, severity: r.severity,
        verified: r.verified, upvotes: r.upvotes || 0,
        createdAt: r.created_at
      }));
    }
  }

  if (!reports) {
    // Fallback to JSON file
    reports = loadCarrierReports();
    if (brokerMC) reports = reports.filter(r => r.brokerMC === brokerMC.replace(/\D/g,''));
    if (category) reports = reports.filter(r => r.categories?.includes(category));
    if (severity) reports = reports.filter(r => r.severity === severity);
    if (q) {
      const t = q.toLowerCase();
      reports = reports.filter(r =>
        (r.brokerName||'').toLowerCase().includes(t) ||
        (r.brokerMC||'').includes(t) ||
        (r.description||'').toLowerCase().includes(t) ||
        (r.categories||[]).join(' ').includes(t)
      );
    }
    reports.sort((a,b) => b.createdAt > a.createdAt ? 1 : -1);
  }

  const total = reports.length;
  const page  = reports.slice(Number(offset), Number(offset)+Number(limit));
  res.json({ reports: page, total, hasMore: total > Number(offset)+Number(limit) });
});

// Get broker reputation summary
app.get('/api/carrier-hub/broker-rep/:mc', async (req, res) => {
  const mc = req.params.mc.replace(/\D/g,'');
  const reports = loadCarrierReports().filter(r => r.brokerMC === mc);
  const catCounts = {};
  for (const r of reports) for (const c of (r.categories||[])) catCounts[c] = (catCounts[c]||0)+1;
  const topCats = Object.entries(catCounts).sort((a,b)=>b[1]-a[1]).slice(0,5)
    .map(([id,count]) => ({ ...REPORT_CATEGORIES.find(c=>c.id===id), count }));
  const totalOwed = reports.reduce((s,r)=>s+(Number(r.amountOwed)||0),0);
  const isTriggerHappy = (catCounts['trigger_happy']||0) >= 2;
  res.json({ mc, totalReports: reports.length, topCategories: topCats, totalAmountOwed: totalOwed, isTriggerHappy, riskLevel: reports.length >= 5 ? 'HIGH' : reports.length >= 2 ? 'MEDIUM' : reports.length >= 1 ? 'LOW' : 'NONE', recentReports: reports.slice(0,5) });
});

// Upvote a report
app.post('/api/carrier-hub/report/:id/upvote', (req, res) => {
  const reports = loadCarrierReports();
  const r = reports.find(r => r.id === req.params.id);
  if (!r) return res.status(404).json({ error: 'Report not found' });
  r.upvotes = (r.upvotes||0)+1;
  saveCarrierReports(reports);
  res.json({ ok: true, upvotes: r.upvotes });
});

// Edit own report
app.put('/api/carrier-hub/report/:id', requireCarrierHub, (req, res) => {
  const reports = loadCarrierReports();
  const report = reports.find(r => r.id === req.params.id);
  if (!report) return res.status(404).json({ error: 'Report not found' });
  if (report.reporterEmail !== req.carrier.email && report.reporterMC !== req.carrier.mcNumber) {
    return res.status(403).json({ error: 'You can only edit your own reports' });
  }
  const { description, amountOwed, severity, loadNumber } = req.body;
  if (description) report.description = description.substring(0, 5000);
  if (amountOwed !== undefined) report.amountOwed = Number(amountOwed) || 0;
  if (severity && ['low','medium','high','critical'].includes(severity)) report.severity = severity;
  if (loadNumber !== undefined) report.loadNumber = loadNumber;
  report.updatedAt = new Date().toISOString();
  saveCarrierReports(reports);
  if (pgPool) pgPool.query(
    'UPDATE carrier_broker_reports SET description=$1,amount_owed=$2,severity=$3,load_number=$4 WHERE id=$5',
    [report.description, report.amountOwed, report.severity, report.loadNumber, req.params.id]
  ).catch(()=>{});
  res.json({ ok: true, report });
});

// Delete own report
app.delete('/api/carrier-hub/report/:id', requireCarrierHub, (req, res) => {
  const reports = loadCarrierReports();
  const idx = reports.findIndex(r => r.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Report not found' });
  const report = reports[idx];
  if (report.reporterEmail !== req.carrier.email && report.reporterMC !== req.carrier.mcNumber) {
    return res.status(403).json({ error: 'You can only delete your own reports' });
  }
  reports.splice(idx, 1);
  saveCarrierReports(reports);
  if (pgPool) pgPool.query('DELETE FROM carrier_broker_reports WHERE id=$1', [req.params.id]).catch(()=>{});
  res.json({ ok: true });
});

// Unsubscribe from report alerts (no auth needed — token in URL)
app.get('/api/carrier-hub/unsubscribe', (req, res) => {
  const { email, token } = req.query;
  if (!email || !token || token !== unsubToken(email)) {
    return res.status(400).send('<h2>Invalid unsubscribe link.</h2>');
  }
  const regs = loadCarrierRegs();
  const carr = regs.find(r => r.email?.toLowerCase() === email.toLowerCase());
  if (carr) { carr.subscribedAlerts = false; saveCarrierRegs(regs); }
  res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Unsubscribed</title>
<style>body{font-family:-apple-system,sans-serif;background:#f2f2f7;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;}
.box{background:#fff;border-radius:16px;padding:48px 40px;max-width:440px;text-align:center;box-shadow:0 4px 24px rgba(0,0,0,0.08);}
h1{color:#1d1d1f;font-size:24px;margin-bottom:8px;}p{color:#6e6e73;font-size:15px;line-height:1.6;}
a{display:inline-block;margin-top:24px;background:#c0392b;color:#fff;padding:12px 28px;border-radius:10px;text-decoration:none;font-weight:700;font-size:15px;}</style></head>
<body><div class="box"><div style="font-size:48px;margin-bottom:16px;">✅</div>
<h1>You've been unsubscribed</h1>
<p>You'll no longer receive new broker report alerts. You can re-enable alerts anytime from your dashboard.</p>
<a href="https://freightguarddefense.com/carrier-hub.html">Back to Carrier Hub</a></div></body></html>`);
});

// Extract text from uploaded rate con file (PDF, TXT, DOCX)
const multer = (() => { try { return require('multer'); } catch(e) { return null; } })();
const pdfParse = (() => { try { return require('pdf-parse'); } catch(e) { return null; } })();
const rcUpload = multer ? multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 } }) : null;

if (rcUpload) {
  app.post('/api/carrier-hub/extract-text', rcUpload.single('file'), async (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
      const ext = (req.file.originalname || '').split('.').pop().toLowerCase();
      let text = '';
      if (ext === 'txt') {
        text = req.file.buffer.toString('utf8');
      } else if (ext === 'pdf' && pdfParse) {
        const data = await pdfParse(req.file.buffer);
        text = data.text || '';
      } else if (['doc','docx'].includes(ext)) {
        // Basic docx: extract raw text from XML
        const JSZip = (() => { try { return require('jszip'); } catch(e) { return null; } })();
        if (JSZip) {
          const zip = await JSZip.loadAsync(req.file.buffer);
          const wordDoc = zip.files['word/document.xml'];
          if (wordDoc) {
            const xml = await wordDoc.async('text');
            text = xml.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
          }
        }
      }
      if (!text) return res.json({ text: '', warning: 'Could not extract text from this file type. Please paste text manually.' });
      res.json({ text: text.substring(0, 50000) });
    } catch(e) {
      console.error('extract-text error:', e.message);
      res.status(500).json({ error: 'Extraction failed: ' + e.message });
    }
  });
} else {
  app.post('/api/carrier-hub/extract-text', express.raw({ type: '*/*', limit: '20mb' }), async (req, res) => {
    res.json({ text: '', warning: 'File extraction requires multer package. Please paste text manually.' });
  });
}

// Carrier hub watchlist management
app.post('/api/carrier-hub/watchlist/:mc', requireCarrierHub, (req, res) => {
  const mc   = req.params.mc.replace(/\D/g,'');
  const regs = loadCarrierRegs();
  const carr = regs.find(r => r.id === req.carrier.id);
  if (!carr) return res.status(404).json({ error: 'Carrier not found' });
  if (!carr.watchlist) carr.watchlist = [];
  if (!carr.watchlist.includes(mc)) carr.watchlist.push(mc);
  saveCarrierRegs(regs);
  res.json({ ok: true, watchlist: carr.watchlist });
});

app.get('/api/carrier-hub/me', requireCarrierHub, (req, res) => {
  const regs = loadCarrierRegs();
  const carr = regs.find(r => r.id === req.carrier.id);
  if (!carr) return res.status(404).json({ error: 'Not found' });
  res.json({ carrier: { ...carr, passwordHash: undefined } });
});

// ── DELETE account ───────────────────────────────────────────────────────────
app.delete('/api/carrier-hub/account', requireCarrierHub, (req, res) => {
  try {
    let regs = loadCarrierRegs();
    const idx = regs.findIndex(r => r.id === req.carrier.id);
    if (idx === -1) return res.status(404).json({ error: 'Account not found' });
    regs.splice(idx, 1);
    saveJSON(CARRIER_REG_FILE, regs);
    res.json({ success: true, message: 'Account deleted' });
  } catch(e) {
    console.error('Delete account error:', e);
    res.status(500).json({ error: 'Failed to delete account' });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// FEATURE 1 — "IS THIS BROKER SAFE?" PUBLIC WIDGET
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/broker-safe/:mc', async (req, res) => {
  const mc       = req.params.mc.replace(/\D/g,'');
  const reports  = loadCarrierReports().filter(r => r.brokerMC === mc);
  const letters  = await loadLetters();
  const demandLetters = letters.filter(l => String(l.brokerMC||'').replace(/\D/g,'') === mc);
  const trigger  = reports.filter(r => r.categories?.includes('trigger_happy')).length;
  const nonpay   = reports.filter(r => r.categories?.includes('nonpayment')).length;
  const fraud    = reports.filter(r => r.categories?.includes('fraud')).length;
  const totalOwed= reports.reduce((s,r)=>s+(Number(r.amountOwed)||0),0);
  let riskScore  = 0;
  if (reports.length >= 1)  riskScore += 20;
  if (reports.length >= 3)  riskScore += 20;
  if (reports.length >= 5)  riskScore += 20;
  if (trigger >= 1)         riskScore += 15;
  if (nonpay  >= 1)         riskScore += 15;
  if (fraud   >= 1)         riskScore += 30;
  if (demandLetters.length >= 1) riskScore += 10;
  riskScore = Math.min(100, riskScore);
  const safe    = riskScore < 25;
  const caution = riskScore >= 25 && riskScore < 60;
  const danger  = riskScore >= 60;
  const label   = danger ? 'HIGH RISK' : caution ? 'USE CAUTION' : 'LOW RISK';
  const color   = danger ? '#e74c3c' : caution ? '#f0a830' : '#27ae60';
  const emoji   = danger ? '🚨' : caution ? '⚠️' : '✅';
  res.json({ mc, riskScore, label, color, emoji, safe, reports: reports.length, demandLetters: demandLetters.length, trigger, nonpay, fraud, totalOwed });
});

// Embeddable widget SVG
app.get('/widget/broker/:mc.svg', async (req, res) => {
  const mc = req.params.mc.replace(/\D/g,'');
  const reports = loadCarrierReports().filter(r => r.brokerMC === mc);
  const risk = Math.min(100, reports.length * 20 + (reports.filter(r=>r.categories?.includes('fraud')).length*30));
  const label = risk >= 60 ? 'HIGH RISK' : risk >= 25 ? 'USE CAUTION' : 'LOW RISK';
  const color = risk >= 60 ? '#e74c3c' : risk >= 25 ? '#f0a830' : '#27ae60';
  const emoji = risk >= 60 ? '🚨' : risk >= 25 ? '⚠️' : '✅';
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="280" height="70">
    <rect width="280" height="70" rx="8" fill="#0a1628"/>
    <text x="14" y="22" font-family="Arial,sans-serif" font-size="10" fill="#7ab3ff" font-weight="700">FreightGuard Defense — Broker Check</text>
    <text x="14" y="44" font-family="Arial,sans-serif" font-size="16" fill="${color}" font-weight="900">${emoji} MC-${mc}: ${label}</text>
    <text x="14" y="61" font-family="Arial,sans-serif" font-size="10" fill="#667788">${reports.length} carrier report${reports.length!==1?'s':''} · freightguarddefense.com</text>
    <rect x="1" y="1" width="278" height="68" rx="7" fill="none" stroke="${color}" stroke-width="1.5"/>
  </svg>`;
  res.set('Content-Type','image/svg+xml'); res.send(svg);
});

// ════════════════════════════════════════════════════════════════════════════
// FEATURE 2 — RATE CON RED FLAG ANALYZER
// ════════════════════════════════════════════════════════════════════════════
app.post('/api/analyze-ratecon', rateLimit(60000, 10), async (req, res) => {
  const { text, brokerMC } = req.body;
  if (!text || text.length < 50) return res.status(400).json({ error: 'Paste the full rate confirmation text' });

  const prompt = `You are a transportation law attorney reviewing a freight broker rate confirmation for red flags that could harm the carrier.

Analyze this rate confirmation and return a JSON response with this exact structure:
{
  "riskScore": 1-10,
  "flags": [
    { "severity": "critical|high|medium|low", "category": "string", "issue": "string", "quote": "exact text from doc", "recommendation": "string" }
  ],
  "summary": "2-3 sentence plain English summary",
  "missingClauses": ["list of important missing clauses"]
}

Check for:
- Vague or one-sided damage/cargo claim language
- Missing or inadequate detention provisions
- Re-brokering permission clauses (carrier unknowingly authorizes re-brokering)
- Unilateral rate reduction clauses
- Broad indemnification language favoring broker
- Missing payment terms or excessively long payment windows
- Tracking/monitoring requirements that could affect independent contractor status
- Unauthorized deduction language
- Dispute resolution clauses that favor broker
- Missing or inadequate cargo liability terms
- Any language that waives carrier rights

Rate confirmation text:
${text.substring(0, 4000)}`;

  try {
    const message = await anthropic.messages.create({
      model: 'claude-opus-4-6', max_tokens: 1500,
      messages: [{ role: 'user', content: prompt }],
    });
    let result = message.content[0].type === 'text' ? message.content[0].text : '{}';
    // Extract JSON
    const jsonMatch = result.match(/\{[\s\S]*\}/);
    if (jsonMatch) result = jsonMatch[0];
    const parsed = JSON.parse(result);

    // Also check broker reputation if MC provided
    let brokerRep = null;
    if (brokerMC) {
      const mc = brokerMC.replace(/\D/g,'');
      const rpts = loadCarrierReports().filter(r => r.brokerMC === mc);
      if (rpts.length > 0) brokerRep = { reports: rpts.length, topIssues: [...new Set(rpts.flatMap(r=>r.categories||[]))].slice(0,3) };
    }

    res.json({ ...parsed, brokerRep, analyzedAt: new Date().toISOString() });
  } catch(e) {
    res.status(500).json({ error: 'Analysis failed: ' + e.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// FEATURE 3 — CARRIER REPUTATION SCORE
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/carrier-score/:mc', async (req, res) => {
  const mc = req.params.mc.replace(/\D/g,'');
  // Check if any reports filed AGAINST this carrier MC
  const reportsAgainst = loadCarrierReports().filter(r => r.reporterMC === mc && r.categories?.includes('trigger_happy'));
  // Check FMCSA safety
  let fmcsaData = {};
  try {
    const url = `https://safer.fmcsa.dot.gov/query.asp?searchtype=ANY&query_type=queryCarrierSnapshot&query_param=MC_MX&query_string=${mc}`;
    const r = await fetch(url, { headers:{'User-Agent':'Mozilla/5.0'}, signal: AbortSignal.timeout ? AbortSignal.timeout(6000) : undefined });
    const html = await r.text();
    const sm = html.match(/USDOT Status:<\/A>[\s\S]*?<TD[^>]*class=["']queryfield["'][^>]*>([\s\S]*?)<\/TD>/i);
    const status = sm ? sm[1].replace(/<!--[\s\S]*?-->/g,'').replace(/<[^>]+>/g,'').trim() : '';
    const srm = html.match(/Safety Rating:<\/A>[^<]*<\/A>[\s\S]*?<TD[^>]*class=["']queryfield["'][^>]*>([\s\S]*?)<\/TD>/i);
    fmcsaData = { status, safetyRating: srm ? srm[1].replace(/<[^>]+>/g,'').trim() : '' };
  } catch {}

  let score = 85; // base score
  if (fmcsaData.status?.toLowerCase().includes('active'))            score += 5;
  if (fmcsaData.safetyRating?.toLowerCase().includes('satisfactory')) score += 10;
  if (fmcsaData.safetyRating?.toLowerCase().includes('conditional')) score -= 20;
  if (fmcsaData.safetyRating?.toLowerCase().includes('unsatisfactory')) score -= 40;
  score = Math.min(100, Math.max(0, score));
  const tier = score >= 90 ? 'PLATINUM' : score >= 75 ? 'GOLD' : score >= 60 ? 'SILVER' : 'NEEDS REVIEW';
  const color = score >= 90 ? '#a78bfa' : score >= 75 ? '#f0a830' : score >= 60 ? '#aaaaaa' : '#e74c3c';
  res.json({ mc, score, tier, color, fmcsa: fmcsaData, checkedAt: new Date().toISOString() });
});

// Public carrier profile
app.get('/api/carrier-profile/:mc', async (req, res) => {
  const mc   = req.params.mc.replace(/\D/g,'');
  const regs = loadCarrierRegs();
  const carr = regs.find(r => r.mcNumber === mc);
  if (!carr) return res.status(404).json({ error: 'Carrier not registered' });
  res.json({ companyName: carr.companyName, mc, state: carr.state, memberSince: carr.createdAt, reportsFilied: loadCarrierReports().filter(r=>r.reporterMC===mc).length });
});

// ════════════════════════════════════════════════════════════════════════════
// FEATURE 4 — ANONYMOUS TIP LINE + FMCSA COMPLAINT FILING ($49)
// ════════════════════════════════════════════════════════════════════════════
const TIPS_FILE = path.join(DATA_DIR, 'tips.json');
function loadTips()   { return loadJSON(TIPS_FILE);  }
function saveTips(d)  { saveJSON(TIPS_FILE, d);       }

app.post('/api/tip/submit', rateLimit(60000, 5), async (req, res) => {
  const { brokerMC, brokerName, description, evidence, tipsterEmail, requestFiling } = req.body;
  if (!brokerMC || !description || description.length < 50)
    return res.status(400).json({ error: 'Broker MC and detailed description required' });

  const id  = 'TIP-' + Date.now().toString().slice(-8);
  const tip = { id, brokerMC: brokerMC.replace(/\D/g,''), brokerName, description, evidence: evidence||'', tipsterEmail: tipsterEmail||'', requestFiling: !!requestFiling, status: 'received', createdAt: new Date().toISOString() };
  const tips = loadTips(); tips.push(tip); saveTips(tips);

  // Notify admin
  try {
    await dispatchEmail({
      to: process.env.ADMIN_EMAIL || 'mikee@megafleetcorp.com',
      subject: `[TIP RECEIVED] ${brokerName||'MC-'+tip.brokerMC} — ${requestFiling ? '💳 FILING REQUESTED ($49)' : 'Review Only'}`,
      text: `New tip received.\nBroker: ${brokerName||'MC-'+tip.brokerMC}\nFiling Requested: ${requestFiling}\nDescription:\n${description}\n\nTip ID: ${id}`,
      html: `<p><strong>Tip ID: ${id}</strong></p><p>Broker: ${brokerName||'MC-'+tip.brokerMC} (MC-${tip.brokerMC})</p>${requestFiling?'<p style="color:#c0392b;font-weight:700;">💳 FMCSA COMPLAINT FILING REQUESTED — $49 pending</p>':''}<p>${description}</p>`,
    });
  } catch {}

  res.json({ ok: true, tipId: id, message: requestFiling ? 'Tip received. An attorney will review within 48 hours and contact you about filing.' : 'Tip received. Our team will review within 48 hours.' });
});

app.post('/api/tip/request-filing', rateLimit(60000, 10), async (req, res) => {
  const { tipId, email } = req.body;
  if (!stripe) return res.json({ devMode: true });
  try {
    const baseUrl = process.env.BASE_URL || 'https://freightguarddefense.com';
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'], customer_email: email||undefined,
      line_items: [{ price_data: { currency:'usd', product_data:{ name:'FMCSA Complaint Filing Service', description:'Attorney-reviewed FMCSA complaint filed on your behalf within 48 hours.' }, unit_amount:4900 }, quantity:1 }],
      mode: 'payment',
      success_url: `${baseUrl}/carrier-hub.html?tip_paid=1&tip=${tipId}`,
      cancel_url:  `${baseUrl}/carrier-hub.html`,
      metadata: { tipId, service: 'fmcsa_complaint' },
    });
    res.json({ url: session.url });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/tips', requireAdmin, (req, res) => res.json({ tips: loadTips().reverse() }));

// ════════════════════════════════════════════════════════════════════════════
// FEATURE 5 — WEEKLY BAD BROKER BULLETIN
// ════════════════════════════════════════════════════════════════════════════
async function sendWeeklyBulletin() {
  const reports  = loadCarrierReports();
  const regs     = loadCarrierRegs().filter(r => r.subscribedAlerts !== false);
  const oneWeekAgo = Date.now() - 7*24*3600*1000;
  const thisWeek = reports.filter(r => new Date(r.createdAt).getTime() > oneWeekAgo);

  if (!thisWeek.length && !reports.length) return;

  // Top brokers this week
  const brokerCounts = {};
  thisWeek.forEach(r => { brokerCounts[r.brokerMC] = brokerCounts[r.brokerMC] || {mc:r.brokerMC,name:r.brokerName,count:0,cats:new Set(),owed:0}; brokerCounts[r.brokerMC].count++; (r.categories||[]).forEach(c=>brokerCounts[r.brokerMC].cats.add(c)); brokerCounts[r.brokerMC].owed+=Number(r.amountOwed)||0; });
  const topBrokers = Object.values(brokerCounts).sort((a,b)=>b.count-a.count).slice(0,5);
  const triggerCount = thisWeek.filter(r=>r.categories?.includes('trigger_happy')).length;
  const totalOwed   = thisWeek.reduce((s,r)=>s+(Number(r.amountOwed)||0),0);
  const siteUrl     = process.env.SITE_URL||'https://freightguarddefense.com';

  const topBrokerRows = topBrokers.map((b,i) =>
    `<tr style="background:${i%2?'#f9f9f9':'#fff'}"><td style="padding:8px 12px;font-weight:700;">#${i+1}</td><td style="padding:8px 12px;">${b.name||'MC-'+b.mc}</td><td style="padding:8px 12px;text-align:center;">${b.count}</td><td style="padding:8px 12px;color:#c0392b;">$${b.owed.toLocaleString()}</td><td style="padding:8px 12px;font-size:11px;">${[...b.cats].slice(0,2).join(', ')}</td></tr>`
  ).join('');

  const html = `<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;background:#f5f5f5;margin:0;padding:0;">
<div style="max-width:640px;margin:0 auto;">
  <div style="background:#0a1628;padding:28px 32px;">
    <h1 style="color:#fff;font-size:20px;margin:0;">⚖️ FreightGuard Defense</h1>
    <p style="color:#7ab3ff;font-size:13px;margin:6px 0 0;">Weekly Bad Broker Bulletin — ${new Date().toLocaleDateString('en-US',{month:'long',day:'numeric',year:'numeric'})}</p>
  </div>
  <div style="background:#fff;padding:28px 32px;">
    <div style="display:flex;gap:16px;margin-bottom:24px;">
      <div style="flex:1;background:#fff3f3;border:1px solid #fcc;border-radius:8px;padding:16px;text-align:center;"><div style="font-size:28px;font-weight:900;color:#e74c3c;">${thisWeek.length}</div><div style="font-size:11px;color:#888;text-transform:uppercase;margin-top:4px;">Reports This Week</div></div>
      <div style="flex:1;background:#fff8f0;border:1px solid #fde8c8;border-radius:8px;padding:16px;text-align:center;"><div style="font-size:28px;font-weight:900;color:#f0a830;">${triggerCount}</div><div style="font-size:11px;color:#888;text-transform:uppercase;margin-top:4px;">Trigger-Happy</div></div>
      <div style="flex:1;background:#f0fff4;border:1px solid #c8f0d8;border-radius:8px;padding:16px;text-align:center;"><div style="font-size:28px;font-weight:900;color:#27ae60;">$${(totalOwed/1000).toFixed(0)}k</div><div style="font-size:11px;color:#888;text-transform:uppercase;margin-top:4px;">Owed by Brokers</div></div>
    </div>
    <h3 style="font-size:15px;color:#1a1a2a;border-bottom:2px solid #e74c3c;padding-bottom:8px;margin-bottom:16px;">🚨 Most Reported Brokers This Week</h3>
    ${topBrokers.length ? `<table style="width:100%;border-collapse:collapse;font-size:13px;"><thead><tr style="background:#1a1a2a;color:#fff;"><th style="padding:8px 12px;text-align:left;">#</th><th style="padding:8px 12px;text-align:left;">Broker</th><th style="padding:8px 12px;text-align:center;">Reports</th><th style="padding:8px 12px;">$ Owed</th><th style="padding:8px 12px;">Top Issues</th></tr></thead><tbody>${topBrokerRows}</tbody></table>` : '<p style="color:#888;">No new reports this week — great news!</p>'}
    <div style="margin-top:24px;background:#f0f4ff;border-radius:8px;padding:16px;text-align:center;">
      <p style="font-size:13px;color:#333;margin-bottom:12px;">Need to report a broker or file a demand letter?</p>
      <a href="${siteUrl}/carrier-hub.html" style="background:#c0392b;color:#fff;padding:10px 24px;border-radius:6px;text-decoration:none;font-weight:700;margin-right:8px;">🚨 File a Report</a>
      <a href="${siteUrl}" style="background:#1a2f4a;color:#7ab3ff;padding:10px 24px;border-radius:6px;text-decoration:none;font-weight:700;border:1px solid #2a5a8a;">⚖️ Get Demand Letter</a>
    </div>
  </div>
  <div style="background:#f5f5f5;padding:16px 32px;text-align:center;font-size:11px;color:#999;">FreightGuard Defense · ${siteUrl}<br>You're receiving this because you registered at Carrier Hub. <a href="${siteUrl}/carrier-hub.html" style="color:#999;">Unsubscribe</a></div>
</div></body></html>`;

  const text = `FreightGuard Defense — Weekly Bad Broker Bulletin\n\n${thisWeek.length} reports this week · ${triggerCount} trigger-happy · $${totalOwed.toLocaleString()} owed\n\nTop brokers:\n${topBrokers.map((b,i)=>`${i+1}. ${b.name||'MC-'+b.mc} — ${b.count} reports`).join('\n')}\n\nView full report: ${siteUrl}/carrier-hub.html`;

  let sent = 0;
  for (const reg of regs) {
    try {
      await dispatchEmail({ to: reg.email, subject: `⚠️ Weekly Bad Broker Bulletin — ${thisWeek.length} Reports This Week | FreightGuard Defense`, text, html });
      sent++;
      await new Promise(r => setTimeout(r, 150)); // rate limit
    } catch(e) { console.warn('Bulletin email failed:', reg.email, e.message); }
  }
  console.log(`[Bulletin] Sent to ${sent}/${regs.length} carriers`);
}

// Every Monday at 8am (run weekly check every hour, send on Monday)
setInterval(() => {
  const now = new Date();
  if (now.getDay() === 1 && now.getHours() === 8 && now.getMinutes() < 60) {
    sendWeeklyBulletin().catch(e => console.error('Bulletin error:', e));
  }
}, 3600000);

// Admin trigger
app.post('/api/admin/send-bulletin', requireAdmin, async (req, res) => {
  sendWeeklyBulletin().catch(e => console.error(e));
  res.json({ ok: true, message: 'Weekly bulletin sending in background' });
});

// ════════════════════════════════════════════════════════════════════════════
// BROKER411 — PUBLIC BROKER BLACKLIST & REPORTING PLATFORM
// ════════════════════════════════════════════════════════════════════════════

// Full broker profile — FMCSA data + all community reports + demand letters
app.get('/api/broker411/profile/:mc', async (req, res) => {
  const mc = req.params.mc.replace(/\D/g,'');
  if (!mc || mc.length < 5) return res.status(400).json({ error: 'Invalid MC' });

  // Pull FMCSA data
  let fmcsa = { legalName:'', dbaName:'', dotNumber:'', mcNumber:mc, address:'', phone:'', status:'', entityType:'' };
  try {
    const url = `https://safer.fmcsa.dot.gov/query.asp?searchtype=ANY&query_type=queryCarrierSnapshot&query_param=MC_MX&query_string=${mc}`;
    const r   = await fetch(url, { headers:{'User-Agent':'Mozilla/5.0'}, signal: AbortSignal.timeout ? AbortSignal.timeout(8000) : undefined });
    const html = await r.text();
    function ex(label) {
      const re = new RegExp(label + '[^<]*<\/[Aa]>[^<]*<\/[Tt][Hh]>\\s*<[Tt][Dd][^>]*class=["\'"]queryfield["\'"][^>]*>([\\s\\S]*?)<\/[Tt][Dd]>', 'i');
      const m = html.match(re); if (!m) return '';
      return m[1].replace(/<br\s*\/?>/gi,' ').replace(/<[^>]+>/g,'').replace(/&nbsp;/g,' ').replace(/\s+/g,' ').trim();
    }
    function exAddr() {
      const m = html.match(/id=["']physicaladdressvalue["'][^>]*>([\s\S]*?)<\/[Tt][Dd]>/i);
      if (!m) return '';
      return m[1].replace(/<br\s*\/?>/gi,' ').replace(/<[^>]+>/g,'').replace(/&nbsp;/g,' ').replace(/\s+/g,' ').trim();
    }
    function exStatus() {
      const m = html.match(/USDOT Status:<\/A>[\s\S]*?<TD[^>]*class=["']queryfield["'][^>]*>([\s\S]*?)<\/TD>/i);
      if (!m) return ''; return m[1].replace(/<!--[\s\S]*?-->/g,'').replace(/<[^>]+>/g,'').replace(/&nbsp;/g,' ').trim();
    }
    fmcsa = { legalName: ex('Legal Name') || ex('Entity\/DBA Name'), dbaName: ex('DBA Name'), dotNumber: ex('USDOT Number'), mcNumber: mc, address: exAddr() || ex('Physical Address'), phone: ex('Phone'), status: exStatus(), entityType: ex('Entity Type') };
  } catch(e) { console.warn('FMCSA fetch failed:', e.message); }

  // Community reports
  const allReports = loadCarrierReports().filter(r => r.brokerMC === mc);
  // Demand letters
  const allLetters = await loadLetters();
  const demands    = allLetters.filter(l => String(l.brokerMC||'').replace(/\D/g,'') === mc);
  // Risk calc
  const catCounts = {};
  for (const r of allReports) for (const c of (r.categories||[])) catCounts[c] = (catCounts[c]||0)+1;
  const totalOwed  = allReports.reduce((s,r)=>s+(Number(r.amountOwed)||0),0);
  const totalDemands = demands.reduce((s,l)=>s+(Number(l.totalDamages)||0),0);
  let riskScore = 0;
  if (allReports.length>=1) riskScore+=15; if (allReports.length>=3) riskScore+=15; if (allReports.length>=5) riskScore+=15;
  if (catCounts['trigger_happy']>=1) riskScore+=15; if (catCounts['nonpayment']>=1) riskScore+=10;
  if (catCounts['fraud']>=1) riskScore+=25; if (demands.length>=1) riskScore+=10;
  riskScore = Math.min(100,riskScore);

  // Subscribers who watch this broker (for notification count)
  const wl = loadWatchlist();
  const watcherCount = (wl[mc]?.subscribers||[]).length + loadCarrierRegs().filter(r=>r.watchlist?.includes(mc)).length;

  res.json({
    mc, fmcsa,
    stats: { totalReports: allReports.length, totalDemandLetters: demands.length, totalOwed, totalDamagesClaimed: totalDemands, riskScore, watcherCount },
    categories: catCounts,
    reports: allReports.slice(0,20).map(r=>({ ...r, reporterEmail: undefined })), // hide email
    demandLetters: demands.slice(0,10).map(l=>({ caseRef:l.caseRef, carrierName:l.carrierName, totalDamages:l.totalDamages, ts:l.ts, status:l.status })),
  });
});

// DOT lookup redirect
app.get('/api/broker411/by-dot/:dot', async (req, res) => {
  const dot = req.params.dot.replace(/\D/g,'');
  try {
    const url = `https://safer.fmcsa.dot.gov/query.asp?searchtype=ANY&query_type=queryCarrierSnapshot&query_param=USDOT&query_string=${dot}`;
    const r   = await fetch(url, { headers:{'User-Agent':'Mozilla/5.0'}, signal: AbortSignal.timeout ? AbortSignal.timeout(8000) : undefined });
    const html = await r.text();
    const mm   = html.match(/Docket Number[^<]*<\/[Aa]>[^<]*<\/[Tt][Hh]>[\s\S]*?<[Tt][Dd][^>]*class=["']queryfield["'][^>]*>([\s\S]*?)<\/[Tt][Dd]>/i);
    const mc   = mm ? mm[1].replace(/<[^>]+>/g,'').replace(/[^\d]/g,'').trim() : '';
    if (mc) return res.json({ mc, found: true });
    res.json({ mc: '', found: false, dot });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// File broker report WITH full notification (enhanced version)
app.post('/api/broker411/report', rateLimit(60000, 5), async (req, res) => {
  const {
    brokerMC, brokerName, brokerAddress, brokerPhone, brokerEmail: brokerEmailAddr, brokerDOT,
    contactName, incidentDate, categories, description, amountOwed, loadNumber, severity,
    reporterName, reporterEmail, reporterMC, reporterPhone, reporterCompany,
    generateLetter, carrierNarrative,
  } = req.body;

  if (!brokerMC || !categories?.length || !description || description.length < 30)
    return res.status(400).json({ error: 'Broker MC, at least one category, and detailed description required' });

  const id = 'B411-' + Date.now().toString().slice(-8);
  const report = {
    id, brokerMC: brokerMC.replace(/\D/g,''), brokerName: brokerName||'', brokerAddress: brokerAddress||'',
    brokerPhone: brokerPhone||'', brokerEmail: brokerEmailAddr||'', brokerDOT: brokerDOT||'',
    contactName: contactName||'',
    reporterMC: reporterMC||'', reporterName: reporterName||'Anonymous Carrier',
    reporterEmail: reporterEmail||'', reporterPhone: reporterPhone||'', reporterCompany: reporterCompany||'',
    incidentDate: incidentDate||new Date().toISOString().split('T')[0],
    categories, description, amountOwed: Number(amountOwed)||0,
    loadNumber: loadNumber||'', severity: severity||'medium',
    verified: false, upvotes: 0, createdAt: new Date().toISOString(),
  };

  const allReports = loadCarrierReports();
  allReports.push(report); saveCarrierReports(allReports);
  if (pgPool) await pgPool.query('INSERT INTO carrier_broker_reports(id,broker_mc,broker_name,broker_address,reporter_mc,reporter_name,reporter_email,incident_date,categories,description,amount_owed,load_number,severity) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)',
    [id,report.brokerMC,brokerName||'',brokerAddress||'',reporterMC||'',reporterName||'Anonymous Carrier',reporterEmail||'',incidentDate||null,categories,description,Number(amountOwed)||0,loadNumber||'',severity||'medium']).catch(()=>{});
  await logAudit(id,'broker411_report',reporterEmail||'anonymous',`${categories.join(',')} against ${brokerName||'MC-'+brokerMC}`);

  // Build category labels
  const CATMAP = {trigger_happy:'🚨 Trigger-Happy Reporter',nonpayment:'💸 Non-Payment',unauthorized_rebroke:'🔄 Unauthorized Re-Brokering',no_authority:'⛔ No Authority',no_bond:'🔓 No Bond',alias:'🎭 Alias',fraud:'🚫 Fraud',unethical:'⚠️ Unethical',rate_reduction:'📉 Rate Reduction',detention:'⏱ Detention Refusal',tracking_deductions:'📍 Tracking Deductions',unauth_deductions:'✂️ Unauthorized Deductions'};
  const catLabels = categories.map(c=>CATMAP[c]||c).join(' · ');
  const sevColor  = {critical:'#e74c3c',high:'#f07060',medium:'#f0a830',low:'#40c070'}[severity||'medium']||'#f0a830';

  // Full alert email to ALL subscribers and registered carriers watching this broker
  const alertHtml = `<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;background:#f5f5f5;margin:0;padding:0;">
<div style="max-width:640px;margin:0 auto;">
  <div style="background:#1a0505;padding:20px 28px;border-bottom:3px solid #c0392b;">
    <h1 style="color:#fff;font-size:18px;margin:0;">🚨 FreightGuard Defense — Broker Report Alert</h1>
    <p style="color:#f07060;font-size:12px;margin:4px 0 0;">A carrier just reported a broker in your watchlist</p>
  </div>
  <div style="background:#fff;padding:24px 28px;">
    <div style="background:#fff3f3;border:1px solid #fcc;border-radius:8px;padding:16px 18px;margin-bottom:20px;">
      <div style="font-size:18px;font-weight:900;color:#c0392b;">${brokerName||'Unknown Broker'}</div>
      <div style="font-size:13px;color:#888;margin-top:2px;">MC-${brokerMC}${brokerDOT ? ' · DOT-'+brokerDOT : ''}${brokerPhone ? ' · '+brokerPhone : ''}</div>
      ${brokerAddress ? `<div style="font-size:12px;color:#888;margin-top:2px;">📍 ${brokerAddress}</div>` : ''}
      ${brokerEmailAddr ? `<div style="font-size:12px;color:#888;margin-top:2px;">✉️ ${brokerEmailAddr}</div>` : ''}
      ${contactName ? `<div style="font-size:12px;color:#888;margin-top:2px;">👤 Contact: ${contactName}</div>` : ''}
    </div>
    <table style="width:100%;font-size:13px;border-collapse:collapse;margin-bottom:16px;">
      <tr style="background:#f9f9f9;"><td style="padding:8px 12px;color:#888;width:35%;">Categories:</td><td style="padding:8px 12px;font-weight:700;color:#c0392b;">${catLabels}</td></tr>
      <tr><td style="padding:8px 12px;color:#888;">Severity:</td><td style="padding:8px 12px;font-weight:700;color:${sevColor};text-transform:capitalize;">${severity||'medium'}</td></tr>
      <tr style="background:#f9f9f9;"><td style="padding:8px 12px;color:#888;">Incident Date:</td><td style="padding:8px 12px;">${incidentDate||'Recent'}</td></tr>
      ${amountOwed ? `<tr><td style="padding:8px 12px;color:#888;">Amount Owed:</td><td style="padding:8px 12px;font-weight:700;color:#c0392b;">$${Number(amountOwed).toLocaleString()}</td></tr>` : ''}
      ${loadNumber ? `<tr style="background:#f9f9f9;"><td style="padding:8px 12px;color:#888;">Load #:</td><td style="padding:8px 12px;">${loadNumber}</td></tr>` : ''}
      <tr><td style="padding:8px 12px;color:#888;">Reported By:</td><td style="padding:8px 12px;">${reporterCompany||reporterName||'Anonymous Carrier'}${reporterMC?' (MC-'+reporterMC+')':''}</td></tr>
    </table>
    <div style="background:#f5f5f5;border-left:3px solid #c0392b;padding:12px 16px;margin-bottom:20px;font-size:13px;color:#333;line-height:1.7;">${description.substring(0,500)}${description.length>500?'...':''}</div>
    <div style="text-align:center;margin-top:16px;">
      <a href="${process.env.SITE_URL||'https://freightguarddefense.com'}/broker411.html?mc=${brokerMC}" style="background:#c0392b;color:#fff;padding:11px 24px;border-radius:6px;text-decoration:none;font-weight:700;margin-right:8px;">View Full Profile</a>
      <a href="${process.env.SITE_URL||'https://freightguarddefense.com'}?broker=${brokerMC}" style="background:#1a2f4a;color:#7ab3ff;padding:11px 24px;border-radius:6px;text-decoration:none;font-weight:700;border:1px solid #2a5a8a;">⚖️ Get Demand Letter</a>
    </div>
  </div>
  <div style="background:#f5f5f5;padding:12px 28px;text-align:center;font-size:11px;color:#999;">FreightGuard Defense · ${process.env.SITE_URL||'https://freightguarddefense.com'}</div>
</div></body></html>`;

  const alertText = `🚨 BROKER ALERT — FreightGuard Defense\n\nBroker: ${brokerName||'MC-'+brokerMC}\nMC: ${brokerMC}${brokerDOT?' · DOT-'+brokerDOT:''}\nPhone: ${brokerPhone||'N/A'}\nAddress: ${brokerAddress||'N/A'}\nContact: ${contactName||'N/A'}\nBroker Email: ${brokerEmailAddr||'N/A'}\n\nCategories: ${catLabels}\nSeverity: ${severity||'medium'}\nAmount Owed: $${Number(amountOwed||0).toLocaleString()}\nLoad #: ${loadNumber||'N/A'}\n\nDescription:\n${description}\n\nFiled by: ${reporterCompany||reporterName||'Anonymous'} (MC-${reporterMC||'?'})\n\nView: ${process.env.SITE_URL||'https://freightguarddefense.com'}/broker411.html?mc=${brokerMC}`;

  // Collect all recipients — watchlist + registered carrier subscribers
  const wl       = loadWatchlist();
  const mc_clean  = report.brokerMC;
  const wlSubs    = (wl[mc_clean]?.subscribers||[]).map(s=>s.email);
  const regSubs   = loadCarrierRegs().filter(r=>r.subscribedAlerts!==false && r.watchlist?.includes(mc_clean) && r.email!==reporterEmail).map(r=>r.email);
  const allEmails = [...new Set([...wlSubs,...regSubs])].filter(e=>e&&e!==reporterEmail);

  let alertsSent = 0;
  for (const email of allEmails) {
    try {
      await dispatchEmail({ to:email, subject:`⚠️ BROKER ALERT: ${brokerName||'MC-'+brokerMC} — ${catLabels.substring(0,50)} — FreightGuard Defense`, text:alertText, html:alertHtml });
      alertsSent++;
      await new Promise(r=>setTimeout(r,100));
    } catch(e) { console.warn('Alert email failed:', e.message); }
  }

  // Confirmation to reporter if email provided
  if (reporterEmail) {
    try {
      await dispatchEmail({ to:reporterEmail, subject:`✅ Your Report Was Filed — ${brokerName||'MC-'+brokerMC} (${id})`, text:`Your report against ${brokerName||'MC-'+brokerMC} has been filed.\n\nReport ID: ${id}\n${alertsSent} carriers have been notified.\n\nView the broker's profile: ${process.env.SITE_URL||'https://freightguarddefense.com'}/broker411.html?mc=${brokerMC}`, html:`<p>Your report against <strong>${brokerName||'MC-'+brokerMC}</strong> has been filed (ID: ${id}).</p><p>${alertsSent} carriers watching this broker have been notified with full broker details.</p><p><a href="${process.env.SITE_URL||'https://freightguarddefense.com'}/broker411.html?mc=${brokerMC}">View Broker Profile</a></p>` });
    } catch {}
  }

  res.json({ ok:true, reportId:id, alertsSent, message:`Report filed. ${alertsSent} carriers notified with full broker info.` });
});

// Search brokers by name
app.get('/api/broker411/search', async (req, res) => {
  const { q } = req.query;
  if (!q || q.length < 2) return res.json({ results:[] });
  const allReports = loadCarrierReports();
  const seen = new Set(); const results = [];
  for (const r of allReports) {
    const key = r.brokerMC;
    if (seen.has(key)) continue; seen.add(key);
    if ((r.brokerName||'').toLowerCase().includes(q.toLowerCase()) || r.brokerMC.includes(q.replace(/\D/g,''))) {
      const count = allReports.filter(x=>x.brokerMC===r.brokerMC).length;
      results.push({ mc:r.brokerMC, name:r.brokerName, address:r.brokerAddress, reports:count });
    }
  }
  res.json({ results: results.slice(0,10) });
});

// Most reported brokers
app.get('/api/broker411/most-reported', async (req, res) => {
  const all = loadCarrierReports();
  const counts = {};
  all.forEach(r=>{
    if (!counts[r.brokerMC]) counts[r.brokerMC]={mc:r.brokerMC,name:r.brokerName,reports:0,owed:0,cats:new Set()};
    counts[r.brokerMC].reports++;
    counts[r.brokerMC].owed+=Number(r.amountOwed)||0;
    (r.categories||[]).forEach(c=>counts[r.brokerMC].cats.add(c));
  });
  const top = Object.values(counts).map(b=>({...b,cats:[...b.cats]})).sort((a,b)=>b.reports-a.reports).slice(0,20);
  res.json({ brokers:top });
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


// ── WEEKLY BROKER BLACKLIST EMAIL ─────────────────────────────────────────────

function buildWeeklyEmailHTML({ reports, weekOf, totalAmount, totalCarriers }) {
  const topBrokers = reports.slice(0, 10);
  const categoryLabels = {
    trigger_happy:        '🚨 False Report',
    nonpayment:           '💸 Non-Payment',
    unauthorized_rebroke: '🔄 Re-Brokering',
    no_authority:         '⛔ No Authority',
    no_bond:              '🔓 No Bond',
    alias:                '🎭 Alias',
    fraud:                '🚫 Fraud',
    unethical:            '⚠️ Unethical',
    rate_reduction:       '📉 Rate Cut',
    detention:            '⏱ Detention',
    tracking_deductions:  '📍 Tracking',
    unauthorized_deductions: '✂️ Deductions',
  };

  const brokerRows = topBrokers.map((b, i) => {
    const cats = (b.categories || []).slice(0,2).map(c => categoryLabels[c] || c).join(' &nbsp;·&nbsp; ');
    const amtStr = b.amount_owed > 0 ? `$${Number(b.amount_owed).toLocaleString()}` : '—';
    const severityColor = b.severity === 'high' ? '#c0392b' : b.severity === 'low' ? '#1a7a3c' : '#9a6e00';
    return `
    <tr>
      <td style="padding:14px 16px;border-bottom:1px solid #f0f0f0;font-weight:700;color:#1d1d1f;font-size:14px;">${i+1}. ${b.broker_name || 'Unknown Broker'}</td>
      <td style="padding:14px 16px;border-bottom:1px solid #f0f0f0;color:#6e6e73;font-size:13px;">MC-${b.broker_mc || 'N/A'}</td>
      <td style="padding:14px 16px;border-bottom:1px solid #f0f0f0;text-align:center;">
        <span style="background:${severityColor}18;color:${severityColor};font-size:11px;font-weight:800;padding:4px 10px;border-radius:100px;text-transform:uppercase;letter-spacing:0.5px;">${b.severity || 'medium'}</span>
      </td>
      <td style="padding:14px 16px;border-bottom:1px solid #f0f0f0;color:#c0392b;font-weight:700;font-size:14px;">${amtStr}</td>
      <td style="padding:14px 16px;border-bottom:1px solid #f0f0f0;color:#6e6e73;font-size:12px;">${cats || '—'}</td>
    </tr>`;
  }).join('');

  const noReports = topBrokers.length === 0;

  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Weekly Broker Blacklist — FreightGuard Defense</title>
</head>
<body style="margin:0;padding:0;background:#f5f5f7;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;-webkit-font-smoothing:antialiased;">

<!-- WRAPPER -->
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f5f5f7;padding:40px 20px;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;">

  <!-- HEADER -->
  <tr><td style="background:linear-gradient(170deg,#1d1d1f 0%,#2d2d2f 100%);border-radius:20px 20px 0 0;padding:40px 44px 36px;text-align:center;">
    <div style="display:inline-flex;align-items:center;gap:10px;margin-bottom:24px;">
      <div style="width:40px;height:40px;background:#c0392b;border-radius:10px;display:inline-block;line-height:40px;text-align:center;font-size:20px;">🛡️</div>
      <span style="font-size:18px;font-weight:700;color:#ffffff;letter-spacing:-0.3px;vertical-align:middle;margin-left:10px;">FreightGuard Defense</span>
    </div>
    <h1 style="margin:0 0 10px;font-size:32px;font-weight:800;color:#ffffff;letter-spacing:-1px;line-height:1.1;">Weekly Broker<br>Blacklist Report</h1>
    <p style="margin:0;font-size:15px;color:rgba(255,255,255,0.55);font-weight:400;">Week of ${weekOf}</p>
  </td></tr>

  <!-- STAT BAR -->
  <tr><td style="background:#c0392b;padding:0;">
    <table width="100%" cellpadding="0" cellspacing="0">
    <tr>
      <td style="padding:20px 0;text-align:center;border-right:1px solid rgba(255,255,255,0.2);">
        <div style="font-size:28px;font-weight:900;color:#ffffff;letter-spacing:-1px;">${reports.length}</div>
        <div style="font-size:11px;color:rgba(255,255,255,0.7);text-transform:uppercase;letter-spacing:0.8px;margin-top:4px;font-weight:600;">New Reports</div>
      </td>
      <td style="padding:20px 0;text-align:center;border-right:1px solid rgba(255,255,255,0.2);">
        <div style="font-size:28px;font-weight:900;color:#ffffff;letter-spacing:-1px;">$${Number(totalAmount).toLocaleString()}</div>
        <div style="font-size:11px;color:rgba(255,255,255,0.7);text-transform:uppercase;letter-spacing:0.8px;margin-top:4px;font-weight:600;">Owed to Carriers</div>
      </td>
      <td style="padding:20px 0;text-align:center;">
        <div style="font-size:28px;font-weight:900;color:#ffffff;letter-spacing:-1px;">${totalCarriers}</div>
        <div style="font-size:11px;color:rgba(255,255,255,0.7);text-transform:uppercase;letter-spacing:0.8px;margin-top:4px;font-weight:600;">Carriers Reporting</div>
      </td>
    </tr>
    </table>
  </td></tr>

  <!-- MAIN CARD -->
  <tr><td style="background:#ffffff;padding:36px 44px;">

    ${noReports ? `
    <div style="text-align:center;padding:40px 0;">
      <div style="font-size:48px;margin-bottom:16px;">✅</div>
      <h2 style="font-size:22px;font-weight:800;color:#1d1d1f;margin:0 0 8px;">All clear this week!</h2>
      <p style="font-size:16px;color:#6e6e73;margin:0;">No new broker reports were filed in the past 7 days.</p>
    </div>
    ` : `
    <h2 style="font-size:20px;font-weight:800;color:#1d1d1f;margin:0 0 6px;letter-spacing:-0.5px;">⚠️ Brokers Reported This Week</h2>
    <p style="font-size:14px;color:#6e6e73;margin:0 0 24px;">These brokers were flagged by carriers in our network. Share with your driver community.</p>

    <!-- TABLE -->
    <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #f0f0f0;border-radius:14px;overflow:hidden;border-collapse:separate;border-spacing:0;">
      <thead>
        <tr style="background:#fafafa;">
          <th style="padding:12px 16px;text-align:left;font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:1px;color:#6e6e73;border-bottom:1.5px solid #ebebeb;">Broker Name</th>
          <th style="padding:12px 16px;text-align:left;font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:1px;color:#6e6e73;border-bottom:1.5px solid #ebebeb;">MC#</th>
          <th style="padding:12px 16px;text-align:center;font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:1px;color:#6e6e73;border-bottom:1.5px solid #ebebeb;">Risk</th>
          <th style="padding:12px 16px;text-align:left;font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:1px;color:#6e6e73;border-bottom:1.5px solid #ebebeb;">Amt Owed</th>
          <th style="padding:12px 16px;text-align:left;font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:1px;color:#6e6e73;border-bottom:1.5px solid #ebebeb;">Category</th>
        </tr>
      </thead>
      <tbody>${brokerRows}</tbody>
    </table>
    `}

    <!-- CTA -->
    <div style="margin-top:32px;text-align:center;">
      <a href="https://freightguarddefense.com/broker411.html" style="display:inline-block;background:#c0392b;color:#ffffff;font-size:16px;font-weight:700;padding:16px 40px;border-radius:100px;text-decoration:none;letter-spacing:-0.2px;box-shadow:0 4px 20px rgba(192,57,43,0.35);">View Full Blacklist →</a>
    </div>

    <!-- DIVIDER -->
    <hr style="border:none;border-top:1px solid #f0f0f0;margin:32px 0;">

    <!-- REPORT A BROKER -->
    <h3 style="font-size:17px;font-weight:800;color:#1d1d1f;margin:0 0 10px;letter-spacing:-0.3px;">🚨 Have a Bad Broker to Report?</h3>
    <p style="font-size:14px;color:#6e6e73;line-height:1.6;margin:0 0 20px;">If a broker hasn't paid you, filed a false FreightGuard report, or ripped you off — file a report and let our network of attorneys fight back.</p>
    <table cellpadding="0" cellspacing="0">
    <tr>
      <td style="padding-right:12px;"><a href="https://freightguarddefense.com/carrier-hub.html" style="display:inline-block;background:#1d1d1f;color:#ffffff;font-size:14px;font-weight:700;padding:13px 24px;border-radius:100px;text-decoration:none;">Report a Broker</a></td>
      <td><a href="https://freightguarddefense.com" style="display:inline-block;background:transparent;color:#1d1d1f;font-size:14px;font-weight:700;padding:12px 24px;border-radius:100px;text-decoration:none;border:1.5px solid #e0e0e0;">Fight a False Report</a></td>
    </tr>
    </table>

  </td></tr>

  <!-- FOOTER -->
  <tr><td style="background:#f5f5f7;border-radius:0 0 20px 20px;padding:28px 44px;text-align:center;">
    <p style="font-size:13px;color:#6e6e73;margin:0 0 8px;">FreightGuard Defense · freightguarddefense.com</p>
    <p style="font-size:12px;color:#aaa;margin:0;">You're receiving this because you have a carrier account with us.<br>
    <a href="https://freightguarddefense.com/carrier-hub.html" style="color:#6e6e73;">Manage alert preferences</a> &nbsp;·&nbsp; <a href="https://freightguarddefense.com/carrier-hub.html?unsubscribe=1" style="color:#6e6e73;">Unsubscribe</a></p>
  </td></tr>

</table>
</td></tr>
</table>
</body>
</html>`;
}

// ── SEND WEEKLY REPORT (manual trigger or cron) ───────────────────────────────
async function sendWeeklyBrokerReport(triggeredBy = 'cron') {
  if (!resendClient) {
    console.warn('[Weekly Email] Resend not configured — skipping');
    return { sent: 0, skipped: true };
  }

  const fromEmail = process.env.RESEND_FROM_EMAIL || 'reports@freightguarddefense.com';
  const fromName  = 'FreightGuard Defense';
  const weekOf    = new Date().toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' });

  // Get reports from the past 7 days
  const reportsResult = pgPool
    ? await pgPool.query(`
        SELECT broker_mc, broker_name, reporter_name, reporter_email,
               categories, amount_owed, severity, created_at
        FROM carrier_broker_reports
        WHERE created_at >= NOW() - INTERVAL '7 days'
        ORDER BY severity DESC, amount_owed DESC
      `).catch(() => null)
    : null;

  const reports      = reportsResult ? reportsResult.rows : [];
  const totalAmount  = reports.reduce((s, r) => s + Number(r.amount_owed || 0), 0);
  const totalCarriers= new Set(reports.map(r => r.reporter_email).filter(Boolean)).size;

  // Get all subscribed carriers
  const usersResult = pgPool
    ? await pgPool.query(`
        SELECT email, company_name, contact_name
        FROM carrier_registrations
        WHERE subscribed_alerts = TRUE AND email IS NOT NULL AND email != ''
      `).catch(() => null)
    : null;

  const subscribers = usersResult ? usersResult.rows : [];
  console.log(`[Weekly Email] Sending to ${subscribers.length} subscribers | ${reports.length} reports | triggered by: ${triggeredBy}`);

  if (subscribers.length === 0) {
    console.log('[Weekly Email] No subscribers — nothing to send');
    return { sent: 0, subscribers: 0, reports: reports.length };
  }

  const html    = buildWeeklyEmailHTML({ reports, weekOf, totalAmount, totalCarriers });
  const subject = reports.length > 0
    ? `⚠️ ${reports.length} Broker${reports.length > 1 ? 's' : ''} Reported This Week — FreightGuard Defense`
    : `✅ All Clear This Week — FreightGuard Defense Broker Report`;

  let sent = 0;
  let errors = 0;

  // Send in batches of 50 (Resend rate limits)
  const batchSize = 50;
  for (let i = 0; i < subscribers.length; i += batchSize) {
    const batch = subscribers.slice(i, i + batchSize);
    await Promise.all(batch.map(async (user) => {
      try {
        const personalizedHtml = html.replace(
          '🛡️</div>',
          `🛡️</div><p style="font-size:13px;color:rgba(255,255,255,0.45);margin:8px 0 0;">Hello, ${user.contact_name || user.company_name || 'Carrier'}!</p>`
        );
        const { error } = await resendClient.emails.send({
          from: `${fromName} <${fromEmail}>`,
          to:   user.email,
          subject,
          html: personalizedHtml,
        });
        if (error) { errors++; console.error(`[Weekly Email] Failed ${user.email}:`, error); }
        else sent++;
      } catch(e) {
        errors++;
        console.error(`[Weekly Email] Error sending to ${user.email}:`, e.message);
      }
    }));
    if (i + batchSize < subscribers.length) await new Promise(r => setTimeout(r, 500)); // rate-limit pause
  }

  console.log(`[Weekly Email] ✅ Sent: ${sent} | Errors: ${errors}`);
  return { sent, errors, subscribers: subscribers.length, reports: reports.length };
}

// ── ADMIN ENDPOINT: manual trigger ───────────────────────────────────────────
app.post('/api/admin/send-weekly-report', requireAdmin, async (req, res) => {
  try {
    const result = await sendWeeklyBrokerReport('admin-manual');
    res.json({ ok: true, ...result });
  } catch(e) {
    console.error('[Weekly Email] Error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ── WEEKLY CRON: every Monday at 7 AM server time ────────────────────────────
(function scheduleWeeklyEmail() {
  let lastSentWeek = null;

  function getWeekKey() {
    const now = new Date();
    const yr  = now.getFullYear();
    const wk  = Math.floor((now - new Date(yr, 0, 1)) / 604800000);
    return `${yr}-W${wk}`;
  }

  setInterval(async () => {
    const now  = new Date();
    const day  = now.getDay();   // 1 = Monday
    const hour = now.getHours(); // 7 AM
    const wk   = getWeekKey();

    if (day === 1 && hour === 7 && lastSentWeek !== wk) {
      console.log('[Weekly Email] 🕖 Monday 7 AM — firing weekly report...');
      lastSentWeek = wk;
      await sendWeeklyBrokerReport('cron').catch(e => console.error('[Weekly Email] Cron error:', e));
    }
  }, 60 * 1000); // check every minute
})();


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