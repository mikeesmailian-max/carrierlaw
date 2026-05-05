require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');
const Anthropic = require('@anthropic-ai/sdk');
const Stripe = require('stripe');

const app = express();
const PORT = process.env.PORT || 3000;
const stripe = process.env.STRIPE_SECRET_KEY ? Stripe(process.env.STRIPE_SECRET_KEY) : null;

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

// ── SECURITY HEADERS ──────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// ── SIMPLE RATE LIMITER (no extra packages) ───────────────────
const _rateCounts = new Map();
function rateLimit(windowMs, max) {
  return (req, res, next) => {
    const key = req.ip + req.path;
    const now = Date.now();
    const entry = _rateCounts.get(key) || { count: 0, reset: now + windowMs };
    if (now > entry.reset) { entry.count = 0; entry.reset = now + windowMs; }
    entry.count++;
    _rateCounts.set(key, entry);
    if (entry.count > max) {
      return res.status(429).json({ error: 'Too many requests. Please wait a moment and try again.' });
    }
    next();
  };
}
// Clear rate map every 10 minutes to prevent memory leak
setInterval(() => _rateCounts.clear(), 600000);

// ── HEALTH CHECK ──────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    uptime: Math.floor(process.uptime()),
    anthropic: !!process.env.ANTHROPIC_API_KEY,
    stripe:    !!process.env.STRIPE_SECRET_KEY,
    email:     !!process.env.SMTP_USER,
    ts: new Date().toISOString(),
  });
});

// ── DATA FILES ────────────────────────────────────────────────
const DATA_DIR     = path.join(__dirname, 'data');
const ATTORNEYS_FILE = path.join(DATA_DIR, 'attorneys.json');
const REPORTS_FILE   = path.join(DATA_DIR, 'broker-reports.json');
const FOLLOWUPS_FILE = path.join(DATA_DIR, 'followups.json');

if (!fs.existsSync(DATA_DIR))    fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(ATTORNEYS_FILE)) fs.writeFileSync(ATTORNEYS_FILE, '[]');
if (!fs.existsSync(REPORTS_FILE))   fs.writeFileSync(REPORTS_FILE, '[]');
if (!fs.existsSync(FOLLOWUPS_FILE)) fs.writeFileSync(FOLLOWUPS_FILE, '[]');

function loadAttorneys() {
  try { return JSON.parse(fs.readFileSync(ATTORNEYS_FILE, 'utf8')); }
  catch { return []; }
}

function saveAttorneys(data) {
  fs.writeFileSync(ATTORNEYS_FILE, JSON.stringify(data, null, 2));
}

// ── CASE REFERENCE & BROKER REPORT HELPERS ───────────────────
function generateCaseRef() {
  const year = new Date().getFullYear();
  const seq  = String(Date.now()).slice(-5);
  return `FGD-${year}-${seq}`;
}

function loadReports() {
  try { return JSON.parse(fs.readFileSync(REPORTS_FILE, 'utf8')); }
  catch { return []; }
}
function recordBrokerReport(brokerMC, brokerName, carrierName, caseRef) {
  const reports = loadReports();
  reports.push({ brokerMC: String(brokerMC).trim(), brokerName, carrierName, caseRef, ts: new Date().toISOString() });
  fs.writeFileSync(REPORTS_FILE, JSON.stringify(reports, null, 2));
}

function loadFollowups() {
  try { return JSON.parse(fs.readFileSync(FOLLOWUPS_FILE, 'utf8')); }
  catch { return []; }
}
function saveFollowups(data) {
  fs.writeFileSync(FOLLOWUPS_FILE, JSON.stringify(data, null, 2));
}

// ── FEDERAL COURT LOCATOR ─────────────────────────────────────
const FEDERAL_COURTS = {
  AL: { name: 'U.S. District Court, Northern District of Alabama', address: '1729 5th Ave N', city: 'Birmingham', state: 'AL', zip: '35203', dept: 'Civil Division, Room 140', phone: '(205) 278-1700' },
  AK: { name: 'U.S. District Court, District of Alaska', address: '222 W 7th Ave', city: 'Anchorage', state: 'AK', zip: '99513', dept: 'Civil Filing Office, Room 4', phone: '(907) 677-6100' },
  AZ: { name: 'U.S. District Court, District of Arizona', address: '401 W Washington St', city: 'Phoenix', state: 'AZ', zip: '85003', dept: 'Civil Division, Suite 130', phone: '(602) 322-7200' },
  AR: { name: 'U.S. District Court, Eastern District of Arkansas', address: '600 W Capitol Ave', city: 'Little Rock', state: 'AR', zip: '72201', dept: 'Civil Clerk\'s Office, Room A149', phone: '(501) 604-5351' },
  CA: { name: 'U.S. District Court, Central District of California', address: '350 W 1st St', city: 'Los Angeles', state: 'CA', zip: '90012', dept: 'Civil Division, Suite 4311', phone: '(213) 894-1565' },
  CO: { name: 'U.S. District Court, District of Colorado', address: '901 19th St', city: 'Denver', state: 'CO', zip: '80294', dept: 'Civil Clerk\'s Office, Room A105', phone: '(303) 844-3433' },
  CT: { name: 'U.S. District Court, District of Connecticut', address: '141 Church St', city: 'New Haven', state: 'CT', zip: '06510', dept: 'Civil Division, Room 107', phone: '(203) 773-2140' },
  DE: { name: 'U.S. District Court, District of Delaware', address: '844 N King St', city: 'Wilmington', state: 'DE', zip: '19801', dept: 'Civil Clerk\'s Office, Unit 18', phone: '(302) 573-6170' },
  FL: { name: 'U.S. District Court, Middle District of Florida', address: '801 N Florida Ave', city: 'Tampa', state: 'FL', zip: '33602', dept: 'Civil Division, Suite 500', phone: '(813) 301-5400' },
  GA: { name: 'U.S. District Court, Northern District of Georgia', address: '75 Ted Turner Dr SW', city: 'Atlanta', state: 'GA', zip: '30303', dept: 'Civil Clerk\'s Office, Room 2211', phone: '(404) 215-1600' },
  HI: { name: 'U.S. District Court, District of Hawaii', address: '300 Ala Moana Blvd', city: 'Honolulu', state: 'HI', zip: '96850', dept: 'Civil Division, Room C338', phone: '(808) 541-1300' },
  ID: { name: 'U.S. District Court, District of Idaho', address: '550 W Fort St', city: 'Boise', state: 'ID', zip: '83724', dept: 'Civil Clerk\'s Office, Room 400', phone: '(208) 334-1361' },
  IL: { name: 'U.S. District Court, Northern District of Illinois', address: '219 S Dearborn St', city: 'Chicago', state: 'IL', zip: '60604', dept: 'Civil Division, Room 2050', phone: '(312) 435-5670' },
  IN: { name: 'U.S. District Court, Southern District of Indiana', address: '46 E Ohio St', city: 'Indianapolis', state: 'IN', zip: '46204', dept: 'Civil Clerk\'s Office, Room 105', phone: '(317) 229-3700' },
  IA: { name: 'U.S. District Court, Southern District of Iowa', address: '123 E Walnut St', city: 'Des Moines', state: 'IA', zip: '50309', dept: 'Civil Division, Suite 300', phone: '(515) 284-6248' },
  KS: { name: 'U.S. District Court, District of Kansas', address: '500 State Ave', city: 'Kansas City', state: 'KS', zip: '66101', dept: 'Civil Clerk\'s Office, Suite 259', phone: '(913) 735-2200' },
  KY: { name: 'U.S. District Court, Eastern District of Kentucky', address: '101 Barr St', city: 'Lexington', state: 'KY', zip: '40507', dept: 'Civil Division, Suite 201', phone: '(859) 233-2503' },
  LA: { name: 'U.S. District Court, Eastern District of Louisiana', address: '500 Poydras St', city: 'New Orleans', state: 'LA', zip: '70130', dept: 'Civil Clerk\'s Office, Room C151', phone: '(504) 589-7650' },
  ME: { name: 'U.S. District Court, District of Maine', address: '156 Federal St', city: 'Portland', state: 'ME', zip: '04101', dept: 'Civil Division, Room 311', phone: '(207) 780-3356' },
  MD: { name: 'U.S. District Court, District of Maryland', address: '101 W Lombard St', city: 'Baltimore', state: 'MD', zip: '21201', dept: 'Civil Clerk\'s Office, Room 4415', phone: '(410) 962-2600' },
  MA: { name: 'U.S. District Court, District of Massachusetts', address: '1 Courthouse Way', city: 'Boston', state: 'MA', zip: '02210', dept: 'Civil Division, Suite 2300', phone: '(617) 748-9152' },
  MI: { name: 'U.S. District Court, Eastern District of Michigan', address: '231 W Lafayette Blvd', city: 'Detroit', state: 'MI', zip: '48226', dept: 'Civil Clerk\'s Office, Room 564', phone: '(313) 234-5005' },
  MN: { name: 'U.S. District Court, District of Minnesota', address: '300 S 4th St', city: 'Minneapolis', state: 'MN', zip: '55415', dept: 'Civil Division, Suite 202', phone: '(612) 664-5000' },
  MS: { name: 'U.S. District Court, Southern District of Mississippi', address: '501 E Court St', city: 'Jackson', state: 'MS', zip: '39201', dept: 'Civil Clerk\'s Office, Suite 2.500', phone: '(601) 608-4000' },
  MO: { name: 'U.S. District Court, Eastern District of Missouri', address: '111 S 10th St', city: 'St. Louis', state: 'MO', zip: '63102', dept: 'Civil Division, Suite 3.300', phone: '(314) 244-7900' },
  MT: { name: 'U.S. District Court, District of Montana', address: '2601 2nd Ave N', city: 'Billings', state: 'MT', zip: '59101', dept: 'Civil Clerk\'s Office, Room 5405', phone: '(406) 247-7000' },
  NE: { name: 'U.S. District Court, District of Nebraska', address: '111 S 18th Plaza', city: 'Omaha', state: 'NE', zip: '68102', dept: 'Civil Division, Suite 1152', phone: '(402) 661-7350' },
  NV: { name: 'U.S. District Court, District of Nevada', address: '333 Las Vegas Blvd S', city: 'Las Vegas', state: 'NV', zip: '89101', dept: 'Civil Clerk\'s Office, Room 1334', phone: '(702) 464-5400' },
  NH: { name: 'U.S. District Court, District of New Hampshire', address: '55 Pleasant St', city: 'Concord', state: 'NH', zip: '03301', dept: 'Civil Division, Room 110', phone: '(603) 225-1423' },
  NJ: { name: 'U.S. District Court, District of New Jersey', address: '402 E State St', city: 'Trenton', state: 'NJ', zip: '08608', dept: 'Civil Clerk\'s Office, Room 2020', phone: '(609) 989-2065' },
  NM: { name: 'U.S. District Court, District of New Mexico', address: '333 Lomas Blvd NW', city: 'Albuquerque', state: 'NM', zip: '87102', dept: 'Civil Division, Suite 270', phone: '(505) 348-2000' },
  NY: { name: 'U.S. District Court, Southern District of New York', address: '500 Pearl St', city: 'New York', state: 'NY', zip: '10007', dept: 'Civil Clerk\'s Office, Room 120', phone: '(212) 805-0136' },
  NC: { name: 'U.S. District Court, Middle District of North Carolina', address: '324 W Market St', city: 'Greensboro', state: 'NC', zip: '27401', dept: 'Civil Division, Room 202', phone: '(336) 332-6000' },
  ND: { name: 'U.S. District Court, District of North Dakota', address: '220 E Rosser Ave', city: 'Bismarck', state: 'ND', zip: '58501', dept: 'Civil Clerk\'s Office, Room 476', phone: '(701) 530-2300' },
  OH: { name: 'U.S. District Court, Southern District of Ohio', address: '85 Marconi Blvd', city: 'Columbus', state: 'OH', zip: '43215', dept: 'Civil Division, Room 121', phone: '(614) 719-3000' },
  OK: { name: 'U.S. District Court, Western District of Oklahoma', address: '200 NW 4th St', city: 'Oklahoma City', state: 'OK', zip: '73102', dept: 'Civil Clerk\'s Office, Room 1210', phone: '(405) 609-5000' },
  OR: { name: 'U.S. District Court, District of Oregon', address: '1000 SW 3rd Ave', city: 'Portland', state: 'OR', zip: '97204', dept: 'Civil Division, Suite 740', phone: '(503) 326-8000' },
  PA: { name: 'U.S. District Court, Eastern District of Pennsylvania', address: '601 Market St', city: 'Philadelphia', state: 'PA', zip: '19106', dept: 'Civil Clerk\'s Office, Room 2609', phone: '(215) 597-7704' },
  RI: { name: 'U.S. District Court, District of Rhode Island', address: '1 Exchange Terrace', city: 'Providence', state: 'RI', zip: '02903', dept: 'Civil Division, Room 302', phone: '(401) 752-7200' },
  SC: { name: 'U.S. District Court, District of South Carolina', address: '901 Richland St', city: 'Columbia', state: 'SC', zip: '29201', dept: 'Civil Clerk\'s Office, Room 2500', phone: '(803) 765-5816' },
  SD: { name: 'U.S. District Court, District of South Dakota', address: '225 S Pierre St', city: 'Pierre', state: 'SD', zip: '57501', dept: 'Civil Division, Room 405', phone: '(605) 945-4600' },
  TN: { name: 'U.S. District Court, Middle District of Tennessee', address: '801 Broadway', city: 'Nashville', state: 'TN', zip: '37203', dept: 'Civil Clerk\'s Office, Room A800', phone: '(615) 736-5498' },
  TX: { name: 'U.S. District Court, Northern District of Texas', address: '1100 Commerce St', city: 'Dallas', state: 'TX', zip: '75242', dept: 'Civil Division, Room 1452', phone: '(214) 753-2200' },
  UT: { name: 'U.S. District Court, District of Utah', address: '351 S West Temple', city: 'Salt Lake City', state: 'UT', zip: '84101', dept: 'Civil Clerk\'s Office, Room 1.100', phone: '(801) 524-6100' },
  VT: { name: 'U.S. District Court, District of Vermont', address: '11 Elmwood Ave', city: 'Burlington', state: 'VT', zip: '05401', dept: 'Civil Division, Room 502', phone: '(802) 951-6301' },
  VA: { name: 'U.S. District Court, Eastern District of Virginia', address: '701 E Broad St', city: 'Richmond', state: 'VA', zip: '23219', dept: 'Civil Clerk\'s Office, Room 3000', phone: '(804) 916-2200' },
  WA: { name: 'U.S. District Court, Western District of Washington', address: '700 Stewart St', city: 'Seattle', state: 'WA', zip: '98101', dept: 'Civil Division, Suite 2310', phone: '(206) 370-8400' },
  WV: { name: 'U.S. District Court, Southern District of West Virginia', address: '300 Virginia St E', city: 'Charleston', state: 'WV', zip: '25301', dept: 'Civil Clerk\'s Office, Room 2303', phone: '(304) 529-5588' },
  WI: { name: 'U.S. District Court, Eastern District of Wisconsin', address: '517 E Wisconsin Ave', city: 'Milwaukee', state: 'WI', zip: '53202', dept: 'Civil Division, Room 362', phone: '(414) 297-3372' },
  WY: { name: 'U.S. District Court, District of Wyoming', address: '2120 Capitol Ave', city: 'Cheyenne', state: 'WY', zip: '82001', dept: 'Civil Clerk\'s Office, Room 2131', phone: '(307) 433-2120' },
  DC: { name: 'U.S. District Court, District of Columbia', address: '333 Constitution Ave NW', city: 'Washington', state: 'DC', zip: '20001', dept: 'Civil Division, Room 1225', phone: '(202) 354-3000' },
};

function extractState(address) {
  const m = address.match(/\b(AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC)\b/);
  return m ? m[1] : 'IL';
}

function getCourt(address) {
  const state = extractState(address);
  return FEDERAL_COURTS[state] || FEDERAL_COURTS['IL'];
}

function calcDamages(weeklyRevenue, numTrucks) {
  const monthly = weeklyRevenue * 4.33;
  const annualPerTruck = monthly * 12;
  const totalAnnual = annualPerTruck * numTrucks;
  const reRegisterCosts = 5000;
  const legalFees = 15000;
  const total = totalAnnual + reRegisterCosts + legalFees;
  return {
    weeklyPerTruck: weeklyRevenue,
    monthlyPerTruck: Math.round(monthly),
    annualPerTruck: Math.round(annualPerTruck),
    numTrucks,
    totalAnnualRevenue: Math.round(totalAnnual),
    reRegisterCosts,
    legalFees,
    totalDamages: Math.round(total),
  };
}

// ── ATTORNEY ROUTES ───────────────────────────────────────────
app.get('/api/attorneys', (req, res) => res.json(loadAttorneys()));

app.post('/api/attorneys', (req, res) => {
  const { name, barNumber, barState, email, phone, licenseStates, specialty, firmName } = req.body;
  if (!name || !barNumber || !email) return res.status(400).json({ error: 'Name, bar number, and email required' });
  const attorneys = loadAttorneys();
  const attorney = { id: Date.now().toString(), name, barNumber, barState, email, phone, licenseStates, specialty, firmName, createdAt: new Date().toISOString() };
  attorneys.push(attorney);
  saveAttorneys(attorneys);
  res.json(attorney);
});

app.delete('/api/attorneys/:id', (req, res) => {
  const attorneys = loadAttorneys().filter(a => a.id !== req.params.id);
  saveAttorneys(attorneys);
  res.json({ success: true });
});

// ── BROKER REPEAT-OFFENDER CHECK ─────────────────────────────
app.get('/api/check-broker', (req, res) => {
  const { mc } = req.query;
  if (!mc) return res.json({ count: 0, reports: [] });
  const mc_clean = String(mc).trim().replace(/^MC-?/i, '');
  const reports = loadReports().filter(r => String(r.brokerMC).replace(/^MC-?/i,'') === mc_clean);
  res.json({ count: reports.length, reports });
});

// ── LETTER GENERATION ─────────────────────────────────────────
app.post('/api/generate-letter', rateLimit(60000, 5), async (req, res) => {
  try {
    const {
      carrierName, carrierMC, carrierDOT, carrierEmail,
      weeklyRevenue, numTrucks, carrierNarrative, evidenceDescription,
      brokerName, brokerMC, brokerAddress, brokerPOC, reporterName, reportContent,
      assignedAttorneyId
    } = req.body;

    const caseRef = generateCaseRef();
    const damages = calcDamages(Number(weeklyRevenue), Number(numTrucks));
    const court = getCourt(brokerAddress);
    const attorneys = loadAttorneys();
    const attorney = assignedAttorneyId ? attorneys.find(a => a.id === assignedAttorneyId) : null;

    // Log this broker for repeat-offender tracking
    recordBrokerReport(brokerMC, brokerName, carrierName, caseRef);

    const today = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
    const deadline = new Date();
    deadline.setDate(deadline.getDate() + 14);
    const deadlineStr = deadline.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });

    const firmLine = attorney
      ? `${attorney.firmName || attorney.name + ', Attorney at Law'}`
      : '[LAW FIRM NAME — TBD]';
    const attorneyBlock = attorney
      ? `\n\nRespectfully submitted,\n\n${attorney.name}\n${attorney.firmName || 'Attorney at Law'}\nBar No. ${attorney.barNumber} (${attorney.barState})\n${attorney.phone || ''}\n${attorney.email}`
      : '\n\nRespectfully submitted,\n\n_________________________________\nAuthorized Representative\nLegal Department';

    const prompt = `You are a senior transportation law attorney drafting a formal federal court demand letter. Write this letter exactly as a real law firm would send it — authoritative, legally precise, and intimidating to the recipient.

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

COMPUTED DAMAGES:
- Weekly gross revenue per truck: $${damages.weeklyPerTruck.toLocaleString()}
- Monthly revenue per truck: $${damages.monthlyPerTruck.toLocaleString()}
- Annual revenue per truck: $${damages.annualPerTruck.toLocaleString()}
- Number of trucks affected: ${damages.numTrucks}
- Total annual lost revenue: $${damages.totalAnnualRevenue.toLocaleString()}
- Re-registration/restructuring costs: $${damages.reRegisterCosts.toLocaleString()}
- Estimated legal fees and costs: $${damages.legalFees.toLocaleString()}
- TOTAL DAMAGES CLAIMED: $${damages.totalDamages.toLocaleString()}

VENUE COURT (where this will be filed):
${court.name}
${court.address}, ${court.city}, ${court.state} ${court.zip}
${court.dept}
Phone: ${court.phone}

LEGAL CAUSES OF ACTION TO CITE:
1. Defamation / Libel (state common law)
2. Tortious Interference with Business Relations / Prospective Economic Advantage
3. 49 U.S.C. § 14915 — False statements to FMCSA/industry reporting systems
4. 49 CFR Part 386 — FMCSA regulations on carrier safety and ratings
5. Lanham Act § 43(a), 15 U.S.C. § 1125(a) — False statements in commerce (if applicable)

LETTER REQUIREMENTS:
1. Start with formal letterhead block: firm name, then "VIA EMAIL AND CERTIFIED U.S. MAIL, RETURN RECEIPT REQUESTED"
2. Full defendant address block
3. Bold "RE: Case No. ${caseRef}" subject line, then on the next line "RE: Formal Demand for Retraction of False FreightGuard Report and Payment of Damages" — make it a two-line RE block
4. Opening paragraph: who we represent and purpose of letter
5. "STATEMENT OF FACTS" section — numbered paragraphs, include the carrier's narrative verbatim
6. "THE FREIGHTGUARD REPORT" section — quote the report and explain why it is false
7. "LEGAL AUTHORITY" section — cite all statutes above with brief explanations
8. "DAMAGES" section — present the full damages table line by line
9. "DEMANDS" section — numbered list: (1) immediate retraction of the FreightGuard report, (2) written apology to carrier, (3) payment of $${damages.totalDamages.toLocaleString()} in damages, (4) cease all further disparaging communications
10. State that failure to comply within 14 days (by ${deadlineStr}) will result in filing in ${court.name}, ${court.dept}
11. Include court address and phone number in the filing threat
12. Professional closing

Write the complete letter. Use [DATE] as the date placeholder. Make every word feel like it was written by a $500/hour attorney.

${attorneyBlock}`;

    const message = await anthropic.messages.create({
      model: 'claude-opus-4-6',
      max_tokens: 3000,
      messages: [{ role: 'user', content: prompt }],
    });

    const letterText = message.content[0].type === 'text' ? message.content[0].text : '';

    res.json({
      letter: letterText,
      damages,
      court,
      attorney: attorney || null,
      caseRef,
    });
  } catch (err) {
    console.error('Letter generation error:', err);
    res.status(500).json({ error: 'Letter generation failed: ' + err.message });
  }
});

// ── EMAIL SENDING ─────────────────────────────────────────────
app.post('/api/send-email', rateLimit(60000, 10), async (req, res) => {
  try {
    const { brokerEmail, carrierEmail, brokerName, carrierName, letterHtml, letterText, subject } = req.body;

    if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
      return res.status(503).json({ error: 'Email not configured. Add SMTP_USER and SMTP_PASS to your .env file.' });
    }

    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST || 'smtp.gmail.com',
      port: Number(process.env.SMTP_PORT) || 587,
      secure: false,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });

    const emailSubject = subject || `FORMAL LEGAL DEMAND — ${brokerName} — FreightGuard Report Retraction Required`;
    const fromName = process.env.FIRM_NAME || 'Legal Department';
    const fromEmail = process.env.SMTP_USER;

    await transporter.sendMail({
      from: `"${fromName}" <${fromEmail}>`,
      to: brokerEmail,
      cc: carrierEmail,
      subject: emailSubject,
      text: letterText,
      html: `
        <div style="font-family: 'Times New Roman', Times, serif; max-width: 800px; margin: 0 auto; padding: 40px; color: #111; line-height: 1.7; font-size: 14px;">
          <pre style="font-family: 'Times New Roman', Times, serif; white-space: pre-wrap; font-size: 14px; line-height: 1.8; border: none; background: none; padding: 0; margin: 0;">${letterText.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</pre>
          <hr style="margin: 40px 0; border: 1px solid #ccc;" />
          <p style="font-size: 11px; color: #666;">This communication is from a law office and contains information that is confidential and legally privileged. If you are not the intended recipient, you are hereby notified that any disclosure, copying, distribution, or use of this communication is strictly prohibited. If you received this in error, please immediately notify the sender and destroy this communication.</p>
        </div>
      `,
    });

    // Schedule Day 7 + Day 14 escalation follow-ups
    const caseRef  = req.body.caseRef || 'N/A';
    const now      = Date.now();
    const followups = loadFollowups();
    followups.push({
      id:           now.toString(),
      caseRef,
      brokerEmail,  carrierEmail, brokerName, carrierName,
      originalSubject: emailSubject,
      pending: [
        { label: 'Day 7 Reminder',      sendAt: now + 7  * 86400000, sent: false },
        { label: 'Day 14 Final Notice', sendAt: now + 14 * 86400000, sent: false },
      ],
    });
    saveFollowups(followups);

    res.json({ success: true, message: `Demand letter sent to ${brokerEmail} with CC to ${carrierEmail}` });
  } catch (err) {
    console.error('Email error:', err);
    res.status(500).json({ error: 'Email failed: ' + err.message });
  }
});

// ── STRIPE PAYMENT ────────────────────────────────────────────
app.post('/api/create-checkout', rateLimit(60000, 10), async (req, res) => {
  if (!stripe) {
    // Dev mode — skip payment
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
            name: 'FreightGuard Defense — Demand Letter',
            description: 'AI-drafted federal demand letter with damages calculation, court locator, and direct email delivery to broker.',
            images: [],
          },
          unit_amount: parseInt(process.env.STRIPE_PRICE_AMOUNT) || 25000,
        },
        quantity: 1,
      }],
      mode: 'payment',
      success_url: `${baseUrl}/?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${baseUrl}/`,
      metadata: { product: 'demand_letter' },
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error('Stripe error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/verify-payment', async (req, res) => {
  const { session_id } = req.query;
  if (!session_id) return res.status(400).json({ error: 'No session ID' });
  if (!stripe) return res.json({ paid: true, devMode: true });
  try {
    const session = await stripe.checkout.sessions.retrieve(session_id);
    res.json({ paid: session.payment_status === 'paid', email: session.customer_details?.email || '' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── ATTORNEY COVERAGE BY STATE ────────────────────────────────
// Returns attorneys licensed in a given state + court city for that state
app.get('/api/attorneys/coverage', (req, res) => {
  const { state } = req.query;
  const attorneys = loadAttorneys();
  const matched = state
    ? attorneys.filter(a => {
        const states = (a.licenseStates || a.barState || '').toUpperCase();
        return states.includes(state.toUpperCase());
      })
    : attorneys;

  const result = matched.map(a => {
    // Use their barState or first licensed state to find city
    const primaryState = (a.barState || (a.licenseStates||'').split(',')[0] || '').trim().toUpperCase();
    const court = FEDERAL_COURTS[primaryState] || FEDERAL_COURTS['IL'];
    return {
      id: a.id,
      name: a.name,
      firmName: a.firmName || null,
      barState: a.barState,
      licenseStates: a.licenseStates,
      city: court.city,
      state: court.state,
      phone: a.phone || null,
    };
  });

  res.json(result);
});

// ── COURT LOOKUP ENDPOINT ─────────────────────────────────────
app.get('/api/court', (req, res) => {
  const { address } = req.query;
  if (!address) return res.status(400).json({ error: 'Address required' });
  res.json(getCourt(address));
});

// ── FOLLOW-UP EMAIL SCHEDULER ────────────────────────────────
async function runFollowupScheduler() {
  if (!process.env.SMTP_USER || !process.env.SMTP_PASS) return;
  const followups = loadFollowups();
  let changed = false;
  const now = Date.now();

  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: Number(process.env.SMTP_PORT) || 587,
    secure: false,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });

  for (const job of followups) {
    for (const step of job.pending) {
      if (step.sent || now < step.sendAt) continue;
      const isDay14 = step.label.includes('14');
      const subj = isDay14
        ? `⚠️ FINAL NOTICE — Case ${job.caseRef} — 14-Day Deadline Expired — Filing Imminent`
        : `FOLLOW-UP — Case ${job.caseRef} — Awaiting Response to Legal Demand`;
      const body = isDay14
        ? `${job.brokerName},

This is final notice regarding Case No. ${job.caseRef}.

Our client's 14-day response deadline has now expired. Our attorneys have reviewed the file and are prepared to file in federal court. This is your final opportunity to resolve this matter without litigation.

Unless we receive written confirmation of (1) retraction of the FreightGuard report and (2) payment confirmation within 48 hours, we will proceed with filing.

Do not ignore this communication.

Legal Department
${process.env.FIRM_NAME || 'FreightGuard Defense'}`
        : `${job.brokerName},

This is a follow-up regarding our formal demand letter sent on behalf of ${job.carrierName} (Case No. ${job.caseRef}).

As of today, we have not received a response. Our client's 14-day deadline is approaching. We strongly encourage you to review the demand and respond in writing before the deadline expires.

Failure to respond will leave our attorneys no option but to proceed with filing in federal court.

Legal Department
${process.env.FIRM_NAME || 'FreightGuard Defense'}`;

      try {
        await transporter.sendMail({
          from: `"${process.env.FIRM_NAME || 'Legal Department'}" <${process.env.SMTP_USER}>`,
          to:   job.brokerEmail,
          cc:   job.carrierEmail,
          subject: subj,
          text:    body,
        });
        step.sent   = true;
        step.sentAt = new Date().toISOString();
        changed = true;
        console.log(`✉️  Follow-up sent [${step.label}] → ${job.brokerEmail} (Case ${job.caseRef})`);
      } catch (e) {
        console.error(`Follow-up send failed [${step.label}]:`, e.message);
      }
    }
  }
  if (changed) saveFollowups(followups);
}

// Run scheduler every hour
setInterval(runFollowupScheduler, 3600000);
// Also run once 30s after boot (in case any are overdue)
setTimeout(runFollowupScheduler, 30000);

// ── START ─────────────────────────────────────────────────────
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log('');
  console.log('╔══════════════════════════════════════════════════╗');
  console.log('║       FreightGuard Defense  —  Server Ready       ║');
  console.log('╚══════════════════════════════════════════════════╝');
  console.log(`  🌐  URL:            http://0.0.0.0:${PORT}`);
  console.log(`  🤖  Anthropic API:  ${process.env.ANTHROPIC_API_KEY ? '✅ Connected' : '❌ Missing ANTHROPIC_API_KEY'}`);
  console.log(`  💳  Stripe:         ${process.env.STRIPE_SECRET_KEY ? '✅ Connected' : '⚠️  Not set — dev mode (free access)'}`);
  console.log(`  📧  Email (SMTP):   ${process.env.SMTP_USER        ? '✅ Connected' : '⚠️  Not set — email disabled'}`);
  console.log(`  📁  Data dir:       ${DATA_DIR}`);
  console.log('');
  if (!process.env.ANTHROPIC_API_KEY) {
    console.error('  ⛔  FATAL: ANTHROPIC_API_KEY is required. Add it to your .env file.');
    process.exit(1);
  }
});

// ── GRACEFUL SHUTDOWN ─────────────────────────────────────────
function shutdown(signal) {
  console.log(`\n${signal} received — shutting down gracefully...`);
  server.close(() => {
    console.log('Server closed.');
    process.exit(0);
  });
  setTimeout(() => { console.error('Forced shutdown.'); process.exit(1); }, 10000);
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));
process.on('uncaughtException',  err => { console.error('Uncaught:', err.message); });
process.on('unhandledRejection', err => { console.error('Unhandled:', err);        });
