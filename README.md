# FreightGuard Defense

**A web app that helps trucking carriers fight back against false FreightGuard reports.**

Carriers pay $250, fill in their info and the broker's info, and receive a professionally drafted federal demand letter — complete with damages calculation, courthouse auto-location, and direct email delivery to the broker. An automated follow-up sequence fires at Day 7 and Day 14 if the broker doesn't respond.

---

## What's Inside

```
freightguard-defense/
├── server.js           ← Express backend (all routes + scheduler)
├── package.json
├── .env.example        ← Copy to .env and fill in your keys
├── Procfile            ← For Railway / Heroku
├── railway.toml        ← Railway one-click config
├── render.yaml         ← Render.com config
├── data/               ← Auto-created on first run (gitignored)
│   ├── attorneys.json  ← Your attorney database
│   ├── broker-reports.json  ← Repeat-offender tracking
│   └── followups.json  ← Scheduled follow-up emails
└── public/
    └── index.html      ← Full single-page app (landing + form + admin)
```

---

## Accounts You Need Before Deploying

| Service | What It's For | Free? |
|---|---|---|
| [Anthropic](https://console.anthropic.com) | AI letter generation | Pay per use (~$0.02/letter) |
| [Stripe](https://dashboard.stripe.com) | $250 payment processing | Free (2.9% + 30¢ per charge) |
| Gmail or [SendGrid](https://sendgrid.com) | Sending demand letters by email | Free tier available |
| [Railway](https://railway.app) or [Render](https://render.com) | Hosting | ~$5/month |

---

## Local Setup (Test on Your Computer First)

**1. Clone the repo and install**
```bash
git clone https://github.com/YOUR_USERNAME/freightguard-defense.git
cd freightguard-defense
npm install
```

**2. Create your `.env` file**
```bash
cp .env.example .env
```
Open `.env` and fill in your keys (see Environment Variables section below).

**3. Run it**
```bash
npm start
```
Open `http://localhost:3000` — the landing page will load.

> **No Stripe key set?** The app runs in dev mode — clicking "Fight Back for $250" skips payment and goes straight to the form. Perfect for testing.

---

## Environment Variables

Open `.env` and fill these in:

```env
# ── REQUIRED ─────────────────────────────────────────────────
ANTHROPIC_API_KEY=sk-ant-...        # From console.anthropic.com → API Keys

# ── STRIPE (set when ready to charge real money) ──────────────
STRIPE_SECRET_KEY=sk_live_...       # Stripe Dashboard → Developers → API Keys
STRIPE_PUBLISHABLE_KEY=pk_live_...  # Same place
STRIPE_PRICE_AMOUNT=25000           # In cents — 25000 = $250.00

# ── EMAIL (demand letters + follow-ups are sent from here) ────
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=youremail@gmail.com
SMTP_PASS=xxxx xxxx xxxx xxxx      # Gmail App Password (see below)

# ── BRANDING ──────────────────────────────────────────────────
FIRM_NAME=FreightGuard Defense Legal Network   # Shows as email sender name

# ── DEPLOYMENT ────────────────────────────────────────────────
BASE_URL=https://yourdomain.com     # Your live URL (no trailing slash)
PORT=3000
```

### How to get a Gmail App Password
1. Go to your Google Account → Security
2. Turn on 2-Step Verification (required)
3. Go to Security → App Passwords
4. Select "Mail" + "Other (custom name)" → type "FreightGuard"
5. Copy the 16-character password → paste as `SMTP_PASS`

### Using SendGrid instead of Gmail
```env
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USER=apikey
SMTP_PASS=SG.xxxxxxxxxxxxxxxx     # Your SendGrid API key
```

---

## Deploy to Railway (Recommended — Easiest)

Railway connects directly to GitHub and auto-deploys on every push.

**Step 1 — Push to GitHub**
```bash
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/freightguard-defense.git
git push -u origin main
```

**Step 2 — Create Railway project**
1. Go to [railway.app](https://railway.app) → New Project
2. Click **Deploy from GitHub repo** → select `freightguard-defense`
3. Railway detects Node.js automatically and starts deploying

**Step 3 — Add environment variables**
1. In your Railway project → click your service → **Variables**
2. Click **Raw Editor** and paste all your `.env` contents (without the comments)
3. Add `BASE_URL=https://YOUR-RAILWAY-URL.up.railway.app`
4. Railway auto-redeploys

**Step 4 — Connect your custom domain**
1. Railway service → **Settings** → **Domains** → Add Custom Domain
2. Enter `freightguarddefense.com` (or whatever you have)
3. Railway gives you CNAME/A records → add them in your domain registrar's DNS
4. Update `BASE_URL` in Railway Variables to `https://freightguarddefense.com`

**Step 5 — Set up Railway Volume (keeps data across deploys)**
1. Railway project → **New** → **Volume**
2. Mount path: `/app/data`
3. This ensures your attorneys.json, broker-reports.json, and followups.json survive redeploys

---

## Deploy to Render (Alternative)

1. Go to [render.com](https://render.com) → New → Web Service
2. Connect your GitHub repo
3. Render reads `render.yaml` automatically — just click **Create**
4. Go to **Environment** → add all your env vars
5. For persistent data: create a **Disk** → mount at `/app/data`, size 1 GB

---

## Stripe Setup

**To charge real money:**

1. Go to [dashboard.stripe.com](https://dashboard.stripe.com)
2. Complete business verification (takes a few minutes)
3. Copy your **Live** keys (not Test keys) once you're ready to go live
4. Set `STRIPE_SECRET_KEY=sk_live_...` and `STRIPE_PUBLISHABLE_KEY=pk_live_...`

**To test payments first:**
- Use Test keys: `sk_test_...` and `pk_test_...`
- Test card: `4242 4242 4242 4242`, any future date, any CVC
- No real money moves

---

## Adding Attorneys to Your Network

Once the app is running, go to `https://yourdomain.com` → scroll down → click **"Attorneys"** tab in the top nav (or navigate to `/#attorneys` in the form screen).

Fill in:
- **Attorney Name** — e.g., Jonathan R. Calloway
- **Firm Name** — e.g., Calloway & Sterling, P.C.
- **Bar Number** — their state bar number
- **Bar State** — primary state (2-letter)
- **Licensed States** — comma-separated: `TN, MS, AL` — these are the states where they appear on your landing page
- **Email + Phone** — for the letter signature block

Once an attorney is added for a state, they automatically appear in the "Local Representation" section of the landing page when a carrier browses it.

---

## How the $250 Payment Flow Works

1. Carrier clicks **"Fight Back for $250"** on landing page
2. Server creates a Stripe Checkout session → browser redirects to Stripe's hosted checkout
3. Carrier pays with credit card
4. Stripe redirects back to `/?session_id=cs_xxx`
5. App verifies the session with Stripe API → unlocks the form
6. Session ID is single-use — refreshing the page after payment re-verifies from Stripe

---

## How the Follow-Up Scheduler Works

After a carrier sends the demand letter by email, the server logs two pending follow-ups in `data/followups.json`:
- **Day 7** — "We have not received a response. Deadline is approaching."
- **Day 14** — "⚠️ FINAL NOTICE — Filing imminent."

A background scheduler checks for due follow-ups every hour. When one is due, it sends automatically from your SMTP account to the broker (with carrier CC'd). No manual action needed.

---

## Endpoints Reference

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Server status check |
| POST | `/api/create-checkout` | Create Stripe session |
| GET | `/api/verify-payment` | Verify Stripe payment |
| POST | `/api/generate-letter` | AI letter generation |
| POST | `/api/send-email` | Send letter to broker |
| GET | `/api/court?address=...` | Court lookup by address |
| GET | `/api/check-broker?mc=...` | Repeat-offender check |
| GET | `/api/attorneys` | List all attorneys |
| POST | `/api/attorneys` | Add attorney |
| DELETE | `/api/attorneys/:id` | Remove attorney |
| GET | `/api/attorneys/coverage?state=XX` | Attorneys by state |

---

## Troubleshooting

**"Letter generation failed"**
→ Check `ANTHROPIC_API_KEY` is set and has credit. Test at console.anthropic.com.

**"Email failed"**
→ Make sure you're using a Gmail **App Password**, not your regular Gmail password. Regular passwords don't work with SMTP.

**Payment goes to form immediately (free)**
→ `STRIPE_SECRET_KEY` is not set — that's dev mode. Add your Stripe key.

**Attorneys not showing on landing page**
→ Make sure the attorney's `licenseStates` field includes the 2-letter state code for the broker's state.

**Data resets after redeploy**
→ You haven't mounted a Railway Volume or Render Disk to `/app/data`. Do that first.

---

## Revenue Math

- $250 per letter × 20 carriers/month = **$5,000/month**
- $250 per letter × 100 carriers/month = **$25,000/month**
- Anthropic cost per letter: ~$0.02–$0.05
- Stripe fee per transaction: ~$7.55 (2.9% + $0.30)
- Hosting: ~$5–$10/month
- **Net margin: ~97%**

---

## Support

For issues with this codebase, check the Troubleshooting section above. For Anthropic API issues, visit [docs.anthropic.com](https://docs.anthropic.com). For Stripe, visit [stripe.com/docs](https://stripe.com/docs).
