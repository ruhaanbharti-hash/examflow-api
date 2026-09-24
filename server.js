const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");
const crypto = require("crypto");

const PORT = process.env.PORT || 4000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-2.5-flash";
const GEMINI_BASE = process.env.GEMINI_API_BASE || "https://generativelanguage.googleapis.com"; // overridable only for local testing
// Email (Brevo). Verification and password reset switch on only when BREVO_API_KEY and EMAIL_FROM are set.
const BREVO_API_KEY = process.env.BREVO_API_KEY || "";
const BREVO_API_URL = process.env.BREVO_API_URL || "https://api.brevo.com/v3/smtp/email";
const EMAIL_FROM = process.env.EMAIL_FROM || "";
const EMAIL_FROM_NAME = process.env.EMAIL_FROM_NAME || "ExamFlow";
const EMAIL_ENABLED = Boolean(BREVO_API_KEY && EMAIL_FROM);
const FRONTEND_ORIGINS = (process.env.FRONTEND_ORIGIN || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

if (!DATABASE_URL) {
  console.error("Missing DATABASE_URL environment variable. Set it in the Render dashboard (Environment tab) and redeploy.");
  process.exit(1);
}
if (!JWT_SECRET) {
  console.error("Missing JWT_SECRET environment variable. Set it in the Render dashboard (Environment tab) and redeploy.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const EMPTY_DATA = { exams: [], sessions: [], settings: { dailyGoalMinutes: 120, remindExams: true, remindTasks: true } };

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      is_admin BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_data (
      user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      data JSONB NOT NULL DEFAULT '{}'::jsonb,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  // Anonymous usage analytics — works whether or not the visitor has an account, feeds the admin dashboard.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS events (
      id SERIAL PRIMARY KEY,
      device_id TEXT,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      event_type TEXT NOT NULL,
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_events_type_time ON events(event_type, created_at);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_events_device ON events(device_id);`);
  // Admin panel additions — all backwards-compatible (new columns with defaults / new tables only).
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT false;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_active_at TIMESTAMPTZ;`);
  await pool.query(`ALTER TABLE events ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES users(id) ON DELETE SET NULL;`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS feedback (
      id SERIAL PRIMARY KEY,
      kind TEXT NOT NULL CHECK (kind IN ('feedback', 'bug')),
      message TEXT NOT NULL,
      page TEXT,
      user_agent TEXT,
      device_id TEXT,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_feedback_time ON feedback(created_at);`);
  // Turns a text date into a date, or NULL if it isn't a valid date (so one bad value can't break admin reports).
  await pool.query(`
    CREATE OR REPLACE FUNCTION ef_safe_date(t text) RETURNS date
    LANGUAGE plpgsql IMMUTABLE SET search_path = '' AS $fn$
    BEGIN
      IF t IS NULL OR t !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}' THEN RETURN NULL; END IF;
      RETURN substr(t, 1, 10)::date;
    EXCEPTION WHEN others THEN RETURN NULL;
    END $fn$;
  `);
  await pool.query(`REVOKE ALL ON FUNCTION ef_safe_date(text) FROM PUBLIC;`);
  // Phase 2: workflows. New columns have defaults; new tables only. Nothing existing is removed or renamed.
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_disabled BOOLEAN NOT NULL DEFAULT false;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS disabled_at TIMESTAMPTZ;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS disabled_reason TEXT;`);
  // Email verification: accounts that existed before verification was introduced are treated as verified.
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN;`);
  await pool.query(`UPDATE users SET email_verified = true WHERE email_verified IS NULL;`);
  await pool.query(`ALTER TABLE users ALTER COLUMN email_verified SET DEFAULT false;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ;`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS email_codes (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      purpose TEXT NOT NULL CHECK (purpose IN ('verify', 'reset')),
      code_hash TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0,
      used_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_email_codes_user ON email_codes(user_id, purpose, created_at);`);
  await pool.query(`ALTER TABLE feedback ADD COLUMN IF NOT EXISTS category TEXT;`);
  await pool.query(`ALTER TABLE feedback ADD COLUMN IF NOT EXISTS title TEXT;`);
  await pool.query(`ALTER TABLE feedback ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'new';`);
  await pool.query(`ALTER TABLE feedback ADD COLUMN IF NOT EXISTS priority TEXT NOT NULL DEFAULT 'medium';`);
  await pool.query(`ALTER TABLE feedback ADD COLUMN IF NOT EXISTS duplicate_of INTEGER REFERENCES feedback(id) ON DELETE SET NULL;`);
  await pool.query(`ALTER TABLE feedback ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ;`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS feedback_notes (
      id SERIAL PRIMARY KEY,
      feedback_id INTEGER NOT NULL REFERENCES feedback(id) ON DELETE CASCADE,
      admin_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      kind TEXT NOT NULL DEFAULT 'internal' CHECK (kind IN ('internal', 'resolution')),
      note TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS feedback_history (
      id SERIAL PRIMARY KEY,
      feedback_id INTEGER NOT NULL REFERENCES feedback(id) ON DELETE CASCADE,
      admin_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      field TEXT NOT NULL,
      old_value TEXT,
      new_value TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS announcements (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      type TEXT NOT NULL DEFAULT 'general' CHECK (type IN ('general', 'feature_update', 'maintenance', 'important')),
      status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'archived')),
      publish_at TIMESTAMPTZ,
      created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS admin_activity_logs (
      id SERIAL PRIMARY KEY,
      admin_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      target_type TEXT,
      target_id TEXT,
      details JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_feedback_notes_item ON feedback_notes(feedback_id);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_feedback_history_item ON feedback_history(feedback_id);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_feedback_dup ON feedback(duplicate_of);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_admin_logs_time ON admin_activity_logs(created_at);`);
  await pool.query(`
    DO $do$ BEGIN
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN REVOKE ALL ON FUNCTION ef_safe_date(text) FROM anon; END IF;
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN REVOKE ALL ON FUNCTION ef_safe_date(text) FROM authenticated; END IF;
    END $do$;
  `);
}

// Records that a logged-in user was active. Throttled to one write per user per 5 minutes.
function touchActive(userId) {
  if (!userId) return;
  pool
    .query(
      "UPDATE users SET last_active_at = now() WHERE id = $1 AND (last_active_at IS NULL OR last_active_at < now() - interval '5 minutes')",
      [userId]
    )
    .catch((e) => console.error("touchActive failed", e.message));
}

async function logEvent(deviceId, userId, eventType, metadata) {
  try {
    await pool.query(
      "INSERT INTO events (device_id, user_id, event_type, metadata) VALUES ($1, $2, $3, $4)",
      [typeof deviceId === "string" ? deviceId.slice(0, 100) : null, userId || null, eventType, metadata || {}]
    );
  } catch (e) {
    console.error("logEvent failed", eventType, e.message);
  }
}

const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "20mb" }));
app.use(
  cors({
    origin: FRONTEND_ORIGINS.length ? FRONTEND_ORIGINS : true,
  })
);

/* ---------------- helpers ---------------- */

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function signToken(user) {
  return jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: "30d" });
}

// Optional auth: attaches req.userId if a valid token is present, but never blocks the request.
// ExamFlow works fully without an account — this just lets logged-in users get extra behavior.
// Account state ("ok", "disabled" or "missing"), cached for 20 seconds so it isn't looked up on every request.
const userStateCache = new Map();
async function userState(userId) {
  const hit = userStateCache.get(userId);
  if (hit && Date.now() - hit.at < 20000) return hit.state;
  const r = await pool.query("SELECT is_disabled, email_verified, password_changed_at FROM users WHERE id = $1", [userId]);
  const row = r.rows[0];
  const state = !row ? "missing" : row.is_disabled === true ? "disabled" : "ok";
  const info = { state, verified: !row || row.email_verified !== false, pwChangedAt: row && row.password_changed_at ? new Date(row.password_changed_at).getTime() : 0 };
  userStateCache.set(userId, { state: info, at: Date.now() });
  if (userStateCache.size > 5000) userStateCache.clear();
  return info;
}
function forgetUserState(userId) { userStateCache.delete(userId); }
const DISABLED_MSG = "This account has been disabled. If you think this is a mistake, please contact ExamFlow.";

async function optionalAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (token) {
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      const st = await userState(payload.sub);
      if (st.state === "ok" && !tokenPredatesPassword(payload, st)) {
        req.userId = payload.sub;
        touchActive(req.userId);
      }
    } catch (e) { /* invalid/expired — treat as anonymous */ }
  }
  next();
}

// A token issued before the password was last changed (e.g. reset) is no longer valid.
const tokenPredatesPassword = (payload, st) => Boolean(st.pwChangedAt && payload.iat && payload.iat * 1000 < st.pwChangedAt);
const UNVERIFIED_MSG = "Please verify your email address to continue.";

// requireAuth: a valid login for an active (and, when email is on, verified) account.
// requireLogin: the same, but also lets unverified accounts through (for /api/me and the verification routes).
function requireAuth(req, res, next) { return authCheck(req, res, next, true); }
function requireLogin(req, res, next) { return authCheck(req, res, next, false); }

async function authCheck(req, res, next, needVerified) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Please log in to continue." });
  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return res.status(401).json({ error: "Your session has expired. Please log in again." });
  }
  let state;
  try {
    state = await userState(payload.sub);
  } catch (e) {
    console.error("userState error", e.message);
    return res.status(503).json({ error: "ExamFlow is having trouble right now. Please try again in a moment." });
  }
  if (state.state === "missing" || tokenPredatesPassword(payload, state)) return res.status(401).json({ error: "Your session has expired. Please log in again." });
  if (state.state === "disabled") return res.status(403).json({ error: DISABLED_MSG });
  if (needVerified && EMAIL_ENABLED && !state.verified) return res.status(403).json({ error: UNVERIFIED_MSG, code: "email_unverified" });
  req.userId = payload.sub;
  req.tokenPayload = payload;
  touchActive(req.userId);
  next();
}

/* ---------------- auth routes ---------------- */

// Slows down password guessing: 20 login attempts per IP per 15 minutes.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many login attempts. Please wait a few minutes and try again." },
});

app.post("/api/auth/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !name.trim()) return res.status(400).json({ error: "Please enter your name." });
    if (!email || !EMAIL_RE.test(email.trim())) return res.status(400).json({ error: "Please enter a valid email address." });
    if (!password || password.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters." });

    const normalizedEmail = email.trim().toLowerCase();
    const existing = await pool.query("SELECT id FROM users WHERE email = $1", [normalizedEmail]);
    if (existing.rows.length) return res.status(409).json({ error: "An account with this email already exists. Try logging in instead." });

    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (name, email, password_hash, email_verified) VALUES ($1, $2, $3, $4) RETURNING id, name, email, created_at",
      [name.trim(), normalizedEmail, hash, !EMAIL_ENABLED]
    );
    const user = result.rows[0];
    await pool.query("INSERT INTO user_data (user_id, data) VALUES ($1, $2)", [user.id, EMPTY_DATA]);

    const token = signToken(user);
    await logEvent(req.body.deviceId, user.id, "user_registered", {});
    let codeSent = false;
    if (EMAIL_ENABLED) codeSent = await sendCode(user, "verify");
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, emailVerified: !EMAIL_ENABLED }, emailVerificationRequired: EMAIL_ENABLED, codeSent });
  } catch (e) {
    console.error("signup error", e);
    res.status(500).json({ error: "Something went wrong creating your account. Please try again." });
  }
});

app.post("/api/auth/login", loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "Please enter your email and password." });

    const normalizedEmail = email.trim().toLowerCase();
    const result = await pool.query("SELECT id, name, email, password_hash, is_disabled, email_verified FROM users WHERE email = $1", [normalizedEmail]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: "Incorrect email or password." });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Incorrect email or password." });
    if (user.is_disabled === true) return res.status(403).json({ error: DISABLED_MSG });

    const token = signToken(user);
    await logEvent(req.body.deviceId, user.id, "user_login", {});
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, emailVerified: user.email_verified !== false || !EMAIL_ENABLED }, emailVerificationRequired: EMAIL_ENABLED });
  } catch (e) {
    console.error("login error", e);
    res.status(500).json({ error: "Something went wrong logging you in. Please try again." });
  }
});

app.get("/api/me", requireLogin, async (req, res) => {
  try {
    const result = await pool.query("SELECT id, name, email, created_at, is_admin, email_verified FROM users WHERE id = $1", [req.userId]);
    const row = result.rows[0];
    if (!row) return res.status(404).json({ error: "Account not found." });
    res.json({
      user: { id: row.id, name: row.name, email: row.email, created_at: row.created_at, isAdmin: row.is_admin === true, emailVerified: row.email_verified !== false || !EMAIL_ENABLED },
      emailVerificationRequired: EMAIL_ENABLED,
    });
  } catch (e) {
    console.error("me error", e);
    res.status(500).json({ error: "Couldn't load your account." });
  }
});

/* ---------------- email: verification codes and password reset ---------------- */
const CODE_TTL_MIN = 15;
const CODE_MAX_ATTEMPTS = 5;
const hashCode = (code) => crypto.createHmac("sha256", JWT_SECRET).update(String(code)).digest("hex");
const escapeHtml = (v) => String(v).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function sendEmail(to, subject, html, text) {
  if (!EMAIL_ENABLED) return false;
  try {
    const r = await fetch(BREVO_API_URL, {
      method: "POST",
      headers: { "api-key": BREVO_API_KEY, "Content-Type": "application/json", accept: "application/json" },
      body: JSON.stringify({ sender: { email: EMAIL_FROM, name: EMAIL_FROM_NAME }, to: [{ email: to }], subject, htmlContent: html, textContent: text }),
      signal: AbortSignal.timeout(10000),
    });
    if (!r.ok) { console.error("email send failed", r.status, (await r.text()).slice(0, 300)); return false; }
    return true;
  } catch (e) {
    console.error("email send error", e.message);
    return false;
  }
}

function codeEmail(name, code, purpose) {
  const verify = purpose === "verify";
  const subject = verify ? `${code} is your ExamFlow verification code` : `${code} is your ExamFlow password reset code`;
  const intro = verify ? "Welcome to ExamFlow! Enter this code to verify your email address:" : "We received a request to reset your ExamFlow password. Enter this code to choose a new one:";
  const outro = verify ? "If you didn't create an ExamFlow account, you can ignore this email." : "If you didn't ask to reset your password, you can ignore this email. Your password won't change.";
  const html = `<!doctype html><html><body style="margin:0;background:#F6F5FB;font-family:Arial,Helvetica,sans-serif;color:#17142B">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="padding:32px 12px"><tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#fff;border-radius:18px;padding:32px">
<tr><td style="font-size:20px;font-weight:800;color:#5B4FE8">🎓 ExamFlow</td></tr>
<tr><td style="padding-top:20px;font-size:16px">Hi ${escapeHtml(name || "there")},</td></tr>
<tr><td style="padding-top:8px;font-size:16px;line-height:1.5">${intro}</td></tr>
<tr><td align="center" style="padding:24px 0"><div style="display:inline-block;font-size:34px;font-weight:800;letter-spacing:8px;background:#EEECFE;color:#4A3FD4;border-radius:14px;padding:14px 22px">${code}</div></td></tr>
<tr><td style="font-size:14px;color:#4B4663;line-height:1.5">This code expires in ${CODE_TTL_MIN} minutes. ${outro}</td></tr>
<tr><td style="padding-top:24px;font-size:12px;color:#8A86A6">ExamFlow · Your smarter study space</td></tr>
</table></td></tr></table></body></html>`;
  const text = `Hi ${name || "there"},\n\n${intro}\n\n${code}\n\nThis code expires in ${CODE_TTL_MIN} minutes. ${outro}\n\nExamFlow`;
  return { subject, html, text };
}

// Creates a new single-use code (replacing earlier unused ones) and emails it. Returns whether the email was accepted.
async function sendCode(user, purpose) {
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, "0");
  await pool.query("UPDATE email_codes SET used_at = now() WHERE user_id = $1 AND purpose = $2 AND used_at IS NULL", [user.id, purpose]);
  await pool.query(
    `INSERT INTO email_codes (user_id, purpose, code_hash, expires_at) VALUES ($1, $2, $3, now() + interval '${CODE_TTL_MIN} minutes')`,
    [user.id, purpose, hashCode(code)]
  );
  const m = codeEmail(user.name, code, purpose);
  return sendEmail(user.email, m.subject, m.html, m.text);
}

// Checks a code. Returns "ok", or an error message for the student.
async function checkCode(userId, purpose, code) {
  const r = await pool.query(
    "SELECT id, code_hash, expires_at, attempts FROM email_codes WHERE user_id = $1 AND purpose = $2 AND used_at IS NULL ORDER BY created_at DESC LIMIT 1",
    [userId, purpose]
  );
  const row = r.rows[0];
  if (!row) return "That code isn't valid. Ask for a new one.";
  if (new Date(row.expires_at).getTime() < Date.now()) return "That code has expired. Ask for a new one.";
  if (row.attempts >= CODE_MAX_ATTEMPTS) return "Too many wrong tries. Ask for a new code.";
  const given = hashCode(String(code || "").replace(/\D/g, ""));
  const match = given.length === row.code_hash.length && crypto.timingSafeEqual(Buffer.from(given), Buffer.from(row.code_hash));
  if (!match) {
    await pool.query("UPDATE email_codes SET attempts = attempts + 1 WHERE id = $1", [row.id]);
    const left = CODE_MAX_ATTEMPTS - row.attempts - 1;
    return left > 0 ? `That code isn't right. ${left} ${left === 1 ? "try" : "tries"} left.` : "Too many wrong tries. Ask for a new code.";
  }
  await pool.query("UPDATE email_codes SET used_at = now() WHERE id = $1", [row.id]);
  return "ok";
}

// At most one code per minute and 5 per hour, per account and purpose.
async function codeRateLimited(userId, purpose) {
  const r = await pool.query(
    `SELECT COUNT(*) FILTER (WHERE created_at > now() - interval '1 minute') AS m, COUNT(*) FILTER (WHERE created_at > now() - interval '1 hour') AS h
     FROM email_codes WHERE user_id = $1 AND purpose = $2`,
    [userId, purpose]
  );
  const m = Number(r.rows[0].m), h = Number(r.rows[0].h);
  if (m > 0) return "Please wait a minute before asking for another code.";
  if (h >= 5) return "You've asked for a lot of codes. Please try again in an hour.";
  return null;
}

const codeLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false, message: { error: "Too many attempts. Please wait a few minutes and try again." } });

app.post("/api/auth/verify-email", codeLimiter, requireLogin, async (req, res) => {
  try {
    if (!EMAIL_ENABLED) return res.json({ ok: true, emailVerified: true });
    const u = (await pool.query("SELECT email_verified FROM users WHERE id = $1", [req.userId])).rows[0];
    if (u && u.email_verified === true) return res.json({ ok: true, emailVerified: true });
    const result = await checkCode(req.userId, "verify", (req.body || {}).code);
    if (result !== "ok") return res.status(400).json({ error: result });
    await pool.query("UPDATE users SET email_verified = true WHERE id = $1", [req.userId]);
    forgetUserState(req.userId);
    await logEvent(null, req.userId, "email_verified", {});
    res.json({ ok: true, emailVerified: true });
  } catch (e) {
    console.error("verify error", e);
    res.status(500).json({ error: "Couldn't verify your email. Please try again." });
  }
});

app.post("/api/auth/resend-verification", codeLimiter, requireLogin, async (req, res) => {
  try {
    if (!EMAIL_ENABLED) return res.json({ ok: true });
    const u = (await pool.query("SELECT id, name, email, email_verified FROM users WHERE id = $1", [req.userId])).rows[0];
    if (u.email_verified === true) return res.json({ ok: true, emailVerified: true });
    const limited = await codeRateLimited(u.id, "verify");
    if (limited) return res.status(429).json({ error: limited });
    const sent = await sendCode(u, "verify");
    if (!sent) return res.status(502).json({ error: "We couldn't send the email right now. Please try again in a few minutes." });
    res.json({ ok: true });
  } catch (e) {
    console.error("resend error", e);
    res.status(500).json({ error: "Couldn't send a new code. Please try again." });
  }
});

// Always answers the same way, so it can't be used to find out which emails have accounts.
app.post("/api/auth/forgot-password", codeLimiter, async (req, res) => {
  const generic = { ok: true, message: "If an account exists for that email, we've sent a code to it." };
  try {
    if (!EMAIL_ENABLED) return res.status(503).json({ error: "Password reset isn't available yet. Please contact ExamFlow for help." });
    const email = String((req.body || {}).email || "").trim().toLowerCase();
    if (!EMAIL_RE.test(email)) return res.status(400).json({ error: "Please enter a valid email address." });
    const u = (await pool.query("SELECT id, name, email, is_disabled FROM users WHERE email = $1", [email])).rows[0];
    if (!u || u.is_disabled) return res.json(generic);
    if (await codeRateLimited(u.id, "reset")) return res.json(generic);
    await sendCode(u, "reset");
    await logEvent(null, u.id, "password_reset_requested", {});
    res.json(generic);
  } catch (e) {
    console.error("forgot error", e);
    res.status(500).json({ error: "Something went wrong. Please try again." });
  }
});

app.post("/api/auth/reset-password", codeLimiter, async (req, res) => {
  try {
    if (!EMAIL_ENABLED) return res.status(503).json({ error: "Password reset isn't available yet." });
    const { email, code, password } = req.body || {};
    const normalized = String(email || "").trim().toLowerCase();
    if (!password || password.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters." });
    const u = (await pool.query("SELECT id, name, email, is_disabled, is_admin FROM users WHERE email = $1", [normalized])).rows[0];
    if (!u) return res.status(400).json({ error: "That code isn't valid. Ask for a new one." });
    if (u.is_disabled) return res.status(403).json({ error: DISABLED_MSG });
    const result = await checkCode(u.id, "reset", code);
    if (result !== "ok") return res.status(400).json({ error: result });
    const hash = await bcrypt.hash(password, 10);
    // Resetting proves the student owns the inbox, so it also verifies the email. Older logins stop working.
    await pool.query("UPDATE users SET password_hash = $2, email_verified = true, password_changed_at = now() WHERE id = $1", [u.id, hash]);
    forgetUserState(u.id);
    await new Promise((r) => setTimeout(r, 1100)); // new login must be issued after the change time (1-second resolution)
    const token = signToken(u);
    await logEvent(null, u.id, "password_reset", {});
    res.json({ token, user: { id: u.id, name: u.name, email: u.email, emailVerified: true } });
  } catch (e) {
    console.error("reset error", e);
    res.status(500).json({ error: "Couldn't reset your password. Please try again." });
  }
});

/* ---------------- data sync routes (account holders only) ---------------- */

// Parts of a student's saved data. exams/sessions/settings are the original ones; tasks, notes and schedule are new.
const DATA_KEYS = { exams: "array", sessions: "array", settings: "object", tasks: "array", notes: "array", schedule: "array", quizzes: "array" };

app.get("/api/data", requireAuth, async (req, res) => {
  try {
    const result = await pool.query("SELECT data FROM user_data WHERE user_id = $1", [req.userId]);
    const row = result.rows[0];
    res.json(row ? row.data : EMPTY_DATA);
  } catch (e) {
    console.error("get data error", e);
    res.status(500).json({ error: "Couldn't load your data." });
  }
});

app.put("/api/data", requireAuth, async (req, res) => {
  try {
    // Only the parts a client sends are replaced; everything else in the student's saved data is kept.
    // This lets older and newer versions of the app save side by side without erasing each other's data
    // (e.g. the older app only knows exams/sessions/settings and must not wipe tasks or notes).
    const body = req.body || {};
    const patch = {};
    for (const [key, kind] of Object.entries(DATA_KEYS)) {
      if (body[key] === undefined) continue;
      const v = body[key];
      if (kind === "array" && !Array.isArray(v)) return res.status(400).json({ error: `Invalid ${key}.` });
      if (kind === "object" && (!v || typeof v !== "object" || Array.isArray(v))) return res.status(400).json({ error: `Invalid ${key}.` });
      if (kind === "array" && v.length > 5000) return res.status(400).json({ error: `Too many ${key}.` });
      patch[key] = v;
    }
    if (!Object.keys(patch).length) return res.status(400).json({ error: "Nothing to save." });
    await pool.query(
      `INSERT INTO user_data (user_id, data, updated_at) VALUES ($1, $2::jsonb, now())
       ON CONFLICT (user_id) DO UPDATE SET data = user_data.data || EXCLUDED.data, updated_at = now()`,
      [req.userId, patch]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error("put data error", e);
    res.status(500).json({ error: "Couldn't save your data. Please try again." });
  }
});

app.delete("/api/account", requireLogin, async (req, res) => {
  try {
    await pool.query("DELETE FROM users WHERE id = $1", [req.userId]);
    res.json({ ok: true });
  } catch (e) {
    console.error("delete account error", e);
    res.status(500).json({ error: "Couldn't delete your account. Please try again." });
  }
});

/* ---------------- tracking (works with or without an account) ---------------- */

app.post("/api/track", optionalAuth, async (req, res) => {
  const { deviceId, eventType, metadata } = req.body || {};
  if (!eventType || typeof eventType !== "string") return res.status(400).json({ error: "Missing event type." });
  await logEvent(deviceId, req.userId, eventType, metadata && typeof metadata === "object" ? metadata : {});
  res.json({ ok: true });
});

/* ---------------- feedback & bug reports (works with or without an account) ---------------- */

const feedbackLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "You've sent a lot of messages recently. Please try again later." },
});

app.post("/api/feedback", feedbackLimiter, optionalAuth, async (req, res) => {
  try {
    const { kind: rawKind, message, page, deviceId, category: rawCategory, title: rawTitle } = req.body || {};
    if (!["feedback", "bug", "feature"].includes(rawKind)) return res.status(400).json({ error: "Choose feedback, a feature request or a bug report." });
    if (!message || typeof message !== "string" || !message.trim()) return res.status(400).json({ error: "Please write a message." });
    const kind = rawKind === "bug" ? "bug" : "feedback";
    const category = rawKind === "feature" ? "feature_request"
      : kind === "feedback" ? (["general", "suggestion", "other"].includes(rawCategory) ? rawCategory : "general") : null;
    const title = typeof rawTitle === "string" && rawTitle.trim() ? rawTitle.trim().slice(0, 150) : null;
    await pool.query(
      "INSERT INTO feedback (kind, message, page, user_agent, device_id, user_id, category, title) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
      [
        kind,
        message.trim().slice(0, 4000),
        typeof page === "string" ? page.slice(0, 300) : null,
        String(req.headers["user-agent"] || "").slice(0, 300),
        typeof deviceId === "string" ? deviceId.slice(0, 100) : null,
        req.userId || null,
        category,
        title,
      ]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error("feedback error", e);
    res.status(500).json({ error: "Couldn't send your message. Please try again." });
  }
});

/* ---------------- smart import (AI extraction via Gemini, multi-pass merge) ---------------- */

const MAX_FILE_BYTES = 8 * 1024 * 1024; // ~8MB per file, base64 included

// Rate-limit the AI endpoint per-IP to protect the free Gemini quota (import works for guests too, no account gate).
const importLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 12,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "You've hit the upload limit for now. Please try again in a bit." },
});

function fileToGeminiPart(file, label) {
  if (!file || !file.base64 || !file.mediaType) return null;
  if (file.base64.length > MAX_FILE_BYTES) throw new Error(`${label} file is too large. Please use a file under ~6MB.`);
  if (file.mediaType === "application/pdf" || file.mediaType.startsWith("image/")) {
    return { inline_data: { mime_type: file.mediaType, data: file.base64 } };
  }
  throw new Error(`${label} must be a PDF, JPG, or PNG.`);
}

function normalizeName(name) {
  return (name || "").trim().toLowerCase().replace(/\s+/g, " ");
}

async function callGeminiOnce(parts, temperature) {
  const aiRes = await fetch(
    `${GEMINI_BASE}/v1beta/models/${GEMINI_MODEL}:generateContent?key=${GEMINI_API_KEY}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents: [{ role: "user", parts }],
        generationConfig: { temperature, responseMimeType: "application/json" },
      }),
    }
  );
  if (!aiRes.ok) {
    const errText = await aiRes.text().catch(() => "");
    console.error("Gemini API error", aiRes.status, errText);
    throw new Error("gemini_request_failed");
  }
  const aiJson = await aiRes.json();
  const textOut = aiJson?.candidates?.[0]?.content?.parts?.map((p) => p.text).filter(Boolean).join("") || "";
  if (!textOut) throw new Error("gemini_empty_response");

  let cleaned = textOut.trim();
  cleaned = cleaned.replace(/^```json\s*/i, "").replace(/^```\s*/i, "").replace(/```\s*$/i, "").trim();

  const parsed = JSON.parse(cleaned);
  const subjects = Array.isArray(parsed.subjects) ? parsed.subjects : [];
  return subjects
    .filter((s) => s && s.subject)
    .map((s) => ({
      subject: String(s.subject).trim(),
      examDate: typeof s.examDate === "string" && /^\d{4}-\d{2}-\d{2}$/.test(s.examDate) ? s.examDate : null,
      examTime: typeof s.examTime === "string" && /^\d{2}:\d{2}$/.test(s.examTime) ? s.examTime : null,
      examName: typeof s.examName === "string" && s.examName.trim() ? s.examName.trim().slice(0, 80) : null,
      topics: Array.isArray(s.topics) ? s.topics.filter(Boolean).map((t) => String(t).trim()).slice(0, 80) : [],
    }));
}

// Merges 2-3 independent extraction passes into one result: union of subjects, union of topics per
// subject (deduped by normalized name), and a majority vote on exam date/time. This catches topics
// that any single pass misses.
function mergeExtractionPasses(passResults) {
  const bySubject = new Map();

  passResults.forEach((subjects) => {
    subjects.forEach((s) => {
      const key = normalizeName(s.subject);
      if (!bySubject.has(key)) {
        bySubject.set(key, { subject: s.subject, examDateVotes: {}, examTimeVotes: {}, examNameVotes: {}, topics: new Map(), seen: 0 });
      }
      const entry = bySubject.get(key);
      entry.seen += 1;
      if (s.examName) entry.examNameVotes[s.examName] = (entry.examNameVotes[s.examName] || 0) + 1;
      if (s.examDate) entry.examDateVotes[s.examDate] = (entry.examDateVotes[s.examDate] || 0) + 1;
      if (s.examTime) entry.examTimeVotes[s.examTime] = (entry.examTimeVotes[s.examTime] || 0) + 1;
      s.topics.forEach((t) => {
        const tKey = normalizeName(t);
        if (!entry.topics.has(tKey)) entry.topics.set(tKey, t);
      });
    });
  });

  const pickTopVote = (votes) => {
    const entries = Object.entries(votes);
    if (!entries.length) return null;
    entries.sort((a, b) => b[1] - a[1]);
    return entries[0][0];
  };

  // A date is "uncertain" when the independent readings disagreed about it (or only some of them found one),
  // so the student is asked to double-check it instead of it being trusted silently.
  return Array.from(bySubject.values()).map((entry) => {
    const dateVotes = Object.values(entry.examDateVotes);
    const dateCount = dateVotes.reduce((a, n) => a + n, 0);
    return {
      subject: entry.subject,
      examDate: pickTopVote(entry.examDateVotes),
      examTime: pickTopVote(entry.examTimeVotes),
      examName: pickTopVote(entry.examNameVotes),
      dateUncertain: dateVotes.length > 1 || (dateCount > 0 && dateCount < entry.seen),
      topics: Array.from(entry.topics.values()),
    };
  });
}

// Smart Import is for signed-in students only (it also costs money per request, so it must not be open to anyone).
app.post("/api/import/analyze", importLimiter, requireAuth, async (req, res) => {
  try {
    if (!GEMINI_API_KEY) {
      return res.status(503).json({ error: "Smart Import isn't set up yet. Please try again later." });
    }
    const { syllabusFile, datesheetFile, deviceId } = req.body || {};
    if (!syllabusFile && !datesheetFile) {
      return res.status(400).json({ error: "Please upload at least one document." });
    }

    const parts = [];
    try {
      const dsPart = fileToGeminiPart(datesheetFile, "Date sheet");
      if (dsPart) { parts.push({ text: "This document is the DATE SHEET (exam schedule):" }); parts.push(dsPart); }
      const syPart = fileToGeminiPart(syllabusFile, "Syllabus");
      if (syPart) { parts.push({ text: "This document is the SYLLABUS (chapters/topics):" }); parts.push(syPart); }
    } catch (fileErr) {
      return res.status(400).json({ error: fileErr.message });
    }

    const today = new Date().toISOString().slice(0, 10);
    parts.push({
      text:
        `Extract academic schedule information from the document(s) above. Be thorough — list every chapter, unit, ` +
        `or topic heading you can find, including ones that appear in tables, sub-lists, or smaller print. ` +
        `If both a date sheet and a syllabus are provided, match each subject in the syllabus to its exam date/time in the date sheet, ` +
        `recognizing equivalent/abbreviated subject names as the same subject (for example: "Maths" = "Mathematics", "SST" = "Social Science", "EVS" = "Environmental Studies"). ` +
        `Today's date is ${today}; if a date sheet gives a day/month without a year, assume the nearest future occurrence. ` +
        `Respond with ONLY raw JSON (no markdown code fences, no explanation) matching exactly this shape:\n` +
        `{"subjects":[{"subject":"string","examDate":"YYYY-MM-DD or null","examTime":"HH:MM 24-hour or null","examName":"exam name/type such as Half-Yearly, Unit Test 2, Final Exam, or null","topics":["string", ...]}]}\n` +
        `Topics should be the chapters (or units, if there are no chapters) in the order they appear. ` +
        `Include every subject you can identify from either document, even if some fields are null. Never guess a date that isn't in the document: use null instead.`,
    });

    const temperatures = [0.1, 0.4, 0.7];
    const results = await Promise.allSettled(temperatures.map((t) => callGeminiOnce(parts, t)));
    const succeeded = results.filter((r) => r.status === "fulfilled").map((r) => r.value);

    if (succeeded.length === 0) {
      await logEvent(deviceId, req.userId, "upload_failed", { reason: "all_passes_failed" });
      return res.status(502).json({ error: "Couldn't analyze your documents right now. Please try again." });
    }

    const merged = mergeExtractionPasses(succeeded);
    if (merged.length === 0) {
      await logEvent(deviceId, req.userId, "upload_failed", { reason: "no_subjects_found" });
    } else {
      if (syllabusFile) await logEvent(deviceId, req.userId, "syllabus_uploaded", { subjects: merged.length, passes: succeeded.length });
      if (datesheetFile) await logEvent(deviceId, req.userId, "date_sheet_uploaded", { subjects: merged.length, passes: succeeded.length });
    }

    res.json({ subjects: merged });
  } catch (e) {
    console.error("import analyze error", e);
    await logEvent((req.body || {}).deviceId, req.userId, "api_error", { route: "/api/import/analyze", message: e.message });
    res.status(500).json({ error: "Something went wrong analyzing your documents. Please try again." });
  }
});

/* ---------------- AI study assistant + practice quizzes (Gemini, signed-in students only) ---------------- */
// The Gemini key stays on the server. Each student's own subjects/chapters are loaded here from their account,
// so one student's data can never be used for another. Daily limits protect the shared free quota.
const AI_LIMITS = { ai_chat: 40, quiz_generated: 15 };
const aiLimiter = rateLimit({ windowMs: 60 * 1000, max: 12, standardHeaders: true, legacyHeaders: false, message: { error: "Slow down a little — try again in a minute." } });

async function aiQuotaLeft(userId, kind) {
  const r = await pool.query(`SELECT COUNT(*) AS n FROM events WHERE user_id = $1 AND event_type = $2 AND created_at > now() - interval '1 day'`, [userId, kind]);
  return AI_LIMITS[kind] - Number(r.rows[0].n);
}

async function callGemini({ system, contents, json = false, temperature = 0.6, maxTokens = 1400 }) {
  const aiRes = await fetch(`${GEMINI_BASE}/v1beta/models/${GEMINI_MODEL}:generateContent?key=${GEMINI_API_KEY}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      systemInstruction: { parts: [{ text: system }] },
      contents,
      generationConfig: { temperature, maxOutputTokens: maxTokens, ...(json ? { responseMimeType: "application/json" } : {}) },
    }),
    signal: AbortSignal.timeout(45000),
  });
  if (!aiRes.ok) { console.error("Gemini error", aiRes.status, (await aiRes.text().catch(() => "")).slice(0, 300)); throw new Error("gemini_request_failed"); }
  const j = await aiRes.json();
  const text = j?.candidates?.[0]?.content?.parts?.map((p) => p.text).filter(Boolean).join("") || "";
  if (!text) throw new Error("gemini_empty_response");
  return text;
}

// A compact summary of the student's own syllabus, used as context.
async function studyContext(userId) {
  const r = await pool.query("SELECT data FROM user_data WHERE user_id = $1", [userId]);
  const data = (r.rows[0] && r.rows[0].data) || {};
  const exams = Array.isArray(data.exams) ? data.exams : [];
  const label = { not_started: "not started", in_progress: "learning", completed: "completed", needs_revision: "needs revision", mastered: "mastered" };
  const lines = exams.slice(0, 20).map((e) => {
    const date = e.examDate && !Number.isNaN(new Date(e.examDate).getTime()) ? ` — ${e.examName || "exam"} on ${new Date(e.examDate).toISOString().slice(0, 10)}` : " — no exam date";
    const ch = (Array.isArray(e.chapters) ? e.chapters : []).slice(0, 40)
      .map((c) => `${String(c.name || "").slice(0, 80)} (${label[c.status] || (c.completed ? "completed" : "not started")}, ${c.difficulty || "Medium"})`).join("; ");
    return `- ${String(e.subject || "").slice(0, 60)}${date}: ${ch || "no chapters yet"}`;
  });
  return { exams, text: lines.length ? lines.join("\n") : "The student hasn't added any subjects yet." };
}

const findChapter = (exams, examId, chapterId) => {
  const e = exams.find((x) => x.id === examId);
  const c = e && Array.isArray(e.chapters) ? e.chapters.find((x) => x.id === chapterId) : null;
  return { exam: e || null, chapter: c || null };
};

app.post("/api/ai/chat", aiLimiter, requireAuth, async (req, res) => {
  try {
    if (!GEMINI_API_KEY) return res.status(503).json({ error: "The AI assistant isn't set up yet." });
    const left = await aiQuotaLeft(req.userId, "ai_chat");
    if (left <= 0) return res.status(429).json({ error: "You've reached today's limit for the AI assistant. It resets tomorrow." });
    const body = req.body || {};
    const history = (Array.isArray(body.messages) ? body.messages : []).slice(-12)
      .filter((m) => m && typeof m.text === "string" && m.text.trim() && (m.role === "user" || m.role === "assistant"))
      .map((m) => ({ role: m.role === "assistant" ? "model" : "user", parts: [{ text: m.text.slice(0, 2000) }] }));
    if (!history.length || history[history.length - 1].role !== "user") return res.status(400).json({ error: "Type a question first." });
    const ctx = await studyContext(req.userId);
    const focus = body.focus && body.focus.examId ? findChapter(ctx.exams, body.focus.examId, body.focus.chapterId) : null;
    const focusLine = focus && focus.exam ? `\nThe student is currently asking about: ${focus.exam.subject}${focus.chapter ? ` — ${focus.chapter.name}` : ""}.` : "";
    const today = new Date().toISOString().slice(0, 10);
    const system =
      `You are the ExamFlow Study Assistant, helping a school student learn and revise. Today is ${today}.\n` +
      `Style: friendly, encouraging and clear; short paragraphs or brief bullet lists; plain language; keep answers under about 220 words unless the student asks for more. ` +
      `Use simple Markdown only (**bold**, bullet lists with "- ", numbered lists). No tables, no headings, no emojis overload.\n` +
      `Teaching: explain step by step and check understanding. When asked to quiz, ask one question at a time and wait for the answer. ` +
      `For homework, help the student understand how to solve it rather than only giving the final answer. If you're not sure about a fact, say so.\n` +
      `"What should I study today?": use the student's subjects below — prefer chapters that need revision, are still being learned, or have the nearest exam dates.\n` +
      `Stay on study-related topics. If a question isn't about studying, answer very briefly and steer back. Never help with cheating on a live test, and don't give harmful or adult content.\n` +
      `The student's subjects and chapters (their own data):\n${ctx.text}${focusLine}`;
    const reply = await callGemini({ system, contents: history, temperature: 0.6, maxTokens: 1200 });
    await logEvent(null, req.userId, "ai_chat", { chars: reply.length });
    res.json({ reply: reply.trim(), left: left - 1 });
  } catch (e) {
    console.error("ai chat error", e.message);
    res.status(502).json({ error: "The assistant couldn't answer right now. Please try again in a moment." });
  }
});

const QUIZ_TYPES = { mcq: "multiple-choice questions with 4 options each", short: "short-answer questions", tf: "true/false questions", mixed: "a mix of multiple-choice, true/false and short-answer questions", quick: "quick recall questions for fast revision (mostly multiple-choice and true/false)" };

function cleanQuiz(raw, count) {
  const qs = (Array.isArray(raw && raw.questions) ? raw.questions : []).slice(0, count);
  const out = [];
  for (const q of qs) {
    if (!q || typeof q.question !== "string" || !q.question.trim()) continue;
    const base = { question: q.question.trim().slice(0, 600), explanation: typeof q.explanation === "string" ? q.explanation.trim().slice(0, 600) : "", topic: typeof q.topic === "string" ? q.topic.trim().slice(0, 80) : "" };
    if (q.type === "mcq" && Array.isArray(q.options) && q.options.length >= 2) {
      const options = q.options.slice(0, 5).map((o) => String(o).trim().slice(0, 200)).filter(Boolean);
      const answer = Number(q.answer);
      if (options.length >= 2 && Number.isInteger(answer) && answer >= 0 && answer < options.length) out.push({ type: "mcq", ...base, options, answer });
    } else if (q.type === "tf" && typeof q.answer === "boolean") {
      out.push({ type: "tf", ...base, answer: q.answer });
    } else if (q.type === "short" && (typeof q.answer === "string" || typeof q.answer === "number")) {
      out.push({ type: "short", ...base, answer: String(q.answer).trim().slice(0, 400) });
    }
  }
  return out;
}

app.post("/api/ai/quiz", aiLimiter, requireAuth, async (req, res) => {
  try {
    if (!GEMINI_API_KEY) return res.status(503).json({ error: "Practice quizzes aren't set up yet." });
    const left = await aiQuotaLeft(req.userId, "quiz_generated");
    if (left <= 0) return res.status(429).json({ error: "You've reached today's limit for practice quizzes. It resets tomorrow." });
    const body = req.body || {};
    const type = QUIZ_TYPES[body.type] ? body.type : "mixed";
    const count = Math.min(10, Math.max(3, Number.parseInt(body.count, 10) || 5));
    const level = ["easy", "medium", "hard"].includes(body.level) ? body.level : "medium";
    const ctx = await studyContext(req.userId);
    const { exam, chapter } = body.examId ? findChapter(ctx.exams, body.examId, body.chapterId) : { exam: null, chapter: null };
    const customTopic = typeof body.topic === "string" ? body.topic.trim().slice(0, 150) : "";
    const subject = exam ? exam.subject : (typeof body.subject === "string" ? body.subject.trim().slice(0, 60) : "");
    const topic = chapter ? chapter.name : customTopic;
    if (!topic && !subject) return res.status(400).json({ error: "Choose a chapter or type a topic." });
    const system =
      `You write accurate practice questions for school students. Only include questions you are confident are factually correct, ` +
      `with one clearly correct answer. Keep wording clear and age-appropriate. Respond with ONLY JSON.`;
    const prompt =
      `Write ${count} ${QUIZ_TYPES[type]} at ${level} difficulty on ${topic ? `"${topic}"` : "the subject"}${subject ? ` (subject: ${subject})` : ""}.\n` +
      `JSON shape: {"title":"string","questions":[{"type":"mcq"|"tf"|"short","question":"string","options":["A","B","C","D"] (mcq only),` +
      `"answer": index of the correct option (mcq) | true/false (tf) | short model answer string (short),"explanation":"one or two sentences","topic":"the sub-topic this tests"}]}`;
    const text = await callGemini({ system, contents: [{ role: "user", parts: [{ text: prompt }] }], json: true, temperature: 0.4, maxTokens: 3000 });
    let parsed;
    try { parsed = JSON.parse(text.replace(/^```json\s*|```\s*$/g, "").trim()); } catch (e) { throw new Error("quiz_parse_failed"); }
    const questions = cleanQuiz(parsed, count);
    if (questions.length < 2) return res.status(502).json({ error: "Couldn't make a good quiz for that topic. Try again or pick another chapter." });
    await logEvent(null, req.userId, "quiz_generated", { type, count: questions.length });
    res.json({
      quiz: { title: typeof parsed.title === "string" ? parsed.title.slice(0, 120) : `${topic || subject} practice`, type, level, subject, topic, examId: exam ? exam.id : null, chapterId: chapter ? chapter.id : null, questions },
      left: left - 1,
    });
  } catch (e) {
    console.error("ai quiz error", e.message);
    res.status(502).json({ error: "Couldn't create a quiz right now. Please try again in a moment." });
  }
});

/* ---------------- admin (read-only analytics) ---------------- */
// Access is decided by the server from the database (users.is_admin), never by anything the browser sends.
// Every route below is read-only: none of them modify student data.

function requireAdmin(req, res, next) {
  requireAuth(req, res, async () => {
    try {
      const r = await pool.query("SELECT is_admin FROM users WHERE id = $1", [req.userId]);
      if (!r.rows[0] || r.rows[0].is_admin !== true) {
        return res.status(403).json({ error: "This account doesn't have access to the admin panel." });
      }
      res.set("Cache-Control", "no-store");
      next();
    } catch (e) {
      console.error("requireAdmin error", e);
      res.status(500).json({ error: "Couldn't verify admin access." });
    }
  });
}

// Timezone used for "today", upcoming/past and daily charts.
const ADMIN_TZ = "Asia/Kolkata";
const TODAY = `(now() AT TIME ZONE '${ADMIN_TZ}')::date`;
const FRONTEND_URL = FRONTEND_ORIGINS[0] || "https://examflow-1f03.onrender.com";

// Expands each student's saved study data (one JSON document per student) into rows:
//   ex = exams, ch = syllabus topics (chapters), se = planned study sessions (planner tasks).
const STUDY_CTE = `
  ex AS (
    SELECT ud.user_id,
           e->>'id' AS exam_id,
           NULLIF(btrim(e->>'subject'), '') AS subject,
           ef_safe_date(e->>'examDate') AS exam_date,
           NULLIF(e->>'priority', '') AS priority,
           CASE WHEN jsonb_typeof(e->'chapters') = 'array' THEN e->'chapters' ELSE '[]'::jsonb END AS chapters
    FROM user_data ud,
         jsonb_array_elements(CASE WHEN jsonb_typeof(ud.data->'exams') = 'array' THEN ud.data->'exams' ELSE '[]'::jsonb END) e
    WHERE jsonb_typeof(e) = 'object'
  ),
  ch AS (
    SELECT ex.user_id, ex.exam_id, ex.subject,
           c->>'id' AS chapter_id,
           NULLIF(btrim(c->>'name'), '') AS name,
           NULLIF(c->>'difficulty', '') AS difficulty,
           COALESCE(c->>'status' = 'completed' OR c->>'completed' = 'true', false) AS done,
           (COALESCE(btrim(c->>'notes'), '') <> '') AS has_note,
           CASE WHEN c->>'estMinutes' ~ '^[0-9]+$' THEN (c->>'estMinutes')::int END AS est_minutes
    FROM ex, jsonb_array_elements(ex.chapters) c
    WHERE jsonb_typeof(c) = 'object'
  ),
  se AS (
    SELECT ud.user_id,
           s->>'id' AS session_id,
           s->>'examId' AS exam_id,
           s->>'chapterId' AS chapter_id,
           NULLIF(btrim(s->>'chapterName'), '') AS chapter_name,
           NULLIF(btrim(s->>'subject'), '') AS subject,
           ef_safe_date(s->>'date') AS due_date,
           NULLIF(s->>'start', '') AS start_time,
           NULLIF(s->>'end', '') AS end_time,
           COALESCE(s->>'completed' = 'true', false) AS done
    FROM user_data ud,
         jsonb_array_elements(CASE WHEN jsonb_typeof(ud.data->'sessions') = 'array' THEN ud.data->'sessions' ELSE '[]'::jsonb END) s
    WHERE jsonb_typeof(s) = 'object'
  )`;

// Last time each student did anything we can see: logged-in API use, saving study data, or a tracked action.
const SEEN_CTE = `
  seen AS (
    SELECT u.id AS user_id,
           GREATEST(u.last_active_at, ud.updated_at, ev.last_ev) AS last_seen
    FROM users u
    LEFT JOIN user_data ud ON ud.user_id = u.id
    LEFT JOIN (
      SELECT user_id, MAX(created_at) AS last_ev FROM events
      WHERE user_id IS NOT NULL AND event_type NOT IN ('admin_panel_viewed', 'user_registered')
      GROUP BY user_id
    ) ev ON ev.user_id = u.id
  )`;

const TASK_STATUS = `CASE WHEN se.done THEN 'completed' WHEN se.due_date < ${TODAY} THEN 'overdue' ELSE 'pending' END`;
const EXAM_STATUS = `CASE WHEN ex.exam_date IS NULL THEN 'no_date' WHEN ex.exam_date < ${TODAY} THEN 'past' ELSE 'upcoming' END`;

const num = (v) => Number(v || 0);
const clampInt = (v, def, min, max) => Math.min(max, Math.max(min, Number.parseInt(v, 10) || def));
const isoDate = (v) => (typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v) ? v : null);
const cleanText = (v, max = 100) => (typeof v === "string" ? v.trim().slice(0, max) : "");

function adminError(res, what, e) {
  console.error(`admin ${what} error`, e);
  res.status(500).json({ error: `Unable to load ${what}. Please try again.` });
}

/* ---- overview ---- */
app.get("/api/admin/overview", requireAdmin, async (req, res) => {
  try {
    const [users, devices, study, fb] = await Promise.all([
      pool.query(`
        WITH ${SEEN_CTE}
        SELECT
          COUNT(*) AS total,
          COUNT(*) FILTER (WHERE (u.created_at AT TIME ZONE '${ADMIN_TZ}')::date = ${TODAY}) AS new_today,
          COUNT(*) FILTER (WHERE u.created_at >= now() - interval '7 days') AS new_7d,
          COUNT(*) FILTER (WHERE u.created_at >= now() - interval '30 days') AS new_30d,
          COUNT(*) FILTER (WHERE seen.last_seen >= now() - interval '1 day') AS active_1d,
          COUNT(*) FILTER (WHERE seen.last_seen >= now() - interval '7 days') AS active_7d,
          COUNT(*) FILTER (WHERE seen.last_seen >= now() - interval '30 days') AS active_30d
        FROM users u JOIN seen ON seen.user_id = u.id`),
      pool.query(`
        SELECT COUNT(DISTINCT device_id) AS ever,
               COUNT(DISTINCT device_id) FILTER (WHERE created_at >= now() - interval '1 day') AS d1,
               COUNT(DISTINCT device_id) FILTER (WHERE created_at >= now() - interval '7 days') AS d7
        FROM events WHERE device_id IS NOT NULL AND event_type <> 'admin_panel_viewed'`),
      pool.query(`
        WITH ${STUDY_CTE},
        exam_topics AS (SELECT user_id, exam_id, COUNT(*) AS n, COUNT(*) FILTER (WHERE done) AS d FROM ch GROUP BY user_id, exam_id)
        SELECT
          (SELECT COUNT(*) FROM ex) AS exams,
          (SELECT COUNT(*) FROM ex WHERE exam_date >= ${TODAY}) AS upcoming,
          (SELECT COUNT(*) FROM ex WHERE exam_date < ${TODAY}) AS past,
          (SELECT COUNT(*) FROM exam_topics WHERE n > 0 AND n = d) AS syllabus_complete,
          (SELECT COUNT(*) FROM ch) AS topics,
          (SELECT COUNT(*) FROM ch WHERE done) AS topics_done,
          (SELECT COUNT(*) FROM ch WHERE has_note) AS notes,
          (SELECT COUNT(*) FROM se) AS tasks,
          (SELECT COUNT(*) FROM se WHERE done) AS tasks_done,
          (SELECT COUNT(*) FROM se WHERE NOT done AND due_date < ${TODAY}) AS tasks_overdue`),
      pool.query(`
        SELECT COUNT(*) FILTER (WHERE f.kind = 'feedback' AND COALESCE(f.category, 'general') <> 'feature_request') AS feedback,
               COUNT(*) FILTER (WHERE f.kind = 'feedback' AND f.category = 'feature_request') AS features,
               COUNT(*) FILTER (WHERE f.kind = 'bug') AS bugs,
               COUNT(*) FILTER (WHERE ${OPEN_BUG_SQL}) AS open_bugs,
               COUNT(*) FILTER (WHERE f.status = 'new' AND f.kind = 'feedback' AND COALESCE(f.category, 'general') <> 'feature_request') AS new_feedback,
               COUNT(*) FILTER (WHERE f.status = 'new' AND f.category = 'feature_request') AS new_features,
               COUNT(*) FILTER (WHERE f.created_at >= now() - interval '7 days') AS last_7d
        FROM feedback f`),
    ]);
    const u = users.rows[0], d = devices.rows[0], s = study.rows[0], f = fb.rows[0];
    await logEvent(null, req.userId, "admin_panel_viewed", {});
    res.json({
      timezone: ADMIN_TZ,
      users: {
        total: num(u.total), newToday: num(u.new_today), new7d: num(u.new_7d), new30d: num(u.new_30d),
        active1d: num(u.active_1d), active7d: num(u.active_7d), active30d: num(u.active_30d),
      },
      devices: { ever: num(d.ever), active1d: num(d.d1), active7d: num(d.d7) },
      exams: { total: num(s.exams), upcoming: num(s.upcoming), past: num(s.past), syllabusComplete: num(s.syllabus_complete) },
      topics: { total: num(s.topics), completed: num(s.topics_done), withNotes: num(s.notes) },
      tasks: {
        total: num(s.tasks), completed: num(s.tasks_done), overdue: num(s.tasks_overdue),
        pending: num(s.tasks) - num(s.tasks_done) - num(s.tasks_overdue),
      },
      // Bug reports have no status yet, so every bug report counts as open until statuses are added.
      feedback: {
        feedback: num(f.feedback), features: num(f.features), bugs: num(f.bugs), openBugs: num(f.open_bugs),
        newFeedback: num(f.new_feedback), newFeatures: num(f.new_features), last7d: num(f.last_7d), statusTracked: true,
      },
    });
  } catch (e) {
    adminError(res, "overview", e);
  }
});

/* ---- charts: time series for any range ---- */
app.get("/api/admin/charts", requireAdmin, async (req, res) => {
  try {
    const range = ["7", "30", "90", "all"].includes(String(req.query.range)) ? String(req.query.range) : "30";
    let start;
    if (range === "all") {
      const r = await pool.query(`
        SELECT LEAST(
          (SELECT MIN(created_at) FROM users), (SELECT MIN(created_at) FROM events), (SELECT MIN(created_at) FROM feedback)
        ) AS first`);
      start = r.rows[0].first ? new Date(r.rows[0].first) : new Date();
    } else {
      start = new Date(Date.now() - (Number(range) - 1) * 86400000);
    }
    const spanDays = Math.ceil((Date.now() - start.getTime()) / 86400000) + 1;
    const requestedUnit = ["day", "week", "month"].includes(req.query.unit) ? req.query.unit : null;
    const unit = requestedUnit || (spanDays > 120 ? "week" : "day");
    const bucketTs = (col) => `date_trunc('${unit}', (${col} AT TIME ZONE '${ADMIN_TZ}'))::date`;
    const bucketDate = (col) => `date_trunc('${unit}', ${col})::date`;

    const result = await pool.query(
      `
      WITH ${STUDY_CTE},
      b AS (
        SELECT generate_series(
          date_trunc('${unit}', ($1::timestamptz AT TIME ZONE '${ADMIN_TZ}'))::date,
          ${TODAY},
          interval '1 ${unit}'
        )::date AS bucket
      ),
      signups AS (SELECT ${bucketTs("created_at")} AS bucket, COUNT(*) AS n FROM users GROUP BY 1),
      act AS (
        SELECT ${bucketTs("created_at")} AS bucket, COUNT(DISTINCT device_id) AS devices, COUNT(DISTINCT user_id) AS users
        FROM events WHERE event_type NOT IN ('admin_panel_viewed') GROUP BY 1
      ),
      exams_created AS (SELECT ${bucketTs("created_at")} AS bucket, COUNT(*) AS n FROM events WHERE event_type = 'exam_created' GROUP BY 1),
      tasks AS (
        SELECT ${bucketDate("due_date")} AS bucket, COUNT(*) AS planned, COUNT(*) FILTER (WHERE done) AS completed
        FROM se WHERE due_date IS NOT NULL GROUP BY 1
      ),
      fb AS (
        SELECT ${bucketTs("created_at")} AS bucket,
               COUNT(*) FILTER (WHERE kind = 'feedback') AS feedback, COUNT(*) FILTER (WHERE kind = 'bug') AS bugs
        FROM feedback GROUP BY 1
      )
      SELECT b.bucket::text AS bucket,
             COALESCE(signups.n, 0) AS signups,
             COALESCE(act.devices, 0) AS active_devices,
             COALESCE(act.users, 0) AS active_users,
             COALESCE(exams_created.n, 0) AS exams_created,
             COALESCE(tasks.planned, 0) AS tasks_planned,
             COALESCE(tasks.completed, 0) AS tasks_completed,
             COALESCE(fb.feedback, 0) AS feedback,
             COALESCE(fb.bugs, 0) AS bugs
      FROM b
      LEFT JOIN signups USING (bucket) LEFT JOIN act USING (bucket) LEFT JOIN exams_created USING (bucket)
      LEFT JOIN tasks USING (bucket) LEFT JOIN fb USING (bucket)
      ORDER BY b.bucket`,
      [start.toISOString()]
    );
    res.json({
      range, unit, timezone: ADMIN_TZ,
      points: result.rows.map((r) => ({
        date: String(r.bucket).slice(0, 10),
        signups: num(r.signups), activeDevices: num(r.active_devices), activeUsers: num(r.active_users),
        examsCreated: num(r.exams_created), tasksPlanned: num(r.tasks_planned), tasksCompleted: num(r.tasks_completed),
        feedback: num(r.feedback), bugs: num(r.bugs),
      })),
    });
  } catch (e) {
    adminError(res, "charts", e);
  }
});

/* ---- live activity feed (real events only) ---- */
const FEED_EVENTS = ["exam_created", "study_plan_created", "focus_session_completed", "syllabus_uploaded", "date_sheet_uploaded", "user_login"];

async function activityFeed({ userId = null, limit = 30 }) {
  const params = [limit, FEED_EVENTS];
  let userFilterUsers = "", userFilterEvents = "", userFilterFb = "";
  if (userId) {
    params.push(userId);
    userFilterUsers = "WHERE u.id = $3";
    userFilterEvents = "AND ev.user_id = $3";
    userFilterFb = "WHERE f.user_id = $3";
  }
  const r = await pool.query(
    `
    SELECT * FROM (
      SELECT 'student_registered' AS type, u.created_at AS at, u.id AS user_id, '{}'::jsonb AS meta FROM users u ${userFilterUsers}
      UNION ALL
      SELECT ev.event_type AS type, ev.created_at AS at, ev.user_id, ev.metadata AS meta
      FROM events ev WHERE ev.event_type = ANY($2::text[]) ${userFilterEvents}
      UNION ALL
      SELECT CASE WHEN f.kind = 'bug' THEN 'bug_reported' WHEN f.category = 'feature_request' THEN 'feature_requested' ELSE 'feedback_submitted' END AS type, f.created_at AS at, f.user_id,
             jsonb_build_object('page', f.page) AS meta
      FROM feedback f ${userFilterFb}
    ) a
    LEFT JOIN (SELECT id, name FROM users) nm ON nm.id = a.user_id
    ORDER BY a.at DESC
    LIMIT $1`,
    params
  );
  const SAFE_META = ["priority", "studiedMinutes", "subjects", "page"];
  return r.rows.map((row) => {
    const meta = {};
    for (const k of SAFE_META) if (row.meta && row.meta[k] !== undefined) meta[k] = row.meta[k];
    return { type: row.type, at: row.at, userId: row.user_id, userName: row.name || null, meta };
  });
}

app.get("/api/admin/feed", requireAdmin, async (req, res) => {
  try {
    res.json({ items: await activityFeed({ limit: clampInt(req.query.limit, 30, 1, 100) }) });
  } catch (e) {
    adminError(res, "recent activity", e);
  }
});

/* ---- students ---- */
app.get("/api/admin/users", requireAdmin, async (req, res) => {
  try {
    const limit = clampInt(req.query.limit, 25, 1, 100);
    const page = clampInt(req.query.page, 1, 1, 100000);
    const q = cleanText(req.query.q);
    const status = ["active", "inactive", "disabled"].includes(req.query.status) ? req.query.status : "all";
    const sort = { newest: "u.created_at DESC", oldest: "u.created_at ASC", last_active: "seen.last_seen DESC NULLS LAST" }[req.query.sort] || "u.created_at DESC";
    const joinedFrom = isoDate(req.query.joinedFrom);
    const joinedTo = isoDate(req.query.joinedTo);

    const where = [];
    const params = [];
    const add = (v) => { params.push(v); return `$${params.length}`; };
    if (q) { const p = add(`%${q}%`); where.push(`(u.name ILIKE ${p} OR u.email ILIKE ${p})`); }
    if (status === "active") where.push(`seen.last_seen >= now() - interval '30 days'`);
    if (status === "inactive") where.push(`(seen.last_seen IS NULL OR seen.last_seen < now() - interval '30 days')`);
    if (status === "disabled") where.push(`u.is_disabled = true`);
    if (joinedFrom) where.push(`(u.created_at AT TIME ZONE '${ADMIN_TZ}')::date >= ${add(joinedFrom)}::date`);
    if (joinedTo) where.push(`(u.created_at AT TIME ZONE '${ADMIN_TZ}')::date <= ${add(joinedTo)}::date`);
    const whereSql = where.length ? "WHERE " + where.join(" AND ") : "";
    const limitP = add(limit), offsetP = add((page - 1) * limit);

    const rows = await pool.query(
      `
      WITH ${STUDY_CTE}, ${SEEN_CTE},
      exs AS (SELECT user_id, COUNT(*) AS n, COUNT(*) FILTER (WHERE exam_date >= ${TODAY}) AS upcoming FROM ex GROUP BY user_id),
      ses AS (SELECT user_id, COUNT(*) AS n, COUNT(*) FILTER (WHERE done) AS done FROM se GROUP BY user_id),
      filtered AS (
        SELECT u.id, u.name, u.email, u.created_at, u.is_admin, u.is_disabled, seen.last_seen
        FROM users u JOIN seen ON seen.user_id = u.id
        ${whereSql}
      )
      SELECT f.*, COALESCE(exs.n, 0) AS exams, COALESCE(exs.upcoming, 0) AS upcoming,
             COALESCE(ses.n, 0) AS tasks, COALESCE(ses.done, 0) AS tasks_done,
             (SELECT COUNT(*) FROM filtered) AS total_count
      FROM filtered f
      LEFT JOIN exs ON exs.user_id = f.id
      LEFT JOIN ses ON ses.user_id = f.id
      ORDER BY ${sort.replace("u.", "f.").replace("seen.", "f.")}
      LIMIT ${limitP} OFFSET ${offsetP}`,
      params
    );
    let total = rows.rows.length ? num(rows.rows[0].total_count) : 0;
    if (!rows.rows.length && page > 1) {
      const c = await pool.query(`WITH ${SEEN_CTE} SELECT COUNT(*) AS n FROM users u JOIN seen ON seen.user_id = u.id ${whereSql}`, params.slice(0, params.length - 2));
      total = num(c.rows[0].n);
    }
    res.json({
      page, limit, total,
      users: rows.rows.map((r) => ({
        id: r.id, name: r.name, email: r.email, isAdmin: r.is_admin === true, accountStatus: r.is_disabled ? "disabled" : "active",
        createdAt: r.created_at, lastActiveAt: r.last_seen,
        exams: num(r.exams), upcomingExams: num(r.upcoming), tasks: num(r.tasks), tasksCompleted: num(r.tasks_done),
      })),
    });
  } catch (e) {
    adminError(res, "student data", e);
  }
});

app.get("/api/admin/users/:id", requireAdmin, async (req, res) => {
  try {
    const id = Number.parseInt(req.params.id, 10);
    if (!id) return res.status(400).json({ error: "Invalid student id." });
    const u = await pool.query(
      `WITH ${SEEN_CTE} SELECT u.id, u.name, u.email, u.created_at, u.is_admin, u.is_disabled, u.disabled_at, u.disabled_reason, seen.last_seen FROM users u JOIN seen ON seen.user_id = u.id WHERE u.id = $1`,
      [id]
    );
    if (!u.rows[0]) return res.status(404).json({ error: "Student not found." });
    const [exams, tasks, feed] = await Promise.all([
      pool.query(
        `
        WITH ${STUDY_CTE},
        t AS (SELECT exam_id, COUNT(*) AS n, COUNT(*) FILTER (WHERE done) AS d FROM ch WHERE user_id = $1 GROUP BY exam_id)
        SELECT ex.exam_id, ex.subject, ex.exam_date::text AS exam_date, ex.priority, ${EXAM_STATUS} AS status,
               COALESCE(t.n, 0) AS topics, COALESCE(t.d, 0) AS topics_done
        FROM ex LEFT JOIN t ON t.exam_id = ex.exam_id
        WHERE ex.user_id = $1
        ORDER BY ex.exam_date NULLS LAST`,
        [id]
      ),
      pool.query(
        `
        WITH ${STUDY_CTE}
        SELECT COUNT(*) AS total, COUNT(*) FILTER (WHERE done) AS done,
               COUNT(*) FILTER (WHERE NOT done AND due_date < ${TODAY}) AS overdue
        FROM se WHERE user_id = $1`,
        [id]
      ),
      activityFeed({ userId: id, limit: 15 }),
    ]);
    const r = u.rows[0], t = tasks.rows[0];
    const examRows = exams.rows.map((e) => ({
      id: e.exam_id, subject: e.subject, examDate: e.exam_date, priority: e.priority, status: e.status,
      topics: num(e.topics), topicsCompleted: num(e.topics_done),
    }));
    res.json({
      student: {
        id: r.id, name: r.name, email: r.email, isAdmin: r.is_admin === true, accountStatus: r.is_disabled ? "disabled" : "active",
        disabledAt: r.disabled_at, disabledReason: r.disabled_reason,
        createdAt: r.created_at, lastActiveAt: r.last_seen,
      },
      exams: examRows,
      examSummary: {
        total: examRows.length,
        upcoming: examRows.filter((e) => e.status === "upcoming").length,
        past: examRows.filter((e) => e.status === "past").length,
        syllabusComplete: examRows.filter((e) => e.topics > 0 && e.topics === e.topicsCompleted).length,
      },
      tasks: { total: num(t.total), completed: num(t.done), overdue: num(t.overdue), pending: num(t.total) - num(t.done) - num(t.overdue) },
      subjects: [...new Set(examRows.map((e) => e.subject).filter(Boolean))],
      activity: feed,
    });
  } catch (e) {
    adminError(res, "this student", e);
  }
});

/* ---- exams ---- */
app.get("/api/admin/exams", requireAdmin, async (req, res) => {
  try {
    const limit = clampInt(req.query.limit, 25, 1, 100);
    const page = clampInt(req.query.page, 1, 1, 100000);
    const status = ["upcoming", "past", "syllabus_complete", "no_date"].includes(req.query.status) ? req.query.status : "all";
    const subject = cleanText(req.query.subject);
    const q = cleanText(req.query.q);
    const from = isoDate(req.query.from), to = isoDate(req.query.to);

    const where = [];
    const params = [];
    const add = (v) => { params.push(v); return `$${params.length}`; };
    if (status === "upcoming") where.push(`x.exam_date >= ${TODAY}`);
    if (status === "past") where.push(`x.exam_date < ${TODAY}`);
    if (status === "no_date") where.push(`x.exam_date IS NULL`);
    if (status === "syllabus_complete") where.push(`x.topics > 0 AND x.topics = x.topics_done`);
    if (subject) where.push(`lower(x.subject) = lower(${add(subject)})`);
    if (q) { const p = add(`%${q}%`); where.push(`(x.subject ILIKE ${p} OR x.student_name ILIKE ${p} OR x.student_email ILIKE ${p})`); }
    if (from) where.push(`x.exam_date >= ${add(from)}::date`);
    if (to) where.push(`x.exam_date <= ${add(to)}::date`);
    const whereSql = where.length ? "WHERE " + where.join(" AND ") : "";
    const limitP = add(limit), offsetP = add((page - 1) * limit);

    const base = `
      WITH ${STUDY_CTE},
      t AS (SELECT user_id, exam_id, COUNT(*) AS n, COUNT(*) FILTER (WHERE done) AS d FROM ch GROUP BY user_id, exam_id),
      x AS (
        SELECT ex.user_id, ex.exam_id, ex.subject, ex.exam_date, ex.priority, ${EXAM_STATUS} AS status,
               COALESCE(t.n, 0) AS topics, COALESCE(t.d, 0) AS topics_done,
               u.name AS student_name, u.email AS student_email
        FROM ex JOIN users u ON u.id = ex.user_id
        LEFT JOIN t ON t.user_id = ex.user_id AND t.exam_id = ex.exam_id
      )`;
    const [rows, stats, subjects] = await Promise.all([
      pool.query(
        `${base}, filtered AS (SELECT * FROM x ${whereSql})
         SELECT *, exam_date::text AS exam_date_text, (SELECT COUNT(*) FROM filtered) AS total_count
         FROM filtered ORDER BY (exam_date < ${TODAY}), exam_date NULLS LAST, subject
         LIMIT ${limitP} OFFSET ${offsetP}`,
        params
      ),
      pool.query(`${base}
        SELECT COUNT(*) AS total,
               COUNT(*) FILTER (WHERE exam_date >= ${TODAY}) AS upcoming,
               COUNT(*) FILTER (WHERE exam_date < ${TODAY}) AS past,
               COUNT(*) FILTER (WHERE exam_date >= date_trunc('week', ${TODAY})::date AND exam_date < date_trunc('week', ${TODAY})::date + 7) AS this_week,
               COUNT(*) FILTER (WHERE topics > 0 AND topics = topics_done) AS syllabus_complete
        FROM x`),
      pool.query(`WITH ${STUDY_CTE}
        SELECT MIN(subject) AS subject, COUNT(*) AS n FROM ex WHERE subject IS NOT NULL
        GROUP BY lower(subject) ORDER BY n DESC, MIN(subject) LIMIT 100`),
    ]);
    const s = stats.rows[0];
    res.json({
      page, limit, total: rows.rows.length ? num(rows.rows[0].total_count) : 0,
      stats: { total: num(s.total), upcoming: num(s.upcoming), past: num(s.past), thisWeek: num(s.this_week), syllabusComplete: num(s.syllabus_complete) },
      subjects: subjects.rows.map((r) => r.subject),
      exams: rows.rows.map((r) => ({
        userId: r.user_id, examId: r.exam_id, subject: r.subject, examDate: r.exam_date_text, priority: r.priority, status: r.status,
        topics: num(r.topics), topicsCompleted: num(r.topics_done),
        studentName: r.student_name, studentEmail: r.student_email,
      })),
    });
  } catch (e) {
    adminError(res, "exams", e);
  }
});

app.get("/api/admin/exams/:userId/:examId", requireAdmin, async (req, res) => {
  try {
    const userId = Number.parseInt(req.params.userId, 10);
    const examId = cleanText(req.params.examId, 200);
    if (!userId || !examId) return res.status(400).json({ error: "Invalid exam." });
    const exam = await pool.query(
      `WITH ${STUDY_CTE}
       SELECT ex.exam_id, ex.subject, ex.exam_date::text AS exam_date, ex.priority, ${EXAM_STATUS} AS status, u.id AS uid, u.name, u.email
       FROM ex JOIN users u ON u.id = ex.user_id WHERE ex.user_id = $1 AND ex.exam_id = $2 LIMIT 1`,
      [userId, examId]
    );
    if (!exam.rows[0]) return res.status(404).json({ error: "Exam not found." });
    const [topics, sessions] = await Promise.all([
      pool.query(
        `WITH ${STUDY_CTE} SELECT name, difficulty, done, has_note, est_minutes FROM ch WHERE user_id = $1 AND exam_id = $2`,
        [userId, examId]
      ),
      pool.query(
        `WITH ${STUDY_CTE}
         SELECT se.chapter_name, se.due_date::text AS due_date, se.start_time, se.end_time, ${TASK_STATUS} AS status
         FROM se WHERE se.user_id = $1 AND se.exam_id = $2 ORDER BY se.due_date NULLS LAST, se.start_time`,
        [userId, examId]
      ),
    ]);
    const e = exam.rows[0];
    res.json({
      exam: { id: e.exam_id, subject: e.subject, examDate: e.exam_date, priority: e.priority, status: e.status, createdAt: null },
      student: { id: e.uid, name: e.name, email: e.email },
      // Topic names and difficulty are syllabus structure; the text of students' personal notes is not shown.
      topics: topics.rows.map((t) => ({ name: t.name, difficulty: t.difficulty, completed: t.done, hasNotes: t.has_note, estMinutes: t.est_minutes })),
      sessions: sessions.rows.map((s) => ({ chapter: s.chapter_name, date: s.due_date, start: s.start_time, end: s.end_time, status: s.status })),
    });
  } catch (e) {
    adminError(res, "this exam", e);
  }
});

/* ---- study tasks (planner sessions) ---- */
app.get("/api/admin/tasks", requireAdmin, async (req, res) => {
  try {
    const limit = clampInt(req.query.limit, 25, 1, 100);
    const page = clampInt(req.query.page, 1, 1, 100000);
    const status = ["completed", "pending", "overdue"].includes(req.query.status) ? req.query.status : "all";
    const subject = cleanText(req.query.subject);
    const difficulty = cleanText(req.query.difficulty, 30);
    const q = cleanText(req.query.q);
    const from = isoDate(req.query.from), to = isoDate(req.query.to);
    const sort = req.query.sort === "due_desc" ? "t.due_date DESC NULLS LAST" : "t.due_date ASC NULLS LAST";

    const where = [];
    const params = [];
    const add = (v) => { params.push(v); return `$${params.length}`; };
    if (status !== "all") where.push(`t.status = ${add(status)}`);
    if (subject) where.push(`lower(t.subject) = lower(${add(subject)})`);
    if (difficulty) where.push(`lower(t.difficulty) = lower(${add(difficulty)})`);
    if (q) { const p = add(`%${q}%`); where.push(`(t.chapter ILIKE ${p} OR t.subject ILIKE ${p} OR t.student_name ILIKE ${p} OR t.student_email ILIKE ${p})`); }
    if (from) where.push(`t.due_date >= ${add(from)}::date`);
    if (to) where.push(`t.due_date <= ${add(to)}::date`);
    const whereSql = where.length ? "WHERE " + where.join(" AND ") : "";
    const limitP = add(limit), offsetP = add((page - 1) * limit);

    const base = `
      WITH ${STUDY_CTE},
      t AS (
        SELECT se.user_id, se.session_id, COALESCE(se.subject, ex.subject) AS subject,
               COALESCE(se.chapter_name, ch.name) AS chapter, ch.difficulty,
               se.due_date, se.start_time, se.end_time, ${TASK_STATUS} AS status,
               u.name AS student_name, u.email AS student_email
        FROM se
        JOIN users u ON u.id = se.user_id
        LEFT JOIN LATERAL (SELECT subject FROM ex WHERE ex.user_id = se.user_id AND ex.exam_id = se.exam_id LIMIT 1) ex ON true
        LEFT JOIN LATERAL (
          SELECT name, difficulty FROM ch
          WHERE ch.user_id = se.user_id AND ch.chapter_id = se.chapter_id AND (se.exam_id IS NULL OR ch.exam_id = se.exam_id)
          LIMIT 1
        ) ch ON true
      )`;
    const [rows, stats, facets] = await Promise.all([
      pool.query(
        `${base}, filtered AS (SELECT t.* FROM t ${whereSql})
         SELECT t.*, t.due_date::text AS due_text, (SELECT COUNT(*) FROM filtered) AS total_count
         FROM filtered t ORDER BY ${sort}, t.start_time NULLS LAST LIMIT ${limitP} OFFSET ${offsetP}`,
        params
      ),
      pool.query(`${base}
        SELECT COUNT(*) AS total, COUNT(*) FILTER (WHERE status = 'completed') AS completed,
               COUNT(*) FILTER (WHERE status = 'pending') AS pending, COUNT(*) FILTER (WHERE status = 'overdue') AS overdue
        FROM t`),
      pool.query(`${base}
        SELECT (SELECT jsonb_agg(DISTINCT subject) FROM t WHERE subject IS NOT NULL) AS subjects,
               (SELECT jsonb_agg(DISTINCT difficulty) FROM t WHERE difficulty IS NOT NULL) AS difficulties`),
    ]);
    const s = stats.rows[0];
    res.json({
      page, limit, total: rows.rows.length ? num(rows.rows[0].total_count) : 0,
      stats: {
        total: num(s.total), completed: num(s.completed), pending: num(s.pending), overdue: num(s.overdue),
        completionRate: num(s.total) ? Math.round((num(s.completed) / num(s.total)) * 100) : null,
      },
      subjects: facets.rows[0].subjects || [],
      difficulties: facets.rows[0].difficulties || [],
      tasks: rows.rows.map((r) => ({
        userId: r.user_id, studentName: r.student_name, studentEmail: r.student_email,
        task: r.chapter ? `Study ${r.chapter}` : "Study session",
        subject: r.subject, chapter: r.chapter, difficulty: r.difficulty,
        dueDate: r.due_text, start: r.start_time, end: r.end_time, status: r.status, createdAt: null,
      })),
    });
  } catch (e) {
    adminError(res, "study tasks", e);
  }
});

/* ---- analytics ---- */
app.get("/api/admin/analytics", requireAdmin, async (req, res) => {
  try {
    const range = ["7", "30", "90", "all"].includes(String(req.query.range)) ? String(req.query.range) : "30";
    const since = range === "all" ? `'-infinity'::timestamptz` : `now() - interval '${Number(range)} days'`;
    const [users, examStats, subjects, study, difficulty] = await Promise.all([
      pool.query(`
        WITH ${SEEN_CTE},
        dev_days AS (
          SELECT device_id, COUNT(DISTINCT (created_at AT TIME ZONE '${ADMIN_TZ}')::date) AS days
          FROM events WHERE device_id IS NOT NULL AND created_at >= ${since} AND event_type <> 'admin_panel_viewed'
          GROUP BY device_id
        )
        SELECT (SELECT COUNT(*) FROM users) AS total,
               (SELECT COUNT(*) FROM users WHERE created_at >= ${since}) AS new_users,
               (SELECT COUNT(*) FROM seen WHERE last_seen >= ${since}) AS active,
               (SELECT COUNT(*) FROM dev_days) AS devices,
               (SELECT COUNT(*) FROM dev_days WHERE days >= 2) AS returning_devices`),
      pool.query(`
        WITH ${STUDY_CTE},
        t AS (SELECT user_id, exam_id, COUNT(*) AS n, COUNT(*) FILTER (WHERE done) AS d FROM ch GROUP BY user_id, exam_id)
        SELECT (SELECT COUNT(*) FROM events WHERE event_type = 'exam_created' AND created_at >= ${since}) AS created,
               (SELECT COUNT(*) FROM ex) AS total,
               (SELECT COUNT(*) FROM ex WHERE exam_date >= ${TODAY}) AS upcoming,
               (SELECT COUNT(*) FROM ex WHERE exam_date < ${TODAY}) AS past,
               (SELECT COUNT(*) FROM t WHERE n > 0 AND n = d) AS syllabus_complete`),
      pool.query(`
        WITH ${STUDY_CTE}
        SELECT MIN(subject) AS subject, COUNT(*) AS n FROM ex WHERE subject IS NOT NULL
        GROUP BY lower(subject) ORDER BY n DESC, MIN(subject) LIMIT 10`),
      pool.query(`
        WITH ${STUDY_CTE}
        SELECT (SELECT COUNT(*) FROM se) AS tasks, (SELECT COUNT(*) FROM se WHERE done) AS tasks_done,
               (SELECT COUNT(*) FROM se WHERE NOT done AND due_date < ${TODAY}) AS overdue,
               (SELECT COUNT(*) FROM events WHERE event_type = 'study_plan_created' AND created_at >= ${since}) AS plans,
               (SELECT COUNT(*) FROM events WHERE event_type = 'focus_session_completed' AND created_at >= ${since}) AS focus`),
      pool.query(`
        WITH ${STUDY_CTE}
        SELECT COALESCE(difficulty, 'Not set') AS difficulty, COUNT(*) AS topics, COUNT(*) FILTER (WHERE done) AS completed
        FROM ch GROUP BY 1 ORDER BY 2 DESC`),
    ]);
    const u = users.rows[0], x = examStats.rows[0], s = study.rows[0];
    res.json({
      range,
      users: {
        total: num(u.total), newUsers: num(u.new_users), active: num(u.active),
        devices: num(u.devices), returningDevices: num(u.returning_devices),
      },
      exams: {
        createdInRange: num(x.created), total: num(x.total), upcoming: num(x.upcoming), past: num(x.past),
        syllabusComplete: num(x.syllabus_complete),
        topSubjects: subjects.rows.map((r) => ({ subject: r.subject, count: num(r.n) })),
      },
      study: {
        tasks: num(s.tasks), completed: num(s.tasks_done), overdue: num(s.overdue),
        completionRate: num(s.tasks) ? Math.round((num(s.tasks_done) / num(s.tasks)) * 100) : null,
        studyPlansInRange: num(s.plans), focusSessionsInRange: num(s.focus),
        difficulty: difficulty.rows.map((r) => ({ difficulty: r.difficulty, topics: num(r.topics), completed: num(r.completed) })),
      },
    });
  } catch (e) {
    adminError(res, "analytics", e);
  }
});

/* ---- feedback & bug reports (read-only for now) ---- */
app.get("/api/admin/feedback", requireAdmin, async (req, res) => {
  try {
    const limit = clampInt(req.query.limit, 50, 1, 200);
    const kind = req.query.kind === "bug" || req.query.kind === "feedback" ? req.query.kind : null;
    const q = cleanText(req.query.q, 200);
    const where = [];
    const params = [limit];
    if (kind) { params.push(kind); where.push(`f.kind = $${params.length}`); }
    if (q) { params.push(`%${q}%`); where.push(`(f.message ILIKE $${params.length} OR u.name ILIKE $${params.length} OR u.email ILIKE $${params.length})`); }
    const order = req.query.sort === "oldest" ? "ASC" : "DESC";
    const result = await pool.query(
      `SELECT f.id, f.kind, f.message, f.page, f.user_agent, f.created_at, f.user_id, u.name AS user_name, u.email AS user_email
       FROM feedback f LEFT JOIN users u ON u.id = f.user_id
       ${where.length ? "WHERE " + where.join(" AND ") : ""}
       ORDER BY f.created_at ${order} LIMIT $1`,
      params
    );
    res.json({ items: result.rows });
  } catch (e) {
    adminError(res, "feedback", e);
  }
});

app.get("/api/admin/events", requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(200, Number(req.query.limit) || 50);
    const eventType = req.query.eventType;
    const result = eventType
      ? await pool.query("SELECT id, device_id, user_id, event_type, metadata, created_at FROM events WHERE event_type = $1 ORDER BY created_at DESC LIMIT $2", [eventType, limit])
      : await pool.query("SELECT id, device_id, user_id, event_type, metadata, created_at FROM events ORDER BY created_at DESC LIMIT $1", [limit]);
    res.json({ events: result.rows });
  } catch (e) {
    adminError(res, "events", e);
  }
});

/* ---- system health ---- */
app.get("/api/admin/health", requireAdmin, async (req, res) => {
  const checkedAt = new Date().toISOString();
  const services = {};

  services.api = { status: "online", responseMs: 0, detail: `Running for ${Math.round(process.uptime())} s` };

  let t = Date.now();
  try {
    await pool.query("SELECT 1");
    services.database = { status: "online", responseMs: Date.now() - t };
  } catch (e) {
    services.database = { status: "offline", responseMs: null, detail: "The database can't be reached." };
  }

  t = Date.now();
  try {
    const probe = jwt.sign({ probe: true }, JWT_SECRET, { expiresIn: 30 });
    jwt.verify(probe, JWT_SECRET);
    let usersOk = services.database.status === "online";
    if (usersOk) await pool.query("SELECT 1 FROM users LIMIT 1");
    services.auth = { status: usersOk ? "online" : "offline", responseMs: Date.now() - t, detail: usersOk ? "Sign-in tokens and account lookup working" : "Accounts can't be checked while the database is offline" };
  } catch (e) {
    services.auth = { status: "offline", responseMs: null, detail: "Sign-in tokens can't be created or checked." };
  }

  t = Date.now();
  try {
    const r = await fetch(FRONTEND_URL, { method: "GET", signal: AbortSignal.timeout(8000) });
    services.frontend = { status: r.ok ? "online" : "offline", responseMs: Date.now() - t, detail: r.ok ? "Student website responding" : `Website returned status ${r.status}` };
  } catch (e) {
    services.frontend = { status: "offline", responseMs: null, detail: "The student website didn't respond within 8 seconds." };
  }

  let errors = [], errorCount24h = 0, dbSizeBytes = null;
  if (services.database.status === "online") {
    try {
      const [er, cnt, sz] = await Promise.all([
        pool.query(`SELECT created_at, metadata FROM events WHERE event_type = 'api_error' ORDER BY created_at DESC LIMIT 15`),
        pool.query(`SELECT COUNT(*) AS n FROM events WHERE event_type = 'api_error' AND created_at >= now() - interval '1 day'`),
        pool.query(`SELECT pg_database_size(current_database()) AS b`),
      ]);
      errors = er.rows.map((r) => ({
        at: r.created_at,
        route: typeof r.metadata?.route === "string" ? r.metadata.route.slice(0, 100) : null,
        message: typeof r.metadata?.message === "string" ? r.metadata.message.slice(0, 200) : null,
      }));
      errorCount24h = num(cnt.rows[0].n);
      dbSizeBytes = num(sz.rows[0].b);
    } catch (e) { /* ignore */ }
  }

  const anyOffline = Object.values(services).some((s) => s.status !== "online");
  res.json({
    checkedAt,
    status: services.database.status !== "online" || services.auth.status !== "online" ? "critical" : anyOffline || errorCount24h > 20 ? "warning" : "healthy",
    services,
    databaseSizeBytes: dbSizeBytes,
    smartImportConfigured: Boolean(GEMINI_API_KEY),
    errorCount24h,
    recentErrors: errors,
  });
});

/* ---- current admin session ---- */
app.get("/api/admin/me", requireAdmin, async (req, res) => {
  try {
    const [u, logins] = await Promise.all([
      pool.query("SELECT name, email, created_at FROM users WHERE id = $1", [req.userId]),
      pool.query("SELECT created_at FROM events WHERE user_id = $1 AND event_type = 'user_login' ORDER BY created_at DESC LIMIT 5", [req.userId]),
    ]);
    const p = req.tokenPayload || {};
    res.json({
      name: u.rows[0].name, email: u.rows[0].email, accountCreatedAt: u.rows[0].created_at,
      recentLogins: logins.rows.map((r) => r.created_at),
      session: {
        signedInAt: p.iat ? new Date(p.iat * 1000).toISOString() : null,
        expiresAt: p.exp ? new Date(p.exp * 1000).toISOString() : null,
      },
      timezone: ADMIN_TZ,
    });
  } catch (e) {
    adminError(res, "admin session", e);
  }
});

/* ---------------- admin phase 2: workflows and actions ---------------- */
// Every write below requires an admin account, validates its input, and is recorded in admin_activity_logs.
// Nothing here deletes feedback, bug reports or their history.

const FB_TYPES = {
  feedback: { statuses: ["new", "reviewing", "in_progress", "resolved", "closed"], priorities: ["low", "medium", "high"] },
  bug: { statuses: ["new", "investigating", "in_progress", "fixed", "closed"], priorities: ["low", "medium", "high", "critical"] },
  feature: { statuses: ["new", "reviewing", "planned", "in_development", "released", "declined"], priorities: ["low", "medium", "high"] },
};
const FB_CATEGORIES = ["general", "feature_request", "suggestion", "other"];
const OPEN_BUG_SQL = `(f.kind = 'bug' AND f.status NOT IN ('fixed', 'closed'))`;
const TYPE_SQL = `CASE WHEN f.kind = 'bug' THEN 'bug' WHEN f.category = 'feature_request' THEN 'feature' ELSE 'feedback' END`;
const typeOfRow = (r) => (r.kind === "bug" ? "bug" : r.category === "feature_request" ? "feature" : "feedback");

async function logAdmin(adminId, action, targetType, targetId, details) {
  try {
    await pool.query(
      "INSERT INTO admin_activity_logs (admin_id, action, target_type, target_id, details) VALUES ($1, $2, $3, $4, $5)",
      [adminId, action, targetType, targetId == null ? null : String(targetId), details || {}]
    );
  } catch (e) {
    console.error("logAdmin failed", action, e.message);
  }
}

/* ---- inbox: feedback, bug reports and feature requests ---- */
function inboxRow(r) {
  return {
    id: r.id, type: r.type, kind: r.kind, category: r.kind === "bug" ? null : r.category || "general",
    title: r.title, message: r.message, page: r.page, status: r.status, priority: r.priority,
    duplicateOf: r.duplicate_of, requestCount: r.request_count == null ? null : Number(r.request_count),
    notesCount: Number(r.notes_count || 0), createdAt: r.created_at, updatedAt: r.updated_at,
    user: r.user_id ? { id: r.user_id, name: r.user_name, email: r.user_email, deleted: !r.user_email } : null,
  };
}

app.get("/api/admin/inbox", requireAdmin, async (req, res) => {
  try {
    const type = ["feedback", "bug", "feature"].includes(req.query.type) ? req.query.type : "feedback";
    const limit = clampInt(req.query.limit, 25, 1, 100);
    const page = clampInt(req.query.page, 1, 1, 100000);
    const q = cleanText(req.query.q, 200);
    const status = cleanText(req.query.status, 30);
    const priority = cleanText(req.query.priority, 30);
    const category = FB_CATEGORIES.includes(req.query.category) ? req.query.category : null;
    const sorts = {
      newest: "f.created_at DESC", oldest: "f.created_at ASC",
      priority: "CASE f.priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, f.created_at DESC",
      most_requested: "request_count DESC NULLS LAST, f.created_at DESC",
      updated: "COALESCE(f.updated_at, f.created_at) DESC",
    };
    const sort = sorts[req.query.sort] || sorts.newest;

    const where = [];
    const params = [];
    const add = (v) => { params.push(v); return `$${params.length}`; };
    if (type === "bug") where.push("f.kind = 'bug'");
    if (type === "feature") where.push("f.kind = 'feedback' AND f.category = 'feature_request'");
    if (type === "feedback") {
      where.push("f.kind = 'feedback'");
      if (category) where.push(`COALESCE(f.category, 'general') = ${add(category)}`);
    }
    if (status === "open") where.push("f.status NOT IN ('resolved', 'closed', 'fixed', 'released', 'declined')");
    else if (status) where.push(`f.status = ${add(status)}`);
    if (priority) where.push(`f.priority = ${add(priority)}`);
    if (q) { const p = add(`%${q}%`); where.push(`(f.message ILIKE ${p} OR f.title ILIKE ${p} OR u.name ILIKE ${p} OR u.email ILIKE ${p})`); }
    const whereSql = "WHERE " + where.join(" AND ");
    const limitP = add(limit), offsetP = add((page - 1) * limit);

    const base = `
      FROM feedback f
      LEFT JOIN users u ON u.id = f.user_id
      LEFT JOIN (SELECT feedback_id, COUNT(*) AS n FROM feedback_notes GROUP BY feedback_id) nc ON nc.feedback_id = f.id
      LEFT JOIN (SELECT duplicate_of, COUNT(*) AS n FROM feedback WHERE duplicate_of IS NOT NULL GROUP BY duplicate_of) dup ON dup.duplicate_of = f.id`;
    const [rows, counts] = await Promise.all([
      pool.query(
        `SELECT f.*, ${TYPE_SQL} AS type, u.name AS user_name, u.email AS user_email, COALESCE(nc.n, 0) AS notes_count,
                CASE WHEN f.category = 'feature_request' THEN 1 + COALESCE(dup.n, 0) END AS request_count,
                COUNT(*) OVER () AS total_count
         ${base} ${whereSql} ORDER BY ${sort} LIMIT ${limitP} OFFSET ${offsetP}`,
        params
      ),
      pool.query(
        `SELECT f.status, COUNT(*) AS n FROM feedback f
         WHERE ${type === "bug" ? "f.kind = 'bug'" : type === "feature" ? "f.kind = 'feedback' AND f.category = 'feature_request'" : "f.kind = 'feedback'"}
         GROUP BY f.status`
      ),
    ]);
    res.json({
      type, page, limit, total: rows.rows.length ? Number(rows.rows[0].total_count) : 0,
      statuses: FB_TYPES[type].statuses, priorities: FB_TYPES[type].priorities, categories: FB_CATEGORIES,
      statusCounts: Object.fromEntries(counts.rows.map((r) => [r.status, Number(r.n)])),
      items: rows.rows.map(inboxRow),
    });
  } catch (e) {
    adminError(res, "messages", e);
  }
});

async function loadInboxItem(id) {
  const r = await pool.query(
    `SELECT f.*, ${TYPE_SQL} AS type, u.name AS user_name, u.email AS user_email,
            (SELECT COUNT(*) FROM feedback_notes n WHERE n.feedback_id = f.id) AS notes_count,
            CASE WHEN f.category = 'feature_request' THEN 1 + (SELECT COUNT(*) FROM feedback d WHERE d.duplicate_of = f.id) END AS request_count
     FROM feedback f LEFT JOIN users u ON u.id = f.user_id WHERE f.id = $1`,
    [id]
  );
  return r.rows[0] || null;
}

app.get("/api/admin/inbox/:id", requireAdmin, async (req, res) => {
  try {
    const id = Number.parseInt(req.params.id, 10);
    const row = id && (await loadInboxItem(id));
    if (!row) return res.status(404).json({ error: "Message not found." });
    const [notes, history, dups, parent] = await Promise.all([
      pool.query(
        `SELECT n.id, n.kind, n.note, n.created_at, a.name AS admin_name FROM feedback_notes n
         LEFT JOIN users a ON a.id = n.admin_id WHERE n.feedback_id = $1 ORDER BY n.created_at`,
        [id]
      ),
      pool.query(
        `SELECT h.field, h.old_value, h.new_value, h.created_at, a.name AS admin_name FROM feedback_history h
         LEFT JOIN users a ON a.id = h.admin_id WHERE h.feedback_id = $1 ORDER BY h.created_at`,
        [id]
      ),
      pool.query(
        `SELECT f.id, f.title, left(f.message, 140) AS message, f.created_at, u.name AS user_name
         FROM feedback f LEFT JOIN users u ON u.id = f.user_id WHERE f.duplicate_of = $1 ORDER BY f.created_at`,
        [id]
      ),
      row.duplicate_of
        ? pool.query(`SELECT id, title, left(message, 140) AS message, status FROM feedback WHERE id = $1`, [row.duplicate_of])
        : Promise.resolve({ rows: [] }),
    ]);
    const type = typeOfRow(row);
    res.json({
      item: { ...inboxRow(row), userAgent: row.user_agent },
      statuses: FB_TYPES[type].statuses, priorities: FB_TYPES[type].priorities, categories: FB_CATEGORIES,
      notes: notes.rows.map((n) => ({ id: n.id, kind: n.kind, note: n.note, createdAt: n.created_at, adminName: n.admin_name })),
      history: history.rows.map((h) => ({ field: h.field, from: h.old_value, to: h.new_value, at: h.created_at, adminName: h.admin_name })),
      duplicates: dups.rows.map((d) => ({ id: d.id, title: d.title, message: d.message, createdAt: d.created_at, userName: d.user_name })),
      duplicateOfItem: parent.rows[0] || null,
    });
  } catch (e) {
    adminError(res, "this message", e);
  }
});

app.patch("/api/admin/inbox/:id", requireAdmin, async (req, res) => {
  const client = await pool.connect();
  try {
    const id = Number.parseInt(req.params.id, 10);
    const row = id && (await loadInboxItem(id));
    if (!row) return res.status(404).json({ error: "Message not found." });
    const body = req.body || {};
    const next = { status: row.status, priority: row.priority, category: row.category, duplicate_of: row.duplicate_of };

    if (body.category !== undefined) {
      if (row.kind === "bug") return res.status(400).json({ error: "Bug reports don't have a category." });
      if (!FB_CATEGORIES.includes(body.category)) return res.status(400).json({ error: "Unknown category." });
      next.category = body.category;
    }
    const newType = row.kind === "bug" ? "bug" : next.category === "feature_request" ? "feature" : "feedback";
    const rules = FB_TYPES[newType];
    if (body.status !== undefined) {
      if (!rules.statuses.includes(body.status)) return res.status(400).json({ error: "That status isn't available for this item." });
      next.status = body.status;
    } else if (!rules.statuses.includes(next.status)) {
      next.status = "new"; // category changed to a type with different statuses
    }
    if (body.priority !== undefined) {
      if (!rules.priorities.includes(body.priority)) return res.status(400).json({ error: "That priority isn't available for this item." });
      next.priority = body.priority;
    } else if (!rules.priorities.includes(next.priority)) {
      next.priority = "high";
    }
    if (body.duplicateOf !== undefined) {
      if (body.duplicateOf === null) next.duplicate_of = null;
      else {
        const target = Number.parseInt(body.duplicateOf, 10);
        if (!target || target === id) return res.status(400).json({ error: "Choose a different request." });
        const t = await pool.query("SELECT id, kind, category, duplicate_of FROM feedback WHERE id = $1", [target]);
        if (!t.rows[0] || t.rows[0].category !== "feature_request" || next.category !== "feature_request")
          return res.status(400).json({ error: "Only feature requests can be merged, and only into another feature request." });
        if (t.rows[0].duplicate_of) return res.status(400).json({ error: "That request is itself a duplicate. Choose the original request." });
        const kids = await pool.query("SELECT 1 FROM feedback WHERE duplicate_of = $1 LIMIT 1", [id]);
        if (kids.rows.length) return res.status(400).json({ error: "Other requests are merged into this one, so it can't be merged elsewhere." });
        next.duplicate_of = target;
      }
    }

    const changes = [];
    for (const [field, col] of [["status", "status"], ["priority", "priority"], ["category", "category"], ["duplicateOf", "duplicate_of"]]) {
      const before = row[col] == null ? null : String(row[col]);
      const after = next[col] == null ? null : String(next[col]);
      if (before !== after) changes.push({ field, before, after });
    }
    if (!changes.length) return res.json({ ok: true, changed: false });

    await client.query("BEGIN");
    await client.query(
      "UPDATE feedback SET status = $1, priority = $2, category = $3, duplicate_of = $4, updated_at = now() WHERE id = $5",
      [next.status, next.priority, row.kind === "bug" ? row.category : next.category, next.duplicate_of, id]
    );
    for (const c of changes) {
      await client.query(
        "INSERT INTO feedback_history (feedback_id, admin_id, field, old_value, new_value) VALUES ($1, $2, $3, $4, $5)",
        [id, req.userId, c.field, c.before, c.after]
      );
    }
    await client.query("COMMIT");
    await logAdmin(req.userId, "inbox_updated", newType, id, { changes });
    res.json({ ok: true, changed: true });
  } catch (e) {
    try { await client.query("ROLLBACK"); } catch (x) {}
    console.error("admin inbox update error", e);
    res.status(500).json({ error: "Couldn't save the change. Please try again." });
  } finally {
    client.release();
  }
});

app.post("/api/admin/inbox/:id/notes", requireAdmin, async (req, res) => {
  try {
    const id = Number.parseInt(req.params.id, 10);
    const row = id && (await loadInboxItem(id));
    if (!row) return res.status(404).json({ error: "Message not found." });
    const note = cleanText((req.body || {}).note, 4000);
    const kind = (req.body || {}).kind === "resolution" ? "resolution" : "internal";
    if (!note) return res.status(400).json({ error: "Write a note first." });
    if (kind === "resolution" && row.kind !== "bug") return res.status(400).json({ error: "Resolution notes are for bug reports." });
    await pool.query("INSERT INTO feedback_notes (feedback_id, admin_id, kind, note) VALUES ($1, $2, $3, $4)", [id, req.userId, kind, note]);
    await pool.query("UPDATE feedback SET updated_at = now() WHERE id = $1", [id]);
    await logAdmin(req.userId, kind === "resolution" ? "resolution_note_added" : "note_added", typeOfRow(row), id, {});
    res.json({ ok: true });
  } catch (e) {
    console.error("admin note error", e);
    res.status(500).json({ error: "Couldn't save the note. Please try again." });
  }
});

/* ---- announcements ---- */
const ANN_TYPES = ["general", "feature_update", "maintenance", "important"];
const ANN_STATUSES = ["draft", "published", "archived"];
const annRow = (r) => ({
  id: r.id, title: r.title, message: r.message, type: r.type, status: r.status,
  publishAt: r.publish_at, createdAt: r.created_at, updatedAt: r.updated_at, createdBy: r.author_name || null,
});

app.get("/api/admin/announcements", requireAdmin, async (req, res) => {
  try {
    const status = ANN_STATUSES.includes(req.query.status) ? req.query.status : null;
    const r = await pool.query(
      `SELECT a.*, u.name AS author_name FROM announcements a LEFT JOIN users u ON u.id = a.created_by
       ${status ? "WHERE a.status = $1" : ""} ORDER BY COALESCE(a.publish_at, a.created_at) DESC LIMIT 200`,
      status ? [status] : []
    );
    res.json({ items: r.rows.map(annRow), types: ANN_TYPES, statuses: ANN_STATUSES });
  } catch (e) {
    adminError(res, "announcements", e);
  }
});

function validateAnnouncement(body, partial) {
  const out = {};
  if (!partial || body.title !== undefined) {
    out.title = cleanText(body.title, 120);
    if (!out.title) return { error: "Give the announcement a title." };
  }
  if (!partial || body.message !== undefined) {
    out.message = cleanText(body.message, 2000);
    if (!out.message) return { error: "Write the announcement message." };
  }
  if (!partial || body.type !== undefined) {
    out.type = ANN_TYPES.includes(body.type) ? body.type : null;
    if (!out.type) return { error: "Choose an announcement type." };
  }
  if (!partial || body.status !== undefined) {
    out.status = ANN_STATUSES.includes(body.status) ? body.status : null;
    if (!out.status) return { error: "Choose a status." };
  }
  if (body.publishAt !== undefined) {
    if (body.publishAt === null || body.publishAt === "") out.publish_at = null;
    else {
      const d = new Date(body.publishAt);
      if (Number.isNaN(d.getTime())) return { error: "The publish date isn't valid." };
      out.publish_at = d.toISOString();
    }
  }
  return { value: out };
}

app.post("/api/admin/announcements", requireAdmin, async (req, res) => {
  try {
    const v = validateAnnouncement(req.body || {}, false);
    if (v.error) return res.status(400).json({ error: v.error });
    const a = v.value;
    if (a.status === "published" && !a.publish_at) a.publish_at = new Date().toISOString();
    const r = await pool.query(
      `INSERT INTO announcements (title, message, type, status, publish_at, created_by) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [a.title, a.message, a.type, a.status, a.publish_at || null, req.userId]
    );
    await logAdmin(req.userId, "announcement_created", "announcement", r.rows[0].id, { title: a.title, status: a.status });
    res.json({ item: annRow(r.rows[0]) });
  } catch (e) {
    console.error("announcement create error", e);
    res.status(500).json({ error: "Couldn't save the announcement. Please try again." });
  }
});

app.patch("/api/admin/announcements/:id", requireAdmin, async (req, res) => {
  try {
    const id = Number.parseInt(req.params.id, 10);
    const cur = await pool.query("SELECT * FROM announcements WHERE id = $1", [id]);
    if (!cur.rows[0]) return res.status(404).json({ error: "Announcement not found." });
    const v = validateAnnouncement(req.body || {}, true);
    if (v.error) return res.status(400).json({ error: v.error });
    const a = { ...v.value };
    if (a.status === "published" && !cur.rows[0].publish_at && a.publish_at === undefined) a.publish_at = new Date().toISOString();
    const cols = Object.keys(a);
    if (!cols.length) return res.json({ item: annRow(cur.rows[0]) });
    const sets = cols.map((c, i) => `${c} = $${i + 1}`).join(", ");
    const r = await pool.query(`UPDATE announcements SET ${sets}, updated_at = now() WHERE id = $${cols.length + 1} RETURNING *`, [...cols.map((c) => a[c]), id]);
    await logAdmin(req.userId, "announcement_updated", "announcement", id, { fields: cols, status: r.rows[0].status });
    res.json({ item: annRow(r.rows[0]) });
  } catch (e) {
    console.error("announcement update error", e);
    res.status(500).json({ error: "Couldn't save the announcement. Please try again." });
  }
});

app.delete("/api/admin/announcements/:id", requireAdmin, async (req, res) => {
  try {
    const id = Number.parseInt(req.params.id, 10);
    const cur = await pool.query("SELECT status, title FROM announcements WHERE id = $1", [id]);
    if (!cur.rows[0]) return res.status(404).json({ error: "Announcement not found." });
    if (cur.rows[0].status !== "draft") return res.status(400).json({ error: "Only drafts can be deleted. Archive published announcements instead." });
    if ((req.body || {}).confirm !== true) return res.status(400).json({ error: "Deleting needs confirmation." });
    await pool.query("DELETE FROM announcements WHERE id = $1", [id]);
    await logAdmin(req.userId, "announcement_deleted", "announcement", id, { title: cur.rows[0].title });
    res.json({ ok: true });
  } catch (e) {
    console.error("announcement delete error", e);
    res.status(500).json({ error: "Couldn't delete the announcement. Please try again." });
  }
});

// Public: what students see. Only published announcements whose publish time has arrived.
app.get("/api/announcements", async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT id, title, message, type, publish_at FROM announcements
       WHERE status = 'published' AND (publish_at IS NULL OR publish_at <= now())
       ORDER BY COALESCE(publish_at, created_at) DESC LIMIT 3`
    );
    res.set("Cache-Control", "public, max-age=60");
    res.json({ items: r.rows.map((a) => ({ id: a.id, title: a.title, message: a.message, type: a.type, publishedAt: a.publish_at })) });
  } catch (e) {
    console.error("public announcements error", e);
    res.json({ items: [] });
  }
});

/* ---- account actions (destructive: require explicit confirmation) ---- */
async function loadTarget(req, res) {
  const id = Number.parseInt(req.params.id, 10);
  if (!id) { res.status(400).json({ error: "Invalid student id." }); return null; }
  const r = await pool.query("SELECT id, name, email, is_admin, is_disabled FROM users WHERE id = $1", [id]);
  const u = r.rows[0];
  if (!u) { res.status(404).json({ error: "Student not found." }); return null; }
  if (u.is_admin || u.id === req.userId) { res.status(400).json({ error: "Admin accounts can't be disabled or deleted from the admin panel." }); return null; }
  return u;
}

app.post("/api/admin/users/:id/disable", requireAdmin, async (req, res) => {
  try {
    const u = await loadTarget(req, res); if (!u) return;
    if ((req.body || {}).confirm !== true) return res.status(400).json({ error: "Disabling needs confirmation." });
    const reason = cleanText((req.body || {}).reason, 300) || null;
    await pool.query("UPDATE users SET is_disabled = true, disabled_at = now(), disabled_reason = $2 WHERE id = $1", [u.id, reason]);
    forgetUserState(u.id);
    await logAdmin(req.userId, "account_disabled", "user", u.id, { email: u.email, reason });
    res.json({ ok: true });
  } catch (e) {
    console.error("disable error", e);
    res.status(500).json({ error: "Couldn't disable the account. Please try again." });
  }
});

app.post("/api/admin/users/:id/enable", requireAdmin, async (req, res) => {
  try {
    const u = await loadTarget(req, res); if (!u) return;
    await pool.query("UPDATE users SET is_disabled = false, disabled_at = NULL, disabled_reason = NULL WHERE id = $1", [u.id]);
    forgetUserState(u.id);
    await logAdmin(req.userId, "account_enabled", "user", u.id, { email: u.email });
    res.json({ ok: true });
  } catch (e) {
    console.error("enable error", e);
    res.status(500).json({ error: "Couldn't re-enable the account. Please try again." });
  }
});

app.delete("/api/admin/users/:id", requireAdmin, async (req, res) => {
  try {
    const u = await loadTarget(req, res); if (!u) return;
    const typed = String((req.body || {}).confirmEmail || "").trim().toLowerCase();
    if (typed !== u.email.toLowerCase()) return res.status(400).json({ error: "Type the student's email address exactly to confirm deletion." });
    await pool.query("DELETE FROM users WHERE id = $1", [u.id]); // study data is removed with the account; their feedback stays, marked as from a deleted account
    forgetUserState(u.id);
    await logAdmin(req.userId, "account_deleted", "user", u.id, { email: u.email, name: u.name });
    res.json({ ok: true });
  } catch (e) {
    console.error("admin delete error", e);
    res.status(500).json({ error: "Couldn't delete the account. Please try again." });
  }
});

/* ---- admin activity log ---- */
app.get("/api/admin/logs", requireAdmin, async (req, res) => {
  try {
    const limit = clampInt(req.query.limit, 30, 1, 100);
    const page = clampInt(req.query.page, 1, 1, 100000);
    const r = await pool.query(
      `SELECT l.id, l.action, l.target_type, l.target_id, l.details, l.created_at, u.name AS admin_name, COUNT(*) OVER () AS total_count
       FROM admin_activity_logs l LEFT JOIN users u ON u.id = l.admin_id
       ORDER BY l.created_at DESC LIMIT $1 OFFSET $2`,
      [limit, (page - 1) * limit]
    );
    res.json({
      page, limit, total: r.rows.length ? Number(r.rows[0].total_count) : 0,
      items: r.rows.map((l) => ({ id: l.id, action: l.action, targetType: l.target_type, targetId: l.target_id, details: l.details, at: l.created_at, adminName: l.admin_name })),
    });
  } catch (e) {
    adminError(res, "the admin log", e);
  }
});

app.get("/health", (req, res) => res.json({ ok: true }));

initDb()
  .then(() => {
    app.listen(PORT, () => console.log(`ExamFlow API listening on port ${PORT}`));
  })
  .catch((e) => {
    console.error("Failed to initialize database", e);
    process.exit(1);
  });
    
