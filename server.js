const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");

const PORT = process.env.PORT || 4000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-2.5-flash";
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
function optionalAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (token) {
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      req.userId = payload.sub;
      touchActive(req.userId);
    } catch (e) { /* invalid/expired — treat as anonymous */ }
  }
  next();
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Please log in to continue." });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.sub;
    touchActive(req.userId);
    next();
  } catch (e) {
    return res.status(401).json({ error: "Your session has expired. Please log in again." });
  }
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
      "INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, name, email, created_at",
      [name.trim(), normalizedEmail, hash]
    );
    const user = result.rows[0];
    await pool.query("INSERT INTO user_data (user_id, data) VALUES ($1, $2)", [user.id, EMPTY_DATA]);

    const token = signToken(user);
    await logEvent(req.body.deviceId, user.id, "user_registered", {});
    res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
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
    const result = await pool.query("SELECT id, name, email, password_hash FROM users WHERE email = $1", [normalizedEmail]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: "Incorrect email or password." });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Incorrect email or password." });

    const token = signToken(user);
    await logEvent(req.body.deviceId, user.id, "user_login", {});
    res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
  } catch (e) {
    console.error("login error", e);
    res.status(500).json({ error: "Something went wrong logging you in. Please try again." });
  }
});

app.get("/api/me", requireAuth, async (req, res) => {
  try {
    const result = await pool.query("SELECT id, name, email, created_at, is_admin FROM users WHERE id = $1", [req.userId]);
    const row = result.rows[0];
    if (!row) return res.status(404).json({ error: "Account not found." });
    res.json({ user: { id: row.id, name: row.name, email: row.email, created_at: row.created_at, isAdmin: row.is_admin === true } });
  } catch (e) {
    console.error("me error", e);
    res.status(500).json({ error: "Couldn't load your account." });
  }
});

/* ---------------- data sync routes (account holders only) ---------------- */

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
    const { exams, sessions, settings } = req.body || {};
    const data = {
      exams: Array.isArray(exams) ? exams : [],
      sessions: Array.isArray(sessions) ? sessions : [],
      settings: settings && typeof settings === "object" ? settings : {},
    };
    await pool.query(
      `INSERT INTO user_data (user_id, data, updated_at) VALUES ($1, $2, now())
       ON CONFLICT (user_id) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`,
      [req.userId, data]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error("put data error", e);
    res.status(500).json({ error: "Couldn't save your data. Please try again." });
  }
});

app.delete("/api/account", requireAuth, async (req, res) => {
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
    const { kind, message, page, deviceId } = req.body || {};
    if (kind !== "feedback" && kind !== "bug") return res.status(400).json({ error: "Choose feedback or bug report." });
    if (!message || typeof message !== "string" || !message.trim()) return res.status(400).json({ error: "Please write a message." });
    await pool.query(
      "INSERT INTO feedback (kind, message, page, user_agent, device_id, user_id) VALUES ($1, $2, $3, $4, $5, $6)",
      [
        kind,
        message.trim().slice(0, 4000),
        typeof page === "string" ? page.slice(0, 300) : null,
        String(req.headers["user-agent"] || "").slice(0, 300),
        typeof deviceId === "string" ? deviceId.slice(0, 100) : null,
        req.userId || null,
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
    `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${GEMINI_API_KEY}`,
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
        bySubject.set(key, { subject: s.subject, examDateVotes: {}, examTimeVotes: {}, topics: new Map() });
      }
      const entry = bySubject.get(key);
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

  return Array.from(bySubject.values()).map((entry) => ({
    subject: entry.subject,
    examDate: pickTopVote(entry.examDateVotes),
    examTime: pickTopVote(entry.examTimeVotes),
    topics: Array.from(entry.topics.values()),
  }));
}

app.post("/api/import/analyze", importLimiter, optionalAuth, async (req, res) => {
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
        `{"subjects":[{"subject":"string","examDate":"YYYY-MM-DD or null","examTime":"HH:MM 24-hour or null","topics":["string", ...]}]}\n` +
        `Include every subject you can identify from either document, even if some fields are null.`,
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

/* ---------------- admin (read-only analytics) ---------------- */
// Access is decided by the server from the database (users.is_admin), never by anything the browser sends.
// Only accounts marked is_admin = true in the database can use these routes.

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

// Timezone used for "today" and daily charts.
const ADMIN_TZ = "Asia/Kolkata";

// Expands each user's saved study data into exams, syllabus topics (chapters) and planned study sessions.
const STUDY_DATA_CTE = `
  ex AS (
    SELECT ud.user_id, e FROM user_data ud,
      jsonb_array_elements(CASE WHEN jsonb_typeof(ud.data->'exams') = 'array' THEN ud.data->'exams' ELSE '[]'::jsonb END) e
  ),
  ch AS (
    SELECT ex.user_id, c FROM ex,
      jsonb_array_elements(CASE WHEN jsonb_typeof(e->'chapters') = 'array' THEN e->'chapters' ELSE '[]'::jsonb END) c
  ),
  se AS (
    SELECT ud.user_id, s FROM user_data ud,
      jsonb_array_elements(CASE WHEN jsonb_typeof(ud.data->'sessions') = 'array' THEN ud.data->'sessions' ELSE '[]'::jsonb END) s
  )`;
const TOPIC_DONE = `(c->>'status' = 'completed' OR c->>'completed' = 'true')`;
const TOPIC_HAS_NOTE = `(COALESCE(btrim(c->>'notes'), '') <> '')`;
const SESSION_DONE = `(s->>'completed' = 'true')`;

app.get("/api/admin/overview", requireAdmin, async (req, res) => {
  try {
    const [users, devices, study, events, fb] = await Promise.all([
      pool.query(`
        SELECT
          COUNT(*) AS total,
          COUNT(*) FILTER (WHERE created_at >= date_trunc('day', now() AT TIME ZONE '${ADMIN_TZ}') AT TIME ZONE '${ADMIN_TZ}') AS new_today,
          COUNT(*) FILTER (WHERE created_at >= now() - interval '7 days') AS new_7d,
          COUNT(*) FILTER (WHERE created_at >= now() - interval '30 days') AS new_30d,
          COUNT(*) FILTER (WHERE last_active_at >= now() - interval '1 day') AS active_1d,
          COUNT(*) FILTER (WHERE last_active_at >= now() - interval '7 days') AS active_7d,
          COUNT(*) FILTER (WHERE last_active_at >= now() - interval '30 days') AS active_30d
        FROM users`),
      pool.query(`
        SELECT
          COUNT(DISTINCT device_id) AS ever,
          COUNT(DISTINCT device_id) FILTER (WHERE created_at >= now() - interval '1 day') AS d1,
          COUNT(DISTINCT device_id) FILTER (WHERE created_at >= now() - interval '7 days') AS d7,
          COUNT(DISTINCT device_id) FILTER (WHERE created_at >= now() - interval '30 days') AS d30
        FROM events WHERE device_id IS NOT NULL`),
      pool.query(`
        WITH ${STUDY_DATA_CTE}
        SELECT
          (SELECT COUNT(*) FROM ex) AS exams,
          (SELECT COUNT(*) FROM ch) AS topics,
          (SELECT COUNT(*) FROM ch WHERE ${TOPIC_DONE}) AS topics_done,
          (SELECT COUNT(*) FROM ch WHERE ${TOPIC_HAS_NOTE}) AS notes,
          (SELECT COUNT(*) FROM se) AS sessions,
          (SELECT COUNT(*) FROM se WHERE ${SESSION_DONE}) AS sessions_done,
          (SELECT COUNT(DISTINCT user_id) FROM ex) AS users_with_exams`),
      pool.query(`SELECT event_type, COUNT(*) AS n FROM events GROUP BY event_type`),
      pool.query(`
        SELECT
          COUNT(*) FILTER (WHERE kind = 'feedback') AS feedback,
          COUNT(*) FILTER (WHERE kind = 'bug') AS bugs,
          COUNT(*) FILTER (WHERE created_at >= now() - interval '7 days') AS last_7d
        FROM feedback`),
    ]);

    const u = users.rows[0], d = devices.rows[0], st = study.rows[0], f = fb.rows[0];
    const ev = Object.fromEntries(events.rows.map((r) => [r.event_type, Number(r.n)]));
    const n = (v) => Number(v || 0);

    await logEvent(null, req.userId, "admin_panel_viewed", {});

    res.json({
      timezone: ADMIN_TZ,
      users: {
        total: n(u.total), newToday: n(u.new_today), new7d: n(u.new_7d), new30d: n(u.new_30d),
        active1d: n(u.active_1d), active7d: n(u.active_7d), active30d: n(u.active_30d),
      },
      devices: { ever: n(d.ever), active1d: n(d.d1), active7d: n(d.d7), active30d: n(d.d30) },
      study: {
        exams: n(st.exams), usersWithExams: n(st.users_with_exams),
        topics: n(st.topics), topicsCompleted: n(st.topics_done), notes: n(st.notes),
        sessions: n(st.sessions), sessionsCompleted: n(st.sessions_done),
      },
      activity: {
        focusSessions: ev.focus_session_completed || 0,
        studyPlansCreated: ev.study_plan_created || 0,
        syllabusUploads: ev.syllabus_uploaded || 0,
        dateSheetUploads: ev.date_sheet_uploaded || 0,
        failedUploads: ev.upload_failed || 0,
      },
      feedback: { feedback: n(f.feedback), bugs: n(f.bugs), last7d: n(f.last_7d) },
    });
  } catch (e) {
    console.error("admin overview error", e);
    res.status(500).json({ error: "Couldn't load overview." });
  }
});

// Daily series for charts: new sign-ups, active devices, active logged-in users, and each event type.
app.get("/api/admin/activity", requireAdmin, async (req, res) => {
  try {
    const days = Math.min(90, Math.max(7, Number(req.query.days) || 30));
    const series = await pool.query(
      `
      WITH d AS (
        SELECT generate_series(
          (date_trunc('day', now() AT TIME ZONE '${ADMIN_TZ}') - ($1::int - 1) * interval '1 day')::date,
          (now() AT TIME ZONE '${ADMIN_TZ}')::date,
          interval '1 day'
        )::date AS day
      ),
      signups AS (
        SELECT (created_at AT TIME ZONE '${ADMIN_TZ}')::date AS day, COUNT(*) AS n FROM users GROUP BY 1
      ),
      act AS (
        SELECT (created_at AT TIME ZONE '${ADMIN_TZ}')::date AS day,
               COUNT(DISTINCT device_id) AS devices,
               COUNT(DISTINCT user_id) AS users
        FROM events WHERE event_type <> 'admin_panel_viewed' GROUP BY 1
      )
      SELECT d.day::text AS day, COALESCE(signups.n, 0) AS signups, COALESCE(act.devices, 0) AS devices, COALESCE(act.users, 0) AS users
      FROM d LEFT JOIN signups USING (day) LEFT JOIN act USING (day) ORDER BY d.day`,
      [days]
    );
    const byType = await pool.query(
      `SELECT event_type, COUNT(*) AS n FROM events
       WHERE created_at >= now() - ($1::int * interval '1 day') AND event_type <> 'admin_panel_viewed'
       GROUP BY event_type ORDER BY n DESC`,
      [days]
    );
    res.json({
      timezone: ADMIN_TZ,
      days: series.rows.map((r) => ({
        date: String(r.day).slice(0, 10),
        signups: Number(r.signups), activeDevices: Number(r.devices), activeUsers: Number(r.users),
      })),
      featureUsage: byType.rows.map((r) => ({ eventType: r.event_type, count: Number(r.n) })),
    });
  } catch (e) {
    console.error("admin activity error", e);
    res.status(500).json({ error: "Couldn't load activity." });
  }
});

// Account-level list. Never returns password hashes or study content — only counts.
app.get("/api/admin/users", requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 25));
    const page = Math.max(1, Number(req.query.page) || 1);
    const q = typeof req.query.q === "string" ? req.query.q.trim().slice(0, 100) : "";
    const params = [limit, (page - 1) * limit];
    let where = "";
    if (q) { params.push(`%${q}%`); where = `WHERE u.name ILIKE $3 OR u.email ILIKE $3`; }

    const [rows, total] = await Promise.all([
      pool.query(
        `
        WITH ${STUDY_DATA_CTE},
        exs AS (SELECT user_id, COUNT(*) AS n FROM ex GROUP BY user_id),
        chs AS (SELECT user_id, COUNT(*) AS n, COUNT(*) FILTER (WHERE ${TOPIC_DONE}) AS done FROM ch GROUP BY user_id),
        ses AS (SELECT user_id, COUNT(*) AS n, COUNT(*) FILTER (WHERE ${SESSION_DONE}) AS done FROM se GROUP BY user_id)
        SELECT u.id, u.name, u.email, u.created_at, u.last_active_at, u.is_admin,
               COALESCE(exs.n, 0) AS exams, COALESCE(chs.n, 0) AS topics, COALESCE(chs.done, 0) AS topics_done,
               COALESCE(ses.n, 0) AS sessions, COALESCE(ses.done, 0) AS sessions_done,
               ud.updated_at AS data_updated_at
        FROM users u
        LEFT JOIN exs ON exs.user_id = u.id
        LEFT JOIN chs ON chs.user_id = u.id
        LEFT JOIN ses ON ses.user_id = u.id
        LEFT JOIN user_data ud ON ud.user_id = u.id
        ${where}
        ORDER BY u.created_at DESC
        LIMIT $1 OFFSET $2`,
        params
      ),
      pool.query(`SELECT COUNT(*) AS n FROM users u ${q ? "WHERE u.name ILIKE $1 OR u.email ILIKE $1" : ""}`, q ? [`%${q}%`] : []),
    ]);
    res.json({
      page, limit, total: Number(total.rows[0].n),
      users: rows.rows.map((r) => ({
        id: r.id, name: r.name, email: r.email, isAdmin: r.is_admin === true,
        createdAt: r.created_at, lastActiveAt: r.last_active_at, dataUpdatedAt: r.data_updated_at,
        exams: Number(r.exams), topics: Number(r.topics), topicsCompleted: Number(r.topics_done),
        sessions: Number(r.sessions), sessionsCompleted: Number(r.sessions_done),
      })),
    });
  } catch (e) {
    console.error("admin users error", e);
    res.status(500).json({ error: "Couldn't load users." });
  }
});

app.get("/api/admin/feedback", requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(200, Math.max(1, Number(req.query.limit) || 50));
    const kind = req.query.kind === "bug" || req.query.kind === "feedback" ? req.query.kind : null;
    const result = await pool.query(
      `SELECT f.id, f.kind, f.message, f.page, f.user_agent, f.created_at, u.name AS user_name, u.email AS user_email
       FROM feedback f LEFT JOIN users u ON u.id = f.user_id
       ${kind ? "WHERE f.kind = $2" : ""}
       ORDER BY f.created_at DESC LIMIT $1`,
      kind ? [limit, kind] : [limit]
    );
    res.json({ items: result.rows });
  } catch (e) {
    console.error("admin feedback error", e);
    res.status(500).json({ error: "Couldn't load feedback." });
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
    console.error("admin events error", e);
    res.status(500).json({ error: "Couldn't load events." });
  }
});

app.get("/api/admin/health", requireAdmin, async (req, res) => {
  const startedAt = Date.now();
  let dbOk = true;
  try {
    await pool.query("SELECT 1");
  } catch (e) {
    dbOk = false;
  }
  const dbLatencyMs = Date.now() - startedAt;
  let errorCountToday = 0, lastError = null, dbSizeBytes = null;
  try {
    const r = await pool.query(`SELECT COUNT(*) AS n, MAX(created_at) AS last FROM events WHERE event_type = 'api_error' AND created_at >= now() - interval '1 day'`);
    errorCountToday = Number(r.rows[0].n);
    lastError = r.rows[0].last;
    const sz = await pool.query(`SELECT pg_database_size(current_database()) AS b`);
    dbSizeBytes = Number(sz.rows[0].b);
  } catch (e) { /* ignore */ }

  res.json({
    status: dbOk ? (errorCountToday > 20 ? "warning" : "healthy") : "critical",
    database: dbOk ? "connected" : "unreachable",
    databaseLatencyMs: dbLatencyMs,
    databaseSizeBytes: dbSizeBytes,
    processUptimeSeconds: Math.round(process.uptime()),
    nodeVersion: process.version,
    smartImportConfigured: Boolean(GEMINI_API_KEY),
    errorCountToday,
    lastErrorAt: lastError,
  });
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
