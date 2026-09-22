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
    req.tokenPayload = payload;
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
        SELECT COUNT(*) FILTER (WHERE kind = 'feedback') AS feedback,
               COUNT(*) FILTER (WHERE kind = 'bug') AS bugs,
               COUNT(*) FILTER (WHERE created_at >= now() - interval '7 days') AS last_7d
        FROM feedback`),
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
      feedback: { feedback: num(f.feedback), bugs: num(f.bugs), openBugs: num(f.bugs), last7d: num(f.last_7d), statusTracked: false },
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
      SELECT CASE WHEN f.kind = 'bug' THEN 'bug_reported' ELSE 'feedback_submitted' END AS type, f.created_at AS at, f.user_id,
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
    const status = ["active", "inactive"].includes(req.query.status) ? req.query.status : "all";
    const sort = { newest: "u.created_at DESC", oldest: "u.created_at ASC", last_active: "seen.last_seen DESC NULLS LAST" }[req.query.sort] || "u.created_at DESC";
    const joinedFrom = isoDate(req.query.joinedFrom);
    const joinedTo = isoDate(req.query.joinedTo);

    const where = [];
    const params = [];
    const add = (v) => { params.push(v); return `$${params.length}`; };
    if (q) { const p = add(`%${q}%`); where.push(`(u.name ILIKE ${p} OR u.email ILIKE ${p})`); }
    if (status === "active") where.push(`seen.last_seen >= now() - interval '30 days'`);
    if (status === "inactive") where.push(`(seen.last_seen IS NULL OR seen.last_seen < now() - interval '30 days')`);
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
        SELECT u.id, u.name, u.email, u.created_at, u.is_admin, seen.last_seen
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
        id: r.id, name: r.name, email: r.email, isAdmin: r.is_admin === true, accountStatus: "active",
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
      `WITH ${SEEN_CTE} SELECT u.id, u.name, u.email, u.created_at, u.is_admin, seen.last_seen FROM users u JOIN seen ON seen.user_id = u.id WHERE u.id = $1`,
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
        id: r.id, name: r.name, email: r.email, isAdmin: r.is_admin === true, accountStatus: "active",
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

app.get("/health", (req, res) => res.json({ ok: true }));

initDb()
  .then(() => {
    app.listen(PORT, () => console.log(`ExamFlow API listening on port ${PORT}`));
  })
  .catch((e) => {
    console.error("Failed to initialize database", e);
    process.exit(1);
  });
