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
const ADMIN_KEY = process.env.ADMIN_KEY || "";
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
    next();
  } catch (e) {
    return res.status(401).json({ error: "Your session has expired. Please log in again." });
  }
}

/* ---------------- auth routes ---------------- */

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

app.post("/api/auth/login", async (req, res) => {
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
    const result = await pool.query("SELECT id, name, email, created_at FROM users WHERE id = $1", [req.userId]);
    const user = result.rows[0];
    if (!user) return res.status(404).json({ error: "Account not found." });
    res.json({ user });
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

/* ---------------- admin (usage analytics) ---------------- */

function requireAdmin(req, res, next) {
  if (!ADMIN_KEY) return res.status(503).json({ error: "Admin dashboard isn't configured yet." });
  const key = req.headers["x-admin-key"];
  if (key !== ADMIN_KEY) return res.status(401).json({ error: "Invalid admin key." });
  next();
}

app.get("/api/admin/overview", requireAdmin, async (req, res) => {
  try {
    const dayAgo = "now() - interval '1 day'";
    const weekAgo = "now() - interval '7 days'";
    const monthAgo = "now() - interval '30 days'";

    const [usersTotal, usersToday, usersWeek, devicesTotal, eventsByType, activeToday, activeWeek] = await Promise.all([
      pool.query(`SELECT COUNT(*) AS n FROM users`),
      pool.query(`SELECT COUNT(*) AS n FROM users WHERE created_at >= ${dayAgo}`),
      pool.query(`SELECT COUNT(*) AS n FROM users WHERE created_at >= ${weekAgo}`),
      pool.query(`SELECT COUNT(DISTINCT device_id) AS n FROM events WHERE device_id IS NOT NULL`),
      pool.query(`SELECT event_type, COUNT(*) AS n FROM events WHERE created_at >= ${monthAgo} GROUP BY event_type ORDER BY n DESC`),
      pool.query(`SELECT COUNT(DISTINCT device_id) AS n FROM events WHERE device_id IS NOT NULL AND created_at >= ${dayAgo}`),
      pool.query(`SELECT COUNT(DISTINCT device_id) AS n FROM events WHERE device_id IS NOT NULL AND created_at >= ${weekAgo}`),
    ]);

    res.json({
      registeredUsers: Number(usersTotal.rows[0].n),
      newUsersToday: Number(usersToday.rows[0].n),
      newUsersThisWeek: Number(usersWeek.rows[0].n),
      devicesEverSeen: Number(devicesTotal.rows[0].n),
      activeToday: Number(activeToday.rows[0].n),
      activeThisWeek: Number(activeWeek.rows[0].n),
      eventCountsLast30Days: eventsByType.rows.map((r) => ({ eventType: r.event_type, count: Number(r.n) })),
    });
  } catch (e) {
    console.error("admin overview error", e);
    res.status(500).json({ error: "Couldn't load overview." });
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
  let errorCountToday = 0;
  try {
    const r = await pool.query(`SELECT COUNT(*) AS n FROM events WHERE event_type = 'api_error' AND created_at >= now() - interval '1 day'`);
    errorCountToday = Number(r.rows[0].n);
  } catch (e) { /* ignore */ }

  res.json({
    status: dbOk ? (errorCountToday > 20 ? "warning" : "healthy") : "critical",
    database: dbOk ? "connected" : "unreachable",
    databaseLatencyMs: dbLatencyMs,
    processUptimeSeconds: Math.round(process.uptime()),
    errorCountToday,
  });
});

app.get("/health", (req, res) => res.json({ ok: true }));

initDb()
  .then(async () => {
    if (process.env.RUN_DB_MIGRATION === "yes") {
      try {
        await require("./migrate")();
      } catch (e) {
        console.error("MIGRATION FAILED:", e.message);
      }
    }
    app.listen(PORT, () => console.log(`ExamFlow API listening on port ${PORT}`));
  })
  .catch((e) => {
    console.error("Failed to initialize database", e);
    process.exit(1);
  });
