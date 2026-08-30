const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
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
}

const app = express();
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

/* ---------------- data sync routes ---------------- */

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

/* ---------------- smart import (AI extraction) ---------------- */

const MAX_FILE_BYTES = 8 * 1024 * 1024; // ~8MB per file, base64 included

function fileToContentBlock(file, label) {
  // file: { mediaType, base64 }
  if (!file || !file.base64 || !file.mediaType) return null;
  if (file.base64.length > MAX_FILE_BYTES) throw new Error(`${label} file is too large. Please use a file under ~6MB.`);
  if (file.mediaType === "application/pdf") {
    return { type: "document", source: { type: "base64", media_type: "application/pdf", data: file.base64 } };
  }
  if (file.mediaType.startsWith("image/")) {
    return { type: "image", source: { type: "base64", media_type: file.mediaType, data: file.base64 } };
  }
  throw new Error(`${label} must be a PDF, JPG, or PNG.`);
}

app.post("/api/import/analyze", requireAuth, async (req, res) => {
  try {
    if (!ANTHROPIC_API_KEY) {
      return res.status(503).json({ error: "Smart Import isn't set up yet. Please try again later." });
    }
    const { syllabusFile, datesheetFile } = req.body || {};
    if (!syllabusFile && !datesheetFile) {
      return res.status(400).json({ error: "Please upload at least one document." });
    }

    const content = [];
    try {
      const dsBlock = fileToContentBlock(datesheetFile, "Date sheet");
      if (dsBlock) { content.push({ type: "text", text: "This document is the DATE SHEET (exam schedule):" }); content.push(dsBlock); }
      const syBlock = fileToContentBlock(syllabusFile, "Syllabus");
      if (syBlock) { content.push({ type: "text", text: "This document is the SYLLABUS (chapters/topics):" }); content.push(syBlock); }
    } catch (fileErr) {
      return res.status(400).json({ error: fileErr.message });
    }

    const today = new Date().toISOString().slice(0, 10);
    content.push({
      type: "text",
      text:
        `Extract academic schedule information from the document(s) above. ` +
        `If both a date sheet and a syllabus are provided, match each subject in the syllabus to its exam date/time in the date sheet, ` +
        `recognizing equivalent/abbreviated subject names as the same subject (for example: "Maths" = "Mathematics", "SST" = "Social Science", "EVS" = "Environmental Studies"). ` +
        `Today's date is ${today}; if a date sheet gives a day/month without a year, assume the nearest future occurrence. ` +
        `Respond with ONLY raw JSON (no markdown code fences, no explanation) matching exactly this shape:\n` +
        `{"subjects":[{"subject":"string","examDate":"YYYY-MM-DD or null","examTime":"HH:MM 24-hour or null","topics":["string", ...]}]}\n` +
        `Include every subject you can identify from either document, even if some fields are null. Keep topic names short and specific (chapter/unit/section titles).`,
    });

    const aiRes = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: "claude-sonnet-4-6",
        max_tokens: 4000,
        messages: [{ role: "user", content }],
      }),
    });

    if (!aiRes.ok) {
      const errText = await aiRes.text().catch(() => "");
      console.error("Anthropic API error", aiRes.status, errText);
      return res.status(502).json({ error: "Couldn't analyze your documents right now. Please try again." });
    }

    const aiJson = await aiRes.json();
    const textBlock = (aiJson.content || []).find((b) => b.type === "text");
    if (!textBlock) return res.status(502).json({ error: "The AI didn't return a readable response. Please try again." });

    let cleaned = textBlock.text.trim();
    cleaned = cleaned.replace(/^```json\s*/i, "").replace(/^```\s*/i, "").replace(/```\s*$/i, "").trim();

    let parsed;
    try {
      parsed = JSON.parse(cleaned);
    } catch (parseErr) {
      console.error("JSON parse failed", cleaned.slice(0, 500));
      return res.status(502).json({ error: "Couldn't understand the documents clearly. Try clearer photos or a text-based PDF." });
    }

    const subjects = Array.isArray(parsed.subjects) ? parsed.subjects : [];
    const clean = subjects
      .filter((s) => s && s.subject)
      .map((s) => ({
        subject: String(s.subject).trim(),
        examDate: typeof s.examDate === "string" && /^\d{4}-\d{2}-\d{2}$/.test(s.examDate) ? s.examDate : null,
        examTime: typeof s.examTime === "string" && /^\d{2}:\d{2}$/.test(s.examTime) ? s.examTime : null,
        topics: Array.isArray(s.topics) ? s.topics.filter(Boolean).map((t) => String(t).trim()).slice(0, 60) : [],
      }));

    res.json({ subjects: clean });
  } catch (e) {
    console.error("import analyze error", e);
    res.status(500).json({ error: "Something went wrong analyzing your documents. Please try again." });
  }
});

/* ---------------- account management ---------------- */

app.delete("/api/account", requireAuth, async (req, res) => {
  try {
    await pool.query("DELETE FROM users WHERE id = $1", [req.userId]);
    res.json({ ok: true });
  } catch (e) {
    console.error("delete account error", e);
    res.status(500).json({ error: "Couldn't delete your account. Please try again." });
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
