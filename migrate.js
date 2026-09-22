// One-time copy of all ExamFlow data from the old database (DATABASE_URL)
// to the new Supabase database (NEW_DATABASE_URL).
// Runs only when the RUN_DB_MIGRATION environment variable is "yes".
// Safe to run more than once: rows that already exist in the new database are skipped.
const { Pool } = require("pg");

const TABLES = [
  { name: "users", cols: ["id", "name", "email", "password_hash", "is_admin", "created_at"], key: "id" },
  { name: "user_data", cols: ["user_id", "data", "updated_at"], key: "user_id" },
  { name: "events", cols: ["id", "device_id", "user_id", "event_type", "metadata", "created_at"], key: "id" },
];
const BATCH = 500;

async function copyTable(src, dst, t) {
  let lastKey = -1;
  let copied = 0;
  for (;;) {
    const { rows } = await src.query(
      `SELECT ${t.cols.join(", ")} FROM ${t.name} WHERE ${t.key} > $1 ORDER BY ${t.key} LIMIT ${BATCH}`,
      [lastKey]
    );
    if (!rows.length) break;
    const params = [];
    const tuples = rows.map((row) => {
      const ph = t.cols.map((c) => {
        const v = row[c];
        params.push(v !== null && typeof v === "object" && !(v instanceof Date) ? JSON.stringify(v) : v);
        return `$${params.length}`;
      });
      return `(${ph.join(", ")})`;
    });
    const res = await dst.query(
      `INSERT INTO ${t.name} (${t.cols.join(", ")}) VALUES ${tuples.join(", ")} ON CONFLICT (${t.key}) DO NOTHING`,
      params
    );
    copied += res.rowCount;
    lastKey = rows[rows.length - 1][t.key];
  }
  return copied;
}

module.exports = async function migrate() {
  const NEW_URL = process.env.NEW_DATABASE_URL;
  if (!NEW_URL) throw new Error("NEW_DATABASE_URL is not set");
  const src = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
  const dst = new Pool({ connectionString: NEW_URL, ssl: { rejectUnauthorized: false } });
  try {
    console.log("MIGRATION: starting copy from old database to new database");
    for (const t of TABLES) {
      const copied = await copyTable(src, dst, t);
      console.log(`MIGRATION: ${t.name}: ${copied} new rows copied`);
    }
    // Make sure new sign-ups and events continue numbering after the copied rows.
    for (const t of ["users", "events"]) {
      await dst.query(
        `SELECT setval(pg_get_serial_sequence('${t}', 'id'), COALESCE(MAX(id), 1), MAX(id) IS NOT NULL) FROM ${t}`
      );
    }
    // Verify counts match.
    let allMatch = true;
    for (const t of TABLES) {
      const a = Number((await src.query(`SELECT COUNT(*) AS n FROM ${t.name}`)).rows[0].n);
      const b = Number((await dst.query(`SELECT COUNT(*) AS n FROM ${t.name}`)).rows[0].n);
      if (a !== b) allMatch = false;
      console.log(`MIGRATION CHECK: ${t.name}: old=${a} new=${b} ${a === b ? "OK" : "MISMATCH"}`);
    }
    console.log(allMatch ? "MIGRATION COMPLETE: all counts match" : "MIGRATION WARNING: some counts differ");
  } finally {
    await src.end();
    await dst.end();
  }
};
