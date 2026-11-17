// P&N MOIN accounts: PostgreSQL + scrypt password hashing + HttpOnly cookie sessions.
// Needs the DATABASE_URL environment variable. Without it the game still works as a guest.
const crypto = require("crypto");
let Pool = null;
try { ({ Pool } = require("pg")); } catch (e) { /* pg not installed */ }

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  player_id TEXT UNIQUE NOT NULL,
  username TEXT NOT NULL,
  email TEXT NOT NULL,
  pass_hash TEXT NOT NULL,
  avatar TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS users_username_ci ON users (lower(username));
CREATE UNIQUE INDEX IF NOT EXISTS users_email_ci ON users (lower(email));
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS reset_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  used BOOLEAN NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS games (
  id SERIAL PRIMARY KEY,
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  cid TEXT NOT NULL,
  mode TEXT NOT NULL,
  diff TEXT,
  won BOOLEAN NOT NULL,
  attempts INT NOT NULL,
  source TEXT NOT NULL DEFAULT 'client',
  played_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, cid)
);`;

let pool = null, ready = false;

async function init() {
  const url = process.env.DATABASE_URL;
  if (!url || !Pool) { console.log("Accounts disabled: " + (!url ? "set the DATABASE_URL variable" : "the pg package is not installed")); return; }
  try {
    const host = new URL(url).hostname;
    const forced = process.env.DATABASE_SSL;
    const useSsl = forced ? forced !== "false" : host.includes("."); // Render internal hosts have no dots
    pool = new Pool({ connectionString: url, ssl: useSsl ? { rejectUnauthorized: false } : false, max: 8 });
    pool.on("error", e => console.log("Database connection error:", e.message));
    await pool.query(SCHEMA);
    ready = true;
    console.log("Accounts ready (PostgreSQL connected)");
    setInterval(() => pool.query("DELETE FROM sessions WHERE expires_at < now()").catch(() => {}), 3600e3);
  } catch (e) { console.log("Accounts disabled, database error:", e.message); }
}

/* ---------- helpers ---------- */
const scrypt = (pw, salt) => new Promise((res, rej) => crypto.scrypt(pw, salt, 64, (e, k) => (e ? rej(e) : res(k))));
async function hashPw(pw) {
  const salt = crypto.randomBytes(16);
  return "s1$" + salt.toString("base64") + "$" + (await scrypt(pw, salt)).toString("base64");
}
async function checkPw(pw, stored) {
  const [v, s, h] = String(stored).split("$");
  if (v !== "s1" || !s || !h) return false;
  const k = await scrypt(pw, Buffer.from(s, "base64")), hb = Buffer.from(h, "base64");
  return hb.length === k.length && crypto.timingSafeEqual(hb, k);
}
const sha = t => crypto.createHash("sha256").update(t).digest("hex");
const json = (res, code, obj, headers = {}) => {
  res.writeHead(code, Object.assign({ "Content-Type": "application/json", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" }, headers));
  res.end(JSON.stringify(obj));
};
const readBody = req => new Promise(r => {
  let b = "";
  req.on("data", c => { b += c; if (b.length > 120000) req.destroy(); });
  req.on("end", () => { try { r(JSON.parse(b || "{}")); } catch (e) { r(null); } });
  req.on("error", () => r(null));
});
const getCookie = (req, name) => {
  const p = (req.headers.cookie || "").split(";").map(s => s.trim().split("=")).find(x => x[0] === name);
  return p ? p[1] : null;
};
const hits = new Map();
function limited(req, key, max, windowMs) {
  const ip = String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
  const k = key + ip, now = Date.now();
  let h = hits.get(k);
  if (!h || now > h.t) h = { n: 0, t: now + windowMs };
  h.n++; hits.set(k, h);
  return h.n > max;
}
setInterval(() => { const n = Date.now(); hits.forEach((v, k) => { if (n > v.t) hits.delete(k); }); }, 60000);

const validName = s => typeof s === "string" && /^[A-Za-z0-9_]{3,20}$/.test(s);
const validEmail = s => typeof s === "string" && s.length <= 254 && /^[^\s@]{1,64}@[^\s@]+\.[^\s@]{2,}$/.test(s);
const validPw = s => typeof s === "string" && s.length >= 8 && s.length <= 100;
const cleanAvatar = a => (typeof a === "string" && a.length <= 60000 && /^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(a) ? a : null);
const pub = u => ({ id: u.player_id, username: u.username, email: u.email, avatar: u.avatar, created: u.created_at });
const playerId = () => "PN-" + crypto.randomInt(100000, 1000000);

async function mail(to, subject, text) {
  const key = process.env.RESEND_API_KEY, from = process.env.MAIL_FROM;
  if (!key || !from) { console.log("[email not configured] To: " + to + "\n" + subject + "\n" + text); return false; }
  try {
    const r = await fetch("https://api.resend.com/emails", { method: "POST",
      headers: { Authorization: "Bearer " + key, "Content-Type": "application/json" },
      body: JSON.stringify({ from, to: [to], subject, text }) });
    return r.ok;
  } catch (e) { return false; }
}

async function newSession(req, res, userId, payload) {
  const t = crypto.randomBytes(32).toString("hex");
  await pool.query("INSERT INTO sessions(token_hash, user_id, expires_at) VALUES ($1, $2, now() + interval '30 days')", [sha(t), userId]);
  const secure = req.headers["x-forwarded-proto"] === "https" ? "; Secure" : "";
  json(res, 200, payload, { "Set-Cookie": `pn_sid=${t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${30 * 86400}${secure}` });
}
async function authUser(req) {
  const t = getCookie(req, "pn_sid");
  if (!t) return null;
  const r = await pool.query("SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = $1 AND s.expires_at > now()", [sha(t)]);
  if (r.rows[0]) pool.query("UPDATE users SET last_seen = now() WHERE id = $1", [r.rows[0].id]).catch(() => {});
  return r.rows[0] || null;
}
async function stats(userId) {
  const r = await pool.query("SELECT mode, diff, won, attempts FROM games WHERE user_id = $1 ORDER BY played_at, id", [userId]);
  let w = 0, l = 0, cur = 0, best = 0; const bd = {};
  r.rows.forEach(g => {
    if (g.won) {
      w++; cur++; best = Math.max(best, cur);
      const k = g.mode === "online" ? "online" : g.diff;
      if (!bd[k] || g.attempts < bd[k]) bd[k] = g.attempts;
    } else { l++; cur = 0; }
  });
  return { games: w + l, wins: w, losses: l, winRate: w + l ? Math.round((w / (w + l)) * 100) : 0, bestStreak: best, best: bd };
}
const clearCookie = { "Set-Cookie": "pn_sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0" };

/* ---------- routes ---------- */
async function route(req, res, u) {
  const p = u.pathname;
  if (!ready) {
    if (req.method === "GET" && p === "/api/me") return json(res, 200, { enabled: false, user: null });
    return json(res, 503, { error: "Accounts are not set up on this server yet" });
  }
  try {
    if (req.method === "GET" && p === "/api/me") {
      const me = await authUser(req);
      return json(res, 200, { enabled: true, user: me ? pub(me) : null, stats: me ? await stats(me.id) : null });
    }
    if (req.method !== "POST") return json(res, 405, { error: "Method not allowed" });
    if (!/json/.test(req.headers["content-type"] || "")) return json(res, 415, { error: "Bad request" });
    const origin = req.headers.origin;
    if (origin) { let ok = false; try { ok = new URL(origin).host === req.headers.host; } catch (e) {} if (!ok) return json(res, 403, { error: "Forbidden" }); }
    const b = await readBody(req);
    if (!b || typeof b !== "object") return json(res, 400, { error: "Bad request" });

    if (p === "/api/auth/register") {
      if (limited(req, "reg", 8, 3600e3)) return json(res, 429, { error: "Too many attempts. Try again later." });
      if (!validName(b.username)) return json(res, 400, { error: "Username: 3-20 letters, numbers or _" });
      if (!validEmail(b.email)) return json(res, 400, { error: "Enter a valid email" });
      if (!validPw(b.password)) return json(res, 400, { error: "Password must be 8-100 characters" });
      const hash = await hashPw(b.password), av = b.avatar ? cleanAvatar(b.avatar) : null;
      for (let i = 0; i < 5; i++) {
        try {
          const r = await pool.query("INSERT INTO users(player_id, username, email, pass_hash, avatar) VALUES ($1, $2, $3, $4, $5) RETURNING *",
            [playerId(), b.username, b.email.toLowerCase(), hash, av]);
          const user = r.rows[0];
          return newSession(req, res, user.id, { user: pub(user), stats: await stats(user.id) });
        } catch (er) {
          if (er.code === "23505") {
            const c = er.constraint || "";
            if (/username/.test(c)) return json(res, 409, { error: "That username is already taken" });
            if (/email/.test(c)) return json(res, 409, { error: "That email is already registered" });
            continue; // player id collision: try again
          }
          throw er;
        }
      }
      return json(res, 500, { error: "Could not create the account" });
    }

    if (p === "/api/auth/login") {
      if (limited(req, "login", 10, 600e3)) return json(res, 429, { error: "Too many attempts. Wait a few minutes." });
      const id = String(b.id || "").trim(), pw = String(b.password || "");
      const r = await pool.query("SELECT * FROM users WHERE lower(username) = lower($1) OR lower(email) = lower($1)", [id]);
      const user = r.rows[0];
      let good = false;
      if (user) good = await checkPw(pw, user.pass_hash); else await scrypt(pw, Buffer.alloc(16));
      if (!good) return json(res, 401, { error: "Wrong username/email or password" });
      return newSession(req, res, user.id, { user: pub(user), stats: await stats(user.id) });
    }

    if (p === "/api/auth/logout") {
      const t = getCookie(req, "pn_sid");
      if (t) await pool.query("DELETE FROM sessions WHERE token_hash = $1", [sha(t)]);
      return json(res, 200, { ok: true }, clearCookie);
    }

    if (p === "/api/auth/forgot") {
      if (limited(req, "forgot", 5, 3600e3)) return json(res, 429, { error: "Too many requests. Try again later." });
      const email = String(b.email || "").trim();
      if (validEmail(email)) {
        const r = await pool.query("SELECT id, username FROM users WHERE lower(email) = lower($1)", [email]);
        if (r.rows[0]) {
          const t = crypto.randomBytes(32).toString("hex");
          await pool.query("INSERT INTO reset_tokens(token_hash, user_id, expires_at) VALUES ($1, $2, now() + interval '1 hour')", [sha(t), r.rows[0].id]);
          const base = process.env.PUBLIC_URL || ((req.headers["x-forwarded-proto"] || "http") + "://" + req.headers.host);
          await mail(email, "Reset your P&N MOIN password",
            `Hi ${r.rows[0].username},\n\nOpen this link to choose a new password (valid for 1 hour):\n${base}/?reset=${t}\n\nIf you did not ask for this, ignore this email.`);
        }
      }
      return json(res, 200, { ok: true }); // same answer whether or not the email exists
    }

    if (p === "/api/auth/reset") {
      if (limited(req, "reset", 10, 3600e3)) return json(res, 429, { error: "Too many attempts. Try again later." });
      if (!validPw(b.password)) return json(res, 400, { error: "Password must be 8-100 characters" });
      const r = await pool.query("UPDATE reset_tokens SET used = true WHERE token_hash = $1 AND used = false AND expires_at > now() RETURNING user_id", [sha(String(b.token || ""))]);
      if (!r.rows[0]) return json(res, 400, { error: "This reset link is invalid or has expired" });
      await pool.query("UPDATE users SET pass_hash = $1 WHERE id = $2", [await hashPw(b.password), r.rows[0].user_id]);
      await pool.query("DELETE FROM sessions WHERE user_id = $1", [r.rows[0].user_id]);
      return json(res, 200, { ok: true });
    }

    // Everything below needs a signed-in user
    const me = await authUser(req);
    if (!me) return json(res, 401, { error: "Please sign in" });

    if (p === "/api/me/update") {
      const sets = [], vals = [];
      if (b.username !== undefined && b.username !== me.username) {
        if (!validName(b.username)) return json(res, 400, { error: "Username: 3-20 letters, numbers or _" });
        vals.push(b.username); sets.push("username = $" + vals.length);
      }
      if (b.avatar !== undefined) {
        const av = b.avatar === null ? null : cleanAvatar(b.avatar);
        if (b.avatar !== null && !av) return json(res, 400, { error: "That picture is not supported or is too large" });
        vals.push(av); sets.push("avatar = $" + vals.length);
      }
      if (!sets.length) return json(res, 200, { user: pub(me) });
      vals.push(me.id);
      try {
        const r = await pool.query("UPDATE users SET " + sets.join(", ") + " WHERE id = $" + vals.length + " RETURNING *", vals);
        return json(res, 200, { user: pub(r.rows[0]) });
      } catch (er) {
        if (er.code === "23505") return json(res, 409, { error: "That username is already taken" });
        throw er;
      }
    }

    if (p === "/api/me/delete") {
      if (limited(req, "del", 5, 3600e3)) return json(res, 429, { error: "Too many attempts. Try again later." });
      if (!(await checkPw(String(b.password || ""), me.pass_hash))) return json(res, 401, { error: "Wrong password" });
      await pool.query("DELETE FROM users WHERE id = $1", [me.id]); // sessions, games and tokens cascade
      return json(res, 200, { ok: true }, clearCookie);
    }

    if (p === "/api/sync") {
      const list = Array.isArray(b.games) ? b.games.slice(0, 100) : [];
      const now = Date.now();
      for (const g of list) {
        if (!g || typeof g.cid !== "string" || g.cid.length < 8 || g.cid.length > 64) continue;
        if (!["cpu", "two", "online"].includes(g.mode) || !["easy", "medium", "hard", "online"].includes(g.diff)) continue;
        const attempts = Math.floor(Number(g.attempts));
        if (typeof g.won !== "boolean" || !(attempts >= 1 && attempts <= 1000)) continue;
        const ts = Math.min(Math.max(Number(g.ts) || now, now - 3.15e10), now);
        await pool.query("INSERT INTO games(user_id, cid, mode, diff, won, attempts, source, played_at) VALUES ($1, $2, $3, $4, $5, $6, 'client', $7) ON CONFLICT (user_id, cid) DO NOTHING",
          [me.id, g.cid, g.mode, g.diff, g.won, attempts, new Date(ts)]);
      }
      return json(res, 200, { ok: true, stats: await stats(me.id) });
    }

    return json(res, 404, { error: "Not found" });
  } catch (e) {
    console.error("auth error:", e.message);
    return json(res, 500, { error: "Server error. Please try again." });
  }
}

module.exports = { init, route, _test: { hashPw, checkPw } };
