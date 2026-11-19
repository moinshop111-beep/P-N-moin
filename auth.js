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
);
CREATE TABLE IF NOT EXISTS friendships (
  id SERIAL PRIMARY KEY,
  requester INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  addressee INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK (status IN ('pending', 'accepted', 'blocked')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS friendships_pair ON friendships (LEAST(requester, addressee), GREATEST(requester, addressee));
CREATE TABLE IF NOT EXISTS notifications (
  id SERIAL PRIMARY KEY,
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  data JSONB NOT NULL DEFAULT '{}',
  read BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS show_online BOOLEAN NOT NULL DEFAULT true;
CREATE TABLE IF NOT EXISTS dms (
  id SERIAL PRIMARY KEY,
  from_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  to_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  text TEXT NOT NULL,
  read BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS dms_pair ON dms (LEAST(from_id, to_id), GREATEST(from_id, to_id), id);
CREATE INDEX IF NOT EXISTS dms_unread ON dms (to_id) WHERE NOT read;`;

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
    setInterval(() => {
      pool.query("DELETE FROM sessions WHERE expires_at < now()").catch(() => {});
      pool.query("DELETE FROM notifications WHERE created_at < now() - interval '30 days'").catch(() => {});
      pool.query("DELETE FROM dms WHERE created_at < now() - interval '60 days'").catch(() => {});
    }, 3600e3);
    setInterval(() => conns.forEach(set => set.forEach(c => { try { c.res.write(": ping\n\n"); } catch (e) {} })), 25000);
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
const pub = u => ({ id: u.player_id, username: u.username, email: u.email, avatar: u.avatar, created: u.created_at, showOnline: u.show_online !== false });
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

/* ---------- friends, presence, notifications ---------- */
const conns = new Map();      // userId -> Set of { res, cid, st }  (one per open tab/device)
const lastStatus = new Map(); // userId -> last status we told friends about
const offTimers = new Map();  // userId -> timer that confirms a real disconnect
const statusOf = id => {
  const s = conns.get(id);
  if (!s || !s.size) return "offline";
  let st = "away";
  for (const c of s) { if (c.st === "game") return "game"; if (c.st === "online") st = "online"; }
  return st;
};
const emit = (id, obj) => {
  const s = conns.get(id);
  if (!s) return;
  const d = "data: " + JSON.stringify(obj) + "\n\n";
  s.forEach(c => { try { c.res.write(d); } catch (e) {} });
};
async function friendIds(id) {
  const r = await pool.query("SELECT CASE WHEN requester = $1 THEN addressee ELSE requester END AS fid FROM friendships WHERE status = 'accepted' AND (requester = $1 OR addressee = $1)", [id]);
  return r.rows.map(x => x.fid);
}
async function refreshPresence(u) {
  const st = statusOf(u.id), prev = lastStatus.get(u.id) || "offline";
  if (st === prev) return;
  if (st === "offline") lastStatus.delete(u.id); else lastStatus.set(u.id, st);
  const ids = await friendIds(u.id), seen = new Date().toISOString();
  ids.forEach(f => {
    emit(f, { t: "presence", id: u.player_id, status: st, seen });
    if (prev === "offline") emit(f, { t: "notify", kind: "friend_online", name: u.username });
  });
}
function openEvents(req, res, me) {
  res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive", "X-Accel-Buffering": "no" });
  const c = { res, cid: crypto.randomBytes(6).toString("hex"), st: "online" };
  if (!conns.has(me.id)) conns.set(me.id, new Set());
  conns.get(me.id).add(c);
  clearTimeout(offTimers.get(me.id)); offTimers.delete(me.id);
  res.write("retry: 3000\n\n");
  res.write("data: " + JSON.stringify({ t: "hello", cid: c.cid }) + "\n\n");
  refreshPresence(me).catch(() => {});
  req.on("close", () => {
    const s = conns.get(me.id);
    if (s) { s.delete(c); if (!s.size) conns.delete(me.id); }
    if (conns.has(me.id)) return void refreshPresence(me).catch(() => {});
    // wait a few seconds so a page refresh does not look like going offline
    clearTimeout(offTimers.get(me.id));
    offTimers.set(me.id, setTimeout(() => {
      offTimers.delete(me.id);
      pool.query("UPDATE users SET last_seen = now() WHERE id = $1", [me.id]).catch(() => {});
      refreshPresence(me).catch(() => {});
    }, 6000));
  });
}
const userByPid = async pid => (await pool.query("SELECT id, player_id, username FROM users WHERE player_id = $1", [pid])).rows[0];
const pairRow = async (a, b) => (await pool.query("SELECT * FROM friendships WHERE (requester = $1 AND addressee = $2) OR (requester = $2 AND addressee = $1)", [a, b])).rows[0];
async function notify(userId, type, data) {
  await pool.query("INSERT INTO notifications(user_id, type, data) VALUES ($1, $2, $3)", [userId, type, data]);
  emit(userId, { t: "notify", kind: type, name: data.username });
  emit(userId, { t: "friends_changed" });
}
async function friendsList(me) {
  const r = await pool.query(`SELECT f.status, f.requester, u.id AS uid, u.player_id, u.username, (u.avatar IS NOT NULL) AS av, u.last_seen
    FROM friendships f JOIN users u ON u.id = CASE WHEN f.requester = $1 THEN f.addressee ELSE f.requester END
    WHERE f.requester = $1 OR f.addressee = $1 ORDER BY u.username`, [me.id]);
  const un = new Map((await pool.query("SELECT from_id, count(*)::int AS n FROM dms WHERE to_id = $1 AND NOT read GROUP BY from_id", [me.id])).rows.map(x => [x.from_id, x.n]));
  const out = { friends: [], incoming: [], outgoing: [], blocked: [] };
  r.rows.forEach(x => {
    const o = { id: x.player_id, username: x.username, av: x.av };
    if (x.status === "accepted") out.friends.push(Object.assign(o, { status: statusOf(x.uid), seen: x.last_seen, unread: un.get(x.uid) || 0 }));
    else if (x.status === "pending") (x.requester === me.id ? out.outgoing : out.incoming).push(o);
    else if (x.status === "blocked" && x.requester === me.id) out.blocked.push(o);
  });
  return out;
}
async function notifList(id) {
  const r = await pool.query("SELECT type, data, read, created_at FROM notifications WHERE user_id = $1 ORDER BY id DESC LIMIT 30", [id]);
  const n = await pool.query("SELECT count(*)::int AS n FROM notifications WHERE user_id = $1 AND NOT read", [id]);
  return { items: r.rows.map(x => ({ type: x.type, name: x.data.username, read: x.read, at: x.created_at })), unread: n.rows[0].n };
}

/* ---------- leaderboard ---------- */
const LB = {
  wins: "SELECT user_id, count(*) FILTER (WHERE won)::int AS v FROM games WHERE source = 'verified' GROUP BY user_id HAVING count(*) FILTER (WHERE won) > 0",
  winrate: "SELECT user_id, round(100.0 * count(*) FILTER (WHERE won) / count(*))::int AS v FROM games WHERE source = 'verified' GROUP BY user_id HAVING count(*) >= 5",
  games: "SELECT user_id, count(*)::int AS v FROM games WHERE source = 'verified' GROUP BY user_id",
  weekly: "SELECT user_id, count(*) FILTER (WHERE won)::int AS v FROM games WHERE source = 'verified' AND played_at > now() - interval '7 days' GROUP BY user_id HAVING count(*) FILTER (WHERE won) > 0",
  monthly: "SELECT user_id, count(*) FILTER (WHERE won)::int AS v FROM games WHERE source = 'verified' AND played_at > now() - interval '30 days' GROUP BY user_id HAVING count(*) FILTER (WHERE won) > 0",
  streak: "SELECT user_id, max(len)::int AS v FROM (SELECT user_id, count(*) AS len FROM (SELECT user_id, won, row_number() OVER (PARTITION BY user_id ORDER BY played_at, id) - row_number() OVER (PARTITION BY user_id, won ORDER BY played_at, id) AS grp FROM games WHERE source = 'verified') t WHERE won GROUP BY user_id, grp) s GROUP BY user_id"
};
const relOf = (meId, otherId, rows) => {
  const f = rows.find(y => y.requester === otherId || y.addressee === otherId);
  return !f ? "none" : f.status === "accepted" ? "friend" : f.status === "pending" ? (f.requester === meId ? "pending_out" : "pending_in") : "blocked";
};

/* ---------- helpers used by the match server ---------- */
const userFromReq = async req => { if (!ready) return null; try { return await authUser(req); } catch (e) { return null; } };
const isOnline = id => !!(conns.get(id) && conns.get(id).size);
const friendUser = async (meId, pid) => {
  if (!ready) return null;
  const r = await pool.query("SELECT u.id, u.username FROM users u JOIN friendships f ON f.status = 'accepted' AND ((f.requester = $1 AND f.addressee = u.id) OR (f.addressee = $1 AND f.requester = u.id)) WHERE u.player_id = $2", [meId, pid]);
  return r.rows[0] || null;
};
const recordMatch = (userId, cid, won, attempts) => {
  if (!ready) return;
  pool.query("INSERT INTO games(user_id, cid, mode, diff, won, attempts, source) VALUES ($1, $2, 'online', 'online', $3, $4, 'verified') ON CONFLICT (user_id, cid) DO NOTHING", [userId, cid, won, attempts])
    .catch(e => console.log("recordMatch:", e.message));
};

/* ---------- routes ---------- */
async function route(req, res, u) {
  const p = u.pathname;
  if (!ready) {
    if (req.method === "GET" && p === "/api/me") return json(res, 200, { enabled: false, user: null });
    if (req.method === "GET" && p === "/api/leaderboard") return json(res, 200, { cat: "wins", rows: [] });
    return json(res, 503, { error: "Accounts are not set up on this server yet" });
  }
  try {
    if (req.method === "GET" && p === "/api/leaderboard") {
      const cat = u.searchParams.get("cat") || "wins";
      if (!Object.prototype.hasOwnProperty.call(LB, cat)) return json(res, 400, { error: "Unknown category" });
      const viewer = await authUser(req);
      const r = await pool.query("SELECT x.v, u.player_id, u.username, (u.avatar IS NOT NULL) AS av FROM (" + LB[cat] + ") x JOIN users u ON u.id = x.user_id ORDER BY x.v DESC, u.username LIMIT 50");
      return json(res, 200, { cat, rows: r.rows.map((x, i) => ({ rank: i + 1, id: x.player_id, username: x.username, av: x.av, v: x.v, me: !!viewer && viewer.player_id === x.player_id })) });
    }
    if (req.method === "GET" && p === "/api/me") {
      const me = await authUser(req);
      return json(res, 200, { enabled: true, user: me ? pub(me) : null, stats: me ? await stats(me.id) : null });
    }
    if (req.method === "GET" && p.startsWith("/api/me/")) {
      const me = await authUser(req);
      if (!me) return json(res, 401, { error: "Please sign in" });
      if (p === "/api/me/events") return openEvents(req, res, me);
      if (p === "/api/me/friends") return json(res, 200, await friendsList(me));
      if (p === "/api/me/notifications") return json(res, 200, await notifList(me.id));
      if (p === "/api/me/dm") {
        const f = await friendUser(me.id, String(u.searchParams.get("with") || ""));
        if (!f) return json(res, 403, { error: "You can only chat with friends" });
        const r = await pool.query("SELECT id, from_id, text, created_at FROM dms WHERE (from_id = $1 AND to_id = $2) OR (from_id = $2 AND to_id = $1) ORDER BY id DESC LIMIT 60", [me.id, f.id]);
        await pool.query("UPDATE dms SET read = true WHERE to_id = $1 AND from_id = $2 AND NOT read", [me.id, f.id]);
        return json(res, 200, { name: f.username, status: statusOf(f.id), messages: r.rows.reverse().map(x => ({ mine: x.from_id === me.id, text: x.text, at: x.created_at })) });
      }
      if (p === "/api/me/online") {
        const ids = [...conns.keys()].filter(id => id !== me.id);
        if (!ids.length) return json(res, 200, { players: [] });
        const r = await pool.query(`SELECT u.id, u.player_id, u.username, u.show_online, (u.avatar IS NOT NULL) AS av FROM users u WHERE u.id = ANY($1)
          AND NOT EXISTS (SELECT 1 FROM friendships f WHERE f.status = 'blocked' AND ((f.requester = u.id AND f.addressee = $2) OR (f.requester = $2 AND f.addressee = u.id))) LIMIT 100`, [ids, me.id]);
        const fr = (await pool.query("SELECT requester, addressee, status FROM friendships WHERE (requester = $1 AND addressee = ANY($2)) OR (addressee = $1 AND requester = ANY($2))", [me.id, ids])).rows;
        const order = { game: 0, online: 1, away: 2 };
        const players = r.rows.map(x => ({ id: x.player_id, username: x.username, av: x.av, status: statusOf(x.id), rel: relOf(me.id, x.id, fr), show: x.show_online }))
          .filter(x => x.show || x.rel === "friend").map(({ show, ...x }) => x)
          .sort((a, b) => order[a.status] - order[b.status] || a.username.localeCompare(b.username));
        return json(res, 200, { players });
      }
      if (p === "/api/me/profile") {
        const [st, fc, rc] = await Promise.all([stats(me.id),
          pool.query("SELECT count(*)::int AS n FROM friendships WHERE status = 'accepted' AND (requester = $1 OR addressee = $1)", [me.id]),
          pool.query("SELECT mode, diff, won, attempts, played_at FROM games WHERE user_id = $1 ORDER BY played_at DESC, id DESC LIMIT 10", [me.id])]);
        return json(res, 200, { stats: st, friends: fc.rows[0].n, recent: rc.rows.map(x => ({ mode: x.mode, diff: x.diff, won: x.won, attempts: x.attempts, at: x.played_at })) });
      }
      if (p === "/api/me/player") { // public view of another player's account (never shows the email)
        const pid = String(u.searchParams.get("id") || "");
        const t = (await pool.query("SELECT id, player_id, username, (avatar IS NOT NULL) AS av, created_at, last_seen FROM users WHERE player_id = $1", [pid])).rows[0];
        if (!t) return json(res, 404, { error: "Player not found" });
        const row = t.id === me.id ? null : await pairRow(me.id, t.id);
        if (row && row.status === "blocked" && row.requester !== me.id) return json(res, 404, { error: "Player not found" });
        const rel = t.id === me.id ? "self" : !row ? "none" : row.status === "accepted" ? "friend" : row.status === "pending" ? (row.requester === me.id ? "pending_out" : "pending_in") : "blocked";
        const out = { id: t.player_id, username: t.username, av: t.av, joined: t.created_at, rel, stats: await stats(t.id) };
        if (rel === "friend") { out.status = statusOf(t.id); out.seen = t.last_seen; }
        return json(res, 200, out);
      }
      if (p === "/api/me/friends/search") {
        const raw = (u.searchParams.get("q") || "").trim().slice(0, 24);
        if (raw.length < 2) return json(res, 200, { results: [] });
        const byId = /^pn-\d{6}$/i.test(raw);
        const r = await pool.query("SELECT id, player_id, username, (avatar IS NOT NULL) AS av FROM users WHERE " + (byId ? "player_id = $1" : "username ILIKE $1") +
          " AND id <> $2 AND NOT EXISTS (SELECT 1 FROM friendships f WHERE f.status = 'blocked' AND f.requester = users.id AND f.addressee = $2) ORDER BY username LIMIT 10",
          [byId ? raw.toUpperCase() : raw.replace(/[\\%_]/g, "\\$&") + "%", me.id]);
        const ids = r.rows.map(x => x.id);
        const fr = ids.length ? (await pool.query("SELECT requester, addressee, status FROM friendships WHERE (requester = $1 AND addressee = ANY($2)) OR (addressee = $1 AND requester = ANY($2))", [me.id, ids])).rows : [];
        return json(res, 200, { results: r.rows.map(x => {
          const f = fr.find(y => y.requester === x.id || y.addressee === x.id);
          const rel = !f ? "none" : f.status === "accepted" ? "friend" : f.status === "pending" ? (f.requester === me.id ? "pending_out" : "pending_in") : "blocked";
          return { id: x.player_id, username: x.username, av: x.av, rel };
        }) });
      }
      const am = p.match(/^\/api\/me\/avatar\/(PN-\d{6})$/);
      if (am) {
        const r = await pool.query("SELECT avatar FROM users WHERE player_id = $1", [am[1]]);
        const m = r.rows[0] && r.rows[0].avatar && r.rows[0].avatar.match(/^data:(image\/\w+);base64,(.*)$/);
        if (!m) { res.writeHead(404); return res.end(); }
        res.writeHead(200, { "Content-Type": m[1], "Cache-Control": "private, max-age=300", "X-Content-Type-Options": "nosniff" });
        return res.end(Buffer.from(m[2], "base64"));
      }
      return json(res, 404, { error: "Not found" });
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

    if (p === "/api/me/presence") {
      const st = ["online", "away", "game"].includes(b.status) ? b.status : "online";
      const set = conns.get(me.id);
      if (set) for (const c of set) if (c.cid === b.cid) c.st = st;
      await refreshPresence(me);
      return json(res, 200, { ok: true });
    }
    if (p === "/api/me/notifications/read") {
      await pool.query("UPDATE notifications SET read = true WHERE user_id = $1 AND NOT read", [me.id]);
      return json(res, 200, { ok: true });
    }
    if (p === "/api/me/dm/send") {
      if (limited(req, "dm", 40, 60000)) return json(res, 429, { error: "Slow down a little" });
      const f = await friendUser(me.id, String(b.id || ""));
      if (!f) return json(res, 403, { error: "You can only chat with friends" });
      const text = String(b.text || "").replace(/\s+/g, " ").trim().slice(0, 500);
      if (!text) return json(res, 400, { error: "Empty message" });
      await pool.query("INSERT INTO dms(from_id, to_id, text) VALUES ($1, $2, $3)", [me.id, f.id, text]);
      emit(f.id, { t: "dm", from: me.player_id, name: me.username, text, ts: Date.now() });
      return json(res, 200, { ok: true });
    }
    if (p === "/api/me/settings") {
      if (typeof b.showOnline !== "boolean") return json(res, 400, { error: "Bad request" });
      const r = await pool.query("UPDATE users SET show_online = $1 WHERE id = $2 RETURNING *", [b.showOnline, me.id]);
      return json(res, 200, { user: pub(r.rows[0]) });
    }
    const fm = p.match(/^\/api\/me\/friends\/(request|accept|reject|cancel|remove|block|unblock)$/);
    if (fm) {
      if (limited(req, "soc", 60, 60000)) return json(res, 429, { error: "Slow down a little" });
      const t = await userByPid(String(b.id || ""));
      if (!t || t.id === me.id) return json(res, 404, { error: "Player not found" });
      const row = await pairRow(me.id, t.id), act = fm[1];
      const changed = () => { emit(me.id, { t: "friends_changed" }); emit(t.id, { t: "friends_changed" }); };
      const drop = () => pool.query("DELETE FROM friendships WHERE id = $1", [row.id]);
      const accept = async () => {
        await pool.query("UPDATE friendships SET status = 'accepted' WHERE id = $1", [row.id]);
        await notify(t.id, "friend_accepted", { from: me.player_id, username: me.username });
        changed();
      };
      if (act === "request") {
        if (row) {
          if (row.status === "pending" && row.requester === t.id) { await accept(); return json(res, 200, { ok: true, state: "friend" }); }
          if (row.status === "accepted") return json(res, 409, { error: "You are already friends" });
          if (row.status === "pending") return json(res, 409, { error: "Request already sent" });
          return json(res, 403, { error: "You can’t send a request to this player" });
        }
        await pool.query("INSERT INTO friendships(requester, addressee, status) VALUES ($1, $2, 'pending')", [me.id, t.id]);
        await notify(t.id, "friend_request", { from: me.player_id, username: me.username });
        changed();
        return json(res, 200, { ok: true, state: "pending" });
      }
      if (act === "accept") {
        if (!row || row.status !== "pending" || row.addressee !== me.id) return json(res, 404, { error: "No such request" });
        await accept(); return json(res, 200, { ok: true });
      }
      if (act === "reject") {
        if (!row || row.status !== "pending" || row.addressee !== me.id) return json(res, 404, { error: "No such request" });
        await drop(); changed(); return json(res, 200, { ok: true });
      }
      if (act === "cancel") {
        if (!row || row.status !== "pending" || row.requester !== me.id) return json(res, 404, { error: "No such request" });
        await drop(); changed(); return json(res, 200, { ok: true });
      }
      if (act === "remove") {
        if (!row || row.status !== "accepted") return json(res, 404, { error: "You are not friends" });
        await drop(); changed(); return json(res, 200, { ok: true });
      }
      if (act === "block") {
        if (row) await drop();
        await pool.query("INSERT INTO friendships(requester, addressee, status) VALUES ($1, $2, 'blocked')", [me.id, t.id]);
        changed(); return json(res, 200, { ok: true });
      }
      if (act === "unblock") {
        if (!row || row.status !== "blocked" || row.requester !== me.id) return json(res, 404, { error: "Player is not blocked" });
        await drop(); changed(); return json(res, 200, { ok: true });
      }
    }

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

module.exports = { init, route, userFromReq, isOnline, emitTo: emit, friendUser, recordMatch, _test: { setReady: v => { ready = v; }, hashPw, checkPw, openEvents, refreshPresence, statusOf, conns, setPool: x => { pool = x; } } };
