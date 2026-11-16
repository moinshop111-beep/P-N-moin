// P&N online duel server. No dependencies. Run: node server.js
const http = require("http"), fs = require("fs"), path = require("path"), crypto = require("crypto");
const PORT = process.env.PORT || 3000, rooms = new Map();

const valid = s => typeof s === "string" && /^[1-9]\d\d$/.test(s) && new Set(s).size === 3;
// P = digits in the exact position, N = all guessed digits that exist in the secret
const score = (s, g) => { let p = 0, n = 0; for (let i = 0; i < 3; i++) { if (g[i] === s[i]) p++; if (s.includes(g[i])) n++; } return { p, n }; };
const tok = () => crypto.randomBytes(8).toString("hex");

// Each player only ever receives their own view; secrets stay hidden until the game is over.
const view = (r, me) => ({
  code: r.code, me, phase: r.phase, turn: r.turn, winner: r.winner,
  joined: r.toks.map(Boolean), ready: r.secret.map(Boolean), online: r.clients.map(c => c.size > 0),
  mine: r.guesses[me], theirs: r.guesses[1 - me], secrets: r.phase === "over" ? r.secret : null
});
const push = r => { r.t = Date.now(); [0, 1].forEach(i => r.clients[i].forEach(res => res.write("data: " + JSON.stringify(view(r, i)) + "\n\n"))); };
const reset = r => { r.secret = [null, null]; r.guesses = [[], []]; r.cracked = [false, false]; r.turn = 0; r.winner = null; r.phase = "setup"; };

const actions = {
  create() {
    let code; do code = String(1000 + crypto.randomInt(9000)); while (rooms.has(code));
    const r = { code, toks: [tok(), null], clients: [new Set(), new Set()], t: Date.now() };
    reset(r); r.phase = "wait"; rooms.set(code, r);
    return { room: code, pid: 0, tok: r.toks[0] };
  },
  join(b) {
    const r = rooms.get(b.room);
    if (!r) return { error: "Room not found" };
    if (r.toks[1]) return { error: "Room is full" };
    r.toks[1] = tok(); r.phase = "setup"; push(r);
    return { room: r.code, pid: 1, tok: r.toks[1] };
  },
  secret(b, r, me) {
    if (r.phase !== "setup" || r.secret[me]) return { error: "Not allowed now" };
    if (!valid(b.secret)) return { error: "Invalid code" };
    r.secret[me] = b.secret;
    if (r.secret[0] && r.secret[1]) { r.phase = "play"; r.turn = 0; }
    push(r); return { ok: 1 };
  },
  guess(b, r, me) {
    if (r.phase !== "play") return { error: "Game is not running" };
    if (r.turn !== me) return { error: "Wait for your turn" };
    if (!valid(b.guess)) return { error: "Invalid guess" };
    const res = score(r.secret[1 - me], b.guess);
    r.guesses[me].push({ guess: b.guess, p: res.p, n: res.n });
    if (res.p === 3) r.cracked[me] = true;
    if (me === 0) r.turn = 1; // player 2 always gets a reply, so both have equal turns
    else {
      if (r.cracked[0] && r.cracked[1]) r.winner = "draw";
      else if (r.cracked[1]) r.winner = 1;
      else if (r.cracked[0]) r.winner = 0;
      if (r.winner !== null) r.phase = "over"; else r.turn = 0;
    }
    push(r); return { ok: 1, res };
  },
  rematch(b, r) { if (r.phase === "over") { reset(r); push(r); } return { ok: 1 }; }
};

const server = http.createServer((req, res) => {
  const u = new URL(req.url, "http://x");
  if (req.method === "GET" && u.pathname === "/api/events") {
    const t = u.searchParams.get("tok"), r = rooms.get(u.searchParams.get("room")), me = r && t ? r.toks.indexOf(t) : -1;
    if (me < 0) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive", "X-Accel-Buffering": "no" });
    res.write("retry: 2000\n\n");
    r.clients[me].add(res); push(r);
    req.on("close", () => { r.clients[me].delete(res); push(r); });
    return;
  }
  if (req.method === "POST" && u.pathname.startsWith("/api/")) {
    let body = "";
    req.on("data", c => { body += c; if (body.length > 5000) req.destroy(); });
    req.on("end", () => {
      let b = {}; try { b = JSON.parse(body || "{}"); } catch (e) {}
      const act = u.pathname.slice(5); let out;
      if (!Object.prototype.hasOwnProperty.call(actions, act)) out = { error: "Unknown action" };
      else if (act === "create" || act === "join") out = actions[act](b);
      else {
        const r = rooms.get(b.room), me = r && b.tok ? r.toks.indexOf(b.tok) : -1;
        out = me < 0 ? { error: "Room not found" } : actions[act](b, r, me);
      }
      res.writeHead(200, { "Content-Type": "application/json" }); res.end(JSON.stringify(out));
    });
    return;
  }
  if (req.method === "GET" && (u.pathname === "/" || u.pathname === "/index.html"))
    return fs.readFile(path.join(__dirname, "index.html"), (e, d) => {
      if (e) { res.writeHead(500); return res.end("index.html is missing next to server.js"); }
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" }); res.end(d);
    });
  res.writeHead(404); res.end("Not found");
});

// Keep connections alive and drop rooms idle for 3 hours
setInterval(() => {
  const now = Date.now();
  rooms.forEach((r, k) => { if (now - r.t > 3 * 3600e3) rooms.delete(k); r.clients.forEach(s => s.forEach(c => c.write(": ping\n\n"))); });
}, 25000);

server.listen(PORT, () => console.log("P&N server running on http://localhost:" + PORT));
