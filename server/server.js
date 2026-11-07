require("dotenv").config();
const express = require("express");
const http = require("http");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const { Server } = require("socket.io");
const webpush = require("web-push");
const path = require("path");
const fs = require("fs");

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || "";
if (JWT_SECRET.length < 32) {
  console.error("Set JWT_SECRET in .env (at least 32 characters).");
  process.exit(1);
}

const dbFile = process.env.DATABASE_FILE || "./data/nowa.sqlite";
fs.mkdirSync(path.dirname(path.resolve(dbFile)), { recursive: true });
const db = new Database(dbFile);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE COLLATE NOCASE,
  phone TEXT UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS contacts (
  owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  contact_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(owner_id, contact_id),
  CHECK(owner_id <> contact_id)
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender_id INTEGER NOT NULL REFERENCES users(id),
  recipient_id INTEGER NOT NULL REFERENCES users(id),
  body TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_messages_pair ON messages(sender_id, recipient_id, id);
CREATE TABLE IF NOT EXISTS push_subscriptions(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,endpoint TEXT NOT NULL UNIQUE,subscription_json TEXT NOT NULL);
`);

if(process.env.VAPID_PUBLIC_KEY&&process.env.VAPID_PRIVATE_KEY) webpush.setVapidDetails(process.env.VAPID_SUBJECT||"mailto:admin@example.com",process.env.VAPID_PUBLIC_KEY,process.env.VAPID_PRIVATE_KEY);
const app = express();
app.set('trust proxy', 1);
const server = http.createServer(app);
const allowedOrigin = process.env.CLIENT_ORIGIN || "http://localhost:5173";
app.use(helmet());
app.use(cors({ origin: allowedOrigin, credentials: true }));
app.use(express.json({ limit: "32kb" }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: true, legacyHeaders: false }));
app.use(express.static(path.join(__dirname, "../client")));

const io = new Server(server, { cors: { origin: allowedOrigin, methods: ["GET", "POST"] } });
const online = new Map();

function tokenFor(user) {
  return jwt.sign({ sub: String(user.id) }, JWT_SECRET, { expiresIn: "7d", issuer: "nowa" });
}
function auth(req, res, next) {
  const value = req.headers.authorization || "";
  const token = value.startsWith("Bearer ") ? value.slice(7) : "";
  try {
    const payload = jwt.verify(token, JWT_SECRET, { issuer: "nowa" });
    req.userId = Number(payload.sub);
    if (!Number.isSafeInteger(req.userId)) throw new Error("bad subject");
    next();
  } catch {
    res.status(401).json({ error: "Требуется действительный вход в NOWA." });
  }
}
function publicUser(row) {
  return { id: row.id, name: row.name, email: row.email, phone: row.phone };
}
function isValidIdentity(email, phone) {
  if (email) return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  if (phone) return /^\+[1-9]\d{7,14}$/.test(phone);
  return false;
}
function roomFor(a, b) { return [Number(a), Number(b)].sort((x,y)=>x-y).join(":"); }

app.get("/health", (_req, res) => res.json({ ok: true, service: "NOWA API" }));

app.post("/api/auth/register", rateLimit({ windowMs: 60*60*1000, limit: 10 }), async (req, res) => {
  try {
    const name = String(req.body.name || "").trim().slice(0, 40);
    const email = req.body.email ? String(req.body.email).trim().toLowerCase() : null;
    const phone = req.body.phone ? String(req.body.phone).trim() : null;
    const password = String(req.body.password || "");
    if (name.length < 2 || !isValidIdentity(email, phone) || (email && phone) || password.length < 10 || password.length > 128) {
      return res.status(400).json({ error: "Укажите имя, один корректный email или телефон и пароль от 10 символов." });
    }
    const hash = await bcrypt.hash(password, 12);
    const info = db.prepare("INSERT INTO users(name,email,phone,password_hash) VALUES(?,?,?,?)").run(name,email,phone,hash);
    const user = db.prepare("SELECT id,name,email,phone FROM users WHERE id=?").get(info.lastInsertRowid);
    res.status(201).json({ token: tokenFor(user), user: publicUser(user) });
  } catch (e) {
    if (String(e.code || "").includes("SQLITE_CONSTRAINT")) return res.status(409).json({ error: "Этот email или номер уже зарегистрирован." });
    res.status(500).json({ error: "Не удалось создать аккаунт." });
  }
});

app.post("/api/auth/login", rateLimit({ windowMs: 15*60*1000, limit: 10 }), async (req, res) => {
  const email = req.body.email ? String(req.body.email).trim().toLowerCase() : null;
  const phone = req.body.phone ? String(req.body.phone).trim() : null;
  const password = String(req.body.password || "");
  if ((email && phone) || (!email && !phone)) return res.status(400).json({ error: "Введите email или телефон." });
  const user = db.prepare("SELECT * FROM users WHERE " + (email ? "email=?" : "phone=?")).get(email || phone);
  if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: "Неверные данные для входа." });
  res.json({ token: tokenFor(user), user: publicUser(user) });
});

app.get("/api/me", auth, (req,res) => {
  const user = db.prepare("SELECT id,name,email,phone FROM users WHERE id=?").get(req.userId);
  if (!user) return res.status(404).json({ error: "Аккаунт не найден." });
  res.json({ user: publicUser(user) });
});

app.get("/api/users/search", auth, (req,res) => {
  const q = String(req.query.q || "").trim().slice(0,60);
  if (q.length < 2) return res.json({ users: [] });
  const like = "%" + q.replace(/[\\%_]/g, "\\$&") + "%";
  const rows = db.prepare(`SELECT id,name,email,phone FROM users
    WHERE id<>? AND (name LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\' OR phone LIKE ? ESCAPE '\\')
    ORDER BY name LIMIT 30`).all(req.userId,like,like,like);
  res.json({ users: rows.map(publicUser) });
});

app.post("/api/contacts/:id", auth, (req,res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id === req.userId) return res.status(400).json({ error: "Некорректный контакт." });
  if (!db.prepare("SELECT id FROM users WHERE id=?").get(id)) return res.status(404).json({ error: "Пользователь не найден." });
  db.prepare("INSERT OR IGNORE INTO contacts(owner_id,contact_id) VALUES(?,?)").run(req.userId,id);
  res.status(201).json({ ok: true });
});
app.get("/api/contacts", auth, (req,res) => {
  const rows = db.prepare(`SELECT u.id,u.name,u.email,u.phone FROM contacts c
    JOIN users u ON u.id=c.contact_id WHERE c.owner_id=? ORDER BY u.name`).all(req.userId);
  res.json({ contacts: rows.map(publicUser) });
});
app.get("/api/push/public-key",auth,(_req,res)=>{if(!process.env.VAPID_PUBLIC_KEY)return res.status(503).json({error:"Push не настроен."});res.json({publicKey:process.env.VAPID_PUBLIC_KEY})});
app.post("/api/push/subscribe",auth,(req,res)=>{const sub=req.body.subscription;if(!sub||!sub.endpoint||!sub.keys)return res.status(400).json({error:"Некорректная подписка"});db.prepare("INSERT INTO push_subscriptions(user_id,endpoint,subscription_json) VALUES(?,?,?) ON CONFLICT(endpoint) DO UPDATE SET user_id=excluded.user_id,subscription_json=excluded.subscription_json").run(req.userId,sub.endpoint,JSON.stringify(sub));res.status(201).json({ok:true})});


app.get("/api/messages/:userId", auth, (req,res) => {
  const other = Number(req.params.userId);
  if (!Number.isSafeInteger(other) || !db.prepare("SELECT id FROM users WHERE id=?").get(other)) return res.status(404).json({ error: "Пользователь не найден." });
  const rows = db.prepare(`SELECT id,sender_id AS senderId,recipient_id AS recipientId,body,created_at AS createdAt
    FROM messages WHERE (sender_id=? AND recipient_id=?) OR (sender_id=? AND recipient_id=?)
    ORDER BY id DESC LIMIT 100`).all(req.userId,other,other,req.userId).reverse();
  res.json({ messages: rows });
});
app.post("/api/messages/:userId", auth, (req,res) => {
  const recipient = Number(req.params.userId);
  const body = String(req.body.body || "").trim();
  if (!Number.isSafeInteger(recipient) || recipient === req.userId || !db.prepare("SELECT id FROM users WHERE id=?").get(recipient))
    return res.status(400).json({ error: "Некорректный получатель." });
  if (!body || body.length > 4000) return res.status(400).json({ error: "Сообщение должно быть от 1 до 4000 символов." });
  const info = db.prepare("INSERT INTO messages(sender_id,recipient_id,body) VALUES(?,?,?)").run(req.userId,recipient,body);
  const message = db.prepare("SELECT id,sender_id AS senderId,recipient_id AS recipientId,body,created_at AS createdAt FROM messages WHERE id=?").get(info.lastInsertRowid);
  io.to(String(recipient)).emit("message:new", message);
  if(process.env.VAPID_PUBLIC_KEY&&process.env.VAPID_PRIVATE_KEY){
    for(const sub of db.prepare("SELECT id,subscription_json FROM push_subscriptions WHERE user_id=?").all(recipient)){
      webpush.sendNotification(JSON.parse(sub.subscription_json),JSON.stringify({title:"NOWA",body:"Новое сообщение",url:"./index.html"})).catch(err=>{if(err.statusCode===404||err.statusCode===410)db.prepare("DELETE FROM push_subscriptions WHERE id=?").run(sub.id);});
    }
  }
  res.status(201).json({ message });
});

io.use((socket,next) => {
  try {
    const token = socket.handshake.auth?.token;
    const payload = jwt.verify(token, JWT_SECRET, { issuer: "nowa" });
    socket.userId = Number(payload.sub);
    next();
  } catch { next(new Error("unauthorized")); }
});
io.on("connection", socket => {
  const uid = String(socket.userId);
  socket.join(uid);
  online.set(uid,(online.get(uid)||0)+1);
  const relayCall = (event, targetEvent, payload) => {
    const to=Number(payload?.to);
    if(!Number.isSafeInteger(to)||to===Number(uid)||!db.prepare("SELECT id FROM users WHERE id=?").get(to)) return;
    if(!online.has(String(to))) { socket.emit("call:unavailable"); return; }
    const user=db.prepare("SELECT name FROM users WHERE id=?").get(Number(uid));
    io.to(String(to)).emit(targetEvent,{...payload,from:Number(uid),name:user?.name||"Пользователь NOWA"});
  };
  socket.on("call:invite",p=>relayCall("call:invite","call:incoming",p));
  socket.on("call:accept",p=>relayCall("call:accept","call:accepted",p));
  socket.on("call:reject",p=>relayCall("call:reject","call:rejected",p));
  socket.on("call:signal",p=>relayCall("call:signal","call:signal",p));
  socket.on("call:end",p=>relayCall("call:end","call:ended",p));
  socket.on("disconnect",()=>{const n=(online.get(uid)||1)-1;if(n<=0)online.delete(uid);else online.set(uid,n);});
});
app.get("/api/users/:id/online", auth, (req,res) => res.json({ online: (online.get(String(Number(req.params.id)))||0)>0 }));

app.use((err,_req,res,_next) => {
  console.error(err);
  res.status(500).json({ error: "Внутренняя ошибка сервера." });
});
server.listen(PORT, () => console.log(`NOWA API listening on http://localhost:${PORT}`));
