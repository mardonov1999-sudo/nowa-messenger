 'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data.json');
const PUBLIC_DIR = path.join(__dirname, 'public');
const SECRET = process.env.NOWA_SECRET || crypto.randomBytes(32).toString('hex');

// ---------- storage ----------
let db = { users: [], chats: [], messages: [], receipts: {} };
try { db = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch (_) {}
const save = () => fs.writeFileSync(DATA_FILE, JSON.stringify(db));

const uid = () => crypto.randomUUID();
const now = () => Date.now();

// ---------- tokens (HMAC) ----------
function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const mac = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return body + '.' + mac;
}
function verify(token) {
  if (!token) return null;
  const [body, mac] = token.split('.');
  if (!body || !mac) return null;
  const expect = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  if (!crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(expect))) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (payload.exp && payload.exp < now()) return null;
    return payload;
  } catch { return null; }
}
const makeToken = (userId) => sign({ uid: userId, exp: now() + 1000 * 60 * 60 * 24 * 30 });

function hashPassword(pw, salt = crypto.randomBytes(16).toString('hex')) {
  return salt + ':' + crypto.scryptSync(pw, salt, 32).toString('hex');
}
function checkPassword(pw, stored) {
  const [salt, hash] = String(stored).split(':');
  const test = crypto.scryptSync(pw, salt, 32).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(test, 'hex'));
}

// ---------- http helpers ----------
function send(res, code, data, headers = {}) {
  const body = typeof data === 'string' ? data : JSON.stringify(data);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', ...headers });
  res.end(body);
}
function readBody(req, limit = 25 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => { size += c.length; if (size > limit) { reject(new Error('too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {}); } catch (e) { reject(e); } });
    req.on('error', reject);
  });
}
function authUser(req) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  const p = verify(token);
  if (!p) return null;
  return db.users.find(u => u.id === p.uid) || null;
}
function publicUser(u) {
  if (!u) return null;
  return { id: u.id, name: u.name, phone: u.phone, email: u.email, about: u.about || '', avatar: u.avatar || '', lastSeen: u.lastSeen || 0 };
}
function chatView(chat, meId) {
  const members = chat.members.map(id => publicUser(db.users.find(u => u.id === id))).filter(Boolean);
  const last = [...db.messages].reverse().find(m => m.chatId === chat.id);
  const unread = db.messages.filter(m => m.chatId === chat.id && m.senderId !== meId).filter(m => {
    const r = db.receipts[m.id];
    return !(r && r.read && r.read.includes(meId));
  }).length;
  return { id: chat.id, name: chat.name, isGroup: !!chat.isGroup, members, avatar: chat.avatar || '', lastMessage: last || null, unread };
}

// ---------- SSE ----------
const clients = new Map(); // userId -> Set(res)
function broadcast(userIds, event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  userIds.forEach(id => {
    const set = clients.get(id);
    if (set) set.forEach(res => { try { res.write(payload); } catch (_) {} });
  });
}
function broadcastChat(chat, event, data) {
  broadcast(chat.members, event, data);
}

// ---------- routes ----------
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const method = req.method;
  const p = url.pathname;

  // CORS для локальной разработки
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  if (method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  try {
    // ---- static ----
    if (method === 'GET' && (p === '/' || p.startsWith('/public') || p === '/index.html')) {
      const file = path.join(PUBLIC_DIR, p === '/' ? 'index.html' : p.replace(/^\/public/, ''));
      if (!file.startsWith(PUBLIC_DIR) || !fs.existsSync(file)) return send(res, 404, { error: 'not found' });
      const ext = path.extname(file);
      const type = ext === '.html' ? 'text/html' : ext === '.js' ? 'text/javascript' : ext === '.css' ? 'text/css' : 'application/octet-stream';
      res.writeHead(200, { 'Content-Type': type + '; charset=utf-8' });
      return fs.createReadStream(file).pipe(res);
    }

    // ---- auth ----
    if (method === 'POST' && p === '/api/auth/register') {
      const b = await readBody(req);
      const identity = (b.email || b.phone || '').toString().trim();
      const password = (b.password || '').toString();
      const name = (b.name || '').toString().trim();
      if (!identity || !password || password.length < 10) return send(res, 400, { error: 'bad input' });
      if (db.users.some(u => u.email === b.email || u.phone === b.phone)) return send(res, 409, { error: 'already exists' });
      const user = { id: uid(), name: name || identity, email: b.email || '', phone: b.phone || '', password: hashPassword(password), about: '', avatar: '', createdAt: now(), lastSeen: now() };
      db.users.push(user); save();
      return send(res, 200, { token: makeToken(user.id), user: publicUser(user) });
    }

    if (method === 'POST' && p === '/api/auth/login') {
      const b = await readBody(req);
      const u = db.users.find(x => (b.email && x.email === b.email) || (b.phone && x.phone === b.phone));
      if (!u || !checkPassword(b.password || '', u.password)) return send(res, 401, { error: 'invalid credentials' });
      u.lastSeen = now(); save();
      return send(res, 200, { token: makeToken(u.id), user: publicUser(u) });
    }

    // ---- auth required ниже ----
    const me = authUser(req);
    if (p.startsWith('/api/') && p !== '/api/auth/logout') {
      if (!me) return send(res, 401, { error: 'unauthorized' });
    }

    if (method === 'POST' && p === '/api/auth/logout') return send(res, 200, { ok: true });

    if (method === 'GET' && p === '/api/me') return send(res, 200, { user: publicUser(me) });

    if (method === 'PATCH' && p === '/api/me') {
      const b = await readBody(req);
      if (typeof b.name === 'string' && b.name.trim().length >= 2) me.name = b.name.trim();
      if (typeof b.about === 'string') me.about = b.about.slice(0, 200);
      if (typeof b.avatar === 'string') me.avatar = b.avatar;
      save(); return send(res, 200, { user: publicUser(me) });
    }

    // ---- users search ----
    if (method === 'GET' && p === '/api/users') {
      const q = (url.searchParams.get('q') || '').toLowerCase();
      const list = db.users.filter(u => u.id !== me.id && (u.name.toLowerCase().includes(q) || (u.phone || '').includes(q))).slice(0, 20).map(publicUser);
      return send(res, 200, list);
    }

    // ---- chats ----
    if (method === 'GET' && p === '/api/chats') {
      const list = db.chats.filter(c => c.members.includes(me.id)).map(c => chatView(c, me.id));
      return send(res, 200, list);
    }

    if (method === 'POST' && p === '/api/chats') {
      const b = await readBody(req);
      const isGroup = !!b.isGroup;
      const members = Array.from(new Set([me.id, ...(Array.isArray(b.members) ? b.members : [])]));
      if (!isGroup && members.length !== 2) return send(res, 400, { error: 'direct chat needs one peer' });
      // для личного чата вернуть существующий
      if (!isGroup) {
        const peer = members.find(id => id !== me.id);
        const existing = db.chats.find(c => !c.isGroup && c.members.length === 2 && c.members.includes(me.id) && c.members.includes(peer));
        if (existing) return send(res, 200, chatView(existing, me.id));
      }
      const chat = { id: uid(), name: b.name || (isGroup ? 'Группа' : ''), isGroup, members, avatar: b.avatar || '', createdBy: me.id, createdAt: now(), archivedBy: [], mutedBy: [] };
      db.chats.push(chat); save();
      broadcastChat(chat, 'chat:new', chatView(chat, me.id));
      return send(res, 200, chatView(chat, me.id));
    }

    const chatMatch = p.match(/^\/api\/chats\/([^/]+)$/);
    if (chatMatch && method === 'GET') {
      const c = db.chats.find(x => x.id === chatMatch[1] && x.members.includes(me.id));
      if (!c) return send(res, 404, { error: 'not found' });
      return send(res, 200, chatView(c, me.id));
    }
    if (chatMatch && method === 'PATCH') {
      const c = db.chats.find(x => x.id === chatMatch[1] && x.members.includes(me.id));
      if (!c) return send(res, 404, { error: 'not found' });
      const b = await readBody(req);
      if (typeof b.name === 'string' && b.name.trim()) c.name = b.name.trim();
      if (typeof b.avatar === 'string') c.avatar = b.avatar;
      if (typeof b.archived === 'boolean') c.archivedBy = b.archived ? Array.from(new Set([...c.archivedBy, me.id])) : c.archivedBy.filter(id => id !== me.id);
      if (typeof b.muted === 'boolean') c.mutedBy = b.muted ? Array.from(new Set([...c.mutedBy, me.id])) : c.mutedBy.filter(id => id !== me.id);
      if (Array.isArray(b.addMembers)) c.members = Array.from(new Set([...c.members, ...b.addMembers]));
      if (Array.isArray(b.removeMembers)) c.members = c.members.filter(id => !b.removeMembers.includes(id));
      save(); broadcastChat(c, 'chat:update', chatView(c, me.id));
      return send(res, 200, chatView(c, me.id));
    }
    if (chatMatch && method === 'DELETE') {
      const idx = db.chats.findIndex(x => x.id === chatMatch[1] && x.members.includes(me.id));
      if (idx < 0) return send(res, 404, { error: 'not found' });
      const [c] = db.chats.splice(idx, 1);
      db.messages = db.messages.filter(m => m.chatId !== c.id);
      save(); broadcastChat(c, 'chat:delete', { id: c.id });
      return send(res, 200, { ok: true });
    }

    // ---- messages ----
    if (method === 'GET' && p.match(/^\/api\/chats\/[^/]+\/messages$/)) {
      const id = p.split('/')[3];
      const c = db.chats.find(x => x.id === id && x.members.includes(me.id));
      if (!c) return send(res, 404, { error: 'not found' });
      const before = Number(url.searchParams.get('before') || 0);
      const limit = Math.min(100, Number(url.searchParams.get('limit') || 50));
      let list = db.messages.filter(m => m.chatId === id);
      if (before) list = list.filter(m => m.ts < before);
      list = list.sort((a, b) => a.ts - b.ts).slice(-limit);
      return send(res, 200, { messages: list, hasMore: db.messages.filter(m => m.chatId === id).length > list.length });
    }

    if (method === 'POST' && p.match(/^\/api\/chats\/[^/]+\/messages$/)) {
      const id = p.split('/')[3];
      const c = db.chats.find(x => x.id === id && x.members.includes(me.id));
      if (!c) return send(res, 404, { error: 'not found' });
      const b = await readBody(req);
      const msg = {
        id: uid(), chatId: id, senderId: me.id, text: String(b.text || '').slice(0, 4000),
        type: b.type || 'text', attachment: b.attachment || null,
        replyTo: b.replyTo || null, ts: now(), editedAt: null, deletedAt: null, reactions: {}
      };
      db.messages.push(msg); save();
      broadcastChat(c, 'message:new', msg);
      return send(res, 200, { message: msg });
    }

    const msgMatch = p.match(/^\/api\/messages\/([^/]+)$/);
    if (msgMatch) {
      const m = db.messages.find(x => x.id === msgMatch[1]);
      if (!m) return send(res, 404, { error: 'not found' });
      const c = db.chats.find(x => x.id === m.chatId);
      if (!c || !c.members.includes(me.id)) return send(res, 403, { error: 'forbidden' });
      if (method === 'PATCH') {
        if (m.senderId !== me.id) return send(res, 403, { error: 'forbidden' });
        const b = await readBody(req);
        if (typeof b.text === 'string') { m.text = b.text.slice(0, 4000); m.editedAt = now(); }
        save(); broadcastChat(c, 'message:update', m);
        return send(res, 200, { message: m });
      }
      if (method === 'DELETE') {
        if (m.senderId !== me.id) return send(res, 403, { error: 'forbidden' });
        m.deletedAt = now(); m.text = ''; save();
        broadcastChat(c, 'message:update', m);
        return send(res, 200, { ok: true });
      }
    }

    const reactMatch = p.match(/^\/api\/messages\/([^/]+)\/reactions$/);
    if (reactMatch && method === 'POST') {
      const m = db.messages.find(x => x.id === reactMatch[1]);
      if (!m) return send(res, 404, { error: 'not found' });
      const c = db.chats.find(x => x.id === m.chatId);
      if (!c || !c.members.includes(me.id)) return send(res, 403, { error: 'forbidden' });
      const b = await readBody(req);
      const emoji = String(b.emoji || '').slice(0, 8);
      m.reactions = m.reactions || {};
      const set = new Set(m.reactions[emoji] || []);
      if (set.has(me.id)) set.delete(me.id); else set.add(me.id);
      m.reactions[emoji] = [...set];
      if (!m.reactions[emoji].length) delete m.reactions[emoji];
      save(); broadcastChat(c, 'message:update', m);
      return send(res, 200, { message: m });
    }

    // ---- receipts ----
    if (method === 'POST' && p === '/api/receipts') {
      const b = await readBody(req);
      const chatId = b.chatId;
      const kind = b.kind === 'read' ? 'read' : 'delivered';
      const c = db.chats.find(x => x.id === chatId && x.members.includes(me.id));
      if (!c) return send(res, 404, { error: 'not found' });
      const ids = db.messages.filter(m => m.chatId === chatId).map(m => m.id);
      ids.forEach(id => {
        const r = db.receipts[id] = db.receipts[id] || { delivered: [], read: [] };
        if (kind === 'read') { if (!r.read.includes(me.id)) r.read.push(me.id); }
        if (!r.delivered.includes(me.id)) r.delivered.push(me.id);
      });
      save();
      broadcastChat(c, 'receipts', { chatId, kind, by: me.id, ts: now() });
      return send(res, 200, { ok: true });
    }

    // ---- typing ----
    if (method === 'POST' && p === '/api/typing') {
      const b = await readBody(req);
      const c = db.chats.find(x => x.id === b.chatId && x.members.includes(me.id));
      if (!c) return send(res, 404, { error: 'not found' });
      broadcast(c.members.filter(id => id !== me.id), 'typing', { chatId: c.id, userId: me.id, name: me.name });
      return send(res, 200, { ok: true });
    }

    // ---- contacts (все пользователи, кроме меня) ----
    if (method === 'GET' && p === '/api/contacts') {
      return send(res, 200, db.users.filter(u => u.id !== me.id).map(publicUser));
    }

    // ---- SSE stream ----
    if (method === 'GET' && p === '/api/stream') {
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
      res.write(': connected\n\n');
      const set = clients.get(me.id) || new Set();
      set.add(res); clients.set(me.id, set);
      const ping = setInterval(() => { try { res.write(': ping\n\n'); } catch (_) {} }, 20000);
      req.on('close', () => { clearInterval(ping); set.delete(res); if (!set.size) clients.delete(me.id); });
      return;
    }

    send(res, 404, { error: 'not found' });
  } catch (e) {
    send(res, 500, { error: e.message || 'server error' });
  }
});

server.listen(PORT, () => console.log('NOWA server on http://localhost:' + PORT));
