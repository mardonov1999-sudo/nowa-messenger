 'use strict';

/**
 * NOWA — референсный сервер мессенджера.
 * Работает локально и на Render.
 *
 * Переменные окружения (Render → Environment):
 *   PORT          — выдаёт Render автоматически, трогать не нужно
 *   NOWA_SECRET   — длинная случайная строка для подписи токенов (ОБЯЗАТЕЛЬНО на Render)
 *   DATA_DIR      — папка для data.json (например, /var/data при подключённом диске)
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, '..', 'клиент');
const DATA_DIR = process.env.DATA_DIR || __dirname;
const DATA_FILE = path.join(DATA_DIR, 'data.json');
const SECRET = process.env.NOWA_SECRET || crypto.randomBytes(32).toString('hex');

// ---------- storage ----------
function ensureDataDir() {
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  } catch (e) {
    console.error('Не удалось создать DATA_DIR:', DATA_DIR, e.message);
  }
}
ensureDataDir();

let db = { users: [], chats: [], messages: [], receipts: {} };
try {
  if (fs.existsSync(DATA_FILE)) {
    const raw = fs.readFileSync(DATA_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object') db = { users: [], chats: [], messages: [], receipts: {}, ...parsed };
    console.log('Данные загружены из', DATA_FILE, '| users:', db.users.length, 'chats:', db.chats.length, 'messages:', db.messages.length);
  } else {
    console.log('Файл данных ещё не создан, стартуем с пустой базы:', DATA_FILE);
  }
} catch (e) {
  console.error('Ошибка чтения data.json, стартуем с пустой базы:', e.message);
}

let saveScheduled = false;
function save() {
  if (saveScheduled) return;
  saveScheduled = true;
  setImmediate(() => {
    saveScheduled = false;
    try {
      const tmp = DATA_FILE + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify(db));
      fs.renameSync(tmp, DATA_FILE);
    } catch (e) {
      console.error('Ошибка записи data.json:', e.message);
    }
  });
}

const uid = () => crypto.randomUUID();
const now = () => Date.now();

// ---------- tokens (HMAC) ----------
function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const mac = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return body + '.' + mac;
}
function verify(token) {
  if (!token || typeof token !== 'string') return null;
  const i = token.lastIndexOf('.');
  if (i < 0) return null;
  const body = token.slice(0, i);
  const mac = token.slice(i + 1);
  const expect = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  const a = Buffer.from(mac);
  const b = Buffer.from(expect);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (payload.exp && payload.exp < now()) return null;
    return payload;
  } catch {
    return null;
  }
}
const makeToken = (userId) => sign({ uid: userId, exp: now() + 1000 * 60 * 60 * 24 * 30 });

// ---------- passwords ----------
function hashPassword(pw, salt = crypto.randomBytes(16).toString('hex')) {
  return salt + ':' + crypto.scryptSync(pw, salt, 32).toString('hex');
}
function checkPassword(pw, stored) {
  try {
    const [salt, hash] = String(stored).split(':');
    if (!salt || !hash) return false;
    const test = crypto.scryptSync(pw, salt, 32).toString('hex');
    const a = Buffer.from(hash, 'hex');
    const b = Buffer.from(test, 'hex');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

// ---------- http helpers ----------
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
  'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS'
};

function send(res, code, data) {
  const body = typeof data === 'string' ? data : JSON.stringify(data);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS });
  res.end(body);
}
function readBody(req, limit = 30 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > limit) { reject(new Error('too large')); req.destroy(); }
      else chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

function authUserFromHeader(req) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  const p = verify(token);
  if (!p) return null;
  return db.users.find(u => u.id === p.uid) || null;
}
function authUserFromQuery(url) {
  const t = url.searchParams.get('token') || '';
  const p = verify(t);
  if (!p) return null;
  return db.users.find(u => u.id === p.uid) || null;
}

function publicUser(u) {
  if (!u) return null;
  return {
    id: u.id, name: u.name, phone: u.phone || '', email: u.email || '',
    about: u.about || '', avatar: u.avatar || '', lastSeen: u.lastSeen || 0
  };
}

function chatView(chat, meId) {
  const members = chat.members
    .map(id => publicUser(db.users.find(u => u.id === id)))
    .filter(Boolean);
  const last = [...db.messages].reverse().find(m => m.chatId === chat.id && !m.deletedAt);
  const unread = db.messages.filter(m => m.chatId === chat.id && m.senderId !== meId && !m.deletedAt).filter(m => {
    const r = db.receipts[m.id];
    return !(r && r.read && r.read.includes(meId));
  }).length;
  return {
    id: chat.id, name: chat.name, isGroup: !!chat.isGroup, members,
    avatar: chat.avatar || '', lastMessage: last || null, unread,
    archived: (chat.archivedBy || []).includes(meId),
    muted: (chat.mutedBy || []).includes(meId)
  };
}

// ---------- SSE ----------
const clients = new Map(); // userId -> Set(res)
function broadcast(userIds, event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  userIds.forEach(id => {
    const set = clients.get(id);
    if (!set) return;
    set.forEach(res => { try { res.write(payload); } catch (_) {} });
  });
}
function broadcastChat(chat, event, data) {
  broadcast(chat.members, event, data);
}

// ---------- static ----------
function serveStatic(req, res, pathname) {
  let rel = pathname === '/' ? '/index.html' : pathname;
  rel = rel.replace(/^\/+/, '');
  const file = path.resolve(PUBLIC_DIR, rel);
  if (!file.startsWith(path.resolve(PUBLIC_DIR))) return send(res, 403, { error: 'forbidden' });
  if (!fs.existsSync(file) || !fs.statSync(file).isFile()) {
    // SPA fallback
    const fallback = path.join(PUBLIC_DIR, 'index.html');
    if (fs.existsSync(fallback)) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return fs.createReadStream(fallback).pipe(res);
    }
    return send(res, 404, { error: 'not found' });
  }
  const ext = path.extname(file).toLowerCase();
  const type = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.webp': 'image/webp',
    '.ico': 'image/x-icon',
    '.woff2': 'font/woff2'
  }[ext] || 'application/octet-stream';
  res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'no-cache' });
  fs.createReadStream(file).pipe(res);
}

// ---------- server ----------
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const method = req.method;
  const p = url.pathname;

  if (method === 'OPTIONS') {
    res.writeHead(204, CORS_HEADERS);
    return res.end();
  }

  // healthcheck для Render
  if (method === 'GET' && (p === '/healthz' || p === '/health')) {
    return send(res, 200, { ok: true, ts: now() });
  }

  try {
    // ---- API ----
    if (p.startsWith('/api/')) {
      // public routes
      if (method === 'POST' && p === '/api/auth/register') {
        const b = await readBody(req);
        const email = (b.email || '').toString().trim().toLowerCase();
        const phone = (b.phone || '').toString().trim();
        const password = (b.password || '').toString();
        const name = (b.name || '').toString().trim();
        if ((!email && !phone) || password.length < 10) return send(res, 400, { error: 'bad input' });
        if (db.users.some(u => (email && u.email === email) || (phone && u.phone === phone))) {
          return send(res, 409, { error: 'already exists' });
        }
        const user = {
          id: uid(), name: name || email || phone, email, phone,
          password: hashPassword(password), about: '', avatar: '',
          createdAt: now(), lastSeen: now()
        };
        db.users.push(user);
        save();
        return send(res, 200, { token: makeToken(user.id), user: publicUser(user) });
      }

      if (method === 'POST' && p === '/api/auth/login') {
        const b = await readBody(req);
        const email = (b.email || '').toString().trim().toLowerCase();
        const phone = (b.phone || '').toString().trim();
        const u = db.users.find(x => (email && x.email === email) || (phone && x.phone === phone));
        if (!u || !checkPassword((b.password || '').toString(), u.password)) {
          return send(res, 401, { error: 'invalid credentials' });
        }
        u.lastSeen = now();
        save();
        return send(res, 200, { token: makeToken(u.id), user: publicUser(u) });
      }

      if (method === 'POST' && p === '/api/auth/logout') {
        return send(res, 200, { ok: true });
      }

      // SSE: токен можно передать в query — EventSource не умеет заголовки
      if (method === 'GET' && p === '/api/stream') {
        const me = authUserFromHeader(req) || authUserFromQuery(url);
        if (!me) return send(res, 401, { error: 'unauthorized' });
        res.writeHead(200, {
          'Content-Type': 'text/event-stream; charset=utf-8',
          'Cache-Control': 'no-cache, no-transform',
          Connection: 'keep-alive',
          'X-Accel-Buffering': 'no',
          ...CORS_HEADERS
        });
        res.write(`: connected ${me.id}\n\n`);
        const set = clients.get(me.id) || new Set();
        set.add(res);
        clients.set(me.id, set);
        const ping = setInterval(() => { try { res.write(': ping\n\n'); } catch (_) {} }, 20000);
        req.on('close', () => {
          clearInterval(ping);
          set.delete(res);
          if (!set.size) clients.delete(me.id);
        });
        return;
      }

      // всё остальное требует авторизации
      const me = authUserFromHeader(req);
      if (!me) return send(res, 401, { error: 'unauthorized' });

      if (method === 'GET' && p === '/api/me') return send(res, 200, { user: publicUser(me) });

      if (method === 'PATCH' && p === '/api/me') {
        const b = await readBody(req);
        if (typeof b.name === 'string' && b.name.trim().length >= 2) me.name = b.name.trim();
        if (typeof b.about === 'string') me.about = b.about.slice(0, 200);
        if (typeof b.avatar === 'string') me.avatar = b.avatar;
        save();
        return send(res, 200, { user: publicUser(me) });
      }

      if (method === 'GET' && p === '/api/users') {
        const q = (url.searchParams.get('q') || '').toLowerCase().trim();
        const list = db.users
          .filter(u => u.id !== me.id && (!q || u.name.toLowerCase().includes(q) || (u.phone || '').includes(q)))
          .slice(0, 30)
          .map(publicUser);
        return send(res, 200, list);
      }

      if (method === 'GET' && p === '/api/contacts') {
        return send(res, 200, db.users.filter(u => u.id !== me.id).map(publicUser));
      }

      if (method === 'GET' && p === '/api/chats') {
        const list = db.chats.filter(c => c.members.includes(me.id)).map(c => chatView(c, me.id));
        return send(res, 200, list);
      }

      if (method === 'POST' && p === '/api/chats') {
        const b = await readBody(req);
        const isGroup = !!b.isGroup;
        const members = Array.from(new Set([me.id, ...(Array.isArray(b.members) ? b.members : [])]));
        if (!isGroup && members.length !== 2) return send(res, 400, { error: 'direct chat needs one peer' });
        if (!isGroup) {
          const peer = members.find(id => id !== me.id);
          const existing = db.chats.find(c => !c.isGroup && c.members.length === 2 && c.members.includes(me.id) && c.members.includes(peer));
          if (existing) return send(res, 200, chatView(existing, me.id));
        }
        let name = (b.name || '').toString().trim();
        if (!name) {
          if (isGroup) name = 'Группа';
          else {
            const peer = db.users.find(u => u.id === members.find(id => id !== me.id));
            name = peer ? peer.name : 'Чат';
          }
        }
        const chat = {
          id: uid(), name, isGroup, members, avatar: b.avatar || '',
          createdBy: me.id, createdAt: now(), archivedBy: [], mutedBy: []
        };
        db.chats.push(chat);
        save();
        broadcastChat(chat, 'chat:new', chatView(chat, me.id));
        return send(res, 200, chatView(chat, me.id));
      }

      const chatMatch = p.match(/^\/api\/chats\/([^/]+)$/);
      if (chatMatch) {
        const chatId = chatMatch[1];
        const c = db.chats.find(x => x.id === chatId && x.members.includes(me.id));

        if (method === 'GET') {
          if (!c) return send(res, 404, { error: 'not found' });
          return send(res, 200, chatView(c, me.id));
        }
        if (method === 'PATCH') {
          if (!c) return send(res, 404, { error: 'not found' });
          const b = await readBody(req);
          if (typeof b.name === 'string' && b.name.trim()) c.name = b.name.trim();
          if (typeof b.avatar === 'string') c.avatar = b.avatar;
          if (typeof b.archived === 'boolean') {
            c.archivedBy = b.archived
              ? Array.from(new Set([...(c.archivedBy || []), me.id]))
              : (c.archivedBy || []).filter(id => id !== me.id);
          }
          if (typeof b.muted === 'boolean') {
            c.mutedBy = b.muted
              ? Array.from(new Set([...(c.mutedBy || []), me.id]))
              : (c.mutedBy || []).filter(id => id !== me.id);
          }
          if (Array.isArray(b.addMembers)) c.members = Array.from(new Set([...c.members, ...b.addMembers]));
          if (Array.isArray(b.removeMembers)) c.members = c.members.filter(id => !b.removeMembers.includes(id));
          save();
          broadcastChat(c, 'chat:update', chatView(c, me.id));
          return send(res, 200, chatView(c, me.id));
        }
        if (method === 'DELETE') {
          if (!c) return send(res, 404, { error: 'not found' });
          const idx = db.chats.findIndex(x => x.id === c.id);
          db.chats.splice(idx, 1);
          db.messages = db.messages.filter(m => m.chatId !== c.id);
          save();
          broadcastChat(c, 'chat:delete', { id: c.id });
          return send(res, 200, { ok: true });
        }
      }

      if (method === 'GET' && p.match(/^\/api\/chats\/[^/]+\/messages$/)) {
        const id = p.split('/')[3];
        const c = db.chats.find(x => x.id === id && x.members.includes(me.id));
        if (!c) return send(res, 404, { error: 'not found' });
        const before = Number(url.searchParams.get('before') || 0);
        const limit = Math.min(100, Math.max(1, Number(url.searchParams.get('limit') || 50)));
        let list = db.messages.filter(m => m.chatId === id);
        if (before) list = list.filter(m => m.ts < before);
        list = list.sort((a, b) => a.ts - b.ts).slice(-limit);
        const total = db.messages.filter(m => m.chatId === id).length;
        return send(res, 200, { messages: list, hasMore: total > list.length });
      }

      if (method === 'POST' && p.match(/^\/api\/chats\/[^/]+\/messages$/)) {
        const id = p.split('/')[3];
        const c = db.chats.find(x => x.id === id && x.members.includes(me.id));
        if (!c) return send(res, 404, { error: 'not found' });
        const b = await readBody(req);
        const msg = {
          id: uid(), chatId: id, senderId: me.id,
          text: String(b.text || '').slice(0, 4000),
          type: b.type || 'text',
          attachment: b.attachment || null,
          replyTo: b.replyTo || null,
          clientId: b.clientId || null,
          ts: now(), editedAt: null, deletedAt: null, reactions: {}
        };
        db.messages.push(msg);
        save();
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
          save();
          broadcastChat(c, 'message:update', m);
          return send(res, 200, { message: m });
        }
        if (method === 'DELETE') {
          if (m.senderId !== me.id) return send(res, 403, { error: 'forbidden' });
          m.deletedAt = now();
          m.text = '';
          save();
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
        if (!emoji) return send(res, 400, { error: 'emoji required' });
        m.reactions = m.reactions || {};
        const set = new Set(m.reactions[emoji] || []);
        if (set.has(me.id)) set.delete(me.id); else set.add(me.id);
        m.reactions[emoji] = [...set];
        if (!m.reactions[emoji].length) delete m.reactions[emoji];
        save();
        broadcastChat(c, 'message:update', m);
        return send(res, 200, { message: m });
      }

      if (method === 'POST' && p === '/api/receipts') {
        const b = await readBody(req);
        const chatId = b.chatId;
        const kind = b.kind === 'read' ? 'read' : 'delivered';
        const c = db.chats.find(x => x.id === chatId && x.members.includes(me.id));
        if (!c) return send(res, 404, { error: 'not found' });
        const ids = db.messages.filter(m => m.chatId === chatId).map(m => m.id);
        ids.forEach(id => {
          const r = (db.receipts[id] = db.receipts[id] || { delivered: [], read: [] });
          if (kind === 'read' && !r.read.includes(me.id)) r.read.push(me.id);
          if (!r.delivered.includes(me.id)) r.delivered.push(me.id);
        });
        save();
        broadcastChat(c, 'receipts', { chatId, kind, by: me.id, ts: now() });
        return send(res, 200, { ok: true });
      }

      if (method === 'POST' && p === '/api/typing') {
        const b = await readBody(req);
        const c = db.chats.find(x => x.id === b.chatId && x.members.includes(me.id));
        if (!c) return send(res, 404, { error: 'not found' });
        broadcast(c.members.filter(id => id !== me.id), 'typing', { chatId: c.id, userId: me.id, name: me.name });
        return send(res, 200, { ok: true });
      }

      return send(res, 404, { error: 'not found' });
    }

    // ---- static / SPA ----
    if (method === 'GET' || method === 'HEAD') {
      return serveStatic(req, res, p);
    }

    return send(res, 405, { error: 'method not allowed' });
  } catch (e) {
    console.error('Ошибка запроса', method, p, e && e.message);
    if (!res.headersSent) return send(res, 500, { error: 'server error' });
    try { res.end(); } catch (_) {}
  }
});

server.listen(PORT, () => {
  console.log('NOWA server on http://localhost:' + PORT);
  console.log('PUBLIC_DIR =', PUBLIC_DIR);
  console.log('DATA_FILE  =', DATA_FILE);
});

// graceful shutdown для Render
process.on('SIGTERM', () => {
  console.log('SIGTERM, останавливаемся');
  try { save(); } catch (_) {}
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000);
});
