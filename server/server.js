 'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, '..', 'клиент');
const DATA_FILE = process.env.DATA_DIR ? path.join(process.env.DATA_DIR, 'data.json') : path.join(__dirname, 'data.json');
const SECRET = process.env.NOWA_SECRET || crypto.randomBytes(32).toString('hex');

let db = { users: [], chats: [], messages: [], receipts: {} };
try { if (fs.existsSync(DATA_FILE)) db = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch (e) {}
function save() { try { fs.writeFileSync(DATA_FILE, JSON.stringify(db)); } catch (e) {} }
const uid = () => crypto.randomUUID();
const now = () => Date.now();

function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const mac = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return body + '.' + mac;
}
function verify(token) {
  if (!token) return null;
  const i = token.lastIndexOf('.');
  if (i < 0) return null;
  const body = token.slice(0, i), mac = token.slice(i + 1);
  const expect = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  if (mac !== expect) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (p.exp && p.exp < now()) return null;
    return p;
  } catch { return null; }
}
const makeToken = (userId) => sign({ uid: userId, exp: now() + 1000 * 60 * 60 * 24 * 30 });

function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  return salt + ':' + crypto.scryptSync(pw, salt, 32).toString('hex');
}
function checkPassword(pw, stored) {
  try { const [salt, hash] = String(stored).split(':'); return crypto.scryptSync(pw, salt, 32).toString('hex') === hash; } catch { return false; }
}

const CORS = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Authorization, Content-Type', 'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS' };
function send(res, code, data) { res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', ...CORS }); res.end(typeof data === 'string' ? data : JSON.stringify(data)); }
function readBody(req) { return new Promise((resolve) => { let body = ''; req.on('data', c => body += c); req.on('end', () => { try { resolve(JSON.parse(body || '{}')); } catch { resolve({}); } }); }); }

function authUser(req, url) {
  let token = '';
  const h = req.headers.authorization;
  if (h && h.startsWith('Bearer ')) token = h.slice(7);
  else if (url && url.searchParams.get('token')) token = url.searchParams.get('token');
  const p = verify(token);
  return p ? db.users.find(u => u.id === p.uid) : null;
}

function pubUser(u) { return u ? { id: u.id, name: u.name, phone: u.phone, avatar: u.avatar || '', lastSeen: u.lastSeen || 0 } : null; }

function chatView(c, meId) {
  const members = c.members.map(id => pubUser(db.users.find(u => u.id === id))).filter(Boolean);
  const last = [...db.messages].reverse().find(m => m.chatId === c.id && !m.deletedFor?.includes(meId));
  const other = members.find(m => m.id !== meId);
  const online = other ? (now() - other.lastSeen < 60000) : false;
  return { 
    id: c.id, name: c.name, isGroup: !!c.isGroup, members, avatar: c.avatar || '', 
    lastMessage: last || null, online: online, 
    pinnedMessage: c.pinnedMsgId ? db.messages.find(m => m.id === c.pinnedMsgId) : null
  };
}

const clients = new Map();
function broadcast(userIds, event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  userIds.forEach(id => { const set = clients.get(id); if (set) set.forEach(res => { try { res.write(payload); } catch (_) {} }); });
}
function broadcastChat(c, event, data) { broadcast(c.members, event, data); }

function serveStatic(req, res, pathname) {
  let rel = pathname === '/' ? '/index.html' : pathname;
  const file = path.resolve(PUBLIC_DIR, rel.replace(/^\/+/, ''));
  if (!file.startsWith(path.resolve(PUBLIC_DIR))) return send(res, 403, { error: 'forbidden' });
  if (!fs.existsSync(file) || !fs.statSync(file).isFile()) {
    const fallback = path.join(PUBLIC_DIR, 'index.html');
    if (fs.existsSync(fallback)) { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); return fs.createReadStream(fallback).pipe(res); }
    return send(res, 404, { error: 'not found' });
  }
  const ext = path.extname(file).toLowerCase();
  const type = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.webp': 'image/webp' }[ext] || 'application/octet-stream';
  res.writeHead(200, { 'Content-Type': type }); fs.createReadStream(file).pipe(res);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const method = req.method; const p = url.pathname;
  if (method === 'OPTIONS') { res.writeHead(204, CORS); return res.end(); }
  if (method === 'GET' && p === '/healthz') return send(res, 200, { ok: true });

  try {
    if (p.startsWith('/api/')) {
      if (method === 'POST' && p === '/api/auth/register') {
        const b = await readBody(req);
        if (!b.name || !b.phone || b.password.length < 10) return send(res, 400, { error: 'Заполните все поля (пароль от 10 символов)' });
        if (db.users.some(u => u.phone === b.phone)) return send(res, 409, { error: 'Этот номер уже занят' });
        const user = { id: uid(), name: b.name, phone: b.phone, password: hashPassword(b.password), lastSeen: now() };
        db.users.push(user); save(); return send(res, 200, { token: makeToken(user.id), user: pubUser(user) });
      }
      if (method === 'POST' && p === '/api/auth/login') {
        const b = await readBody(req);
        const u = db.users.find(x => x.phone === b.phone);
        if (!u || !checkPassword(b.password, u.password)) return send(res, 401, { error: 'Неверный номер или пароль' });
        u.lastSeen = now(); save(); return send(res, 200, { token: makeToken(u.id), user: pubUser(u) });
      }
      if (method === 'GET' && p === '/api/stream') {
        const me = authUser(req, url);
        if (!me) return send(res, 401, { error: 'unauthorized' });
        res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive', ...CORS });
        res.write(`: connected\n\n`);
        const set = clients.get(me.id) || new Set(); set.add(res); clients.set(me.id, set);
        req.on('close', () => { set.delete(res); if (!set.size) clients.delete(me.id); });
        return;
      }
      const me = authUser(req, url);
      if (!me) return send(res, 401, { error: 'unauthorized' });
      me.lastSeen = now();
      if (method === 'GET' && p === '/api/me') return send(res, 200, { user: pubUser(me) });
      if (method === 'PATCH' && p === '/api/me') {
        const b = await readBody(req); if (b.name) me.name = b.name; if (b.avatar) me.avatar = b.avatar; save();
        return send(res, 200, { user: pubUser(me) });
      }
      if (method === 'GET' && p === '/api/chats') return send(res, 200, db.chats.filter(c => c.members.includes(me.id)).map(c => chatView(c, me.id)));
      if (method === 'POST' && p === '/api/chats') {
        const b = await readBody(req);
        let peer = db.users.find(u => u.name.toLowerCase() === (b.name || '').toLowerCase() && u.id !== me.id);
        if (!peer && !b.isGroup) return send(res, 404, { error: 'Пользователь не найден' });
        let c = db.chats.find(x => !x.isGroup && !b.isGroup && x.members.includes(me.id) && x.members.includes(peer?.id));
        if (!c) { 
            c = { id: uid(), name: b.name || peer.name, isGroup: !!b.isGroup, members: b.isGroup ? [me.id, ...b.members] : [me.id, peer.id], createdAt: now(), deletedFor: [] }; 
            db.chats.push(c); save(); 
        }
        return send(res, 200, chatView(c, me.id));
      }
      if (method === 'DELETE' && p.startsWith('/api/chats/')) {
        const id = p.split('/')[3]; const c = db.chats.find(x => x.id === id && x.members.includes(me.id));
        if (!c) return send(res, 404, { error: 'not found' });
        c.deletedFor = c.deletedFor || []; if (!c.deletedFor.includes(me.id)) c.deletedFor.push(me.id);
        save(); return send(res, 200, { ok: true });
      }
      if (method === 'GET' && p.startsWith('/api/chats/') && p.endsWith('/messages')) {
        const id = p.split('/')[3]; const c = db.chats.find(x => x.id === id && x.members.includes(me.id));
        if (!c) return send(res, 404, { error: 'not found' });
        db.messages.filter(m => m.chatId === id && m.senderId !== me.id).forEach(m => {
            db.receipts[m.id] = db.receipts[m.id] || []; if (!db.receipts[m.id].includes(me.id)) db.receipts[m.id].push(me.id);
        });
        save(); broadcastChat(c, 'read_receipt', { chatId: id, by: me.id });
        return send(res, 200, { messages: db.messages.filter(m => m.chatId === id && !m.deletedFor?.includes(me.id)).sort((a, b) => a.ts - b.ts).map(m => ({ ...m, readBy: db.receipts[m.id] || [] })) });
      }
      if (method === 'POST' && p.startsWith('/api/chats/') && p.endsWith('/messages')) {
        const id = p.split('/')[3]; const c = db.chats.find(x => x.id === id && x.members.includes(me.id));
        if (!c) return send(res, 404, { error: 'not found' });
        const b = await readBody(req);
        const msg = { id: uid(), chatId: id, senderId: me.id, text: String(b.text || '').slice(0, 4000), type: b.type || 'text', attachment: b.attachment || null, replyTo: b.replyTo || null, ts: now(), deleted: false, reactions: {}, deletedFor: [] };
        db.messages.push(msg); save(); broadcastChat(c, 'message:new', msg);
        return send(res, 200, { message: msg });
      }
      if (method === 'PATCH' && p.startsWith('/api/messages/')) {
        const id = p.split('/')[3]; const m = db.messages.find(x => x.id === id);
        if (!m) return send(res, 404, { error: 'not found' });
        const b = await readBody(req); 
        if (b.text) m.text = b.text; 
        if (b.deleted) { m.deleted = true; m.text = 'Сообщение удалено'; }
        if (b.deleteForMe) { m.deletedFor = m.deletedFor || []; if (!m.deletedFor.includes(me.id)) m.deletedFor.push(me.id); }
        save(); broadcastChat(db.chats.find(c => c.id === m.chatId), 'message:update', m);
        return send(res, 200, { message: m });
      }
      // Закрепление
      if (method === 'POST' && p === '/api/pin') {
        const b = await readBody(req); const c = db.chats.find(x => x.id === b.chatId && x.members.includes(me.id));
        if (c) { c.pinnedMsgId = b.msgId; save(); broadcastChat(c, 'chat:update', chatView(c, me.id)); }
        return send(res, 200, { ok: true });
      }
      if (method === 'POST' && p === '/api/typing') {
        const b = await readBody(req); const c = db.chats.find(x => x.id === b.chatId && x.members.includes(me.id));
        if (c) broadcast(c.members.filter(id => id !== me.id), 'typing', { chatId: c.id, userId: me.id });
        return send(res, 200, { ok: true });
      }
      return send(res, 404, { error: 'not found' });
    }
    if (method === 'GET') return serveStatic(req, res, p);
    return send(res, 405, { error: 'method not allowed' });
  } catch (e) { send(res, 500, { error: 'server error' }); }
});
server.listen(PORT, () => console.log('NOWA server on port', PORT));
