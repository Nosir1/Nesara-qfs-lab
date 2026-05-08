/**
 * NESARA QFS LAB — Backend Server v6
 * Contact: info@nesaraqfslab.com | +1 (206) 251-7105
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(process.cwd(), 'data');
const DB_FILE = path.join(DATA_DIR, 'users.json');
const TICKETS_FILE = path.join(DATA_DIR, 'tickets.json');

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

function loadJSON(file, fallback = []) {
  try { if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (_) {}
  return fallback;
}

function saveJSON(file, data) {
  ensureDataDir();
  fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8');
}

ensureDataDir();
let users = loadJSON(DB_FILE, []);
let tickets = loadJSON(TICKETS_FILE, []);
const sessions = {};

function uid() { return crypto.randomBytes(16).toString('hex'); }
function genSession() { return crypto.randomBytes(24).toString('base64url'); }
function hashPw(pw) { return crypto.createHash('sha256').update(pw + 'nqfs_salt_v1').digest('hex'); }

function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(c => {
    const [k, ...v] = c.trim().split('=');
    if (k) out[k] = v.join('=');
  });
  return out;
}

function getUser(req) {
  const sid = parseCookies(req).nqfs_session;
  if (!sid || !sessions[sid]) return null;
  return users.find(u => u.id === sessions[sid]) || null;
}

function safeUser(u) { const { password, ...s } = u; return s; }

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Allow-Credentials': 'true',
};

function json(res, status, data, extra = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json', ...CORS, ...extra });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => { try { resolve(JSON.parse(body || '{}')); } catch { resolve({}); } });
    req.on('error', reject);
  });
}

// Send email notification via simple log (Hostinger SMTP would be added here)
function notifyAdmin(subject, message) {
  const timestamp = new Date().toISOString();
  const logLine = `[${timestamp}] ${subject}: ${message}\n`;
  try {
    fs.appendFileSync(path.join(DATA_DIR, 'notifications.log'), logLine);
  } catch(e) {}
  console.log(`📧 ADMIN NOTIFICATION: ${subject} — ${message}`);
}

const MIME = {
  '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css',
  '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.gif': 'image/gif', '.svg': 'image/svg+xml', '.ico': 'image/x-icon',
};

const routes = {
  async 'POST /api/register'(req, res) {
    const { name, email, password } = await readBody(req);
    if (!email || !password) return json(res, 400, { error: 'Email and password required.' });
    if (users.find(u => u.email === email.toLowerCase())) return json(res, 409, { error: 'Email already registered.' });
    if (password.length < 6) return json(res, 400, { error: 'Password must be at least 6 characters.' });
    const user = {
      id: uid(), name: name?.trim() || 'User', email: email.toLowerCase().trim(),
      password: hashPw(password), kycStatus: 'unverified', kycFile: null, kycDocType: null,
      balances: { XLM: 0, XRP: 0, USDC: 0, BTC: 0 },
      transactions: [], tickets: [], depositProofs: [],
      createdAt: new Date().toISOString(), lastLogin: new Date().toISOString(),
    };
    users.push(user);
    saveJSON(DB_FILE, users);
    notifyAdmin('New Registration', `${user.name} (${user.email}) just registered`);
    const sid = genSession();
    sessions[sid] = user.id;
    json(res, 201, { success: true, user: safeUser(user) }, {
      'Set-Cookie': `nqfs_session=${sid}; HttpOnly; Path=/; Max-Age=86400; SameSite=Lax`,
    });
  },

  async 'POST /api/login'(req, res) {
    const { email, password } = await readBody(req);
    const user = users.find(u => u.email === email?.toLowerCase().trim());
    if (!user || user.password !== hashPw(password)) return json(res, 401, { error: 'Invalid email or password.' });
    user.lastLogin = new Date().toISOString();
    saveJSON(DB_FILE, users);
    const sid = genSession();
    sessions[sid] = user.id;
    json(res, 200, { success: true, user: safeUser(user) }, {
      'Set-Cookie': `nqfs_session=${sid}; HttpOnly; Path=/; Max-Age=86400; SameSite=Lax`,
    });
  },

  async 'POST /api/logout'(req, res) {
    const sid = parseCookies(req).nqfs_session;
    if (sid) delete sessions[sid];
    json(res, 200, { success: true }, { 'Set-Cookie': 'nqfs_session=; HttpOnly; Path=/; Max-Age=0' });
  },

  async 'GET /api/me'(req, res) {
    const user = getUser(req);
    if (!user) return json(res, 401, { error: 'Not authenticated.' });
    json(res, 200, { user: safeUser(user) });
  },

  async 'POST /api/wallet/sync'(req, res) {
    const user = getUser(req);
    if (!user) return json(res, 401, { error: 'Not authenticated.' });
    user.lastSync = new Date().toISOString();
    saveJSON(DB_FILE, users);
    json(res, 200, { success: true, balances: user.balances, syncedAt: user.lastSync });
  },

  async 'POST /api/kyc/submit'(req, res) {
    const user = getUser(req);
    if (!user) return json(res, 401, { error: 'Not authenticated.' });
    const body = await readBody(req);
    if (user.kycStatus === 'verified') return json(res, 200, { success: true, status: 'verified' });
    user.kycStatus = 'pending';
    user.kycFile = body.fileData || null;
    user.kycDocType = body.docType || 'unknown';
    saveJSON(DB_FILE, users);
    notifyAdmin('KYC Submitted', `${user.name} (${user.email}) submitted ${user.kycDocType} for KYC review`);
    json(res, 200, { success: true, status: 'pending' });
  },

  async 'GET /api/kyc/status'(req, res) {
    const user = getUser(req);
    if (!user) return json(res, 401, { error: 'Not authenticated.' });
    json(res, 200, { status: user.kycStatus, verifiedAt: user.kycVerifiedAt || null });
  },

  async 'POST /api/ticket'(req, res) {
    const body = await readBody(req);
    const { name, email, subject, message, userId } = body;
    if (!email || !message) return json(res, 400, { error: 'Email and message required.' });
    const ticket = {
      id: uid(), name: name || 'Anonymous', email, subject: subject || 'General',
      message, status: 'open', userId: userId || null, createdAt: new Date().toISOString(),
    };
    // Save to global tickets
    tickets.push(ticket);
    saveJSON(TICKETS_FILE, tickets);
    // Also save to user if logged in
    if (userId) {
      const user = users.find(u => u.id === userId);
      if (user) {
        if (!user.tickets) user.tickets = [];
        user.tickets.unshift({ ...ticket });
        saveJSON(DB_FILE, users);
      }
    }
    notifyAdmin('Support Ticket', `From: ${name} (${email}) — Subject: ${subject} — Message: ${message.substring(0, 100)}`);
    json(res, 201, { success: true, ticketId: ticket.id });
  },

  async 'POST /api/deposit-proof'(req, res) {
    const user = getUser(req);
    if (!user) return json(res, 401, { error: 'Not authenticated.' });
    const body = await readBody(req);
    const proof = {
      id: uid(), coin: body.coin, amount: body.amount, txhash: body.txhash || '',
      screenshot: body.screenshot || null, status: 'pending',
      submittedAt: new Date().toISOString(),
    };
    if (!user.depositProofs) user.depositProofs = [];
    user.depositProofs.unshift(proof);
    saveJSON(DB_FILE, users);
    notifyAdmin('Deposit Proof', `${user.name} (${user.email}) submitted proof for ${body.amount} ${body.coin}. TX: ${body.txhash || 'No hash'}`);
    json(res, 201, { success: true, proofId: proof.id });
  },

  async 'GET /api/tickets'(req, res) {
    json(res, 200, { tickets });
  },

  async 'GET /api/users'(req, res) {
    json(res, 200, { users: users.map(safeUser) });
  },

  async 'POST /api/admin/save-users'(req, res) {
    const body = await readBody(req);
    if (!body.users) return json(res, 400, { error: 'No users provided' });
    // Merge incoming users with existing - don't overwrite passwords
    body.users.forEach(incomingUser => {
      const existing = users.find(u => u.id === incomingUser.id);
      if (existing) {
        // Update balances, kyc, etc but keep password from server
        Object.assign(existing, { ...incomingUser, password: existing.password });
      } else if (incomingUser.id) {
        users.push(incomingUser);
      }
    });
    saveJSON(DB_FILE, users);
    json(res, 200, { success: true, count: users.length });
  },

  async 'POST /api/admin/update-user'(req, res) {
    const body = await readBody(req);
    const { userId, updates } = body;
    const user = users.find(u => u.id === userId);
    if (!user) return json(res, 404, { error: 'User not found' });
    Object.assign(user, updates);
    saveJSON(DB_FILE, users);
    json(res, 200, { success: true, user: safeUser(user) });
  },

  async 'GET /api/status'(req, res) {
    json(res, 200, {
      status: 'operational', version: '6.0.0', uptime: process.uptime(),
      users: users.length, sessions: Object.keys(sessions).length,
      ticketsOpen: tickets.filter(t => t.status === 'open').length,
      timestamp: new Date().toISOString(),
    });
  },
};

const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;

  if (req.method === 'OPTIONS') { res.writeHead(204, CORS); res.end(); return; }

  const key = `${req.method} ${pathname}`;
  if (routes[key]) {
    try { await routes[key](req, res); } catch (err) {
      console.error('Route error:', err);
      json(res, 500, { error: 'Internal server error.' });
    }
    return;
  }

  // Admin route
  if (pathname === '/admin' || pathname === '/admin/') {
    const adminFile = path.join(process.cwd(), 'public', 'admin.html');
    fs.readFile(adminFile, (err, content) => {
      if (err) { res.writeHead(404); res.end('Admin not found'); return; }
      res.writeHead(200, { 'Content-Type': 'text/html', ...CORS });
      res.end(content);
    });
    return;
  }

  // Static files
  const publicDir = path.join(process.cwd(), 'public');
  let filePath = path.join(publicDir, pathname === '/' ? 'index.html' : pathname);
  if (!filePath.startsWith(publicDir)) { json(res, 403, { error: 'Forbidden.' }); return; }

  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, content) => {
    if (err) {
      fs.readFile(path.join(publicDir, 'index.html'), (e2, html) => {
        if (e2) { res.writeHead(404); res.end('Not Found'); return; }
        res.writeHead(200, { 'Content-Type': 'text/html', ...CORS });
        res.end(html);
      });
    } else {
      res.writeHead(200, { 'Content-Type': contentType, ...CORS });
      res.end(content);
    }
  });
});

server.listen(PORT, () => {
  console.log(`\n🚀 NESARA QFS LAB Server v6.0 running on port ${PORT}`);
  console.log(`📧 Notifications logged to: ${DATA_DIR}/notifications.log`);
  console.log(`👑 Admin panel: /admin`);
});

process.on('SIGTERM', () => { saveJSON(DB_FILE, users); saveJSON(TICKETS_FILE, tickets); server.close(() => process.exit(0)); });
process.on('SIGINT', () => { saveJSON(DB_FILE, users); saveJSON(TICKETS_FILE, tickets); server.close(() => process.exit(0)); });
