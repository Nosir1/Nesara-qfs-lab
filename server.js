/**
 * ============================================================
 *   NESARA QFS LAB — Backend Server
 *   Contact: info@nesaraqfslab.com | +1 (206) 251-7105
 * ============================================================
 */

const http = require('http');
const fs   = require('fs');
const path = require('path');
const url  = require('url');
const crypto = require('crypto');

const PORT     = process.env.PORT || 3000;
const DATA_DIR  = path.join(process.cwd(), 'data');
const DB_FILE   = path.join(DATA_DIR, 'users.json');
const LOG_FILE  = path.join(DATA_DIR, 'tickets.json');

// ── Data helpers ──────────────────────────────────────────────
function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

function loadJSON(file, fallback = []) {
  try {
    if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (_) {}
  return fallback;
}

function saveJSON(file, data) {
  ensureDataDir();
  fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8');
}

// ── In-memory state ───────────────────────────────────────────
ensureDataDir();
let users    = loadJSON(DB_FILE, []);
let tickets  = loadJSON(LOG_FILE, []);
const sessions = {}; // sessionId → userId

// ── Utilities ─────────────────────────────────────────────────
function uid()       { return crypto.randomBytes(16).toString('hex'); }
function sessionId() { return crypto.randomBytes(24).toString('base64url'); }

function hashPassword(pw) {
  return crypto.createHash('sha256').update(pw + 'nqfs_salt_v1').digest('hex');
}

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

function safeUser(u) {
  const { password, ...safe } = u;
  return safe;
}

const CORS = {
  'Access-Control-Allow-Origin'  : '*',
  'Access-Control-Allow-Methods' : 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers' : 'Content-Type, Authorization',
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
    req.on('end', () => {
      try { resolve(JSON.parse(body || '{}')); }
      catch { resolve({}); }
    });
    req.on('error', reject);
  });
}

// ── MIME types ────────────────────────────────────────────────
const MIME = {
  '.html': 'text/html',
  '.js'  : 'text/javascript',
  '.css' : 'text/css',
  '.json': 'application/json',
  '.png' : 'image/png',
  '.jpg' : 'image/jpeg',
  '.gif' : 'image/gif',
  '.svg' : 'image/svg+xml',
  '.ico' : 'image/x-icon',
  '.woff2': 'font/woff2',
  '.woff' : 'font/woff',
};

// ── Route handlers ────────────────────────────────────────────
const routes = {

  // POST /api/register
  async 'POST /api/register'(req, res) {
    const { name, email, password } = await readBody(req);
    if (!email || !password) return json(res, 400, { error: 'Email and password are required.' });
    if (users.find(u => u.email === email.toLowerCase()))
      return json(res, 409, { error: 'An account with this email already exists.' });
    if (password.length < 6)
      return json(res, 400, { error: 'Password must be at least 6 characters.' });

    const user = {
      id            : uid(),
      name          : name?.trim() || 'User',
      email         : email.toLowerCase().trim(),
      password      : hashPassword(password),
      walletBalance : 0,
      kycStatus     : 'unverified',
      createdAt     : new Date().toISOString(),
      lastLogin     : new Date().toISOString(),
    };
    users.push(user);
    saveJSON(DB_FILE, users);

    const sid = sessionId();
    sessions[sid] = user.id;

    json(res, 201, { success: true, user: safeUser(user) }, {
      'Set-Cookie': `nqfs_session=${sid}; HttpOnly; Path=/; Max-Age=86400; SameSite=Lax`,
    });
  },

  // POST /api/login
  async 'POST /api/login'(req, res) {
    const { email, password } = await readBody(req);
    if (!email || !password) return json(res, 400, { error: 'Email and password are required.' });

    const user = users.find(u => u.email === email.toLowerCase().trim());
    if (!user || user.password !== hashPassword(password))
      return json(res, 401, { error: 'Invalid email or password.' });

    user.lastLogin = new Date().toISOString();
    saveJSON(DB_FILE, users);

    const sid = sessionId();
    sessions[sid] = user.id;

    json(res, 200, { success: true, user: safeUser(user) }, {
      'Set-Cookie': `nqfs_session=${sid}; HttpOnly; Path=/; Max-Age=86400; SameSite=Lax`,
    });
  },

  // POST /api/logout
  async 'POST /api/logout'(req, res) {
    const sid = parseCookies(req).nqfs_session;
    if (sid) delete sessions[sid];
    json(res, 200, { success: true }, {
      'Set-Cookie': 'nqfs_session=; HttpOnly; Path=/; Max-Age=0',
    });
  },

  // GET /api/me
  async 'GET /api/me'(req, res) {
    const user = getUser(req);
    if (!user) return json(res, 401, { error: 'Not authenticated.' });
    json(res, 200, { user: safeUser(user) });
  },

  // POST /api/wallet/sync
  async 'POST /api/wallet/sync'(req, res) {
    const user = getUser(req);
    if (!user) return json(res, 401, { error: 'Not authenticated.' });

    // Simulate QFS network sync
    const delta = Math.floor(Math.random() * 900_000) + 50_000;
    user.walletBalance = delta;
    user.lastSync = new Date().toISOString();
    saveJSON(DB_FILE, users);

    json(res, 200, {
      success: true,
      balance: user.walletBalance,
      qfsBalance: (user.walletBalance * 0.82).toFixed(2),
      syncedAt: user.lastSync,
    });
  },

  // POST /api/kyc/submit
  async 'POST /api/kyc/submit'(req, res) {
    const user = getUser(req);
    if (!user) return json(res, 401, { error: 'Not authenticated.' });
    if (user.kycStatus === 'verified') return json(res, 200, { success: true, status: 'verified' });

    user.kycStatus = 'pending';
    saveJSON(DB_FILE, users);

    // Auto-verify after 3 s (simulation)
    setTimeout(() => {
      user.kycStatus = 'verified';
      user.kycVerifiedAt = new Date().toISOString();
      saveJSON(DB_FILE, users);
    }, 3000);

    json(res, 200, { success: true, status: 'pending' });
  },

  // GET /api/kyc/status
  async 'GET /api/kyc/status'(req, res) {
    const user = getUser(req);
    if (!user) return json(res, 401, { error: 'Not authenticated.' });
    json(res, 200, { status: user.kycStatus, verifiedAt: user.kycVerifiedAt || null });
  },

  // POST /api/tickets
  async 'POST /api/tickets'(req, res) {
    const { name, email, subject, message } = await readBody(req);
    if (!email || !message) return json(res, 400, { error: 'Email and message are required.' });

    const ticket = {
      id       : uid(),
      name     : name || 'Anonymous',
      email,
      subject  : subject || 'General',
      message,
      status   : 'open',
      createdAt: new Date().toISOString(),
    };
    tickets.push(ticket);
    saveJSON(LOG_FILE, tickets);

    console.log(`\n[TICKET #${ticket.id.slice(0,8)}] From: ${email} | ${subject}`);
    json(res, 201, { success: true, ticketId: ticket.id });
  },

  // GET /api/tickets (admin – no auth for demo)
  async 'GET /api/tickets'(req, res) {
    json(res, 200, { tickets });
  },

  // GET /api/status
  async 'GET /api/status'(req, res) {
    json(res, 200, {
      status      : 'operational',
      version     : '2.0.0',
      uptime      : process.uptime(),
      users       : users.length,
      sessions    : Object.keys(sessions).length,
      ticketsOpen : tickets.filter(t => t.status === 'open').length,
      timestamp   : new Date().toISOString(),
    });
  },
};

// ── HTTP Server ───────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const parsed   = url.parse(req.url, true);
  const pathname = parsed.pathname;

  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, CORS);
    res.end();
    return;
  }

  // API routing
  const key = `${req.method} ${pathname}`;
  if (routes[key]) {
    try { await routes[key](req, res); }
    catch (err) {
      console.error('Route error:', err);
      json(res, 500, { error: 'Internal server error.' });
    }
    return;
  }

  // Static file serving (from /public directory)
  const publicDir = path.join(process.cwd(), 'public');
  let filePath = path.join(publicDir, pathname === '/' ? 'index.html' : pathname);

  // Security: prevent directory traversal
  if (!filePath.startsWith(publicDir)) {
    json(res, 403, { error: 'Forbidden.' });
    return;
  }

  const ext         = path.extname(filePath).toLowerCase();
  const contentType = MIME[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        // SPA fallback: serve index.html for unknown paths
        fs.readFile(path.join(publicDir, 'index.html'), (e2, html) => {
          if (e2) { res.writeHead(404); res.end('Not Found'); return; }
          res.writeHead(200, { 'Content-Type': 'text/html', ...CORS });
          res.end(html);
        });
      } else {
        res.writeHead(500);
        res.end('Server Error: ' + err.code);
      }
    } else {
      res.writeHead(200, { 'Content-Type': contentType, ...CORS });
      res.end(content);
    }
  });
});

// ── Start ─────────────────────────────────────────────────────
server.listen(PORT, () => {
  const banner = `
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   ███╗   ██╗ ██████╗ ███████╗ █████╗ ██████╗  █████╗    ║
║   ████╗  ██║██╔═══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗   ║
║   ██╔██╗ ██║██║   ██║███████╗███████║██████╔╝███████║   ║
║   ██║╚██╗██║██║   ██║╚════██║██╔══██║██╔══██╗██╔══██║   ║
║   ██║ ╚████║╚██████╔╝███████║██║  ██║██║  ██║██║  ██║   ║
║   ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝  ║
║                                                          ║
║            QFS LAB — Backend Server v2.0                 ║
╠══════════════════════════════════════════════════════════╣
║                                                          ║
║  🌐  http://localhost:${PORT}                               ║
║  📧  info@nesaraqfslab.com                               ║
║  📞  +1 (206) 251-7105                                   ║
║                                                          ║
║  API Endpoints:                                          ║
║  POST  /api/register        Register new user            ║
║  POST  /api/login           Authenticate user            ║
║  POST  /api/logout          End session                  ║
║  GET   /api/me              Current user info            ║
║  POST  /api/wallet/sync     Sync wallet balance          ║
║  POST  /api/kyc/submit      Submit KYC verification      ║
║  GET   /api/kyc/status      Get KYC status               ║
║  POST  /api/tickets         Submit support ticket        ║
║  GET   /api/tickets         List all tickets             ║
║  GET   /api/status          System health check          ║
║                                                          ║
║  Static files served from: ./public/                     ║
║  Data stored in: ./data/                                 ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝`;
  console.log(banner);
});

// ── Graceful shutdown ─────────────────────────────────────────
function gracefulShutdown(signal) {
  console.log(`\n[${signal}] Saving data and shutting down...`);
  saveJSON(DB_FILE, users);
  saveJSON(LOG_FILE, tickets);
  server.close(() => {
    console.log('Server closed. Goodbye.');
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 5000);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT',  () => gracefulShutdown('SIGINT'));
