/**
 * NesaraQFS Lab — Backend Server
 * Contact: info@nesaraqfslab.com | +1 (206) 251-7105
 */

'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'data', 'users.json');
const SESSION_TTL = 86400000; // 24 hours

// ---- Ensure data directory ----
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

// ---- In-memory store ----
let users = [];
let sessions = {};

// ---- DB helpers ----
function loadDB() {
  try {
    if (fs.existsSync(DB_FILE)) {
      const raw = fs.readFileSync(DB_FILE, 'utf8');
      users = JSON.parse(raw);
      console.log(`[DB] Loaded ${users.length} users.`);
    }
  } catch (err) {
    console.error('[DB] Load error:', err.message);
    users = [];
  }
}

function saveDB() {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(users, null, 2), 'utf8');
  } catch (err) {
    console.error('[DB] Save error:', err.message);
  }
}

// ---- Crypto helpers ----
function hashPassword(password) {
  return crypto.createHash('sha256').update(password + 'nesaraqfs_salt_2025').digest('hex');
}

function generateSessionId() {
  return crypto.randomBytes(32).toString('hex');
}

function generateCardNum() {
  return Math.floor(1000 + Math.random() * 9000).toString();
}

// ---- Session helpers ----
function cleanExpiredSessions() {
  const now = Date.now();
  Object.keys(sessions).forEach(k => {
    if (sessions[k].expiresAt < now) delete sessions[k];
  });
}
setInterval(cleanExpiredSessions, 600000); // every 10 min

// ---- Cookie parser ----
function parseCookies(req) {
  const cookies = {};
  const header = req.headers.cookie;
  if (!header) return cookies;
  header.split(';').forEach(part => {
    const [name, ...rest] = part.trim().split('=');
    if (name) cookies[name.trim()] = rest.join('=').trim();
  });
  return cookies;
}

// ---- Sanitize user for output ----
function safeUser(user) {
  const { password, ...safe } = user;
  return safe;
}

// ---- CORS headers ----
const CORS = {
  'Access-Control-Allow-Origin': process.env.ALLOWED_ORIGIN || '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Allow-Credentials': 'true'
};

// ---- Response helpers ----
function sendJSON(res, statusCode, data, extraHeaders = {}) {
  res.writeHead(statusCode, { 'Content-Type': 'application/json', ...CORS, ...extraHeaders });
  res.end(JSON.stringify(data));
}

function sendError(res, statusCode, message) {
  sendJSON(res, statusCode, { success: false, error: message });
}

// ---- Auth middleware ----
function requireAuth(req) {
  const cookies = parseCookies(req);
  const sessionId = cookies['nqfs_session'];
  if (!sessionId || !sessions[sessionId]) return null;
  const session = sessions[sessionId];
  if (session.expiresAt < Date.now()) {
    delete sessions[sessionId];
    return null;
  }
  const user = users.find(u => u.id === session.userId);
  return user || null;
}

// ---- Parse JSON body ----
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
      if (body.length > 1e6) reject(new Error('Payload too large'));
    });
    req.on('end', () => {
      try { resolve(JSON.parse(body || '{}')); }
      catch(e) { resolve({}); }
    });
    req.on('error', reject);
  });
}

// ---- MIME types ----
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.webp': 'image/webp',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2'
};

// ---- Rate limiting (simple) ----
const rateLimitMap = {};
function rateLimit(ip, limit = 20, window = 60000) {
  const now = Date.now();
  if (!rateLimitMap[ip] || rateLimitMap[ip].resetAt < now) {
    rateLimitMap[ip] = { count: 0, resetAt: now + window };
  }
  rateLimitMap[ip].count++;
  return rateLimitMap[ip].count > limit;
}

// ============================================================
// API ROUTES
// ============================================================
const routes = {};

// ---- POST /api/register ----
routes['POST /api/register'] = async (req, res) => {
  const body = await parseBody(req);
  const { name, email, password } = body;

  if (!name || !email || !password)
    return sendError(res, 400, 'Name, email, and password are required.');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return sendError(res, 400, 'Invalid email address.');
  if (password.length < 6)
    return sendError(res, 400, 'Password must be at least 6 characters.');
  if (users.find(u => u.email.toLowerCase() === email.toLowerCase()))
    return sendError(res, 409, 'An account with this email already exists.');

  const user = {
    id: crypto.randomUUID ? crypto.randomUUID() : Date.now().toString(36) + Math.random().toString(36),
    name: name.trim(),
    email: email.toLowerCase().trim(),
    password: hashPassword(password),
    walletBalance: 0,
    kycStatus: 'unverified',
    cardNum: generateCardNum(),
    createdAt: new Date().toISOString()
  };

  users.push(user);
  saveDB();

  const sessionId = generateSessionId();
  sessions[sessionId] = { userId: user.id, expiresAt: Date.now() + SESSION_TTL };

  sendJSON(res, 201, { success: true, user: safeUser(user) }, {
    'Set-Cookie': `nqfs_session=${sessionId}; HttpOnly; SameSite=Lax; Max-Age=${SESSION_TTL / 1000}; Path=/`
  });
};

// ---- POST /api/login ----
routes['POST /api/login'] = async (req, res) => {
  const body = await parseBody(req);
  const { email, password } = body;

  if (!email || !password)
    return sendError(res, 400, 'Email and password are required.');

  const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (!user || user.password !== hashPassword(password))
    return sendError(res, 401, 'Invalid email or password.');

  const sessionId = generateSessionId();
  sessions[sessionId] = { userId: user.id, expiresAt: Date.now() + SESSION_TTL };

  sendJSON(res, 200, { success: true, user: safeUser(user) }, {
    'Set-Cookie': `nqfs_session=${sessionId}; HttpOnly; SameSite=Lax; Max-Age=${SESSION_TTL / 1000}; Path=/`
  });
};

// ---- GET /api/me ----
routes['GET /api/me'] = (req, res) => {
  const user = requireAuth(req);
  if (!user) return sendError(res, 401, 'Not authenticated.');
  sendJSON(res, 200, { success: true, user: safeUser(user) });
};

// ---- POST /api/logout ----
routes['POST /api/logout'] = (req, res) => {
  const cookies = parseCookies(req);
  const sessionId = cookies['nqfs_session'];
  if (sessionId) delete sessions[sessionId];
  sendJSON(res, 200, { success: true }, {
    'Set-Cookie': 'nqfs_session=; HttpOnly; SameSite=Lax; Max-Age=0; Path=/'
  });
};

// ---- POST /api/wallet/sync ----
routes['POST /api/wallet/sync'] = (req, res) => {
  const user = requireAuth(req);
  if (!user) return sendError(res, 401, 'Not authenticated.');

  user.walletBalance = Math.floor(Math.random() * 500000) + 50000;
  user.lastSynced = new Date().toISOString();
  saveDB();

  sendJSON(res, 200, { success: true, balance: user.walletBalance, qfsCoins: (user.walletBalance / 1.24).toFixed(2) });
};

// ---- POST /api/kyc/submit ----
routes['POST /api/kyc/submit'] = (req, res) => {
  const user = requireAuth(req);
  if (!user) return sendError(res, 401, 'Not authenticated.');
  if (user.kycStatus === 'verified') return sendJSON(res, 200, { success: true, status: 'verified', message: 'Already verified.' });

  user.kycStatus = 'pending';
  user.kycSubmittedAt = new Date().toISOString();
  saveDB();

  // Auto-verify after 5 seconds (simulation)
  setTimeout(() => {
    const u = users.find(u2 => u2.id === user.id);
    if (u && u.kycStatus === 'pending') {
      u.kycStatus = 'verified';
      u.kycVerifiedAt = new Date().toISOString();
      saveDB();
    }
  }, 5000);

  sendJSON(res, 200, { success: true, status: 'pending', message: 'KYC submitted. Verification in progress.' });
};

// ---- PUT /api/profile ----
routes['PUT /api/profile'] = async (req, res) => {
  const user = requireAuth(req);
  if (!user) return sendError(res, 401, 'Not authenticated.');
  const body = await parseBody(req);
  if (body.name) user.name = body.name.trim().substring(0, 100);
  saveDB();
  sendJSON(res, 200, { success: true, user: safeUser(user) });
};

// ---- GET /api/health ----
routes['GET /api/health'] = (req, res) => {
  sendJSON(res, 200, {
    status: 'operational',
    service: 'NesaraQFS Lab API',
    uptime: process.uptime(),
    users: users.length,
    timestamp: new Date().toISOString()
  });
};

// ---- Static file server ----
const STATIC_DIR = path.join(__dirname, '..', 'frontend');

function serveStatic(req, res, pathname) {
  const filePath = path.join(STATIC_DIR, pathname === '/' ? 'index.html' : pathname);
  const safeBase = path.resolve(STATIC_DIR);
  const safeTarget = path.resolve(filePath);
  if (!safeTarget.startsWith(safeBase)) {
    res.writeHead(403); res.end('Forbidden'); return;
  }
  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME[ext] || 'application/octet-stream';
  fs.readFile(filePath, (err, data) => {
    if (err) {
      if (err.code === 'ENOENT') {
        fs.readFile(path.join(STATIC_DIR, 'index.html'), (e2, d2) => {
          if (e2) { res.writeHead(404); res.end('Not found'); }
          else { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...CORS }); res.end(d2); }
        });
      } else { res.writeHead(500); res.end('Server error'); }
    } else {
      res.writeHead(200, { 'Content-Type': contentType, ...CORS, 'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=3600' });
      res.end(data);
    }
  });
}

// ---- Main server ----
const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';

  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, CORS);
    res.end();
    return;
  }

  // Rate limiting on API
  if (pathname.startsWith('/api/') && rateLimit(clientIp)) {
    return sendError(res, 429, 'Too many requests. Please slow down.');
  }

  // API routes
  const routeKey = `${req.method} ${pathname}`;
  if (routes[routeKey]) {
    try {
      await routes[routeKey](req, res);
    } catch (err) {
      console.error('[API Error]', routeKey, err.message);
      sendError(res, 500, 'Internal server error.');
    }
    return;
  }

  // Unknown API
  if (pathname.startsWith('/api/')) {
    return sendError(res, 404, 'API endpoint not found.');
  }

  // Static files
  serveStatic(req, res, pathname);
});

// ---- Boot ----
loadDB();

server.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   ███╗   ██╗███████╗███████╗ █████╗ ██████╗  █████╗     ║
║   ████╗  ██║██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗   ║
║   ██╔██╗ ██║█████╗  ███████╗███████║██████╔╝███████║   ║
║   ██║╚██╗██║██╔══╝  ╚════██║██╔══██║██╔══██╗██╔══██║   ║
║   ██║ ╚████║███████╗███████║██║  ██║██║  ██║██║  ██║   ║
║   ╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ║
║                    QFS LAB SERVER                        ║
╠══════════════════════════════════════════════════════════╣
║                                                          ║
║  🚀 Server:    http://localhost:${PORT}                       ║
║  📧 Email:     info@nesaraqfslab.com                    ║
║  📞 Phone:     +1 (206) 251-7105                        ║
║                                                          ║
║  API Endpoints:                                          ║
║  POST /api/register  — Create account                   ║
║  POST /api/login     — Authenticate                     ║
║  GET  /api/me        — Get current user                 ║
║  POST /api/logout    — End session                      ║
║  POST /api/wallet/sync — Sync wallet balance            ║
║  POST /api/kyc/submit  — Submit KYC documents           ║
║  PUT  /api/profile   — Update profile                   ║
║  GET  /api/health    — System health check              ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
`);
});

// ---- Graceful shutdown ----
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
function shutdown() {
  console.log('\n[Server] Shutting down gracefully...');
  saveDB();
  server.close(() => {
    console.log('[Server] Closed. Goodbye.');
    process.exit(0);
  });
}
