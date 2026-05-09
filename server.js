/**
 * NESARA QFS LAB — Backend Server v7
 * ALL data operations through API — no localStorage dependency
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

function ensureDataDir() { if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true }); }
function loadJSON(file, fallback = []) { try { if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (_) {} return fallback; }
function saveJSON(file, data) { ensureDataDir(); fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8'); }

ensureDataDir();
let users = loadJSON(DB_FILE, []);
const sessions = {};

function uid() { return crypto.randomBytes(12).toString('hex'); }
function genToken() { return crypto.randomBytes(32).toString('base64url'); }
function hashPw(pw) { return crypto.createHash('sha256').update(pw + 'nqfs_v7').digest('hex'); }
function safeUser(u) { const { password, kycFile, ...s } = u; s.hasKycFile = !!u.kycFile; return s; }

function getSession(req) {
  const auth = req.headers.authorization;
  if (auth && auth.startsWith('Bearer ')) {
    const token = auth.slice(7);
    const userId = sessions[token];
    if (userId) return users.find(u => u.id === userId) || null;
  }
  return null;
}

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Allow-Credentials': 'true',
};

function json(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json', ...CORS });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', c => { if (body.length < 10000000) body += c; }); // 10MB limit
    req.on('end', () => { try { resolve(JSON.parse(body || '{}')); } catch { resolve({}); } });
  });
}

const MIME = { '.html':'text/html', '.js':'text/javascript', '.css':'text/css', '.json':'application/json', '.png':'image/png', '.jpg':'image/jpeg', '.svg':'image/svg+xml', '.ico':'image/x-icon' };

// ═══════════════════════════════════════
// API ROUTES
// ═══════════════════════════════════════

const routes = {

  // ── AUTH ──
  async 'POST /api/register'(req, res) {
    const { name, email, password } = await readBody(req);
    if (!email || !password) return json(res, 400, { error: 'Email and password required.' });
    if (password.length < 6) return json(res, 400, { error: 'Password must be at least 6 characters.' });
    if (users.find(u => u.email === email.toLowerCase().trim())) return json(res, 409, { error: 'Email already registered.' });

    const user = {
      id: uid(),
      name: (name || 'User').trim(),
      email: email.toLowerCase().trim(),
      password: hashPw(password),
      kycStatus: 'unverified',
      kycFile: null,
      kycDocType: null,
      balances: { XLM: 0, XRP: 0, USDC: 0, BTC: 0 },
      transactions: [],
      tickets: [],
      depositProofs: [],
      withdrawals: [],
      createdAt: new Date().toISOString(),
    };

    users.push(user);
    saveJSON(DB_FILE, users);

    const token = genToken();
    sessions[token] = user.id;

    console.log(`📧 NEW REGISTRATION: ${user.name} (${user.email})`);
    json(res, 201, { success: true, token, user: safeUser(user) });
  },

  async 'POST /api/login'(req, res) {
    const { email, password } = await readBody(req);
    if (!email || !password) return json(res, 400, { error: 'Email and password required.' });

    const user = users.find(u => u.email === email.toLowerCase().trim());
    if (!user || user.password !== hashPw(password)) return json(res, 401, { error: 'Invalid email or password.' });

    const token = genToken();
    sessions[token] = user.id;

    json(res, 200, { success: true, token, user: safeUser(user) });
  },

  async 'POST /api/logout'(req, res) {
    const auth = req.headers.authorization;
    if (auth && auth.startsWith('Bearer ')) delete sessions[auth.slice(7)];
    json(res, 200, { success: true });
  },

  async 'GET /api/me'(req, res) {
    const user = getSession(req);
    if (!user) return json(res, 401, { error: 'Not authenticated.' });
    json(res, 200, { user: safeUser(user) });
  },

  async 'POST /api/change-password'(req, res) {
    const user = getSession(req);
    if (!user) return json(res, 401, { error: 'Not authenticated.' });
    const { currentPassword, newPassword } = await readBody(req);
    if (user.password !== hashPw(currentPassword)) return json(res, 400, { error: 'Current password incorrect.' });
    if (!newPassword || newPassword.length < 6) return json(res, 400, { error: 'New password must be 6+ characters.' });
    user.password = hashPw(newPassword);
    saveJSON(DB_FILE, users);
    json(res, 200, { success: true });
  },

  async 'POST /api/update-profile'(req, res) {
    const user = getSession(req);
    if (!user) return json(res, 401, { error: 'Not authenticated.' });
    const { name } = await readBody(req);
    if (name) user.name = name.trim();
    saveJSON(DB_FILE, users);
    json(res, 200, { success: true, user: safeUser(user) });
  },

  // ── KYC ──
  async 'POST /api/kyc/submit'(req, res) {
    const user = getSession(req);
    if (!user) return json(res, 401, { error: 'Not authenticated.' });
    if (user.kycStatus === 'verified') return json(res, 200, { success: true, status: 'verified' });

    const { docType, fileData } = await readBody(req);
    user.kycStatus = 'pending';
    user.kycDocType = docType || 'unknown';
    user.kycFile = fileData || null;
    user.kycSubmittedAt = new Date().toISOString();
    saveJSON(DB_FILE, users);

    console.log(`🪪 KYC SUBMITTED: ${user.name} (${user.email}) — ${user.kycDocType}`);
    json(res, 200, { success: true, status: 'pending' });
  },

  async 'GET /api/kyc/status'(req, res) {
    const user = getSession(req);
    if (!user) return json(res, 401, { error: 'Not authenticated.' });
    json(res, 200, { status: user.kycStatus, docType: user.kycDocType, submittedAt: user.kycSubmittedAt });
  },

  // ── DEPOSIT PROOF ──
  async 'POST /api/deposit-proof'(req, res) {
    const user = getSession(req);
    if (!user) return json(res, 401, { error: 'Not authenticated.' });

    const { coin, amount, txhash, screenshot } = await readBody(req);
    if (!coin || !amount) return json(res, 400, { error: 'Coin and amount required.' });

    const proof = {
      id: uid(), coin, amount: parseFloat(amount), txhash: txhash || '',
      screenshot: screenshot || null, status: 'pending',
      submittedAt: new Date().toISOString(),
    };

    if (!user.depositProofs) user.depositProofs = [];
    user.depositProofs.unshift(proof);
    saveJSON(DB_FILE, users);

    console.log(`💰 DEPOSIT PROOF: ${user.name} — ${amount} ${coin}`);
    json(res, 201, { success: true, proof: { ...proof, screenshot: null } });
  },

  async 'GET /api/deposit-proofs'(req, res) {
    const user = getSession(req);
    if (!user) return json(res, 401, { error: 'Not authenticated.' });
    const proofs = (user.depositProofs || []).map(p => ({ ...p, screenshot: null }));
    json(res, 200, { proofs });
  },

  // ── WITHDRAWAL ──
  async 'POST /api/withdrawal'(req, res) {
    const user = getSession(req);
    if (!user) return json(res, 401, { error: 'Not authenticated.' });

    const { coin, amount, address, note } = await readBody(req);
    if (!coin || !amount || !address) return json(res, 400, { error: 'Coin, amount and address required.' });

    const bal = (user.balances && user.balances[coin]) || 0;
    if (parseFloat(amount) > bal) return json(res, 400, { error: 'Insufficient balance.' });

    const wd = {
      id: uid(), coin, amount: parseFloat(amount), address, note: note || '',
      status: 'pending', submittedAt: new Date().toISOString(),
    };

    if (!user.withdrawals) user.withdrawals = [];
    user.withdrawals.unshift(wd);
    saveJSON(DB_FILE, users);

    console.log(`💸 WITHDRAWAL REQUEST: ${user.name} — ${amount} ${coin} to ${address}`);
    json(res, 201, { success: true, withdrawal: wd });
  },

  async 'GET /api/withdrawals'(req, res) {
    const user = getSession(req);
    if (!user) return json(res, 401, { error: 'Not authenticated.' });
    json(res, 200, { withdrawals: user.withdrawals || [] });
  },

  // ── TICKETS ──
  async 'POST /api/ticket'(req, res) {
    const { name, email, subject, message } = await readBody(req);
    if (!message) return json(res, 400, { error: 'Message required.' });

    const ticket = {
      id: uid(), name: name || 'Anonymous', email: email || '',
      subject: subject || 'General', message, status: 'open',
      createdAt: new Date().toISOString(),
    };

    // Save to user if logged in
    const user = getSession(req);
    if (user) {
      if (!user.tickets) user.tickets = [];
      user.tickets.unshift(ticket);
    }

    saveJSON(DB_FILE, users);
    console.log(`🎫 TICKET: ${ticket.name} (${ticket.email}) — ${ticket.subject}`);
    json(res, 201, { success: true, ticketId: ticket.id });
  },

  async 'GET /api/tickets'(req, res) {
    const user = getSession(req);
    if (!user) return json(res, 401, { error: 'Not authenticated.' });
    json(res, 200, { tickets: user.tickets || [] });
  },

  // ── BALANCES ──
  async 'GET /api/balances'(req, res) {
    const user = getSession(req);
    if (!user) return json(res, 401, { error: 'Not authenticated.' });
    json(res, 200, { balances: user.balances || { XLM: 0, XRP: 0, USDC: 0, BTC: 0 } });
  },

  // ── TRANSACTIONS ──
  async 'GET /api/transactions'(req, res) {
    const user = getSession(req);
    if (!user) return json(res, 401, { error: 'Not authenticated.' });
    json(res, 200, { transactions: user.transactions || [] });
  },

  // ═══ ADMIN ENDPOINTS ═══

  async 'GET /api/admin/users'(req, res) {
    const adminUsers = users.map(u => ({
      ...safeUser(u),
      hasKycFile: !!u.kycFile,
      ticketCount: (u.tickets || []).length,
      proofCount: (u.depositProofs || []).length,
      withdrawalCount: (u.withdrawals || []).length,
    }));
    json(res, 200, { users: adminUsers });
  },

  async 'GET /api/admin/user-detail'(req, res) {
    const parsed = url.parse(req.url, true);
    const userId = parsed.query.id;
    const user = users.find(u => u.id === userId);
    if (!user) return json(res, 404, { error: 'User not found.' });
    json(res, 200, { user: { ...safeUser(user), tickets: user.tickets, depositProofs: (user.depositProofs||[]).map(p=>({...p,screenshot:null})), withdrawals: user.withdrawals } });
  },

  async 'POST /api/admin/kyc-approve'(req, res) {
    const { userId } = await readBody(req);
    const user = users.find(u => u.id === userId);
    if (!user) return json(res, 404, { error: 'User not found.' });
    user.kycStatus = 'verified';
    user.kycVerifiedAt = new Date().toISOString();
    saveJSON(DB_FILE, users);
    console.log(`✅ KYC APPROVED: ${user.name} (${user.email})`);
    json(res, 200, { success: true });
  },

  async 'POST /api/admin/kyc-reject'(req, res) {
    const { userId } = await readBody(req);
    const user = users.find(u => u.id === userId);
    if (!user) return json(res, 404, { error: 'User not found.' });
    user.kycStatus = 'rejected';
    user.kycFile = null;
    saveJSON(DB_FILE, users);
    json(res, 200, { success: true });
  },

  async 'GET /api/admin/kyc-image'(req, res) {
    const parsed = url.parse(req.url, true);
    const userId = parsed.query.id;
    const user = users.find(u => u.id === userId);
    if (!user || !user.kycFile) return json(res, 404, { error: 'No KYC file.' });
    json(res, 200, { file: user.kycFile, docType: user.kycDocType });
  },

  async 'POST /api/admin/add-funds'(req, res) {
    const { userId, coin, amount, action } = await readBody(req);
    const user = users.find(u => u.id === userId);
    if (!user) return json(res, 404, { error: 'User not found.' });
    if (!user.balances) user.balances = { XLM: 0, XRP: 0, USDC: 0, BTC: 0 };

    const amt = parseFloat(amount) || 0;
    if (action === 'add') user.balances[coin] = (user.balances[coin] || 0) + amt;
    else if (action === 'set') user.balances[coin] = amt;
    else if (action === 'deduct') user.balances[coin] = Math.max(0, (user.balances[coin] || 0) - amt);

    if (!user.transactions) user.transactions = [];
    user.transactions.unshift({
      id: uid(), type: action === 'deduct' ? 'Deduction' : 'Credit',
      coin, amount: amt, date: new Date().toISOString(),
    });

    saveJSON(DB_FILE, users);
    console.log(`💰 FUNDS ${action.toUpperCase()}: ${amt} ${coin} for ${user.name}`);
    json(res, 200, { success: true, balances: user.balances });
  },

  async 'POST /api/admin/approve-proof'(req, res) {
    const { userId, proofId } = await readBody(req);
    const user = users.find(u => u.id === userId);
    if (!user) return json(res, 404, { error: 'User not found.' });

    const proof = (user.depositProofs || []).find(p => p.id === proofId);
    if (!proof) return json(res, 404, { error: 'Proof not found.' });

    proof.status = 'approved';
    proof.approvedAt = new Date().toISOString();

    if (!user.balances) user.balances = { XLM: 0, XRP: 0, USDC: 0, BTC: 0 };
    user.balances[proof.coin] = (user.balances[proof.coin] || 0) + proof.amount;

    if (!user.transactions) user.transactions = [];
    user.transactions.unshift({
      id: uid(), type: 'Deposit Credit', coin: proof.coin,
      amount: proof.amount, date: new Date().toISOString(),
    });

    saveJSON(DB_FILE, users);
    console.log(`✅ PROOF APPROVED: ${proof.amount} ${proof.coin} for ${user.name}`);
    json(res, 200, { success: true });
  },

  async 'POST /api/admin/reject-proof'(req, res) {
    const { userId, proofId } = await readBody(req);
    const user = users.find(u => u.id === userId);
    if (!user) return json(res, 404, { error: 'User not found.' });
    const proof = (user.depositProofs || []).find(p => p.id === proofId);
    if (proof) proof.status = 'rejected';
    saveJSON(DB_FILE, users);
    json(res, 200, { success: true });
  },

  async 'POST /api/admin/approve-withdrawal'(req, res) {
    const { userId, withdrawalId } = await readBody(req);
    const user = users.find(u => u.id === userId);
    if (!user) return json(res, 404, { error: 'User not found.' });

    const wd = (user.withdrawals || []).find(w => w.id === withdrawalId);
    if (!wd) return json(res, 404, { error: 'Withdrawal not found.' });

    wd.status = 'approved';
    if (!user.balances) user.balances = { XLM: 0, XRP: 0, USDC: 0, BTC: 0 };
    user.balances[wd.coin] = Math.max(0, (user.balances[wd.coin] || 0) - wd.amount);

    if (!user.transactions) user.transactions = [];
    user.transactions.unshift({
      id: uid(), type: 'Withdrawal', coin: wd.coin,
      amount: wd.amount, date: new Date().toISOString(),
    });

    saveJSON(DB_FILE, users);
    json(res, 200, { success: true });
  },

  async 'POST /api/admin/reject-withdrawal'(req, res) {
    const { userId, withdrawalId } = await readBody(req);
    const user = users.find(u => u.id === userId);
    if (!user) return json(res, 404, { error: 'User not found.' });
    const wd = (user.withdrawals || []).find(w => w.id === withdrawalId);
    if (wd) wd.status = 'rejected';
    saveJSON(DB_FILE, users);
    json(res, 200, { success: true });
  },

  async 'POST /api/admin/resolve-ticket'(req, res) {
    const { userId, ticketId } = await readBody(req);
    const user = users.find(u => u.id === userId);
    if (!user) return json(res, 404, { error: 'User not found.' });
    const ticket = (user.tickets || []).find(t => t.id === ticketId);
    if (ticket) ticket.status = 'resolved';
    saveJSON(DB_FILE, users);
    json(res, 200, { success: true });
  },

  async 'POST /api/admin/delete-user'(req, res) {
    const { userId } = await readBody(req);
    users = users.filter(u => u.id !== userId);
    saveJSON(DB_FILE, users);
    json(res, 200, { success: true });
  },

  async 'POST /api/forgot-password'(req, res) {
    const { email } = await readBody(req);
    const user = users.find(u => u.email === email?.toLowerCase().trim());
    // Always return success to prevent email enumeration
    console.log(`🔑 PASSWORD RESET REQUEST: ${email} — ${user ? 'USER FOUND' : 'NOT FOUND'}`);
    json(res, 200, { success: true, message: 'If this email exists, a reset link has been sent.' });
  },

  async 'GET /api/status'(req, res) {
    json(res, 200, {
      status: 'operational', version: '7.0.0',
      users: users.length,
      sessions: Object.keys(sessions).length,
    });
  },
};

// ═══════════════════════════════════════
// HTTP SERVER
// ═══════════════════════════════════════

const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  let pathname = parsed.pathname;

  if (req.method === 'OPTIONS') { res.writeHead(204, CORS); res.end(); return; }

  // API routes — try exact match first, then with query string stripped
  const key = `${req.method} ${pathname}`;
  if (routes[key]) {
    try { await routes[key](req, res); } catch (err) {
      console.error('API Error:', err.message);
      json(res, 500, { error: 'Server error.' });
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
  console.log(`\n🚀 NESARA QFS LAB Server v7.0 on port ${PORT}`);
  console.log(`📧 Admin: /admin`);
  console.log(`👥 Users: ${users.length}`);
  console.log(`📂 Data: ${DATA_DIR}`);
});

process.on('SIGTERM', () => { saveJSON(DB_FILE, users); server.close(() => process.exit(0)); });
process.on('SIGINT', () => { saveJSON(DB_FILE, users); server.close(() => process.exit(0)); });
