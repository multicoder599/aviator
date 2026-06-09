/**
 * ═══════════════════════════════════════════════════════════
 * AVIATOR HELA — PRODUCTION SERVER v2.2
 * Fixed: Telegram Multiplier Display, Throttled Frequency, 50% Margin
 * ═══════════════════════════════════════════════════════════
 */

'use strict';

const express       = require('express');
const http          = require('http');
const { Server }    = require('socket.io');
const path          = require('path');
const mongoose      = require('mongoose');
const bcrypt        = require('bcryptjs');
const jwt           = require('jsonwebtoken');
const cors          = require('cors');
const crypto        = require('crypto');
const rateLimit     = require('express-rate-limit');
const helmet        = require('helmet');
require('dotenv').config();

let sharp;
try { sharp = require('sharp'); } catch(e) { console.warn('⚠️ sharp not installed. Run: npm install sharp'); }

const app    = express();
const server = http.createServer(app);

const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '8667539105:AAHbGcsG-1h0zagrXcHsfu-c2zSGz5BQ-c4';
const TELEGRAM_CHAT_ID   = process.env.TELEGRAM_CHAT_ID   || '5475481064';
const MEGAPAY_BASE       = process.env.MEGAPAY_BASE       || 'https://megapay.co.ke/backend/v1';
const MEGAPAY_API_KEY    = process.env.MEGAPAY_API_KEY    || '';

const allowedOrigins = [
  'https://aviatorhela.com', 'https://www.aviatorhela.com', 'https://api.aviatorhela.com',
  'http://localhost:3000', 'http://127.0.0.1:5500'
];

const io = new Server(server, {
  cors: { origin: allowedOrigins, methods: ['GET','POST'], credentials: true },
  pingTimeout: 60000, pingInterval: 25000,
});

const PORT = process.env.PORT || 3005;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/aviator-hela';
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_in_production';
const HOUSE_EDGE = parseFloat(process.env.HOUSE_EDGE) || 0.04;
const WITHDRAW_FEE = 200;

app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors({ origin: allowedOrigins, methods: ['GET','POST','PUT','DELETE'], credentials: true }));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: { error: 'Too many requests. Please wait 15 minutes.' } });
app.use('/api/register', authLimiter);
app.use('/api/login', authLimiter);

mongoose.connect(MONGO_URI, { maxPoolSize: 10, serverSelectionTimeoutMS: 5000, socketTimeoutMS: 45000 })
.then(() => console.log('✅ MongoDB connected'))
.catch(err => { console.error('❌ MongoDB error:', err.message); process.exit(1); });

mongoose.connection.on('disconnected', () => console.warn('[DB] Disconnected'));
mongoose.connection.on('reconnected', () => console.log('[DB] Reconnected'));

const UserSchema = new mongoose.Schema({
  phone: { type: String, required: true, unique: true, trim: true, index: true },
  username: { type: String, required: true, trim: true },
  password: { type: String, required: true },
  balance: { type: Number, default: 0, min: 0 },
  totalDeposit: { type: Number, default: 0 },
  totalBets: { type: Number, default: 0 },
  totalWins: { type: Number, default: 0 },
  status: { type: String, enum: ['active','suspended','banned'], default: 'active' },
  role: { type: String, enum: ['user','admin'], default: 'user' },
  createdAt: { type: Date, default: Date.now },
});

const BetSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  username: String,
  betAmount: { type: Number, required: true, min: 0 },
  cashoutMultiplier: { type: Number, default: 0 },
  winnings: { type: Number, default: 0 },
  roundId: { type: String, index: true },
  createdAt: { type: Date, default: Date.now, index: true },
});

const TransactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  type: { type: String, enum: ['DEPOSIT','WITHDRAWAL'], required: true },
  amount: { type: Number, required: true, min: 0 },
  fee: { type: Number, default: 0 },
  receipt: { type: String, unique: true, sparse: true },
  status: { type: String, enum: ['PENDING','COMPLETED','FAILED','REJECTED'], default: 'PENDING' },
  providerRef: { type: String, sparse: true },
  createdAt: { type: Date, default: Date.now, index: true },
});

const RoundSchema = new mongoose.Schema({
  roundId: { type: Number, unique: true },
  crashPoint: Number,
  serverSeed: String,
  hash: String,
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model('User', UserSchema);
const Bet = mongoose.model('Bet', BetSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const Round = mongoose.model('Round', RoundSchema);

const genToken = (user) => jwt.sign({ id: user._id, phone: user.phone, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
const toLocalPhone = (p) => { const n = (p||'').replace(/\D/g,''); return n.startsWith('254') ? '0' + n.slice(3) : n; };
const toInternationalPhone = (p) => { const n = (p||'').replace(/\D/g,''); return n.startsWith('0') ? '254' + n.slice(1) : n; };

const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized. Token missing.' });
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user || user.status !== 'active') return res.status(403).json({ error: 'Account not active.' });
    req.user = user; next();
  } catch (err) { return res.status(401).json({ error: 'Invalid or expired token.' }); }
};

app.post('/api/register', async (req, res) => {
  try {
    const { username, phone, password } = req.body;
    if (!phone || !password) return res.status(400).json({ error: 'Phone and password are required.' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
    const localPhone = toLocalPhone(phone);
    const existing = await User.findOne({ phone: localPhone });
    if (existing) return res.status(400).json({ error: 'Phone number already registered.' });
    const hashed = await bcrypt.hash(password, 12);
    const user = await User.create({ phone: localPhone, username: username || 'Player_' + localPhone.slice(-4), password: hashed });
    const token = genToken(user);
    res.status(201).json({ message: 'Registration successful!', token, user: { id: user._id, phone: user.phone, username: user.username, balance: user.balance } });
  } catch (err) { console.error('Register error:', err); res.status(500).json({ error: 'Registration failed.' }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    if (!phone || !password) return res.status(400).json({ error: 'Phone and password required.' });
    const localPhone = toLocalPhone(phone);
    const user = await User.findOne({ phone: localPhone });
    if (!user) return res.status(400).json({ error: 'Invalid credentials.' });
    if (user.status !== 'active') return res.status(403).json({ error: 'Account not active.' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'Invalid credentials.' });
    const token = genToken(user);
    res.json({ token, user: { id: user._id, phone: user.phone, username: user.username, balance: user.balance, totalBets: user.totalBets, totalWins: user.totalWins, totalDeposit: user.totalDeposit } });
  } catch (err) { console.error('Login error:', err); res.status(500).json({ error: 'Login failed.' }); }
});

app.get('/api/me', authenticate, async (req, res) => {
  try {
    const user = req.user;
    res.json({ id: user._id, phone: user.phone, username: user.username, balance: user.balance, totalBets: user.totalBets, totalWins: user.totalWins, totalDeposit: user.totalDeposit, createdAt: user.createdAt });
  } catch (err) { res.status(500).json({ error: 'Failed to fetch user.' }); }
});

app.post('/api/deposit/initiate', authenticate, async (req, res) => {
  try {
    const { amount } = req.body;
    const amt = parseFloat(amount);
    if (isNaN(amt) || amt < 100) return res.status(400).json({ error: 'Minimum deposit is 100 KES.' });
    const user = req.user;
    const phone = toInternationalPhone(user.phone);
    const receipt = 'DEP-' + crypto.randomBytes(6).toString('hex').toUpperCase();
    const tx = await Transaction.create({ userId: user._id, type: 'DEPOSIT', amount: amt, fee: 0, status: 'PENDING', receipt });
    try {
      const mpResp = await fetch(`${MEGAPAY_BASE}/initiatestk`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${MEGAPAY_API_KEY}` },
        body: JSON.stringify({ amount: amt, phone: phone, reference: receipt, callback_url: `https://api.aviatorhela.com/api/callback/megapay`, description: `AviatorHela deposit for ${user.username}` })
      });
      const mpData = await mpResp.json();
      if (!mpResp.ok) throw new Error(mpData.message || 'Megapay rejected request');
      if (mpData.checkout_request_id || mpData.transaction_id) { tx.providerRef = mpData.checkout_request_id || mpData.transaction_id; await tx.save(); }
      res.json({ success: true, message: 'STK push sent to your phone. Enter M-Pesa PIN to complete.', receipt, providerRef: tx.providerRef, pollUrl: `/api/deposit/status?receipt=${receipt}` });
    } catch (mpErr) {
      console.error('Megapay initiate error:', mpErr.message);
      tx.status = 'FAILED'; await tx.save();
      user.balance += amt; user.totalDeposit += amt; await user.save();
      tx.status = 'COMPLETED'; await tx.save();
      return res.json({ success: true, newBalance: user.balance, message: `Deposit of ${amt.toFixed(2)} KES completed (fallback mode).`, receipt });
    }
  } catch (err) { console.error('Deposit initiate error:', err); res.status(500).json({ error: 'Deposit processing failed.' }); }
});

app.get('/api/deposit/status', authenticate, async (req, res) => {
  try {
    const { receipt } = req.query;
    const tx = await Transaction.findOne({ receipt, userId: req.user._id });
    if (!tx) return res.status(404).json({ error: 'Transaction not found.' });
    if (tx.status === 'PENDING' && tx.providerRef) {
      try {
        const mpResp = await fetch(`${MEGAPAY_BASE}/transactionstatus`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${MEGAPAY_API_KEY}` },
          body: JSON.stringify({ transaction_id: tx.providerRef })
        });
        const mpData = await mpResp.json();
        if (mpData.status === 'SUCCESS' || mpData.result_code === '0') {
          tx.status = 'COMPLETED'; await tx.save();
          req.user.balance += tx.amount; req.user.totalDeposit += tx.amount; await req.user.save();
        } else if (mpData.status === 'FAILED' || mpData.result_code === '1') { tx.status = 'FAILED'; await tx.save(); }
      } catch(e) {}
    }
    res.json({ status: tx.status, amount: tx.amount, receipt: tx.receipt, newBalance: req.user.balance });
  } catch (err) { res.status(500).json({ error: 'Status check failed.' }); }
});

app.post('/api/callback/megapay', async (req, res) => {
  try {
    const { reference, result_code, transaction_id } = req.body;
    if (!reference) return res.status(400).json({ error: 'Missing reference' });
    const tx = await Transaction.findOne({ receipt: reference });
    if (!tx) return res.status(404).json({ error: 'Transaction not found' });
    if (result_code === '0' || result_code === 0) {
      if (tx.status !== 'COMPLETED') {
        tx.status = 'COMPLETED'; tx.providerRef = transaction_id || tx.providerRef; await tx.save();
        const user = await User.findById(tx.userId);
        if (user) { user.balance += tx.amount; user.totalDeposit += tx.amount; await user.save(); }
      }
    } else { tx.status = 'FAILED'; await tx.save(); }
    res.json({ received: true });
  } catch (err) { console.error('Callback error:', err); res.status(500).json({ error: 'Callback processing failed' }); }
});

app.post('/api/withdraw', authenticate, async (req, res) => {
  try {
    const { amount } = req.body;
    const amt = parseFloat(amount);
    if (isNaN(amt) || amt < 500) return res.status(400).json({ error: 'Minimum withdrawal is 500 KES.' });
    const totalCharge = amt + WITHDRAW_FEE;
    const user = req.user;
    if (user.balance < totalCharge) return res.status(400).json({ error: `Insufficient balance. You need ${totalCharge.toFixed(2)} KES (includes 200 KES processing fee).` });
    user.balance -= totalCharge; await user.save();
    await Transaction.create({ userId: user._id, type: 'WITHDRAWAL', amount: amt, fee: WITHDRAW_FEE, status: 'PENDING', receipt: 'WIT-' + crypto.randomBytes(6).toString('hex').toUpperCase() });
    res.json({ success: true, newBalance: user.balance, message: `Withdrawal of ${amt.toFixed(2)} KES initiated. 200 KES fee deducted.` });
  } catch (err) { console.error('Withdraw error:', err); res.status(500).json({ error: 'Withdrawal processing failed.' }); }
});

app.get('/api/transactions', authenticate, async (req, res) => {
  try { const txs = await Transaction.find({ userId: req.user._id }).sort({ createdAt: -1 }).limit(50); res.json(txs); }
  catch (err) { res.status(500).json({ error: 'Failed to fetch transactions.' }); }
});

/* ────────────────────────────────────────
   AVIATOR ENGINE — 50% WIN / 50% LOSS
──────────────────────────────────────── */
let gameState = 'WAITING';
let currentMult = 1.00;
let targetCrashPoint = 1.00;
let history = [2.16, 1.15, 4.63, 3.55, 1.18, 12.87, 5.18, 1.12, 4.75, 1.05, 1.33, 8.44, 1.22, 1.88, 3.21];
let roundCounter = 1000;
let flightTickInterval;
let waitTickInterval;
let activeRoundBets = {};
let roundStartTime = Date.now();
let telegramSkipCounter = 0;
let telegramSendEvery = 4; // Send every 4th round (adjustable)

const fakeNames = ["Kamau99","072***12","079***44","011***88","075***01","Alex**","Guest_48","JohnDoe","Wanjiku*","Davy_K","SpribeKing","BetMaster","Akinyi*","User_992","SammyBoy","Winner254","Boss_Man","Msoo_Ke","LuckyOne","Punter_7"];
let serverBots = [];

(async function initRoundCounter() {
  try {
    const lastRound = await Round.findOne().sort({ roundId: -1 });
    if (lastRound && lastRound.roundId >= roundCounter) { roundCounter = lastRound.roundId + 1; console.log(`[Engine] Resumed round counter at ${roundCounter}`); }
  } catch(e) { console.error('[Engine] Failed to init round counter:', e.message); }
})();

function generateCrashPoint() {
  const rand = Math.random();
  // 50% of rounds crash early (1.00 - 1.80x) → House wins
  // 50% of rounds go high (2.00x+) → Players can win
  if (rand < 0.50) {
    const early = 1.00 + (Math.random() * 0.80);
    return parseFloat(early.toFixed(2));
  } else {
    const seed = crypto.randomBytes(32).toString('hex');
    const h = parseInt(seed.slice(0,13), 16);
    const e = Math.pow(2, 52);
    const r = h / e;
    const cp = (1 - HOUSE_EDGE) / (1 - r);
    return parseFloat(Math.min(Math.max(2.00, cp), 10000.00).toFixed(2));
  }
}

function generateBots() {
  serverBots = [];
  const count = Math.floor(Math.random() * 10) + 15;
  for(let i=0; i<count; i++) {
    serverBots.push({
      id: `bot_${i}_${Date.now()}`,
      name: fakeNames[Math.floor(Math.random() * fakeNames.length)],
      amt: parseFloat((Math.random() * 2500 + 50).toFixed(2)),
      target: Math.random() < 0.65 ? (Math.random() * 1.5 + 1.05) : (Math.random() * 8 + 2.0),
      cashed: false
    });
  }
}

async function saveRound(roundId, crashPoint, seed) {
  try {
    const hash = crypto.createHash('sha256').update(seed).digest('hex');
    await Round.create({ roundId, crashPoint, serverSeed: seed, hash });
  } catch(e) {
    if (e.code === 11000) console.warn(`[Round] Duplicate roundId ${roundId} skipped.`);
    else console.error('Save round error:', e.message);
  }
}

async function processCrashedBets() {
  for (const key of Object.keys(activeRoundBets)) {
    const b = activeRoundBets[key];
    try {
      await Bet.create({ userId: b.userId, username: b.username, betAmount: b.amount, cashoutMultiplier: 0, winnings: 0, roundId: String(roundCounter) });
      await User.findByIdAndUpdate(b.userId, { $inc: { totalBets: 1 } });
    } catch(e) {}
  }
}

/* ────────────────────────────────────────
   TELEGRAM MULTIPLIER IMAGE
──────────────────────────────────────── */
function generateMultiplierSVG(multiplier) {
  const isHigh = multiplier >= 2.0;
  const color = isHigh ? '#28a909' : '#e50b24';
  const glowColor = isHigh ? 'rgba(40,169,9,0.4)' : 'rgba(229,11,36,0.4)';
  const date = new Date().toLocaleString('en-KE', { timeZone: 'Africa/Nairobi', hour12: false });

  return `<svg xmlns="http://www.w3.org/2000/svg" width="600" height="340" viewBox="0 0 600 340">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#0a0a0f;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#1a0a0f;stop-opacity:1" />
    </linearGradient>
    <filter id="glow">
      <feGaussianBlur stdDeviation="4" result="coloredBlur"/>
      <feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
    <filter id="textGlow">
      <feGaussianBlur stdDeviation="3" result="blur"/>
      <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
  </defs>
  <rect width="600" height="340" fill="url(#bg)" rx="20" ry="20"/>
  <rect x="14" y="14" width="572" height="312" fill="none" stroke="${color}" stroke-width="3" rx="16" ry="16" opacity="0.5"/>

  <!-- Top Brand -->
  <text x="300" y="55" font-family="Arial Black, Arial, sans-serif" font-size="22" font-weight="900" fill="#ffffff" text-anchor="middle" letter-spacing="4">AVIATOR HELA</text>
  <text x="300" y="82" font-family="Arial, sans-serif" font-size="12" fill="#666" text-anchor="middle" letter-spacing="2">KENYA'S MOST TRUSTED CRASH GAME</text>

  <!-- Divider -->
  <line x1="60" y1="100" x2="540" y2="100" stroke="#333" stroke-width="1"/>

  <!-- Label -->
  <text x="300" y="140" font-family="Arial, sans-serif" font-size="16" font-weight="700" fill="#888" text-anchor="middle" letter-spacing="3">NEXT ROUND MULTIPLIER</text>

  <!-- Main Multiplier -->
  <text x="300" y="230" font-family="Arial Black, Arial, sans-serif" font-size="90" font-weight="900" fill="${color}" text-anchor="middle" filter="url(#textGlow)" letter-spacing="-2">x${multiplier}</text>

  <!-- Indicator -->
  <rect x="220" y="250" width="160" height="36" rx="18" fill="${color}" opacity="0.15" stroke="${color}" stroke-width="1"/>
  <text x="300" y="274" font-family="Arial, sans-serif" font-size="14" font-weight="700" fill="${color}" text-anchor="middle">${isHigh ? '🔥 HIGH POTENTIAL' : '⚡ PLAY NOW'}</text>

  <!-- Footer -->
  <text x="300" y="310" font-family="monospace" font-size="11" fill="#444" text-anchor="middle">${date} EAT • aviatorhela.com</text>
</svg>`;
}

async function sendTelegramMultiplierImage(multiplier) {
  try {
    const svg = generateMultiplierSVG(multiplier);
    let imageBuffer;
    let filename;

    if (sharp) {
      imageBuffer = await sharp(Buffer.from(svg), { density: 144 }).png({ compressionLevel: 9 }).toBuffer();
      filename = `aviator-next-x${multiplier}.png`;
    } else {
      console.warn('[Telegram] sharp not available, sending text fallback.');
      await sendTelegramMultiplierText(multiplier);
      return;
    }

    const boundary = '----FormBoundary' + crypto.randomBytes(16).toString('hex');
    const caption = `🎰 <b>AviatorHela Next Round</b>\n📈 Multiplier: <code>x${multiplier}</code>\n🔥 Don't miss out — play now!\n📲 <a href="https://aviatorhela.com">aviatorhela.com</a>`;

    const pre = Buffer.from(
      `--${boundary}\r\nContent-Disposition: form-data; name="chat_id"\r\n\r\n${TELEGRAM_CHAT_ID}\r\n` +
      `--${boundary}\r\nContent-Disposition: form-data; name="caption"\r\n\r\n${caption}\r\n` +
      `--${boundary}\r\nContent-Disposition: form-data; name="parse_mode"\r\n\r\nHTML\r\n` +
      `--${boundary}\r\nContent-Disposition: form-data; name="photo"; filename="${filename}"\r\nContent-Type: image/png\r\n\r\n`
    );
    const post = Buffer.from(`\r\n--${boundary}--\r\n`);
    const body = Buffer.concat([pre, imageBuffer, post]);

    const resp = await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendPhoto`, {
      method: 'POST',
      headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` },
      body: body
    });
    const data = await resp.json();
    if (!data.ok) console.error('[Telegram] API error:', data.description);
    else console.log(`[Telegram] Multiplier image x${multiplier} sent`);
  } catch (e) {
    console.error('[Telegram] Send failed:', e.message);
    await sendTelegramMultiplierText(multiplier);
  }
}

async function sendTelegramMultiplierText(multiplier) {
  try {
    const text = `🎰 <b>AviatorHela Next Round</b>\n\n📈 Next Round: <code>x${multiplier}</code>\n🔥 Play now at aviatorhela.com`;
    await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: TELEGRAM_CHAT_ID, text, parse_mode: 'HTML', disable_web_page_preview: true })
    });
  } catch(e) { console.error('[Telegram] Text fallback failed:', e.message); }
}

/* ────────────────────────────────────────
   ROUND MANAGER
──────────────────────────────────────── */
function startRound() {
  gameState = 'WAITING';
  currentMult = 1.00;
  activeRoundBets = {};
  roundCounter++;
  roundStartTime = Date.now();

  const seed = crypto.randomBytes(32).toString('hex');
  targetCrashPoint = generateCrashPoint();
  saveRound(roundCounter, targetCrashPoint, seed);

  // Throttled Telegram: send every N rounds with some randomness
  telegramSkipCounter++;
  if (telegramSkipCounter >= telegramSendEvery) {
    telegramSkipCounter = 0;
    // Add randomness: 50% chance to actually send when counter hits, so avg every 6-8 rounds
    if (Math.random() < 0.6) {
      sendTelegramMultiplierImage(targetCrashPoint);
    }
  }

  generateBots();
  io.emit('game_event', { type: 'WAITING', time: 5, history: history.slice(0,20), roundId: roundCounter });
  serverBots.forEach(b => { io.emit('game_event', { type: 'PLAYER_JOINED', id: b.id, name: b.name, amt: b.amt }); });

  let timeLeft = 5;
  waitTickInterval = setInterval(() => {
    timeLeft -= 1;
    io.emit('game_event', { type: 'WAIT_TICK', time: Math.max(0, timeLeft) });
  }, 1000);

  setTimeout(() => {
    clearInterval(waitTickInterval);
    if (gameState !== 'WAITING') return;
    gameState = 'FLYING';
    io.emit('game_event', { type: 'FLYING', roundId: roundCounter });
    let startTime = Date.now();

    flightTickInterval = setInterval(() => {
      let elapsed = Date.now() - startTime;
      currentMult = Math.max(1.00, Math.pow(Math.E, elapsed / 8000));
      if (currentMult >= targetCrashPoint) {
        clearInterval(flightTickInterval);
        currentMult = parseFloat(targetCrashPoint.toFixed(2));
        gameState = 'CRASHED';
        history.unshift(currentMult);
        if (history.length > 25) history.pop();
        io.emit('game_event', { type: 'CRASHED', finalMult: currentMult, roundId: roundCounter });
        processCrashedBets();
        setTimeout(startRound, 4000);
      } else {
        io.emit('game_event', { type: 'TICK', mult: parseFloat(currentMult.toFixed(2)), elapsed });
        serverBots.forEach(b => {
          if (!b.cashed && currentMult >= b.target) {
            b.cashed = true;
            const winAmt = (b.amt * currentMult).toFixed(2);
            io.emit('game_event', { type: 'PLAYER_CASHOUT', id: b.id, name: b.name, mult: parseFloat(currentMult.toFixed(2)), winAmt });
          }
        });
      }
    }, 50);
  }, 5000);
}

/* ────────────────────────────────────────
   SOCKET.IO HANDLERS
──────────────────────────────────────── */
io.on('connection', (socket) => {
  console.log(`[Socket] Client connected: ${socket.id}`);
  if (gameState === 'FLYING') {
    socket.emit('game_event', { type: 'FLYING', roundId: roundCounter });
    socket.emit('game_event', { type: 'TICK', mult: currentMult });
  } else if (gameState === 'WAITING') {
    socket.emit('game_event', { type: 'WAITING', time: 5, history: history.slice(0,20), roundId: roundCounter });
  }

  socket.on('placeBet', async (data) => {
    if (gameState !== 'WAITING') return socket.emit('error', 'Wait for the next round to start.');
    try {
      const identifier = data.username || data.phone;
      const amount = parseFloat(data.amount);
      const betIndex = data.betIndex !== undefined ? parseInt(data.betIndex) : 0;
      if (!identifier || isNaN(amount) || amount < 10) return socket.emit('error', 'Invalid bet amount. Minimum 10 KES.');
      const user = await User.findOneAndUpdate(
        { $or: [{ phone: identifier }, { username: identifier }], status: 'active', balance: { $gte: amount } },
        { $inc: { balance: -amount } }, { new: true }
      );
      if (!user) return socket.emit('error', 'Insufficient balance.');
      const betKey = `${socket.id}_${betIndex}`;
      activeRoundBets[betKey] = { userId: user._id, username: user.phone, amount, betIndex };
      socket.emit('betConfirmed', { newBalance: user.balance, betIndex, amount });
      io.emit('game_event', { type: 'PLAYER_JOINED', id: socket.id, name: user.phone.slice(0,4)+'***', amt: amount });
    } catch (err) { socket.emit('error', 'Bet failed. Please retry.'); }
  });

  socket.on('cashOut', async (data) => {
    const betIndex = data?.betIndex !== undefined ? parseInt(data.betIndex) : 0;
    const betKey = `${socket.id}_${betIndex}`;
    if (gameState !== 'FLYING') return socket.emit('error', 'Can only cash out while flying.');
    if (!activeRoundBets[betKey]) return socket.emit('error', 'No active bet found.');
    try {
      const bet = activeRoundBets[betKey];
      const multi = parseFloat(currentMult.toFixed(2));
      const winnings = parseFloat((bet.amount * multi).toFixed(2));
      delete activeRoundBets[betKey];
      const user = await User.findByIdAndUpdate(bet.userId, { $inc: { balance: winnings, totalBets: 1, totalWins: winnings } }, { new: true });
      await Bet.create({ userId: user._id, username: user.phone, betAmount: bet.amount, cashoutMultiplier: multi, winnings, roundId: String(roundCounter) });
      socket.emit('cashOutSuccess', { betIndex, multiplier: multi.toFixed(2), winnings: winnings.toFixed(2), newBalance: user.balance.toFixed(2) });
      io.emit('game_event', { type: 'PLAYER_CASHOUT', id: socket.id, name: user.phone.slice(0,4)+'***', mult: multi, winAmt: winnings.toFixed(2) });
    } catch (err) { socket.emit('error', 'Cashout failed. Please retry.'); }
  });

  socket.on('disconnect', () => { console.log(`[Socket] Client disconnected: ${socket.id}`); });
});

server.listen(PORT, () => {
  console.log(`🚀 AviatorHela Server running on port ${PORT}`);
  console.log(`📡 Telegram Bot: ${TELEGRAM_BOT_TOKEN ? 'Active' : 'Inactive'}`);
  console.log(`💰 Megapay: ${MEGAPAY_API_KEY ? 'Configured' : 'Missing API Key'}`);
  startRound();
});