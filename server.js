/**
 * ═══════════════════════════════════════════════════════════
 * AVIATOR HELA — PRODUCTION SERVER v1.2
 * Node.js + Express + Socket.IO + MongoDB
 * Fixed: Node 22 Sanitize Bug Removed
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

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, {
  cors: { origin: process.env.ALLOWED_ORIGINS || '*', methods: ['GET','POST'] },
  pingTimeout: 60000,
  pingInterval: 25000,
});

/* ────────────────────────────────────────
   ENVIRONMENT CONSTANTS
──────────────────────────────────────── */
const PORT         = process.env.PORT         || 3000;
const MONGO_URI    = process.env.MONGO_URI    || 'mongodb://127.0.0.1:27017/aviator-hela';
const JWT_SECRET   = process.env.JWT_SECRET   || 'change_this_in_production';
const HOUSE_EDGE   = parseFloat(process.env.HOUSE_EDGE) || 0.04;

/* ────────────────────────────────────────
   SECURITY & PARSING MIDDLEWARE
──────────────────────────────────────── */
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors({ origin: process.env.ALLOWED_ORIGINS || '*' }));

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

app.use(express.static(path.join(__dirname, 'public')));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 20,
  message: { error: 'Too many requests. Please wait 15 minutes.' },
});

app.use('/api/register', authLimiter);
app.use('/api/login',    authLimiter);

/* ────────────────────────────────────────
   DATABASE CONNECTION
──────────────────────────────────────── */
mongoose.connect(MONGO_URI, {
  maxPoolSize: 10,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
})
.then(() => console.log('✅ MongoDB connected'))
.catch(err => { console.error('❌ MongoDB error:', err.message); process.exit(1); });

mongoose.connection.on('disconnected', () => console.warn('[DB] Disconnected'));
mongoose.connection.on('reconnected',  () => console.log('[DB] Reconnected'));

/* ────────────────────────────────────────
   SCHEMAS & MODELS
──────────────────────────────────────── */
const UserSchema = new mongoose.Schema({
  phone:        { type: String, required: true, unique: true, trim: true, index: true },
  username:     { type: String, required: true, trim: true },
  password:     { type: String, required: true },
  balance:      { type: Number, default: 0, min: 0 },
  totalDeposit: { type: Number, default: 0 },
  totalBets:    { type: Number, default: 0 },
  totalWins:    { type: Number, default: 0 },
  status:       { type: String, enum: ['active','suspended','banned'], default: 'active' },
  role:         { type: String, enum: ['user','admin'], default: 'user' },
  createdAt:    { type: Date, default: Date.now },
});

const BetSchema = new mongoose.Schema({
  userId:            { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  username:          String,
  betAmount:         { type: Number, required: true, min: 0 },
  cashoutMultiplier: { type: Number, default: 0 },
  winnings:          { type: Number, default: 0 },
  roundId:           { type: String, index: true },
  createdAt:         { type: Date, default: Date.now, index: true },
});

const TransactionSchema = new mongoose.Schema({
  userId:  { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  type:    { type: String, enum: ['DEPOSIT','WITHDRAWAL'], required: true },
  amount:  { type: Number, required: true, min: 0 },
  receipt: { type: String, unique: true, sparse: true },
  status:  { type: String, enum: ['PENDING','COMPLETED','FAILED','REJECTED'], default: 'PENDING' },
  createdAt: { type: Date, default: Date.now, index: true },
});

const RoundSchema = new mongoose.Schema({
  roundId:    { type: Number, unique: true },
  crashPoint: Number,
  serverSeed: String,
  hash:       String,
  createdAt:  { type: Date, default: Date.now },
});

const User        = mongoose.model('User', UserSchema);
const Bet         = mongoose.model('Bet', BetSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const Round       = mongoose.model('Round', RoundSchema);

/* ────────────────────────────────────────
   AUTH HELPERS
──────────────────────────────────────── */
const genToken = (user) => jwt.sign({ id: user._id, phone: user.phone, role: user.role }, JWT_SECRET, { expiresIn: '7d' });

const toLocalPhone = (p) => {
  const n = (p||'').replace(/\D/g,'');
  return n.startsWith('254') ? '0' + n.slice(3) : n;
};

/* ────────────────────────────────────────
   AUTH ROUTES
──────────────────────────────────────── */
app.post('/api/register', async (req, res) => {
  try {
    const { username, phone, password } = req.body;
    if (!phone || !password) return res.status(400).json({ error: 'Phone and password are required.' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });

    const localPhone = toLocalPhone(phone);
    const existing = await User.findOne({ phone: localPhone });
    if (existing) return res.status(400).json({ error: 'Phone number already registered.' });

    const hashed = await bcrypt.hash(password, 12);
    await User.create({
      phone: localPhone,
      username: username || localPhone,
      password: hashed,
    });

    res.status(201).json({ message: 'Registration successful!' });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed.' });
  }
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
    res.json({
      token,
      user: { id: user._id, phone: user.phone, username: user.username, balance: user.balance }
    });
  } catch (err) {
    res.status(500).json({ error: 'Login failed.' });
  }
});

/* ────────────────────────────────────────
   AVIATOR ENGINE
──────────────────────────────────────── */
let gameState        = 'WAITING';
let currentMult      = 1.00;
let targetCrashPoint = 1.00;
let history          = [2.16, 1.15, 4.63, 3.55, 1.18, 12.87, 5.18, 1.12, 4.75];
let roundCounter     = 1000;
let flightTickInterval;
let waitTickInterval;
let activeRoundBets  = {};

const fakeNames = ["Kamau99", "072***12", "079***44", "011***88", "075***01", "Alex**", "Guest_48", "JohnDoe", "Wanjiku*", "Davy_K", "SpribeKing", "BetMaster", "Akinyi*", "User_992", "SammyBoy", "Winner254", "Boss_Man"];
let serverBots = [];

function generateCrashPoint() {
  const seed = crypto.randomBytes(32).toString('hex');
  const h    = parseInt(seed.slice(0,13), 16);
  const e    = Math.pow(2, 52);
  const r    = h / e;
  const cp   = (1 - HOUSE_EDGE) / (1 - r);
  return parseFloat(Math.min(Math.max(1.00, cp), 10000.00).toFixed(2));
}

function generateBots() {
  serverBots = [];
  const count = Math.floor(Math.random() * 8) + 12; 
  for(let i=0; i<count; i++) {
    serverBots.push({
      id: `bot_${i}`,
      name: fakeNames[Math.floor(Math.random() * fakeNames.length)],
      amt: parseFloat((Math.random() * 2000 + 50).toFixed(2)),
      target: Math.random() < 0.6 ? (Math.random() * 2 + 1.01) : (Math.random() * 10 + 1.5),
      cashed: false
    });
  }
}

async function saveRound(roundId, crashPoint, seed) {
  try {
    const hash = crypto.createHash('sha256').update(seed).digest('hex');
    await Round.create({ roundId, crashPoint, serverSeed: seed, hash });
  } catch {}
}

async function processCrashedBets() {
  for (const key of Object.keys(activeRoundBets)) {
    const b = activeRoundBets[key];
    try {
      await Bet.create({
        userId: b.userId, username: b.username, betAmount: b.amount, cashoutMultiplier: 0, winnings: 0, roundId: String(roundCounter),
      });
      await User.findByIdAndUpdate(b.userId, { $inc: { totalBets: 1 } });
    } catch {}
  }
}

function startRound() {
  gameState       = 'WAITING';
  currentMult     = 1.00;
  activeRoundBets = {};
  roundCounter++;

  const seed = crypto.randomBytes(32).toString('hex');
  targetCrashPoint = generateCrashPoint();
  saveRound(roundCounter, targetCrashPoint, seed);

  generateBots();

  io.emit('game_event', { type: 'WAITING', time: 5, history: history.slice(0,15) });
  
  serverBots.forEach(b => {
    io.emit('game_event', { type: 'PLAYER_JOINED', id: b.id, name: b.name, amt: b.amt });
  });

  let timeLeft = 5;
  waitTickInterval = setInterval(() => {
    timeLeft -= 1;
    io.emit('game_event', { type: 'WAIT_TICK', time: Math.max(0, timeLeft) });
  }, 1000);

  setTimeout(() => {
    clearInterval(waitTickInterval);
    if (gameState !== 'WAITING') return;

    gameState = 'FLYING';
    io.emit('game_event', { type: 'FLYING' });
    
    let startTime = Date.now();

    flightTickInterval = setInterval(() => {
      let elapsed = Date.now() - startTime;
      currentMult = Math.max(1.00, Math.pow(Math.E, elapsed / 8000));

      if (currentMult >= targetCrashPoint) {
        clearInterval(flightTickInterval);
        currentMult = parseFloat(targetCrashPoint.toFixed(2));
        gameState   = 'CRASHED';

        history.unshift(currentMult);
        if (history.length > 20) history.pop();

        io.emit('game_event', { type: 'CRASHED', finalMult: currentMult });
        processCrashedBets();

        setTimeout(startRound, 3500);
      } else {
        io.emit('game_event', { type: 'TICK', mult: parseFloat(currentMult.toFixed(2)) });
        
        serverBots.forEach(b => {
          if (!b.cashed && currentMult >= b.target) {
            b.cashed = true;
            const winAmt = (b.amt * currentMult).toFixed(2);
            io.emit('game_event', { 
              type: 'PLAYER_CASHOUT', 
              id: b.id, name: b.name, 
              mult: parseFloat(currentMult.toFixed(2)), 
              winAmt 
            });
          }
        });
      }
    }, 50); 
  }, 5000);
}

/* ────────────────────────────────────────
   SOCKET.IO EVENT HANDLERS
──────────────────────────────────────── */
io.on('connection', (socket) => {
  if (gameState === 'FLYING') {
    socket.emit('game_event', { type: 'FLYING' });
    socket.emit('game_event', { type: 'TICK', mult: currentMult });
  }

  socket.on('placeBet', async (data) => {
    if (gameState !== 'WAITING') return socket.emit('error', 'Wait for the next round to start.');
    try {
      const identifier = data.username || data.phone;
      const amount     = parseFloat(data.amount);

      if (!identifier || isNaN(amount) || amount < 10) return socket.emit('error', 'Invalid bet amount.');

      const user = await User.findOneAndUpdate(
          { $or: [{ phone: identifier }, { username: identifier }], status: 'active', balance: { $gte: amount } },
          { $inc: { balance: -amount } },
          { new: true }
      );
      if (!user) return socket.emit('error', 'Insufficient balance.');

      const betIndex = data.betIndex !== undefined ? parseInt(data.betIndex) : 0;
      const betKey   = `${socket.id}_${betIndex}`;
      activeRoundBets[betKey] = { userId: user._id, username: user.phone, amount, betIndex };

      socket.emit('betConfirmed', { newBalance: user.balance, betIndex });
      
      io.emit('game_event', { 
        type: 'PLAYER_JOINED', 
        id: socket.id, 
        name: user.phone.slice(0,4)+'***', 
        amt: amount 
      });
    } catch (err) { socket.emit('error', 'Bet failed.'); }
  });

  socket.on('cashOut', async (data) => {
    const betIndex = data?.betIndex !== undefined ? parseInt(data.betIndex) : 0;
    const betKey   = `${socket.id}_${betIndex}`;

    if (gameState !== 'FLYING') return socket.emit('error', 'Can only cash out while flying.');
    if (!activeRoundBets[betKey]) return socket.emit('error', 'No active bet found.');

    try {
      const bet      = activeRoundBets[betKey];
      const multi    = parseFloat(currentMult.toFixed(2));
      const winnings = parseFloat((bet.amount * multi).toFixed(2));

      delete activeRoundBets[betKey];

      const user = await User.findByIdAndUpdate(
          bet.userId, 
          { $inc: { balance: winnings, totalBets: 1, totalWins: winnings } }, 
          { new: true }
      );

      await Bet.create({
        userId: user._id, username: user.phone, betAmount: bet.amount, cashoutMultiplier: multi, winnings, roundId: String(roundCounter),
      });

      socket.emit('cashOutSuccess', { betIndex, multiplier: multi.toFixed(2), winnings: winnings.toFixed(2), newBalance: user.balance.toFixed(2) });
      
      io.emit('game_event', { 
        type: 'PLAYER_CASHOUT', 
        id: socket.id, 
        name: user.phone.slice(0,4)+'***', 
        mult: multi, 
        winAmt: winnings.toFixed(2) 
      });
    } catch (err) { socket.emit('error', 'Cashout failed.'); }
  });
});

/* ────────────────────────────────────────
   SERVER STARTUP
──────────────────────────────────────── */
server.listen(PORT, () => {
  console.log(`🚀 AviatorHela Server running on port ${PORT}`);
  startRound();
});