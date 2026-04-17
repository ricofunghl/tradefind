const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const initSqlJs = require('sql.js');

const PORT = 3001;
const JWT_SECRET = 'tradefind-dev-secret';
const DB_PATH = path.join(__dirname, 'tradefind.db');

const app = express();

// ── Middleware ──
app.use(cors({ origin: 'http://localhost:3000', credentials: true }));
app.use(express.json({ limit: '20mb' }));

// Uploads directory
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
app.use('/uploads', express.static(uploadsDir));

// ── Helpers ──
function uid() { return Date.now().toString(36) + Math.random().toString(36).slice(2, 6); }
function makeToken(user) {
  return jwt.sign({ userId: user.id, name: user.name, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
}

// ── Multer storage ──
const storage = multer.diskStorage({
  destination: uploadsDir,
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, uid() + ext);
  },
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

// ── Auth middleware ──
function authRequired(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function optionalAuth(req, res, next) {
  const header = req.headers.authorization;
  if (header && header.startsWith('Bearer ')) {
    try { req.user = jwt.verify(header.slice(7), JWT_SECRET); } catch {}
  }
  next();
}

// ── Database wrapper ──
let db;

function saveDb() {
  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

function dbRun(sql, params = []) {
  db.run(sql, params);
  saveDb();
}

function dbGet(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  if (stmt.step()) {
    const row = stmt.getAsObject();
    stmt.free();
    return row;
  }
  stmt.free();
  return null;
}

function dbAll(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function dbExec(sql) {
  db.run(sql);
  saveDb();
}

// ── Format helpers ──
function formatContractor(c, reviews) {
  return {
    id: c.id, name: c.name, trade: c.trade, location: c.location,
    bio: c.bio || '', phone: c.phone || '', email: c.email || '',
    rating: c.rating || 0, reviewCount: c.review_count || 0,
    verified: c.verified === 1 || c.verified === true,
    badge: c.badge || null, postedAt: c.posted_at,
    reviews: reviews.map(r => ({
      id: r.id, author: r.author, rating: r.rating, text: r.text,
      helpful: r.helpful || 0, postedAt: r.posted_at,
      helpfulVoters: JSON.parse(r.helpful_voters || '[]'),
    })),
  };
}

function formatJob(j) {
  const quotes = dbAll('SELECT * FROM quotes WHERE job_id = ? ORDER BY posted_at ASC', [j.id]);
  return {
    id: j.id, title: j.title, trade: j.trade, location: j.location,
    description: j.description || '', budget: j.budget || '', urgency: j.urgency || 'flexible',
    customerName: j.customer_name, customerId: j.customer_id || null,
    photos: JSON.parse(j.photos || '[]'),
    status: j.status, hiredQuoteId: j.hired_quote_id || null, postedAt: j.posted_at,
    quotes: quotes.map(q => ({
      id: q.id, contractorId: q.contractor_id, contractorName: q.contractor_name,
      price: q.price, eta: q.eta || '', message: q.message || '',
      rating: q.rating || null, postedAt: q.posted_at,
    })),
  };
}

// ═══════════════════════════════════
//  SCHEMA
// ═══════════════════════════════════
function initSchema() {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT,
      provider TEXT DEFAULT 'email',
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS contractors (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      name TEXT NOT NULL,
      trade TEXT NOT NULL,
      location TEXT NOT NULL,
      bio TEXT DEFAULT '',
      phone TEXT DEFAULT '',
      email TEXT DEFAULT '',
      rating REAL DEFAULT 0,
      review_count INTEGER DEFAULT 0,
      verified INTEGER DEFAULT 0,
      badge TEXT,
      posted_at TEXT DEFAULT (datetime('now'))
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS reviews (
      id TEXT PRIMARY KEY,
      contractor_id TEXT NOT NULL,
      author TEXT NOT NULL,
      author_id TEXT,
      rating REAL NOT NULL,
      text TEXT NOT NULL,
      helpful INTEGER DEFAULT 0,
      helpful_voters TEXT DEFAULT '[]',
      posted_at TEXT DEFAULT (datetime('now'))
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS jobs (
      id TEXT PRIMARY KEY,
      customer_id TEXT,
      customer_name TEXT NOT NULL,
      title TEXT NOT NULL,
      trade TEXT NOT NULL,
      location TEXT NOT NULL,
      description TEXT DEFAULT '',
      budget TEXT DEFAULT '',
      urgency TEXT DEFAULT 'flexible',
      photos TEXT DEFAULT '[]',
      status TEXT DEFAULT 'open',
      hired_quote_id TEXT,
      posted_at TEXT DEFAULT (datetime('now'))
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS quotes (
      id TEXT PRIMARY KEY,
      job_id TEXT NOT NULL,
      contractor_id TEXT DEFAULT 'ext',
      contractor_name TEXT NOT NULL,
      price REAL NOT NULL,
      eta TEXT DEFAULT '',
      message TEXT DEFAULT '',
      rating REAL,
      posted_at TEXT DEFAULT (datetime('now'))
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS notifications (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      type TEXT DEFAULT 'info',
      title TEXT,
      body TEXT,
      job_id TEXT,
      read INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);
  saveDb();
}

// ═══════════════════════════════════
//  SEED DATA
// ═══════════════════════════════════
function seedData() {
  const existing = dbGet('SELECT COUNT(*) as cnt FROM contractors');
  if (existing && existing.cnt > 0) return;

  const now = new Date();
  const postedAt = new Date(now.getTime() - 30 * 24 * 3600 * 1000).toISOString();
  const reviewAt = new Date(now.getTime() - 10 * 24 * 3600 * 1000).toISOString();
  const jobAt = new Date(now.getTime() - 2 * 24 * 3600 * 1000).toISOString();

  const seedContractors = [
    { id: 'seed1', name: 'Blue River Plumbing', trade: 'plumber', location: 'Sydney',
      bio: 'Fully licensed plumbers with 15+ years experience. We handle everything from leaky taps to full bathroom renovations. Available 24/7 for emergencies.',
      phone: '0412 345 678', email: 'info@blueriverplumbing.com', rating: 4.8, review_count: 2, verified: 1 },
    { id: 'seed2', name: 'Watts Electrical Services', trade: 'electrician', location: 'Melbourne',
      bio: 'Master electricians servicing residential and commercial properties. Specialising in switchboard upgrades, solar installations, and EV charger fitting.',
      phone: '0423 456 789', email: 'hello@wattselectrical.com.au', rating: 4.9, review_count: 2, verified: 1 },
    { id: 'seed3', name: 'Summit Builders', trade: 'builder', location: 'Brisbane',
      bio: 'Award-winning builders transforming homes for over 20 years. Kitchen renovations, bathroom makeovers, extensions, and new builds. Quality craftsmanship guaranteed.',
      phone: '0434 567 890', email: 'build@summitbuilders.com', rating: 4.7, review_count: 2, verified: 1 },
    { id: 'seed4', name: 'AirFlow HVAC', trade: 'hvac', location: 'Brisbane',
      bio: 'Installation, service, and repair of all air conditioning and heating systems. Split systems, ducted, evaporative — fast response times.',
      phone: '0489 012 345', email: 'airflow@hvac.net.au', rating: 4.6, review_count: 1, verified: 1 },
    { id: 'seed5', name: 'GreenThumb Landscaping', trade: 'landscaper', location: 'Perth',
      bio: 'Full landscape design and construction. Lawns, gardens, retaining walls, paving, irrigation, and pool surrounds. We turn ordinary backyards into masterpieces.',
      phone: '0490 123 456', email: 'design@greenthumb.com.au', rating: 4.9, review_count: 2, verified: 1 },
    { id: 'seed6', name: 'PrecisionPaint Pros', trade: 'painter', location: 'Adelaide',
      bio: 'Interior and exterior painting specialists. Flawless prep, premium paints, and expert colour consultation. Residential and commercial projects welcome.',
      phone: '0456 789 012', email: 'quotes@precisionpaint.com.au', rating: 4.5, review_count: 1, verified: 1 },
  ];

  for (const c of seedContractors) {
    db.run(
      'INSERT INTO contractors (id, name, trade, location, bio, phone, email, rating, review_count, verified, posted_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
      [c.id, c.name, c.trade, c.location, c.bio, c.phone, c.email, c.rating, c.review_count, c.verified, postedAt]
    );
  }

  const seedReviews = [
    { id: 'sr1', cid: 'seed1', author: 'James K.', rating: 5, text: 'Fixed our burst pipe at 2am without fuss. Arrived in 20 minutes and had it sorted in an hour. Highly recommend!', helpful: 12 },
    { id: 'sr2', cid: 'seed1', author: 'Sarah M.', rating: 5, text: 'Professional and very clean. Replaced all bathroom fittings and left the place spotless. Will use again.', helpful: 8 },
    { id: 'sr3', cid: 'seed2', author: 'Lisa P.', rating: 5, text: 'Installed solar panels perfectly. Very knowledgeable about the rebate process too — saved us $1,800.', helpful: 19 },
    { id: 'sr4', cid: 'seed2', author: 'Mark D.', rating: 5, text: 'Upgraded our switchboard quickly and safely. Explained everything clearly.', helpful: 6 },
    { id: 'sr5', cid: 'seed3', author: 'Angela R.', rating: 5, text: 'Our kitchen renovation is stunning! On time and on budget. The team was respectful of our home.', helpful: 14 },
    { id: 'sr6', cid: 'seed3', author: 'Chris L.', rating: 4, text: 'Great work overall, minor delays but the final result was excellent. Would recommend.', helpful: 2 },
    { id: 'sr7', cid: 'seed4', author: 'Rachel N.', rating: 5, text: 'Installed two split systems in a day. Neat, efficient, and great price.', helpful: 5 },
    { id: 'sr8', cid: 'seed5', author: 'Amy V.', rating: 5, text: 'Our backyard is now the envy of the neighbourhood! The design process was collaborative and fun.', helpful: 17 },
    { id: 'sr9', cid: 'seed5', author: 'Ben M.', rating: 5, text: 'Professional design process, flawless execution. The irrigation system alone is worth it.', helpful: 4 },
    { id: 'sr10', cid: 'seed6', author: 'Karen F.', rating: 5, text: 'Painted our entire house interior in 3 days. Spotless finish and zero mess left behind.', helpful: 7 },
  ];

  for (const r of seedReviews) {
    db.run(
      'INSERT INTO reviews (id, contractor_id, author, rating, text, helpful, posted_at) VALUES (?,?,?,?,?,?,?)',
      [r.id, r.cid, r.author, r.rating, r.text, r.helpful, reviewAt]
    );
  }

  const seedJobs = [
    { id: 'seedj1', customer_name: 'Michael T.', title: 'Burst pipe under kitchen sink', trade: 'plumber', location: 'Sydney',
      description: 'Woke up to water pooling under the kitchen sink. Need someone urgently to assess and fix. Possibly a cracked pipe joint.', urgency: 'emergency', budget: 'open', status: 'open' },
    { id: 'seedj2', customer_name: 'Sandra L.', title: 'Full bathroom electrical fit-out', trade: 'electrician', location: 'Melbourne',
      description: 'New bathroom renovation needs complete electrical including exhaust fan, heat lamp, shaver points, and LED downlights. Approximately 8 light points.', urgency: 'week', budget: '$600-$900', status: 'open' },
    { id: 'seedj3', customer_name: 'Tony R.', title: 'Backyard decking — approx 40sqm', trade: 'builder', location: 'Brisbane',
      description: 'Want a hardwood deck off the back of the house, roughly 8x5m. Need posts, bearers, joists and decking boards. Would prefer spotted gum or blackbutt.', urgency: 'flexible', budget: '$5,000-$8,000', status: 'open' },
  ];

  for (const j of seedJobs) {
    db.run(
      'INSERT INTO jobs (id, customer_id, customer_name, title, trade, location, description, urgency, budget, status, photos, posted_at) VALUES (?,NULL,?,?,?,?,?,?,?,?,"[]",?)',
      [j.id, j.customer_name, j.title, j.trade, j.location, j.description, j.urgency, j.budget, j.status, jobAt]
    );
  }

  saveDb();
  console.log('Seed data inserted.');
}

// ═══════════════════════════════════
//  AUTH ROUTES
// ═══════════════════════════════════
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, email, and password are required.' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  const existing = dbGet('SELECT id FROM users WHERE email = ?', [email.toLowerCase()]);
  if (existing) return res.status(409).json({ error: 'An account with that email already exists.' });
  const hash = await bcrypt.hash(password, 10);
  const id = uid();
  db.run('INSERT INTO users (id, name, email, password_hash, provider) VALUES (?,?,?,?,?)',
    [id, name, email.toLowerCase(), hash, 'email']);
  saveDb();
  const user = { id, name, email: email.toLowerCase() };
  const token = makeToken(user);
  res.json({ token, user: { userId: user.id, name: user.name, email: user.email } });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });
  const user = dbGet('SELECT * FROM users WHERE email = ?', [email.toLowerCase()]);
  if (!user) return res.status(401).json({ error: 'No account found with that email address.' });
  if (!user.password_hash) return res.status(401).json({ error: `This account uses ${user.provider} sign-in.` });
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Incorrect password. Please try again.' });
  const token = makeToken(user);
  res.json({ token, user: { userId: user.id, name: user.name, email: user.email } });
});

app.post('/api/auth/social', (req, res) => {
  const { provider, name, email } = req.body;
  if (!provider || !name || !email) return res.status(400).json({ error: 'Provider, name, and email are required.' });
  let user = dbGet('SELECT * FROM users WHERE email = ?', [email.toLowerCase()]);
  if (!user) {
    const id = uid();
    db.run('INSERT INTO users (id, name, email, password_hash, provider) VALUES (?,?,?,NULL,?)',
      [id, name, email.toLowerCase(), provider]);
    saveDb();
    user = { id, name, email: email.toLowerCase() };
  }
  const token = makeToken(user);
  res.json({ token, user: { userId: user.id, name: user.name, email: user.email } });
});

app.get('/api/auth/me', authRequired, (req, res) => {
  const user = dbGet('SELECT id, name, email, provider FROM users WHERE id = ?', [req.user.userId]);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ userId: user.id, name: user.name, email: user.email, provider: user.provider });
});

// ═══════════════════════════════════
//  CONTRACTOR ROUTES
// ═══════════════════════════════════
app.get('/api/contractors', (req, res) => {
  const contractors = dbAll('SELECT * FROM contractors ORDER BY posted_at DESC');
  const result = contractors.map(c => {
    const reviews = dbAll('SELECT * FROM reviews WHERE contractor_id = ? ORDER BY posted_at DESC', [c.id]);
    return formatContractor(c, reviews);
  });
  res.json(result);
});

app.post('/api/contractors', authRequired, (req, res) => {
  const { name, trade, location, bio, phone, email } = req.body;
  if (!name || !trade || !location) return res.status(400).json({ error: 'Name, trade, and location are required.' });
  const id = uid();
  db.run('INSERT INTO contractors (id, user_id, name, trade, location, bio, phone, email) VALUES (?,?,?,?,?,?,?,?)',
    [id, req.user.userId, name, trade, location, bio || '', phone || '', email || '']);
  saveDb();
  const fresh = dbGet('SELECT * FROM contractors WHERE id = ?', [id]);
  res.status(201).json(formatContractor(fresh, []));
});

app.post('/api/contractors/:id/reviews', authRequired, (req, res) => {
  const contractor = dbGet('SELECT * FROM contractors WHERE id = ?', [req.params.id]);
  if (!contractor) return res.status(404).json({ error: 'Contractor not found' });
  const { text, rating } = req.body;
  if (!text || !rating) return res.status(400).json({ error: 'Text and rating are required.' });
  const id = uid();
  db.run('INSERT INTO reviews (id, contractor_id, author, author_id, rating, text) VALUES (?,?,?,?,?,?)',
    [id, req.params.id, req.user.name || 'Anonymous', req.user.userId, parseFloat(rating), text]);
  // Recalc rating
  const all = dbAll('SELECT rating FROM reviews WHERE contractor_id = ?', [req.params.id]);
  const avg = Math.round(all.reduce((s, r) => s + r.rating, 0) / all.length * 10) / 10;
  db.run('UPDATE contractors SET rating = ?, review_count = ? WHERE id = ?', [avg, all.length, req.params.id]);
  saveDb();
  res.status(201).json({ message: 'Review submitted' });
});

app.post('/api/contractors/:id/reviews/:reviewId/helpful', authRequired, (req, res) => {
  const review = dbGet('SELECT * FROM reviews WHERE id = ? AND contractor_id = ?', [req.params.reviewId, req.params.id]);
  if (!review) return res.status(404).json({ error: 'Review not found' });
  const voters = JSON.parse(review.helpful_voters || '[]');
  if (voters.includes(req.user.userId)) return res.status(409).json({ error: 'Already voted' });
  voters.push(req.user.userId);
  const newHelpful = (review.helpful || 0) + 1;
  db.run('UPDATE reviews SET helpful = ?, helpful_voters = ? WHERE id = ?',
    [newHelpful, JSON.stringify(voters), review.id]);
  saveDb();
  res.json({ helpful: newHelpful });
});

// ═══════════════════════════════════
//  JOB ROUTES
// ═══════════════════════════════════
app.get('/api/jobs', optionalAuth, (req, res) => {
  let jobs;
  if (req.user) {
    jobs = dbAll('SELECT * FROM jobs WHERE customer_id IS NULL OR customer_id = ? ORDER BY posted_at DESC', [req.user.userId]);
  } else {
    jobs = dbAll('SELECT * FROM jobs WHERE customer_id IS NULL ORDER BY posted_at DESC');
  }
  res.json(jobs.map(formatJob));
});

app.post('/api/jobs', authRequired, (req, res) => {
  const { title, trade, location, description, budget, urgency, photos } = req.body;
  if (!title || !trade || !location) return res.status(400).json({ error: 'Title, trade, and location are required.' });
  const id = uid();
  db.run('INSERT INTO jobs (id, customer_id, customer_name, title, trade, location, description, budget, urgency, photos, status) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
    [id, req.user.userId, req.user.name, title, trade, location,
      description || '', budget || 'open', urgency || 'flexible',
      JSON.stringify(Array.isArray(photos) ? photos : []), 'open']);
  saveDb();
  const fresh = dbGet('SELECT * FROM jobs WHERE id = ?', [id]);
  res.status(201).json(formatJob(fresh));
});

app.post('/api/jobs/:id/quotes', optionalAuth, (req, res) => {
  const job = dbGet('SELECT * FROM jobs WHERE id = ?', [req.params.id]);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  const { contractorId, contractorName, price, eta, message, rating } = req.body;
  if (!contractorName || !price) return res.status(400).json({ error: 'Contractor name and price are required.' });
  const id = uid();
  db.run('INSERT INTO quotes (id, job_id, contractor_id, contractor_name, price, eta, message, rating) VALUES (?,?,?,?,?,?,?,?)',
    [id, req.params.id, contractorId || 'ext', contractorName, parseFloat(price),
      eta || '', message || '', rating != null ? parseFloat(rating) : null]);
  if (job.status === 'open') {
    db.run("UPDATE jobs SET status = 'quoted' WHERE id = ?", [req.params.id]);
  }
  if (job.customer_id) {
    db.run('INSERT INTO notifications (id, user_id, type, title, body, job_id) VALUES (?,?,?,?,?,?)',
      [uid(), job.customer_id, 'quote', 'New quote received',
        `${contractorName} quoted $${price} on "${job.title}"`, job.id]);
  }
  saveDb();
  res.status(201).json({ message: 'Quote submitted' });
});

app.put('/api/jobs/:id/hire/:quoteId', authRequired, (req, res) => {
  const job = dbGet('SELECT * FROM jobs WHERE id = ?', [req.params.id]);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  if (job.customer_id !== req.user.userId) return res.status(403).json({ error: 'Not your job' });
  db.run("UPDATE jobs SET status = 'hired', hired_quote_id = ? WHERE id = ?", [req.params.quoteId, req.params.id]);
  saveDb();
  res.json({ message: 'Contractor hired' });
});

app.put('/api/jobs/:id/complete', authRequired, (req, res) => {
  const job = dbGet('SELECT * FROM jobs WHERE id = ?', [req.params.id]);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  if (job.customer_id !== req.user.userId) return res.status(403).json({ error: 'Not your job' });
  db.run("UPDATE jobs SET status = 'completed' WHERE id = ?", [req.params.id]);
  saveDb();
  res.json({ message: 'Job completed' });
});

// ═══════════════════════════════════
//  NOTIFICATION ROUTES
// ═══════════════════════════════════
app.get('/api/notifications', authRequired, (req, res) => {
  const notifs = dbAll('SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50', [req.user.userId]);
  res.json(notifs.map(n => ({
    id: n.id, type: n.type, title: n.title, body: n.body,
    jobId: n.job_id, read: n.read === 1 || n.read === true, createdAt: n.created_at,
    message: n.body || n.title || '',
  })));
});

app.put('/api/notifications/read', authRequired, (req, res) => {
  db.run('UPDATE notifications SET read = 1 WHERE user_id = ?', [req.user.userId]);
  saveDb();
  res.json({ message: 'All marked read' });
});

// ═══════════════════════════════════
//  PHOTO UPLOAD
// ═══════════════════════════════════
app.post('/api/upload', authRequired, upload.array('photos', 5), (req, res) => {
  const urls = req.files.map(f => '/uploads/' + f.filename);
  res.json({ urls });
});

// ═══════════════════════════════════
//  SPA CATCH-ALL
// ═══════════════════════════════════
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ═══════════════════════════════════
//  STARTUP
// ═══════════════════════════════════
async function start() {
  const SQL = await initSqlJs();

  // Load existing DB from disk, or create new
  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(fileBuffer);
    console.log('Loaded existing database from disk.');
  } else {
    db = new SQL.Database();
    console.log('Created new database.');
  }

  initSchema();
  seedData();

  app.listen(PORT, () => console.log(`TradeFind API → http://localhost:${PORT}`));
}

start().catch(err => { console.error('Failed to start:', err); process.exit(1); });
