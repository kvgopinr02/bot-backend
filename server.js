// ╔══════════════════════════════════════════════════════════╗
//  AI INTERVIEW BOT — FULL BACKEND
//  Features: Login System + Admin Dashboard + Voice Support
//  Stack: Node.js + Express + MongoDB + Groq API (FREE)
// ╚══════════════════════════════════════════════════════════╝

const express  = require('express');
const cors     = require('cors');
const mongoose = require('mongoose');
const multer   = require('multer');
const path     = require('path');
const fs       = require('fs');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

// ── File upload ───────────────────────────────────────────
const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['.pdf', '.txt', '.doc', '.docx'];
    const ext = path.extname(file.originalname).toLowerCase();
    allowed.includes(ext) ? cb(null, true) : cb(new Error('Only PDF/TXT/DOC files allowed'));
  }
});

// ── MongoDB ───────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB error:', err.message));

// ══════════════════════════════════════════════════════════
//  SCHEMAS
// ══════════════════════════════════════════════════════════
const UserSchema = new mongoose.Schema({
  name:      { type: String, required: true },
  email:     { type: String, required: true, unique: true, lowercase: true },
  password:  { type: String, required: true },
  role:      { type: String, enum: ['candidate', 'admin'], default: 'candidate' },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

const InterviewSchema = new mongoose.Schema({
  userId:         { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  candidateName:  { type: String, required: true },
  role:           { type: String, required: true },
  interviewType:  { type: String, enum: ['technical','hr','mixed'], default: 'mixed' },
  totalQuestions: { type: Number, default: 8 },
  resumeText:     { type: String, default: '' },
  messages:       [{ role: String, content: String }],
  qaLog: [{
    question: String,
    answer:   String,
    eval:     { type: String, enum: ['good','avg','poor'] },
    comment:  String
  }],
  result: {
    score:     Number,
    verdict:   String,
    overall:   String,
    strengths: String,
    improve:   String
  },
  status:    { type: String, enum: ['in_progress','completed'], default: 'in_progress' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});
const Interview = mongoose.model('Interview', InterviewSchema);

// ══════════════════════════════════════════════════════════
//  JWT MIDDLEWARE
// ══════════════════════════════════════════════════════════
const JWT_SECRET = process.env.JWT_SECRET || 'interview_bot_secret_2024';

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token. Please login.' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function adminMiddleware(req, res, next) {
  authMiddleware(req, res, () => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
    next();
  });
}

// ══════════════════════════════════════════════════════════
//  GROQ API
// ══════════════════════════════════════════════════════════
async function callGroq(systemPrompt, messages) {
  const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${process.env.GROQ_API_KEY}`
    },
    body: JSON.stringify({
      model: 'llama-3.3-70b-versatile',
      max_tokens: 1024,
      temperature: 0.7,
      messages: [{ role: 'system', content: systemPrompt }, ...messages]
    })
  });
  if (!response.ok) {
    const err = await response.json();
    throw new Error(err.error?.message || 'Groq error');
  }
  const data = await response.json();
  return data.choices[0].message.content;
}

function buildSystemPrompt(role, type, totalQ, resumeText) {
  const desc = {
    technical: 'technical CS questions (DSA, OOP, system design, tools from the resume)',
    hr:        'HR and behavioural questions grounded in their resume',
    mixed:     'alternating technical and HR questions based on the resume'
  };
  return `You are an expert interviewer conducting a ${type} fresher interview for "${role}".
RESUME: ${resumeText || 'No resume — ask general questions.'}
RULES:
1. Base EVERY question on the resume — reference specific projects, skills, tech stack.
2. Ask ${desc[type]}. ONE question at a time. Fresher level (0-1 yr).
3. After each answer: brief 1-2 sentence acknowledgement, then next question.
4. Format: **Question N of ${totalQ}:** [question]
5. After question ${totalQ} answered, output INTERVIEW_COMPLETE then JSON in <r></r>:
<r>{"score":<1-10>,"verdict":"<Excellent|Good|Average|Needs Work>","overall":"<feedback>","strengths":"<strengths>","improve":"<improvements>","qa":[{"q":"<q>","a":"<summary>","eval":"<good|avg|poor>","comment":"<comment>"}]}</r>`;
}

// ══════════════════════════════════════════════════════════
//  AUTH ROUTES
// ══════════════════════════════════════════════════════════

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be 6+ characters' });
    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ error: 'Email already registered' });
    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashed });
    await user.save();
    const token = jwt.sign({ id: user._id, name: user.name, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, user: { id: user._id, name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Invalid email or password' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: 'Invalid email or password' });
    const token = jwt.sign({ id: user._id, name: user.name, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get me
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════════════════
//  RESUME UPLOAD
// ══════════════════════════════════════════════════════════
app.post('/api/resume/upload', upload.single('resume'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    const filePath = req.file.path;
    const ext = path.extname(req.file.originalname).toLowerCase();
    let text = '';
    if (ext === '.pdf') {
      try {
        const pdfParse = require('pdf-parse');
        const buf = fs.readFileSync(filePath);
        const pdfData = await pdfParse(buf);
        text = pdfData.text;
      } catch {
        fs.unlinkSync(filePath);
        return res.status(400).json({ error: 'PDF parse failed. Use .txt file.' });
      }
    } else {
      text = fs.readFileSync(filePath, 'utf8');
    }
    fs.unlinkSync(filePath);
    res.json({ resumeText: text.slice(0, 6000), wordCount: text.split(/\s+/).length, fileName: req.file.originalname });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════════════════
//  INTERVIEW ROUTES
// ══════════════════════════════════════════════════════════

// Start Interview
app.post('/api/interview/start', authMiddleware, async (req, res) => {
  try {
    const { role = 'Software Engineer', interviewType = 'mixed', totalQuestions = 8, resumeText = '' } = req.body;
    const reply = await callGroq(
      buildSystemPrompt(role, interviewType, totalQuestions, resumeText),
      [{ role: 'user', content: 'Start the interview. Greet me in one sentence and ask the first question.' }]
    );
    const session = new Interview({
      userId: req.user.id, candidateName: req.user.name,
      role, interviewType, totalQuestions: parseInt(totalQuestions), resumeText,
      messages: [{ role: 'user', content: 'START' }, { role: 'assistant', content: reply }]
    });
    await session.save();
    res.status(201).json({ sessionId: session._id, message: reply, questionNumber: 1, totalQuestions: session.totalQuestions });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Submit Answer
app.post('/api/interview/:sessionId/answer', authMiddleware, async (req, res) => {
  try {
    const { answer } = req.body;
    if (!answer?.trim()) return res.status(400).json({ error: 'Answer cannot be empty' });
    const session = await Interview.findById(req.params.sessionId);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    if (session.status === 'completed') return res.status(400).json({ error: 'Already completed' });

    const lastBot = [...session.messages].reverse().find(m => m.role === 'assistant')?.content || '';
    const qm = lastBot.match(/\*\*Question \d+ of \d+:\*\*\s*(.+)/);
    session.qaLog.push({ question: qm ? qm[1].trim() : 'Question', answer });
    session.messages.push({ role: 'user', content: answer });

    const msgs = session.messages.filter(m => m.content !== 'START').map(m => ({ role: m.role, content: m.content }));
    const reply = await callGroq(buildSystemPrompt(session.role, session.interviewType, session.totalQuestions, session.resumeText), msgs);

    if (reply.includes('INTERVIEW_COMPLETE')) {
      const match = reply.match(/<r>([\s\S]*?)<\/r>/);
      let result = null;
      if (match) { try { result = JSON.parse(match[1].trim()); } catch {} }
      if (result) {
        session.result = { score: result.score, verdict: result.verdict, overall: result.overall, strengths: result.strengths, improve: result.improve };
        (result.qa || []).forEach((item, i) => { if (session.qaLog[i]) { session.qaLog[i].eval = item.eval; session.qaLog[i].comment = item.comment; } });
      }
      session.status = 'completed'; session.updatedAt = new Date();
      session.messages.push({ role: 'assistant', content: reply });
      await session.save();
      return res.json({ message: reply, completed: true, result, sessionId: session._id });
    }

    session.messages.push({ role: 'assistant', content: reply });
    session.updatedAt = new Date();
    await session.save();
    res.json({ message: reply, completed: false, questionNumber: session.messages.filter(m => m.role === 'assistant').length, totalQuestions: session.totalQuestions });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// My interviews
app.get('/api/my-interviews', authMiddleware, async (req, res) => {
  try {
    const interviews = await Interview.find({ userId: req.user.id })
      .select('role interviewType status result.score result.verdict createdAt totalQuestions')
      .sort({ createdAt: -1 });
    res.json(interviews);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Single interview
app.get('/api/interview/:id', authMiddleware, async (req, res) => {
  try {
    const s = await Interview.findById(req.params.id);
    if (!s) return res.status(404).json({ error: 'Not found' });
    res.json(s);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════════════════
//  ADMIN ROUTES
// ══════════════════════════════════════════════════════════

app.get('/api/admin/analytics', adminMiddleware, async (req, res) => {
  try {
    const [total, completed, users, avgArr, byRole, byType, recent] = await Promise.all([
      Interview.countDocuments(),
      Interview.countDocuments({ status: 'completed' }),
      User.countDocuments({ role: 'candidate' }),
      Interview.aggregate([{ $match: { status: 'completed' } }, { $group: { _id: null, avg: { $avg: '$result.score' } } }]),
      Interview.aggregate([{ $group: { _id: '$role', count: { $sum: 1 } } }, { $sort: { count: -1 } }, { $limit: 8 }]),
      Interview.aggregate([{ $group: { _id: '$interviewType', count: { $sum: 1 } } }]),
      Interview.find({ status: 'completed' }).select('result.score createdAt candidateName role').sort({ createdAt: -1 }).limit(10)
    ]);
    res.json({ total, completed, inProgress: total - completed, totalUsers: users, avgScore: avgArr[0]?.avg?.toFixed(1) || 0, byRole, byType, recent });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/interviews', adminMiddleware, async (req, res) => {
  try {
    const { page = 1, limit = 20, status } = req.query;
    const filter = {};
    if (status) filter.status = status;
    const total = await Interview.countDocuments(filter);
    const sessions = await Interview.find(filter)
      .populate('userId', 'name email')
      .select('candidateName role interviewType status result.score result.verdict createdAt userId')
      .sort({ createdAt: -1 })
      .skip((parseInt(page) - 1) * parseInt(limit))
      .limit(parseInt(limit));
    res.json({ total, sessions });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/users', adminMiddleware, async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ createdAt: -1 });
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/interview/:id', adminMiddleware, async (req, res) => {
  try {
    await Interview.findByIdAndDelete(req.params.id);
    res.json({ message: 'Deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/admin/user/:id/make-admin', adminMiddleware, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.params.id, { role: 'admin' });
    res.json({ message: 'User promoted to admin' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected' });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`\n╔══════════════════════════════════════════╗`);
  console.log(`║  🚀 AI Interview Bot Running             ║`);
  console.log(`║  http://localhost:${PORT}                   ║`);
  console.log(`╚══════════════════════════════════════════╝\n`);
  console.log(`🌐 App:    http://localhost:${PORT}`);
  console.log(`📊 Admin:  http://localhost:${PORT}/admin.html\n`);
});