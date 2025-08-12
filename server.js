require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors()); // adjust origin in production
app.use(express.json());

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_in_prod';
const SALT_ROUNDS = 10;

/* ---------- Mongoose models ---------- */
const userSchema = new mongoose.Schema({
  username: { type: String, required: false },
  email: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
}, { timestamps: true });

const drawerSchema = new mongoose.Schema({
  drawerName: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
}, { timestamps: true });

const noteSchema = new mongoose.Schema({
  ownerType: { type: String, enum: ['user', 'drawer'], required: true }, // 'user' or 'drawer'
  ownerId: { type: mongoose.Schema.Types.ObjectId, required: true },      // user._id or drawer._id
  title: String,
  content: String,
  createdAt: { type: Date, default: Date.now },
  updatedAt: Date
});

const User = mongoose.model('User', userSchema);
const Drawer = mongoose.model('Drawer', drawerSchema);
const Note = mongoose.model('Note', noteSchema);

/* ---------- DB connect ---------- */
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
.then(() => console.log('MongoDB connected'))
.catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

/* ---------- Helpers ---------- */
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

function authMiddleware(req, res, next) {
  // Accept token from Authorization: Bearer <token>
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'No auth token' });
  const token = header.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

/* ---------- Auth & drawer routes ---------- */

// Register user
app.post('/api/register', async (req, res) => {
  const { email, username, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });
  try {
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ error: 'Email already in use' });

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    const user = new User({ email, username, passwordHash });
    await user.save();
    const token = signToken({ id: user._id, type: 'user' });
    res.json({ token, user: { id: user._id, email: user.email, username: user.username } });
  } catch (err) {
    res.status(500).json({ error: 'server error' });
  }
});

// Login user
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(400).json({ error: 'Invalid credentials' });
    const token = signToken({ id: user._id, type: 'user' });
    res.json({ token, user: { id: user._id, email: user.email, username: user.username } });
  } catch (err) {
    res.status(500).json({ error: 'server error' });
  }
});

// Create drawer
app.post('/api/drawers', async (req, res) => {
  const { drawerName, password } = req.body;
  if (!drawerName || !password) return res.status(400).json({ error: 'drawerName and password required' });
  try {
    const existing = await Drawer.findOne({ drawerName });
    if (existing) return res.status(400).json({ error: 'Drawer name taken' });
    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    const drawer = new Drawer({ drawerName, passwordHash });
    await drawer.save();
    const token = signToken({ id: drawer._id, type: 'drawer' });
    res.json({ token, drawer: { id: drawer._id, drawerName: drawer.drawerName } });
  } catch (err) {
    res.status(500).json({ error: 'server error' });
  }
});

// Login drawer
app.post('/api/drawers/login', async (req, res) => {
  const { drawerName, password } = req.body;
  if (!drawerName || !password) return res.status(400).json({ error: 'drawerName and password required' });
  try {
    const drawer = await Drawer.findOne({ drawerName });
    if (!drawer) return res.status(400).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, drawer.passwordHash);
    if (!ok) return res.status(400).json({ error: 'Invalid credentials' });
    const token = signToken({ id: drawer._id, type: 'drawer' });
    res.json({ token, drawer: { id: drawer._id, drawerName: drawer.drawerName } });
  } catch (err) {
    res.status(500).json({ error: 'server error' });
  }
});

/* ---------- Notes CRUD ---------- */
/*
  Authorization:
  - If JWT payload has type === 'user', then ownerType='user' and ownerId = user id.
  - If JWT payload has type === 'drawer', then ownerType='drawer' and ownerId = drawer id.
*/

// fetch notes for current auth
app.get('/api/notes', authMiddleware, async (req, res) => {
  const { id, type } = req.user;
  try {
    const notes = await Note.find({ ownerType: type, ownerId: id }).sort({ createdAt: -1 });
    res.json(notes);
  } catch (err) {
    res.status(500).json({ error: 'server error' });
  }
});

// create note
app.post('/api/notes', authMiddleware, async (req, res) => {
  const { id, type } = req.user;
  const { title = '', content = '' } = req.body;
  try {
    const note = new Note({ ownerType: type, ownerId: id, title, content, createdAt: new Date() });
    await note.save();
    res.json(note);
  } catch (err) {
    res.status(500).json({ error: 'server error' });
  }
});

// update note
app.put('/api/notes/:id', authMiddleware, async (req, res) => {
  const { id: authId, type } = req.user;
  const noteId = req.params.id;
  const { title, content } = req.body;
  try {
    const note = await Note.findById(noteId);
    if (!note) return res.status(404).json({ error: 'not found' });
    if (String(note.ownerId) !== String(authId) || note.ownerType !== type) {
      return res.status(403).json({ error: 'forbidden' });
    }
    note.title = title;
    note.content = content;
    note.updatedAt = new Date();
    await note.save();
    res.json(note);
  } catch (err) {
    res.status(500).json({ error: 'server error' });
  }
});

// delete note
app.delete('/api/notes/:id', authMiddleware, async (req, res) => {
  const { id: authId, type } = req.user;
  const noteId = req.params.id;
  try {
    const note = await Note.findById(noteId);
    if (!note) return res.status(404).json({ error: 'not found' });
    if (String(note.ownerId) !== String(authId) || note.ownerType !== type) {
      return res.status(403).json({ error: 'forbidden' });
    }
    await Note.deleteOne({ _id: noteId });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'server error' });
  }
});

/* ---------- Start server ---------- */
app.listen(PORT, () => {
  console.log('Server started on port', PORT);
});
