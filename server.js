import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;

if (!MONGO_URI) {
  console.error("❌ MONGO_URI not set in environment variables");
  process.exit(1);
}

// Connect to MongoDB
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => {
    console.error("❌ MongoDB connection error:", err);
    process.exit(1);
  });

// Schemas
const userSchema = new mongoose.Schema({ email: String, passwordHash: String });
const drawerSchema = new mongoose.Schema({ drawerName: String, passwordHash: String });
const noteSchema = new mongoose.Schema({
  ownerType: String, // "user" or "drawer"
  ownerId: mongoose.Schema.Types.ObjectId,
  title: String,
  content: String,
  createdAt: { type: String, default: () => new Date().toISOString() }
});

const User = mongoose.model("User", userSchema);
const Drawer = mongoose.model("Drawer", drawerSchema);
const Note = mongoose.model("Note", noteSchema);

// Middleware for authentication
function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

// --- REGISTER USER ---
app.post("/api/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email and password required" });

  const exists = await User.findOne({ email });
  if (exists) return res.status(400).json({ error: "User already exists" });

  const passwordHash = await bcrypt.hash(password, 10);
  const newUser = await User.create({ email, passwordHash });

  // Create token for immediate login
  const token = jwt.sign({ type: "user", id: newUser._id }, JWT_SECRET, { expiresIn: "7d" });

  res.json({ success: true, token });
});

// --- CREATE DRAWER ---
app.post("/api/drawers/create", async (req, res) => {
  const { drawerName, password } = req.body;
  if (!drawerName || !password) return res.status(400).json({ error: "Drawer name and password required" });

  const exists = await Drawer.findOne({ drawerName });
  if (exists) return res.status(400).json({ error: "Drawer already exists" });

  const passwordHash = await bcrypt.hash(password, 10);
  const newDrawer = await Drawer.create({ drawerName, passwordHash });

  // Create token for immediate access
  const token = jwt.sign({ type: "drawer", id: newDrawer._id }, JWT_SECRET, { expiresIn: "7d" });

  res.json({ success: true, token });
});

// --- LOGIN USER ---
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const u = await User.findOne({ email });
  if (!u) return res.status(400).json({ error: "User not found" });

  const match = await bcrypt.compare(password, u.passwordHash);
  if (!match) return res.status(400).json({ error: "Wrong password" });

  const token = jwt.sign({ type: "user", id: u._id }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token });
});

// --- LOGIN DRAWER ---
app.post("/api/drawers/login", async (req, res) => {
  const { drawerName, password } = req.body;
  const d = await Drawer.findOne({ drawerName });
  if (!d) return res.status(400).json({ error: "Drawer not found" });

  const match = await bcrypt.compare(password, d.passwordHash);
  if (!match) return res.status(400).json({ error: "Wrong password" });

  const token = jwt.sign({ type: "drawer", id: d._id }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token });
});

// --- GET NOTES ---
app.get("/api/notes", auth, async (req, res) => {
  const notes = await Note.find({ ownerType: req.user.type, ownerId: req.user.id });
  res.json(notes);
});

// --- CREATE NOTE ---
app.post("/api/notes", auth, async (req, res) => {
  const n = await Note.create({
    ownerType: req.user.type,
    ownerId: req.user.id,
    title: req.body.title || "",
    content: req.body.content || ""
  });
  res.json(n);
});

// --- UPDATE NOTE ---
app.put("/api/notes/:id", auth, async (req, res) => {
  const n = await Note.findOneAndUpdate(
    { _id: req.params.id, ownerId: req.user.id },
    { title: req.body.title, content: req.body.content },
    { new: true }
  );
  res.json(n);
});

// --- DELETE NOTE ---
app.delete("/api/notes/:id", auth, async (req, res) => {
  await Note.deleteOne({ _id: req.params.id, ownerId: req.user.id });
  res.json({ success: true });
});

// Start server
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
