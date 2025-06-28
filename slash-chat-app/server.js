const express = require("express");
const fs = require("fs");
const path = require("path");
const multer = require("multer");
const cors = require("cors");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_FILE = "messages.json";
const USERS_FILE = "users.json";
const UPLOADS_DIR = "uploads";
const PFPS_DIR = "pfps";

if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR);
if (!fs.existsSync(PFPS_DIR)) fs.mkdirSync(PFPS_DIR);
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, "[]");
if (!fs.existsSync(USERS_FILE)) {
  const defaultUsers = [
    {
      username: "/admin1",
      passwordHash: bcrypt.hashSync("ali1382ali", 10),
      pfp: null
    },
    {
      username: "/admin2",
      passwordHash: bcrypt.hashSync("araz1389araz", 10),
      pfp: null
    }
  ];
  fs.writeFileSync(USERS_FILE, JSON.stringify(defaultUsers, null, 2));
}

app.use(cors());
app.use(express.json());
app.use(cookieParser());
app.use(express.static("."));
app.use("/uploads", express.static(UPLOADS_DIR));
app.use("/pfps", express.static(PFPS_DIR));

const upload = multer({ dest: UPLOADS_DIR });
const pfpUpload = multer({ dest: PFPS_DIR });

// Utility functions
function loadUsers() {
  return JSON.parse(fs.readFileSync(USERS_FILE));
}

function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function loadMessages() {
  return JSON.parse(fs.readFileSync(DATA_FILE));
}

function saveMessages(messages) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(messages, null, 2));
}

function hashIP(ip) {
  return crypto.createHash("sha256").update(ip).digest("hex");
}

function getUserFromSession(req) {
  const sessionId = req.cookies.sessionId;
  if (!sessionId) return null;
  const users = loadUsers();
  return users.find(user => user.sessionId === sessionId) || null;
}

// API routes
app.get("/api/messages", (req, res) => {
  res.json(loadMessages());
});

app.post("/api/messages", upload.single("image"), (req, res) => {
  const user = getUserFromSession(req);
  if (!user) return res.status(401).json({ error: "Unauthorized" });

  const { message } = req.body;
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;

  const newMessage = {
    username: user.username,
    message,
    imageUrl,
    timestamp: Date.now(),
    ipHash: hashIP(req.ip)
  };

  const messages = loadMessages();
  messages.push(newMessage);
  saveMessages(messages);
  res.json(newMessage);
});

// Signup
app.post("/api/signup", (req, res) => {
  const users = loadUsers();
  const nonAdminUsers = users.filter(u => !u.username.startsWith("/admin"));

  const newUsername = `/user_${nonAdminUsers.length + 1}`;
  const { password } = req.body;
  const passwordHash = bcrypt.hashSync(password, 10);
  const sessionId = crypto.randomBytes(16).toString("hex");

  const newUser = {
    username: newUsername,
    passwordHash,
    pfp: null,
    sessionId
  };

  users.push(newUser);
  saveUsers(users);

  res.cookie("sessionId", sessionId, { httpOnly: true, sameSite: "Strict" });
  res.json({ username: newUsername });
});

// Login
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const users = loadUsers();
  const user = users.find(u => u.username === username);

  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const sessionId = crypto.randomBytes(16).toString("hex");
  user.sessionId = sessionId;
  saveUsers(users);

  res.cookie("sessionId", sessionId, { httpOnly: true, sameSite: "Strict" });
  res.json({ username: user.username });
});

// Change password
app.post("/api/change-password", (req, res) => {
  const user = getUserFromSession(req);
  if (!user) return res.status(401).json({ error: "Unauthorized" });

  const { oldPassword, newPassword } = req.body;
  if (!bcrypt.compareSync(oldPassword, user.passwordHash)) {
    return res.status(403).json({ error: "Incorrect old password" });
  }

  user.passwordHash = bcrypt.hashSync(newPassword, 10);
  saveUsers(loadUsers().map(u => (u.username === user.username ? user : u)));
  res.json({ success: true });
});

// Upload profile picture
app.post("/api/upload-pfp", pfpUpload.single("pfp"), (req, res) => {
  const user = getUserFromSession(req);
  if (!user) return res.status(401).json({ error: "Unauthorized" });

  const pfpPath = `/pfps/${req.file.filename}`;
  user.pfp = pfpPath;
  saveUsers(loadUsers().map(u => (u.username === user.username ? user : u)));
  res.json({ pfp: pfpPath });
});

// Get current user
app.get("/api/me", (req, res) => {
  const user = getUserFromSession(req);
  if (!user) return res.status(401).json({ error: "Unauthorized" });
  res.json({ username: user.username, pfp: user.pfp || null });
});

// Serve index.html
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
