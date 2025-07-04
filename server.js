// Updated server.js with sign-out functionality and PFP support in posts

const express = require("express");
const fs = require("fs");
const multer = require("multer");
const cors = require("cors");
const path = require("path");
const bcrypt = require("bcrypt");
const session = require("express-session");

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_FILE = "messages.json";
const USERS_FILE = "users.json";
const UPLOAD_DIR = "uploads";
const PFP_DIR = "pfps";

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);
if (!fs.existsSync(PFP_DIR)) fs.mkdirSync(PFP_DIR);

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const isPfp = req.originalUrl.includes("/upload-pfp");
    cb(null, isPfp ? PFP_DIR : UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, unique + path.extname(file.originalname));
  }
});

const upload = multer({ storage });

app.use(cors());
app.use(express.static("."));
app.use("/uploads", express.static(UPLOAD_DIR));
app.use("/pfps", express.static(PFP_DIR));
app.use(express.json());
app.use(session({
  secret: "supersecret", // Replace with a strong secret in production
  resave: false,
  saveUninitialized: true,
}));

// Load/save helpers
function loadUsers() {
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE));
  } catch {
    return {};
  }
}

function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function loadMessages() {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE));
  } catch {
    return [];
  }
}

function saveMessages(messages) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(messages, null, 2));
}

// Predefined admin accounts
const admins = {
  "/admin1": "ali1382ali",
  "/admin2": "araz1389araz"
};

const users = loadUsers();
for (const [admin, pass] of Object.entries(admins)) {
  if (!users[admin]) {
    users[admin] = {
      password: bcrypt.hashSync(pass, 10),
      pfp: null
    };
  }
}
saveUsers(users);

app.post("/signup", (req, res) => {
  const users = loadUsers();
  const userCount = Object.keys(users).filter(u => u.startsWith("/user_")).length + 1;
  const newUsername = `/user_${userCount}`;

  const { password } = req.body;
  if (!password) return res.status(400).json({ error: "Password required" });

  const hashedPassword = bcrypt.hashSync(password, 10);
  users[newUsername] = { password: hashedPassword, pfp: null };
  saveUsers(users);

  req.session.username = newUsername;
  res.json({ username: newUsername });
});

app.post("/login", (req, res) => {
  const users = loadUsers();
  const { username, password } = req.body;

  const user = users[username];
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  req.session.username = username;
  res.json({ username });
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ message: "Logged out" });
  });
});

app.get("/session", (req, res) => {
  if (req.session.username) {
    const users = loadUsers();
    res.json({ username: req.session.username, pfp: users[req.session.username]?.pfp });
  } else {
    res.status(401).json({ error: "Not signed in" });
  }
});

app.post("/upload-pfp", upload.single("pfp"), (req, res) => {
  if (!req.session.username) return res.status(401).json({ error: "Unauthorized" });

  const users = loadUsers();
  users[req.session.username].pfp = `/pfps/${req.file.filename}`;
  saveUsers(users);
  res.json({ pfp: users[req.session.username].pfp });
});

app.post("/api/messages", upload.single("image"), (req, res) => {
  if (!req.session.username) return res.status(401).json({ error: "Unauthorized" });

  const users = loadUsers();
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;
  const pfp = users[req.session.username]?.pfp || null;
  const newMsg = {
    username: req.session.username,
    message: req.body.message,
    timestamp: Date.now(),
    imageUrl,
    pfp
  };

  const messages = loadMessages();
  messages.push(newMsg);
  saveMessages(messages);
  res.json(newMsg);
});

app.get("/api/messages", (req, res) => {
  res.json(loadMessages());
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
