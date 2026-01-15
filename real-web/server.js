const express = require('express');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const morgan = require('morgan');
const { auth } = require('./middleware/auth');
const { allowRole } = require('./middleware/roles');

const SECRET = "HONEY_SECRET_KEY";
const PORT = 3000;

const app = express();
app.use(express.json());
app.use(express.static("public"));

const failedLogins = {};

// Logging (เก็บ log การกระทำทั้งหมด)
if (!fs.existsSync('./logs')) fs.mkdirSync('./logs');
const accessLogStream = fs.createWriteStream('./logs/access.log', { flags: 'a' });
app.use(morgan('combined', { stream: accessLogStream }));

// SQLite db
const db = new sqlite3.Database('./db.sqlite');

// Init tables
db.run(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT,
  role TEXT
)
`);

// Register
app.post("/api/register", (req, res) => {
  const { username, password, role } = req.body;
  const hash = bcrypt.hashSync(password, 10);

  db.run(
    `INSERT INTO users (username, password, role) VALUES (?, ?, ?)`,
    [username, hash, role || 'user'],
    function (err) {
      if (err) return res.status(400).json({ error: "User exists" });
      res.json({ message: "Registered" });
    }
  );
});

// Login
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;

  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
    if (!user) return res.status(401).json({ message: "Invalid user" });

    const match = bcrypt.compareSync(password, user.password);
    if (!match) return res.status(401).json({ message: "Wrong password" });

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      SECRET,
      { expiresIn: '2h' }
    );

    res.json({ token, role: user.role });
  });
});

// User Route
app.get("/api/user", auth, (req, res) => {
  res.json({ message: "User panel", user: req.user });
});

// Admin Route
app.get("/api/admin", auth, allowRole("admin"), (req, res) => {
  res.json({ message: "Admin panel", user: req.user });
});

// Serve HTML pages (fix for Express v5)
app.get(/.*/, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
