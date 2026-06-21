const express = require("express");
const { Pool } = require("pg");
const path = require("path");
const crypto = require("crypto");

const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

const sessions = {};
const challenges = {};

function hashPassword(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

function auth(req, res, next) {
  const token = req.headers.authorization;
  if (!token || !sessions[token]) return res.status(401).json({ error: "Unauthorized" });
  req.userId = sessions[token];
  next();
}

async function start() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS webauthn_credentials (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      credential_id TEXT NOT NULL,
      public_key TEXT NOT NULL
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS expenses (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      category TEXT NOT NULL,
      description TEXT,
      amount REAL NOT NULL,
      date TEXT NOT NULL,
      paid INTEGER DEFAULT 0
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS settings (
      id SERIAL PRIMARY KEY,
      user_id INTEGER UNIQUE REFERENCES users(id),
      monthly_income REAL NOT NULL
    )
  `);

  app.use(express.json({ limit: "5mb" }));
  app.use(express.static(path.join(__dirname, "public")));

  // Register
  app.post("/api/register", async (req, res) => {
    const { username, password } = req.body;
    const hashed = hashPassword(password);
    try {
      const result = await pool.query("INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id", [username, hashed]);
      await pool.query("INSERT INTO settings (user_id, monthly_income) VALUES ($1, 15076)", [result.rows[0].id]);
      res.json({ success: true });
    } catch (e) {
      res.status(400).json({ error: "Username already exists" });
    }
  });

  // Login
  app.post("/api/login", async (req, res) => {
    const { username, password } = req.body;
    const hashed = hashPassword(password);
    const result = await pool.query("SELECT id FROM users WHERE username=$1 AND password=$2", [username, hashed]);
    if (!result.rows.length) return res.status(401).json({ error: "Invalid username or password" });
    const token = crypto.randomBytes(32).toString("hex");
    sessions[token] = result.rows[0].id;
    res.json({ token, userId: result.rows[0].id });
  });

  // WebAuthn - start registration
  app.post("/api/webauthn/register-options", auth, async (req, res) => {
    const challenge = crypto.randomBytes(32).toString("base64url");
    challenges[req.userId] = challenge;
    res.json({
      challenge,
      rp: { name: "Harry's Budget Tracking", id: new URL(req.headers.origin || "https://budget-tracking-038j.onrender.com").hostname },
      user: { id: String(req.userId), name: req.body.username, displayName: req.body.username },
      pubKeyCredParams: [{ alg: -7, type: "public-key" }, { alg: -257, type: "public-key" }],
      authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required" }
    });
  });

  // WebAuthn - finish registration
  app.post("/api/webauthn/register", auth, async (req, res) => {
    const { credentialId, publicKey } = req.body;
    await pool.query("INSERT INTO webauthn_credentials (user_id, credential_id, public_key) VALUES ($1, $2, $3)", [req.userId, credentialId, publicKey]);
    res.json({ success: true });
  });

  // WebAuthn - start login
  app.post("/api/webauthn/login-options", async (req, res) => {
    const { username } = req.body;
    const user = (await pool.query("SELECT id FROM users WHERE username=$1", [username])).rows[0];
    if (!user) return res.status(404).json({ error: "User not found" });

    const creds = (await pool.query("SELECT credential_id FROM webauthn_credentials WHERE user_id=$1", [user.id])).rows;
    if (!creds.length) return res.status(400).json({ error: "No biometric registered" });

    const challenge = crypto.randomBytes(32).toString("base64url");
    challenges[user.id] = challenge;

    res.json({
      challenge,
      allowCredentials: creds.map(c => ({ id: c.credential_id, type: "public-key" })),
      userVerification: "required",
      userId: user.id
    });
  });

  // WebAuthn - finish login
  app.post("/api/webauthn/login", async (req, res) => {
    const { userId, credentialId } = req.body;
    const cred = (await pool.query("SELECT * FROM webauthn_credentials WHERE user_id=$1 AND credential_id=$2", [userId, credentialId])).rows[0];
    if (!cred) return res.status(401).json({ error: "Biometric verification failed" });

    const token = crypto.randomBytes(32).toString("hex");
    sessions[token] = userId;
    res.json({ token });
  });

  // Check if user has biometric
  app.post("/api/webauthn/check", async (req, res) => {
    const { username } = req.body;
    const user = (await pool.query("SELECT id FROM users WHERE username=$1", [username])).rows[0];
    if (!user) return res.json({ hasBiometric: false });
    const creds = (await pool.query("SELECT id FROM webauthn_credentials WHERE user_id=$1", [user.id])).rows;
    res.json({ hasBiometric: creds.length > 0 });
  });

  // Dashboard
  app.get("/api/dashboard", auth, async (req, res) => {
    const income = (await pool.query("SELECT monthly_income FROM settings WHERE user_id=$1", [req.userId])).rows[0].monthly_income;
    const month = new Date().toISOString().slice(0, 7);

    const expenses = (await pool.query("SELECT * FROM expenses WHERE user_id=$1 AND date LIKE $2 ORDER BY date DESC", [req.userId, `${month}%`])).rows;
    const catRows = (await pool.query("SELECT category, SUM(amount) as total FROM expenses WHERE user_id=$1 AND date LIKE $2 GROUP BY category ORDER BY total DESC", [req.userId, `${month}%`])).rows;

    const totalSpent = catRows.reduce((s, r) => s + parseFloat(r.total), 0);
    res.json({ income, totalSpent, savings: income - totalSpent, expenses, byCategory: catRows });
  });

  app.post("/api/expenses", auth, async (req, res) => {
    const { category, description, amount, date } = req.body;
    const result = await pool.query("INSERT INTO expenses (user_id, category, description, amount, date, paid) VALUES ($1,$2,$3,$4,$5,0) RETURNING id", [req.userId, category, description, amount, date]);
    res.json({ id: result.rows[0].id });
  });

  app.patch("/api/expenses/:id/toggle", auth, async (req, res) => {
    await pool.query("UPDATE expenses SET paid = CASE WHEN paid=1 THEN 0 ELSE 1 END WHERE id=$1 AND user_id=$2", [req.params.id, req.userId]);
    res.json({ success: true });
  });

  app.delete("/api/expenses/:id", auth, async (req, res) => {
    await pool.query("DELETE FROM expenses WHERE id=$1 AND user_id=$2", [req.params.id, req.userId]);
    res.json({ success: true });
  });

  app.put("/api/income", auth, async (req, res) => {
    await pool.query("UPDATE settings SET monthly_income=$1 WHERE user_id=$2", [req.body.income, req.userId]);
    res.json({ success: true });
  });

  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Budget Tracking running on port ${PORT}`));
}

start();
