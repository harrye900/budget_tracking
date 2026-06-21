const express = require("express");
const { Pool } = require("pg");
const path = require("path");
const crypto = require("crypto");

const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

const sessions = {};

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

  app.use(express.json());
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
    res.json({ token });
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
