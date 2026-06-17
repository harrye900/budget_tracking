const express = require("express");
const initSqlJs = require("sql.js");
const fs = require("fs");
const path = require("path");

const app = express();
const DB_PATH = path.join(__dirname, "budget.db");

let db;

async function start() {
  const SQL = await initSqlJs();

  if (fs.existsSync(DB_PATH)) {
    db = new SQL.Database(fs.readFileSync(DB_PATH));
  } else {
    db = new SQL.Database();
  }

  db.run(`
    CREATE TABLE IF NOT EXISTS expenses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      category TEXT NOT NULL,
      description TEXT,
      amount REAL NOT NULL,
      date TEXT NOT NULL,
      paid INTEGER DEFAULT 0
    )
  `);
  db.run(`CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY, monthly_income REAL NOT NULL)`);
  db.run(`INSERT OR IGNORE INTO settings (id, monthly_income) VALUES (1, 15076)`);
  save();

  app.use(express.json());
  app.use(express.static(path.join(__dirname, "public")));

  app.get("/api/dashboard", (req, res) => {
    const income = db.exec("SELECT monthly_income FROM settings WHERE id=1")[0].values[0][0];
    const month = new Date().toISOString().slice(0, 7);

    const expRows = db.exec(`SELECT id, category, description, amount, date, paid FROM expenses WHERE date LIKE '${month}%' ORDER BY date DESC`);
    const expenses = expRows.length ? expRows[0].values.map(r => ({ id: r[0], category: r[1], description: r[2], amount: r[3], date: r[4], paid: r[5] })) : [];

    const catRows = db.exec(`SELECT category, SUM(amount) as total FROM expenses WHERE date LIKE '${month}%' GROUP BY category ORDER BY total DESC`);
    const byCategory = catRows.length ? catRows[0].values.map(r => ({ category: r[0], total: r[1] })) : [];

    const totalSpent = byCategory.reduce((s, r) => s + r.total, 0);
    res.json({ income, totalSpent, savings: income - totalSpent, expenses, byCategory });
  });

  app.post("/api/expenses", (req, res) => {
    const { category, description, amount, date } = req.body;
    db.run("INSERT INTO expenses (category, description, amount, date, paid) VALUES (?,?,?,?,0)", [category, description, amount, date]);
    save();
    const id = db.exec("SELECT last_insert_rowid()")[0].values[0][0];
    res.json({ id });
  });

  app.patch("/api/expenses/:id/toggle", (req, res) => {
    db.run("UPDATE expenses SET paid = CASE WHEN paid=1 THEN 0 ELSE 1 END WHERE id=?", [req.params.id]);
    save();
    res.json({ success: true });
  });

  app.delete("/api/expenses/:id", (req, res) => {
    db.run("DELETE FROM expenses WHERE id=?", [req.params.id]);
    save();
    res.json({ success: true });
  });

  app.put("/api/income", (req, res) => {
    db.run("UPDATE settings SET monthly_income=? WHERE id=1", [req.body.income]);
    save();
    res.json({ success: true });
  });

  app.listen(3000, () => console.log("Budget Tracker running at http://localhost:3000"));
}

function save() {
  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

start();
