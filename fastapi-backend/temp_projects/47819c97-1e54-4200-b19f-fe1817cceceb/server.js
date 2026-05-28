const express = require("express");
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 🔴 Reflected XSS
app.get("/search", (req, res) => {
  const q = req.query.q;
  res.send(`<h1>Search Results for: ${q}</h1>`);
});

// 🔴 Insecure Login (No rate limit)
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (username === "admin" && password === "admin123") {
    res.send("Login successful!");
  } else {
    res.status(401).send("Invalid credentials");
  }
});

// 🔴 Command Injection
app.get("/ping", (req, res) => {
  const { exec } = require("child_process");
  const host = req.query.host;

  exec(`ping -c 1 ${host}`, (err, stdout, stderr) => {
    if (err) {
      return res.send(stderr);
    }
    res.send(`<pre>${stdout}</pre>`);
  });
});

// 🔴 Sensitive Data Exposure
app.get("/config", (req, res) => {
  res.json({
    db_password: "supersecret123",
    api_key: "12345-ABCDE"
  });
});

app.listen(8000, () => {
  console.log("Vulnerable app running on port 8000");
});