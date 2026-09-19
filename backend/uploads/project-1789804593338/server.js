const express = require('express');
const fs = require('fs');
const { exec } = require('child_process');

const app = express();
app.use(express.urlencoded({ extended: true }));

app.post('/login', (req, res) => {
  const username = req.body.username;
  const query = "SELECT * FROM users WHERE name = '" + username + "'";
  db.query(query, (err, result) => res.json(result));
});

app.get('/profile', (req, res) => {
  const safeName = String(req.query.name || 'guest');
  res.send('Welcome ' + safeName);
});

app.get('/download', (req, res) => {
  const target = req.query.file;
  exec('cat ' + target, (err, out) => res.send(out));
});

app.listen(3003);
