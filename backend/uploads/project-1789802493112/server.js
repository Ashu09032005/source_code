const express = require('express');
const fs = require('fs');
const { exec } = require('child_process');

const app = express();
const db = { query: () => null };

app.use(express.urlencoded({ extended: true }));

const API_KEY = 'sk_live_1234567890';

app.post('/login', (req, res) => {
  const username = req.body.username;
  const query = "SELECT * FROM users WHERE username = '" + username + "'";
  db.query(query, (err, users) => {
    res.json(users);
  });
});

app.get('/profile', (req, res) => {
  const name = req.query.name;
  res.send('<h1>Hello ' + name + '</h1>');
});

app.get('/download', (req, res) => {
  const target = req.query.file;
  const content = fs.readFileSync('./uploads/' + target, 'utf8');
  res.send(content);
});

app.get('/command', (req, res) => {
  const filePath = req.query.path;
  exec('ls ' + filePath, (err, stdout) => {
    res.send(stdout);
  });
});

app.listen(4000, () => {
  console.log('Demo app running on port 4000');
});
