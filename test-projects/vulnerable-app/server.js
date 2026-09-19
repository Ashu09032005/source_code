const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');

const app = express();
app.use(express.urlencoded({ extended: true }));

app.post('/login', (req, res) => {
  const user = req.body.username;
  const query = "SELECT * FROM users WHERE name = '" + user + "'";
  db.query(query, (err, result) => res.json(result));
});

app.get('/files', (req, res) => {
  const file = req.query.file;
  const content = fs.readFileSync('./uploads/' + file, 'utf8');
  res.send(content);
});

app.get('/run', (req, res) => {
  const cmd = req.query.cmd;
  exec('ls ' + cmd, (err, out) => res.send(out));
});

app.listen(3001);
