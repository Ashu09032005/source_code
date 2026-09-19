const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.urlencoded({ extended: true }));

app.post('/login', (req, res) => {
  const user = String(req.body.username || '').trim();
  const query = 'SELECT * FROM users WHERE name = ?';
  db.query(query, [user], (err, result) => res.json(result));
});

app.get('/files', (req, res) => {
  const file = String(req.query.file || '').trim();
  const safePath = path.join(__dirname, 'safe', path.basename(file));
  const content = fs.readFileSync(safePath, 'utf8');
  res.send(content);
});

app.get('/hello', (req, res) => {
  const name = String(req.query.name || 'Guest');
  res.send('<h1>Hello ' + name + '</h1>');
});

app.listen(3002);
