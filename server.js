const express = require('express');
const fs = require('fs');
const app = express();

app.use(express.json());
app.use(express.static(__dirname));

let users = {};

function logEvent(event, user, ip) {
  const log = `${new Date().toISOString()} | ${event} | user=${user} | ip=${ip}\n`;
  fs.appendFileSync('security.log', log);
}

app.post('/register', (req, res) => {
  const { user, pass } = req.body;
  users[user] = pass;
  logEvent('REGISTER', user, req.ip);
  res.sendStatus(200);
});

app.post('/login', (req, res) => {
  const { user, pass } = req.body;

  if (users[user] && users[user] === pass) {
    logEvent('LOGIN_SUCCESS', user, req.ip);
    res.sendStatus(200);
  } else {
    logEvent('LOGIN_FAIL', user, req.ip);
    res.sendStatus(401);
  }
});

app.listen(3000, () => {
  console.log('Servidor activo en http://localhost:3000');
});
