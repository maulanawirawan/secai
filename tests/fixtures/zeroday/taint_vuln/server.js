// DELIBERATELY VULNERABLE fixture for tools/taint_engine.py — never run.
const express = require('express');
const { exec } = require('child_process');
const axios = require('axios');
const app = express();
app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec('ping -c 1 ' + host, (e, out) => res.send(out));
});
app.get('/user', (req, res) => {
  const { name } = req.query;
  db.query(`SELECT * FROM users WHERE name = '${name}'`, (e, r) => res.json(r));
});
app.get('/file', (req, res) => {
  res.sendFile('/srv/files/' + req.query.f);
});
app.get('/go', (req, res) => res.redirect(req.query.next));
app.get('/fetch', async (req, res) => {
  const r = await axios.get(req.query.url);
  res.send(r.data);
});
app.post('/calc', (req, res) => res.send(String(eval(req.body.expr))));
