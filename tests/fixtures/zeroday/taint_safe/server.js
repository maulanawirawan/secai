// FP-CONTROL fixture: safe versions; taint_engine must report nothing.
const path = require('path');
const { execFile } = require('child_process');
app.get('/ping', (req, res) => {
  const host = req.query.host;
  execFile('ping', ['-c', '1', host], (e, out) => res.send(out));
});
app.get('/user', (req, res) => {
  db.query('SELECT * FROM users WHERE name = ?', [req.query.name], (e, r) => res.json(r));
});
app.get('/id', (req, res) => {
  const id = parseInt(req.query.id, 10);
  db.query('SELECT * FROM t WHERE id = ' + id, (e, r) => res.json(r));
});
app.get('/file', (req, res) => res.sendFile(path.join('/srv/files', path.basename(req.query.f))));
app.get('/re', (req, res) => { const m = /a(b)/.exec(req.query.s); res.json(m); });
app.get('/go', (req, res) => res.redirect('/home'));
