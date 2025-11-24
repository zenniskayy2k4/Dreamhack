import express from 'express';
import axios from 'axios';
import path from 'path';

const app = express();

const FLAG = 'null{REDACTED}';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get('/', (req, res) => {
  return res.sendFile(path.join(__dirname, "..", "greet.html"));
});

/**
 * @description Private API
 */
app.get('/api', (req, res) => {
  if (req.ip !== '::1') return res.send('No');

  const isAdmin = Number(req.query.admin);

  console.log('isAdmin', isAdmin);

  if (isAdmin !== 0) {
    return res.send(FLAG);
  }
  return res.send(`${req.query.msg} ❤️`);
});

app.post('/greet', async (req, res) => {
  const msg = String(req.body.msg);
  if (msg.includes('admin') || msg.includes('\\') || msg.includes('%') || msg.includes('?') || msg.includes(';') || msg.includes('#') || msg.includes('[') || msg.includes(']')) return res.json({ result: 'Not allowed character' });

  const resp = await axios.get(`http://localhost:3000/api?msg=${msg}&admin=0`);

  return res.json({ result: resp.data });
});

app.listen(3000);