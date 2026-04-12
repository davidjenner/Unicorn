'use strict';

const express    = require('express');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const cors       = require('cors');
const path       = require('path');
const { runScan, validateUrl } = require('./lib/scanner');

const app  = express();
const PORT = process.env.PORT || 5000;

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '10kb' }));
app.use(cors({
  origin: process.env.CLIENT_URL || ['http://localhost:5173', 'http://localhost:4173'],
  methods: ['GET', 'POST'],
}));

// 10 scans per 15 minutes per IP
app.use('/api/scan', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Rate limit reached. Please wait before scanning again.' },
  standardHeaders: true,
  legacyHeaders: false,
}));

app.post('/api/scan', async (req, res) => {
  const { url, consent } = req.body;
  if (!consent)
    return res.status(400).json({ error: 'You must confirm authorization to scan this website.' });
  if (!url || typeof url !== 'string' || url.length > 500)
    return res.status(400).json({ error: 'A valid URL is required.' });

  const result = await runScan(url.trim());
  if (result.error) return res.status(400).json(result);
  res.json(result);
});

app.get('/api/health', (_req, res) => res.json({ status: 'ok', version: '2.0.0' }));

// Serve built frontend in production
app.use(express.static(path.join(__dirname, 'dist')));
app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'dist', 'index.html')));

app.listen(PORT, () => console.log(`Unicorn Scanner v2 → http://localhost:${PORT}`));
