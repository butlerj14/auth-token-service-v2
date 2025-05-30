// server.js
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const { Pool } = require('pg');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
app.set('trust proxy', 1);
app.use(cors());
app.use(bodyParser.json());

// Rate limiting for token endpoint
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10 // limit each IP to 10 requests per minute
});
app.use('/get-auth-token', limiter);

// PostgreSQL connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Middleware to verify JWT
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid token' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.tokenPayload = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Token verification failed' });
  }
}

// Protected endpoint example
app.get('/protected', verifyToken, async (req, res) => {
  const clientId = req.tokenPayload.client_id;

  try {
    const result = await pool.query(
      'SELECT * FROM clients WHERE client_id = $1',
      [clientId]
    );
    res.json({ data: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Issue a short-lived JWT
app.post('/get-auth-token', async (req, res) => {
  const { client_id, shared_secret } = req.body;

  if (!client_id || !shared_secret) {
    return res.status(400).json({ error: 'Missing client_id or shared_secret' });
  }

  try {
    const result = await pool.query(
      'SELECT api_key, shared_secret FROM clients WHERE client_id = $1',
      [client_id]
    );
    const client = result.rows[0];

    if (!client || client.shared_secret !== shared_secret) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const apiKey = client.api_key;
    const halfApiKey = apiKey.substring(0, 16);

    const tokenPayload = {
      client_id,
      half_api_key: halfApiKey
    };

    const token = jwt.sign(tokenPayload, process.env.JWT_SECRET, { expiresIn: '15m' });

    res.json({ token: `Bearer ${token}` });
  } catch (error) {
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Admin-only: add or update a client
app.post('/add-client', async (req, res) => {
  const { client_id, api_key, shared_secret, admin_secret } = req.body;

  if (admin_secret !== process.env.ADMIN_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  if (!client_id || !api_key || !shared_secret) {
    return res.status(400).json({ error: 'Missing client_id, api_key, or shared_secret' });
  }

  try {
    await pool.query(
      'INSERT INTO clients (client_id, api_key, shared_secret) VALUES ($1, $2, $3) ON CONFLICT (client_id) DO UPDATE SET api_key = $2, shared_secret = $3',
      [client_id, api_key, shared_secret]
    );
    res.json({ success: true, message: `Client ${client_id} added/updated.` });
  } catch (error) {
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Auth service running on port ${PORT}`));
