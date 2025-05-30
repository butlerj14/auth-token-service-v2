// server.js
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const { Pool } = require('pg');
const bodyParser = require('body-parser');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

// PostgreSQL connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // Render internal DB still requires SSL
});

// GET AUTH TOKEN
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
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const halfApiKey = apiKey.substring(0, 16);
    const securityHash = crypto.createHash('md5').update(timestamp + apiKey).digest('hex');

    const payload = {
      half_api_key: halfApiKey,
      message_timestamp: timestamp,
      security_hash: securityHash
    };

    const base64 = Buffer.from(JSON.stringify(payload)).toString('base64');
    res.json({ token: `Bearer ${base64}` });
  } catch (error) {
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});


// ADD/UPDATE CLIENT (admin protected)
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
