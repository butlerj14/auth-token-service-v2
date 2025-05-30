const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const { Pool } = require('pg');
const bodyParser = require('body-parser');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Utility function to create HMAC SHA256
function createHmac(secret, payload) {
  return crypto.createHmac('sha256', secret).update(payload).digest('base64');
}

// Endpoint to generate token
app.post('/get-auth-token', async (req, res) => {
  const { client_id } = req.body;
  const receivedSignature = req.headers['x-signature'];

  if (!client_id || !receivedSignature) {
    return res.status(400).json({ error: 'Missing client_id or signature header' });
  }

  try {
    const result = await pool.query('SELECT api_key, shared_secret FROM clients WHERE client_id = $1', [client_id]);
    const row = result.rows[0];

    if (!row) return res.status(404).json({ error: 'Client not found' });

    const payload = JSON.stringify(req.body);
    const expectedSignature = createHmac(row.shared_secret, payload);

    if (receivedSignature !== expectedSignature) {
      return res.status(401).json({ error: 'Invalid signature' });
    }

    const timestamp = Math.floor(Date.now() / 1000).toString();
    const halfApiKey = row.api_key.substring(0, 16);
    const securityHash = crypto.createHash('md5').update(timestamp + row.api_key).digest('hex');

    const tokenPayload = {
      half_api_key: halfApiKey,
      message_timestamp: timestamp,
      security_hash: securityHash
    };

    const base64 = Buffer.from(JSON.stringify(tokenPayload)).toString('base64');
    res.json({ token: `Bearer ${base64}` });
  } catch (error) {
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Auth service running on port ${PORT}`));
