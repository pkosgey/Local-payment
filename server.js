require('dotenv').config();
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const app = express();

// Serve static files (frontend page)
app.use(express.static('public'));

// Webhook route must be placed before express.json() and use raw body
app.post('/webhook/paystack', express.raw({ type: 'application/json' }), (req, res) => {
  const signature = req.headers['x-paystack-signature'];
  const secret = process.env.PAYSTACK_SECRET_KEY;

  // Paystack uses HMAC-SHA512 to sign the raw body [citation:4][citation:5]
  const expected = crypto.createHmac('sha512', secret).update(req.body).digest('hex');

  if (signature !== expected) {
    return res.status(401).send('Invalid signature');
  }

  const event = JSON.parse(req.body);
  if (event.event === 'charge.success') {
    console.log('Webhook: Payment successful, reference:', event.data.reference);
    // Mark the order as paid in the database here
  }

  res.sendStatus(200);
});

// Normal JSON parsing for other routes
app.use(express.json());

// Verification endpoint: frontend calls this after payment callback
app.get('/api/verify/:reference', async (req, res) => {
  try {
    const response = await axios.get(
      `https://api.paystack.co/transaction/verify/${req.params.reference}`,
      { headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` } }
    );

    const data = response.data.data;

    // Must verify amount and status [citation:9]
    if (data.status === 'success') {
      res.json({ status: 'success', amount: data.amount });
    } else {
      res.status(400).json({ status: 'failed' });
    }
  } catch (error) {
    res.status(500).json({ status: 'error', message: error.message });
  }
});

module.exports = app;