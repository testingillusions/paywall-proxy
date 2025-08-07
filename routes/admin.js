const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { adminSecret } = require('../config');
const { upsertUserKey } = require('../services/userService');

function adminAuth(req, res, next) {
  const key = req.headers['x-admin-secret'] || req.query.adminSecret;
  if (key !== adminSecret) return res.status(403).send('Forbidden');
  next();
}

router.post('/api/generate-token', adminAuth, async (req, res) => {
  const { userIdentifier, subscriptionStatus='active' } = req.body;
  if (!userIdentifier) return res.status(400).json({ error:'userIdentifier required' });
  const apiKey = crypto.randomBytes(32).toString('hex');
  await upsertUserKey(userIdentifier, apiKey, subscriptionStatus);
  res.json({ userIdentifier, apiKey, subscriptionStatus });
});

router.post('/api/update-subscription-status', adminAuth, async (req, res) => {
  const { userIdentifier, subscriptionStatus } = req.body;
  if (!userIdentifier||!subscriptionStatus) return res.status(400).json({ error:'fields required' });
  await upsertUserKey(userIdentifier, null, subscriptionStatus);
  res.json({ userIdentifier, subscriptionStatus });
});

router.post('/api/register', express.urlencoded({ extended: true }), async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).send('Missing email or password');
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const userIdentifier = email;
  const apiKey = crypto.randomBytes(32).toString('hex');

  await upsertUserKey(userIdentifier, apiKey, 'active', passwordHash);

  res.status(201).json({ message: 'User registered', apiKey });
});



module.exports = router;
