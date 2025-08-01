const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const router = express.Router();
const { jwtSecret, appBaseUrl } = require('../config');
const { upsertUserKey, findUserByEmail, findUserByApiKey } = require('../services/userService');
const { generateToken, consumeToken } = require('../services/tokenService');

router.get('/login', (req, res) => {
  res.send(`
    <form method="POST" action="/login">
      <input name="email"    type="email"    placeholder="Email"    required />
      <input name="password" type="password" placeholder="Password" required />
      <button type="submit">Log In</button>
    </form>
  `);
});

router.post('/login', express.urlencoded({ extended: true }), async (req, res) => {
  const { email, password } = req.body;
  const user = await findUserByEmail(email);
  console.log('Login attempt for:', email, 'User found:', !!user);
  if (!user || !(await bcrypt.compare(password, user.password_hash)))
    return res.status(401).send('Invalid');
  if (user.subscription_status !== 'active')
    return res.status(403).send('Inactive');
  const token = jwt.sign({ api_key: user.api_key }, jwtSecret, { expiresIn:'1h' });
  res.cookie('auth_token', token, { httpOnly:true, secure:true, sameSite:'lax' });
  res.redirect('/');
});

router.post('/register', express.urlencoded({ extended: true }), async (req, res) => {
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

router.get('/auth-launch', async (req, res) => {
  const raw = req.query.token || req.headers['vue-auth'];
  const apiKey = consumeToken(raw) || (await findUserByApiKey(req.headers['vue-email']))?.api_key;
  if (!apiKey) return res.status(403).send('Forbidden');
  const jwtToken = jwt.sign({ api_key: apiKey }, jwtSecret, { expiresIn:'1h' });
  res.cookie('auth_token', jwtToken, { httpOnly:true, secure:true, sameSite:'lax' });
  res.redirect('/');
});

router.get('/api/create-launch-token', async (req, res) => {
  const auth = req.headers.authorization;
  const apiKey = auth?.split(' ')[1];
  const user = await findUserByApiKey(apiKey);
  if (!user || user.subscription_status!=='active')
    return res.status(401).send('Unauthorized');
  const token = generateToken(apiKey);
  res.json({ launch_url: `${appBaseUrl}/auth-launch?token=${token}` });
});

module.exports = router;
