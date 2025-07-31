const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { jwtSecret } = require('../config');
const { findUserByApiKey } = require('../services/userService');

const excluded = [
  '/assets/', '/css/', '/js/', '/images/', '/favicon.ico',
  '/api/generate-token','/api/update-subscription-status','/healthcheck'
];

async function paywall(req, res, next) {
  if (excluded.some(p => req.path.startsWith(p))) return next();
  let apiKey;
  const token = req.cookies?.auth_token;
  if (token) {
    try {
      const dec = jwt.verify(token, jwtSecret);
      apiKey = dec.api_key;
    } catch { /* invalid */ }
  }
  apiKey = apiKey || (req.headers.authorization||'').split(' ')[1];

  if (!apiKey) return res.redirect('/login');
  const user = await findUserByApiKey(apiKey);
  if (!user || user.subscription_status !== 'active') {
    res.clearCookie('auth_token');
    return res.status(401).send('Unauthorized');
  }
  req.user = user;
  if (!token) {
    const newToken = jwt.sign({ api_key: apiKey }, jwtSecret, { expiresIn: '1h' });
    res.cookie('auth_token', newToken, { httpOnly:true, secure:true, sameSite:'lax' });
  }
  next();
}

module.exports = [cookieParser(), paywall];
