const crypto = require('crypto');
const launchTokens = new Map(); // token -> { apiKey, expires }

function generateToken(apiKey, email, ttlMs = 60000) {
  const token = crypto.randomBytes(24).toString('hex');
  console.log(`Generated token: ${token} for API Key: ${apiKey} and Email: ${email}`);
  launchTokens.set(token, {
    apiKey: apiKey,
    email: email,
    expires: Date.now() + ttlMs,
  });
  return token;
}

function consumeToken(token) {
  const entry = launchTokens.get(token);
  console.log(`Consuming token: ${token} - Entry found: ${!!entry}`);
  console.log(`Token entry details: ${JSON.stringify(entry)}`);
  if (!entry || Date.now() > entry.expires) return null;
  launchTokens.delete(token);
  return entry.apiKey, entry.email;
}

module.exports = { generateToken, consumeToken };
