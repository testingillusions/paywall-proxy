const { getDb } = require('./db');

async function findUserByApiKey(apiKey) {
  const [rows] = await getDb().query(
    'SELECT user_identifier, subscription_status, email, password_hash, api_key FROM users WHERE api_key = ?',
    [apiKey]
  );
  return rows[0];
}

async function findUserByEmail(email) {
  const [rows] = await getDb().query(
    'SELECT api_key, user_identifier, subscription_status, password_hash FROM users WHERE email = ?',
    [email]
  );
  return rows[0];
}

async function upsertUserKey(userIdentifier, apiKey, status) {
  const db = getDb();
  const [existing] = await db.query(
    'SELECT id FROM users WHERE user_identifier = ?',
    [userIdentifier]
  );
  if (existing.length) {
    await db.query(
      'UPDATE users SET api_key = ?, subscription_status = ?, updated_at = NOW() WHERE id = ?',
      [apiKey, status, existing[0].id]
    );
  } else {
    await db.query(
      'INSERT INTO users (user_identifier, api_key, subscription_status) VALUES (?, ?, ?)',
      [userIdentifier, apiKey, status]
    );
  }
}

module.exports = { findUserByApiKey, findUserByEmail, upsertUserKey };
