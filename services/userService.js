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

// services/userService.js
async function upsertUserKey(userIdentifier, apiKey, status, passwordHash = null) {
  const db = getDb();
  const [existing] = await db.query(
    'SELECT id FROM users WHERE user_identifier = ?',
    [userIdentifier]
  );

  if (existing.length) {
    const fields = ['subscription_status = ?', 'updated_at = NOW()'];
    const values = [status];

    if (apiKey) {
      fields.unshift('api_key = ?');
      values.unshift(apiKey);
    }
    if (passwordHash) {
      fields.unshift('password_hash = ?');
      values.unshift(passwordHash);
    }

    await db.query(
      `UPDATE users SET ${fields.join(', ')} WHERE id = ?`,
      [...values, existing[0].id]
    );
  } else {
    await db.query(
      'INSERT INTO users (user_identifier, api_key, subscription_status, password_hash, email) VALUES (?, ?, ?, ?, ?)',
      [userIdentifier, apiKey, status, passwordHash, userIdentifier]
    );
  }
}

module.exports = { findUserByApiKey, findUserByEmail, upsertUserKey };
