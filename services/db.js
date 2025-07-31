const mysql = require('mysql2/promise');
const { db: dbConfig } = require('../config');

let pool;
async function initDb() {
  pool = mysql.createPool(dbConfig);
  await pool.query('SELECT 1');
  console.info('Database connected');
}
function getDb() {
  if (!pool) throw new Error('Pool not initialized');
  return pool;
}
module.exports = { initDb, getDb };
