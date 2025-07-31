require('dotenv').config();

const requiredEnv = [
  'PORT', 'TARGET_URL', 'DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME',
  'JWT_SECRET', 'ADMIN_SECRET_KEY', 'APP_BASE_URL'
];
requiredEnv.forEach(key => {
  if (!process.env[key]) {
    console.error(`FATAL: Missing env var ${key}`);
    process.exit(1);
  }
});

module.exports = {
  port: parseInt(process.env.PORT, 10),
  useHttps: process.env.USE_HTTPS === 'true',
  targetUrl: process.env.TARGET_URL,
  db: {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
  },
  jwtSecret: process.env.JWT_SECRET,
  adminSecret: process.env.ADMIN_SECRET_KEY,
  appBaseUrl: process.env.APP_BASE_URL,
};