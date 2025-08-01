const express = require('express');
const helmet = require('helmet');
const morgan = require('morgan');
const config = require('./config');
const { initDb } = require('./services/db');
const corsMiddleware = require('./middleware/cors');
const paywall = require('./middleware/paywall');
const rateLimiter = require('./middleware/rateLimiter');
const errorHandler = require('./middleware/errorHandler');

const healthRouter = require('./routes/health');
const authRouter = require('./routes/auth');
const adminRouter = require('./routes/admin');
const proxyMiddleware = require('./routes/proxy');

async function start() {
  await initDb();
  const app = express();
  app.use(helmet());
  app.use(morgan('combined'));
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  

  app.use('/healthcheck', healthRouter);
  app.use(authRouter);
  app.use(adminRouter);
  
  app.use(corsMiddleware);
  // index.js, before any middleware
  app.set('trust proxy', 1);

  app.use(paywall);
  app.use(rateLimiter);
  app.use('/', proxyMiddleware);

  app.use(errorHandler);

  const server = (config.useHttps
    ? require('https').createServer({ /* certs */ }, app)
    : require('http').createServer(app)
  );

  server.listen(config.port, () => {
    console.log(`Server listening on port ${config.port}`);
  });
}

start().catch(err => {
  console.error('Failed to start server', err);
  process.exit(1);
});
