// proxy-server.js
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();
const PORT = 3000;

// ① Point this at your Beeceptor endpoint (or any https://… you want)
const TARGET = 'https://echo.free.beeceptor.com';

app.use((req, res, next) => {
  // Add a new custom header
  req.headers['x-custom-header'] = 'MyCustomValue';

  // Modify an existing header (e.g., User-Agent)
  // req.headers['user-agent'] = 'ModifiedUserAgent';

  next(); // Pass control to the next middleware or route handler
});

app.use(
  '/',
  createProxyMiddleware({
    target: TARGET,
    changeOrigin: true,
    secure: true,        // verify SSL certs
    logLevel: 'debug',   // so you can see onProxyReq logs
    headers: {
        'Authorization': 'Bearer YOUR_AUTH_TOKEN', // Add an authorization header
        'X-Custom-Header': 'My-Value',             // Add a custom header
        'User-Agent': 'MyProxyClient'             // Overwrite the User-Agent header
    },
    onProxyReq: (proxyReq, req, res) => {
      proxyReq.setHeader('X-Added-Header', 'my-custom-value');
      console.log('👉 Injected X-Added-Header into proxied request');
    },
  })
);

app.listen(PORT, () => {
  console.log(`Proxy listening on http://localhost:${PORT} → ${TARGET}`);
});