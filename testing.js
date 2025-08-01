// proxy-server.js
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();
const PORT = 3000;

// ① Point this at your Beeceptor endpoint (or any https://… you want)
const TARGET = 'https://echo.free.beeceptor.com';

app.use(
  '/',
  createProxyMiddleware({
    target: TARGET,
    changeOrigin: true,
    secure: true,        // verify SSL certs
    logLevel: 'debug',   // so you can see onProxyReq logs
    onProxyReq: (proxyReq, req, res) => {
      proxyReq.setHeader('X-Added-Header', 'my-custom-value');
      console.log('👉 Injected X-Added-Header into proxied request');
    },
  })
);

app.listen(PORT, () => {
  console.log(`Proxy listening on http://localhost:${PORT} → ${TARGET}`);
});