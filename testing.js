// proxy-server.js
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();

// Change this to wherever you want to forward traffic
const TARGET_URL = 'http://example.com';

app.use(
  '/',
  createProxyMiddleware({
    target: TARGET_URL,
    changeOrigin: true,
    onProxyReq: (proxyReq, req, res) => {
      // Add or overwrite a header on the outgoing (proxied) request:
      proxyReq.setHeader('X-Added-Header', 'my-custom-value');
    }
  })
);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Proxy listening on http://localhost:${PORT} → ${TARGET_URL}`);
});