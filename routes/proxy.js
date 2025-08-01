const { createProxyMiddleware } = require('http-proxy-middleware');
const { targetUrl } = require('../config');
const zlib = require('zlib');
const { DISALLOWED_EXTENSIONS = [] } = {};

module.exports = createProxyMiddleware({
  target: targetUrl,
  changeOrigin: true,
  ws: true,
  onProxyReq: (proxyReq, req) => {
    console.log('🔁 Proxying request to:', req.url);
    if (req.user?.email) proxyReq.setHeader('VUE-EMAIL', req.user.email);
    proxyReq.setHeader('VUE-AUTH', 'AE8A774F-1DE0-4F98-B037-659645706A66'); 
    proxyReq.setHeader('TBA-PLAN-TIER', 'Tier1');  
  },
  onProxyRes: (proxyRes, req, res) => {
    console.log('🔁 Proxying onProxyRes:', req.url);
    // minimal rewrite logic
    proxyRes.pipe(res);
  },
});
