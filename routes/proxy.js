const { createProxyMiddleware } = require('http-proxy-middleware');
const { targetUrl } = require('../config');
const zlib = require('zlib');
const { DISALLOWED_EXTENSIONS = [] } = {};

module.exports = createProxyMiddleware({
  target: targetUrl,
  changeOrigin: true,
  ws: true,
  headers: {
    'VUE-EMAIL': req.user.email,
    'VUE-AUTH': 'AE8A774F-1DE0-4F98-B037-659645706A66',
    'TBA-PLAN-TIER': 'Tier1'
  },
  pathRewrite: (path) => path,
  onProxyRes: (proxyRes, req, res) => {
    console.log('🔁 Proxying onProxyRes:', req.url);
    // minimal rewrite logic
    proxyRes.pipe(res);
  },
});
