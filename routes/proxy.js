const { createProxyMiddleware } = require('http-proxy-middleware');
const { targetUrl } = require('../config');
const zlib = require('zlib');
const { DISALLOWED_EXTENSIONS = [] } = {};

module.exports = createProxyMiddleware({
  target: targetUrl,
  changeOrigin: true,
  ws: true,
  //pathRewrite: (path) => path,
  onProxyReq: (proxyReq, req) => {
    onsole.log('🔁 Proxying request to:', req.url);
    if (req.user?.email) proxyReq.setHeader('VUE-EMAIL', req.user.email);
    proxyReq.setHeader('VUE-AUTH', 'AE8A774F-1DE0-4F98-B037-659645706A66'); 
    proxyReq.setHeader('TBA-PLAN-TIER', 'Tier1');  
    console.log('Injecting headers into proxy:', {
        'VUE-AUTH': 'STATIC_TOKEN_12345',
        'TBA-PLAN-TIER': 'pro',
        'VUE-EMAIL': req.user?.email
  });

  },
  onProxyRes: (proxyRes, req, res) => {
    // minimal rewrite logic
    proxyRes.pipe(res);
  },
});
