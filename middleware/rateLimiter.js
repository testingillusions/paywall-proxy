const rateLimit = require('express-rate-limit');

module.exports = rateLimit({
  windowMs: 15*60*1000,
  max: 100,
  statusCode: 429,
  handler: (req, res) => res.status(429).send('Too many requests'),
});
