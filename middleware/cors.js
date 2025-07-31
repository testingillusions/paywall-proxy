const cors = require('cors');
const allowedOrigins = ['https://testingillusions.com', 'https://tba.vueocity.com'];

module.exports = cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    callback(new Error('Not allowed by CORS'));
  },
  methods: ['GET','POST','OPTIONS'],
  allowedHeaders: ['Authorization','Content-Type'],
  credentials: true,
});
