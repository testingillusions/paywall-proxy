const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const router = express.Router();
const { jwtSecret, appBaseUrl,vueAPI} = require('../config');
const { upsertUserKey, findUserByEmail, findUserByApiKey } = require('../services/userService');
const { generateToken, consumeToken } = require('../services/tokenService');


// Paths for Login via Username/Password
router.get('/api/login', (req, res) => {
  res.send(`
    <form method="POST" action="/login">
      <input name="email"    type="email"    placeholder="Email"    required />
      <input name="password" type="password" placeholder="Password" required />
      <button type="submit">Log In</button>
    </form>
  `);
});

router.post('/api/login', express.urlencoded({ extended: true }), async (req, res) => {
  const { email, password } = req.body;
  const user = await findUserByEmail(email);
  console.log('Login attempt for:', email, 'User found:', !!user);
  if (!user || !(await bcrypt.compare(password, user.password_hash)))
    return res.status(401).send('Invalid');
  if (user.subscription_status !== 'active')
    return res.status(403).send('Inactive');
  const token = jwt.sign({ api_key: user.api_key }, jwtSecret, { expiresIn:'1h' });
  res.cookie('auth_token', token, { httpOnly:true, secure:true, sameSite:'lax' });
  res.send(200, { message: 'Login successful' });
});


// Path for Vue Launch
// Requires VUE API Key and Email in headers
router.get('/api/vue-launch', async (req, res) => {
  const vueAuthToken = req.headers['vue-auth'];
  if (!vueAuthToken) return res.status(403).send('Forbidden');
  if (vueAuthToken !== vueAPI) return res.status(403).send('Forbidden');
  
  // Get API key from Proxy DB
  const apiKey = (await findUserByApiKey(req.headers['vue-email']))?.api_key;
  if (!apiKey) return res.status(403).send('Forbidden');
  const jwtToken = jwt.sign({ api_key: apiKey, email: req.headers['vue-email']}, jwtSecret, { expiresIn:'1h' });
  res.cookie('auth_token', jwtToken, { httpOnly:true, secure:true, sameSite:'lax',path: '/' });
  res.send(`
    <html>
      <head>
        <title>Redirecting...</title>
        <script>
          // Break out of iframe and go to secured path
          if (window.top !== window.self) {
            window.top.location = 'http://tba.testingillusions.com/';
          } else {
            window.location = 'http://tba.testingillusions.com/';
          }
        </script>
      </head>
      <body>
        Redirecting...
      </body>
    </html>
  `);
});


// Path for Auth Check from NGINX
// Requires JWT cookie
// Returns 401 if no cookie or invalid
// Returns 200 with email in header if valid
router.all('/api/auth', (req, res) => {
    const token = req.cookies['auth_token'];

    if (!token) {
        return res.status(401).json({ message: 'Unauthorized: No token' });
    }

    try {
        const decoded = jwt.verify(token, jwtSecret);
        res.set('X-Authenticated-Email', decoded.email);
        return res.status(200).json({ user: decoded.email });

    } catch (err) {
        return res.status(401).json({ message: 'Unauthorized: Invalid token' });
    }
});



module.exports = router;


/* 
router.get('/api/create-launch-token', async (req, res) => {
  const auth = req.headers.authorization;
  const apiKey = auth?.split(' ')[1];
  const user = await findUserByApiKey(apiKey);
  if (!user || user.subscription_status!=='active')
    return res.status(401).send('Unauthorized');
  const token = generateToken(apiKey);
  res.json({ launch_url: `${appBaseUrl}/auth-launch?token=${token}` });
});
 */