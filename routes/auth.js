const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const router = express.Router();
const { jwtSecret, targetURI,vueAPI} = require('../config');
const { upsertUserKey, findUserByEmail, findUserByApiKey } = require('../services/userService');
const { generateToken, consumeToken } = require('../services/tokenService');


// Paths for Login via Username/Password
router.get('/api/login', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <link
      href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
      rel="stylesheet"
    >
    <style>
        body {
            background-color: #f8f9fa;
        }
        .login-container {
            max-width: 400px;
            margin: 80px auto;
            padding: 30px;
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-container">
            <img src="/images/tba_logo.png" alt="The Benefits Academy" class="logo">
            <h2 class="text-center mb-4">Login</h2>
            <form method="POST" action="/login">
                <div class="mb-3">
                    <label for="email" class="form-label">Email address</label>
                    <input type="email" class="form-control" name="email" id="email" required>
                </div>
                <div class="mb-3">
                    <label for="password" class="form-label">Password</label>
                    <input type="password" class="form-control" name="password" id="password" required>
                </div>
                <div class="d-grid">
                    <button type="submit" class="btn btn-primary">Sign In</button>
                </div>
            </form>
        </div>
    </div>
</body>
</html>
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
  if (!vueAuthToken) return res.status(403).send('Forbidden-001');
  if (vueAuthToken !== vueAPI) return res.status(403).send('Forbidden-002');
  
  // Get API key from Proxy DB
  const apiKey = (await findUserByEmail(req.headers['vue-email']))?.api_key;
  if (!apiKey) return res.status(403).send('Forbidden-003', vueAuthToken, req.headers['vue-email'], apiKey);
  const jwtToken = jwt.sign({ api_key: apiKey, email: req.headers['vue-email']}, jwtSecret, { expiresIn:'1h' });
  res.cookie('auth_token', jwtToken, {
      httpOnly: true,
      secure: true,        // required with SameSite=None
      sameSite: 'None',    // exact case/casing
      path: '/',
      domain: targetURI, // add this explicitly
  });
  
  res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Redirecting to Plan Comparison Tool</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <style>
    html, body {
     height: 100%;
     margin: 0;
     padding: 0;
    }
    body {
        margin: 0;
        padding: 16px;
        font-family: Arial, sans-serif;
        background: #f7f9fc;
    }

    .container {
      text-align: center;
      padding: 30px;
      border-radius: 10px;
      background-color: #fff;
      box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
    }

    h1 {
      font-size: 1.5rem;
      margin-bottom: 10px;
    }

    p {
      font-size: 1rem;
      margin-bottom: 20px;
    }

    .loader {
      border: 4px solid #f3f3f3;
      border-top: 4px solid #007BFF;
      border-radius: 50%;
      width: 30px;
      height: 30px;
      animation: spin 1s linear infinite;
      margin: 0 auto 20px;
    }

    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }

    button {
      background-color: #007BFF;
      color: #fff;
      border: none;
      padding: 12px 24px;
      border-radius: 5px;
      font-size: 1rem;
      cursor: pointer;
      transition: background-color 0.3s ease;
    }
    
    button:hover {
      background-color: #0056b3;
    }
    .container {
        margin-top: 0;
        padding-top: 0;
    }
    .loader {
        margin-bottom: 16px;
    }
    .inline-redirect {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 10px;
        flex-wrap: wrap; /* ensures wrapping on narrow iframes */
    }

    .inline-redirect p {
        margin: 0;
        font-size: 0.95rem;
    }

    .inline-redirect button {
        padding: 6px 12px;
        font-size: 0.9rem;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="loader"></div>
    <h1>Redirecting to the Plan Comparison Tool...</h1>
    <div class="inline-redirect">
        <p>If you are not redirected within a few seconds, click here:</p>
        <button id="goButton">Load PCT</button>
    </div>
  </div>

  <script>
    
    async function redirectToTool() {
      try {
        const response = await fetch('http://ec2-44-200-40-252.compute-1.amazonaws.com', {
          method: 'GET',
          headers: {
            'Authorization': 'Bearer ${apiKey}'
          }
        });

        if (!response.ok) {
          throw new Error('Server responded with ' + response.statusText);
        }

        const data = await response.json();
        console.log('Launch URL:', data.launch_url);

        if (data.launch_url) {
          if (window.top !== window.self) {
            window.top.location = data.launch_url;
          } else {
            window.location.href = data.launch_url;
          }
        } else {
          alert('launch_url not found in response');
        }
      } catch (error) {
        console.error('Error:', error);
        alert('An error occurred while redirecting. Check console for details.');
      }
    }

    document.getElementById('goButton').addEventListener('click', redirectToTool);

    // Automatically redirect after 3 seconds
    window.onload = function () {
      setTimeout(redirectToTool, 3000);
    };
  </script>
</body>
</html>		`)
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