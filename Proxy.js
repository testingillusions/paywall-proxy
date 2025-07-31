
// =========================================
// Load Environment Variables and Modules
// =========================================
// NEW: Load environment variables from .env file
require('dotenv').config();

// Import necessary modules
const express = require('express'); // Express.js for creating the server
const { createProxyMiddleware } = require('http-proxy-middleware'); // Middleware for proxying requests
const zlib = require('zlib'); // Node.js built-in module for compression/decompression
const https = require('https'); // Import https module
const http = require('http');   // Import http module
const fs = require('fs');       // Import fs module to read certificate files
const cookieParser = require('cookie-parser'); // Import cookie-parser
const jwt = require('jsonwebtoken'); // Import jsonwebtoken
const mysql = require('mysql2/promise'); // Import mysql2 for database connection
const crypto = require('crypto'); // For generating random API keys
const rateLimit = require('express-rate-limit'); // Import express-rate-limit
const bcrypt = require('bcrypt'); //Import bcrypt for login screen 

// In memory implementation for storing launch keys. 
// NOTE: This will need to be updated if scaling the proxy is necessary. 
const launchTokens = {}; // token -> { apiKey, expires }


//Add in Health Check path for Amazon Load Balancing
const appHealth = express()
const port = 3002

appHealth.get('/healthcheck', (req, res) => res.send('Hello World!'))
appHealth.listen(port, () => console.log(`Example app listening on port ${port}!`));



// =========================================
// Initialize Express Application
// =========================================
// Initialize the Express application
const app = express();
app.use(express.json()); // Enable parsing of JSON request bodies for API endpoints
app.use('/images', express.static('public/images'));

// --- Log all incoming Express requests ---
/* app.use((req, res, next) => {
    console.log(`DEBUG: Express received request for: ${req.originalUrl}`);
    console.log('DEBUG: Incoming request headers:\n', JSON.stringify(req.headers, null, 2));
      console.log('--- Incoming Request ---');
  // Basic request line
  console.log('Method:       ', req.method);
  console.log('Original URL: ', req.originalUrl);
  console.log('Base URL:     ', req.baseUrl);
  console.log('Path:         ', req.path);
  console.log('Query params: ', req.query);
  console.log('Route params: ', req.params);

  // Headers & protocol
  console.log('Host:         ', req.get('host'));
  console.log('Protocol:     ', req.protocol);
  console.log('Secure?       ', req.secure);
  console.log('Subdomains:   ', req.subdomains);

  // Body and cookies (after body-parsers and cookieParser have run)
  console.log('Body:         ', req.body);
  console.log('Cookies:      ', req.cookies);
  console.log('SignedCookies:', req.signedCookies);

  // Client/network info
  console.log('IP:           ', req.ip);
  console.log('IPs (if behind proxy):', req.ips);
  console.log('Socket addr:  ', req.socket.remoteAddress);

  // Convenience methods
  console.log('Accepts JSON? ', req.is('application/json'));
  console.log('Accepts HTML? ', req.accepts('html'));
  console.log('XHR request?  ', req.xhr);

  // Raw headers array
  console.log('Raw headers:  ', req.rawHeaders);
    next(); // Pass the request to the next middleware (which is our proxy)
});
 */

app.use((req, res, next) => {
    const allowedOrigins = ['https://testingillusions.com', 'https://tba.vueocity.com'];
    const origin = req.headers.origin;

    if (allowedOrigins.includes(origin)) {
        res.header('Access-Control-Allow-Origin', origin);
        res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.header('Access-Control-Allow-Headers', 'Authorization, Content-Type');
        res.header('Access-Control-Allow-Credentials', 'true');
    }
    
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }

    next();
});

// --- Use cookie-parser middleware ---
app.use(cookieParser());



// =========================================
// Server Port and Target Configuration
// =========================================
// Define the port on which the proxy server will listen
// Read from .env, fallback to 443
const PORT = process.env.PORT || 443;

// Define the target URL to which requests will be proxied.
// Read from .env, fallback to default
const TARGET_URL = process.env.TARGET_URL || 'http://tba.uglyyellowbunny.com/';


// =========================================
// HTTPS Certificate Loading and Validation
// =========================================
// --- HTTPS Certificate Credentials ---
// For local deployment, these files (key.pem, cert.pem) should be in the same directory.
// Environment variables TLS_KEY_PATH and TLS_CERT_PATH are for container deployments.
let credentials = null;
// Use USE_HTTPS env var to explicitly enable HTTPS, or if PORT is 443
if (process.env.USE_HTTPS === 'true' || PORT === 443) {
    try {
        const privateKey = fs.readFileSync(process.env.TLS_KEY_PATH || 'key.pem', 'utf8');
        const certificate = fs.readFileSync(process.env.TLS_CERT_PATH || 'cert.pem', 'utf8');
        credentials = { key: privateKey, cert: certificate };
        console.log('INFO: HTTPS certificates loaded.');
    } catch (err) {
        console.error('ERROR: Could not load HTTPS certificates. Ensure key.pem/cert.pem or TLS_KEY_PATH/TLS_CERT_PATH are correct. Falling back to HTTP if port is not 443.', err.message);
        if (PORT === 443) {
            console.error('FATAL: Cannot start HTTPS server on port 443 without valid certificates. Exiting.');
            process.exit(1);
        }
    }
}
// --- END HTTPS Certificate Credentials ---



// =========================================
// MySQL Database Initialization and Validation
// =========================================
// --- MySQL Database Configuration ---
const dbConfig = {
    host: process.env.DB_HOST, // Read from .env
    user: process.env.DB_USER, // Read from .env
    password: process.env.DB_PASSWORD, // Read from .env
    database: process.env.DB_NAME // Read from .env
};

// Basic validation for DB config
if (!dbConfig.host || !dbConfig.user || !dbConfig.password || !dbConfig.database) {
    console.error('FATAL ERROR: Missing one or more required database environment variables (DB_HOST, DB_USER, DB_PASSWORD, DB_NAME). Please check your .env file.');
    process.exit(1);
}


let pool; // Connection pool for MySQL

async function initializeDatabase() {
    try {
        pool = mysql.createPool(dbConfig);
        console.log('INFO: MySQL database connection pool created successfully.');
        // Test the connection
        await pool.query('SELECT 1 + 1 AS solution');
        console.log('INFO: Successfully connected to MySQL database.');
    } catch (err) {
        console.error('FATAL ERROR: Could not connect to MySQL database:', err.message);
        process.exit(1); // Exit the process if database connection fails
    }
}

// Initialize database connection when the application starts
initializeDatabase();
// --- END MySQL Database Configuration ---



// =========================================
// API Key / Cookie-based Paywall Middleware
// =========================================
// --- PAYWALL CONFIGURATION ---
const JWT_SECRET = process.env.JWT_SECRET; // Read from .env
const AUTH_COOKIE_NAME = 'auth_token';
const ADMIN_SECRET_KEY = process.env.ADMIN_SECRET_KEY; // Read from .env

// Basic validation for app secrets
if (!JWT_SECRET || !ADMIN_SECRET_KEY) {
    console.error('FATAL ERROR: Missing one or more required application secret environment variables (JWT_SECRET, ADMIN_SECRET_KEY). Please check your .env file.');
    process.exit(1);
}

// Paywall Middleware
const EXCLUDED_PAYWALL_PATHS = [
  '/assets/', '/css/', '/js/', '/images/', '/favicon.ico',
  '/api/generate-token',
  '/api/update-subscription-status',
  '/app/modules/tba/'
];

const paywallMiddleware = async (req, res, next) => {
  try {
    const isExcluded = EXCLUDED_PAYWALL_PATHS.some(prefix => req.originalUrl.startsWith(prefix));
    if (isExcluded) {
      console.log(`INFO: Skipping paywall for: ${req.originalUrl}`);
      return next();
    }

    const apiKey = await getApiKeyFromRequest(req, res);
    if (!apiKey) {
      console.warn('WARNING: No API key or valid cookie provided.');
      return res.redirect('/login');
    }

    const user = await getUserByApiKey(apiKey);
    if (!user || user.subscription_status !== 'active') {
      console.warn(`WARNING: Access denied for API Key: ${apiKey}`);
      res.clearCookie(AUTH_COOKIE_NAME);
      return res.status(401).send('Unauthorized: Invalid or inactive API Key.');
    }

    // Attach user details to request
    req.user = {
      apiKey,
      userIdentifier: user.user_identifier,
      user_email: user.email
    };

    // Set cookie if it wasn't already valid
    if (!req.cookies[AUTH_COOKIE_NAME]) {
      const token = jwt.sign(
        { authenticated: true, api_key: apiKey, user: user.user_identifier },
        JWT_SECRET,
        { expiresIn: '1h' }
      );
      res.cookie(AUTH_COOKIE_NAME, token, {
        httpOnly: true,
        secure: true,
        sameSite: 'lax'
      });
      console.log(`INFO: Auth cookie set for ${req.originalUrl}`);
    }

    return next();

  } catch (err) {
    console.error('ERROR in paywallMiddleware:', err);
    return res.status(500).send('Internal Server Error');
  }
};

// --- Helpers ---

async function getApiKeyFromRequest(req, res) {
  const cookieToken = req.cookies[AUTH_COOKIE_NAME];
  console.log(`DEBUG: getApiKeyFromRequest called. Cookie token: ${cookieToken}`);
  console.log("DEBUG: Authorization header: ",JSON.stringify(req.headers['authorization'], null, 2));
  // 1. Try cookie
  if (cookieToken) {
    try {
      const decoded = jwt.verify(cookieToken, JWT_SECRET);
      if (decoded.authenticated && decoded.api_key) {
        return decoded.api_key;
      }
    } catch (err) {
      console.warn(`WARNING: Invalid cookie: ${err.message}`);
      res.clearCookie(AUTH_COOKIE_NAME);
    }
  }

  // 2. Try Bearer header or query param
  const header = req.headers['authorization'];

  const query = req.query.apiKey;

  if (header?.startsWith('Bearer ')) return header.split(' ')[1];
  if (query) return query;

  return null;
}

async function getUserByApiKey(apiKey) {
  const [rows] = await pool.query(
    'SELECT user_identifier, subscription_status, email FROM users WHERE api_key = ?',
    [apiKey]
  );
  return rows[0];
}
// --- END PAYWALL CONFIGURATION ---



// =========================================
// Express Rate Limiter to Prevent Abuse
// =========================================
// --- Rate Limiting Configuration ---
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again after 15 minutes.',
    statusCode: 429, // 429 Too Many Requests
    // Optional: keyGenerator can be used to limit by API key if req.user is populated
    // keyGenerator: (req) => {
    //     return req.user ? req.user.apiKey : req.ip; // Limit by API key if authenticated, else by IP
    // },
    // Optional: handler to customize response for rate-limited requests
    handler: (req, res, next) => {
        console.warn(`WARNING: Rate limit exceeded for IP: ${req.ip} (URL: ${req.originalUrl})`);
        res.status(apiLimiter.statusCode).send(apiLimiter.message);
    }
});
// --- END Rate Limiting Configuration ---



// =========================================
// Admin API Endpoints for Token Management
// =========================================
// --- API Endpoints for Token Management (for 3rd party subscription manager) ---

// Middleware to protect API management endpoints
const adminAuthMiddleware = (req, res, next) => {
    const adminKey = req.headers['x-admin-secret'] || req.query.adminSecret;
    if (adminKey === ADMIN_SECRET_KEY) {
        next();
    } else {
        console.warn('WARNING: Unauthorized access attempt to admin API.');
        res.status(403).send('Forbidden: Admin secret required.');
    }
};

// API to generate a new API key for a user
app.post('/api/generate-token', adminAuthMiddleware, async (req, res) => {
    const { userIdentifier, subscriptionStatus = 'active' } = req.body; // userIdentifier is required

    if (!userIdentifier) {
        return res.status(400).json({ error: 'userIdentifier is required.' });
    }

    try {
        const newApiKey = crypto.randomBytes(32).toString('hex'); // Generate a 64-char hex string

        // Check if user already exists
        const [existingUsers] = await pool.query('SELECT id, api_key FROM users WHERE user_identifier = ?', [userIdentifier]);

        if (existingUsers.length > 0) {
            // Update existing user's API key and status
            await pool.query('UPDATE users SET api_key = ?, subscription_status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', [newApiKey, subscriptionStatus, existingUsers[0].id]);
            console.log(`INFO: Updated API Key for existing user "${userIdentifier}".`);
        } else {
            // Insert new user
            await pool.query('INSERT INTO users (user_identifier, api_key, subscription_status) VALUES (?, ?, ?)', [userIdentifier, newApiKey, subscriptionStatus]);
            console.log(`INFO: Generated new API Key for user "${userIdentifier}".`);
        }

        res.status(200).json({ userIdentifier, apiKey: newApiKey, subscriptionStatus });
    } catch (dbError) {
        console.error('ERROR: Database error generating token:', dbError);
        res.status(500).json({ error: 'Failed to generate token due to database error.' });
    }
});

// API to revoke/update a user's subscription status
app.post('/api/update-subscription-status', adminAuthMiddleware, async (req, res) => {
    const { userIdentifier, subscriptionStatus } = req.body; // userIdentifier and subscriptionStatus are required

    if (!userIdentifier || !subscriptionStatus) {
        return res.status(400).json({ error: 'userIdentifier and subscriptionStatus are required.' });
    }

    try {
        const [result] = await pool.query('UPDATE users SET subscription_status = ?, updated_at = CURRENT_TIMESTAMP WHERE user_identifier = ?', [subscriptionStatus, userIdentifier]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }

        console.log(`INFO: Updated subscription status for user "${userIdentifier}" to "${subscriptionStatus}".`);
        res.status(200).json({ userIdentifier, subscriptionStatus, message: 'Subscription status updated successfully.' });
    } catch (dbError) {
        console.error('ERROR: Database error updating subscription status:', dbError);
        res.status(500).json({ error: 'Failed to update subscription status due to database error.' });
    }
});
// --- END API Endpoints for Token Management ---


// Define a list of file extensions that are NOT allowed to be proxied
const DISALLOWED_EXTENSIONS = [
    '.exe', '.zip', '.tar', '.gz', '.dmg', '.msi', '.bat', '.sh',
    '.php', '.asp', '.aspx', '.jsp', '.py', '.rb', // Script files
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.xlsm', '.ppt', '.pptx' // Common document types (example)
];


// The following endpoints are used by 3rd Party App (Wordpress) to authenticate and redirect to the proxy site. 
// This is a two step process.

//Step 1: Creating a temporary token for use by the 3rd Pary App. 

app.get('/api/create-launch-token', async (req, res) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).send('Authorization header missing or malformed');
    }

    const apiKey = authHeader.split(' ')[1];

    try {
        const [rows] = await pool.query('SELECT user_identifier, subscription_status FROM users WHERE api_key = ?', [apiKey]);

        if (rows.length === 0 || rows[0].subscription_status !== 'active') {
            return res.status(401).send('Invalid or inactive API key.');
        }

        const token = crypto.randomBytes(24).toString('hex');
        const expires = Date.now() + 60000; // valid for 1 min

        launchTokens[token] = { apiKey, expires };

        const launchUrl =  process.env.APP_BASE_URL + `/auth-launch?token=${token}`;

        res.json({ launch_url: launchUrl });
    } catch (err) {
        console.error('Launch token generation failed:', err);
        res.status(500).send('Server error');
    }
});

// Step 2: Browser is launched, calling this app with the temporary token. This will validate the token, create the cookie, then 
// redirect to the root to server up the proxy content. 

//TODO: ADDED LOGIC FOR WORKAROUND WITH VUE, THIS NEEDS TO BE REMOVED AFTER MIGRATION!!!
const tempKey = "eIAtCjEocfNqAlFZBveO6vBwL2Ra2bkO9bRPVQVAMzbOcbX6Q1Je75gu4nmAodTd"
//const tempKeyAPI= "3603b3d381d05fc28ef60adfc11c17769c9ab6945e6798a8cf87f3db0b2b4422"

app.get('/auth-launch', async (req, res) => {
    const token = req.query.token;
    // NOTE: This will need to be changed if scaling is required. 
    if (token!=tempKey) // This is the normal path this workflow should take.
    {

        if( !token || !launchTokens[token] ) {
        return res.status(403).send('Invalid or missing launch token.');
        }
        
        const { apiKey, expires } = launchTokens[token];

        if (Date.now() > expires) {
            delete launchTokens[token];
            return res.status(403).send('Launch token expired.');
        }

        // Token is valid
        delete launchTokens[token];
     
        try {
        const [rows] = await pool.query('SELECT user_identifier FROM users WHERE api_key = ?', [apiKey]);

        if (rows.length === 0) {
            return res.status(403).send('User not found.');
        }

        const jwtToken = jwt.sign(
            { authenticated: true, api_key: apiKey, user: rows[0].user_identifier },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.cookie(AUTH_COOKIE_NAME, jwtToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'Lax'
        });
       
	    return res.redirect('/');
        } catch (err) {
            console.error('Auth-launch DB error:', err);
            res.status(500).send('Server error');
    }

    }
    else {  //This is the path if coming from Vue.
	    if(!req.headers['vue-auth'] || !req.headers['vue-auth']=="AE8A774F-1DE0-4F98-B037-659645706A66"){
            return res.status(403).send('Invalid or missing launch token - NOT FROM VUE.');
        }
        useremail = req.headers['vue-email']
        
        if (!useremail || useremail.length < 5) {
            return res.status(403).send('Invalid or missing email.');
        }
        else {
            const [rows] = await pool.query('SELECT user_identifier, subscription_status,api_key FROM users WHERE user_identifier = ?', [useremail]);
            if (rows.length === 0 || rows[0].subscription_status !== 'active') {
                return res.status(401).send('Invalid or inactive Email key for ' + [useremail]);
            }
            else {
                apiKey = rows[0].api_key; // Use the API key from the database
        	res.send (`
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
        const response = await fetch('https://tba.testingillusions.com/api/create-launch-token', {
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
	    }
        }
    }
    
});

// Used to prompt user for a username and password.
app.get('/login', (req, res) => {
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

app.post('/login', express.urlencoded({ extended: true }), async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).send('Missing email or password.');
    }

    try {
        const [rows] = await pool.query('SELECT api_key, user_identifier, subscription_status, password_hash FROM users WHERE email = ?', [email]);

        if (rows.length === 0) {
            return res.status(401).send('Invalid email or password.');
        }

        const user = rows[0];
        const passwordMatch = await bcrypt.compare(password, user.password_hash);
        if (!passwordMatch) {
            return res.status(401).send('Invalid email or password.');
        }

        if (user.subscription_status !== 'active') {
            return res.status(403).send('Your subscription is not active.');
        }

        const token = jwt.sign(
            { authenticated: true, api_key: user.api_key, user: user.user_identifier },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.cookie(AUTH_COOKIE_NAME, token, {
            httpOnly: true,
            secure: true,
            sameSite: 'Lax'
        });

        res.redirect('/'); // Redirect to root after successful login
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).send('Internal server error during login.');
    }
});

// used to register an email/password in the database
// Requires Admin Secret

app.post('/api/register', express.urlencoded({ extended: true }), adminAuthMiddleware, async (req, res) => {
     const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
    }

    try {
        const passwordHash = await bcrypt.hash(password, 10);
        const newApiKey = crypto.randomBytes(32).toString('hex');

        // Use email as the user_identifier for legacy compatibility
        await pool.query(
            'INSERT INTO users (email, password_hash, user_identifier, api_key, subscription_status) VALUES (?, ?, ?, ?, ?)',
            [email, passwordHash, email, newApiKey, 'active']
        );

        res.status(201).json({
            message: 'User registered successfully.',
            email,
            apiKey: newApiKey,
            subscriptionStatus: 'active'
        });
    } catch (err) {
        console.error('Registration error:', err);
        if (err.code === 'ER_DUP_ENTRY') {
            res.status(409).json({ error: 'Email already registered.' });
        } else {
            res.status(500).json({ error: 'Server error during registration.' });
        }
    }
});


// =========================================
// Proxy Middleware Configuration and Handlers
// =========================================
// Configure the proxy middleware
const apiProxy = createProxyMiddleware({
    target: TARGET_URL, // The target URL for the proxy
    changeOrigin: true,  // Changes the origin of the host header to the target URL
    headers: {
    'TBA-PLAN-TIER': 'Tier1',
    'VUE-AUTH':'AE8A774F-1DE0-4F98-B037-659645706A66'
    },
    ws: true,            // Enables proxying of WebSockets
    logLevel: 'debug',   // Set log level to 'debug' for detailed logging in the console
    // Custom pathRewrite function to add '?format=raw' for specific requests
    pathRewrite: function (path, req) {
        console.log(`DEBUG: pathRewrite received path: ${path}`); // Log the exact path received

        // List of paths that should receive the '?format=raw' argument
        const pathsToFormatRaw = [
            '/assets/js/mootools-core-1.6.0.js',
            '/assets/js/mootools-more-1.6.0-compressed.js',
            'ajax.php'
        ];

        // Check if the path starts with any of the specific MooTools file paths
        const shouldAddFormatRaw = pathsToFormatRaw.some(segment => path.startsWith(segment));

        if (shouldAddFormatRaw) {
                            let newPath = path;
            // Check if there are existing query parameters
            if (path.includes('?')) {
                newPath += '&format=raw'; // Append with & if query params exist
            } else {
                newPath += '?format=raw'; // Append with ? if no query params
            }
            console.log(`DEBUG: Rewriting path for moo.tools file: ${newPath}`);
            return newPath;
        }
        // For all other paths, return the path as is (with the leading '/')
        // The target URL will handle the base path.
        console.log(`DEBUG: Keeping general path as is: ${path}`);
        return path;
    },
    onProxyReq: (proxyReq, req, res) => {
        // Log at the very start of onProxyReq
        console.log(`DEBUG: onProxyReq function entered for URL: ${req.originalUrl}`);
        if (req.user?.user_email) {
            proxyReq.setHeader('VUE-EMAIL', req.user.user_email);
        }
        
        const urlPath = req.originalUrl; // Get the original requested URL path

        // Log the Host header being sent to the target to verify changeOrigin
        console.log(`DEBUG: Proxying request Host header: ${proxyReq.getHeader('Host')}`);

        // Extract the file extension from the URL path
        const extensionMatch = urlPath.match(/\.([0-9a-z]+)(?:[\?#]|$)/i);

        // Log if a request is being checked for blocking
        console.log(`DEBUG: Checking request for disallowed extensions: ${urlPath}`);

        if (extensionMatch) {
            const fileExtension = '.' + extensionMatch[1].toLowerCase(); // e.g., '.zip'

            // Re-enabled blocking logic
            if (DISALLOWED_EXTENSIONS.includes(fileExtension)) {
                console.warn(`🚫 BLOCKING: Disallowed file type request for ${urlPath} (extension: ${fileExtension})`);
                res.status(403).send(`Forbidden: Requests for "${fileExtension}" files are not allowed.`);
                proxyReq.destroy(); // Crucially, destroy the proxy request to prevent it from going out
                return; // Stop further processing for this request
            }
        }
        console.log(`Proxying request: ${req.method} ${urlPath} -> ${TARGET_URL}${proxyReq.path}`);
    },
    onProxyRes: (proxyRes, req, res) => {
        console.log(`Received response from target for: ${req.originalUrl} with status ${proxyRes.statusCode}`);

        // --- Start: Logic for rewriting response body URLs ---
        const originalHeaders = proxyRes.headers;
        const contentType = originalHeaders['content-type'];
        const contentEncoding = originalHeaders['content-encoding'];

        // Only attempt to rewrite text-based content (HTML, JavaScript, CSS)
        if (contentType && (contentType.includes('text/html') || contentType.includes('application/javascript') || contentType.includes('text/css'))) {
            let body = Buffer.from('');
            proxyRes.on('data', (chunk) => {
                body = Buffer.concat([body, chunk]);
            });

            proxyRes.on('end', () => {
                let decodedBody;

                // Decompress if necessary
                try {
                    if (contentEncoding === 'gzip') {
                        decodedBody = zlib.gunzipSync(body).toString('utf8');
                    } else if (contentEncoding === 'deflate') {
                        decodedBody = zlib.inflateSync(body).toString('utf8');
                    } else {
                        decodedBody = body.toString('utf8');
                    }
                } catch (e) {
                    console.error('Error decompressing response body:', e);
                    // Fallback to sending original body if decompression fails
                    res.setHeader('Content-Length', body.length);
                    if (contentType) res.setHeader('Content-Type', contentType);
                    if (contentEncoding) res.setHeader('Content-Encoding', contentEncoding);
                    res.end(body);
                    return;
                }

                // Determine the public proxy host for URL rewriting based on request protocol and host
                const requestProtocol = req.protocol || (req.socket.encrypted ? 'https' : 'http');
                const requestHost = req.headers.host;
                const publicProxyHostForRewrite = `${requestProtocol}://${requestHost}`;

                // Perform the replacement for http://localhost/ or http://localhost:PORT/
                const localhostRegex = /(https?:\/\/localhost(:\d+)?)(?=\/|$|['";\s])/g;
                const rewrittenBody = decodedBody.replace(localhostRegex, publicProxyHostForRewrite);

                let reencodedBody;
                // Re-compress if original was compressed
                try {
                    if (contentEncoding === 'gzip') {
                        reencodedBody = zlib.gzipSync(rewrittenBody);
                    } else if (contentEncoding === 'deflate') {
                        reencodedBody = zlib.deflateSync(rewrittenBody);
                    } else {
                        reencodedBody = Buffer.from(rewrittenBody, 'utf8');
                    }
                } catch (e) {
                    console.error('Error re-compressing response body:', e);
                    // Fallback to sending uncompressed modified body if re-compression fails
                    reencodedBody = Buffer.from(rewrittenBody, 'utf8');
                    // Remove content-encoding header if re-compression failed
                    delete proxyRes.headers['content-encoding'];
                }

                // Update headers for the client response
                res.setHeader('Content-Length', reencodedBody.length);
                // Preserve original content-type and content-encoding (if re-compression succeeded)
                if (contentType) res.setHeader('Content-Type', contentType);
                if (contentEncoding && reencodedBody !== Buffer.from(rewrittenBody, 'utf8')) { // Only set if original was compressed and re-compression worked
                    res.setHeader('Content-Encoding', contentEncoding);
                } else {
                    // If re-compression failed or wasn't needed, ensure content-encoding is removed
                    delete proxyRes.headers['content-encoding'];
                }


                // Pipe other headers from the original response to the client response
                Object.keys(originalHeaders).forEach(header => {
                    // Avoid overwriting headers we explicitly handle (Content-Type, Content-Length, Content-Encoding)
                    if (!['content-type', 'content-length', 'content-encoding'].includes(header.toLowerCase())) {
                        res.setHeader(header, originalHeaders[header]);
                    }
                });

                // Send the modified body
                res.end(reencodedBody);
            });
        } else {
            // For non-text content, or if no rewriting is needed, just pipe the original response
            proxyRes.pipe(res);
        }
        // --- End: Logic for rewriting response body URLs ---

        // Also handle Location header for redirects (from previous iteration)
        if (proxyRes.statusCode >= 300 && proxyRes.statusCode < 400 && proxyRes.headers.location) {
            let location = proxyRes.headers.location;
            console.log(`DEBUG: Original redirect Location header: ${location}`);

            // If the redirect location points to localhost, rewrite it to use the dynamically determined public proxy host
            if (location.startsWith('http://localhost')) {
                const requestProtocol = req.protocol || (req.socket.encrypted ? 'https' : 'http');
                const requestHost = req.headers.host;
                const publicProxyHostForRewrite = `${requestProtocol}://${requestHost}`;
                location = location.replace(/^http:\/\/localhost(:\d+)?/, publicProxyHostForRewrite);
                console.log(`DEBUG: Rewriting redirect Location header to: ${location}`);
                proxyRes.headers.location = location;
            }
        }
    },
    onError: (err, req, res) => {
        console.error(`Proxy error for ${req.originalUrl}:`, err);
        res.status(500).send('Proxy Error: Could not reach the target server.');
    },
});


// =========================================
// Attach Middleware and Start Proxy Server
// =========================================
// --- APPLY PAYWALL MIDDLEWARE BEFORE THE PROXY ---
app.use(paywallMiddleware);

// Use the proxy middleware for all requests starting with '/' (root path)
app.use('/', apiProxy);

// Basic route for the root URL to show that the proxy is running
app.get('/', (req, res) => {

});



// --- Server Creation (Conditional HTTP/HTTPS) ---
let server;
if (credentials && (PORT === 443 || process.env.USE_HTTPS === 'true')) {
    server = https.createServer(credentials, app);
    console.log(`INFO: Starting HTTPS server on port ${PORT}`);
} else {
    server = http.createServer(app);
    console.log(`INFO: Starting HTTP server on port ${PORT}`);
}

server.listen(PORT, () => {
    console.log(`Proxy server is running on ${credentials ? 'https' : 'http'}://localhost:${PORT}`);
    console.log(`Proxying requests from ${credentials ? 'https' : 'http'}://localhost:${PORT}/ to ${TARGET_URL}`);
    console.log('To stop the server, press Ctrl+C');
});
