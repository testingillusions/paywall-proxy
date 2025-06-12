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


const launchTokens = {}; // token -> { apiKey, expires }


//Add in Health Check path for Amazon Load Balancing
const appHealth = express()
const port = 3002

appHealth.get('/healthcheck', (req, res) => res.send('Hello World!'))
appHealth.listen(port, () => console.log(`Example app listening on port ${port}!`));


// Initialize the Express application
const app = express();
app.use(express.json()); // Enable parsing of JSON request bodies for API endpoints


app.use((req, res, next) => {
    const origin = req.headers.origin;

    // Update this if supporting multiple origins
    const allowedOrigin = 'https://testingillusions.com';

    if (origin === allowedOrigin) {
        res.header('Access-Control-Allow-Origin', allowedOrigin);
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

// --- Log all incoming Express requests ---
app.use((req, res, next) => {
    console.log(`DEBUG: Express received request for: ${req.originalUrl}`);
    next(); // Pass the request to the next middleware (which is our proxy)
});

// Define the port on which the proxy server will listen
// Read from .env, fallback to 443
const PORT = process.env.PORT || 443;

// Define the target URL to which requests will be proxied.
// Read from .env, fallback to default
const TARGET_URL = process.env.TARGET_URL || 'http://tba.uglyyellowbunny.com/';

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
const paywallMiddleware = async (req, res, next) => { // Made async to use await for DB queries
    // Define paths that should NOT require an API key (e.g., static assets that are publicly accessible)
    // Also exclude the new API management endpoints from the main paywall
    const EXCLUDED_PAYWALL_PATHS = [
        '/assets/',
        '/css/',
        '/js/',
        '/images/',
        '/favicon.ico',
        '/api/generate-token', // Exclude API management endpoints
        '/api/update-subscription-status'    // Exclude API management endpoints
    ];

    // Check if the current request path starts with any of the excluded paths
    const isExcludedPath = EXCLUDED_PAYWALL_PATHS.some(prefix => req.originalUrl.startsWith(prefix));

    if (isExcludedPath) {
        console.log(`INFO: Skipping main paywall for excluded path: ${req.originalUrl}`);
        return next(); // Skip paywall check for static assets and API management endpoints
    }

    // --- Check for existing authentication cookie first ---
    const authToken = req.cookies[AUTH_COOKIE_NAME];
    if (authToken) {
        try {
            const decoded = jwt.verify(authToken, JWT_SECRET);
            if (decoded.authenticated === true && decoded.api_key) {
                // Verify the API key from the token against the database to ensure subscription is active
                const [rows] = await pool.query('SELECT subscription_status FROM users WHERE api_key = ?', [decoded.api_key]);
                if (rows.length > 0 && rows[0].subscription_status === 'active') {
                    console.log(`INFO: Access granted via cookie for API Key: ${decoded.api_key}`);
                    // Attach user info to request for potential future use (e.g., rate limiting by user)
                    req.user = { apiKey: decoded.api_key, userIdentifier: rows[0].user_identifier };
                    return next(); // Valid cookie and active subscription found, proceed
                } else {
                    console.warn(`WARNING: Cookie valid but subscription status is not active for API Key: ${decoded.api_key}`);
                    res.clearCookie(AUTH_COOKIE_NAME); // Clear invalid cookie
                }
            }
        } catch (err) {
            console.warn(`WARNING: Invalid or expired cookie: ${err.message}`);
            // If cookie is invalid, clear it to force re-authentication
            res.clearCookie(AUTH_COOKIE_NAME);
        }
    }

    // --- Check for API Key in Header or Query (if no valid cookie was found) ---
    const apiKeyFromHeader = req.headers['authorization'];
    const apiKeyFromQuery = req.query.apiKey;

    let providedApiKey = null;

    if (apiKeyFromHeader && apiKeyFromHeader.startsWith('Bearer ')) {
        providedApiKey = apiKeyFromHeader.split(' ')[1];
    } else if (apiKeyFromQuery) {
        providedApiKey = apiKeyFromQuery;
    }

    if (providedApiKey) {
        try {
            // Query database to validate the provided API key
            const [rows] = await pool.query('SELECT user_identifier, subscription_status FROM users WHERE api_key = ?', [providedApiKey]);

            if (rows.length > 0 && rows[0].subscription_status === 'active') {
                console.log(`INFO: Access granted via API Key: ${providedApiKey} (User: ${rows[0].user_identifier})`);

                // Set authentication cookie upon successful API key validation
                const token = jwt.sign({ authenticated: true, api_key: providedApiKey, user: rows[0].user_identifier }, JWT_SECRET, { expiresIn: '1h' }); // Token valid for 1 hour
                res.cookie(AUTH_COOKIE_NAME, token, {
                    httpOnly: true, // Prevents client-side JavaScript from accessing the cookie
                    secure: true,   // Ensures cookie is only sent over HTTPS
                    sameSite: 'lax' // Recommended for CSRF protection
                });
                console.log(`INFO: Authentication cookie set for ${req.originalUrl}`);
                // Attach user info to request for potential future use (e.g., rate limiting by user)
                req.user = { apiKey: providedApiKey, userIdentifier: rows[0].user_identifier };

                next(); // API key is valid and active, proceed
            } else {
                console.warn(`WARNING: Access denied: API Key "${providedApiKey}" not found or subscription not active.`);
                res.status(401).send('Unauthorized: Invalid or inactive API Key.');
            }
        } catch (dbError) {
            console.error('ERROR: Database error during API Key validation:', dbError);
            res.status(500).send('Internal Server Error during authentication.');
        }
    } else {
        console.warn(`WARNING: Access denied: No API Key or valid cookie provided.`);
        res.status(401).send('Unauthorized: Valid API Key or authentication cookie required.');
    }
};
// --- END PAYWALL CONFIGURATION ---


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
        const launchUrl = `https://tba.testingillusions.com/auth-launch?token=${token}`;

        res.json({ launch_url: launchUrl });
    } catch (err) {
        console.error('Launch token generation failed:', err);
        res.status(500).send('Server error');
    }
});

app.get('/auth-launch', async (req, res) => {
    const token = req.query.token;

    if (!token || !launchTokens[token]) {
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
});

// Configure the proxy middleware
const apiProxy = createProxyMiddleware({
    target: TARGET_URL, // The target URL for the proxy
    changeOrigin: true,  // Changes the origin of the host header to the target URL
    ws: true,            // Enables proxying of WebSockets
    logLevel: 'debug',   // Set log level to 'debug' for detailed logging in the console
    // Custom pathRewrite function to add '?format=raw' for specific requests
    pathRewrite: function (path, req) {
        console.log(`DEBUG: pathRewrite received path: ${path}`); // Log the exact path received

        // List of paths that should receive the '?format=raw' argument
        const pathsToFormatRaw = [
            '/assets/js/mootools-core-1.6.0.js',
            '/assets/js/mootools-more-1.6.0-compressed.js'
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

// --- APPLY PAYWALL MIDDLEWARE BEFORE THE PROXY ---
app.use(paywallMiddleware);

// Use the proxy middleware for all requests starting with '/' (root path)
app.use('/', apiProxy);

// Basic route for the root URL to show that the proxy is running
app.get('/', (req, res) => {
    // NEW: Use APP_BASE_URL from environment, fallback to dynamic request host
    const currentUrlBase = process.env.APP_BASE_URL || `${req.protocol || (req.socket.encrypted ? 'https' : 'http')}://${req.headers.host}`;

    res.send(`
        <h1>Node.js HTTPS Proxy Server with Database-backed Paywall & Rate Limiting (Local Deployment)</h1>
        <p>This server is proxying all requests from <code>/</code> to <code>${TARGET_URL}</code>.</p>
        <p><strong>IMPORTANT:</strong> You must access this via HTTPS (e.g., <a href="https://localhost:${PORT}/">https://localhost:${PORT}/</a>).</p>
        <p>Since this is a self-signed certificate, your browser will show a security warning. You need to proceed past it.</p>
        <p>To gain access, provide a valid API key once. A cookie will then remember your authentication.</p>
        <h2>Admin API Endpoints (for 3rd Party Subscription Manager)</h2>
        <p>These endpoints require the <code>X-Admin-Secret</code> header or <code>adminSecret</code> query parameter.</p>
        <h3>Generate/Update API Key: <code>POST /api/generate-token</code></h3>
        <p><strong>Example curl (Windows):</strong></p>
        <pre><code>curl.exe -k -X POST -H "Content-Type: application/json" ^
-H "X-Admin-Secret: ${ADMIN_SECRET_KEY}" ^
-d "{\"userIdentifier\": \"testuser@example.com\", \"subscriptionStatus\": \"active\"}" ^
${currentUrlBase}/api/generate-token</code></pre>

        <h3>Update Subscription Status: <code>POST /api/update-subscription-status</code></h3>
        <p><strong>Example curl (Windows):</strong></p>
        <pre><code>curl.exe -k -X POST -H "Content-Type: application/json" ^
-H "X-Admin-Secret: ${ADMIN_SECRET_KEY}" ^
-d "{\"userIdentifier\": \"testuser@example.com\", \"subscriptionStatus\": \"inactive\"}" ^
${currentUrlBase}/api/update-subscription-status</code></pre>

        <h2>User Access</h2>
        <p>1. Try visiting: <a href="${currentUrlBase}/">${currentUrlBase}/</a> (will be Unauthorized)</p>
        <p>2. Get authorized (sets cookie): <a href="${currentUrlBase}/?apiKey=YOUR_GENERATED_API_KEY">${currentUrlBase}/?apiKey=YOUR_GENERATED_API_KEY</a></p>
        <p>3. After step 2, try visiting: <a href="${currentUrlBase}/">${currentUrlBase}/</a> again (should now be authorized by cookie)</p>
        <p>Or use a header for initial authorization: <code>Authorization: Bearer YOUR_GENERATED_API_KEY</code></p>
        <p>The proxy is listening on port ${PORT}.</p>
    `);
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