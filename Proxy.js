const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const rateLimit = require('express-rate-limit');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const http = require('http');
const cookieParser = require('cookie-parser');

const app = express();

// --- CONFIGURATION ---
const PORT = process.env.PORT || 3000;
const TARGET_URL = process.env.TARGET_URL || 'http://tba.uglyyellowbunny.com/';
const CCT_TARGET_URL = process.env.CCT_TARGET_URL || 'https://tba-cloud.uglyyellowbunny.com/ctt/';
const AUTH_COOKIE_NAME = 'auth-token';
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const ADMIN_SECRET_KEY = process.env.ADMIN_SECRET_KEY || '43cc3acc34b59a930b6dd52ba89c85d';

console.log(`INFO: PCT Proxy target URL set to: ${TARGET_URL}`);
console.log(`INFO: CCT Proxy target URL set to: ${CCT_TARGET_URL}`);

// MySQL Database Configuration (using environment variables)
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'paywall_proxy_user',
    password: process.env.DB_PASSWORD || 'StrongDBPassword123',
    database: process.env.DB_NAME || 'paywall_proxy',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

const pool = mysql.createPool(dbConfig);

// --- MIDDLEWARE SETUP ---
app.use(express.json());
app.use(cookieParser());

// Trust proxy headers from load balancer
app.set('trust proxy', 1); // Trust only the first proxy (your load balancer)

// Rate limiting middleware
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 1000, // Increased limit to avoid issues during testing
    message: 'Too many requests, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
    // Skip rate limiting for excluded paths and admin API
    skip: (req) => {
        const excludedPaths = ['/healthcheck', '/api/'];
        return excludedPaths.some(path => req.originalUrl.startsWith(path));
    }
});

// Admin authentication middleware
const adminAuthMiddleware = (req, res, next) => {
    const adminSecret = req.headers['x-admin-secret'];
    if (adminSecret !== ADMIN_SECRET_KEY) {
        return res.status(403).json({ error: 'Forbidden: Invalid admin secret' });
    }
    next();
};

// --- HEALTH CHECK ENDPOINT ---
app.get('/healthcheck', (req, res) => {
    res.status(200).json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        service: 'paywall-proxy'
    });
});

// --- LOGIN ENDPOINT ---
app.get('/login', (req, res) => {
    res.status(200).send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>Paywall Proxy Login</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body { font-family: Arial, sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; }
            .container { background: #f5f5f5; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1 { color: #333; text-align: center; margin-bottom: 30px; }
            .form-group { margin-bottom: 20px; }
            label { display: block; margin-bottom: 5px; color: #555; }
            input[type="text"] { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
            button { width: 100%; padding: 12px; background: #007cba; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
            button:hover { background: #005a87; }
            .info { background: #e7f3ff; padding: 15px; border-left: 4px solid #007cba; margin-bottom: 20px; }
            .error { background: #ffe7e7; padding: 15px; border-left: 4px solid #dc3545; margin-bottom: 20px; display: none; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Paywall Proxy Login</h1>
            <div class="info">
                <strong>Access Required:</strong> Please enter your API key to continue.
            </div>
            <div id="error" class="error"></div>
            <form id="loginForm">
                <div class="form-group">
                    <label for="apiKey">API Key:</label>
                    <input type="text" id="apiKey" name="apiKey" required placeholder="Enter your API key">
                </div>
                <button type="submit">Login</button>
            </form>
        </div>
        
        <script>
            document.getElementById('loginForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                
                const apiKey = document.getElementById('apiKey').value;
                const errorDiv = document.getElementById('error');
                
                if (!apiKey) {
                    showError('Please enter an API key');
                    return;
                }
                
                try {
                    // Test the API key by making a request with it
                    const response = await fetch('/', {
                        headers: {
                            'Authorization': 'Bearer ' + apiKey
                        }
                    });
                    
                    if (response.ok) {
                        // API key is valid, redirect to home
                        window.location.href = '/';
                    } else if (response.status === 401) {
                        showError('Invalid API key. Please check your key and try again.');
                    } else {
                        showError('Login failed. Please try again.');
                    }
                } catch (error) {
                    showError('Network error. Please try again.');
                }
            });
            
            function showError(message) {
                const errorDiv = document.getElementById('error');
                errorDiv.textContent = message;
                errorDiv.style.display = 'block';
            }
        </script>
    </body>
    </html>
    `);
});

// --- LOGOUT ENDPOINT ---
app.get('/logout', (req, res) => {
    res.clearCookie(AUTH_COOKIE_NAME);
    res.status(200).send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>Logged Out - Paywall Proxy</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body { font-family: Arial, sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; }
            .container { background: #f5f5f5; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1 { color: #333; text-align: center; margin-bottom: 30px; }
            .success { background: #d4edda; padding: 15px; border-left: 4px solid #28a745; margin-bottom: 20px; }
            .login-link { text-align: center; margin-top: 20px; }
            .login-link a { color: #007cba; text-decoration: none; }
            .login-link a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Logged Out</h1>
            <div class="success">
                <strong>Success:</strong> You have been logged out successfully.
            </div>
            <div class="login-link">
                <a href="/login">Login Again</a>
            </div>
        </div>
    </body>
    </html>
    `);
});

// --- ADMIN API ROUTES ---
app.post('/api/generate-token', adminAuthMiddleware, async (req, res) => {
    const { userIdentifier, subscriptionStatus } = req.body;

    if (!userIdentifier || !subscriptionStatus) {
        return res.status(400).json({ error: 'userIdentifier and subscriptionStatus are required.' });
    }

    const apiKey = crypto.randomBytes(32).toString('hex');

    try {
        await pool.query('INSERT INTO users (user_identifier, api_key, subscription_status, tier) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE api_key = VALUES(api_key), subscription_status = VALUES(subscription_status), updated_at = CURRENT_TIMESTAMP',
            [userIdentifier, apiKey, subscriptionStatus, 'PCT']);

        console.log(`INFO: Generated API Key for user "${userIdentifier}" with status "${subscriptionStatus}".`);
        res.status(200).json({ userIdentifier, apiKey, subscriptionStatus, tier: 'PCT' });
    } catch (dbError) {
        console.error('ERROR: Database error generating token:', dbError);
        res.status(500).json({ error: 'Failed to generate token due to database error.' });
    }
});

app.post('/api/update-subscription-status', adminAuthMiddleware, async (req, res) => {
    const { userIdentifier, subscriptionStatus } = req.body;

    if (!userIdentifier || !subscriptionStatus) {
        return res.status(400).json({ error: 'userIdentifier and subscriptionStatus are required.' });
    }

    try {
        const [result] = await pool.query('UPDATE users SET subscription_status = ?, updated_at = CURRENT_TIMESTAMP WHERE user_identifier = ?', [subscriptionStatus, userIdentifier]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }

        console.log(`INFO: Updated subscription status for user "${userIdentifier}" to "${subscriptionStatus}".`);
        res.status(200).json({ userIdentifier, subscriptionStatus });
    } catch (dbError) {
        console.error('ERROR: Database error updating subscription status:', dbError);
        res.status(500).json({ error: 'Failed to update subscription status due to database error.' });
    }
});

// API to update a user's tier
app.post('/api/update-tier', adminAuthMiddleware, async (req, res) => {
    const { userIdentifier, tier } = req.body;

    if (!userIdentifier || !tier) {
        return res.status(400).json({ error: 'userIdentifier and tier are required.' });
    }

    // Validate tier values
    const validTiers = ['PCT', 'CCT'];
    if (!validTiers.includes(tier)) {
        return res.status(400).json({ error: 'Invalid tier. Must be PCT or CCT.' });
    }

    try {
        const [result] = await pool.query('UPDATE users SET tier = ?, updated_at = CURRENT_TIMESTAMP WHERE user_identifier = ?', [tier, userIdentifier]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }

        console.log(`INFO: Updated tier for user "${userIdentifier}" to "${tier}".`);
        res.status(200).json({ userIdentifier, tier, message: 'Tier updated successfully.' });
    } catch (dbError) {
        console.error('ERROR: Database error updating tier:', dbError);
        res.status(500).json({ error: 'Failed to update tier due to database error.' });
    }
});

// API to get user information including tier
app.get('/api/user-info', adminAuthMiddleware, async (req, res) => {
    const { userIdentifier } = req.query;

    if (!userIdentifier) {
        return res.status(400).json({ error: 'userIdentifier is required.' });
    }

    try {
        const [rows] = await pool.query('SELECT user_identifier, subscription_status, tier, email, created_at, updated_at FROM users WHERE user_identifier = ?', [userIdentifier]);

        if (rows.length === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }

        res.status(200).json(rows[0]);
    } catch (dbError) {
        console.error('ERROR: Database error retrieving user info:', dbError);
        res.status(500).json({ error: 'Failed to retrieve user info due to database error.' });
    }
});

// --- AUTHENTICATION MIDDLEWARE ---
const paywallMiddleware = async (req, res, next) => {
    console.log(`INFO: Request received: ${req.method} ${req.originalUrl}`);

    // Define paths that should bypass the paywall entirely
    const excludedPaths = ['/login', '/logout', '/public', '/favicon.ico', '/healthcheck'];
    const isExcludedPath = excludedPaths.some(path => req.originalUrl.startsWith(path));

    if (isExcludedPath) {
        console.log(`INFO: Bypassing authentication for excluded path: ${req.originalUrl}`);
        return next();
    }

    // Check for existing authentication cookie first
    const authToken = req.cookies[AUTH_COOKIE_NAME];
    if (authToken) {
        try {
            const decoded = jwt.verify(authToken, JWT_SECRET);
            if (decoded.authenticated === true && decoded.api_key) {
                // Verify the API key from the token against the database to ensure subscription is active
                const [rows] = await pool.query('SELECT user_identifier, subscription_status, email, tier FROM users WHERE api_key = ?', [decoded.api_key]);
                if (rows.length > 0 && rows[0].subscription_status === 'active') {
                    console.log(`INFO: Access granted via cookie for user: ${decoded.user} (Tier: ${rows[0].tier})`);
                    // Attach user info to request including tier
                    req.user = { 
                        apiKey: decoded.api_key, 
                        userIdentifier: decoded.user,
                        email: rows[0].email || decoded.user,
                        planTier: decoded.planTier || 'Tier1',
                        tier: rows[0].tier || 'PCT'
                    };
                    
                    return next();
                } else {
                    console.warn(`WARNING: Cookie valid but subscription status is not active for API Key: ${decoded.api_key}`);
                    res.clearCookie(AUTH_COOKIE_NAME);
                }
            }
        } catch (err) {
            console.warn(`WARNING: Invalid or expired cookie: ${err.message}`);
            res.clearCookie(AUTH_COOKIE_NAME);
        }
    }

    // Extract API Key from headers or query parameters
    let providedApiKey = null;
    const authHeader = req.headers['authorization'];
    if (authHeader && authHeader.startsWith('Bearer ')) {
        providedApiKey = authHeader.split(' ')[1];
    }

    if (!providedApiKey) {
        providedApiKey = req.query.apiKey;
    }

    if (providedApiKey) {
        try {
            // Query database to validate the provided API key (include tier)
            const [rows] = await pool.query('SELECT user_identifier, subscription_status, email, tier FROM users WHERE api_key = ?', [providedApiKey]);

            if (rows.length > 0 && rows[0].subscription_status === 'active') {
                console.log(`INFO: Access granted via API Key: ${providedApiKey} (User: ${rows[0].user_identifier}, Tier: ${rows[0].tier})`);

                // Set authentication cookie upon successful API key validation
                const token = jwt.sign({ authenticated: true, api_key: providedApiKey, user: rows[0].user_identifier }, JWT_SECRET, { expiresIn: '1h' });
                res.cookie(AUTH_COOKIE_NAME, token, {
                    httpOnly: true,
                    secure: req.secure || req.get('X-Forwarded-Proto') === 'https',
                    sameSite: 'lax'
                });
                // Attach user info to request including tier
                req.user = { 
                    apiKey: providedApiKey, 
                    userIdentifier: rows[0].user_identifier,
                    email: rows[0].email || rows[0].user_identifier,
                    planTier: 'Tier1',
                    tier: rows[0].tier || 'PCT'
                };

                return next();
            } else {
                console.warn(`WARNING: Access denied: API Key "${providedApiKey}" not found or subscription not active.`);
                return res.status(401).send('Unauthorized: Invalid or inactive API Key.');
            }
        } catch (dbError) {
            console.error('ERROR: Database error during API Key validation:', dbError);
            return res.status(500).send('Internal Server Error during authentication.');
        }
    } else {
        console.warn(`WARNING: Access denied: No API Key or valid cookie provided.`);
        return res.redirect('/login');
    }
};

// Middleware to determine target based on route and user tier
const routeMiddleware = (req, res, next) => {
    // Define paths that should bypass the paywall entirely
    const excludedPaths = ['/login', '/logout', '/public', '/favicon.ico', '/healthcheck'];
    const isExcludedPath = excludedPaths.some(path => req.originalUrl.startsWith(path));
    
    // Skip routing for excluded paths - they should be handled directly
    if (isExcludedPath) {
        console.log(`INFO: Skipping routing for excluded path: ${req.originalUrl}`);
        return next();
    }
    
    // Check if this is a CCT route from WordPress
    const isCCTRoute = req.originalUrl.startsWith('/secure-cct/');
    
    console.log(`DEBUG: routeMiddleware - URL: ${req.originalUrl}, isCCTRoute: ${isCCTRoute}, user: ${req.user ? req.user.userIdentifier : 'none'}, tier: ${req.user ? req.user.tier : 'none'}`);
    
    if (isCCTRoute) {
        // CCT route requires CCT tier access
        if (!req.user || req.user.tier !== 'CCT') {
            console.warn(`WARNING: Access denied to CCT route for user: ${req.user ? req.user.userIdentifier : 'anonymous'} (Tier: ${req.user ? req.user.tier : 'none'})`);
            return res.status(403).send('Forbidden: CCT tier access required for this resource.');
        }
        req.targetUrl = CCT_TARGET_URL;
        req.isCCTRoute = true;
        console.log(`INFO: Routing to CCT for user: ${req.user.userIdentifier} (${req.originalUrl})`);
    } else {
        // PCT route - accessible by both PCT and CCT users
        req.targetUrl = TARGET_URL;
        req.isCCTRoute = false;
        console.log(`INFO: Routing to PCT for user: ${req.user ? req.user.userIdentifier : 'anonymous'} (${req.originalUrl})`);
    }
    
    next();
};

// Configure the proxy middleware with dynamic routing
const createDynamicProxy = () => {
    return (req, res, next) => {
        // Define paths that should not be proxied
        const excludedPaths = ['/login', '/logout', '/public', '/favicon.ico', '/healthcheck'];
        const isExcludedPath = excludedPaths.some(path => req.originalUrl.startsWith(path));
        
        // Skip proxying for excluded paths - send 404 for non-existent routes
        if (isExcludedPath) {
            console.log(`INFO: Skipping proxy for excluded path: ${req.originalUrl}`);
            return res.status(404).send('Not Found');
        }
        
        const targetUrl = req.targetUrl || TARGET_URL;
        
        const proxy = createProxyMiddleware({
            target: targetUrl,
            changeOrigin: true,
            logLevel: 'warn',
            pathRewrite: req.isCCTRoute ? {
                '^/secure-cct': ''  // Strip /secure-cct completely, keep the rest
            } : {
                '^/secure-proxy/': '/',
                '^/': '/',
            },
            on: {
                proxyReq: (proxyReq, req, res) => {
                    // Only inject headers for PCT routes, not CCT
                    if (!req.isCCTRoute && req.user && req.user.userIdentifier) {
                        proxyReq.setHeader('TBA-PLAN-TIER', req.user.planTier || 'Tier1');
                        proxyReq.setHeader('VUE-AUTH', 'AE8A774F-1DE0-4F98-B037-659645706A66');
                        proxyReq.setHeader('VUE-EMAIL', req.user.email);
                        console.log(`INFO: Injected PCT headers for ${req.user.email} (${req.user.planTier})`);
                    } else if (req.isCCTRoute) {
                        console.log(`INFO: CCT route - no headers injected for ${req.user ? req.user.email : 'anonymous'}`);
                    } else {
                        // Set default headers for unauthenticated PCT requests
                        proxyReq.setHeader('TBA-PLAN-TIER', 'Tier1');
                        proxyReq.setHeader('VUE-AUTH', 'AE8A774F-1DE0-4F98-B037-659645706A66');
                    }
                },
                proxyRes: (proxyRes, req, res) => {
                    if (proxyRes.statusCode >= 400) {
                        console.warn(`WARN: Proxy response ${proxyRes.statusCode} for ${req.originalUrl} (Target: ${req.targetUrl || 'default'})`);
                    }
                },
                error: (err, req, res) => {
                    console.error(`ERROR: Proxy error for ${req.originalUrl} (Target: ${req.targetUrl || 'default'}):`, err.message);
                    if (err.code === 'ECONNREFUSED') {
                        res.status(502).send(`Bad Gateway: Target server ${req.targetUrl || TARGET_URL} is not responding`);
                    } else {
                        res.status(500).send('Proxy Error: Could not reach the target server.');
                    }
                }
            }
        });
        
        proxy(req, res, next);
    };
};

const dynamicProxy = createDynamicProxy();

// --- APPLY MIDDLEWARE IN CORRECT ORDER ---
app.use(limiter);               // Rate limiting first
app.use(paywallMiddleware);     // Authentication second
app.use(routeMiddleware);       // Route determination third
app.use('/', dynamicProxy);     // Dynamic proxy last

// --- HTTP SERVER SETUP ---
http.createServer(app).listen(PORT, () => {
    console.log(`INFO: HTTP Proxy server is running on port ${PORT}.`);
    console.log(`INFO: Proxying to: ${TARGET_URL} (PCT) and ${CCT_TARGET_URL} (CCT)`);
});