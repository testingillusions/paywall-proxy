const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');

const app = express();
const SECRET_KEY = 'your-secret-key'; // Replace with secure value
const PORT = 4000;

// Example API keys store (replace with DB or ENV-based in prod)
const VALID_API_KEYS = {
    '12345-abcde': 'joe.kayak@gmail.com',
    '67890-fghij': 'user2@example.com',
};

app.use(cors({
    origin: true,
    credentials: true
}));
app.use(express.json());
app.use(cookieParser());

// 🔐 Auth check: verifies JWT cookie
app.all('/api/auth', (req, res) => {
    console.log('DEBUG: Auth check called', req);
    const token = req.cookies['auth_token'];

    if (!token) {
        return res.status(401).json({ message: 'Unauthorized: No token' });
    }

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        return res.status(200).json({ user: decoded.email });
    } catch (err) {
        return res.status(401).json({ message: 'Unauthorized: Invalid token' });
    }
});

// 🔐 Login: validate API key header and issue JWT
app.all('/api/login', (req, res) => {
    const apiKey = req.headers['apikey'];

    if (!apiKey || !(apiKey in VALID_API_KEYS)) {
        return res.status(401).json({ message: 'Invalid or missing API key' });
    }

    const email = VALID_API_KEYS[apiKey];
    const token = jwt.sign({ email }, SECRET_KEY, { expiresIn: '1h' });

    res.cookie('auth_token', token, {
        httpOnly: true,
        secure: false, // Change to true for HTTPS
        sameSite: 'Lax',
        maxAge: 3600000
    });

    return res.status(200).json({ message: 'Login successful' });
});

app.listen(PORT, () => {
    console.log(`Auth server running on port ${PORT}`);
});