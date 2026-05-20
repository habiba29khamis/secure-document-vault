const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const passport = require('passport');
const https = require('https');
const fs = require('fs');
const path = require('path');
const managerRoutes = require('./src/routes/manager');

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;


// Middleware (same as before)
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-hashes'"],
            scriptSrcAttr: ["'unsafe-inline'", "'unsafe-hashes'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
        }
    }
}));
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use('/pics', express.static('pics'));

app.use(session({
    secret: process.env.SESSION_SECRET || 'mysecret',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: true } // true for HTTPS
}));

app.use(passport.initialize());
app.use(passport.session());

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use('/api/', limiter);

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

db.connect((err) => {
    if (err) {
        console.error('Database connection failed:', err);
        return;
    }
    console.log('Connected to MySQL database');
});

app.use((req, res, next) => {
    req.db = db;
    next();
});

// Routes
const authRoutes = require('./src/routes/auth');
const documentRoutes = require('./src/routes/documents');
const adminRoutes = require('./src/routes/admin');
const oauthRoutes = require('./src/routes/oauth');
const { authenticateToken } = require('./src/middleware/auth');

app.use('/api/auth', authRoutes);
app.use('/api/documents', documentRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/auth', oauthRoutes);
app.use('/api/manager', managerRoutes);
app.get('/api/protected', authenticateToken, (req, res) => {
    res.json({ message: `Hello ${req.user.username}`, user: req.user });
});

app.get('/', (req, res) => {
    res.send('Secure Document Vault API is running');
});

// Generate self-signed certificate for development
const httpsOptions = {
    key: fs.readFileSync(path.join(__dirname, 'key.pem')),
    cert: fs.readFileSync(path.join(__dirname, 'cert.pem'))
};

// Create HTTPS server
https.createServer(httpsOptions, app).listen(3443, () => {
    console.log('HTTPS Server running on https://localhost:3443');
    console.log('HTTP Server running on http://localhost:3000');
});

// Also keep HTTP for testing
app.listen(port, () => {
    console.log(`HTTP Server running on port ${port}`);
});