const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
});
app.use('/api/', limiter);

// Database connection
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

// Make db available to routes
app.use((req, res, next) => {
    req.db = db;
    next();
});

// Routes
const authRoutes = require('./src/routes/auth');
const documentRoutes = require('./src/routes/documents');
const { authenticateToken } = require('./src/middleware/auth');

app.use('/api/auth', authRoutes);
app.use('/api/documents', documentRoutes);

app.get('/api/protected', authenticateToken, (req, res) => {
    res.json({ message: `Hello ${req.user.username}, you have access!`, user: req.user });
});

// Test route
app.get('/', (req, res) => {
    res.send('Secure Document Vault API is running');
});

// Start server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});