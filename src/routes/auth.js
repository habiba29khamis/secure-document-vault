const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const router = express.Router();
const { authenticateToken } = require('../middleware/auth');


// Registration
router.post('/register', (req, res) => {
    const { username, email, password } = req.body;
    const db = req.app.get('db') || req.db;

    if (!username || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    const passwordRegex = /^(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,}$/;
    if (!passwordRegex.test(password)) {
        return res.status(400).json({ error: 'Password must be at least 8 characters, contain 1 uppercase letter and 1 number' });
    }

    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) return res.status(500).json({ error: 'Server error' });

        const query = 'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)';
        req.db.query(query, [username, email, hashedPassword, 'user'], (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(400).json({ error: 'Username or email already exists' });
                }
                return res.status(500).json({ error: 'Database error' });
            }
            
            // Generate 2FA secret and QR code for the new user
            const speakeasy = require('speakeasy');
            const qrcode = require('qrcode');
            
            const secret = speakeasy.generateSecret({
                name: `SecureVault:${username}`
            });
            
            // Store secret in database
            req.db.query('UPDATE users SET two_factor_secret = ? WHERE id = ?', [secret.base32, result.insertId], (err2) => {
                if (err2) console.error('2FA secret save error:', err2);
            });
            
            // Generate QR code as base64
            qrcode.toDataURL(secret.otpauth_url, (err3, qrCode) => {
                if (err3) {
                    return res.status(201).json({ 
                        message: 'User registered successfully. 2FA setup available in profile.',
                        userId: result.insertId
                    });
                }
                
                res.status(201).json({ 
                    message: 'User registered successfully! Scan QR code for 2FA.',
                    userId: result.insertId,
                    twoFactorSecret: secret.base32,
                    qrCode: qrCode
                });
            });
        });
    });
});

// Login
router.post('/login', (req, res) => {
    const { username, password, twoFactorToken } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }

    req.db.query('SELECT * FROM users WHERE username = ?', [username], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });

        if (rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = rows[0];
        bcrypt.compare(password, user.password_hash, (err, validPassword) => {
            if (err) return res.status(500).json({ error: 'Server error' });

            if (!validPassword) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            // Check if 2FA is enabled
            if (user.two_factor_enabled === 1 || user.two_factor_enabled === true) {
                if (!twoFactorToken) {
                    return res.status(401).json({ error: '2FA required', requires2FA: true });
                }
                
                const speakeasy = require('speakeasy');
                const verified = speakeasy.totp.verify({
                    secret: user.two_factor_secret,
                    encoding: 'base32',
                    token: twoFactorToken
                });
                
                if (!verified) {
                    return res.status(401).json({ error: 'Invalid 2FA token' });
                }
            }

            const token = jwt.sign(
                { id: user.id, username: user.username, role: user.role },
                process.env.JWT_SECRET,
                { expiresIn: '24h' }
            );

            res.json({
                message: 'Login successful',
                token,
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    role: user.role
                }
            });
        });
    });
});

// Setup 2FA
router.post('/setup-2fa', authenticateToken, async (req, res) => {
    try {
        const secret = speakeasy.generateSecret({
            name: `SecureVault:${req.user.username}`
        });
        
        // Store secret temporarily or in database
        req.db.query('UPDATE users SET two_factor_secret = ? WHERE id = ?', [secret.base32, req.user.id], (err) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            
            // Generate QR code
            qrcode.toDataURL(secret.otpauth_url, (err, qrCode) => {
                if (err) return res.status(500).json({ error: 'QR generation failed' });
                
                res.json({
                    message: '2FA setup initiated',
                    secret: secret.base32,
                    qrCode: qrCode
                });
            });
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Verify and enable 2FA
router.post('/verify-2fa', authenticateToken, async (req, res) => {
    const { token } = req.body;
    
    if (!token) {
        return res.status(400).json({ error: 'Token required' });
    }
    
    req.db.query('SELECT two_factor_secret FROM users WHERE id = ?', [req.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (rows.length === 0) return res.status(404).json({ error: 'User not found' });
        
        const secret = rows[0].two_factor_secret;
        if (!secret) return res.status(400).json({ error: '2FA not setup' });
        
        const verified = speakeasy.totp.verify({
            secret: secret,
            encoding: 'base32',
            token: token
        });
        
        if (verified) {
            req.db.query('UPDATE users SET two_factor_enabled = TRUE WHERE id = ?', [req.user.id], (err) => {
                if (err) return res.status(500).json({ error: 'Database error' });
                res.json({ message: '2FA enabled successfully' });
            });
        } else {
            res.status(401).json({ error: 'Invalid 2FA token' });
        }
    });
});

// Login with 2FA
router.post('/login-2fa', async (req, res) => {
    const { username, password, twoFactorToken } = req.body;
    
    if (!username || !password || !twoFactorToken) {
        return res.status(400).json({ error: 'All fields required' });
    }
    
    req.db.query('SELECT * FROM users WHERE username = ?', [username], async (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
        
        const user = rows[0];
        const validPassword = await bcrypt.compare(password, user.password_hash);
        
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Verify 2FA if enabled
        if (user.two_factor_enabled) {
            const verified = speakeasy.totp.verify({
                secret: user.two_factor_secret,
                encoding: 'base32',
                token: twoFactorToken
            });
            
            if (!verified) {
                return res.status(401).json({ error: 'Invalid 2FA token' });
            }
        }
        
        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({
            message: 'Login successful',
            token,
            user: { id: user.id, username: user.username, email: user.email, role: user.role }
        });
    });
});


// Verify 2FA during registration
router.post('/verify-2fa-setup', (req, res) => {
    const { userId, secret, token } = req.body;
    
    if (!userId || !secret || !token) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    
    const speakeasy = require('speakeasy');
    const verified = speakeasy.totp.verify({
        secret: secret,
        encoding: 'base32',
        token: token
    });
    
    if (verified) {
        req.db.query('UPDATE users SET two_factor_enabled = TRUE, two_factor_secret = ? WHERE id = ?', 
            [secret, userId], (err) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.json({ message: '2FA verified and enabled successfully' });
        });
    } else {
        res.status(401).json({ error: 'Invalid 2FA token' });
    }
});


module.exports = router;