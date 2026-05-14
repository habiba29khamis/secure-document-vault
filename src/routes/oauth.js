const express = require('express');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const dotenv = require('dotenv');
const router = express.Router();

dotenv.config();

// Database connection pool
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
}).promise();

// Google Strategy setup
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/api/auth/google/callback'
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      const [rows] = await pool.query('SELECT * FROM users WHERE oauth_id = ? AND oauth_provider = ?', 
        [profile.id, 'google']);
      
      if (rows.length > 0) {
        return done(null, rows[0]);
      }
      
      const [existingUser] = await pool.query('SELECT * FROM users WHERE email = ?', [profile.emails[0].value]);
      
      if (existingUser.length > 0) {
        await pool.query('UPDATE users SET oauth_id = ?, oauth_provider = ? WHERE id = ?',
          [profile.id, 'google', existingUser[0].id]);
        return done(null, existingUser[0]);
      }
      
      const username = profile.displayName.replace(/\s/g, '') + Math.floor(Math.random() * 1000);
      const [result] = await pool.query(
        'INSERT INTO users (username, email, oauth_id, oauth_provider, password_hash, role) VALUES (?, ?, ?, ?, ?, ?)',
        [username, profile.emails[0].value, profile.id, 'google', 'oauth_user', 'user']
      );
      
      const [newUser] = await pool.query('SELECT * FROM users WHERE id = ?', [result.insertId]);
      return done(null, newUser[0]);
      
    } catch (error) {
      return done(error, null);
    }
  }
));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  const [rows] = await pool.query('SELECT * FROM users WHERE id = ?', [id]);
  done(null, rows[0]);
});

// Google Auth Route
router.get('/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

// Google Callback Route
router.get('/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    const token = jwt.sign(
      { id: req.user.id, username: req.user.username, role: req.user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.send(`
      <html>
      <body>
      <script>
        localStorage.setItem('token', '${token}');
        localStorage.setItem('user', JSON.stringify({
          id: ${req.user.id},
          username: '${req.user.username}',
          email: '${req.user.email}',
          role: '${req.user.role}'
        }));
        window.location.href = '/dashboard.html';
      </script>
      </body>
      </html>
    `);
  }
);

module.exports = router;