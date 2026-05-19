const jwt = require('jsonwebtoken');

// Verify JWT token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token.' });
        }
        req.user = user;
        next();
    });
}

// STRICT: Admin only
function isAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Strict Admin access required.' });
    }
    next();
}

// STRICT: Manager only
function isManager(req, res, next) {
    if (req.user.role !== 'manager') {
        return res.status(403).json({ error: 'Strict Manager access required.' });
    }
    next();
}

// STRICT: User only
function isUser(req, res, next) {
    if (req.user.role !== 'user') {
        return res.status(403).json({ error: 'Strict User access required.' });
    }
    next();
}

module.exports = { authenticateToken, isAdmin, isManager, isUser };