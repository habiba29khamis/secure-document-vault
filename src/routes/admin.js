const express = require('express');
const router = express.Router();
const { authenticateToken, isAdmin } = require('../middleware/auth');

// Get all users (Admin only)
router.get('/users', authenticateToken, isAdmin, (req, res) => {
    const query = 'SELECT id, username, email, role, two_factor_enabled, created_at FROM users';
    
    req.db.query(query, (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(results);
    });
});

// Update user role (Admin only)
router.put('/users/:id/role', authenticateToken, isAdmin, (req, res) => {
    const { role } = req.body;
    const userId = req.params.id;
    
    const validRoles = ['user', 'manager', 'admin'];
    if (!validRoles.includes(role)) {
        return res.status(400).json({ error: 'Invalid role' });
    }
    
    const query = 'UPDATE users SET role = ? WHERE id = ?';
    req.db.query(query, [role, userId], (err, result) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (result.affectedRows === 0) return res.status(404).json({ error: 'User not found' });
        res.json({ message: 'User role updated successfully' });
    });
});

// Delete user (Admin only)
router.delete('/users/:id', authenticateToken, isAdmin, (req, res) => {
    const userId = req.params.id;
    
    const query = 'DELETE FROM users WHERE id = ?';
    req.db.query(query, [userId], (err, result) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (result.affectedRows === 0) return res.status(404).json({ error: 'User not found' });
        res.json({ message: 'User deleted successfully' });
    });
});

// Get all documents (Admin only)
router.get('/documents', authenticateToken, isAdmin, (req, res) => {
    const query = 'SELECT d.*, u.username FROM documents d JOIN users u ON d.user_id = u.id ORDER BY d.uploaded_at DESC';
    
    req.db.query(query, (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(results);
    });
});

module.exports = router;