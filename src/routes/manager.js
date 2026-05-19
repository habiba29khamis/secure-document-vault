const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const fs = require('fs');
const { authenticateToken, isManager } = require('../middleware/auth');

// Get all documents for review (Strictly Manager)
router.get('/documents', authenticateToken, isManager, (req, res) => {
    // We use d.* to ensure we pull all document columns, avoiding missing column errors
    const query = 'SELECT d.*, u.username FROM documents d JOIN users u ON d.user_id = u.id ORDER BY d.uploaded_at DESC';
    
    req.db.query(query, (err, results) => {
        if (err) {
            console.error("DB Error in Manager Docs:", err);
            return res.status(500).json({ error: 'Database error fetching documents' });
        }
        res.json(results);
    });
});

// Verify any document
router.get('/verify/:id', authenticateToken, isManager, (req, res) => {
    const documentId = req.params.id;
    
    req.db.query('SELECT * FROM documents WHERE id = ?', [documentId], (err, docs) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (docs.length === 0) return res.status(404).json({ error: 'Document not found' });
        
        const doc = docs[0];
        
        req.db.query('SELECT * FROM signatures WHERE document_id = ?', [documentId], (err, sigs) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            if (sigs.length === 0) return res.status(404).json({ error: 'Signature not found' });
            
            const signature = sigs[0];
            
            try {
                const encryptedPath = doc.file_path;
                const encryptionKey = process.env.ENCRYPTION_KEY;
                const key = Buffer.from(encryptionKey, 'utf8');
                const iv = Buffer.from(doc.iv, 'hex');
                const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
                
                const encryptedContent = fs.readFileSync(encryptedPath);
                const decrypted = Buffer.concat([decipher.update(encryptedContent), decipher.final()]);
                
                const currentHash = crypto.createHash('sha256').update(decrypted).digest('hex');
                const signatureSecret = process.env.JWT_SECRET;
                const expectedSignature = crypto.createHmac('sha256', signatureSecret).update(signature.hash_value).digest('hex');
                
                res.json({
                    documentId: documentId,
                    originalName: doc.original_name,
                    integrityValid: (currentHash === signature.hash_value),
                    signatureValid: (expectedSignature === signature.signature)
                });
            } catch (error) {
                console.error(error);
                res.status(500).json({ error: 'Verification failed' });
            }
        });
    });
});

module.exports = router;