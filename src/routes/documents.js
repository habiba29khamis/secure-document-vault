const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const router = express.Router();
const { authenticateToken } = require('../middleware/auth');

// Configure multer for file upload
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = path.join(__dirname, '../../uploads');
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueName = crypto.randomBytes(16).toString('hex') + path.extname(file.originalname);
        cb(null, uniqueName);
    }
});

const fileFilter = (req, file, cb) => {
    const allowedTypes = ['application/pdf', 'image/jpeg', 'image/png', 'text/plain', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
    if (allowedTypes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error('Invalid file type. Allowed: PDF, JPEG, PNG, TXT, DOC, DOCX'), false);
    }
};

const upload = multer({ 
    storage: storage, 
    fileFilter: fileFilter,
    limits: { fileSize: 5 * 1024 * 1024 }
});

// Generate SHA-256 hash of file
function generateHash(filePath) {
    const fileContent = fs.readFileSync(filePath);
    const hash = crypto.createHash('sha256').update(fileContent).digest('hex');
    return hash;
}

// Generate digital signature (using HMAC as simple signature)
function generateSignature(hash, secretKey) {
    const signature = crypto.createHmac('sha256', secretKey).update(hash).digest('hex');
    return signature;
}

// Encrypt file
function encryptFile(filePath, encryptionKey) {
    const iv = crypto.randomBytes(16);
    const key = Buffer.from(encryptionKey, 'utf8');
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    
    const fileContent = fs.readFileSync(filePath);
    const encrypted = Buffer.concat([cipher.update(fileContent), cipher.final()]);
    
    const encryptedPath = filePath + '.enc';
    fs.writeFileSync(encryptedPath, encrypted);
    fs.unlinkSync(filePath);
    
    return { iv: iv.toString('hex'), encryptedPath };
}

// Upload document with signature
router.post('/upload', authenticateToken, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const encryptionKey = process.env.ENCRYPTION_KEY;
        if (!encryptionKey || encryptionKey.length !== 32) {
            return res.status(500).json({ error: 'Encryption key not configured properly' });
        }

        // Generate hash of original file
        const fileHash = generateHash(req.file.path);
        
        // Generate digital signature
        const signatureSecret = process.env.JWT_SECRET;
        const signature = generateSignature(fileHash, signatureSecret);
        
        // Encrypt the file
        const { iv, encryptedPath } = encryptFile(req.file.path, encryptionKey);

        // Store in database
        const query = `INSERT INTO documents (user_id, filename, original_name, file_size, file_type, encrypted_key, iv, file_path) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
        
        req.db.query(query, [
            req.user.id,
            path.basename(encryptedPath),
            req.file.originalname,
            req.file.size,
            req.file.mimetype,
            'encrypted',
            iv,
            encryptedPath
        ], (err, result) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ error: 'Database error' });
            }
            
            // Store signature
            const sigQuery = `INSERT INTO signatures (document_id, hash_value, signature) VALUES (?, ?, ?)`;
            req.db.query(sigQuery, [result.insertId, fileHash, signature], (err2) => {
                if (err2) {
                    console.error(err2);
                }
            });
            
            res.json({ 
                message: 'File uploaded, encrypted, and signed successfully',
                documentId: result.insertId,
                originalName: req.file.originalname,
                fileHash: fileHash,
                signature: signature.substring(0, 20) + '...'
            });
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Upload failed' });
    }
});

// Verify document integrity
router.get('/verify/:id', authenticateToken, (req, res) => {
    const documentId = req.params.id;
    
    req.db.query('SELECT * FROM documents WHERE id = ? AND user_id = ?', [documentId, req.user.id], (err, docs) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (docs.length === 0) return res.status(404).json({ error: 'Document not found' });
        
        const doc = docs[0];
        
        req.db.query('SELECT * FROM signatures WHERE document_id = ?', [documentId], (err, sigs) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            if (sigs.length === 0) return res.status(404).json({ error: 'Signature not found' });
            
            const signature = sigs[0];
            
            // Read encrypted file and decrypt to verify
            const encryptedPath = doc.file_path;
            const encryptionKey = process.env.ENCRYPTION_KEY;
            const key = Buffer.from(encryptionKey, 'utf8');
            const iv = Buffer.from(doc.iv, 'hex');
            const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
            
            const encryptedContent = fs.readFileSync(encryptedPath);
            const decrypted = Buffer.concat([decipher.update(encryptedContent), decipher.final()]);
            
            // Calculate hash of decrypted content
            const currentHash = crypto.createHash('sha256').update(decrypted).digest('hex');
            
            // Verify signature
            const signatureSecret = process.env.JWT_SECRET;
            const expectedSignature = crypto.createHmac('sha256', signatureSecret).update(signature.hash_value).digest('hex');
            const isSignatureValid = (expectedSignature === signature.signature);
            const isIntegrityValid = (currentHash === signature.hash_value);
            
            res.json({
                documentId: documentId,
                originalName: doc.original_name,
                integrityValid: isIntegrityValid,
                signatureValid: isSignatureValid,
                message: isIntegrityValid && isSignatureValid ? 'Document is authentic and untampered' : 'Document may have been tampered!'
            });
        });
    });
});

// List user's documents
router.get('/list', authenticateToken, (req, res) => {
    const query = 'SELECT id, original_name, file_size, uploaded_at FROM documents WHERE user_id = ? ORDER BY uploaded_at DESC';
    
    req.db.query(query, [req.user.id], (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(results);
    });
});

// Delete document
router.delete('/delete/:id', authenticateToken, (req, res) => {
    const documentId = req.params.id;
    
    // First get the file path
    req.db.query('SELECT file_path FROM documents WHERE id = ? AND user_id = ?', [documentId, req.user.id], (err, docs) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (docs.length === 0) return res.status(404).json({ error: 'Document not found' });
        
        const filePath = docs[0].file_path;
        
        // Delete from database
        req.db.query('DELETE FROM documents WHERE id = ? AND user_id = ?', [documentId, req.user.id], (err) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            
            // Delete file from disk
            const fs = require('fs');
            if (fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
            }
            
            res.json({ message: 'Document deleted successfully' });
        });
    });
});


module.exports = router;