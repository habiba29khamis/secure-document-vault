
# Prerequisites
- Node.js (v18 or higher)
- MySQL or MariaDB (XAMPP works)
2. Google OAuth Setup (if they want Google Login)
Add this section:

markdown
## 🔑 Google OAuth Setup (Optional)

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project → APIs & Services → Credentials
3. Create OAuth client ID (Web application)
4. Set redirect URI: `http://localhost:3000/api/auth/google/callback`
5. Copy Client ID and Secret to `.env` file

# 🔐 Secure Document Vault

> A secure web platform to upload, encrypt, sign, and verify documents with role-based access control.

---

## ✨ Features

| Feature | Status |
|---------|--------|
| User Registration + Login | 
| Password Hashing (bcrypt) |
| Password Policy (8+ chars, 1 uppercase, 1 number) | 
| JWT Authentication | 
| Two-Factor Authentication (2FA) | 
| Google OAuth Login | 
| Role-Based Access Control (Admin/Manager/User) | 
| AES-256 Document Encryption | 
| Digital Signatures + SHA-256 Hashing | 
| Document Integrity Verification | 
| Admin Panel | 
| HTTPS Support | 

---

## 🛠️ Tech Stack

- **Backend:** Node.js + Express
- **Database:** MySQL / MariaDB
- **Frontend:** HTML, CSS, JavaScript
- **Security:** bcrypt, JWT, speakeasy (2FA), passport (OAuth)

---

## 🚀 Setup Instructions

### 1. Clone the repository
git clone https://github.com/habiba29khamis/secure-document-vault.git
cd secure-document-vault

2. Install dependencies
npm install

3. Create .env file
env
PORT=3000
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=secure_vault
JWT_SECRET=your_jwt_secret_key_32chars
ENCRYPTION_KEY=01234567890123456789012345678901
SESSION_SECRET=your_session_secret
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret

4. Create Database
Open MySQL/MariaDB:

bash
mysql -u root -p
 Then run:

sql
CREATE DATABASE secure_vault;
USE secure_vault;

Import the schema from database.sql file.

5. Start the Server
bash
node server.js
6. Open Browser
Go to: http://localhost:3000


👑 Creating an Admin
After registering a user, run this SQL command:

sql
UPDATE users SET role = 'admin' WHERE id = 1;
🔒 HTTPS Mode
To run with HTTPS:

node server-https.js
Then open: https://localhost:3443




