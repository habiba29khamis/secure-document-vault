const fs = require('fs');
const { exec } = require('child_process');

console.log('Generating self-signed certificate...');
console.log('This may take a moment...');

exec('node -e "const https = require(\'https\'); const fs = require(\'fs\'); const crypto = require(\'crypto\'); const options = { key: crypto.generateKeyPairSync(\'rsa\', { modulusLength: 2048 }).privateKey.export({ type: \'pkcs1\', format: \'pem\' }), cert: null }; https.createServer(options, (req, res) => { res.end(); }).listen(3001); console.log(\'Server started\');"', (error) => {
    if (error) console.log(error);
});