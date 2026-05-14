const forge = require('node-forge');
const fs = require('fs');

// Generate a keypair
const keys = forge.pki.rsa.generateKeyPair(2048);
const cert = forge.pki.createCertificate();

cert.publicKey = keys.publicKey;
cert.serialNumber = '01';
cert.validity.notBefore = new Date();
cert.validity.notAfter = new Date();
cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

const attrs = [{
    name: 'commonName',
    value: 'localhost'
}];
cert.setSubject(attrs);
cert.setIssuer(attrs);

cert.sign(keys.privateKey, forge.md.sha256.create());

// Convert to PEM format
const pemKey = forge.pki.privateKeyToPem(keys.privateKey);
const pemCert = forge.pki.certificateToPem(cert);

fs.writeFileSync('key.pem', pemKey);
fs.writeFileSync('cert.pem', pemCert);

console.log('✅ Certificate generated: key.pem and cert.pem');