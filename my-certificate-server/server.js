const express = require('express');
const bodyParser = require('body-parser');
const forge = require('node-forge');

const app = express();
const port = 3456;

// Middleware to parse JSON bodies
app.use(bodyParser.json());

// Route to handle GET requests to the root URL
app.get('/', (req, res) => {
    res.send('Hello, your server is running and ready to receive certificates!');
});

// Route to receive the certificate
app.post('/submit-certificate', (req, res) => {
    try {
        const pemCert = req.body.pemCertificate;
        const cert = forge.pki.certificateFromPem(pemCert); // Parse the PEM certificate to a Forge object

        // Attempt to handle various types of public keys
        let publicKey;
        try {
            if (cert.publicKey.n && cert.publicKey.e) { // RSA specific properties
                publicKey = cert.publicKey;
            } else if (cert.publicKey.getPublicKey) { // ECDSA or other types
                publicKey = cert.publicKey.getPublicKey();
            } else {
                throw new Error("Unsupported public key type.");
            }
        } catch (pubKeyError) {
            throw new Error("Error parsing public key: " + pubKeyError.message);
        }

        // Extract information from the certificate
        const subject = cert.subject.attributes.map(attr => `${attr.name}=${attr.value}`).join(', ');
        const issuer = cert.issuer.attributes.map(attr => `${attr.name}=${attr.value}`).join(', ');
        const validFrom = cert.validity.notBefore;
        const validTo = cert.validity.notAfter;

        // Logging for demonstration
        console.log('Received Certificate:');
        console.log(`Subject: ${subject}`);
        console.log(`Issuer: ${issuer}`);
        console.log(`Valid From: ${validFrom}`);
        console.log(`Valid To: ${validTo}`);
        console.log(`Public Key: ${publicKey}`);

        // Respond to the client
        res.send({
            message: 'Certificate received and parsed successfully',
            subject,
            issuer,
            validFrom,
            validTo
        });
    } catch (error) {
        console.error('Error parsing the certificate:', error);
        res.status(400).send('Invalid certificate format');
    }
});

app.listen(port, '0.0.0.0', () => {
    console.log(`Server listening at http://0.0.0.0:${port}`);
});
