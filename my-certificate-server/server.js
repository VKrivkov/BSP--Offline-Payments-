const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const port = 3456;

// Middleware to parse JSON bodies
app.use(bodyParser.json());

// Helper function to load and parse the certificate
function parseCertificate(pemCert) {
    const cert = new crypto.X509Certificate(pemCert); // Corrected constructor usage

    return {
        subject: cert.subject,
        issuer: cert.issuer,
        validFrom: cert.validFrom.toISOString(), // Ensure date is properly formatted
        validTo: cert.validTo.toISOString(), // Ensure date is properly formatted
        publicKey: cert.publicKey.export({ format: 'pem', type: 'spki' }) // Export public key in PEM format
    };
}

// Route to handle GET requests to the root URL
app.get('/', (req, res) => {
    res.send('Hello, your server is running and ready to receive certificates!');
});

// Route to receive the certificate
app.post('/submit-certificate', (req, res) => {
    try {
        const pemCert = req.body.pemCertificate;
        const certDetails = parseCertificate(pemCert);

        // Logging for demonstration
        console.log('Received Certificate:');
        console.log(`Subject: ${certDetails.subject}`);
        console.log(`Issuer: ${certDetails.issuer}`);
        console.log(`Valid From: ${certDetails.validFrom}`);
        console.log(`Valid To: ${certDetails.validTo}`);
        console.log(`Public Key: ${certDetails.publicKey}`);

        // Respond to the client
        res.send({
            message: 'Certificate received and parsed successfully',
            subject: certDetails.subject,
            issuer: certDetails.issuer,
            validFrom: certDetails.validFrom,
            validTo: certDetails.validTo,
            publicKey: certDetails.publicKey
        });
    } catch (error) {
        console.error('Error parsing the certificate:', error);
        res.status(400).send('Invalid certificate format');
    }
});

app.listen(port, '0.0.0.0', () => {
    console.log(`Server test listening at http://0.0.0.0:${port}`);
});
