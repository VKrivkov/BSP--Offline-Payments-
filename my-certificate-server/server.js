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
        publicKey: cert.publicKey.export({ format: 'pem', type: 'spki' }),
        raw: pemCert // Include the raw PEM certificate in the response
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
        console.log(`Public Key: ${certDetails.publicKey}`);
        console.log(`Data: ${certDetails.publicKey}`)

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
