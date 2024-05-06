const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const forge = require('node-forge');
const fs = require('fs');
const axios = require('axios');
const CRL_URL = 'https://android.googleapis.com/attestation/status';

const app = express();
const port = 3456;

// Middleware to parse JSON bodies
app.use(bodyParser.json());

const asn1 = require('asn1.js');
const cbor = require('cbor');

const { Certificate } = require('@fidm/x509');
const { ASN1 } = require('@lapo/asn1js');

const GOOGLE_ROOT_CERT =
"-----BEGIN PUBLIC KEY-----"
'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xU' +
'FmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5j' +
'lRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y' +
'//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73X' +
'pXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYI' +
'mQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB' +
'+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7q' +
'uvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgp' +
'Zrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7' +
'gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82' +
'ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+' +
'NpUFgNPN9PvQi8WEg5UmAGMCAwEAAQ==' +
"-----END PUBLIC KEY-----"; 

// Helper function to load and parse the certificate
function loadCertificate(pemCert) {
    console.log('Received PEM certificate:', pemCert); // Log the received PEM certificate
    return Certificate.fromPEM(Buffer.from(pemCert));
}

// Function to verify the root certificate
function verifyRootCertificate(cert) {
    const issuerCert = Certificate.fromPEM(Buffer.from(GOOGLE_ROOT_CERT));
    return cert.issuerSubject === issuerCert.subject && issuerCert.checkSignature(cert) === null;
}

// Function to verify the certificate chain
function verifyCertificateChain(cert) {
    const issuerCert = Certificate.fromPEM(Buffer.from(GOOGLE_ROOT_CERT));
    return issuerCert.checkSignature(cert) === null;
}

// Parse Key Attestation Extension
function parseAttestationExtension(cert) {
    const extension = cert.extensions.find(ext => ext.oid === '1.3.6.1.4.1.11129.2.1.17');
    if (!extension) return null;
    const result = ASN1.decode(extension.value);
    return result; // Simplified for demonstration; parse according to actual structure
}

// Function to handle incoming certificates
app.post('/submit-certificate', async (req, res) => {
    try {
        const pemCert = req.body.pemCertificate;
        console.log('Received PEM certificate from request body:', pemCert); // Log the PEM certificate from request body
        const cert = loadCertificate(pemCert);

        const rootValid = verifyRootCertificate(cert);
        const chainValid = verifyCertificateChain(cert);
        const attestationDetails = parseAttestationExtension(cert);

        res.send({
            message: 'Certificate processed successfully',
            rootValid,
            chainValid,
            attestationDetails
        });

    } catch (error) {
        console.error('Error processing the certificate:', error);
        res.status(400).send('Invalid certificate format');
    }
});

app.listen(port, '0.0.0.0', () => {
    console.log(`Server listening at http://0.0.0.0:${port}`);
});