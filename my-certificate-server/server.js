const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const forge = require('node-forge');
const fs = require('fs');
const axios = require('axios');
const CRL_URL = 'https://android.googleapis.com/attestation/status';
const EC = require('elliptic').ec;
const ec = new (require('elliptic').ec)('p256');  // Adjust the curve type based on your requirements
const { pem2jwk } = require('pem-jwk');



const app = express();
const port = 3456;

// Middleware to parse JSON bodies
app.use(bodyParser.json());

const asn1 = require('asn1.js');
const cbor = require('cbor');

const { Certificate } = require('@fidm/x509');
const { ASN1 } = require('@lapo/asn1js');

const GOOGLE_ROOT_KEY =
"-----BEGIN PUBLIC KEY-----\n" +
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
"\n-----END PUBLIC KEY-----";

// Helper function to load and parse the certificate
function loadCertificate(pemCert) {
    //console.log('Received PEM certificate:', pemCert);
    try {
        return Certificate.fromPEM(Buffer.from(pemCert));
    } catch (error) {
        console.error('Error parsing PEM certificate:', error);
        throw error;
    }
}

// Function to verify the root certificate  RETURNING FALSE
function verifyRootPublicKey(certPem) {
    try {
        const cert = loadCertificate(certPem)

        const certPublicKey = cert.publicKey;
        console.log("Public Key: ", certPublicKey);

        const publicKeyBuffer = Buffer.from(certPublicKey.keyRaw);
        console.log("Public BUFFER: ", publicKeyBuffer);

        // Construct the DER format for EC public key
        const derPrefixBuffer = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');
        const publicKeyDER = Buffer.concat([derPrefixBuffer, publicKeyBuffer]);

        // Create the public key object from the DER-encoded public key
        const ecPublicKey = crypto.createPublicKey({
            key: publicKeyDER,
            format: 'der',
            type: 'spki'
        });

        const publicKeyPEM = ecPublicKey.export({ type: 'spki', format: 'pem' });
        console.log("Public Key in PEM: ", publicKeyPEM);
        return publicKeyPEM === GOOGLE_ROOT_KEY;
    } catch (error) {
        console.error('Error verifying root public key:', error);
        throw error;
    }
}

function verifyCertificateChain(certificates) {
    try {
        let previousCert = certificates[0];
        for (let i = 1; i < certificates.length; i++) {
            const cert = certificates[i];
            const isVerified = crypto.createVerify('SHA256')
                .update(previousCert)
                .verify(cert, previousCert.signature);
            if (!isVerified) {
                return false;
            }
            previousCert = cert;
        }
        // Check root certificate (self-signed)
        const rootCert = certificates[certificates.length - 1];
        const isVerifiedRoot =  crypto.createVerify('SHA256')
            .update(rootCert)
            .verify(rootCert.publicKey, rootCert.signature);
        console.log("Is root certificate verified ", isVerifiedRoot);

        var rootKey = verifyRootPublicKey(rootCert);
        console.log("Is root key verified ", rootKey);

        return isVerifiedRoot && rootKey;
    } catch (error) {
        console.error('Verification failed:', error);
        return false;
    }
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
        const pemCert = req.body.pemCertificate.trim();
        console.log('Received PEM certificate from request body:', pemCert);
        const cert = loadCertificate(pemCert);

        //const rootValid = verifyRootPublicKey(pemCert);
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