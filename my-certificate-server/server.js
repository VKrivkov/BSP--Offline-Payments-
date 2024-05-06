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

// ASN.1 parsing for Key Attestation Extension
const KeyAttestation = asn1.define('KeyAttestation', function() {
  this.seq().obj(
    this.key('attestationVersion').int(),
    this.key('attestationSecurityLevel').int(),
    this.key('keyMintVersion').int(),
    this.key('keyMintSecurityLevel').int(),
    this.key('attestationChallenge').octstr(),
    this.key('uniqueId').octstr(),
    this.key('softwareEnforced').any(),
    this.key('hardwareEnforced').any()
  );
});







// Helper function to load and parse the certificate
function parseCertificate(pemCert) {
    const cert = new crypto.X509Certificate(pemCert); // Corrected constructor usage

    return {
        publicKey: cert.publicKey.export({ format: 'pem', type: 'spki' }),
        raw: cert // Include the raw PEM certificate in the response
    };
}

// Function to verify the trustworthiness of the root public certificate
function verifyRootCertificate(publicKey) {
    const googleRootKey = 'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xU' +
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
        'NpUFgNPN9PvQi8WEg5UmAGMCAwEAAQ==';

        try {
            const fingerprint = forge.pki.getPublicKeyFingerprint(publicKey, {encoding: 'hex', md: md});
            
            return fingerprint === googleRootKey;
        } catch (error) {
            console.error('Failed to process public key:', error);
            return false;
        }
}

// Function to verify the chain of trust
function verifyCertificateChain(chain) {
    for (let i = 0; i < chain.length - 1; i++) {
        const currentCert = chain[i];
        const nextCert = chain[i + 1];

        // Verify that the current certificate signs the next certificate
        const verified = forge.pki.verifyCertificateChain({
            caStore: [currentCert],
            chain: [nextCert]
        });

        if (!verified) {
            return false;
        }
    }
    return true;
}


function parseAttestationExtension(certificate) {
    const extensions = certificate.extensions || [];
    const attExt = extensions.find(ext => ext.oid === '1.3.6.1.4.1.11129.2.1.17');
    if (!attExt) return null;
    return KeyAttestation.decode(attExt.data, 'der');
  }
  
  function parseProvisioningExtension(certificate) {
    const extensions = certificate.extensions || [];
    const provExt = extensions.find(ext => ext.oid === '1.3.6.1.4.1.11129.2.1.30');
    if (!provExt) return null;
    return cbor.decodeFirstSync(provExt.data);
  }
  
  
  async function checkRevocation(certificate) {
    const serialNumber = certificate.serialNumber.toString(16);
    const crlResponse = await axios.get(CRL_URL);
    const entries = crlResponse.data.entries || {};
    return entries[serialNumber] || 'Active'; // Assuming 'Active' means not revoked
  }


// Route to handle GET requests to the root URL
app.get('/', (req, res) => {
    res.send('Hello, your server is running and ready to receive certificates!');
});

// Route to receive the certificate
app.post('/submit-certificate', async (req, res) => {
    try {
        const pemCert = req.body.pemCertificate;
        const certDetails = parseCertificate(pemCert);
        const attestationDetails = parseAttestationExtension(certDetails.raw);
        const provisioningInfo = parseProvisioningExtension(certDetails.raw);
        const revocationStatus = await checkRevocation(certDetails.raw);
        const root = verifyRootCertificate(certDetails.publicKey);
        const chain = verifyCertificateChain(certDetails.raw);

        // Logging for demonstration
        console.log('Received Certificate:');
        console.log(`Public Key: ${certDetails.publicKey}`);
        console.log(`Data: ${certDetails.raw}`)
        console.log(`Root: ${root}`)
        console.log(`Chain: ${chain}`)
        console.log(`attestationDetails: ${attestationDetails}`)
        console.log(`provisioningInfo: ${provisioningInfo}`)
        console.log(`revocationStatus: ${revocationStatus}`)




        // Respond to the client
        res.send({
            message: 'Certificate received and parsed successfully',
            cert: certDetails.raw,
            publicKey: certDetails.publicKey,
            attestationDetails,
            provisioningInfo,
            revocationStatus
        });

    } catch (error) {
        console.error('Error parsing the certificate:', error);
        res.status(400).send('Invalid certificate format');
    }
});

app.listen(port, '0.0.0.0', () => {
    console.log(`Server test listening at http://0.0.0.0:${port}`);
});
