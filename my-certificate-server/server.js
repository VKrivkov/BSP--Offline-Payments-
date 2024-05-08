const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const fs = require('fs');
const axios = require('axios');
const CRL_URL = 'https://android.googleapis.com/attestation/status';
const EC = require('elliptic').ec;
const ec = new (require('elliptic').ec)('p256');  // Adjust the curve type based on your requirements



const app = express();
const port = 3456;

// Middleware to parse JSON bodies
app.use(bodyParser.json());
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



function parseCertificateChain(chain) {
    try {
           // Split the certificates if the chain contains multiple
           const certs = chain.split('-----END CERTIFICATE-----\n').map(cert => cert + '-----END CERTIFICATE-----\n').slice(0, -1);
           console.log("Individual Certificates: ", certs.length);

           for(i=0; i<certs.length; i++){
            console.log("Individual Certificates: ", certs[i]);
           }
   
           // Parse each certificate using @fidm/x509
           const certificates = certs.map(cert => Certificate.fromPEM(Buffer.from(cert)));
           console.log("Parsed Certificates: ", certificates);
   
           return certificates;
    
      } catch (error) {
        console.error('Error parsing the certificates:', error);
        throw error;
      }
    }


    function verifyCertificateChain(certificates) {
        try {
            console.log("Length:", certificates.length);
            let isChainValid = true;
    
            for (let i = 0; i < certificates.length - 1; i++) {
                const issuerCert = certificates[i];
                const currentCert = certificates[i + 1];
    
                // Use the issuer's public key to verify the current certificate
                const issuerPublicKey = crypto.createPublicKey({
                    key: issuerCert.publicKeyRaw, // Adjust according to your cert structure
                    format: 'der',
                    type: 'spki'
                });
    
                const verifier = crypto.createVerify('SHA256');
                verifier.update(currentCert.raw); // This should be the raw DER-encoded data
                const isVerified = verifier.verify(issuerPublicKey, currentCert.signature); // Ensure signature is correctly formatted
    
                console.log(`Verification of certificate ${i}: ${isVerified}`);
                if (!isVerified) {
                    isChainValid = false;
                    break;
                }
            }
    
            // Check root certificate self-signed
            const rootCert = certificates[certificates.length - 1];
            const rootPublicKey = crypto.createPublicKey({
                key: rootCert.publicKeyRaw, // Adjust according to your cert structure
                format: 'der',
                type: 'spki'
            });
    
            const rootVerifier = crypto.createVerify('SHA256');
            rootVerifier.update(rootCert.raw);
            const isRootVerified = rootVerifier.verify(rootPublicKey, rootCert.signature);
    
            console.log("Is root certificate self-signed verified:", isRootVerified);
            return isChainValid && isRootVerified;
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
        const base64Cert = req.body.CertificateChain.trim();
        console.log('Received PEM certificate chain from request body:', base64Cert);
        const cert = parseCertificateChain(base64Cert);

        //const rootValid = verifyRootPublicKey(base64Cert);
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