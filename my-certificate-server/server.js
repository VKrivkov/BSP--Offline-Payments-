const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const fs = require('fs');
const axios = require('axios');
const CRL_URL = 'https://android.googleapis.com/attestation/status';
const EC = require('elliptic').ec;
const ec = new (require('elliptic').ec)('p256');  // Adjust the curve type based on your requirements
const https = require('https');

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


//WORKS
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
//WORKS
function fetchCRL() {
    return new Promise((resolve, reject) => {
        https.get(CRL_URL, (res) => {
            if (res.statusCode < 200 || res.statusCode >= 300) {
                return reject(new Error('Failed to load page, status code: ' + res.statusCode));
            }
            let data = '';
            res.on('data', (chunk) => {
                data += chunk;
            });
            res.on('end', () => {
                try {
                    resolve(JSON.parse(data));
                } catch (e) {
                    reject(e);
                }
            });
        }).on('error', (err) => {
            reject(err);
        });
    });
}
//WORKS
function verifyCertificateChain(certificates) {
    fetchCRL().then((crl) => {
        certificates.forEach(cert => {
            const certObj = new crypto.X509Certificate(cert.raw);
            const serialNumber = certObj.serialNumber.toLowerCase();
            if (crl.entries[serialNumber]) {
                console.log(`Certificate with serial ${serialNumber} is ${crl.entries[serialNumber].status}.`);
                if (crl.entries[serialNumber].status === 'REVOKED') {
                    console.warn(`Revoked certificate detected: Serial ${serialNumber}`);
                }
            } else {
                console.log(`Certificate with serial ${serialNumber} is valid.`);
            }
        });
    }).catch((error) => {
        console.error('Error verifying certificate chain:', error);
    });
}


function bufferToPem(buffer) {
    // Base64 encode the binary data
    const base64Certificate = buffer.toString('base64');
  
    // Split the base64 string into lines of 64 characters long
    let result = '-----BEGIN PUBLIC KEY-----\n';
    let lineLength = 64;
    for (let i = 0; i < base64Certificate.length; i += lineLength) {
        result += base64Certificate.substring(i, i + lineLength) + '\n';
    }
    result += '\n-----END PUBLIC KEY-----';
    return result;

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
        //const attestationDetails = parseAttestationExtension(cert);
        const RPK = cert[cert.length - 1];
        console.log("KEY RAW DATA: ", RPK);

        const pemRPK = bufferToPem(RPK);
        console.log("KEY RAW DATA: ", pemRPK);

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