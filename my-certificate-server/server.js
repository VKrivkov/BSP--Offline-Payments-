const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const CRL_URL = 'https://android.googleapis.com/attestation/status';
const https = require('https');
const app = express();
const port = 3456;

// Middleware to parse JSON bodies
app.use(bodyParser.json());

const { Certificate } = require('@fidm/x509');
const asn1 = require('asn1');
const { read } = require('fs');
const Ber = asn1.Ber;


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

//WORKS FOR MANDATORY FIELDS
class KeyDescription {
    constructor(reader) {
        try {
            if (reader.readSequence()) {
                this.attestationVersion = this.AttestationVersion(reader.readInt());  // Static value as per your schema
                this.attestationSecurityLevel = this.SecurityLevel(reader.readEnumeration());  // Reading ENUMERATED SecurityLevel

                this.keyMasterVersion = this.KeyMasterVersion(reader.readInt());  // Reading INTEGER
                this.keyMintSecurityLevel = this.SecurityLevel(reader.readEnumeration());  // Reading ENUMERATED SecurityLevel
                this.attestationChallenge = this.AttestationChallenge(reader.readString(0x04, true));  // Reading OCTET_STRING
                this.uniqueId = reader.readString(0x04, true);  // Reading OCTET_STRING
            }
        } catch (error) {
            console.error('Failed to parse KeyDescription:', error);
            console.log('Reader state:', reader);
            throw error;
        }
    }

    SecurityLevel(secLevel){
        switch(secLevel){
            case 0:
                return 'Software';
            case 1:
                return 'TrustedEnvironment';
            case 2:
                return 'StrongBox';
            default:
                return 'Unknown';
        }
    }

    KeyMasterVersion(version){
        switch(version){
            case 0:
                return 'Keymaster version 0.2 or 0.3';
            case 1:
                return 'Keymaster version 1.0';
            case 2:
                return 'Keymaster version 2.0';
            case 3:
                return 'Keymaster version 3.0';
            case 4:
                return 'Keymaster version 4.0';
            case 41:
                return 'Keymaster version 4.1';
            case 100:
                return 'KeyMint version 1.0';
            case 200:
                return 'KeyMint version 2.0';
            default:
                return 'Unknown';
        }
    }

    AttestationVersion(version){
        switch(version){

            case 1:
                return 'Keymaster version 2.0';
            case 2:
                return 'Keymaster version 3.0';
            case 3:
                return 'Keymaster version 4.0';
            case 4:
                return 'Keymaster version 4.1';
            case 100:
                return 'KeyMint version 1.0';
            case 200:
                return 'KeyMint version 2.0';
            default:
                return 'Unknown';
        }
    }

    AttestationChallenge(challenge){
        return challenge.toString('utf-8');

    }
}

//WORKS
function parseCertificateChain(chain) {
    try {
        // Normalize newlines and ensure the chain ends properly
        chain = chain.replace(/\r\n/g, '\n').trim() + '\n';

        // Split the certificates, considering potential formatting issues
        const certs = chain.split('\n-----END CERTIFICATE-----')
                           .filter(cert => cert.trim() !== '')  // Filter out any empty results
                           .map(cert => cert.trim() + '\n-----END CERTIFICATE-----');
 
        // Parse each certificate
        const certificates = certs.map(cert => Certificate.fromPEM(Buffer.from(cert)));
        console.log("Parsed Certificates: ", certificates.length);
        for(let i = 0; i < certificates.length; i++) {
            console.log(`CERTIFICATE ${i + 1}\n: `, certificates[i]);
        }
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
async function verifyCertificateChain(certificates) {
    try {
        const crl = await fetchCRL(); // Wait for the CRL fetch to complete
        let allValid = true; // Assume all certificates are valid initially

        for (let i = 0; i < certificates.length; i++) {
            const certObj = new crypto.X509Certificate(certificates[i].raw);
            const serialNumber = certObj.serialNumber.toLowerCase();
            if (crl.entries[serialNumber]) {
                console.log(`Certificate with serial ${serialNumber} is ${crl.entries[serialNumber].status}.`);
                if (crl.entries[serialNumber].status === 'REVOKED') {
                    console.warn(`Revoked certificate detected: Serial ${serialNumber}`);
                    allValid = false; // If any certificate is revoked, set allValid to false
                }
            } else {
                console.log(`Certificate with serial ${serialNumber} is NOT revoked.`);
            }
        

            if (i < certificates.length - 2) {
                const issuerCertObj = new crypto.X509Certificate(certificates[i + 1].raw);
                // Verify current certificate using issuer's public key
                if (!certificates[i].verify(issuerCertObj.publicKey)) {
                    console.warn(`Certificate with serial ${serialNumber} is not properly signed by its issuer.`);
                    allValid = false; // Mark as invalid if not properly signed
                }
            }
        }

        return allValid; // Return true if all certificates are valid, false otherwise
    } catch (error) {
        console.error('Error verifying certificate chain:', error);
        return false; // Return false if there's an error in processing
    }
}

//WORKS
function verifyRootPublicKey(publicKey) {
    const formattedPublicKey = publicKey.replace(/\s/g, '').trim();
    const formattedGoogleRootKey = GOOGLE_ROOT_KEY.replace(/\s/g, '').trim();

    // Debugging: Print the keys to be compared
    console.log("Formatted Public Key:", formattedPublicKey);
    console.log("Formatted Google Root Key:", formattedGoogleRootKey);

    // Use strict equality for comparison
    return formattedPublicKey === formattedGoogleRootKey;
}

//WORKS
function parseAttestationExtension(cert) {
    try {
        const exts = cert.extensions;
        let keyDescriptionExt = exts.find(ext => ext.oid === '1.3.6.1.4.1.11129.2.1.17');
        if (!keyDescriptionExt) {
            throw new Error('Key attestation extension not found');
        }

        const reader = new Ber.Reader(keyDescriptionExt.value);
        const keyDescription = new KeyDescription(reader);
        console.log('Parsed Key Description:', keyDescription);
        return keyDescription;
        
    } catch (error) {
        console.error('Error parsing attestation extension:', error);
        throw error;
    }
}   


// Function to handle incoming certificates
app.post('/submit-certificate', async (req, res) => {
    try {
        const base64Cert = req.body.CertificateChain.trim();
        console.log('Received PEM certificate chain from request body');
        const cert = parseCertificateChain(base64Cert);

        const chainValid = await verifyCertificateChain(cert);
        const RootCert = cert[cert.length-1];

        rootValid = verifyRootPublicKey(RootCert.publicKey.toPEM())
        console.log("CHAIN verified: ", chainValid);
        console.log("Root PK verified: ", rootValid);

        let attestationDetails = null;
        // Iterate over the certificates to find the one with the attestation extension
        for (let i = 0; i < cert.length; i++) {
            try {
                attestationDetails = parseAttestationExtension(cert[i]);
                // If parsing is successful and data is found, stop the loop
                if (attestationDetails) {
                    console.log("Attestation Details Found in Certificate", i);
                    break;
                }
            } catch (error) {
                console.log(`No attestation data in certificate ${i}`, error);
            }
        }


        await res.send({
            message: 'SUCCESS',
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