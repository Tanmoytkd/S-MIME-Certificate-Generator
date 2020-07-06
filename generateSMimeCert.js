const forge = require('node-forge');
const fs = require('fs');
const { strict } = require('assert');

const DEFAULT_PASSWORD = 'theta1234';

let generateSMimeCert = function (email, certPassword) {
    try {
        // generate a keypair
        var keys = forge.pki.rsa.generateKeyPair(2048);

        // create a certificate
        var cert = forge.pki.createCertificate();
        cert.publicKey = keys.publicKey;
        cert.serialNumber = '01';
        cert.validity.notBefore = new Date();
        cert.validity.notAfter = new Date();
        cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
        var attrs = [{
            name: 'commonName',
            value: email
        }, {
            name: 'countryName',
            value: 'BD'
        }, {
            shortName: 'ST',
            value: 'Dhaka'
        }, {
            name: 'localityName',
            value: 'Dhaka'
        }, {
            name: 'organizationName',
            value: 'Cryptic'
        }, {
            shortName: 'OU',
            value: 'Cryptic'
        }];
        cert.setSubject(attrs);
        cert.setIssuer(attrs);
        cert.setExtensions([{
            name: 'basicConstraints',
            cA: true
        }, {
            name: 'keyUsage',
            keyCertSign: true,
            digitalSignature: true,
            nonRepudiation: true,
            keyEncipherment: true,
            dataEncipherment: true,

            keyAgreement: false,
            cRLSign: false,
            encipherOnly: false,
            decipherOnly: false
        }, {
            name: 'subjectAltName',
            altNames: [{
                type: 1,
                value: email
            }]
        }, {
            name: "extKeyUsage",
            clientAuth: true,
            emailProtection: true
        }]);

        // self-sign certificate
        cert.sign(keys.privateKey, forge.md.sha256.create());

        // create PKCS12
        var password = certPassword ? certPassword : DEFAULT_PASSWORD;
        var newPkcs12Asn1 = forge.pkcs12.toPkcs12Asn1(
            keys.privateKey,
            [cert],
            password,
            {
                generateLocalKeyId: true,
                friendlyName: 'test'
            }
        );

        var newPkcs12Der = forge.asn1.toDer(newPkcs12Asn1).getBytes();
        fs.writeFileSync(__dirname + `/${email}.p12`, newPkcs12Der, { encoding: 'binary' });

    } catch (ex) {
        if (ex.stack) {
            console.log(ex.stack);
        } else {
            console.log('Error', ex);
        }
    }
}


module.exports = generateSMimeCert;