var forge = require('node-forge');
var fs = require('fs');
const { strict } = require('assert');

const DEFAULT_PASSWORD = 'theta1234';

function generateCert(email, certPassword) {
    try {
        // generate a keypair
        console.log('Generating 2048-bit key-pair...');
        var keys = forge.pki.rsa.generateKeyPair(2048);
        console.log('Key-pair created.');

        // create a certificate
        console.log('Creating self-signed certificate...');
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

            //digitalSignature: true,
            //nonRepudiation: false,
            //keyEncipherment: true,
            //dataEncipherment: false,
            keyAgreement: false,
            //keyCertSign: false,
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
        console.log('Certificate created.');

        // create PKCS12
        console.log('\nCreating PKCS#12...');
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

        console.log('\nBase64-encoded new PKCS#12:');
        console.log(forge.util.encode64(newPkcs12Der));

        // create CA store (w/own certificate in this example)
        var caStore = forge.pki.createCaStore([cert]);

        console.log('\nLoading new PKCS#12 to confirm...');
        loadPkcs12(newPkcs12Der, password, caStore);

        fs.writeFileSync(__dirname + `/${email}.p12`, newPkcs12Der, { encoding: 'binary' });

    } catch (ex) {
        if (ex.stack) {
            console.log(ex.stack);
        } else {
            console.log('Error', ex);
        }
    }
}

function loadPkcs12(pkcs12Der, password, caStore) {
    var pkcs12Asn1 = forge.asn1.fromDer(pkcs12Der);
    var pkcs12 = forge.pkcs12.pkcs12FromAsn1(pkcs12Asn1, false, password);

    // load keypair and cert chain from safe content(s) and map to key ID
    var map = {};
    for (var sci = 0; sci < pkcs12.safeContents.length; ++sci) {
        var safeContents = pkcs12.safeContents[sci];
        console.log('safeContents ' + (sci + 1));

        for (var sbi = 0; sbi < safeContents.safeBags.length; ++sbi) {
            var safeBag = safeContents.safeBags[sbi];
            console.log('safeBag.type: ' + safeBag.type);

            var localKeyId = null;
            if (safeBag.attributes.localKeyId) {
                localKeyId = forge.util.bytesToHex(
                    safeBag.attributes.localKeyId[0]);
                console.log('localKeyId: ' + localKeyId);
                if (!(localKeyId in map)) {
                    map[localKeyId] = {
                        privateKey: null,
                        certChain: []
                    };
                }
            } else {
                // no local key ID, skip bag
                continue;
            }

            // this bag has a private key
            if (safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag) {
                console.log('found private key');
                map[localKeyId].privateKey = safeBag.key;
            } else if (safeBag.type === forge.pki.oids.certBag) {
                // this bag has a certificate
                console.log('found certificate');
                map[localKeyId].certChain.push(safeBag.cert);
            }
        }
    }

    console.log('\nPKCS#12 Info:');

    for (var localKeyId in map) {
        var entry = map[localKeyId];
        console.log('\nLocal Key ID: ' + localKeyId);
        if (entry.privateKey) {
            var privateKeyP12Pem = forge.pki.privateKeyToPem(entry.privateKey);
            var encryptedPrivateKeyP12Pem = forge.pki.encryptRsaPrivateKey(
                entry.privateKey, password);

            console.log('\nPrivate Key:');
            console.log(privateKeyP12Pem);
            console.log('Encrypted Private Key (password: "' + password + '"):');
            console.log(encryptedPrivateKeyP12Pem);
        } else {
            console.log('');
        }
        if (entry.certChain.length > 0) {
            console.log('Certificate chain:');
            var certChain = entry.certChain;
            for (var i = 0; i < certChain.length; ++i) {
                var certP12Pem = forge.pki.certificateToPem(certChain[i]);
                console.log(certP12Pem);

                console.log('\n\n');
                console.log(JSON.stringify(certChain[i], null, 4));
            }

            var chainVerified = false;
            try {
                chainVerified = forge.pki.verifyCertificateChain(caStore, certChain);
            } catch (ex) {
                chainVerified = ex;
            }
            console.log('Certificate chain verified: ', chainVerified);
        }
    }
}

generateCert("fahim@tkd.codes")