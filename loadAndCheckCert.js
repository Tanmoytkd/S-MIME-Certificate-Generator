const forge = require('node-forge');
const fs = require('fs');


var pkcs12Asn1 = forge.asn1.fromDer(
    fs.readFileSync('eshita@tkd.codes.pfx', 'binary')
);
console.log(pkcs12Asn1);

var password = '2oT2546BfPzd';



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


