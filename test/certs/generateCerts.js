// Truffle automatically runs this file on test
// To generate certs anew, delete ./validNotAfter.txt

const forge = require('node-forge')
const fs = require('fs')
const extensions = require('./extensions.json')

let expiration
try {
    expiration = fs.readFileSync(__dirname + '/validNotAfter.txt').toString()
} catch (error) {
    if (!error.message.includes("no such file or directory")) throw error
}

if (!expiration || Date.now() > parseInt(expiration) - 10000) {
    console.log('generating new certificates')
    // Save new expiration
    const now = Date.now()
    let expDate = new Date(now)
    expDate.setFullYear(expDate.getFullYear() + 1)
    expiration = expDate.getTime()
    fs.writeFileSync(__dirname + '/validNotAfter.txt', expiration.toString())
    
    let rootKeys = forge.pki.rsa.generateKeyPair(2048);
    let intermediateKeys = forge.pki.rsa.generateKeyPair(2048);
    let leafKeys = forge.pki.rsa.generateKeyPair(2048);
    let invalidKeys = forge.pki.rsa.generateKeyPair(2048);
    
    const rootPemCert = generateCert(now, expiration, extensions.root, rootKeys.publicKey, rootKeys.privateKey);
    const intermediatePemCert = generateCert(now, expiration, extensions.intermediate, intermediateKeys.publicKey, rootKeys.privateKey);
    const leafPemCert = generateCert(now, expiration, extensions.leaf, leafKeys.publicKey, intermediateKeys.privateKey);
    const invalidPemCert = generateCert(now, expiration, extensions.invalid, invalidKeys.publicKey, leafKeys.privateKey);

    const rootPemPubKey = forge.pki.publicKeyToPem(rootKeys.publicKey)
    const intermediatePemPubKey = forge.pki.publicKeyToPem(intermediateKeys.publicKey)
    const leafPemPubKey = forge.pki.publicKeyToPem(leafKeys.publicKey)
    const wrapped = forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(leafKeys.privateKey))
    const leafPemPrivKey = forge.pki.privateKeyInfoToPem(wrapped)
    const invalidPemPubKey = forge.pki.publicKeyToPem(invalidKeys.publicKey)

    // Write certificates and keys to file
    fs.writeFileSync(__dirname + '/root.pem', rootPemCert)
    fs.writeFileSync(__dirname + '/intermediate.pem', intermediatePemCert)
    fs.writeFileSync(__dirname + '/leaf.pem', leafPemCert)
    fs.writeFileSync(__dirname + '/invalid.pem', invalidPemCert)
    fs.writeFileSync(__dirname + '/rootPubKey.pem', rootPemPubKey)
    fs.writeFileSync(__dirname + '/intermediatePubKey.pem', intermediatePemPubKey)
    fs.writeFileSync(__dirname + '/leafPubKey.pem', leafPemPubKey)
    fs.writeFileSync(__dirname + '/leafPrivKey.pem', leafPemPrivKey)
    fs.writeFileSync(__dirname + '/invalidPubKey.pem', invalidPemPubKey)
}

function generateCert(now, expiration, extensions, subjectPubKey, authorityPrivKey) {
    // Generate new Key pair and cert
    let cert = forge.pki.createCertificate();
    cert.publicKey = subjectPubKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date(now);
    cert.validity.notAfter = new Date(expiration);
    var attrs = [
        { name: 'countryName', value: 'US' },
        { shortName: 'ST', value: 'Michigan' },
        { name: 'localityName', value: 'Grand Rapids' },
        { name: 'organizationName', value: 'PKI Payment Network' },
        { shortName: 'OU', value: 'Test' }
    ];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.setExtensions(extensions);
    cert.sign(authorityPrivKey, forge.md.sha256.create());

    const pemCert = forge.pki.certificateToPem(cert)

    return pemCert
}