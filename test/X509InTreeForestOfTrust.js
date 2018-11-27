var X509Forest = artifacts.require("X509InTreeForestOfTrust");
var RsaSha256Algorithm = artifacts.require("RsaSha256Algorithm");
var parsedCert = require('./cert');
var namehash = require('eth-ens-namehash');
var NodeRSA = require('node-rsa');
var Web3 = require('web3');
var fs = require('fs');
var sha256 = require('js-sha256');

var expectedCertId = Web3.utils.sha3(parsedCert.expectedPubKey, {encoding: 'hex'});

contract('X509InTreeForestOfTrust', (accounts) => {
  // Test addRootCert()
  it("should correctly add a valid self-signed certificate and its references", async () => {
    let instance = await X509Forest.deployed();
    let result = await instance.addRootCert(parsedCert.cert, true);
    let actualCertId = await instance.certIdsFromCN.call(Web3.utils.sha3(parsedCert.expectedCommonName), 0);
    let actualCertId2 = await instance.refs.call(parsedCert.fingerprint);
    let cnHash = await instance.refs.call(namehash.hash(parsedCert.expectedCommonName.replace('www.', '')));
    let actualCertId3 = await instance.certIdsFromCN.call(cnHash, 0);
    let actualCert = await instance.certs.call(expectedCertId);

    console.log("      gas: addRootCert(): " + result.receipt.gasUsed);

    assert.equal(result.logs[0].event, "CertAdded", "Function did not complete execution");
    assert.equal(result.logs[0].args[0], expectedCertId, "Function completed but with incorrect certId");
    assert.equal(actualCert.parentId, expectedCertId, "cert not added");
    assert.equal(actualCert.pubKey, parsedCert.expectedPubKey, "cert not added");
    assert.equal(actualCert.serialNumber, parseInt(parsedCert.expectedSerialNumber), "cert not added");
    assert.isTrue(actualCert.canSignHttpExchanges, "failed to find canSignHttpExchanges extension");
    assert.equal(actualCertId, expectedCertId, "common name doesn't map to certId");
    assert.equal(actualCertId2, expectedCertId, "fingerprint doesn't map to certId");
    assert.equal(actualCertId3, expectedCertId, "ens namehash doesn't map to certId");
  })

  // Test signThis() and proveOwnership()
  it("should prove ownership of added Certificate", async () => {
    let instance = await X509Forest.deployed();
    let tuple = await instance.signThis.call();
    let privateKey = fs.readFileSync(__dirname + '/key.pem').toString();
    let key = new NodeRSA(privateKey, 'pkcs8');
    let signed = key.sign(tuple[0].slice(2), 'hex', 'hex');
    let result = await instance.proveOwnership(expectedCertId, "0x"+signed, tuple[1].toNumber(), "0x2a864886f70d01010b");
    let actualCert = await instance.certs.call(expectedCertId);

    console.log("      gas: proveOwnership(): " + result.receipt.gasUsed);

    assert.equal(result.logs[0].event, "CertClaimed", "Function did not complete execution");
    assert.equal(actualCert.owner, accounts[0], "Owner not updated");
  })

  it("should add LetsEncrypt's root cert", async () => {
    let certBytes = '0x' + fs.readFileSync(__dirname + '/letsEncryptRoot.der', {encoding: 'hex'});
    let instance = await X509Forest.deployed();
    let result = await instance.addRootCert(certBytes, false);

    console.log("      gas: addRootCert(): " + result.receipt.gasUsed);

    assert.equal(result.logs[0].event, "CertAdded", "Function did not complete execution");
  })

  it("should add LetsEncrypt's intermediate cert", async () => {
    let certBytes = '0x' + fs.readFileSync(__dirname + '/letsEncryptAuthorityX3.der', {encoding: 'hex'});
    let parentPubKeyBytes = '0x' + fs.readFileSync(__dirname + '/letsEncryptRootPubKey.der', {encoding: 'hex'});
    let instance = await X509Forest.deployed();
    let result = await instance.addCert(certBytes, Web3.utils.sha3(parentPubKeyBytes), false);

    console.log("      gas: addCert(): " + result.receipt.gasUsed);

    assert.equal(result.logs[0].event, "CertAdded", "Function did not complete execution");
  })

  it("should add cert signed by LetsEncrypt's intermediate cert", async () => {
    let certBytes = '0x' + fs.readFileSync(__dirname + '/letsEncryptTest.der', {encoding: 'hex'});
    let parentPubKeyBytes = '0x' + fs.readFileSync(__dirname + '/letsEncryptAuthorityX3PubKey.der', {encoding: 'hex'});
    let instance = await X509Forest.deployed();
    let result = await instance.addCert(certBytes, Web3.utils.sha3(parentPubKeyBytes), false);
    let parent = (await instance.certs(result.logs[0].args[0])).parentId
    let parentSquared = (await instance.certs(parent)).parentId
    let parentCubed = (await instance.certs(parentSquared)).parentId
    let hyperParent = (await instance.certs(parentCubed)).parentId

    console.log("      gas: addCert(): " + result.receipt.gasUsed);

    assert.equal(result.logs[0].event, "CertAdded", "Function did not complete execution")
    assert.equal(parentCubed, hyperParent, "Certificate chain broken somewhere")
  })
});
