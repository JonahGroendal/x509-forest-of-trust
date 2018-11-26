var X509Forest = artifacts.require("X509InTreeForestOfTrust");
var RsaSha256Algorithm = artifacts.require("RsaSha256Algorithm");
var cert = require('./cert');
var namehash = require('eth-ens-namehash');
var NodeRSA = require('node-rsa');
var Web3 = require('web3');
var fs = require('fs');
var sha256 = require('js-sha256');

var expectedCertId = Web3.utils.sha3(cert.expectedPubKey, {encoding: 'hex'});

contract('X509InTreeForestOfTrust', (accounts) => {
  // Test addCertificate()
  it("should correctly add a valid certificate and its reference keys", async () => {
    let instance = await X509Forest.deployed();
    let result = await instance.addCertificate(cert.cert, cert.signersPubKey, true);
    let actualCertId = await instance.certIdsLists.call(namehash.hash(cert.expectedCommonName), 0);
    let actualCertId2 = await instance.certIds.call(cert.fingerprint);
    let actualCert = await instance.certs.call(expectedCertId);

    console.log("      gas: addCertificate(): " + result.receipt.gasUsed);

    assert.equal(result.logs[0].event, "CertificateAdded", "Function did not complete execution");
    assert.equal(result.logs[0].args["certId"], expectedCertId, "Function completed but with incorrect certId");
    assert.equal(actualCert.pubKey, cert.expectedPubKey, "Certificate not added");
    assert.equal(actualCertId, expectedCertId, "common name doesn't map to certId");
    assert.equal(actualCertId2, expectedCertId, "fingerprint doesn't map to certId");
    assert.isTrue(actualCert.canSignHttpExchanges, "failed to find canSignHttpExchanges extension");
  })

  // Test signThis() and proveOwnership()
  it("should prove ownership of added Certificate", async () => {
    let instance = await X509Forest.deployed();
    let tuple = await instance.signThis.call();
    let privateKey = fs.readFileSync(__dirname + '/key.pem').toString();
    let key = new NodeRSA(privateKey, 'pkcs8');
    let signed = key.sign(tuple[0].slice(2), 'hex', 'hex');
    let result = await instance.proveOwnership(expectedCertId, "0x"+signed, tuple[1].toNumber(), web3.utils.keccak256("0x2a864886f70d01010b"));

    console.log("      gas: proveOwnership(): " + result.receipt.gasUsed);

    assert.equal(result.logs[0].event, "CertificateClaimed", "Function did not complete execution");
  })
});
