var X509Forest = artifacts.require("./X509InTreeForestOfTrust.sol");
var cert = require('./cert');
var NodeRSA = require('node-rsa');
var Web3 = require('web3');
var fs = require('fs');

var expectedCertificateId = Web3.utils.sha3(cert.expectedPubKey, {encoding: 'hex'});

contract('X509InTreeForestOfTrust', (accounts) => {
  // Test addCertificate()
  it("should correctly add a valid certificate and its reference keys", async () => {
    let instance = await X509Forest.deployed();
    let result = await instance.addCertificate(cert.tbsCertificate, cert.signature, cert.signersPubKey);
    let addedTbsCertificate = await instance.tbsCertificate.call(expectedCertificateId);
    let actualCertificateId = await instance.certificateId.call(Web3.utils.sha3(cert.expectedSerialNumber, {encoding: 'hex'}));

    console.log("      gas: addCertificate(): " + result.receipt.gasUsed);

    assert.equal(result.logs[0].event, "certificateAdded", "Function did not complete execution");
    assert.equal(result.logs[0].args["certificateId"], expectedCertificateId, "Function completed but with incorrect certificateId");
    assert.equal(Web3.utils.sha3(addedTbsCertificate), Web3.utils.sha3(cert.tbsCertificate), "Certificate not added");
    assert.equal(actualCertificateId[0], expectedCertificateId, "Serial number doesn't map to certificateId");
  })

  // Test addReference()
  it("should add a reference from common name to certificate ID", async () => {
    let instance = await X509Forest.deployed();
    let result = await instance.addReference(expectedCertificateId, "0x00020501050201");
    let lookupResult = await instance.certificateId.call(Web3.utils.sha3(cert.expectedCommonName));

    console.log("      gas: addReference(): " + result.receipt.gasUsed);

    assert.equal(lookupResult[0], expectedCertificateId, "Reference not added");
  })

  // Test signThis() and proveOwnership()
  it("should prove ownership of added Certificate", async () => {
    let instance = await X509Forest.deployed();
    let tuple = await instance.signThis.call();
    let privateKey = fs.readFileSync(__dirname + '/key.pem').toString();
    let key = new NodeRSA(privateKey, 'pkcs1');
    let signed = key.sign(tuple[0].slice(2), 'hex', 'hex');
    let result = await instance.proveOwnership(expectedCertificateId, "0x"+signed, tuple[1].toNumber());

    console.log("      gas: proveOwnership(): " + result.receipt.gasUsed);

    assert.equal(result.logs[0].event, "certificateClaimed", "Function did not complete execution");
  })
});
