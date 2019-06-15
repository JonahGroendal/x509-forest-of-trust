var X509Forest = artifacts.require("X509ForestOfTrust")
var parsedCert = require('./certs/cert')
var namehash = require('eth-ens-namehash')
var NodeRSA = require('node-rsa')
var fs = require('fs')
var forge = require('node-forge')
var extensions = require('./certs/extensions.json')

const keyUsageBitNames = [
  "digitalSignature",
  "nonRepudiation",
  "keyEncipherment",
  "dataEncipherment",
  "keyAgreement",
  "keyCertSign",
  "cRLSign",
  "encipherOnly",
  "decipherOnly"
]

contract('X509ForestOfTrust', (accounts) => {
  it("should verify a valid root certificate and add references to it", async () => {
    const pemCert = fs.readFileSync(__dirname + '/certs/root.pem')
    const pemPubKey = fs.readFileSync(__dirname + '/certs/rootPubKey.pem')
    const cert = forge.pki.certificateFromPem(pemCert)
    const pubKey = forge.pki.publicKeyFromPem(pemPubKey)
    const certBytes = '0x' + forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).toHex()
    const pubKeyBytes = '0x' + forge.asn1.toDer(forge.pki.publicKeyToAsn1(pubKey)).toHex()
    const instance = await X509Forest.deployed()

    const result = await instance.addCert(certBytes, pubKeyBytes)
    console.log("      gas: addCert(): " + result.receipt.gasUsed)

    const fingerprint = forge.md.sha256.create().update(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes()).digest().toHex();
    const expectedId = web3.utils.sha3(pubKeyBytes)
    const validNotAfter = fs.readFileSync(__dirname + '/certs/validNotAfter.txt').toString()
    const actualKeyUsage = await instance.keyUsage(expectedId);
    const assertedKeyUsageBits = Object.keys(extensions.root.filter(ex => ex.name == "keyUsage")[0]).filter(v => v !== "name")
    const bc = await instance.basicConstraints(expectedId)
    const cA = bc[0]
    const pathLenConstraint = bc[1]

    assert.equal(await instance.toCertId('0x' + fingerprint), expectedId, "sha256 fingerprint doesn't map to certId")
    assert.isTrue(cA)
    assert.equal(pathLenConstraint.toString(), "255")
    assert.equal((await instance.serialNumber(expectedId)).toString(), "1")
    assert.equal(await instance.parentId(expectedId), expectedId)
    assert.isFalse(await instance.sxg(expectedId))
    assert.equal(await instance.owner(expectedId), "0x0000000000000000000000000000000000000000")
    assert.isFalse(await instance.unparsedCriticalExtensionPresent(expectedId))
    assert.equal((await instance.validNotAfter(expectedId)).toString(), validNotAfter.slice(0, -3))
    assert.equal(actualKeyUsage[0], assertedKeyUsageBits.length > 0, "key usage is incorrectly marked as present")
    keyUsageBitNames.forEach((name, i) => {
      assert.equal(actualKeyUsage[1][i], assertedKeyUsageBits.includes(name), "key usage flags parsed incorrectly")
    })
  })

  it("should verify a valid intermediate certificate and add references to it", async () => {
    const pemCert = fs.readFileSync(__dirname + '/certs/intermediate.pem')
    const pemPubKey = fs.readFileSync(__dirname + '/certs/intermediatePubKey.pem')
    const parentPemPubKey = fs.readFileSync(__dirname + '/certs/rootPubKey.pem')
    const cert = forge.pki.certificateFromPem(pemCert)
    const pubKey = forge.pki.publicKeyFromPem(pemPubKey)
    const parentPubKey = forge.pki.publicKeyFromPem(parentPemPubKey)
    const certBytes = '0x' + forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).toHex()
    const pubKeyBytes = '0x' + forge.asn1.toDer(forge.pki.publicKeyToAsn1(pubKey)).toHex()
    const parentPubKeyBytes = '0x' + forge.asn1.toDer(forge.pki.publicKeyToAsn1(parentPubKey)).toHex()
    const instance = await X509Forest.deployed()

    const result = await instance.addCert(certBytes, parentPubKeyBytes)
    console.log("      gas: addCert(): " + result.receipt.gasUsed)

    const fingerprint = forge.md.sha256.create().update(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes()).digest().toHex();
    const expectedId = web3.utils.sha3(pubKeyBytes)
    const validNotAfter = fs.readFileSync(__dirname + '/certs/validNotAfter.txt').toString()
    const actualKeyUsage = await instance.keyUsage(expectedId);
    const assertedKeyUsageBits = Object.keys(extensions.intermediate.filter(ex => ex.name == "keyUsage")[0]).filter(v => v !== "name")
    const bc = await instance.basicConstraints(expectedId)
    const cA = bc[0]
    const pathLenConstraint = bc[1]

    assert.equal(await instance.toCertId('0x' + fingerprint), expectedId, "sha256 fingerprint doesn't map to certId")
    assert.isTrue(cA)
    assert.equal(pathLenConstraint.toString(), "0")
    assert.equal((await instance.serialNumber(expectedId)).toString(), "1")
    assert.equal(await instance.parentId(expectedId), web3.utils.sha3(parentPubKeyBytes))
    assert.isFalse(await instance.sxg(expectedId))
    assert.equal(await instance.owner(expectedId), "0x0000000000000000000000000000000000000000")
    assert.isFalse(await instance.unparsedCriticalExtensionPresent(expectedId))
    assert.equal((await instance.validNotAfter(expectedId)).toString(), validNotAfter.slice(0, -3))
    assert.equal(actualKeyUsage[0], assertedKeyUsageBits.length > 0, "key usage is incorrectly marked as present")
    keyUsageBitNames.forEach((name, i) => {
      assert.equal(actualKeyUsage[1][i], assertedKeyUsageBits.includes(name), "key usage flags parsed incorrectly")
    })
  })

  it("should verify a valid leaf certificate and add references to it", async () => {
    const pemCert = fs.readFileSync(__dirname + '/certs/leaf.pem')
    const pemPubKey = fs.readFileSync(__dirname + '/certs/leafPubKey.pem')
    const parentPemPubKey = fs.readFileSync(__dirname + '/certs/intermediatePubKey.pem')
    const cert = forge.pki.certificateFromPem(pemCert)
    const pubKey = forge.pki.publicKeyFromPem(pemPubKey)
    const parentPubKey = forge.pki.publicKeyFromPem(parentPemPubKey)
    const certBytes = '0x' + forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).toHex()
    const pubKeyBytes = '0x' + forge.asn1.toDer(forge.pki.publicKeyToAsn1(pubKey)).toHex()
    const parentPubKeyBytes = '0x' + forge.asn1.toDer(forge.pki.publicKeyToAsn1(parentPubKey)).toHex()
    const instance = await X509Forest.deployed()

    const result = await instance.addCert(certBytes, parentPubKeyBytes)
    console.log("      gas: addCert(): " + result.receipt.gasUsed)

    const fingerprint = forge.md.sha256.create().update(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes()).digest().toHex();
    const expectedId = web3.utils.sha3(pubKeyBytes)
    const validNotAfter = fs.readFileSync(__dirname + '/certs/validNotAfter.txt').toString()
    const actualKeyUsage = await instance.keyUsage(expectedId);
    const assertedKeyUsageBits = Object.keys(extensions.leaf.filter(ex => ex.name == "keyUsage")[0]).filter(v => v !== "name")
    const expectedExtKeyUsageNames = Object.keys(extensions.leaf.filter(ex => ex.name == "extKeyUsage")[0]).filter(v => v !== "name")
    const actualExtKeyUsage = await instance.extKeyUsage(expectedId)
    const bc = await instance.basicConstraints(expectedId)
    const cA = bc[0]
    const pathLenConstraint = bc[1]

    for (let name of extensions.leaf.filter(ex => ex.name == "subjectAltName")[0].altNames) {
      assert.equal((await instance.toCertIdsLength(namehash.hash(name.value))).toString(), "1")
      assert.equal(
        await instance.toCertIds(namehash.hash(name.value), 0),
        expectedId,
        "namehash of "+name.value+" name doesn't map to certIds"
      )
    }
    assert.equal(await instance.toCertId('0x' + fingerprint), expectedId, "sha256 fingerprint doesn't map to certId")
    assert.isFalse(cA)
    assert.equal(pathLenConstraint.toString(), "0")
    assert.equal((await instance.serialNumber(expectedId)).toString(), "1")
    assert.equal(await instance.parentId(expectedId), web3.utils.sha3(parentPubKeyBytes))
    assert.isFalse(await instance.sxg(expectedId))
    assert.equal(await instance.owner(expectedId), "0x0000000000000000000000000000000000000000")
    assert.isFalse(await instance.unparsedCriticalExtensionPresent(expectedId))
    assert.equal((await instance.validNotAfter(expectedId)).toString(), validNotAfter.slice(0, -3))
    assert.equal(actualKeyUsage[0], assertedKeyUsageBits.length > 0, "key usage is incorrectly marked as present")
    keyUsageBitNames.forEach((name, i) => {
      assert.equal(actualKeyUsage[1][i], assertedKeyUsageBits.includes(name), "key usage flags parsed incorrectly")
    })
    assert.equal(actualExtKeyUsage[0], expectedExtKeyUsageNames.length > 0)
    assert.equal(actualExtKeyUsage[1].length, expectedExtKeyUsageNames.length)
  })

  it("should fail to verify a certificate that's signed by a leaf certificate", async () => {
    const pemCert = fs.readFileSync(__dirname + '/certs/invalid.pem')
    const parentPemPubKey = fs.readFileSync(__dirname + '/certs/leafPubKey.pem')
    const cert = forge.pki.certificateFromPem(pemCert)
    const parentPubKey = forge.pki.publicKeyFromPem(parentPemPubKey)
    const certBytes = '0x' + forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).toHex()
    const parentPubKeyBytes = '0x' + forge.asn1.toDer(forge.pki.publicKeyToAsn1(parentPubKey)).toHex()
    const instance = await X509Forest.deployed()
    try {
      const result = await instance.addCert(certBytes, parentPubKeyBytes)
    } catch (error) {
      if (error.message.includes("Invalid parent cert"))
        return;
    }
    assert.isTrue(false, "Added an invalid cert")
  })

  // Test signThis() and proveOwnership()
  it("should prove ownership of leaf Certificate", async () => {
    // Get challenge
    let instance = await X509Forest.deployed()
    let tuple = await instance.signThis.call()
    // Get keys
    let pemPrivKey = fs.readFileSync(__dirname + '/certs/leafPrivKey.pem').toString()
    let pemPubKey = fs.readFileSync(__dirname + '/certs/leafPubKey.pem').toString()
    let pubKey = forge.pki.publicKeyFromPem(pemPubKey)
    let pubKeyBytes = '0x' + forge.asn1.toDer(forge.pki.publicKeyToAsn1(pubKey)).toHex()
    // Calculate signature
    let key = new NodeRSA(pemPrivKey, 'pkcs8')
    let signed = key.sign(tuple[0].slice(2), 'hex', 'hex')

    let result = await instance.proveOwnership(pubKeyBytes, "0x"+signed, tuple[1].toNumber(), "0x2a864886f70d01010b")
    console.log("      gas: proveOwnership(): " + result.receipt.gasUsed)

    assert.equal(result.logs[0].event, "CertClaimed", "Function did not complete execution")
    assert.equal(await instance.owner(web3.utils.sha3(pubKeyBytes)), accounts[0], "Owner not updated")
  })

  it("should add LetsEncrypt's root cert", async () => {
    let certBytes = '0x' + fs.readFileSync(__dirname + '/certs/letsEncryptRoot.der', {encoding: 'hex'})
    let parentPubKeyBytes = '0x' + fs.readFileSync(__dirname + '/certs/letsEncryptRootPubKey.der', {encoding: 'hex'})
    let instance = await X509Forest.deployed()
    let result = await instance.addCert(certBytes, parentPubKeyBytes)

    console.log("      gas: addCert(): " + result.receipt.gasUsed)

    assert.equal(result.logs[0].event, "CertAdded", "Function did not complete execution")
  })

  it("should add LetsEncrypt's intermediate cert", async () => {
    let certBytes = '0x' + fs.readFileSync(__dirname + '/certs/letsEncryptAuthorityX3.der', {encoding: 'hex'})
    let parentPubKeyBytes = '0x' + fs.readFileSync(__dirname + '/certs/letsEncryptRootPubKey.der', {encoding: 'hex'})
    let instance = await X509Forest.deployed()
    let result = await instance.addCert(certBytes, parentPubKeyBytes)

    console.log("      gas: addCert(): " + result.receipt.gasUsed)

    assert.equal(result.logs[0].event, "CertAdded", "Function did not complete execution")
  })

  // Failing because cert is expired now
  // it("should add cert signed by LetsEncrypt's intermediate cert", async () => {
  //   let certBytes = '0x' + fs.readFileSync(__dirname + '/certs/letsEncryptTest.der', {encoding: 'hex'})
  //   let parentPubKeyBytes = '0x' + fs.readFileSync(__dirname + '/certs/letsEncryptAuthorityX3PubKey.der', {encoding: 'hex'})
  //   let instance = await X509Forest.deployed()
  //   let result = await instance.addCert(certBytes, web3.utils.sha3(parentPubKeyBytes), false)
  //   let certId = await instance.toCertIds(namehash.hash("valid-isrgrootx1.letsencrypt.org"), 0)
  //   let parent = (await instance.certs(result.logs[0].args[0])).parentId
  //   let parentSquared = (await instance.certs(parent)).parentId
  //   let parentCubed = (await instance.certs(parentSquared)).parentId
  //   let hyperParent = (await instance.certs(parentCubed)).parentId
  //
  //   console.log("      gas: addCert(): " + result.receipt.gasUsed)
  //
  //   assert.equal(certId, result.logs[0].args[0], "ensNode reference not added")
  //   assert.equal(result.logs[0].event, "CertAdded", "Function did not complete execution")
  //   assert.equal(parentCubed, hyperParent, "Certificate chain broken somewhere")
  // })

  it("should fail to add an expired, but otherwise valid, cert signed by LetsEncrypt's intermediate cert", async () => {
    let certBytes = '0x' + fs.readFileSync(__dirname + '/certs/letsEncryptTest.der', {encoding: 'hex'})
    let parentPubKeyBytes = '0x' + fs.readFileSync(__dirname + '/certs/letsEncryptAuthorityX3PubKey.der', {encoding: 'hex'})
    let instance = await X509Forest.deployed()
    try {
      let result = await instance.addCert(certBytes, parentPubKeyBytes)
    } catch (error) {
      return;
    }
    assert.isTrue(false, "Added an invalid cert")
  })
})
