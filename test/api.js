const CertificateUploader = require('../index')
const Artifact = require('../build/contracts/X509ForestOfTrust.json')
const X509Forest = artifacts.require("X509ForestOfTrust")
const forge = require('node-forge')
const fs = require('fs')
const pemCertRoot = fs.readFileSync(__dirname + '/certs/root.pem')
const pemCertIntermediate = fs.readFileSync(__dirname + '/certs/intermediate.pem')
const pemCertLeaf = fs.readFileSync(__dirname + '/certs/leaf.pem')
const pemPrivKeyLeaf = fs.readFileSync(__dirname + '/certs/leafPrivKey.pem')
const pemPubKeyLeaf = fs.readFileSync(__dirname + '/certs/leafPubKey.pem')

contract('API', accounts => {
  it('should add a cert chain and prove ownership of end-entity cert', async () => {
    const chainId = Object.keys(Artifact.networks).map(parseInt).sort((a, b) => b - a)[0]
    const api = CertificateUploader(web3, { chainId })
    const pemCertChain = [pemCertRoot, pemCertIntermediate, pemCertLeaf]

    await api.addCertAndProveOwnership(accounts[0], pemCertChain, pemPrivKeyLeaf)

    const instance = await X509Forest.deployed()
    const pubKey = forge.pki.publicKeyFromPem(pemPubKeyLeaf)
    const pubKeyBytes = '0x' + forge.asn1.toDer(forge.pki.publicKeyToAsn1(pubKey)).toHex()
    const expectedId = web3.utils.sha3(pubKeyBytes)
    assert.equal(await instance.owner(expectedId), accounts[0])
  })
})
