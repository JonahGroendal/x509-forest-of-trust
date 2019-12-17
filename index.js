const forge = require('node-forge')
const NodeRSA = require('node-rsa')
const Artifact = require('./build/contracts/X509ForestOfTrust.json')

module.exports = CertificateUploader

/**
 * API for adding certificate chains and proving ownership of certificates.
 * An abstraction for the functions addCert, signThis and proveOwnership.
 *
 * @param {object} web3js - An instance of Web3 with Provider and Account already set up.
 */
function CertificateUploader(web3js, options={ chainId: 1 }) {
  const contractAddr = Artifact.networks[options.chainId].address
  const x509Forest = new web3js.eth.Contract(Artifact.abi, contractAddr);
  const keccak256 = web3js.utils.sha3

  return {
    addCertAndProveOwnership: async (from, pemCertChain, pkcs8Key) => {
      return await addCertAndProveOwnership(keccak256, x509Forest, from, pemCertChain, pkcs8Key)
    },
    addCertificate: async (from, pemCert, pemParentPubKey) => {
      return await addCertificate(x509Forest, from, pemCert, pemParentPubKey)
    },
    getCertChallengeBytes: async (from) => {
      return await getCertChallengeBytes(x509Forest, from)
    },
    signAndSubmitCertChallengeBytes: async (from, challengeBytes, pkcs8Key, pemPubKey, blockNum) => {
      return await signAndSubmitCertChallengeBytes(x509Forest, from, challengeBytes, pkcs8Key, pemPubKey, blockNum)
    }
  }
}

/**
 * Adds a certificate chain to the contract and proves ownership of the last
 * certificate in that chain (the end-entity certificate). If a certificate in
 * the chain has already been added, it will be skipped.
 *
 * @param {object} keccak256 - Web3.utils.sha3
 * @param {object} x509Forest - A web3 Contract instance of the X509ForestOfTrust contract
 * @param {string} from - The address that will be set as owner of the end-entity certificate. Must exist as an Account in web3js parameter
 * @param {string[]} pemCertChain - An array of PEM-encoded X.509 certificates starting with root
 * @param {string} pkcs8Key - The PKCS8 private key corresponding to the end-entity certificate's public key
 */
async function addCertAndProveOwnership(keccak256, x509Forest, from, pemCertChain, pkcs8Key) {
  let pemPubKeys = []
  let certIds = []
  let pubKey;
  pemCertChain.forEach(pem => {
    pubKey = forge.pki.certificateFromPem(pem).publicKey
    pemPubKeys.push(forge.pki.publicKeyToPem(pubKey))
    certIds.push(keccak256('0x' + forge.asn1.toDer(forge.pki.publicKeyToAsn1(pubKey)).toHex()))
  })

  for (let i=0; i<pemCertChain.length; i++) {
    if (parseInt(await x509Forest.methods.validNotAfter(certIds[i]).call()) === 0)
      await addCertificate(x509Forest, from, pemCertChain[i], pemPubKeys[Math.max(i - 1, 0)])
  }
  const { challengeBytes, blockNum } = await getCertChallengeBytes(x509Forest, from)

  await signAndSubmitCertChallengeBytes(x509Forest, from, challengeBytes, pkcs8Key, pemPubKeys[pemPubKeys.length-1], blockNum)
}

/**
 * @param {object} x509Forest - A web3 Contract instance of the X509ForestOfTrust contract
 * @param {string} from - The address that the transaction will be send from. Must exist as an Account in web3js parameter
 * @param {string[]} pemCert - A PEM-encoded X.509 certificate
 * @param {string} pemParentPubKey - The PEM-encoded public key of pemCert's parent certificate
 */
async function addCertificate(x509Forest, from, pemCert, pemParentPubKey) {
  const cert = forge.pki.certificateFromPem(pemCert)
  const parentPubKey = forge.pki.publicKeyFromPem(pemParentPubKey)
  const certBytes = '0x' + forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).toHex()
  const parentPubKeyBytes = '0x' + forge.asn1.toDer(forge.pki.publicKeyToAsn1(parentPubKey)).toHex()

  // addCert(bytes memory cert, bytes memory parentPubKey)
  const tx = x509Forest.methods.addCert(certBytes, parentPubKeyBytes)
  const options = { from, gas: 2000000 }
  // Make sure it works
  await tx.call(options)
  // Then send
  await tx.send(options)
}

/**
 * @param {object} x509Forest - A web3 Contract instance of the X509ForestOfTrust contract
 * @param {string} from - The address that the transaction will be send from
 */
async function getCertChallengeBytes(x509Forest, from) {
  // signThis() external view returns (bytes memory, uint)
  const res = await x509Forest.methods.signThis().call({ from })
  return {
    challengeBytes: res[0].slice(2), // remove "0x"
    blockNum: parseInt(res[1].toString())
  }
}

/**
 * @param {object} x509Forest - A web3 Contract instance of the X509ForestOfTrust contract
 * @param {string} from - The address that will be set as owner of the end-entity certificate. Must exist as an Account in web3js parameter
 * @param {string[]} challengeBytes - the result of getCertChallengeBytes()
 * @param {string} pkcs8Key - The PKCS8 private key corresponding to pemPubKey
 * @param {string} pemPubKey - The PEM-encoded public key of a cert that has already been added
 * @param {number} blockNum - the result of getCertChallengeBytes()
 */
async function signAndSubmitCertChallengeBytes(x509Forest, from, challengeBytes, pkcs8Key, pemPubKey, blockNum) {
  let pubKey = forge.pki.publicKeyFromPem(pemPubKey)
  let pubKeyBytes = '0x' + forge.asn1.toDer(forge.pki.publicKeyToAsn1(pubKey)).toHex()
  // Calculate signature
  let key = new NodeRSA(pkcs8Key, 'pkcs8')
  let signed = key.sign(challengeBytes, 'hex', 'hex')

  const sha256WithRSAEncryption = "0x2a864886f70d01010b0000000000000000000000000000000000000000000000"
  const tx = x509Forest.methods.proveOwnership(pubKeyBytes, "0x"+signed, blockNum, sha256WithRSAEncryption)
  const options = { from, gas: 200000 }
  // Make sure it wont revert
  await tx.call(options)
  // Then do it for real
  await tx.send(options)
}
