# x509-forest-of-trust
Solidity contract that parses and verifies X.509 certificate chains and stores them in parent pointer trees on the ETH blockchain. An ETH account can then prove ownership of a verified certificate in the tree.

Useful for:
  1) associating a domain with an Ethereum address: [dns-over-ens](https://github.com/JonahGroendal/dns-over-ens)
  2) verifying HTTP responses on-chain using Signed HTTP Exchanges (SXG) / web packages

The easiest way to use this contract from within your web3 app is via the javascript API:
```javascript
const CertificateUploader = require('x509-forest-of-trust')
const fs = require('fs')
const pemCertRoot =         fs.readFileSync(__dirname + '/certs/root.pem')
const pemCertIntermediate = fs.readFileSync(__dirname + '/certs/intermediate.pem')
const pemCertLeaf =         fs.readFileSync(__dirname + '/certs/leaf.pem')
const pemCertLeafPkcs8Key = fs.readFileSync(__dirname + '/certs/leafPkcs8Key.pem')

// Inject web3 instance into javascript API
const api = CertificateUploader(web3, { chainId: 1 })

const pemCertChain = [pemCertRoot, pemCertIntermediate, pemCertLeaf]
const from = web3.eth.defaultAccount // or any address that's in web3.eth.accounts
api.addCertAndProveOwnership(from, pemCertChain, pemCertLeafPkcs8Key)
.then(() => {
  console.log('Certificates have been parsed, verified, and saved to the blockchain.')
  console.log(from + ' has been set as the owner of the leaf (aka end-entity) certificate.')
})
.catch(console.error)
```

note: contracts must be redeployed between tests
