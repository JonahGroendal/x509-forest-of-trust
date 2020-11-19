let RsaSha256Algorithm = artifacts.require("sig-verify-algs/RsaSha256Algorithm");
let RsaSha256AlgorithmObj = require("sig-verify-algs/build/contracts/RsaSha256Algorithm.json")
let X509ForestOfTrust = artifacts.require("X509ForestOfTrust");
let DateTime = artifacts.require("ethereum-datetime/DateTime");

const networkIds = {
  'kovan': 42,
  'kovan-fork': 42
}

module.exports = function(deployer, network) {
  if (network === 'development') {
    deployer.deploy(RsaSha256Algorithm)
    .then(() => deployer.deploy(DateTime))
    .then(() => deployer.deploy(X509ForestOfTrust, RsaSha256Algorithm.address, DateTime.address));
  } else {
    if (!networkIds[network]) {
      throw new Error('Please set the network ID for '.concat(network))
    }
    const rsaSha256AlgorithmAddr = RsaSha256AlgorithmObj.networks[networkIds[network]].address
    deployer.deploy(DateTime)
    .then(() => deployer.deploy(X509ForestOfTrust, rsaSha256AlgorithmAddr, DateTime.address));
  }
};
