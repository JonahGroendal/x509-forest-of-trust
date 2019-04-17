var Asn1Decode = artifacts.require("asn1-decode/Asn1Decode");
var RsaSha256Algorithm = artifacts.require("sig-verify-algs/RsaSha256Algorithm");
var X509ForestOfTrust = artifacts.require("X509ForestOfTrust");
var ENSNamehash = artifacts.require("ens-namehash/ENSNamehash");
var DateTime = artifacts.require("ethereum-datetime/DateTime");

module.exports = function(deployer, network) {
  deployer.deploy(Asn1Decode, { overwrite: false });
  deployer.link(Asn1Decode, RsaSha256Algorithm);
  deployer.link(Asn1Decode, X509ForestOfTrust);
  deployer.deploy(ENSNamehash, { overwrite: false });
  deployer.link(ENSNamehash, X509ForestOfTrust);
  deployer.deploy(RsaSha256Algorithm, { overwrite: false })
  .then(() => deployer.deploy(DateTime, { overwrite: false }))
  .then(() => deployer.deploy(X509ForestOfTrust, RsaSha256Algorithm.address, DateTime.address));
};
