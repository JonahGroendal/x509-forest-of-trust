var Asn1Decode = artifacts.require("asn1-decode/Asn1Decode");
var RsaSha256Algorithm = artifacts.require("sig-verify-algs/RsaSha256Algorithm");
var X509ForestOfTrust = artifacts.require("X509ForestOfTrust");
var NameHash = artifacts.require("ens-solidity-namehash/NameHash");
var DateTime = artifacts.require("ethereum-datetime/DateTime");

module.exports = function(deployer, network) {
  deployer.deploy(Asn1Decode);
  deployer.link(Asn1Decode, RsaSha256Algorithm);
  deployer.link(Asn1Decode, X509ForestOfTrust);
  deployer.deploy(NameHash);
  deployer.link(NameHash, X509ForestOfTrust);
  deployer.deploy(RsaSha256Algorithm)
  .then(() => deployer.deploy(DateTime))
  .then(() => deployer.deploy(X509ForestOfTrust, RsaSha256Algorithm.address, DateTime.address));
};
