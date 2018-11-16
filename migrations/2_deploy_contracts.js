var Asn1Decode = artifacts.require("Asn1Decode");
var Pkcs1Sha256Verify = artifacts.require("Pkcs1Sha256Verify")
var X509InTreeForestOfTrust = artifacts.require("X509InTreeForestOfTrust");

module.exports = function(deployer, network) {
  deployer.deploy(Asn1Decode).then(function() {
    return deployer.deploy(Pkcs1Sha256Verify).then(function() {
      return deployer.deploy(X509InTreeForestOfTrust, Asn1Decode.address, Pkcs1Sha256Verify.address);
    })
  })
};
