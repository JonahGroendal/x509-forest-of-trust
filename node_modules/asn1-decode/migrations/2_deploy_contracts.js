var Asn1Decode = artifacts.require("Asn1Decode");

module.exports = function(deployer, network) {
  deployer.deploy(Asn1Decode);
};
