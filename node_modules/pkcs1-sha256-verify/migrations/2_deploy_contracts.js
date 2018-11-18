var Pkcs1Sha256Verify = artifacts.require("Pkcs1Sha256Verify");

module.exports = function(deployer, network) {
  deployer.deploy(Pkcs1Sha256Verify);
};
