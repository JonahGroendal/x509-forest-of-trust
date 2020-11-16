var Migrations = artifacts.require("./Migrations.sol");

module.exports = function(deployer, network) {
  if (network !== 'live') {
    deployer.deploy(Migrations);
  }
};
