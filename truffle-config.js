const HDWalletProvider = require('@truffle/hdwallet-provider');
const fs = require('fs');

const infuraKey = "48899b10645a48e189e345be4be19ece";

let privateKeys;
try {
  privateKeys = JSON.parse(fs.readFileSync("keys.json").toString().trim()).private;
} catch {}

module.exports = {
  networks: {
    development: {
      host: "127.0.0.1",
      port: 8545,
      network_id: "*", // Match any network id
    },
    rinkeby: {
      host: "127.0.0.1",
      port: 8545,
      network_id: "4",
    },
    kovan: {
      provider: () => new HDWalletProvider({
        privateKeys,
        providerOrUrl: `https://kovan.infura.io/v3/${infuraKey}`,
        addressIndex: 0,
        numAddresses: 5
      }),
      network_id: 42,
      // gas: 5500000,        // Ropsten has a lower block limit than mainnet
      // confirmations: 2,    // # of confs to wait between deployments. (default: 0)
      // timeoutBlocks: 200,  // # of blocks before a deployment times out  (minimum/default: 50)
      // skipDryRun: true     // Skip dry run before migrations? (default: false for public nets )
    },
  },
  compilers: {
    solc: {
      version: "0.5.2",
      settings: {
        optimizer: {
          enabled: true,
          runs: 200
        }
      }
    }
  }
};
