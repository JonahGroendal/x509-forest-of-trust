# x509-forest-of-trust
Solidity contract that parses and verifies X.509 certificate chains and stores them in parent pointer trees on the ETH blockchain. An ETH account can then prove ownerhip of a verified certificate in the tree.

Useful for:
  1) associating a domain with an Ethereum address: [dns-on-ens](https://github.com/JonahGroendal/dns-on-ens)
  2) verifying HTTP responses on-chain using Signed HTTP Exchanges (SXG) / web packages
  3) authenticating citizens or government workers using government-issued electronic IDs
