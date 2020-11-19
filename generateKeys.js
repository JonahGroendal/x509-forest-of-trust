
// Run this script to create keys.json

const fs = require('fs')
const Accounts = require('web3-eth-accounts');


const NUM_ACCOUNTS = 5

fs.writeFileSync(
  'keys.json',
  JSON.stringify(
    Array(NUM_ACCOUNTS).fill()
    .map(() => Accounts.prototype.create())
    .reduce(
      (acc, cur) => {
        acc.public.push(cur.address)
        acc.private.push(cur.privateKey)
        return acc
      },
      { public: [], private: [] }
    ),
    null,
    2
  )
)
