# Mining and Pool Support

This public repository contains the deployed `c5cb556` source snapshot. It
does not yet contain the newer development-preview Stratum V1 adapter.

## CPU Mining

The signed public package supports standalone CPU mining. Use the verified
package and instructions at [shieldbit.org](https://shieldbit.org/#join), run
your own node, and mine to your own public address. Ubuntu 24.04 and Ubuntu
24.04 on Windows WSL2 are tested environments for the published package.

The reference native miner currently uses one CPU thread. A payout wallet
can be kept separately from the node; public mining and balance inspection do
not require sharing its signing keys with a pool or cloud operator.

## Bitcoin Auxiliary Work

The source under `shieldbit/consensus/auxpow.py` supports Bitcoin-format parent
headers with a coinbase commitment to the ShieldBit child block. A parent hash
that meets ShieldBit's target can produce an SBT auxiliary block. Bitcoin
rewards additionally require a valid Bitcoin block meeting Bitcoin's target.

The node's local owner-only RPC interface offers `aux_block_template` and
`submit_aux_block`. Node P2P TCP 9333 is not a Stratum endpoint. An ASIC cannot
be pointed directly at it as though it were an existing Bitcoin pool.

## Stratum Adapter Status

A newer development-preview adapter has been implemented and tested in the
development repository. It is outside the deployed source snapshot published
here and requires its own reviewed export and signed release before public
operator installation instructions can name that artifact.

That adapter's current scope is fixed-difficulty Stratum V1 work, share
validation, durable candidate submission, AuxPoW construction and manual SBT
PPLNS plans. It has no vardiff or Bitcoin miner payout accounting. Bitcoin
coinbase rewards go to the operator's configured payout script; SBT accounting
does not automatically distribute Bitcoin rewards.

## Steps for a Pool Operator

1. Select a reviewed adapter commit and publish its own sanitized snapshot,
   provenance, tested package and release signature. The current `c5cb556`
   package cannot run the newer adapter.
2. Test work assembly, witness coinbases, valid/invalid/stale shares, child
   submission, Bitcoin block submission, restart recovery and SBT accounting
   with isolated Bitcoin Core regtest and ShieldBit test fixtures.
3. Qualify a consenting real ASIC's model and firmware, reconnect handling,
   share rate and independent block acceptance. CPU/regtest evidence alone
   does not establish hardware compatibility.
4. Complete difficulty/capacity controls, Bitcoin payout accounting or a
   separately integrated payout engine, and the operator's settlement policy.
5. Run the reviewed package with local/private node RPC, authenticated worker
   credentials and a tested TLS Stratum endpoint. Keep wallet signing and
   administrative access separate from miner-facing access.
6. Publish the qualified endpoint, worker enrollment, compatible-device recipe
   and payout terms. Miners can then configure that endpoint in their ASIC
   firmware using their assigned worker credentials.

There is currently no qualified public ShieldBit Stratum endpoint or turnkey
ASIC configuration. Contact support@shieldbit.org for pool integration work.
