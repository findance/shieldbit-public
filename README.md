# ShieldBit (SBT)

Public, reviewed source snapshots of ShieldBit, a peer-to-peer proof-of-work
currency with ML-DSA-65 spending signatures.

**Snapshot:** deployed source commit
`c5cb5568c5499c0e22083f504953b9f7ca7b6134`.

[Website and mining instructions](https://shieldbit.org/#join) |
[Whitepaper](https://shieldbit.org/ShieldBit_Whitepaper.pdf) |
[Mining and pool support](docs/Mining_and_Pool_Support.md)

## Repository Scope

This repository starts with a fresh Git history and contains selected files
from the public source archive. All 43 imported source files remain byte-for-byte
identical to that archive. The README, license, support notes and provenance
manifest are additions for this public repository.

Private development branches, PR history, Git objects, cloud administration,
wallets, credentials and operational logs are not copied into this repository.
Future updates will be separately reviewed snapshots with their original source
commit recorded. Development code newer than this snapshot is not automatically
included. The package metadata retains the historical upstream project URL;
this repository is the public source location.

## Current Network

| Parameter | Deployed value |
|---|---|
| Supply ceiling | 20,000,000 SBT |
| Initial subsidy | 40 SBT |
| Halving interval | 250,000 blocks |
| Target block time | 10 minutes |
| Coinbase maturity | 100 blocks |
| Maximum block size | 6 MiB |
| Spending signatures | ML-DSA-65 |
| Addresses | Versioned 32-byte commitments; mainnet addresses begin `sb11r` |

Mainnet genesis:
`0000094862883b548e8e5262f7b7fabd35188d25ddae0c82438cd031e8b3bdbd`.

Immutable signing network ID:
`3902ef29e80d97be35bdef5c86e71baeadb5ab9dee926040cd56d9c88d268509`.

## Download and Verify

Use the founder-signed Linux x86-64 package for verified deployment. Ubuntu
24.04 and Windows WSL2 Ubuntu 24.04 have been tested. The package requires
CPython 3.12 and glibc 2.34 or newer.

- [Signed package](https://shieldbit.org/downloads/shieldbit-linux-x86_64-c5cb556.tar.gz)
- [Public installer](https://shieldbit.org/downloads/install_public_release.py)
- [Package checksum](https://shieldbit.org/downloads/release-sha256.txt)
- [Original source archive](https://shieldbit.org/downloads/shieldbit-source-c5cb556.tar)
- [Source archive checksum](https://shieldbit.org/downloads/source-sha256.txt)

Package SHA-256:
`1477b0ff77406f023bb40575974f5cd6cf6b059a666510be93c3baa0e4fb2a20`.

Source archive SHA-256:
`d0631104deee928e7612ac9040e77fd083bcfb24abb65ebdd7ad564cd68c6fb0`.

Approved release-key SHA3-256 fingerprint:
`48060e8e6795732b8b6cdb9069c3328ddf9ec61b9dff911b844becca2a70eb45`.

After reviewing the installer and downloading both files, run as a regular
user in Linux or WSL:

```sh
python3.12 install_public_release.py \
  --archive shieldbit-linux-x86_64-c5cb556.tar.gz \
  --sha256 1477b0ff77406f023bb40575974f5cd6cf6b059a666510be93c3baa0e4fb2a20
```

Follow the website's instructions to create your own wallet, verify its backup,
connect a node and mine to your own public address. Keep wallet seeds, private
keys and passwords private.

## Inspect or Build the Source

```sh
git clone https://github.com/findance/shieldbit-public.git
cd shieldbit-public
python3.12 -m venv .venv
.venv/bin/python -m pip install .
```

A source build is a new artifact and does not carry the founder's production
signature. This snapshot does not include the complete private development test
and operations environment. For artifact identity, compare the imported file
hashes in [SNAPSHOT.json](SNAPSHOT.json) with the published source archive.

## Bitcoin ASIC and Pool Support

The deployed source supports bounded Bitcoin-format auxiliary proofs. This
snapshot does not include the newer Stratum adapter. There is no qualified public
Stratum endpoint or device-specific ASIC recipe. See the support notes for
operator qualification and future publication steps.

## Contributing

Public issues, independent review findings and proposed fixes are welcome. Code
changes are reviewed in the development repository before a new snapshot is
published here. Please include the snapshot identifier and reproducible details
in reports, and exclude private keys, credentials and wallet files.

For private security reports, contact support@shieldbit.org. No established
exchange price or guaranteed mining returns are claimed.

## License

Apache-2.0. Existing source copyright notices are preserved. See [LICENSE](LICENSE).
