# Independent public release trust

The website is a distribution mirror, not an independent trust anchor. Obtain
and inspect `release/install_public_release.py` from **this public repository
at an independently reviewed immutable commit**, then compare these values.
Do not trust an installer, checksum and fingerprint obtained only from the same
website: a website compromise could replace all three.

Legacy Linux / WSL package:

- Source commit: `c5cb5568c5499c0e22083f504953b9f7ca7b6134`
- Archive: `shieldbit-linux-x86_64-c5cb556.tar.gz`
- Archive SHA-256: `1477b0ff77406f023bb40575974f5cd6cf6b059a666510be93c3baa0e4fb2a20`
- Production signing-key SHA3-256 fingerprint: `48060e8e6795732b8b6cdb9069c3328ddf9ec61b9dff911b844becca2a70eb45`

This installer pins the outer archive hash and checks the existing pinned inner
wheels, verifier scripts and production signature. It rejects even a matching
user-supplied checksum for a replacement archive. It creates no wallet, starts
no mining and never requests recovery phrases or private keys. Inspect source
before executing it. This is the existing Python 3.12 Linux x86-64 installer,
not a new binary release or a change to the public chain.

`release/release-sha256.txt` is an independent copy of the pinned checksum,
not a newly signed checksum file. No new private signing key, detached checksum
signature, GitHub Release/attestation or DNS trust record is created here.
A release operator with the existing private signing key must sign the checksum
and publish detached signatures/attestations through an independently verified
release channel before producing a new distribution. An unsigned founder launch
record must not be represented as cryptographic authorization.

Immutable GitHub commits make this a separate channel from the website. They
are not a substitute for independently verifying this repository, the review,
the commit identity and the release signing fingerprint. Mutable `main` and a
same-site hash are not independent proof of publisher identity.
