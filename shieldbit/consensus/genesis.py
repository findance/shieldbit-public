"""Founder-approved mainnet genesis bytes; loading is not launch authorization."""

GENESIS_HASH = bytes.fromhex('0000094862883b548e8e5262f7b7fabd35188d25ddae0c82438cd031e8b3bdbd')
GENESIS_BLOCK_SHA256 = '6382ed680adf2bae0b95528bba71eb9c3643c6b96fc94dc1622044cc4ce85a59'
GENESIS_PAYOUT_ADDRESS = 'sb11ry236yvfg9nnwz3x9p80cqwvf774c4q9hewxqpmvqe79htxk8mejsdu0fav'
GENESIS_BLOCK_HEX = (
    '0000000100000000000000000000000000000000000000000000000000000000'
    '00000000b742a34a689dd56a41cfcc16139a5fad6d103c51a682ec7693f0d5db'
    'd552e763a81b2446269653ea4ec9c60c0f4f42e70d4cf7067536115bfcbfd64a'
    'fe03c598000000006aca64411e0ffff000000ffff00000000000000000000000'
    '00000000000000000000000000000000000000000000cc480000000100020200'
    '00000000000000000000000000000000000000000000000100000000ee6b2800'
    '0000002022a3a231282ce6e144c509df803989f7ab8a80b7cb8c00ed80cf8b75'
    '9ac7de65000000000000004300000000000000004f4d207c20303030312d3031'
    '2d30315430313a30313a30315a0a416c776179732062656c6965766520667574'
    '757265206973206272696768746572'
)


def startup_commitment(profile, supplied=None):
    from shieldbit.network_profile import MAIN
    if profile == MAIN:
        if supplied is not None and supplied != GENESIS_HASH:
            raise ValueError('mainnet genesis must match the approved commitment')
        return GENESIS_HASH
    return supplied


def mainnet_genesis():
    import hashlib
    from shieldbit.core.block import Block
    from shieldbit.consensus.params import GENESIS_TIMESTAMP, GENESIS_MESSAGE, block_reward
    from shieldbit.consensus.validation import validate_block
    from shieldbit.crypto.address import address_to_commitment
    from shieldbit.network_profile import ACTIVE, MAIN
    if ACTIVE.get() != MAIN:
        raise ValueError('approved mainnet genesis requires the mainnet profile')
    raw = bytes.fromhex(GENESIS_BLOCK_HEX)
    block = Block.from_bytes(raw)
    output = block.transactions[0].outputs[0]
    if (hashlib.sha256(raw).hexdigest() != GENESIS_BLOCK_SHA256 or
            block.header.hash != GENESIS_HASH or block.serialize() != raw or
            block.header.timestamp != GENESIS_TIMESTAMP or
            block.transactions[0].data != b'\0' * 8 + GENESIS_MESSAGE or
            output.amount != block_reward(0) or
            output.recipient != address_to_commitment(GENESIS_PAYOUT_ADDRESS, 1,
                                                     expected_commitment_version=2)):
        raise ValueError('compiled genesis does not match the approved recipe')
    validate_block(block, None, {}, 0, 0, expected_bits=MAIN.genesis_bits,
                   network_id=MAIN.network_id)
    return block
