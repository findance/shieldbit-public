"""Local fee policy, distinct from the consensus transaction minimum."""
from shieldbit.consensus.params import MIN_FEE

DEFAULT_RELAY_QUANTA_PER_KB = 50
DEFAULT_INCREMENTAL_QUANTA_PER_KB = 50
MLDSA_WIRE_SIGNATURE_BYTES = 3310


def required_fee(size: int, rate: int = DEFAULT_RELAY_QUANTA_PER_KB) -> int:
    """Round up a decimal-kilobyte fee, retaining the transaction floor."""
    if type(size) is not int or size <= 0:
        raise ValueError('size must be a positive integer')
    if type(rate) is not int or rate <= 0:
        raise ValueError('fee rate must be a positive integer')
    return max(MIN_FEE, (size * rate + 999) // 1000)
