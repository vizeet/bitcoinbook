def getTargetThreshold(bits: bytes):
    shift = bits[3]
    value = int.from_bytes(bits[0:3], byteorder='little')
    target_threshold = value * 2 ** (8 * (shift - 3))
    return target_threshold

bits = bytes.fromhex("171007ea")[::-1]
target_threshold = getTargetThreshold(bits)
print('Target Threshold = %x' % target_threshold)
block_hash = 0x00000000000000000005ba3f665a009249baabf894238e5113c2d40cd1e7fdd0
print('Block Hash = %x' % block_hash)
print('Valid' if target_threshold > block_hash else 'Invalid')
