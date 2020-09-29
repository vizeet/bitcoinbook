target_threshold = 0x1007ea*(256**0x14) 
print('Target Threshold = %x' % target_threshold)
block_hash = 0x00000000000000000005ba3f665a009249baabf894238e5113c2d40cd1e7fdd0
print('Block Hash = %x' % block_hash)
print('Valid' if target_threshold > block_hash else 'Invalid')
