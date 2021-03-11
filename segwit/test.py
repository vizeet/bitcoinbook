import binascii

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

def decompress_pubkey(pk):
    x = int.from_bytes(pk[1:33], byteorder='big')
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if y % 2 != pk[0] % 2:
        y = p - y
    y = y.to_bytes(32, byteorder='big')
    return b'\x04' + pk[1:33] + y

print(binascii.hexlify(decompress_pubkey(binascii.unhexlify('0229b3e0919adc41a316aad4f41444d9bf3a9b639550f2aa735676ffff25ba3898'))).decode())
print(binascii.hexlify(decompress_pubkey(binascii.unhexlify('02f15446771c5c585dd25d8d62df5195b77799aa8eac2f2196c54b73ca05f72f27'))).decode())
print(binascii.hexlify(decompress_pubkey(binascii.unhexlify('038262a6c6cec93c2d3ecd6c6072efea86d02ff8e3328bbd0242b20af3425990ac'))).decode())

