
def b128_varint_encode(n: int):
    l = 0
    b = []
    while True:
        # Take 7 bits and set MSB if not last byte
        b.append((n & 0x7F)| (0x80 if l != 0 else 0x00))
        if n <= 0x7F:
            break
        n = (n >> 7) - 1
        l += 1
    return bytes(bytearray(b[::-1]))

def b128_varint_decode(b: bytes):
    n = 0
    pos = 0
    while True:
        data = b[pos]
        pos += 1
        # unset MSB bit 
        n = (n << 7) | (data & 0x7f)
        if data & 0x80 == 0:
            return n
        n += 1

for num in [127, 128, 255, 256, 16383, 16384, 16511, 64535, 65535, 2**32]:
    enc = b128_varint_encode(num)
#    print("num = %d, enc = %s, dec = %d" % (num, enc.hex(), b128_varint_decode(enc)))
    print("0x%s" % enc.hex())
