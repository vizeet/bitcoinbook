import random
import hashlib

def getRandomNumberBits(bit_count: int):
    r = random.SystemRandom().randrange(0, 1 << 32)
    r_b = r.to_bytes((r.bit_length() + 7) // 8, 'big')
    h = hashlib.sha256()
    h.update(r_b)
    h_b = h.digest()
    byte_count = bit_count // 8
    rand_num_b = h_b[0:byte_count]
    return rand_num_b

if __name__ == '__main__':
    print(getRandomNumberBits(128).hex())
