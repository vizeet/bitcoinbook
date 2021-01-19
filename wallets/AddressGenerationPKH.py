import hashlib

PKH_MAINNET_PREFIX = 0x00
SH_MAINNET_PREFIX = 0x05
PKH_TESTNET_PREFIX = 0x6F
SH_TESTNET_PREFIX = 0xC4
PKH_REGTEST_PREFIX = 0x6F
SH_REGTEST_PREFIX = 0xC4

g_alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
g_base_count = len(g_alphabet)

def hash160(secret: bytes):
    secrethash = hashlib.sha256(secret).digest()
    h = hashlib.new('ripemd160')
    h.update(secrethash)
    secret_hash160 = h.digest()
    return secret_hash160

def hash256(bstr: bytes):
    return hashlib.sha256(hashlib.sha256(bstr).digest()).digest()

def base58_encode(num: int):
    global g_alphabet, g_base_count
    encode = ''
    if (num < 0):
        return ''
    while (num >= g_base_count):
        mod = num % g_base_count
        encode = g_alphabet[mod] + encode
        num = num // g_base_count
    if (num >= 0):
        encode = g_alphabet[num] + encode
    return encode

def base58checkEncode(prefix: bytes, b: bytes):
    with_prefix = prefix + b
    with_checksum = with_prefix + hash256(with_prefix)[0:4]
    val = int.from_bytes(with_checksum, byteorder='big')
    encode = base58_encode(val)
    if prefix == b'\x00':
        encoded_prefix = base58_encode(0)
        encode = encoded_prefix + encode
    return encode

def pkh2address(pkh: bytes):
    prefix = PKH_MAINNET_PREFIX
    address = base58checkEncode(bytes.fromhex('%02x' % prefix), pkh)
    return address

def sh2address(sh: bytes):
    prefix = SH_REGTEST_PREFIX
    address = base58checkEncode(bytes.fromhex('%02x' % prefix), pkh)
    return address

def pubkey2address(pubkey: bytes):
    pkh = hash160(pubkey)
    address = pkh2address(pkh)
    return address

if __name__ == '__main__':
    pubkey = '0240bb63da114aa89f4d2cf35d695d3e52e6add7a4bae06f190d947bef5c62b5e0'
    pubkey = '0440bb63da114aa89f4d2cf35d695d3e52e6add7a4bae06f190d947bef5c62b5e0e99601851593a9e54e2059a25d76512698acf60089935dedc015f1bb2bc81eda'
    pubkey_b = bytes.fromhex(pubkey)
    print(pubkey_b.hex())
    address = pubkey2address(pubkey_b)
    print(address)
