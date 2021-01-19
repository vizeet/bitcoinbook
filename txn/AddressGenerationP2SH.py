import hashlib
from functools import reduce

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
    prefix = PKH_REGTEST_PREFIX
    address = base58checkEncode(bytes.fromhex('%02x' % prefix), pkh)
    return address

def sh2address(sh: bytes):
    prefix = SH_REGTEST_PREFIX
    address = base58checkEncode(bytes.fromhex('%02x' % prefix), sh)
    return address

def pubkey2address(pubkey: bytes):
    pkh = hash160(pubkey)
    address = pkh2address(pkh)
    return address

def createVarInt(i: int):
    if i < 0xfd:
        return bytes([i])
    elif i < 0xffff:
        return b'\xfd' + struct.pack('<H', i)
    elif i < 0xffffffff:
        return b'\xfe' + struct.pack('<L', i)
    elif i < 0xffffffffffffffff:
        return b'\xff' + struct.pack('<Q', i)

def createRedeemScript(pubkey_l: list, sigcount: int):
    redeem_script_b = bytes([0x50 + sigcount])
    for pubkey in pubkey_l:
        pubkey_b = bytes.fromhex(pubkey)
        redeem_script_b += createVarInt(len(pubkey_b)) + pubkey_b
    redeem_script_b += bytes([0x50 + len(pubkey_l)]) + b'\xae'
    return redeem_script_b

if __name__ == '__main__':
    pubkey_l = ['037fadaea6edf196bf70af16cefb2bd3c830e54c0a6e9a00bf7806b241933547f7', '02fcb1c7507db15576ab35cd7c9b1ea570141a8b81c9938dae0320392b0f7034d0', '02d50250aa629914e3146a5123a362a516c8aa95e5f0a6f3a078bd31fabe383abc']
    redeem_script_b = createRedeemScript(pubkey_l, 2)
    print('redeem script = %s' % redeem_script_b.hex())
    sh = hash160(redeem_script_b)
    address = sh2address(sh)
    print('P2SH address = %s' % address)
