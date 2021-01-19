import hashlib
from ecdsa import SigningKey, SECP256k1

PRIVKEY_PREFIX_MAINNET=0x80
WIF_PREFIX_MAINNET_COMPRESSED=['L', 'K']
WIF_PREFIX_MAINNET_UNCOMPRESSED=['5']

PRIVKEY_PREFIX_TESTNET=0xEF
WIF_PREFIX_TESTNET_COMPRESSED=['c']
WIF_PREFIX_TESTNET_UNCOMPRESSED=['9']

g_alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
g_base_count = len(g_alphabet)

def hash256(bstr):
    return hashlib.sha256(hashlib.sha256(bstr).digest()).digest()

def base58_decode(s: str):
    global g_alphabet, g_base_count
    decoded = 0
    multi = 1
    s = s[::-1]
    for char in s:
        decoded += multi * g_alphabet.index(char)
        multi = multi * g_base_count
    return decoded

def base58checkDecode(s: str):
    with_checksum_int = base58_decode(s)
    with_checksum_b = bytes.fromhex('%x' % with_checksum_int)
    decode_b = with_checksum_b[1:-4]
    return decode_b

def base58checkVerify(wif: str):
    decoded_wif = base58_decode(wif)
    wif_str = '%02x' % decoded_wif
    if len(wif_str) % 2 == 1:
            wif_str = '0' + wif_str
    postfix = bytes.fromhex(wif_str)[-4:]
    wif_without_postfix = bytes.fromhex(wif_str)[0:-4]
    h = hash256(wif_without_postfix)[0:4]
    if h == postfix:
        return True
    return False

def base58checkDecode(s: str):
        with_checksum_int = base58_decode(s)
        with_checksum_b = bytes.fromhex('%x' % with_checksum_int)
        decode_b = with_checksum_b[1:-4]
        return decode_b

def getNetworkNCompression(wif_prefix: str):
    if wif_prefix in WIF_PREFIX_MAINNET_COMPRESSED:
        return 'mainnet', True
    elif wif_prefix in WIF_PREFIX_MAINNET_UNCOMPRESSED:
        return 'mainnet', False
    elif wif_prefix in WIF_PREFIX_TESTNET_COMPRESSED:
        return 'testnet', True
    elif wif_prefix in WIF_PREFIX_TESTNET_UNCOMPRESSED:
        return 'testnet', False

def privkeyWif2Hex(privkey_wif: str):
    assert base58checkVerify(privkey_wif)
    wif_prefix = privkey_wif[0:1]
    network, compress = getNetworkNCompression(wif_prefix)
    privkey_b = base58checkDecode(privkey_wif)
    if compress == True:
        assert privkey_b[-1] == 0x01
        privkey_b = privkey_b[:-1]
    privkey_i = int.from_bytes(privkey_b, byteorder='big')
    privkey_s = '%064x' % privkey_i
    return privkey_s, network, compress

def compressPubkey(pubkey: bytes):
    x_b = pubkey[1:33]
    y_b = pubkey[33:65]
    if (y_b[31] & 0x01) == 0: # even
        compressed_pubkey = b'\x02' + x_b
    else:
        compressed_pubkey = b'\x03' + x_b
    return compressed_pubkey

def privkeyHex2pubkey(privkey_s: str, compress: bool):
    privkey_b = bytes.fromhex(privkey_s)
    sk = SigningKey.from_string(privkey_b, curve=SECP256k1)
    vk = sk.get_verifying_key()
    pubkey_b = b'\x04' + vk.to_string()
    print('uncompressed : %s' % pubkey_b.hex())
    if compress == True:
        pubkey_b = compressPubkey(pubkey_b)
    return pubkey_b

def privkeyWif2pubkey(privkey: str):
    privkey_s, network, compress = privkeyWif2Hex(privkey)
    pubkey = privkeyHex2pubkey(privkey_s, compress)
    return pubkey

if __name__ == '__main__':
    privkey_wif = 'cNdY2QGfetwijtrqzCK5tAoc78NtGkQJ8smYVaugDW6puLXJvLZG'
#    privkey_wif = '91phZVP8Q5yMLEZbD41vfnGYWwEZuxbjQ5huSxiPUkkTiQw8SL2'
    print(privkey_wif)
    privkey_s, network, compress = privkeyWif2Hex(privkey_wif)
    print('privkey_s = %s, network = %s, compress = %r' % (privkey_s, network, compress))
    pubkey_b = privkeyWif2pubkey(privkey_wif)
    print('pubkey = %s' % pubkey_b.hex())
