import pbkdf2
import hashlib
import hmac
from ecdsa import SigningKey, SECP256k1
import struct
import secp256k1

iterations_g = 10000
dklen_g = 64 # derived key length

g_alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
g_base_count = len(g_alphabet)

def hash256(bstr: bytes):
    return hashlib.sha256(hashlib.sha256(bstr).digest()).digest()

def hash160(secret: bytes):
    secrethash = hashlib.sha256(secret).digest()
    h = hashlib.new('ripemd160')
    h.update(secrethash)
    secret_hash160 = h.digest()
    return secret_hash160

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

def genSeedFromStr(password: str, salt: str):
    password_b = password.encode('utf-8')
    salt_b = salt.encode('utf-8')
    seed = pbkdf2.pbkdf2(hashlib.sha512, password_b, salt_b, iterations_g, dklen_g)
    return seed

def base58checkEncode(prefix: bytes, b: bytes):
    with_prefix = prefix + b
    with_checksum = with_prefix + hash256(with_prefix)[0:4]
    val = int.from_bytes(with_checksum, byteorder='big')
    encode = base58_encode(val)
    if prefix == b'\x00':
        encoded_prefix = base58_encode(0)
        encode = encoded_prefix + encode
    return encode

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

def genMasterKeys(seed: bytes):
    h = hmac.new(bytes("Bitcoin seed", 'utf-8'),
                    seed, 
                    hashlib.sha512).digest()
    private_key = int.from_bytes((h[0:32]), byteorder='big')
    chaincode = h[32:64]
    return private_key, chaincode

XPUB_VERSION = '0488B21E'
XPRV_VERSION = '0488ADE4'
TPUB_VERSION = '043587CF'
TPRV_VERSION = '04358394'

def getMasterXPrv(chaincode_b: bytes, privkey: int):
    version_b = bytes.fromhex(TPRV_VERSION)
    depth_b = b'\x00'
    fingerprint_p_b = bytes(4)
    index_b = bytes(4)
    privkey_b = bytes.fromhex('%066x' % privkey)
    raw_xprv = depth_b + fingerprint_p_b + index_b + chaincode_b + privkey_b
    xprv = base58checkEncode(version_b, raw_xprv)
    return xprv

def getMasterXPub(chaincode_b: bytes, pubkey: str):
    version_b = bytes.fromhex(TPUB_VERSION)
    depth_b = b'\x00'
    fingerprint_p_b = bytes(4)
    index_b = bytes(4)
    pubkey_b = bytes.fromhex(pubkey)
    raw_xpub = depth_b + fingerprint_p_b + index_b + chaincode_b + pubkey_b
    xpub = base58checkEncode(version_b, raw_xpub)
    return xpub

def getXPrv(p_pubkey: str, 
            chaincode_b: bytes, 
            privkey: int, 
            depth: int, 
            index: int):
    version_b = bytes.fromhex(TPRV_VERSION)
    p_pubkey_b = bytes.fromhex(p_pubkey)
    privkey_b = bytes.fromhex('%066x' % privkey)
    depth_b = bytes([depth])
    p_fingerprint_b = hash160(p_pubkey_b)[0:4]
    index_b = struct.pack('>L', index)
    raw_xprv = depth_b + p_fingerprint_b + index_b + chaincode_b + privkey_b
    xprv = base58checkEncode(version_b, raw_xprv)
    return xprv

def decodeRawXPrv(raw_xprv: str):
    raw_xprv_b = bytes.fromhex(raw_xprv)
#    raw_xprv = base58checkDecode(xprv)
    print('version = %s' % raw_xprv_b[0:4].hex())
    print('depth = %s' % raw_xprv_b[4:5].hex())
    print('parent fingerprint = %s' % raw_xprv_b[5:9].hex())
    print('index = %s' % raw_xprv_b[9:13].hex())
    print('chaincode = %s' % raw_xprv_b[13:45].hex())
    print('private key = %s' % raw_xprv_b[45:78].hex())
    

def getXPub(p_pubkey: str, 
            chaincode_b: bytes, 
            pubkey: str, 
            depth: int, 
            index: int):
    version_b = bytes.fromhex(TPUB_VERSION)
    p_pubkey_b = bytes.fromhex(p_pubkey)
    pubkey_b = bytes.fromhex(pubkey)
    depth_b = bytes([depth])
    p_fingerprint_b = hash160(p_pubkey_b)[0:4]
    index_b = struct.pack('>L', index)
    raw_xpub = depth_b + p_fingerprint_b + index_b + chaincode_b + pubkey_b
    xpub = base58checkEncode(version_b, raw_xpub)
    return xpub

def decodeRawXPub(raw_xpub: str):
    raw_xpub_b = bytes.fromhex(raw_xpub)
#    raw_xprv = base58checkDecode(xprv)
    print('version = %s' % raw_xpub_b[0:4].hex())
    print('depth = %s' % raw_xpub_b[4:5].hex())
    print('parent fingerprint = %s' % raw_xpub_b[5:9].hex())
    print('index = %s' % raw_xpub_b[9:13].hex())
    print('chaincode = %s' % raw_xpub_b[13:45].hex())
    print('public key = %s' % raw_xpub_b[45:78].hex())

secp256k1_N = (1 << 256) - 0x14551231950B75FC4402DA1732FC9BEBF

def genChildAtIndex(privkey: int, chaincode: bytes, index: int):
    if index >= (1<<31):
        # hardened
        #print('hardened')
        h = hmac.new(chaincode, b'\x00' + bytes.fromhex('%064x' % privkey) + bytes.fromhex('%08x' % index), hashlib.sha512).digest()
    else:
        # normal
        privkey_s = '%064x' % privkey
        privkey_b = bytes.fromhex(privkey_s)
        sk = SigningKey.from_string(privkey_b, curve=SECP256k1)
        vk = sk.get_verifying_key()

        full_pubkey_b = b'\x04' + vk.to_string()
        pubkey = secp256k1.compressPubkey(full_pubkey_b)
        h = hmac.new(chaincode, pubkey + bytes.fromhex('%08x' % index), hashlib.sha512).digest()
    childprivkey = (int.from_bytes(h[0:32], byteorder='big') + privkey) % secp256k1_N
    child_chaincode = h[32:64]
    return childprivkey, child_chaincode

def finiteFieldAddition(a: int, b: int, modulo: int):
    return (a + b) % modulo

def genNormalChildPrivKey(privkey: int, chaincode: bytes, index: int):
    privkey_s = '%064x' % privkey
    pubkey_b = privkeyHex2pubkey(privkey_s, True)
    index_b = struct.pack('>L', index)
    h = hmac.new(chaincode, pubkey_b + index_b, hashlib.sha512).digest()
    h256 = int.from_bytes(h[0:32], byteorder='big')
    child_privkey = finiteFieldAddition(h256, privkey, secp256k1_N)
    child_chaincode = h[32:64]
    return child_privkey, child_chaincode

def genHardenedChildPrivKey(privkey: int, chaincode: bytes, index: int):
    index_b = struct.pack('>L', index)
    privkey_b = bytes.fromhex('%064x' % privkey)
    h = hmac.new(chaincode, b'\x00' + privkey_b + index_b, hashlib.sha512).digest()
    h256 = int.from_bytes(h[0:32], byteorder='big')
    child_privkey = finiteFieldAddition(h256, privkey, secp256k1_N)
    child_chaincode = h[32:64]
    return child_privkey, child_chaincode

def genNormalChildPubKey(pubkey_b: bytes, chaincode: bytes, index: int):
    index_b = struct.pack('>L', index)
    h = hmac.new(chaincode, pubkey_b + index_b, hashlib.sha512).digest()
    h256 = int.from_bytes(h[0:32], byteorder='big')
    h256G = secp256k1.point_mul(secp256k1.G, h256)
    pubkey = secp256k1.uncompressPubkey(pubkey_b)
    child_pubkey_t = secp256k1.point_add(h256G, pubkey)
    child_pubkey_x_b = bytes.fromhex('%016x' % child_pubkey_t[0])
    child_pubkey_y_b = bytes.fromhex('%016x' % child_pubkey_t[1])
    child_pubkey_b = b'\x04' + child_pubkey_x_b + child_pubkey_y_b
    child_pubkey = secp256k1.compressPubkey(child_pubkey_b)
    child_chaincode = h[32:64]
    return child_pubkey, child_chaincode

def genNormalParentPrivKey(child_privkey_i: int, 
                            pubkey_b: bytes, 
                            chaincode: bytes, 
                            index: int):
    index_b = struct.pack('>L', index)
    h = hmac.new(chaincode, pubkey_b + index_b, hashlib.sha512).digest()
    h256 = int.from_bytes(h[0:32], byteorder='big')
    privkey = finiteFieldAddition(-h256, child_privkey_i, secp256k1_N)
    return privkey

def genPrivkeyPubkeyPair(keypath: str, seed: bytes, compressed: bool):
    keypath_list = keypath.replace(' ', '').split('/')
    if keypath_list[0] != 'm':
        return None
    for key in keypath_list:
        if key == 'm':
            privkey, chaincode = genMasterKeys(seed)
        else:
            if "'" in key:
                index = int(key[:-1]) + (1<<31)
            else:
                index = int(key)
            privkey, chaincode = genChildAtIndex(privkey, chaincode, index)
    privkey_s = '%064x' % privkey
    privkey_b = bytes.fromhex(privkey_s)
    sk = SigningKey.from_string(privkey_b, curve=SECP256k1)
    vk = sk.get_verifying_key()

    pubkey_b = b'\x04' + vk.to_string()
    if compressed == True:
        pubkey = secp256k1.compressPubkey(pubkey_b)
    return privkey, pubkey

#def compressPubkey(pubkey: bytes):
#    x_b = pubkey[1:33]
#    y_b = pubkey[33:65]
#    if (y_b[31] & 0x01) == 0: # even
#        compressed_pubkey = b'\x02' + x_b
#    else:
#        compressed_pubkey = b'\x03' + x_b
#    return compressed_pubkey

def privkeyHex2pubkey(privkey_s: str, compress: bool):
    privkey_b = bytes.fromhex(privkey_s)
    sk = SigningKey.from_string(privkey_b, curve=SECP256k1)
    vk = sk.get_verifying_key()
    pubkey_b = b'\x04' + vk.to_string()
    if compress == True:
        pubkey_b = secp256k1.compressPubkey(pubkey_b)
    return pubkey_b

PRIVKEY_PREFIX_MAINNET=0x80

def encodeWifPrivkey(privkey: int, for_compressed_pubkey: bool):
    prefix_b = bytes.fromhex('%02x' % PRIVKEY_PREFIX_MAINNET)
    privkey_b = bytes.fromhex('%064x' % privkey)
#    print('prefix = %s, privkey = %s, compress = %s' % (prefix_b.hex(), privkey_b.hex(),
#                            '01' if for_compressed_pubkey == True else ''))
    if for_compressed_pubkey == True:
        privkey_b = privkey_b + b'\01'
    wif_encoded = base58checkEncode(prefix_b, privkey_b)
    return wif_encoded

if __name__ == '__main__':
    mnemonic_code_l = ['moral', 'submit', 'comfort', 'cupboard', 'organ', 
            'expand', 'home', 'bid', 'dawn', 'ozone', 'omit', 'helmet']
    mnemonic_code = ' '.join(mnemonic_code_l)
    seed = genSeedFromStr(mnemonic_code, 'mnemonic' + 'mycomplexpasscode')
    privkey, chaincode = genMasterKeys(seed)
    privkey_s = '%064x' % privkey
    print('master privkey = %s' % privkey_s)
    print('master chaincode = %s' % chaincode.hex())

    xprv = getMasterXPrv(chaincode, privkey)
    print('xprv=%s' % xprv)
    pubkey_b = privkeyHex2pubkey(privkey_s, True)
    xpub = getMasterXPub(chaincode, pubkey_b.hex())
    print('xprv=%s' % xpub)

    child_privkey_i, child_chaincode = genNormalChildPrivKey(privkey, chaincode, 10)
    child_privkey_wif = encodeWifPrivkey(child_privkey_i, True)
    print("child privkey = %s" % child_privkey_wif)
    print("child chaincode = %s" % child_chaincode.hex())

    pubkey_b = privkeyHex2pubkey(privkey_s, True)
    child_pubkey_b, child_chaincode = genNormalChildPubKey(pubkey_b, chaincode, 1)
    print("child pubkey key = %s" % child_pubkey_b.hex())
    print("child chaincode = %s"% child_chaincode.hex())

    # We are calculating for index=1 and depth=1
    child_xprv = getXPrv(pubkey_b.hex(), child_chaincode, child_privkey_i, 1, 1)
    print('child xprv:')
    print(child_xprv)

    child_xpub = getXPub(pubkey_b.hex(), child_chaincode, child_pubkey_b.hex(), 1, 1)
    print('child xpub:')
    print(child_xpub)

    p_privkey_i = genNormalParentPrivKey(child_privkey_i, pubkey_b, chaincode, 1)
    p_privkey_wif = encodeWifPrivkey(p_privkey_i, True)
    print('parent privkey = %064x' % p_privkey_i)

    child_privkey_i, child_chaincode = genHardenedChildPrivKey(privkey, chaincode, (1<<31) + 1)
    child_privkey_wif = encodeWifPrivkey(child_privkey_i, True)
    print("child privkey = %s" % child_privkey_wif)
    print("child chaincode = %s" % child_chaincode.hex())

