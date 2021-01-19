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
    prefix = PKH_TESTNET_PREFIX
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
#    pubkey = '0240bb63da114aa89f4d2cf35d695d3e52e6add7a4bae06f190d947bef5c62b5e0'
#    pubkey = '0440bb63da114aa89f4d2cf35d695d3e52e6add7a4bae06f190d947bef5c62b5e0e99601851593a9e54e2059a25d76512698acf60089935dedc015f1bb2bc81eda'
    privpubkey_m = {"KwfxnwxpPG1RmhU8jaU8Ron4m1KZGymLAFNaMnSTonoZ7AQfnV53": "0281238fc6d981efce6aa1b3ccb8556a1b115a40f8ab3315c003f415ceedc3defe","L26JcHRhqEQv8V9DaAmE4bdszwqXS7tHznGYJPp7fxEoEQxxBPcQ": "037fadaea6edf196bf70af16cefb2bd3c830e54c0a6e9a00bf7806b241933547f7","L2R3rzLbZZBLdR7Rv7JmUhkagHgGJ1HtvKjdn8wmRoFMWQx4da3x": "02ae4a5cf9bc03aaa86c67d57d17db6f70d1adc3896ab5fa51ec4f4fe4092dc5c0","KxR8HHyfAwFPidCw2vXThXqT4vSMNeufirHFapnfCfkzLaohtujG": "02fcb1c7507db15576ab35cd7c9b1ea570141a8b81c9938dae0320392b0f7034d0","KyWeQEcM2YdirR2E7JwxSRjfgNuWyt4DR3v4sGtPvmeZqhTxWVrp": "02d50250aa629914e3146a5123a362a516c8aa95e5f0a6f3a078bd31fabe383abc","Ky5CYfpeMkfFku7K4FvzeEwRmTJhWqD2eFiMnjLT7uw2oUVMgyg6": "0319b4b9ab4732e78dab0e48c2c54fd57dd35350a0269f8c041807c3b798aa1872","L1cnATDVZyvuo9m6tprCmbr14vm3JeCbkc4Z2397ZM7P96N3d8GA": "039d5dbb6e052631c46e046c6d11fb95d257eae5093117d2c265aeb784dba4acf6","KyP1xynRgwrCUThXATVy5kbKqteAxisDFY74zrHozSGhb75hJ3M6": "02dfa818542ab4685284f7c222d541e218aed0712fc9e63ca2802b15bb418383c9","KxBhPZZFTY9Cks49wobjsrvkUyWcszKZefKGVvTMSBiTecusWris": "0380ba94a6dc0c3738dc9d937149c0031c582b822cb0871332a2124604501949ef","L3mQ6zMk7vTpHSXD2WZdq7Aw289sPNHvyKvYhhK3Zdfe4kYd1hmg": "0278bc4e22ebd4210f35029e6be3c35b9f69b1e82fe7b19d18ba0781fbfe3c03ed"}
    arr = []
    for privkey, pubkey in privpubkey_m.items():
        pubkey_b = bytes.fromhex(pubkey)
        address = pubkey2address(pubkey_b)
        arr.append('"%s": {"%s": "%s"}' % (privkey, pubkey, address))
    print("{" + ",".join(arr) + "}")
