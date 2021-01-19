from ecdsa import SigningKey, SECP256k1
from ecdsa.util  import sigencode_der_canonize
import struct
import plyvel
import os
import mmap
import hashlib

SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80

BLOCK_HEADER_SIZE = 80

g_alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
g_base_count = len(g_alphabet)

chainstate_db_g = plyvel.DB(os.getenv('REGTEST_CHAINSTATE_DB'), compression=None)

blocks_path_g = os.getenv('REGTEST_BLOCKS_PATH')

PRIVKEY_PREFIX_MAINNET=0x80
WIF_PREFIX_MAINNET_COMPRESSED=['L', 'K']
WIF_PREFIX_MAINNET_UNCOMPRESSED=['5']

PRIVKEY_PREFIX_TESTNET=0xEF
WIF_PREFIX_TESTNET_COMPRESSED=['c']
WIF_PREFIX_TESTNET_UNCOMPRESSED=['9']

def getNetworkNCompression(wif_prefix: str):
    if wif_prefix in WIF_PREFIX_MAINNET_COMPRESSED:
        return 'mainnet', True
    elif wif_prefix in WIF_PREFIX_MAINNET_UNCOMPRESSED:
        return 'mainnet', False
    elif wif_prefix in WIF_PREFIX_TESTNET_COMPRESSED:
        return 'testnet', True
    elif wif_prefix in WIF_PREFIX_TESTNET_UNCOMPRESSED:
        return 'testnet', False

def amount_compress(n: int):
    if n == 0:
        return 0;
    e = 0
    while ((n % 10) == 0) and e < 9:
        n //= 10
        e += 1
    if e < 9:
        d = n % 10
        assert d >= 1 and d <= 9
        n //= 10
        return 1 + (n*9 + d - 1)*10 + e
    else:
        return 1 + (n - 1)*10 + 9

def amount_decompress(x):
    if x == 0:
        return 0
    x -= 1
    e = x % 10
    x //= 10
    if e < 9:
        d = (x % 9) + 1
        x //= 9
        n = x * 10 + d
    else:
        n = x + 1
    while e > 0:
        n *= 10
        e -= 1
    return n

def base58_decode(s: str):
    global g_alphabet, g_base_count
    decoded = 0
    multi = 1
    s = s[::-1]
    for char in s:
        decoded += multi * g_alphabet.index(char)
        multi = multi * g_base_count
    return decoded

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

def address2PubkeyHash(address: str):
    pkh = base58checkDecode(address)
    return pkh

def hash256(bstr: bytes):
    return hashlib.sha256(hashlib.sha256(bstr).digest()).digest()

def b128_varint_decode(b: bytes, pos = 0):
    n = 0
    while True:
        data = b[pos]
        pos += 1
        n = (n << 7) | (data & 0x7f)
        if data & 0x80 == 0:
            return (n, pos)
        n += 1

def b128_varint_encode(n: int):
    l = 0
    tmp = []
    while True:
        tmp.insert(0, n & 0x7F)
        if l != 0:
            tmp[0] |= 0x80
        if n <= 0x7F:
            break
        n = (n >> 7) - 1
        l += 1

    bin_data = bytes(tmp)
    return bin_data

def privkeyWif2Hex(privkey_wif: str):
    assert base58checkVerify(privkey_wif)
    wif_prefix = privkey_wif[0:1]
    network, compress = getNetworkNCompression(wif_prefix)
    privkey_b = base58checkDecode(privkey_wif)
    privkey_i = int.from_bytes(privkey_b, byteorder='big')
    if compress == True:
        privkey_s = '%066x' % privkey_i
    else:
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
    if compress == True:
        privkey_s = privkey_s[0:64]
    privkey_b = bytes.fromhex(privkey_s)
    sk = SigningKey.from_string(privkey_b, curve=SECP256k1)
    vk = sk.get_verifying_key()
    pubkey_b = b'\x04' + vk.to_string()
    if compress == True:
            pubkey_b = compressPubkey(pubkey_b)
    return pubkey_b

def privkeyWif2pubkey(privkey: str):
    privkey_s, network, compress = privkeyWif2Hex(privkey)
    pubkey_b = privkeyHex2pubkey(privkey_s, compress)
    return pubkey_b

def getObfuscationKey(chainstate_db):
    value = chainstate_db.get(b'\x0e\x00' + b'obfuscate_key')
    print('obfuscation key = %s' % value)
    obfuscation_key = value[1:]
    return obfuscation_key

def applyObfuscationKey(data: bytes, chainstate_db):
    obfuscation_key = getObfuscationKey(chainstate_db)
    print('obfuscation_key = %s' % obfuscation_key.hex())
    new_val = bytes()
    for index in range(len(data)):
        obf_key_i = index % len(obfuscation_key)
        dt_i = bytes([data[index] ^ obfuscation_key[obf_key_i]])
        new_val = new_val + dt_i
    new_val1 = bytes(data[index] ^ obfuscation_key[index % len(obfuscation_key)] for index in range(len(data)))
    print('data = \t\t\t\t%s' % data.hex())
    print('obf_key_for_application = \t%s' % bytes(obfuscation_key[index % len(obfuscation_key)] for index in range(len(data))).hex())
    print('new_val = \t\t\t%s' % new_val.hex())
    print('new_val1 = \t\t\t%s' % new_val1.hex())
    return new_val

def getUnspentTransactions(tx_hash: bytes, out_index: int,chainstate_db):
    key = b'C' + tx_hash + b128_varint_encode(out_index)
    value_obf_b = chainstate_db.get(key)
    value_obf_b = applyObfuscationKey(value_obf_b, chainstate_db)
    jsonobj = {}
    code, pos = b128_varint_decode(value_obf_b)
    jsonobj['is_coinbase'] = code & 0x01
    jsonobj['block_height'] = code >> 1
    compressed_amount, pos = b128_varint_decode(value_obf_b, pos)
    print('compressed_amount = %d' % compressed_amount)
    jsonobj['unspent_amount'] = amount_decompress(compressed_amount)
    print('uncompressed_amount = %d' % jsonobj['unspent_amount'])
    print('compressed_amount = %d' % amount_compress(jsonobj['unspent_amount']))
    jsonobj['script_type'], pos = b128_varint_decode(value_obf_b, pos)
    jsonobj['scriptdata']= value_obf_b[pos:].hex()
    return jsonobj

def createVarInt(i: int):
    if i < 0xfd:
        return bytes([i])
    elif i < 0xffff:
        return b'\xfd' + struct.pack('<H', i)
    elif i < 0xffffffff:
        return b'\xfe' + struct.pack('<L', i)
    elif i < 0xffffffffffffffff:
        return b'\xff' + struct.pack('<Q', i)

OP_PUSHDATA1 = 0x4c
OP_PUSHDATA2 = 0x4d
OP_PUSHDATA4 = 0x4e

def encodePushdata(length: int):
    if length <= 0x4b:
        return bytes([length])
    if length <= 0xff:
        return bytes([OP_PUSHDATA1, length])
    if length <= 0xffff:
        return bytes([OP_PUSHDATA2]) + struct.pack('<H', length)
    if length <= 0xffffffff:
        return bytes([OP_PUSHDATA4]) + struct.pack('<L', length)

def getScriptTypeFromAddress(address: str):
    if address[0] in ['m', 'n']:
        return "P2PKH"
    elif address[0] == '2':
        return "P2SH"

def getScriptPubkeyFromAddress(address: str):
    pkh_b = address2PubkeyHash(address)
    pkhSize_b = encodePushdata(len(pkh_b))
    script_type = getScriptTypeFromAddress(address)
    if script_type == 'P2PKH':
        scriptPubkey_b = b'\x76' \
                        + b'\xa9' \
                        + pkhSize_b \
                        + pkh_b \
                        + b'\x88' \
                        + b'\xac'
    elif script_type == 'P2SH':
        scriptPubkey_b = b'\xa9' \
                        + pkhSize_b \
                        + pkh_b \
                        + b'\x87'
    return scriptPubkey_b

def createSignaturePreimage(txn_struct: dict, 
                            script_b: bytes,
                            inp_index: int):
    preimage_b = b''
    preimage_b += struct.pack('<L', txn_struct['version'])
    preimage_b += createVarInt(txn_struct['input_count'])
    for i in range(txn_struct['input_count']):
        prevtxn = txn_struct['inputs'][i]['prevtxn']
        prevtxnindex = txn_struct['inputs'][i]['prevtxnindex']
        preimage_b += bytes.fromhex(prevtxn)[::-1]
        preimage_b += struct.pack('<L', prevtxnindex)
        if i == inp_index:
            preimage_b += createVarInt(len(script_b))
            preimage_b += script_b
        else:
            preimage_b += b'\x00'
        if txn_struct['locktime'] > 0:
            # sequence
            preimage_b += bytes([0xfe, 0xff, 0xff, 0xff])
        else:
            # sequence
            preimage_b += bytes([0xff, 0xff, 0xff, 0xff])
    preimage_b += createVarInt(txn_struct['out_count'])
    for out in range(txn_struct['out_count']):
        satoshis = txn_struct['outputs'][out]['satoshis']
        preimage_b += struct.pack('<Q', satoshis)
        address = txn_struct['outputs'][out]['address']
        scriptPubkey_b = getScriptPubkeyFromAddress(address)
        preimage_b += createVarInt(len(scriptPubkey_b))
        preimage_b += scriptPubkey_b
    preimage_b += struct.pack('<L', txn_struct['locktime'])
    hashtype = txn_struct['inputs'][inp_index]['hash_type']
    preimage_b += struct.pack('<L', hashtype)
    return preimage_b

def signMessage(preimage_b: bytes, 
                privkey_wif: str, 
                hash_type: int):
    hash_preimage = hash256(preimage_b)
    privkey_s, network, compress = privkeyWif2Hex(privkey_wif)
    if privkey_s.__len__() % 2 == 1:
        privkey_s = "0{}".format(privkey_s)
    if compress == True:
        print('compress is true')
        privkey_b = bytes.fromhex(privkey_s)[:-1]
    else:
        privkey_b = bytes.fromhex(privkey_s)
    sk = SigningKey.from_string(privkey_b, curve=SECP256k1)
    sig_b = sk.sign_digest(hash_preimage, 
                    sigencode=sigencode_der_canonize) \
                + bytes([hash_type])
    return sig_b

def createSignedInput(txn_input: dict,
                        signgrp,
                        inp_index: int, 
                        script_b: bytes):
    prevtxn = txn_input['prevtxn']
    prevtx_rb = bytes.fromhex(prevtxn)[::-1]
    prevtxnindex = txn_input['prevtxnindex']
    sgntxnin_b = prevtx_rb + struct.pack('<L', prevtxnindex)
    if txn_input['script_type'] == 'P2SH':
        scriptSig_b = b'\x00'
        for sign_b in signgrp:
            scriptSig_b += encodePushdata(len(sign_b)) + sign_b
        scriptSig_b += encodePushdata(len(script_b)) + script_b
        sgntxnin_b += createVarInt(len(scriptSig_b)) + scriptSig_b
    elif inp['script_type'] == 'P2PKH':
        sign_b = signgrp # it's not a group.. just one signature
        scriptSig_b += encodePushdata(len(sign_b)) + sign_b
        scriptSig_b += encodePushdata(len(script_b)) + script_b
        sgntxnin_b += createVarInt(len(scriptSig_b)) + scriptSig_b
    return sgntxnin_b

def createSignedTransaction(txn_struct: dict, 
                            signgrp_l: list, 
                            script_l: list):
    sgntxn_b = b''
    sgntxn_b += struct.pack('<L', txn_struct['version'])
    sgntxn_b += createVarInt(txn_struct['input_count'])
    for i in range(txn_struct['input_count']):
        txn_input = txn_struct['inputs'][i]
        sgntxn_b += createSignedInput(txn_input, 
                                        signgrp_l[i], i, 
                                        script_l[i])
        if txn_struct['locktime'] > 0:
            # sequence
            sgntxn_b += bytes([0xfe, 0xff, 0xff, 0xff])
        else:
            sgntxn_b += bytes([0xff, 0xff, 0xff, 0xff])
    sgntxn_b += createVarInt(txn_struct['out_count'])
    for out in range(txn_struct['out_count']):
        satoshis = txn_struct['outputs'][out]['satoshis']
        sgntxn_b += struct.pack('<Q', satoshis)
        address = txn_struct['outputs'][out]['address']
        scriptPubkey_b = getScriptPubkeyFromAddress(address)
        sgntxn_b += createVarInt(len(scriptPubkey_b))
        sgntxn_b += scriptPubkey_b
    sgntxn_b += struct.pack('<L', txn_struct['locktime'])
    return sgntxn_b

def getExecutionScript(txn_struct: dict, inp_index: int):
    inp = txn_struct['inputs'][inp_index]
    script_type = inp['script_type']
    if script_type == 'P2SH':
        script_b = b'\x52'
        for pubkey in inp['pubkeys']:
            pubkey_b = bytes.fromhex(pubkey)
            script_b += encodePushdata(len(pubkey_b)) \
                     + pubkey_b
        script_b += b'\x53' + b'\xae'
    elif script_type == 'P2PKH':
        prevtxn = inp['prevtxn']
        prevtxnindex = inp['prevtxnindex']
        utxo = getUnspentTransactions(prevtxn, 
                                prevtxnindex, 
                                chainstate_db_g)
        pkh_b = bytes.fromhex(utxo['scriptdata'])
        pkhSize_b = encodePushdata(len(pkh_b))
        script_b = b'\x76' \
                + b'\xa9' \
                + pkhSize_b \
                + pkh_b \
                + b'\x88' \
                + b'\xac'
    return script_b

def getSignaturesAndExecScripts(txn_struct: dict):
    signgrp_l = []
    script_l = []
    for inp_index in range(txn_struct['input_count']):
        inp = txn_struct['inputs'][inp_index]
        script_b = getExecutionScript(txn_struct, inp_index)
        preimage_b = createSignaturePreimage(txn_struct, 
                                            script_b, 
                                            inp_index)
        inp = txn_struct['inputs'][inp_index]
        signgrp = []
        for privkey in inp['privkeys']:
            hashtype = inp['hash_type']
            sign_b = signMessage(preimage_b, privkey, hashtype)
            signgrp.append(sign_b)
        signgrp_l.append(signgrp)
        script_l.append(script_b)
    return signgrp_l, script_l

def createTransactionStruct():
    txn = {}
    txn['version'] = 1
    txn['input_count'] = 1
    txn['inputs'] = []
    input0 = {}
    input0['prevtxn'] = \
        'de32b06aeb0103381df84d2cc5ea80a35b60bce0c6393bd9436cb395e3f47a5d'
    input0['prevtxnindex'] = 0
    input0['script_type'] = 'P2SH'
    input0['privkeys'] = \
            ['L26JcHRhqEQv8V9DaAmE4bdszwqXS7tHznGYJPp7fxEoEQxxBPcQ', 
             'KxR8HHyfAwFPidCw2vXThXqT4vSMNeufirHFapnfCfkzLaohtujG']
    input0['pubkeys'] = \
        ['037fadaea6edf196bf70af16cefb2bd3c830e54c0a6e9a00bf7806b241933547f7', 
         '02fcb1c7507db15576ab35cd7c9b1ea570141a8b81c9938dae0320392b0f7034d0', 
         '02d50250aa629914e3146a5123a362a516c8aa95e5f0a6f3a078bd31fabe383abc']
    input0['hash_type'] = SIGHASH_ALL
    txn['inputs'].append(input0)
    txn['out_count'] = 2
    txn['outputs'] = []
    output0 = {}
    output0['satoshis'] = 10*(10**8)
    output0['script_type'] = 'P2PKH'
    output0['address'] = 'mxzmMmVycLDgAA48VtHDeh389eDAwiJqwQ'
    txn['outputs'].append(output0)
    output1 = {}
    output1['satoshis'] = 399999*(10**4)
    output1['script_type'] = 'P2PKH'
    output1['address'] = 'miSFmBeKXf5Wp7Luj46XTu3Yh57nAwhZAo'
    txn['outputs'].append(output1)
    txn['locktime'] = 0 # block height
    return txn

if __name__ == '__main__':
    txn_struct = createTransactionStruct()
    signgrp_l, script_l = getSignaturesAndExecScripts(txn_struct)
    signed_txn_b = createSignedTransaction(txn_struct, 
                                        signgrp_l, 
                                        script_l)
    print(signed_txn_b.hex())
