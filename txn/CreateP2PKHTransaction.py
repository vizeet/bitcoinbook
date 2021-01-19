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

txindex_db_g = plyvel.DB(os.getenv('REGTEST_TX_INDEX_DB'), compression=None)
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

def getTransactionIndex(tx_hash: bytes, txindex_db):
    key = b't' + tx_hash
    value = txindex_db.get(key)
    jsonobj = {}
    jsonobj['n_file'], pos = b128_varint_decode(value)
    jsonobj['block_offset'], pos = b128_varint_decode(value, pos)
    jsonobj['file_offset'], pos = b128_varint_decode(value, pos)
    return jsonobj

def getTransactionInfo(payload_m: mmap):
    payload = {}
    pread = payload_m.read(4)
    raw_tx = pread
    payload['version'] = int.from_bytes(pread, byteorder='little')
    pstart = payload_m.tell()
    payload['tx_in count'], _ = getVarInt(payload_m)
    if payload['tx_in count'] == 0:
        # check if segwit
        payload['is_segwit'] = bool(int.from_bytes(payload_m.read(1), byteorder='little'))
        if payload['is_segwit'] == True:
                pstart = payload_m.tell()
                payload['tx_in count'], _ = getVarInt(payload_m)
    payload['tx_in'] = []
    for i in range(payload['tx_in count']):
        txin = {}
        txin['prev_tx_hash'] = payload_m.read(32)[::-1].hex()
        txin['prev_tx_out_index'] = int.from_bytes(payload_m.read(4), byteorder='little')
        txin['bytes_scriptsig'], _ = getVarInt(payload_m)
        txin['sriptsig'] = payload_m.read(txin['bytes_scriptsig']).hex()
        txin['sequence'] = payload_m.read(4)[::-1].hex()
        payload['tx_in'].append(txin)
    payload['tx_out count'], _ = getVarInt(payload_m)
    payload['tx_out'] = []
    for i in range(payload['tx_out count']):
        txout = {}
        txout['satoshis'] = int.from_bytes(payload_m.read(8), byteorder='little')
        txout['bytes_scriptpubkey'], _ = getVarInt(payload_m)
        txout['scriptpubkey'] = payload_m.read(txout['bytes_scriptpubkey']).hex()
        payload['tx_out'].append(txout)
    pend = payload_m.tell()
    payload_m.seek(pstart)
    raw_tx += payload_m.read(pend - pstart)
    if 'is_segwit' in payload and payload['is_segwit'] == True:
        for i in range(payload['tx_in count']):
            payload['tx_in'][i]['witness_count'], _ = getVarInt(payload_m)
            payload['tx_in'][i]['witness'] = []
            for j in range(payload['tx_in'][i]['witness_count']):
                tx_witness = {}
                tx_witness['size'], _ = getVarInt(payload_m)
                tx_witness['witness'] = payload_m.read(tx_witness['size']).hex()
                payload['tx_in'][i]['witness'].append(tx_witness)
    pread = payload_m.read(4)
    raw_tx += pread
    payload['locktime'] = int.from_bytes(pread, byteorder='little')
#    payload['txid'] = hashlib.sha256(hashlib.sha256(raw_tx).digest()).digest()[::-1].hex()
    payload['txid'] = hash256(raw_tx)[::-1].hex()
    return payload

def findTransaction(tx_hash: bytes, txindex_db):
    jsonobj = getTransactionIndex(tx_hash, txindex_db)
    block_filepath = os.path.join(blocks_path_g, 
                                'blk%05d.dat' % jsonobj['n_file'])
    with open(block_filepath, 'r+b') as blk_f:
        blk_m = mmap.mmap(blk_f.fileno(), 0) # map whole file
        location = jsonobj['block_offset'] \
                    + BLOCK_HEADER_SIZE \
                    + jsonobj['file_offset']
        blk_m.seek(location)
        sptr = blk_m.tell()
        blk_m.seek(sptr)
        b = blk_m.read(200)
        blk_m.seek(sptr)
        tx = getTransactionInfo(blk_m)
        blk_m.close()
        return tx

def createVarInt(i: int):
    if i < 0xfd:
        return bytes([i])
    elif i < 0xffff:
        return b'\xfd' + struct.pack('<H', i)
    elif i < 0xffffffff:
        return b'\xfe' + struct.pack('<L', i)
    elif i < 0xffffffffffffffff:
        return b'\xff' + struct.pack('<Q', i)

def getVarInt(mptr: mmap):
    b_cnt_d = {'fd': 2, 'fe': 4, 'ff': 8}
    mptr_read = mptr.read(1)
    size = int.from_bytes(mptr_read, byteorder='little')

    if size < 0xfd:
        return size, mptr_read
    else:
        b_cnt = b_cnt_d['%x' % size]
        int_b = mptr.read(b_cnt)
        size = int.from_bytes(int_b, byteorder='little')
        return size, mptr_read + int_b

def createSignaturePreimage(txn_struct: dict, inp_index: int):
    preimage_b = b''
    preimage_b += struct.pack('<L', txn_struct['version'])
    preimage_b += createVarInt(txn_struct['input_count'])
    for i in range(txn_struct['input_count']):
        prevtxn = txn_struct['inputs'][i]['prevtxn']
        prevtxnindex = txn_struct['inputs'][i]['prevtxnindex']
        preimage_b += bytes.fromhex(prevtxn)[::-1]
        preimage_b += struct.pack('<L', prevtxnindex)
        if i == inp_index:
            prevtx_rb = bytes.fromhex(prevtxn)[::-1]
            prevtx = findTransaction(prevtx_rb, txindex_db_g)
            prevScriptPubkey = \
                    prevtx['tx_out'][prevtxnindex]['scriptpubkey']
            prevScriptPubkey_b = bytes.fromhex(prevScriptPubkey)
            preimage_b += createVarInt(len(prevScriptPubkey_b))
            preimage_b += prevScriptPubkey_b
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
        pkh_b = address2PubkeyHash(address)
        pkhSize_b = createVarInt(len(pkh_b))
        scriptPubkey_b = b'\x76' \
                        + b'\xa9' \
                        + pkhSize_b \
                        + pkh_b \
                        + b'\x88' \
                        + b'\xac'
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
        privkey_b = bytes.fromhex(privkey_s)[:-1]
    else:
        privkey_b = bytes.fromhex(privkey_s)
    sk = SigningKey.from_string(privkey_b, curve=SECP256k1)
    sig_b = sk.sign_digest(hash_preimage, 
                            sigencode=sigencode_der_canonize) \
                + bytes([hash_type])
    return sig_b

def createSignedTransaction(txn_struct: dict, sign_l: list):
    sgntxn_b = b''
    sgntxn_b += struct.pack('<L', txn_struct['version'])
    sgntxn_b += createVarInt(txn_struct['input_count'])
    for i in range(txn_struct['input_count']):
        prevtxn = txn_struct['inputs'][i]['prevtxn']
        prevtx_rb = bytes.fromhex(prevtxn)[::-1]
        prevtxnindex = txn_struct['inputs'][i]['prevtxnindex']
        sgntxn_b += prevtx_rb + struct.pack('<L', prevtxnindex)
        prevtx = findTransaction(prevtx_rb, txindex_db_g)
        sign_b = sign_l[i]
        signSize_b = createVarInt(len(sign_l[i]))
        pubkey = txn_struct['inputs'][i]['privkeys'][0]
        pubkey_b = privkeyWif2pubkey(privkey)
        pubkeySize_b = createVarInt(len(pubkey_b))
        # In P2PKH script ScriptSig is signature + pubkey
        scriptSig_b = signSize_b \
                        + sign_b \
                        + pubkeySize_b \
                        + pubkey_b
        scriptSigSize_b = createVarInt(len(scriptSig_b))
        sgntxn_b += scriptSigSize_b + scriptSig_b
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
        pkh_b = address2PubkeyHash(address)
        pkhSize_b = createVarInt(len(pkh_b))
        scriptPubkey_b = b'\x76' \
                        + b'\xa9' \
                        + pkhSize_b \
                        + pkh_b \
                        + b'\x88' \
                        + b'\xac'
        sgntxn_b += createVarInt(len(scriptPubkey_b))
        sgntxn_b += scriptPubkey_b
    sgntxn_b += struct.pack('<L', txn_struct['locktime'])
    return sgntxn_b

def createTransactionStruct():
    txn = {}
    txn['version'] = 1
    txn['input_count'] = 2
    txn['inputs'] = []
    input0 = {}
    input0['prevtxn'] = '5efcf04e32f061b9c4894f5b3a59fb3d8c5c56a6e7340b89b3a1a9ebacca998f'
    input0['prevtxnindex'] = 0
    input0['script_type'] = 'P2PKH'
    input0['privkeys'] = ['KwfxnwxpPG1RmhU8jaU8Ron4m1KZGymLAFNaMnSTonoZ7AQfnV53']
    input0['hash_type'] = SIGHASH_ALL
    txn['inputs'].append(input0)
    input1 = {}
    input1['prevtxn'] = '53793974d074e57305575d711fd0acd1d39f406264de234e686542ad2d0ddbfb'
    input1['prevtxnindex'] = 0
    input1['script_type'] = 'P2PKH'
    input1['privkeys'] = ['KwfxnwxpPG1RmhU8jaU8Ron4m1KZGymLAFNaMnSTonoZ7AQfnV53']
    input1['hash_type'] = SIGHASH_ALL
    txn['inputs'].append(input1)
    txn['out_count'] = 2
    txn['outputs'] = []
    output0 = {}
    output0['satoshis'] = 40*(10**8)
    output0['script_type'] = 'P2PKH'
    output0['address'] = 'mxzmMmVycLDgAA48VtHDeh389eDAwiJqwQ'
    txn['outputs'].append(output0)
    output1 = {}
    output1['satoshis'] = 599999*(10**4)
    output1['script_type'] = 'P2PKH'
    output1['address'] = 'miSFmBeKXf5Wp7Luj46XTu3Yh57nAwhZAo'
    txn['outputs'].append(output1)
    txn['locktime'] = 110 # block height
    return txn

if __name__ == '__main__':
    txn_struct = createTransactionStruct()
    sign_l = []
    for inp in range(txn_struct['input_count']):
        preimage_b = createSignaturePreimage(txn_struct, inp)
        privkey = txn_struct['inputs'][inp]['privkeys'][0]
        hashtype = txn_struct['inputs'][inp]['hash_type']
        sign_b = signMessage(preimage_b, privkey, hashtype)
        sign_l.append(sign_b)
    signed_txn_b = createSignedTransaction(txn_struct, sign_l)
    print(signed_txn_b.hex())
