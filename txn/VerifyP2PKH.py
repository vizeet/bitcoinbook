import mmap
import hashlib
import json
import plyvel
import copy
import os
import ecdsa
import struct

txindex_db_g = plyvel.DB(os.getenv('TX_INDEX_DB'), compression=None)
blocks_path_g = os.getenv('BLOCKS_PATH')

BLOCK_HEADER_SIZE = 80

def bytes2Mmap(b: bytes):
    m = mmap.mmap(-1, len(b) + 1)
    m.write(b)
    m.seek(0)
    return m

def hash160(secret: bytes):
    secrethash = hashlib.sha256(secret).digest()
    h = hashlib.new('ripemd160')
    h.update(secrethash)
    secret_hash160 = h.digest()
    return secret_hash160

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

def b128_varint_decode(b: bytes, pos = 0):
    n = 0
    while True:
        data = b[pos]
        pos += 1
        n = (n << 7) | (data & 0x7f)
        if data & 0x80 == 0:
            return (n, pos)
        n += 1

def getTransactionIndex(tx_hash: bytes, txindex_db):
    key = b't' + tx_hash
    value = txindex_db.get(key)
    jsonobj = {}
    jsonobj['n_file'], pos = b128_varint_decode(value)
    jsonobj['block_offset'], pos = b128_varint_decode(value, pos)
    jsonobj['file_offset'], pos = b128_varint_decode(value, pos)
    return jsonobj

def findTransaction(tx_hash: bytes, txindex_db):
    jsonobj = getTransactionIndex(tx_hash, txindex_db)
    block_filepath = os.path.join(blocks_path_g, 'blk%05d.dat' % jsonobj['n_file'])
    with open(block_filepath, 'r+b') as blk_f:
        blk_m = mmap.mmap(blk_f.fileno(), 0) # map whole file
        blk_m.seek(jsonobj['block_offset'] + BLOCK_HEADER_SIZE + jsonobj['file_offset'])
        sptr = blk_m.tell()
        blk_m.seek(sptr)
        tx = getTransactionInfo(blk_m)
        blk_m.close()
        return tx

def getScriptSig(tx_m: mmap, inp_index: int):
    version_b = tx_m.read(4) # version
    inp_cnt, inp_cnt_b = getVarInt(tx_m)
    for i in range(inp_cnt):
        tx_id_b = tx_m.read(32) # txid
        tx_index_b = tx_m.read(4) # tx index
        bytes_scriptsig, bytes_scriptsig_b = getVarInt(tx_m)
        scriptsig_b = tx_m.read(bytes_scriptsig)
        if i == inp_index:
            ret_scriptsig_b = scriptsig_b
        sequence_b = tx_m.read(4) #sequence
    return ret_scriptsig_b

SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80

def getPrevScriptPubKey(tx_m: mmap, inp_index: int):
    tx_m.read(4) # version
    inp_cnt, inp_cnt_b = getVarInt(tx_m)
    for i in range(inp_cnt):
        tx_rb = tx_m.read(32) # txid
        prevtx_outindex_b = tx_m.read(4)
        prevtx_outindex = int.from_bytes(prevtx_outindex_b, byteorder='little')
        bytes_scriptsig, bytes_scriptsig_b = getVarInt(tx_m)
        tx_m.read(bytes_scriptsig)
        if i == inp_index:
            prevtx = findTransaction(tx_rb, txindex_db_g)
            prevScriptPubkey = prevtx['outs'][prevtx_outindex]['scriptpubkey']
            prevScriptPubkey_b = bytes.fromhex(prevScriptPubkey)
        tx_m.read(4) # sequence
    out_cnt, out_cnt_b = getVarInt(tx_m)
    for i in range(out_cnt):
        tx_m.read(8) # value
        bytes_scriptpubkey, bytes_scriptpubkey_b = getVarInt(tx_m)
        tx_m.read(bytes_scriptpubkey) # scriptpubkey
    return prevScriptPubkey_b

def createMsgInputsForSig(tx_m: mmap, script_b: bytes, inp_index: int, sighash_type: int, inp_cnt: int):
    msg_b = b''
    for i in range(inp_cnt):
        tx_rb = tx_m.read(32) # txid
        inp_b = tx_rb
        prevtx_outindex_b = tx_m.read(4)
        prevtx_outindex = int.from_bytes(prevtx_outindex_b, byteorder='little')
        inp_b += prevtx_outindex_b
        bytes_scriptsig, bytes_scriptsig_b = getVarInt(tx_m)
        tx_m.read(bytes_scriptsig)
        if i == inp_index:
            inp_b += bytes.fromhex('%02x' % len(script_b))
            inp_b += script_b
            inp_b += tx_m.read(4) # sequence
        else:
            inp_b += bytes(1)
            if sighash_type & 0x03 == SIGHASH_ALL:
                inp_b += tx_m.read(4) # sequence
            else:
                tx_m.read(4) # sequence
                inp_b += bytes(4)
        if ((sighash_type & 0x80 == SIGHASH_ANYONECANPAY and i == inp_index)
            or (sighash_type & 0x80 != SIGHASH_ANYONECANPAY)) :
            msg_b += inp_b
    return msg_b

def createMsgOutsForSig(tx_m: mmap, inp_index: int, sighash_type: int):
    out_cnt, out_cnt_b = getVarInt(tx_m)
    msg_b = b''
    if sighash_type & 0x03 == SIGHASH_ALL:
        msg_b += out_cnt_b
        for i in range(out_cnt):
            msg_b += tx_m.read(8)
            bytes_scriptpubkey, bytes_scriptpubkey_b = getVarInt(tx_m)
            msg_b += bytes_scriptpubkey_b
            msg_b += tx_m.read(bytes_scriptpubkey) # scriptpubkey
    elif sighash_type & 0x03 == SIGHASH_SINGLE:
        msg_b += bytes.fromhex('%02x' % (inp_index + 1))
        for i in range(out_cnt):
            out_b = tx_m.read(8)
            bytes_scriptpubkey, bytes_scriptpubkey_b = getVarInt(tx_m)
            out_b += bytes_scriptpubkey_b
            out_b += tx_m.read(bytes_scriptpubkey) # scriptpubkey
            if i == inp_index:
                msg_b += out_b
                break
            else:
                msg_b += b'\xff'*8
                msg_b += b'\x00'
    else: # sighash_type & 0x02 == SIGHASH_NONE
        msg_b += b'\x00'
        for i in range(out_cnt):
            tx_m.read(8)
            bytes_scriptpubkey, bytes_scriptpubkey_b = getVarInt(tx_m)
            tx_m.read(bytes_scriptpubkey) # scriptpubkey
    return msg_b

def createMsgForSig(tx_m: mmap, script_b: bytes, inp_index: int, sighash_type: int):
    global txindex_db_g
    msg_b = tx_m.read(4) # version
    inp_cnt, inp_cnt_b = getVarInt(tx_m)
    if sighash_type & 0x80 == SIGHASH_ANYONECANPAY:
        msg_b += b'\x01'
    else:
        msg_b += inp_cnt_b
    msg_b += createMsgInputsForSig(tx_m, script_b, inp_index, sighash_type, inp_cnt)
    msg_b += createMsgOutsForSig(tx_m, inp_index, sighash_type)
    msg_b += tx_m.read(4) # locktime
    msg_b += struct.pack('<L', sighash_type)
    return msg_b

def getRandSFromSig(sig_b: bytes):
    sig_m = bytes2Mmap(sig_b)
    struct = sig_m.read(1)
    size = sig_m.read(1)
    rheader = sig_m.read(1)
    rsize_b = sig_m.read(1)
    rsize = int.from_bytes(rsize_b, byteorder='big')
    if rsize == 33:
        sig_m.read(1)
    r = sig_m.read(32)
    sheader = sig_m.read(1)
    ssize_b = sig_m.read(1)
    ssize = int.from_bytes(ssize_b, byteorder='big')
    if ssize == 33:
        sig_m.read(1)
    s = sig_m.read(32)
    return r + s

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

def getYFromX(x: int):
    y_sq = (pow(x, 3, p)  + 7) % p
    y = pow(y_sq, ((p+1) >> 2), p)
    return y

def getFullPubKeyFromCompressed(x_b: bytes):
    x = int.from_bytes(x_b[1:], byteorder='big')
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if y & 1 != x_b[0] & 1:
        y = p - y
    y = y.to_bytes(32, byteorder='big')
    return b'\x04' + x_b[1:] + y

def sigcheck(sig_b: bytes, pubkey_b: bytes, script_b: bytes, inp_index: int):
    sighash_type = sig_b[-1]
    tx_m.seek(0)
    msg_b = createMsgForSig(tx_m, script_b, inp_index, sighash_type)
    print('sig = %s' % sig_b.hex())
    print('pubkey = %s' % pubkey_b.hex())
    print('msg = %s' % msg_b.hex())
    msg_h = hashlib.sha256(msg_b).digest()

    prefix = pubkey_b[0:1]
    if prefix == b"\x02" or prefix == b"\x03":
        fullpubkey_b = getFullPubKeyFromCompressed(pubkey_b)[1:]
    elif prefix == b"\x04":
        fullpubkey_b = pubkey_b[1:]

    rs_b = getRandSFromSig(sig_b)
    print('rs = %s' % rs_b.hex())
    vk = ecdsa.VerifyingKey.from_string(fullpubkey_b, curve=ecdsa.SECP256k1)
    if vk.verify(rs_b, msg_h, hashlib.sha256) == True:
        print("Signature is Valid")
        return b'\x01'
    else:
        print("Signature is not Valid")
        return b'\x00'

st = []
def opHash160():
    v = st.pop()
    h = hash160(v)
    st.append(h)
    printStack()

def opDup():
    v = st.pop()
    st.append(v)
    st.append(v)
    printStack()

def opEqualVerify():
    v1 = st.pop()
    v2 = st.pop()
    printStack()
    if v1 == v2:
        return True
    else:
        return False

def opCheckSig(script_b: bytes, inp_index: int):
    global tx_b, st
    printStack()
    pubkey_b = st.pop()
    sig_b = st.pop()
    v = sigcheck(sig_b, pubkey_b, script_b, inp_index)
    st.append(v)

def pushdata(d: bytes):
    st.append(d)
    printStack()

g_pushdata = range(0x01, 0x4c) # excludes 0x4c

def printStack():
    e_l = []
    for e in st:
        e_l.append(e.hex())
    print(e_l)

def execScript(script_b: bytes, inp_index: int):
    l = len(script_b)
    script_m = bytes2Mmap(script_b)
    print('last ptr = %x' % l)
    while script_m.tell() < l:
        print('current ptr = %x' % script_m.tell())
        v = script_m.read(1)
        b = int.from_bytes(v, byteorder='big')
        print('b = %x' % b)
        if b in g_pushdata:
            d = script_m.read(b)
            pushdata(d)
        elif v == b'\x76':
            opDup()
        elif v == b'\xa9':
            opHash160()
        elif v == b'\x88':
            opEqualVerify()
        elif v == b'\xac':
            opCheckSig(script_b, inp_index)

def verifyScript(tx_m: mmap, inp_index: int):
    global st
    tx_m.seek(0)
    scriptsig_b = getScriptSig(tx_m, inp_index)
    execScript(scriptsig_b, inp_index)
    tx_m.seek(0)
    prev_scriptpubkey_b = getPrevScriptPubKey(tx_m, inp_index)
    execScript(prev_scriptpubkey_b, inp_index)
    status = st.pop()
    if status == b'\x01':
        print('Script succeeded')
    elif status == b'\x00':
        print('Script Failed')
    else:
        print('Invalid state')
    
def getHashTypeInWords(hashtype: int):
    hashtype_s = ""
    if hashtype & SIGHASH_SINGLE == 0x03:
        hashtype_s = "SIGHASH_SINGLE"
    elif hashtype & SIGHASH_NONE == 0x02:
        hashtype_s = "SIGHASH_NONE"
    elif hashtype & SIGHASH_ALL == 0x01:
        hashtype_s = "SIGHASH_ALL"
    if hashtype & SIGHASH_ANYONECANPAY == 0x80:
        hashtype_s = hashtype_s + "|" + "SIGHASH_ANYONECANPAY"
    return hashtype_s

OP_PUSHDATA1 = 0x4c
OP_PUSHDATA2 = 0x4d
OP_PUSHDATA4 = 0x4e

def decodePushdata(script_m: mmap):
    length = int.from_bytes(script_m.read(1), byteorder='little')
    if length == OP_PUSHDATA1:
        length = int.from_bytes(script_m.read(1), byteorder='little')
    elif length == OP_PUSHDATA2:
        length = int.from_bytes(script_m.read(2), byteorder='little')
    elif length == OP_PUSHDATA4:
        length = int.from_bytes(script_m.read(4), byteorder='little')
    return length

def parseScriptSig(script_m: mmap):
    scriptsig = {}
    scriptsig['bytes_sig'] = decodePushdata(script_m)
    scriptsig['sig'] = script_m.read(scriptsig['bytes_sig'] - 1).hex()
    scriptsig['hash_type'] = int.from_bytes(script_m.read(1), byteorder='big')
    scriptsig['hash_type_name'] = getHashTypeInWords(scriptsig['hash_type'])
    scriptsig['bytes_pubkey'] = decodePushdata(script_m)
    scriptsig['pubkey'] = script_m.read(scriptsig['bytes_pubkey']).hex()
    return scriptsig

def getTransactionInfo(tx_m: mmap):
    tx = {}
    tx['version'] = tx_m.read(4)[::-1].hex()
    tx['inp_cnt'], _ = getVarInt(tx_m)
    inp_l = []
    for i in range(tx['inp_cnt']):
        inp = {}
        inp['prev_tx_hash'] = tx_m.read(32)[::-1].hex()
        inp['prev_tx_out_index'] = int.from_bytes(tx_m.read(4), byteorder='little')
        inp['bytes_scriptsig'], _ = getVarInt(tx_m)
        inp['scriptsig'] = tx_m.read(inp['bytes_scriptsig']).hex()
        inp['sequence'] = tx_m.read(4)[::-1].hex()
        inp_l.append(inp)
    tx['inputs'] = inp_l
    tx['out_cnt'], _ = getVarInt(tx_m)
    out_l = []
    for i in range(tx['out_cnt']):
        out = {}
        out['satoshis'] = int.from_bytes(tx_m.read(8), byteorder='little')
        out['bytes_scriptpubkey'], _ = getVarInt(tx_m)
        out['scriptpubkey'] = tx_m.read(out['bytes_scriptpubkey']).hex()
        out_l.append(out)
    tx['outs'] = out_l
    tx['locktime'] = int.from_bytes(tx_m.read(4), byteorder='little')
    return tx

def getTransactionHash(start: int, end: int, tx_b: bytes):
    b = tx_b[start: end]
    h1 = hashlib.sha256(b).digest()
    h2 = hashlib.sha256(h1).digest()
    tx_hash = h2[::-1].hex()
    return tx_hash

tx_b = bytes.fromhex('010000000267d4447e428a846e2d667ed62850f83e444e2d2d771e0d075d47384822596aac010000006b483045022100856ecc275ea6f5f725ff544cfab1c4fe7edfadbdcf472c97be527330ee2377f002204433e38f3b3b9f0d61ba7484c04cb03dc074f9b99f4b574344485a8c9c9679c40121023aa63a2d865b3f82a12f2460165b02d249fe8ade2e3caf072a865bc571f8b611feffffffe675e3df015607bda31b588a4be919ff5accb3d6b904f38b733dd9bb5418d00c010000006a47304402206174721d66fb173da5f913c86ff0026bcabd70a0c8a69a96b2f7c5d65d53aff3022010109aa9d9c2bcdbaf2b40d0d3a5a80ad3b73ae51ea3013198eafc49943c0db5012103cdc126cd2676890d54545d05b578c2b894c892baf3ec6a405466a451626f010ffeffffff02eac1a804000000001976a91449f120df2e9bb6564fe731de22aaf4e1248102a188ac7b214c01000000001976a91446b6b235d8dab4976410cac6d54d1f4fd5796ad688ac751a0600')
tx_m = bytes2Mmap(tx_b)
#tx_m = mmap.mmap(-1, len(tx_b) + 1)
#tx_m.write(tx_b)
#tx_m.seek(0)
stb = tx_m.tell()
tx = getTransactionInfo(tx_m)
endb = tx_m.tell()
tx_hash = getTransactionHash(stb, endb, tx_b)
print('Transaction Hash = %s' % tx_hash)
print('Transaction = %s' % tx)

script_b = bytes.fromhex('47304402203a28d10c786907fcb71c7bf69c507d58884ea9af2e7fa3b413d4e2867eca601502205fb253d82e4daa2672842ec031584ea7a215774422aa7de3cf8928c240e2faa60121030be5aa6d5de8c6dd89d6ac4d0e2a112caf5b12801349ab30fbdf2b205f0b94b8')
script_m = mmap.mmap(-1, len(script_b) + 1)
script_m.write(script_b)
script_m.seek(0)
scriptsig = parseScriptSig(script_m)
print(json.dumps(scriptsig, indent=4))
tx_m.seek(0)
verifyScript(tx_m, 1)
