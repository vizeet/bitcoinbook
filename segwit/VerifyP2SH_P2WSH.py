import mmap
import hashlib
import json
import plyvel
import copy
import os
import ecdsa
import struct

#txindex_db_g = plyvel.DB(os.getenv('TESTNET_TX_INDEX_DB'), compression=None)
#blocks_path_g = os.getenv('TESTNET_BLOCKS_PATH')
txindex_db_g = plyvel.DB(os.getenv('TX_INDEX_DB'), compression=None)
blocks_path_g = os.getenv('BLOCKS_PATH')

BLOCK_HEADER_SIZE = 80

def hash256(bstr: bytes):
    return hashlib.sha256(hashlib.sha256(bstr).digest()).digest()

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

#def getVarInt(mptr: mmap):
#    b_cnt_d = {'fd': 2, 'fe': 4, 'ff': 8}
#    mptr_read = mptr.read(1)
#    size = int.from_bytes(mptr_read, byteorder='little')
#
#    if size < 0xfd:
#        return size, mptr_read
#    else:
#        b_cnt = b_cnt_d['%x' % size]
#        int_b = mptr.read(b_cnt)
#        size = int.from_bytes(int_b, byteorder='little')
#        return size, mptr_read + int_b

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

def getScriptSig(tx: dict, inp_index: int):
    return bytes.fromhex(tx['inputs'][inp_index]['scriptsig'])

SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80

def getPrevScriptPubKey(tx: dict, inp_index: int):
    prevtx_rb = bytes.fromhex(tx['inputs'][inp_index]['prev_tx_hash'])[::-1]
    prevtx_outindex = tx['inputs'][inp_index]['prev_tx_out_index']
    prevtx = findTransaction(prevtx_rb, txindex_db_g)
    prevScriptPubkey = prevtx['outs'][prevtx_outindex]['scriptpubkey']
    prevScriptPubkey_b = bytes.fromhex(prevScriptPubkey)
    return prevScriptPubkey_b

def createMsgInputsForSig(tx: dict, script_b: bytes, inp_index: int, sighash_type: int, inp_cnt: int):
    msg_b = b''
    for i in range(inp_cnt):
        tx_rb = tx_m.read(32) # txid
        inp = tx['inputs'][i]
        msg_b += bytes.fromhex(inp['prev_tx_hash'])[::-1]
        msg_b += struct.pack('<L', inp['prev_tx_out_index'])
        if i == inp_index:
            msg_b += setVarInt(len(script_b))
            msg_b += script_b
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

def createMsgOutsForSig(tx: dict, inp_index: int, sighash_type: int):
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
    tx_m.seek(0)
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

def getAmountFromPrevout(prev_tx_hash_b: bytes, prev_tx_out_index_b: bytes):
    prevtx = findTransaction(prev_tx_hash_b, txindex_db_g)
    prevtx_outindex = int.from_bytes(prev_tx_out_index_b, byteorder = 'little')
    prevAmount = prevtx['outs'][prevtx_outindex]['satoshis']
    amount_b = struct.pack("<Q", prevAmount)
    return amount_b

def setVarInt(n: int):
    if n < 0xfd:
        n_h = '%02x' % n
    elif n > 0xfd and n < 0xffff:
        n_h = 'fd%04x' % n
    elif n > 0xffff and n < 0xFFFFFFFF:
        n_h = 'fe%08x' % n
    else:
        n_h = 'ff%016x' % n
    return bytes.fromhex(n_h)

def createMsgForSigForSegwit(tx: dict, script_b: bytes, inp_index: int, sighash_type: int):
    version_b = bytes.fromhex(tx['version'])[::-1]
    inp_cnt = tx['inp_cnt']
    prevouts_b = b''
    sequences_b = b''
    for i in range(inp_cnt):
        tx_inp = tx['inputs'][i]
        prev_tx_hash_b = bytes.fromhex(tx_inp['prev_tx_hash'])[::-1]
        prev_tx_out_index_b = struct.pack('<L', tx_inp['prev_tx_out_index'])
        sequences_b += bytes.fromhex(tx_inp['sequence'])[::-1]
        prevouts_b += prev_tx_hash_b + prev_tx_out_index_b
        if i == inp_index:
            outpoint_b = prev_tx_hash_b + prev_tx_out_index_b
            print('script = ', script_b.hex())
            scriptCode_b = bytes.fromhex('%x' % len(script_b)) + script_b
            amount_b = getAmountFromPrevout(prev_tx_hash_b, prev_tx_out_index_b)
            sequence_b = bytes.fromhex(tx_inp['sequence'])[::-1]
    out_cnt = tx['out_cnt']
    outputs_b = b''
    for o in range(out_cnt):
        tx_out = tx['outs'][o]
        satoshis_b = struct.pack('<Q', tx_out['satoshis'])
        bytes_scriptpubkey_b = setVarInt(tx_out['bytes_scriptpubkey'])
        scriptpubkey_b = bytes.fromhex(tx_out['scriptpubkey'])
        outputs_b += satoshis_b + bytes_scriptpubkey_b + scriptpubkey_b
    locktime_b = struct.pack('<L', tx['locktime'])
    hashPrevouts_b = hash256(prevouts_b)
    hashSequence_b = hash256(sequences_b)
    hashOutputs_b = hash256(outputs_b)
    hashType_b = struct.pack('<L', sighash_type)
    msg_b = version_b + hashPrevouts_b + hashSequence_b + outpoint_b + scriptCode_b + amount_b + sequence_b + hashOutputs_b + locktime_b + hashType_b
#    print('version = ', version_b.hex())
#    print('prevouts = ', prevouts_b.hex())
#    print('sequences = ', sequences_b.hex())
#    print('outpoint = ', outpoint_b.hex())
#    print('scriptCode = ', scriptCode_b.hex())
#    print('amount = ', amount_b.hex())
#    print('sequence = ', sequence_b.hex())
#    print('outputs = ', outputs_b.hex())
#    print('locktime = ', locktime_b.hex())
#    print('sighash_type = ', sighash_type)
#    print('tx_s = ', tx_s)
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

def sigcheck(sig_b: bytes, pubkey_b: bytes, script_b: bytes, inp_index: int, tx: dict):
    sighash_type = sig_b[-1]
    tx_m.seek(0)
    if tx['is_segwit'] == True:
        msg_b = createMsgForSigForSegwit(tx, script_b, inp_index, sighash_type)
    else:
        msg_b = createMsgForSig(tx, script_b, inp_index, sighash_type)
    print('sig = %s' % sig_b.hex())
    print('pubkey = %s' % pubkey_b.hex())
    print('msg = %s' % msg_b.hex())
    msg_h = hashlib.sha256(msg_b).digest()
    print('msg_h = %s' % msg_h.hex())

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

def opSha256():
    v = st.pop()
    h = hashlib.sha256(v).digest()
    st.append(h)

def opDup():
    v = st.pop()
    st.append(v)
    st.append(v)

def opEqualVerify():
    v1 = st.pop()
    v2 = st.pop()
    if v1 == v2:
        return True
    else:
        return False

def opEqual():
    v1 = st.pop()
    v2 = st.pop()
    if v1 == v2:
        st.append(b'\x01')
    else:
        st.append(b'\x00')

def opNum(b: int):
    num = b - 0x50
    st.append(bytes([num]))

def opCheckSig(script_b: bytes, inp_index: int, tx: dict):
    global tx_b, st
    pubkey_b = st.pop()
    sig_b = st.pop()
    v = sigcheck(sig_b, pubkey_b, script_b, inp_index, tx)
    st.append(v)

def opCheckMultisig(script_b: bytes, inp_index: int, is_segwit: bool):
    global tx_b
    pubkey_cnt = int.from_bytes(st.pop(), byteorder='big')
    pubkey_l = [st.pop() for i in range(pubkey_cnt)][::-1]
    sig_cnt = int.from_bytes(st.pop(), byteorder='big')
    sig_l = [st.pop() for i in range(sig_cnt)][::-1]
    sig_index = 0
    for pubkey_b in pubkey_l:
        v = sigcheck(sig_l[sig_index], pubkey_b, script_b, inp_index, tx)
        if v == b'\x01':
            sig_index += 1
            if sig_index == sig_cnt:
                break
    # convert True/False to b'\x01' or b'\x00'
    b = bytes([int(sig_index == sig_cnt and v == b'\x01')])
    st.append(b)

def pushdata(d: bytes):
    st.append(d)

g_pushdata = range(0x01, 0x4c) # excludes 0x4c
g_pushnumber = range(0x51, 0x61) # excludes 0x61

def printStack():
    e_l = []
    for e in st:
        e_l.append(e.hex())
    print(e_l)

def execScript(script_b: bytes, inp_index: int, tx: dict):
    l = len(script_b)
    script_m = bytes2Mmap(script_b)
    while script_m.tell() < l:
        v = script_m.read(1)
        b = int.from_bytes(v, byteorder='big')
        if b in g_pushdata:
            d = script_m.read(b)
            pushdata(d)
        elif v == b'\x76':
            opDup()
        elif v == b'\xa8': 
            opSha256()
        elif v == b'\xa9':
            opHash160()
        elif b in g_pushnumber:
            opNum(b)
        elif v == b'\x87':
            opEqual()
        elif v == b'\x88':
            opEqualVerify()
        elif v == b'\xac':
            opCheckSig(script_b, inp_index, tx)
        elif v == b'\xae':
            opCheckMultisig(script_b, inp_index, tx)

def checkWrappedMultisig(st):
    script_b = st[-1]
    val = script_b[-2]
    if bytes([script_b[-1]]) == b'\xae' and val in g_pushnumber:
        return True
    else:
        return False

def checkWrappedP2WPKH(st):
    script_b = st[-1]
    if script_b[:2] == b'\x00\x14' and len(script_b) == 22:
        return True
    else:
        return False

def checkWrappedP2WSH(st):
    script_b = st[-1]
    if script_b[:2] == b'\x00\x20' and len(script_b) == 34:
        return True
    else:
        return False

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
    startloc = tx_m.tell()
    tx['version'] = tx_m.read(4)[::-1].hex()
    tx['inp_cnt'], _ = getVarInt(tx_m)
    tx['is_segwit'] = False
    if tx['inp_cnt'] == 0:
        # check segwit flag
        tx['is_segwit'] = (int.from_bytes(tx_m.read(1), byteorder='little') == 1)
        if tx['is_segwit'] == True:
            tx['inp_cnt'], _ = getVarInt(tx_m)
    inp_l = []
    for i in range(tx['inp_cnt']):
        inp = {}
        inp['prev_tx_hash'] = tx_m.read(32)[::-1].hex()
        inp['prev_tx_out_index'] = int.from_bytes(tx_m.read(4), byteorder = 'little')
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
    curloc = tx_m.tell()
    tx_m.seek(startloc)
    txid_b = tx_m.read(curloc - startloc)
    if tx['is_segwit'] == True:
        # if segflag is true than remove segwit marker and flag from txhash calculation
        txid_b = txid_b[:4] + txid_b[6:]
        for i in range(tx['inp_cnt']):
            tx['inputs'][i]['witness_cnt'], _ = getVarInt(tx_m)
            witness_l = []
            witness_cnt = tx['inputs'][i]['witness_cnt']
            for j in range(witness_cnt):
                witness = {}
                witness['size'], _ = getVarInt(tx_m)
                witness['witness'] = tx_m.read(witness['size']).hex()
                witness_l.append(witness)
            tx['inputs'][i]['witnesses'] = witness_l
    locktime_b = tx_m.read(4)
    txid_b += locktime_b
    tx['locktime'] = int.from_bytes(locktime_b, byteorder='little')
    tx['txid'] = hash256(txid_b)[::-1].hex()
    return tx

def pushWitnessData(witness_l: list):
    for data in witness_l:
        if data['size'] != 0:
            st.append(bytes.fromhex(data['witness']))

def getWitnessList(tx_m: mmap, inp_index: int):
    return tx['inputs'][inp_index]['witnesses']

def isP2WPKH(prev_scriptpubkey_b: bytes):
    #0014<20 bytes>
    if len(prev_scriptpubkey_b) == 22 and prev_scriptpubkey_b[0:2] == b'\x00\x14':
        return True
    return False

def isP2WSH(prev_scriptpubkey_b: bytes):
    #0020<32 bytes>
    if len(prev_scriptpubkey_b) == 34 and prev_scriptpubkey_b[0:2] == b'\x00\x20':
        return True
    return False

def verifyScript(tx: dict, inp_index: int):
    global st
    scriptsig_b = getScriptSig(tx, inp_index)
    if scriptsig_b == b'':
        # native segwit
        print('native segwit')
        witness_l = getWitnessList(tx, inp_index)
        pushWitnessData(witness_l)
    else:
        execScript(scriptsig_b, inp_index, tx)
    prev_scriptpubkey_b = getPrevScriptPubKey(tx, inp_index)
    isP2SH = False
    if checkWrappedP2WPKH(st) == True:
        prev_scriptpubkey_b = st[-1]
        st.pop()
        witness_l = getWitnessList(tx, inp_index)
        pushWitnessData(witness_l)
        print('P2SH_P2WPKH')
    if checkWrappedP2WSH(st) == True:
        prev_scriptpubkey_b = st[-1]
        st.pop()
        witness_l = getWitnessList(tx, inp_index)
        pushWitnessData(witness_l)
        print('P2SH_P2WSH')
    if checkWrappedMultisig(st) == True:
        redeemscript_b = st[-1]
        isP2SH = True
        print('P2SH')
    if isP2WPKH(prev_scriptpubkey_b) == True:
        print('P2WPKH')
        prev_scriptpubkey_b = bytes([0x76, 0xa9, 0x14]) + prev_scriptpubkey_b[2:] + bytes([0x88, 0xac])
    if isP2WSH(prev_scriptpubkey_b) == True:
        print('P2WSH')
        prev_scriptpubkey_b = bytes([0xa8, 0x20]) + prev_scriptpubkey_b[2:] + bytes([0x87])
    print('previous scriptpubkey = ', prev_scriptpubkey_b.hex())
    execScript(prev_scriptpubkey_b, inp_index, tx)
    status = st.pop()
    if status == b'\x01':
        print('1st Script succeeded')
    elif status == b'\x01':
        print('1st Script Failed')
        return
    else:
        print('1st Invalid state')
        return
    if isP2SH == True:
        execScript(redeemscript_b, inp_index, tx)
        status = st.pop()
        if status == b'\x01':
            print('2nd Script succeeded')
        elif status == b'\x01':
            print('2nd Script Failed')
        else:
            print('2nd Invalid state')


#txid :: c6ab739d8455cd5133e9f93f542f70a2ccef0c7fb05de998db817dd680af3a91
tx_s = '010000000001024e453d886f11e3af494ce6073956b0de6eaed80865529ab45f778d660459907e2500000023220020ffc74359d1e79a79b94319a1695a68810e439e4c32e4c1be2b0b7c915ca78536ffffffff4e453d886f11e3af494ce6073956b0de6eaed80865529ab45f778d660459907e29000000232200207a21661b84ac4a34a6afc034030faba8ce8344635ebaf34cde31083f186bf871ffffffff02b02a02000000000017a9147b60c1eebfc2c78c9993668dab556344bf1f78d187d9df0500000000002200206f50cccbc64ea3f6cc434d5878bbe45a609e5592026ce6704f586a0e795a6ae40300483045022100d168fa78728fda205eee72ad7b789bc3153adeec982b2588a1526509aa1e2ae8022010443c0652848492dad4904f45258f5452256bfe23d9c715bf052d908154de6e0125512102972c9ea94bfcd5956220f2e99776b3c5ebcca9373a2eccb3fb5fff8bbc9f999451ae03004830450221009691361fa2953e54bc5287306c023fc2d098aa6e85ed1a66d3369e93781260b102201fb639437128d361a12ea385a61bd49247d25c254d1efc03d5272dd368c0acfa01255121027c6cbed24ad235fe147413272ba92cfd61d5ab338c4dabd74cbfb7d11746da5451ae00000000' 
tx_b = bytes.fromhex(tx_s)
tx_m = bytes2Mmap(tx_b)
tx = getTransactionInfo(tx_m)
verifyScript(tx, 0)

