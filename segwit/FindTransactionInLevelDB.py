import plyvel
import datetime
import os
import mmap
import hashlib

txindex_db_g = plyvel.DB(os.getenv('TX_INDEX_DB'), compression=None)

blocks_path_g = os.getenv('BLOCKS_PATH')

BLOCK_HAVE_DATA          =    8
BLOCK_HAVE_UNDO          =   16

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

def getVarInt(blk_m: mmap):
    b_cnt_d = {'fd': 2, 'fe': 4, 'ff': 8}
    prefix = int.from_bytes(blk_m.read(1), byteorder='little')
    if prefix < 0xfd:
        return prefix
    else:
        b_cnt = b_cnt_d['%x' % prefix]
        size = int.from_bytes(blk_m.read(b_cnt), byteorder='little')
        return size

def getTransactionIndex(tx_hash: bytes, txindex_db):
    key = b't' + tx_hash
    value = txindex_db.get(key)
    jsonobj = {}
    jsonobj['n_file'], pos = b128_varint_decode(value)
    jsonobj['block_offset'], pos = b128_varint_decode(value, pos)
    jsonobj['file_offset'], pos = b128_varint_decode(value, pos)
    print(jsonobj)
    return jsonobj

def getTransactionInfo(txn_m):
    tx = {}
    startloc = txn_m.tell()
    tx['version'] = txn_m.read(4)[::-1].hex()
    tx['inp_cnt'] = getVarInt(txn_m)
    tx['is_segwit'] = False
    if tx['inp_cnt'] == 0:
        # check segwit flag
        tx['is_segwit'] = (int.from_bytes(txn_m.read(1), byteorder='little') == 1)
        if tx['is_segwit'] == True:
            tx['inp_cnt'] = getVarInt(txn_m)
    inp_l = []
    for i in range(tx['inp_cnt']):
        inp = {}
        inp['prev_tx_hash'] = txn_m.read(32)[::-1].hex()
        inp['prev_tx_out_index'] = int.from_bytes(txn_m.read(4), byteorder='little')
        inp['bytes_scriptsig'] = getVarInt(txn_m)
        inp['scriptsig'] = txn_m.read(inp['bytes_scriptsig']).hex()
        inp['sequence'] = txn_m.read(4)[::-1].hex()
        inp_l.append(inp)
    tx['inputs'] = inp_l
    tx['out_cnt'] = getVarInt(txn_m)
    out_l = []
    for i in range(tx['out_cnt']):
        out = {}
        out['satoshis'] = int.from_bytes(txn_m.read(8), byteorder='little')
        out['bytes_scriptpubkey'] = getVarInt(txn_m)
        out['scriptpubkey'] = txn_m.read(out['bytes_scriptpubkey']).hex()
        out_l.append(out)
    tx['outs'] = out_l
    curloc = txn_m.tell()
    txn_m.seek(startloc)
    txid_b = txn_m.read(curloc - startloc)
    if tx['is_segwit'] == True:
        # if segflag is true than remove segwit marker and flag from txhash calculation
        txid_b = txid_b[:4] + txid_b[6:]
        for i in range(tx['inp_cnt']):
            tx['inputs'][i]['witness_cnt'] = getVarInt(txn_m)
            witness_l = []
            witness_cnt = tx['inputs'][i]['witness_cnt']
            for j in range(witness_cnt):
                witness = {}
                witness['size'] = getVarInt(txn_m)
                witness['witness'] = txn_m.read(witness['size']).hex()
                witness_l.append(witness)
            tx['inputs'][i]['witnesses'] = witness_l
    locktime_b = txn_m.read(4)
    txid_b += locktime_b
    tx['locktime'] = int.from_bytes(locktime_b, byteorder='little')
    tx['txid'] = hash256(txid_b)[::-1].hex()
    curloc = txn_m.tell()
    txn_m.seek(startloc)
    wtxid_b = txn_m.read(curloc - startloc)
    tx['wtxid'] = hash256(wtxid_b)[::-1].hex()
    return tx

BLOCK_HEADER_SIZE = 80

def findTransaction(tx_hash: bytes, txindex_db):
    jsonobj = getTransactionIndex(tx_hash, txindex_db)
    block_filepath = os.path.join(blocks_path_g, 'blk%05d.dat' % jsonobj['n_file'])
    with open(block_filepath, 'r+b') as blk_f:
        blk_m = mmap.mmap(blk_f.fileno(), 0) # map whole file
        blk_m.seek(jsonobj['block_offset'] + BLOCK_HEADER_SIZE + jsonobj['file_offset'])
        tx = getTransactionInfo(blk_m)
        blk_m.close()
        return tx

#tx_hash = bytes.fromhex('a23203c053852755c97b87e354d1e9053a6d1a20d32892e8ee45dfa2c3105f94')[::-1]
tx_hash = bytes.fromhex('3962d98048dc2a5f4551b2719a55adb68715d9bb2a1f564e26d8699be743e5af')[::-1]
tx = findTransaction(tx_hash, txindex_db_g)
print(tx['inp_cnt'])
