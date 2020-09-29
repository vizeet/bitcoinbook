import plyvel
import datetime
import os
import mmap

txindex_db_g = plyvel.DB(os.getenv('TX_INDEX_DB'), compression=None)

blocks_path_g = os.getenv('BLOCKS_PATH')

BLOCK_HAVE_DATA          =    8
BLOCK_HAVE_UNDO          =   16

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
    if prefix < 0xFD:
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

def getTransactionInfo(blk_m: mmap):
    tx = {}
    tx['version'] = blk_m.read(4)[::-1].hex()
    tx['inp_cnt'] = getVarInt(blk_m)
    inp_l = []
    for i in range(tx['inp_cnt']):
        inp = {}
        inp['prev_tx_hash'] = blk_m.read(32)[::-1].hex()
        inp['prev_tx_out_index'] = blk_m.read(4)[::-1].hex()
        inp['bytes_scriptsig'] = getVarInt(blk_m)
        inp['sriptsig'] = blk_m.read(inp['bytes_scriptsig']).hex()
        inp['sequence'] = blk_m.read(4)[::-1].hex()
        inp_l.append(inp)
    tx['inputs'] = inp_l
    tx['out_cnt'] = getVarInt(blk_m)
    out_l = []
    for i in range(tx['out_cnt']):
        out = {}
        sats_b = blk_m.read(8)
        print(sats_b.hex())
        out['satoshis'] = int.from_bytes(blk_m.read(8), byteorder='little')
        out['bytes_scriptpubkey'] = getVarInt(blk_m)
        out['scriptpubkey'] = blk_m.read(out['bytes_scriptpubkey']).hex()
        out_l.append(out)
    tx['outs'] = out_l
    tx['locktime'] = int.from_bytes(blk_m.read(4), byteorder='little')
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
tx_hash = bytes.fromhex('7301b595279ece985f0c415e420e425451fcf7f684fcce087ba14d10ffec1121')[::-1]
tx = findTransaction(tx_hash, txindex_db_g)
print(tx)
