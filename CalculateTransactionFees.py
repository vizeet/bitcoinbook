import hashlib
import mmap
import plyvel
import datetime
import os

block_db_g = plyvel.DB(os.getenv('BLOCK_INDEX_DB'), compression=None)
txindex_db_g = plyvel.DB(os.getenv('TX_INDEX_DB'), compression=None)

blocks_path_g = os.getenv('BLOCKS_PATH')

BLOCK_HAVE_DATA          =    8
BLOCK_HAVE_UNDO          =   16
BLOCK_HEADER_SIZE        =   80

def b128_varint_decode(b: bytes, pos = 0):
    n = 0
    while True:
        data = b[pos]
        pos += 1
        n = (n << 7) | (data & 0x7f) 
        if data & 0x80 == 0:
            return (n, pos)
        n += 1

def getBlockIndex(block_hash: bytes, block_db):
    key = b'b' + block_hash
    value = block_db.get(key)
    jsonobj = {}
    jsonobj['version'], pos = b128_varint_decode(value)
    jsonobj['height'], pos = b128_varint_decode(value, pos)
    jsonobj['status'], pos = b128_varint_decode(value, pos)
    jsonobj['tx_count'], pos = b128_varint_decode(value, pos)
    if jsonobj['status'] & (BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO):
            jsonobj['n_file'], pos = b128_varint_decode(value, pos)
    if jsonobj['status'] & BLOCK_HAVE_DATA:
            jsonobj['data_pos'], pos = b128_varint_decode(value, pos)
    if jsonobj['status'] & BLOCK_HAVE_UNDO:
            jsonobj['undo_pos'], pos = b128_varint_decode(value, pos)
    return jsonobj

def getVarInt(blk_m: mmap):
    b_cnt_d = {'fd': 2, 'fe': 4, 'ff': 8}
    prefix = int.from_bytes(blk_m.read(1), byteorder='little')
    if prefix < 0xFD:
        return prefix
    else:
        b_cnt = b_cnt_d['%x' % prefix]
        size = int.from_bytes(blk_m.read(b_cnt), byteorder='little')
        return size

def getCoinbaseTransactionInfo(blk_m: mmap):
    tx = {}
    tx['version'] = blk_m.read(4)[::-1].hex()
    tx['inp_cnt'] = getVarInt(blk_m)
    inp_l = []
    for i in range(tx['inp_cnt']):
        inp = {}
        inp['prev_tx_hash'] = blk_m.read(32)[::-1].hex()
        inp['prev_tx_out_index'] = int.from_bytes(blk_m.read(4), byteorder='little')
        inp['bytes_coinbase_data'] = getVarInt(blk_m)
        pos = blk_m.tell()
        inp['bytes_height'] = getVarInt(blk_m)
        inp['height'] = int.from_bytes(blk_m.read(inp['bytes_height']), byteorder='little')
        size = blk_m.tell() - pos
        coinbase_arb_data_size = inp['bytes_coinbase_data'] - size
        inp['coinbase_arb_data'] = blk_m.read(coinbase_arb_data_size).hex()
        inp['sequence'] = blk_m.read(4)[::-1].hex()
        inp_l.append(inp)
    tx['inputs'] = inp_l
    tx['out_cnt'] = getVarInt(blk_m)
    out_l = []
    for i in range(tx['out_cnt']):
        out = {}
        out['satoshis'] = int.from_bytes(blk_m.read(8), byteorder='little')
        out['bytes_scriptpubkey'] = getVarInt(blk_m)
        out['scriptpubkey'] = blk_m.read(out['bytes_scriptpubkey']).hex()
        out_l.append(out)
    tx['outs'] = out_l
    tx['locktime'] = int.from_bytes(blk_m.read(4), byteorder='little')
    return tx

def getTransactionInfo(blk_m: mmap):
    tx = {}
    tx['version'] = blk_m.read(4)[::-1].hex()
    tx['inp_cnt'] = getVarInt(blk_m)
    inp_l = []
    for i in range(tx['inp_cnt']):
        inp = {}
        inp['prev_tx_hash'] = blk_m.read(32)[::-1].hex()
        inp['prev_tx_out_index'] = int.from_bytes(blk_m.read(4), byteorder='little')
        inp['bytes_scriptsig'] = getVarInt(blk_m)
        inp['sriptsig'] = blk_m.read(inp['bytes_scriptsig']).hex()
        inp['sequence'] = blk_m.read(4)[::-1].hex()
        inp_l.append(inp)
    tx['inputs'] = inp_l
    tx['out_cnt'] = getVarInt(blk_m)
    out_l = []
    for i in range(tx['out_cnt']):
        out = {}
        out['satoshis'] = int.from_bytes(blk_m.read(8), byteorder='little')
        out['bytes_scriptpubkey'] = getVarInt(blk_m)
        out['scriptpubkey'] = blk_m.read(out['bytes_scriptpubkey']).hex()
        out_l.append(out)
    tx['outs'] = out_l
    tx['locktime'] = int.from_bytes(blk_m.read(4), byteorder='little')
    return tx

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
        tx = getTransactionInfo(blk_m)
        return tx

def getTransactionOutAmount(tx_hash: bytes, out_index: int, txindex_db):
    tx = findTransaction(tx_hash, txindex_db)
    return tx['outs'][out_index]['satoshis']

def getTransactionFee(tx: dict):
    global txindex_db_g
    inp_val = 0
    for inp in tx['inputs']:
        prev_tx_hash = bytes.fromhex(inp['prev_tx_hash'])[::-1]
        inp_val += getTransactionOutAmount(prev_tx_hash, inp['prev_tx_out_index'], txindex_db_g)
    out_val = 0
    for out in tx['outs']:
        out_val += out['satoshis']
    tx_fee = inp_val - out_val
    return tx_fee

def getTransactionCount(blk_m: mmap):
    tx_cnt = getVarInt(blk_m)
    return tx_cnt

def getTransactionId(start: int, end: int, blk_m: mmap):
    blk_m.seek(start)
    b = blk_m.read(end - start)
    h1 = hashlib.sha256(b).digest()
    h2 = hashlib.sha256(h1).digest()
    hash_s = h2[::-1].hex()
    return hash_s

def getBlockFeeReward(block_hash: bytes, block_db):
    block_index = getBlockIndex(block_hash, block_db)
    if 'data_pos' in block_index:
        block_filepath = os.path.join(blocks_path_g, 'blk%05d.dat' % block_index['n_file'])
        start = block_index['data_pos']
    elif 'undo_pos' in block_index:
        block_filepath = os.path.join(blocks_path_g, 'rev%05d.dat' % block_index['n_file'])
        start = block_index['undo_pos']

    with open(block_filepath, 'r+b') as block_f:
        blk_m = mmap.mmap(block_f.fileno(), 0)
        blk_m.seek(start + BLOCK_HEADER_SIZE)
        tx_cnt = getVarInt(blk_m)
        print(tx_cnt)
        coinbase_tx = getCoinbaseTransactionInfo(blk_m)
        print(coinbase_tx)
        fee_reward = 0
        for i in range(1, tx_cnt):
            print(i)
            start = blk_m.tell()
            tx = getTransactionInfo(blk_m)
            end = blk_m.tell()
            tx_fee = getTransactionFee(tx)
            print(tx_fee)
            fee_reward += tx_fee
        return fee_reward

if __name__ == '__main__':
    block_hash_b = bytes.fromhex('000000000000000004ec466ce4732fe6f1ed1cddc2ed4b328fff5224276e3f6f')[::-1]

    total_tx_fee = getBlockFeeReward(block_hash_b, block_db_g)
    print('Fee Reward = %d' % total_tx_fee)
