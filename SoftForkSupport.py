import plyvel
import datetime
import os

block_db_g = plyvel.DB(os.getenv('BLOCK_INDEX_DB'), compression=None)
chainstate_db_g = plyvel.DB(os.getenv('CHAINSTATE_DB'), compression=None)

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

def getObfuscationKey(chainstate_db):
    value = chainstate_db.get(b'\x0e\x00' + b'obfuscate_key')
#    print('obfuscation key = %s' % value)
    obfuscation_key = value[1:]
    return obfuscation_key

def applyObfuscationKey(data: bytes, chainstate_db):
    obfuscation_key = getObfuscationKey(chainstate_db)
    new_val = bytes(data[index] ^ obfuscation_key[index % len(obfuscation_key)] for index in range(len(data)))
    return new_val

def getRecentBlockHash(chainstate_db):
    key = b'B'
    block_hash_b = chainstate_db.get(key)
    block_hash_b = applyObfuscationKey(block_hash_b, chainstate_db)
    return block_hash_b

def getBlockIndex(block_hash_bigendian: bytes, block_db):
    key = b'b' + block_hash_bigendian
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

def getSoftForSupportPercent(support_bit: int):
    global blocks_path_g, chainstate_db_g

    prev_blkhash_b = getRecentBlockHash(chainstate_db_g)

    support_count = 0
    prev_block_filepath = ''
    block_f = None
    for i in range(2016):
        jsonobj = getBlockIndex(prev_blkhash_b, block_db_g)
        if 'data_pos' in jsonobj:
            block_filepath = os.path.join(blocks_path_g, 'blk%05d.dat' % jsonobj['n_file'])
            start = jsonobj['data_pos']
        elif 'undo_pos' in jsonobj:
            block_filepath = os.path.join(blocks_path_g, 'rev%05d.dat' % jsonobj['n_file'])
            start = jsonobj['undo_pos']

        if block_filepath != prev_block_filepath:
            if prev_block_filepath != '':
                block_f.close()
            block_f = open(block_filepath, 'rb')
            block_f.seek(start)
            version = int.from_bytes(block_f.read(4), 'little')
            support_val = 1 << support_bit
            support = (version & support_val) >> support_bit
            support_count += support
            prev_blkhash_b = block_f.read(32)
    print('percent support = %d' % (support_count * 100 // 2016))

if __name__ == '__main__':
    getSoftForSupportPercent(13)

