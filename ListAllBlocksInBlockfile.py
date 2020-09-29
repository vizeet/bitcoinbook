import plyvel
import datetime
import os

block_db_g = plyvel.DB(os.getenv('BLOCK_INDEX_DB'), compression=None)

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

def getBlockFileIndex(n_file: int, block_db):
    key = b'f' + (n_file).to_bytes(4, byteorder='little')

    value = block_db.get(key)
    jsonobj = {}
    jsonobj['count'], pos = b128_varint_decode(value)
    jsonobj['filesize'], pos = b128_varint_decode(value, pos)
    jsonobj['undofilesize'], pos = b128_varint_decode(value, pos)
    jsonobj['highest'], pos = b128_varint_decode(value, pos)
    jsonobj['lowest'], pos = b128_varint_decode(value, pos)
    jsonobj['highest_timestamp'], pos = b128_varint_decode(value, pos)
    jsonobj['lowest_timestamp'], pos = b128_varint_decode(value, pos)

    return jsonobj

def parseSerialisedBlock(block_f):
    serialized_blk = {}
    serialized_blk['magic_num'] = block_f.read(4)[::-1].hex()
    serialized_blk['blk_size'] = int.from_bytes(block_f.read(4), byteorder='little')
    serialized_blk['version'] = block_f.read(4)[::-1].hex()
    prev_blkhash_b = block_f.read(32)
    serialized_blk['prev_blkhash'] = prev_blkhash_b[::-1].hex()
    serialized_blk['merkle_root_hash'] = block_f.read(32)[::-1].hex()
    serialized_blk['time'] = int.from_bytes(block_f.read(4), byteorder='little')
    serialized_blk['bits'] = block_f.read(4)[::-1].hex()
    serialized_blk['nonce'] = block_f.read(4)[::-1].hex()
    return serialized_blk

## main ##
n_file = 138
block_filepath = os.path.join(blocks_path_g, 'blk%05d.dat' % n_file)
block_f = open(block_filepath, 'rb')
blk_index = getBlockFileIndex(n_file, block_db_g)
print(blk_index)

for i in range(blk_index['count']):
    # moves file pointer to the end of block header
    serialized_blk = parseSerialisedBlock(block_f) 
    next_blk_loc = block_f.tell() - 80 + serialized_blk['blk_size']
    block_f.seek()

    print('height = %d, serialized_blk = %s' % (blk_index['lowest'] + i, serialized_blk))
