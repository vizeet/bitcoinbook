import plyvel
import os

block_db_g = plyvel.DB(os.getenv('BLOCK_INDEX_DB'), compression=None)
blocks_path_g = os.getenv('BLOCKS_PATH')

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

blk_index = getBlockFileIndex(138, block_db_g)
print(blk_index)
