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
    print('obfuscation key = %s' % value)
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

def getBlockFileIndex(fileno: int):
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

def parseBlockHeader(blkhdr: bytes):
    version = blkhdr[0:4]
    blkhdr = blkhdr[4:]
    prev_blkhash = blkhdr[0:32]
    blkhdr = blkhdr[32:]
    merkle_root = blkhdr[0:32]
    blkhdr = blkhdr[32:]
    time = blkhdr[0:4]
    blkhdr = blkhdr[4:]
    bits = blkhdr[0:4]
    blkhdr = blkhdr[4:]
    nonce = blkhdr[0:4]
    return prev_blkhash

def traverseBlockChain():
    global blocks_path_g, chainstate_db_g

    prev_blkhash_b = getRecentBlockHash(chainstate_db_g)

    while True:
        jsonobj = getBlockIndex(prev_blkhash_b, block_db_g)
        if 'data_pos' in jsonobj:
            block_filepath = os.path.join(blocks_path_g, 'blk%05d.dat' % jsonobj['n_file'])
            start = jsonobj['data_pos']
        elif 'undo_pos' in jsonobj:
            block_filepath = os.path.join(blocks_path_g, 'rev%05d.dat' % jsonobj['n_file'])
            start = jsonobj['undo_pos']

        # load file to memory
        with open(block_filepath, 'rb') as block_f:
            block_f.seek(start - 8)
            magic_num = block_f.read(4)[::-1].hex()
            blk_size = int.from_bytes(block_f.read(4), byteorder='little')
            version = block_f.read(4)[::-1].hex()
            prev_blkhash_b = block_f.read(32)
            prev_blkhash = prev_blkhash_b[::-1].hex()
            merkle_root_hash = block_f.read(32)[::-1].hex()
            time = int.from_bytes(block_f.read(4), byteorder='little')
            bits = block_f.read(4)[::-1].hex()
            nonce = block_f.read(4)[::-1].hex()
#        print('height = %d, blockhash = %s' % (jsonobj['height'], prev_blkhash))
        print('height = %d, magic_num = %s, block_size = %d, version = %s, blockhash = %s, merkle_root_hash = %s, time = %d, bits = %s, nonce = %s' % (jsonobj['height'], magic_num, blk_size, version, prev_blkhash, merkle_root_hash, time, bits, nonce))

        if jsonobj['height'] == 1:
            break

def traverseBlockChainV2():
    global blocks_path_g, chainstate_db_g

    prev_blkhash_b = getRecentBlockHash(chainstate_db_g)

    while True:
        jsonobj = getBlockIndex(prev_blkhash_b, block_db_g)
        if 'data_pos' in jsonobj:
            block_filepath = os.path.join(blocks_path_g, 'blk%05d.dat' % jsonobj['n_file'])
            start = jsonobj['data_pos']
        elif 'undo_pos' in jsonobj:
            block_filepath = os.path.join(blocks_path_g, 'rev%05d.dat' % jsonobj['n_file'])
            start = jsonobj['undo_pos']

        # load file to memory
        with open(block_filepath, 'rb') as block_f:
            block_f.seek(start - 8)
            magic_num = block_f.read(4)[::-1].hex()
            blk_size = int.from_bytes(block_f.read(4), byteorder='little')
            version = block_f.read(4)[::-1].hex()
            prev_blkhash_b = block_f.read(32)
            prev_blkhash = prev_blkhash_b[::-1].hex()
            merkle_root_hash = block_f.read(32)[::-1].hex()
            time = int.from_bytes(block_f.read(4), byteorder='little')
            bits = block_f.read(4)[::-1].hex()
            nonce = block_f.read(4)[::-1].hex()
#        print('height = %d, blockhash = %s' % (jsonobj['height'], prev_blkhash))
        print('height = %d, magic_num = %s, block_size = %d, version = %s, blockhash = %s, merkle_root_hash = %s, time = %d, bits = %s, nonce = %s' % (jsonobj['height'], magic_num, blk_size, version, prev_blkhash, merkle_root_hash, time, bits, nonce))

        if jsonobj['height'] == 1:
            break

if __name__ == '__main__':
    traverseBlockChain()

