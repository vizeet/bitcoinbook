import plyvel
import datetime
import pandas as pd
import os
import mmap
import binascii

block_db_g = plyvel.DB(os.getenv('BLOCK_INDEX_DB'), compression=None)
chainstate_db_g = plyvel.DB(os.getenv('CHAINSTATE_DB'), compression=None)

blocks_path_g = os.getenv('BLOCKS_PATH')

BLOCK_HAVE_DATA          =    8
BLOCK_HAVE_UNDO          =   16

def b128_varint_decode(value: bytes, pos = 0):
    n = 0
    while True:
        data = value[pos]
        pos += 1
        n = (n << 7) | (data & 0x7f) # 1111111
        if data & 0x80 == 0: # each byte is greater than or equal to 0x80 except at the end
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
#        print(key)
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

def parseBlockHeader(mptr: mmap, start: int):
    seek = start-4
    mptr.seek(seek)
    block_header = {}
    block_header['block_size'] = int(binascii.hexlify(mptr.read(4)[::-1]), 16)
    v_b = mptr.read(4)
    block_header['version'] = int(binascii.hexlify(v_b[::-1]), 16)
    prev_block_header_hash = mptr.read(32)
    block_header['prev_block_hash'] = bytes.decode(binascii.hexlify(prev_block_header_hash[::-1]))
    block_header['merkle_tree_root'] = bytes.decode(binascii.hexlify(mptr.read(32)[::-1]))
    block_header['timestamp'] = int(binascii.hexlify(mptr.read(4)[::-1]), 16)
    block_header['date_time'] = datetime.datetime.fromtimestamp(block_header['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
    block_header['bits'] = bytes.decode(binascii.hexlify(mptr.read(4)[::-1]))
    block_header['nounce'] = bytes.decode(binascii.hexlify(mptr.read(4)[::-1]))

#    print('block_header = %s' % block_header)
    return block_header, prev_block_header_hash

def getBlockCount(n_file: int, block_db):
#    key = b'f' + (n_file).to_bytes(4, byteorder='big')
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

def traverseBlockChain():
    global blocks_path_g, chainstate_db_g

    df = pd.DataFrame()
    prev_blockhash_bigendian_b = getRecentBlockHash(chainstate_db_g)
    blockheader_list = []

    while True:
        jsonobj = getBlockIndex(prev_blockhash_bigendian_b, block_db_g)
        if 'data_pos' in jsonobj:
            block_filepath = os.path.join(blocks_path_g, 'blk%05d.dat' % jsonobj['n_file'])
            start = jsonobj['data_pos']
            print('height = %d' % jsonobj['height'])
        elif 'undo_pos' in jsonobj:
            block_filepath = os.path.join(blocks_path_g, 'rev%05d.dat' % jsonobj['n_file'])
            start = jsonobj['undo_pos']

        # load file to memory
        with open(block_filepath, 'rb') as block_file:
            with mmap.mmap(block_file.fileno(), 0, prot = mmap.PROT_READ, flags = mmap.MAP_PRIVATE) as mptr: #File is open read-only
                blockheader, prev_blockhash_bigendian_b = parseBlockHeader(mptr, start)

        blockheader['version'] = jsonobj['version']
        blockheader['height'] = jsonobj['height']
        blockheader['tx_count'] = jsonobj['tx_count']
        blockheader_list.append(blockheader)
        if jsonobj['height'] == 1:
            break
    df = pd.DataFrame(blockheader_list)
    df.to_csv('out.csv', index=False)

if __name__ == '__main__':
    traverseBlockChain()

