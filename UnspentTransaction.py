import plyvel
import datetime
import os

block_db_g = plyvel.DB(os.getenv('BLOCK_INDEX_DB'), compression=None)
chainstate_db_g = plyvel.DB(os.getenv('CHAINSTATE_DB'), compression=None)

blocks_path_g = os.getenv('BLOCKS_PATH')

BLOCK_HAVE_DATA          =    8
BLOCK_HAVE_UNDO          =   16

def amount_compress(n: int):
    if n == 0:
        return 0;
    e = 0
    while ((n % 10) == 0) and e < 9:
        n //= 10
        e += 1
    if e < 9:
        d = n % 10
        assert d >= 1 and d <= 9
        n //= 10
        return 1 + (n*9 + d - 1)*10 + e
    else:
        return 1 + (n - 1)*10 + 9

""" Decompresses the Satoshi amount of a UTXO stored in the LevelDB. Code is a port from the Bitcoin Core C++
source:
    https://github.com/bitcoin/bitcoin/blob/v0.13.2/src/compressor.cpp#L161#L185

:param x: Compressed amount to be decompressed.
:type x: int
:return: The decompressed amount of satoshi.
:rtype: int
"""
def amount_decompress(x):
    if x == 0:
        return 0
    x -= 1
    e = x % 10
    x //= 10
    if e < 9:
        d = (x % 9) + 1
        x //= 9
        n = x * 10 + d
    else:
        n = x + 1
    while e > 0:
        n *= 10
        e -= 1
    return n

def b128_varint_encode(n: int):
    l = 0
    tmp = []
    while True:
        tmp.insert(0, n & 0x7F)
        if l != 0:
            tmp[0] |= 0x80
        if n <= 0x7F:
            break
        n = (n >> 7) - 1
        l += 1

    bin_data = bytes(tmp)
    return bin_data

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
    print('obfuscation_key = %s' % obfuscation_key.hex())
    new_val = bytes()
    for index in range(len(data)):
        obf_key_i = index % len(obfuscation_key)
        dt_i = bytes([data[index] ^ obfuscation_key[obf_key_i]])
        new_val = new_val + dt_i
    new_val1 = bytes(data[index] ^ obfuscation_key[index % len(obfuscation_key)] for index in range(len(data)))
    print('data = \t\t\t\t%s' % data.hex())
    print('obf_key_for_application = \t%s' % bytes(obfuscation_key[index % len(obfuscation_key)] for index in range(len(data))).hex())
    print('new_val = \t\t\t%s' % new_val.hex())
    print('new_val1 = \t\t\t%s' % new_val1.hex())
    return new_val

def uncompressScriptType0(script_data: bytes):
    script = bytes([
            0x76, # OP_DUP
            0xa9, # OP_HASH160
            20 # size
            ]) + script_data + bytes([
            0x88, # OP_EQUALVERIFY
            0xac # OP_CHECKSIG
            ])
    return script

def getUnspentTransactions(tx_hash: bytes, out_index: int,chainstate_db):
    key = b'C' + tx_hash + b128_varint_encode(out_index)
    value_obf_b = chainstate_db.get(key)
    value_obf_b = applyObfuscationKey(value_obf_b, chainstate_db)
    jsonobj = {}
    code, pos = b128_varint_decode(value_obf_b)
    jsonobj['is_coinbase'] = code & 0x01
    jsonobj['block_height'] = code >> 1
    compressed_amount, pos = b128_varint_decode(value_obf_b, pos)
    print('compressed_amount = %d' % compressed_amount)
    jsonobj['unspent_amount'] = amount_decompress(compressed_amount)
    print('uncompressed_amount = %d' % jsonobj['unspent_amount'])
    print('compressed_amount = %d' % amount_compress(jsonobj['unspent_amount']))
    jsonobj['script_type'], pos = b128_varint_decode(value_obf_b, pos)
    jsonobj['scriptPubKey']= value_obf_b[pos:].hex()
    return jsonobj

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

if __name__ == '__main__':
    tx = bytes.fromhex('a23203c053852755c97b87e354d1e9053a6d1a20d32892e8ee45dfa2c3105f94')[::-1]
    jsonobj = getUnspentTransactions(tx, 0, chainstate_db_g)
    print(jsonobj)
    script_data = bytes.fromhex('3eba92179cd0b4caff74e3e81a14399e3c1b7ca3')
    script = uncompressScriptType0(script_data)
    print('script = %s' % script.hex())

