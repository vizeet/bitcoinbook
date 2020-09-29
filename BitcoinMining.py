from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
import json
import time

rpc_connection = AuthServiceProxy("http://%s:%s@127.0.0.1:8332"%('test', 'test'))

height = rpc_connection.getblockcount()
#height = 645575
#height = 645119

def getVersionBytes(supported_softfork_bits: int):
    version = 0x20000000 | supported_softfork_bits
    v_bytes = bytes.fromhex(hex(version))[::-1]
    return v_bytes

def getPreviousBlockHash():
    global height
    block_hash = rpc_connection.getblockhash(height)
    block_hash_b = bytes.fromhex(block_hash)[::-1]
    return block_hash_b

def getTimeBytes():
    t = time.time()
    time_b = bytes.fromhex(hex(t))[::-1]
    return time_b

def getBlockHeader(blk: bytes):
    block = {}
    block['version'] = blk[0:4][::-1].hex()
    blk = blk[4:]
    block['prev_blockhash'] = blk[0:32][::-1].hex()
    blk = blk[32:]
    block['merkle_root'] = blk[0:32][::-1].hex()
    blk = blk[32:]
    block['time'] =int.from_bytes(blk[0:4], byteorder='little')
    blk = blk[4:]
    block['bits'] = blk[0:4][::-1].hex()
    blk = blk[4:]
    block['nonce'] = blk[0:4][::-1].hex()
    return block 

def targetThreshold2bits(tt: int):
    tt_b = tt.to_bytes((tt.bit_length() + 7) // 8, 'big')
    print(tt_b.hex())
    prepend = b"0" if tt_b[0] > 0x7f else b""
    tt_b = prepend + tt_b
    b1 = bytes([len(tt_b)])
    tt_b = tt_b + bytes(2)
    tt_b = tt_b[0:3]
    bits = b1 + tt_b
    return bits

def getTargetThreshold(bits: bytes):
    shift = bits[3]
    value = int.from_bytes(bits[0:3], byteorder='little')
    target_threshold = value * 2 ** (8 * (shift - 3))
    return target_threshold

def calculateNextTargetThreshold():
    block_hash = rpc_connection.getblockhash(height)
    block = rpc_connection.getblock(block_hash, 0)
    blkhdr = getBlockHeader(bytes.fromhex(block))
    bits = bytes.fromhex(blkhdr['bits'])[::-1]
    tt_old = getTargetThreshold(bits)
    block_hash_2015 = rpc_connection.getblockhash(height-2015)
    block_2015 = rpc_connection.getblock(block_hash_2015, 0)
    blkhdr_2015 = getBlockHeader(bytes.fromhex(block_2015))
    delta_t = blkhdr['time'] - blkhdr_2015['time']
    tt_new = tt_old * (blkhdr['time'] - blkhdr_2015['time'])//(2016 * 600)
    return tt_new


if __name__ == '__main__':
    block_hash_b = getPreviousBlockHash()
    print(block_hash_b.hex())
    tt = calculateNextTargetThreshold()
    print('%x' % tt)
    bits = targetThreshold2bits(tt)
    print('Next bits = %s' % bits.hex())


