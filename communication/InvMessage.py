from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
import struct

rpc_connection = AuthServiceProxy("http://%s:%s@127.0.0.1:8332"%('test', 'test'))

def setVarInt(n: int):
    if n < 0xfd:
        n_h = '%02x' % n
    elif n > 0xfd and n < 0xffff:
        n_h = 'fd%04x' % n
    elif n > 0xffff and n < 0xFFFFFFFF:
        n_h = 'fe%08x' % n
    else:
        n_h = 'ff%016x' % n
    return bytes.fromhex(n_h)

def createInvBlkPayload():
    MSG_BLOCK = 2
    count = 1
    count_b = setVarInt(count)
    blk_height = rpc_connection.getblockcount()
    blk_hash = rpc_connection.getblockhash(blk_height)
    print(blk_hash)
    blk_hash_b = bytes.fromhex(blk_hash)[::-1]
    inv_vect_b = b''
    for i in range(count):
        blk_type_b = struct.pack('<L', MSG_BLOCK)
        inv_vect_b += blk_type_b + blk_hash_b
    payload = count_b + inv_vect_b
    return payload

payload = createInvBlkPayload()
print(payload.hex())
