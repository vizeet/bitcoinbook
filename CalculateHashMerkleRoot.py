import hashlib
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

rpc_connection = AuthServiceProxy("http://%s:%s@127.0.0.1:8332"%('test', 'test'))

def hashOfJoinedStr(a:str, b:str):
     # Reverse inputs before and after hashing due to big-endian / little-endian nonsense
     a1 = bytes.fromhex(a)[::-1]
     b1 = bytes.fromhex(b)[::-1]
     h = hashlib.sha256(hashlib.sha256(a1 + b1).digest()).digest()
     return h[::-1].hex()

def buildHashMerkleRoot(hash_list: list):
    if len(hash_list) < 2:
        return hash_list[0]
    new_hash_list = []
    # Process pairs. For odd length, the last is skipped
    for i in range(0, len(hash_list) - 1, 2):
        new_hash_list.append(hashOfJoinedStr(hash_list[i], hash_list[i + 1]))
    # odd, hash last item twice
    if len(hash_list) % 2 == 1:
        new_hash_list.append(hashOfJoinedStr(hash_list[-1], hash_list[-1]))
    return buildHashMerkleRoot(new_hash_list)

block_hash = rpc_connection.getblockhash(645575)
block = rpc_connection.getblock(block_hash)
print('Merkle Root Hash from RPC call\t = %s' % block['merkleroot'])
hash_merkle_root = buildHashMerkleRoot(block['tx'])
print('Calculated Merkle Root Hash\t = %s' % hash_merkle_root)
