from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
import json
import pandas as pd
from pandas import DataFrame
import numpy as np
import copy
import hashlib

rpc_connection = AuthServiceProxy("http://%s:%s@127.0.0.1:8332"%('test', 'test'))

def filterTx(tx_v: dict, height: int, time: int):
    if (tx_v['height'] > height) or (tx_v['time'] > time):
        return False
    return True

def addDescendants(df: DataFrame, mempool: dict, height: int, time: int):
    tx_l = df.to_dict('records')
    tx_itr = iter(tx_l)
    added = False
    for i, tx in enumerate(tx_itr):
        if tx_l[i]['processing'] == True:
            tx_l[i]['processing'] = False
            descendants = mempool[tx['txid']]['depends']
            if len(descendants) == 0:
                continue
            for d in descendents:
                if filterTx(mempool[d], height, time):
                    d_sats_per_b = mempool[d]['fee']*10**8/mempool[d]['vsize']
                    d_d = {'txid': d, 'sats_per_byte': d_sats_per_byte, 'vsize': mempool[d]['vsize'], 'processing': True}
                    if d_sats_per_b > tx['sats_per_byte']:
                        added = True
                        tx_l.insert(i+1, d_d)
                    else:
                        new_txiter = copy(tx_iter)
                        for j, new_tx in enumerate(new_txiter):
                            if d_sats_per_b > new_tx['sats_per_byte']:
                                added = True
                                tx_l.insert(i+j+1, d_d)
                                break

    df = pd.DataFrame(tx_l)
    return added, df

def pruneDF(df):
    df['sum_vsize'] = df['vsize'].cumsum()
    mb = 1 << 20
    df = df[df['sum_vsize'] <= mb]
    return df

def getSortedDF(tx_l: list):
    df = pd.DataFrame(tx_l)
    df = df.sort_values(by=['sats_per_byte'], ascending = False)
    df = df.reset_index(drop=True)
    return df

def getTxWithoutAncestors(height: int, time: int):
    mempool = rpc_connection.getrawmempool(True)
    tx_l = []
    for k, v in mempool.items():
        if filterTx(v, height, time):
            if v['ancestorcount'] == 1:
                sats_per_byte = v['fee']*10**8/v['vsize']
                tx_l.append({'txid': k, 'sats_per_byte': sats_per_byte, 'vsize': v['vsize'], 'processing': True})
    return tx_l, mempool

def getHeightNTime():
    height = rpc_connection.getblockcount()
    block_hash = rpc_connection.getblockhash(height)
    block = rpc_connection.getblock(block_hash)
    time = block['time']

    return height, time

def getRawTransaction(txid: str):
    rawtx = rpc_connection.getrawtransaction(txid)
    return rawtx

def getMempoolTx():
    height, time = getHeightNTime()
    tx_l, mempool = getTxWithoutAncestors(height, time)
    df = getSortedDF(tx_l)
    added = True
    while added:
        df = pruneDF(df)
        added, df = addDescendants(df, mempool, height, time)
    return(df['txid'].tolist())

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

if __name__ == '__main__':
    txl = getMempoolTx()
#    print(txl)
    print(len(txl))
#    for txid in txl:
#        rawtx = getRawTransaction(txid)

    mrh = buildHashMerkleRoot(txl)
    print(mrh)
