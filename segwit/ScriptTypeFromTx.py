import hashlib
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
import plyvel
import datetime
import os
import json
import mmap

txindex_db_g = plyvel.DB(os.getenv('TX_INDEX_DB'), compression=None)
blk_db_g = plyvel.DB(os.getenv('BLOCK_INDEX_DB'), compression=None)
blks_path_g = os.getenv('BLOCKS_PATH')

BLOCK_HAVE_DATA          =    8
BLOCK_HAVE_UNDO          =   16

def hash256(bstr: bytes):
    return hashlib.sha256(hashlib.sha256(bstr).digest()).digest()

def b128_varint_decode(b: bytes, pos = 0):
    n = 0
    while True:
        data = b[pos]
        pos += 1
        n = (n << 7) | (data & 0x7f)
        if data & 0x80 == 0:
            return (n, pos)
        n += 1

#rpc_connection = AuthServiceProxy("http://%s:%s@127.0.0.1:8332"%('test', 'test'))

def getVarInt(txn_m):
    b_cnt_d = {'fd': 2, 'fe': 4, 'ff': 8}
    prefix = int.from_bytes(txn_m.read(1), byteorder='little')
    if prefix < 0xfd:
        return prefix
    else:
        b_cnt = b_cnt_d['%x' % prefix]
        varint = int.from_bytes(txn_m.read(b_cnt), byteorder='little')
        return varint

def getBlockIndex(blk_hash: bytes):
    key = b'b' + blk_hash
    value = blk_db_g.get(key)
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


def getCoinbaseTransactionInfo(txn_m):
    tx = {}
    startloc = txn_m.tell()
    tx['version'] = txn_m.read(4)[::-1].hex()
    tx['inp_cnt'] = getVarInt(txn_m)
    tx['is_segwit'] = False
    if tx['inp_cnt'] == 0:
        # check segwit flag
        tx['is_segwit'] = (int.from_bytes(txn_m.read(1), byteorder='little') == 1)
        if tx['is_segwit'] == True:
            tx['inp_cnt'] = getVarInt(txn_m)
    inp_l = []
    for i in range(tx['inp_cnt']):
        inp = {}
        inp['prev_tx_hash'] = txn_m.read(32)[::-1].hex()
        inp['prev_tx_out_index'] = int.from_bytes(txn_m.read(4), byteorder='little')
        inp['bytes_coinbase_data'] = getVarInt(txn_m)
        pos = txn_m.tell()
        inp['bytes_height'] = getVarInt(txn_m)
        inp['height'] = int.from_bytes(txn_m.read(inp['bytes_height']), byteorder='little')
        size = txn_m.tell() - pos
        coinbase_arb_data_size = inp['bytes_coinbase_data'] - size
        inp['coinbase_arb_data'] = txn_m.read(coinbase_arb_data_size).hex()
        inp['sequence'] = txn_m.read(4)[::-1].hex()
        inp_l.append(inp)
    tx['inputs'] = inp_l
    tx['out_cnt'] = getVarInt(txn_m)
    out_l = []
    for i in range(tx['out_cnt']):
        out = {}
        out['satoshis'] = int.from_bytes(txn_m.read(8), byteorder='little')
        out['bytes_scriptpubkey'] = getVarInt(txn_m)
        out['scriptpubkey'] = txn_m.read(out['bytes_scriptpubkey']).hex()
#        parseScript(bytes.fromhex(out['scriptpubkey']))
        out_l.append(out)
    tx['outs'] = out_l
    curloc = txn_m.tell()
    txn_m.seek(startloc)
    txid_b = txn_m.read(curloc - startloc)
    if tx['is_segwit'] == True:
        # if segflag is true than remove segwit marker and flag from txhash calculation
        txid_b = txid_b[:4] + txid_b[6:]
        for i in range(tx['inp_cnt']):
            tx['inputs'][i]['witness_cnt'] = getVarInt(txn_m)
            witness_cnt = tx['inputs'][i]['witness_cnt']
            witness_l = []
            for j in range(witness_cnt):
                witness = {}
                witness['size'] = getVarInt(txn_m)
                witness['witness'] = txn_m.read(witness['size']).hex()
                witness_l.append(witness)
            tx['inputs'][i]['witnesses'] = witness_l
    locktime_b = txn_m.read(4)
    txid_b += locktime_b
    tx['locktime'] = int.from_bytes(locktime_b, byteorder='little')
    tx['txid'] = hash256(txid_b)[::-1].hex()
    return tx

def getTransactionIndex(tx_hash: bytes, txindex_db):
    key = b't' + tx_hash
    value = txindex_db.get(key)
    jsonobj = {}
    jsonobj['n_file'], pos = b128_varint_decode(value)
    jsonobj['block_offset'], pos = b128_varint_decode(value, pos)
    jsonobj['file_offset'], pos = b128_varint_decode(value, pos)
    print(jsonobj)
    return jsonobj

BLOCK_HEADER_SIZE = 80

def findTransaction(tx_hash: bytes, txindex_db):
    jsonobj = getTransactionIndex(tx_hash, txindex_db)
    blk_filepath = os.path.join(blks_path_g, 'blk%05d.dat' % jsonobj['n_file'])
    with open(blk_filepath, 'r+b') as blk_f:
        blk_m = mmap.mmap(blk_f.fileno(), 0) # map whole file
        blk_m.seek(jsonobj['block_offset'] + BLOCK_HEADER_SIZE + jsonobj['file_offset'])
        tx = getTransactionInfo(blk_m)
        blk_m.close()
        return tx

def getPrevScriptPubkey(tx: dict, in_index: int):
    prevtx_hash_b = bytes.fromhex(tx['inputs'][in_index]['prev_tx_hash'])[::-1]
    prev_tx = findTransaction(prevtx_hash_b, txindex_db_g)
    prev_tx_outindex = tx['inputs'][in_index]['prev_tx_out_index']
    print('prev_txid = ', prev_tx['txid'])
    print('prev_tx_outindex =', prev_tx_outindex)
    return prev_tx['outs'][prev_tx_outindex]['scriptpubkey']

def getScriptType(tx: dict, in_index: int):
    prevtx_scriptpubkey = getPrevScriptPubkey(tx, in_index)
    prevtx_scriptpubkey_b = bytes.fromhex(prevtx_scriptpubkey)
    print('prevtx_scriptpubkey', prevtx_scriptpubkey)
    tx_input = tx['inputs'][in_index]
    print('XXXXXXX scriptsig = ', tx_input['scriptsig'])
    print('bytes_scriptsig = ', tx_input['bytes_scriptsig'])
    prevtx_scriptsiglen = len(prevtx_scriptpubkey_b)
    script_type = ''
    if prevtx_scriptpubkey_b[:2] == b'\x00\x14' and prevtx_scriptsiglen == 22:
        script_type = 'P2WPKH'
        print('witnesses = ', tx_input['witnesses'])
        print(script_type)
        print('sighash_type =', tx_input['witnesses'][0]['witness'][-2:])
        return script_type
    if prevtx_scriptpubkey_b[:2] == b'\x00\x20' and prevtx_scriptsiglen == 34:
        script_type = 'P2WSH'
        print('witnesses = ', tx_input['witnesses'])
        print(script_type)
        return script_type
    if prevtx_scriptpubkey_b[:3] == b'\x76\xa9\x14' and prevtx_scriptpubkey_b[23:25] == b'\x88\xac' and prevtx_scriptsiglen == 25:
        script_type = 'P2PKH'
        print(script_type)
        return script_type
    if prevtx_scriptpubkey_b[:2] == b'\xa9\x14' and prevtx_scriptpubkey_b[-1:] == b'\x87' and prevtx_scriptsiglen == 23:
        if tx['is_segwit'] == True and tx_input['scriptsig'][:6] == '160014' and tx_input['bytes_scriptsig'] == 23:
            script_type = 'P2SH-P2WPKH'
            print('witnesses = ', tx_input['witnesses'])
            print(script_type)
            return script_type
        elif tx['is_segwit'] == True and tx_input['scriptsig'][:6] == '220020' and tx_input['bytes_scriptsig'] == 35:
            script_type = 'P2SH-P2WSH'
            print('witnesses = ', tx_input['witnesses'])
            print(script_type)
            return script_type
        else:
            script_type = 'P2SH'
            print(script_type)
            return script_type

def getTransactionInfo(txn_m):
    tx = {}
    startloc = txn_m.tell()
    tx['version'] = txn_m.read(4)[::-1].hex()
    tx['inp_cnt'] = getVarInt(txn_m)
    tx['is_segwit'] = False
    if tx['inp_cnt'] == 0:
        # check segwit flag
        tx['is_segwit'] = (int.from_bytes(txn_m.read(1), byteorder='little') == 1)
        if tx['is_segwit'] == True:
            tx['inp_cnt'] = getVarInt(txn_m)
    inp_l = []
    for i in range(tx['inp_cnt']):
        inp = {}
        inp['prev_tx_hash'] = txn_m.read(32)[::-1].hex()
        inp['prev_tx_out_index'] = int.from_bytes(txn_m.read(4), byteorder='little')
        inp['bytes_scriptsig'] = getVarInt(txn_m)
        inp['scriptsig'] = txn_m.read(inp['bytes_scriptsig']).hex()
        inp['sequence'] = txn_m.read(4)[::-1].hex()
        inp_l.append(inp)
    tx['inputs'] = inp_l
    tx['out_cnt'] = getVarInt(txn_m)
    out_l = []
    for i in range(tx['out_cnt']):
        out = {}
        out['satoshis'] = int.from_bytes(txn_m.read(8), byteorder='little')
        out['bytes_scriptpubkey'] = getVarInt(txn_m)
        out['scriptpubkey'] = txn_m.read(out['bytes_scriptpubkey']).hex()
        out_l.append(out)
    tx['outs'] = out_l
    curloc = txn_m.tell()
    txn_m.seek(startloc)
    txid_b = txn_m.read(curloc - startloc)
    if tx['is_segwit'] == True:
        # if segflag is true than remove segwit marker and flag from txhash calculation
        txid_b = txid_b[:4] + txid_b[6:]
        for i in range(tx['inp_cnt']):
            tx['inputs'][i]['witness_cnt'] = getVarInt(txn_m)
            witness_l = []
            witness_cnt = tx['inputs'][i]['witness_cnt']
            for j in range(witness_cnt):
                witness = {}
                witness['size'] = getVarInt(txn_m)
                witness['witness'] = txn_m.read(witness['size']).hex()
                witness_l.append(witness)
            tx['inputs'][i]['witnesses'] = witness_l
    locktime_b = txn_m.read(4)
    txid_b += locktime_b
    tx['locktime'] = int.from_bytes(locktime_b, byteorder='little')
    tx['txid'] = hash256(txid_b)[::-1].hex()
    curloc = txn_m.tell()
    txn_m.seek(startloc)
    wtxid_b = txn_m.read(curloc - startloc)
    tx['wtxid'] = hash256(wtxid_b)[::-1].hex()
    return tx

def addScriptType(tx: dict):
    for i in range(tx['inp_cnt']):
        tx['inputs'][i]['script_type'] = getScriptType(tx, i)
    return tx

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

def hashOfJoinedStr(a:str, b:str):
     a1 = bytes.fromhex(a)[::-1]
     b1 = bytes.fromhex(b)[::-1]
     h = hashlib.sha256(hashlib.sha256(a1 + b1).digest()).digest()
     return h

def calculateMerkleRootHash(hash_l: list):
    if len(hash_l) < 2:
        return hash_l[0]
    new_hash_l = []
    for i in range(0, len(hash_l) - 1, 2):
        new_hash_l.append(hashOfJoinedStr(hash_l[i], hash_l[i + 1])[::-1].hex())
    if len(hash_l) % 2 == 1:
        new_hash_l.append(hashOfJoinedStr(hash_l[-1], hash_l[-1])[::-1].hex())
    return calculateMerkleRootHash(new_hash_l)

def getWitnessReservedValue(cb_tx: dict):
    return cb_tx['inputs'][0]['witnesses'][0]['witness']

def getRootHashes(txn_m):
    txcount = getVarInt(txn_m)
    print('txcount = ', txcount)
    wtxid_l = []
    txid_l = []
    cb_tx = getCoinbaseTransactionInfo(txn_m)
    print(json.dumps(cb_tx, indent = 4))
    txid_l.append(cb_tx['txid'])
    wtxid_l.append(bytes(32).hex())
    for txindex in range(txcount - 1):
        tx = getTransactionInfo(txn_m)
        wtxid_l.append(tx['wtxid'])
        txid_l.append(tx['txid'])
        print('txid = ', tx['txid'])
        tx = addScriptType(tx)
        print('=====================================================================')
    witness_merkle_root_h = calculateMerkleRootHash(wtxid_l)
    merkle_root_h = calculateMerkleRootHash(txid_l)
    return merkle_root_h, witness_merkle_root_h, cb_tx

def calculateCommitmentHash(blkhash_b: bytes):
    jsonobj = getBlockIndex(blkhash_b)
    if 'data_pos' in jsonobj:
        txn_milepath = os.path.join(blks_path_g, 'blk%05d.dat' % jsonobj['n_file'])
        start = jsonobj['data_pos']
    elif 'undo_pos' in jsonobj:
        txn_milepath = os.path.join(blks_path_g, 'rev%05d.dat' % jsonobj['n_file'])
        start = jsonobj['undo_pos']

    # load file to memory
    with open(txn_milepath, 'rb') as txn_mile:
        #File is open read-only
        with mmap.mmap(txn_mile.fileno(), 0, 
                        prot = mmap.PROT_READ, 
                        flags = mmap.MAP_PRIVATE) as txn_m: 
            txn_m.seek(start)
            blkhdr = getBlockHeader(txn_m.read(80))
            print('blkhdr = ', blkhdr)
            merkle_root_h, witness_merkle_root_h, cb_tx = getRootHashes(txn_m)
            print('Calculated Witness Merkle Root Hash\t = %s' % witness_merkle_root_h)
            print('Calculated Merkle Root Hash\t = %s' % merkle_root_h)
            witness_reserved_value = getWitnessReservedValue(cb_tx)
            print('witness_reserved_value = ', witness_reserved_value)
            # calculate commitment hash
            commitment_hb = hashOfJoinedStr(witness_merkle_root_h, witness_reserved_value)
            commitment_h = commitment_hb.hex()
            print('calculated commitment hash = ', commitment_h)
            verifyCommitmentHash(cb_tx, commitment_h)
            return commitment_h

def getCommitmentHashInCbTx(cb_tx: dict):
    for output in cb_tx['outs']:
        if output['scriptpubkey'][:12] == '6a24aa21a9ed':
            commitment_h = output['scriptpubkey'][12:]
            print('Actual commitment hash = ', commitment_h)
    return commitment_h

def verifyCommitmentHash(cb_tx: dict, commitment_h: str):
    if getCommitmentHashInCbTx(cb_tx) == commitment_h:
        print('Commitment hash matches')
    else:
        print('Invalid commitment hash')

if __name__ == '__main__':
    blk_hb = bytes.fromhex('00000000000000000000f608724d1e152a875384e5ed06ae4a889c5a6c19c2f1')[::-1]
    commitment_h = calculateCommitmentHash(blk_hb)

#blk_hash = rpc_connection.getblockhash(645575)
#block = rpc_connection.getblock(block_hash)
#print('Merkle Root Hash from RPC call\t = %s' % block['merkleroot'])
#hash_merkle_root = buildHashMerkleRoot(block['tx'])
#print('Calculated Merkle Root Hash\t = %s' % hash_merkle_root)
#
