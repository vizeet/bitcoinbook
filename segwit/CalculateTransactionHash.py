import mmap
import hashlib

def hash256(bstr: bytes):
    return hashlib.sha256(hashlib.sha256(bstr).digest()).digest()

def getVarInt(blk_m: mmap):
    b_cnt_d = {'fd': 2, 'fe': 4, 'ff': 8}
    prefix = int.from_bytes(blk_m.read(1), byteorder='little')
    if prefix < 0xFD:
        return prefix
    else:
        b_cnt = b_cnt_d['%x' % prefix]
        varint = int.from_bytes(blk_m.read(b_cnt), byteorder='little')
        return varint

def parseScript(script_b: bytes):
    pass

def getCoinbaseTransactionInfo(txn_m: mmap):
    tx = {}
    startloc = txn_m.tell()
    tx['version'] = txn_m.read(4)[::-1].hex()
    tx['inp_cnt'] = getVarInt(txn_m)
    tx['is_segwit'] = True
    if tx['inp_cnt'] == 0:
        # check segwit flag
        tx['is_segwit'] = (int.from_bytes(txn_m.read(1), byteorder='little') == 1)
        if tx['is_segwit'] == True:
            tx['inp_cnt'] = getVarInt(txn_m)
    inp_l = []
    for i in range(tx['inp_cnt']):
        inp = {}
        inp['prev_tx_hash'] = txn_m.read(32)[::-1].hex()
        inp['prev_tx_out_index'] = txn_m.read(4)[::-1].hex()
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
    print(txid_b.hex())
    tx['locktime'] = int.from_bytes(locktime_b, byteorder='little')
    tx['txid'] = hash256(txid_b)[::-1].hex()
    return tx

#def getScriptType(tx: dict, in_index: int):
#    scriptsig_b = bytes.fromhex(tx[in_index]['scriptsig'])
#    scriptsiglen = tx[in_index]['bytes_scriptsig']
#    if scriptsig_b[:2] == b'\x00\x14' and scriptsiglen == 21:
#        return 'P2WPKH'
#    if scriptsig_b[:2] == b'\x00\x20' and scriptsiglen == 33:
#        return 'P2WSH'
#    if scriptsig_b[:3] == b'\x76\xa9\x14' and scriptsig_b[23:25] == b'\x88\xac' and scriptsiglen == 25:
#        return 'P2PKH'
#    if scriptsig_b[:2] == b'\xa9\x14' and scriptsig_b[22:23] == b'\x87' and scriptsiglen == 23:
#        if tx['is_segwit'] == True and tx['inputs'][i]['witness_cnt'] > 0:
#            if tx['inputs'][i]['witness_cnt'] > 2:
#                return 'P2SH-P2WSH'
#            else
#                return 'P2SH-P2WPKH'
#        else:
#            return 'P2SH'

def getTransactionInfo(blk_m: mmap):
    tx = {}
    startloc = txn_m.tell()
    tx['version'] = blk_m.read(4)[::-1].hex()
    tx['inp_cnt'] = getVarInt(blk_m)
    tx['is_segwit'] = False
    if tx['inp_cnt'] == 0:
        # check segwit flag
        tx['is_segwit'] = (int.from_bytes(txn_m.read(1), byteorder='little') == 1)
        if tx['is_segwit'] == True:
            tx['inp_cnt'] = getVarInt(txn_m)
    inp_l = []
    for i in range(tx['inp_cnt']):
        inp = {}
        inp['prev_tx_hash'] = blk_m.read(32)[::-1].hex()
        inp['prev_tx_out_index'] = blk_m.read(4)[::-1].hex()
        inp['bytes_scriptsig'] = getVarInt(blk_m)
        inp['sriptsig'] = blk_m.read(inp['bytes_scriptsig']).hex()
        inp['sequence'] = blk_m.read(4)[::-1].hex()
        inp_l.append(inp)
    tx['inputs'] = inp_l
    tx['out_cnt'] = getVarInt(blk_m)
    out_l = []
    for i in range(tx['out_cnt']):
        out = {}
        out['satoshis'] = int.from_bytes(blk_m.read(8), byteorder='little')
        out['bytes_scriptpubkey'] = getVarInt(blk_m)
        out['scriptpubkey'] = blk_m.read(out['bytes_scriptpubkey']).hex()
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
    print(txid_b.hex())
    tx['txid'] = hash256(txid_b)[::-1].hex()
    curloc = txn_m.tell()
    txn_m.seek(startloc)
    wtxid_b = txn_m.read(curloc - startloc)
    tx['wtxid'] = hash256(wtxid_b)[::-1].hex()
    tx['bytes'] = len(wtxid_b)
    tx['weight'] = (len(wtxid_b) - len(txid_b)) + (len(txid_b) * 4)
    return tx

def getWtxIDFromTx(txn_b: bytes):
    return hash256(txn_b)[::-1].hex()

blk_height = 668000

if __name__ == '__main__':
    cb_txn_b = bytes.fromhex('010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff400360310a040e5012602f706f6f6c696e2e636f6d2f746170726f6f742f626970392f57414aa61d1d79f4d92b134a2172611e120154741700bd36220000000000ffffffff041d066c260000000017a9149837b6ca944b36f71b94d19cf1e1acd179726424870000000000000000266a24b9e11b6db14323c98fb36550f3bf4d5ce2ea5fcb878ec778a849a99add2cc2e76141432b0000000000000000266a24aa21a9ed1cb4ceb5ec7fef10b852514760a409539056be66601f589c5539e443fbbfdcfc00000000000000002b6a2952534b424c4f434b3a68894f43c4cff546f6ee51f9e9475bcd2bfff279283cb6de9fc47c2c002eb263012000000000000000000000000000000000000000000000000000000000000000006b6066c1')
    txn_m = mmap.mmap(-1, len(cb_txn_b) + 1)
    txn_m.write(cb_txn_b)
    txn_m.seek(0)
    tx = getCoinbaseTransactionInfo(txn_m)
    print(tx)

######### txn id is c6176c811328a9fd82a3a71da78e73781bc5c9a6580fdee4cf4392b165b1a072
    txn_b = bytes.fromhex('02000000000102dc0f4a1601bd6bfec4241fede438bee45958773fe5d95f88ec890e2363983e0c0100000000ffffffff904d74d770c0ef5ce91190750b235d7ffb340b82b392812ba8e6ad5f0a8c4ca70000000000ffffffff02f31f0a00000000001600140c986c1d8ad520c072ee1aa0a151615c891ef71455b8180000000000160014097e656deb55afa3786c600a87d990dcab86fc2d024730440220685234e91eb14e6d1717c543193181700b1cbf5fecddbee79ed9b6b0bbf24077022033dac5cc679dca810327dcac4b84ba2b007a3a4fda6fb2cbc6099ae91c53804f01210277bed123bc0c0f9883b0bc14014f0385d39eac7ac7212d8c9928fa4121a191f4024730440220635eb52780098e3bd1e39a630a23f553ac62b97d0cd0356fa34ceb47cb0195250220599b83d8872ff173781b83b36bf159b59ed7685f73811f449fa1df814fbef15c0121022cd4d498f1ed0ee382eefe4b6e1d8c5aa678d47b693389ccdf77559b3220c5fa00000000')
    txn_m = mmap.mmap(-1, len(txn_b) + 1)
    txn_m.write(txn_b)
    txn_m.seek(0)
    tx = getTransactionInfo(txn_m)
    print(tx)

######## wtxid for the transaction
    wtxid = getWtxIDFromTx(txn_b)
    print('wtxid = ', wtxid)

########
    preimage = bytes.fromhex('0100000096b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd3752b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3bef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a010000001976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac0046c32300000000ffffffff863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e51100000001000000')
    print(hash256(preimage).hex())
