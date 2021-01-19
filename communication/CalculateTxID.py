import mmap
import hashlib

def getVarInt(m: mmap):
    b_cnt_d = {'fd': 2, 'fe': 4, 'ff': 8}
    prefix = int.from_bytes(m.read(1), byteorder='little')
    if prefix < 0xFD:
        return prefix
    else:
        b_cnt = b_cnt_d['%x' % prefix]
        size = int.from_bytes(m.read(b_cnt), byteorder='little')
        return size

def parseTxPayload(payload_m: mmap):
    payload = {}
    pread = payload_m.read(4)
    raw_tx = pread
    payload['version'] = int.from_bytes(pread, byteorder='little')
    pstart = payload_m.tell()
    payload['tx_in count'] = getVarInt(payload_m)
    if payload['tx_in count'] == 0:
        # check if segwit
        payload['is_segwit'] = bool(int.from_bytes(payload_m.read(1), byteorder='little'))
        if payload['is_segwit'] == True:
                pstart = payload_m.tell()
                payload['tx_in count'] = getVarInt(payload_m)
    payload['tx_in'] = []
    for i in range(payload['tx_in count']):
        txin = {}
        txin['prev_tx_hash'] = payload_m.read(32)[::-1].hex()
        txin['prev_tx_out_index'] = int.from_bytes(payload_m.read(4), byteorder='little')
        txin['bytes_scriptsig'] = getVarInt(payload_m)
        txin['sriptsig'] = payload_m.read(txin['bytes_scriptsig']).hex()
        txin['sequence'] = payload_m.read(4)[::-1].hex()
        payload['tx_in'].append(txin)
    payload['tx_out count'] = getVarInt(payload_m)
    payload['tx_out'] = []
    for i in range(payload['tx_out count']):
        txout = {}
        txout['satoshis'] = int.from_bytes(payload_m.read(8), byteorder='little')
        txout['bytes_scriptpubkey'] = getVarInt(payload_m)
        txout['scriptpubkey'] = payload_m.read(txout['bytes_scriptpubkey']).hex()
        payload['tx_out'].append(txout)
    pend = payload_m.tell()
    payload_m.seek(pstart)
    raw_tx += payload_m.read(pend - pstart)
    if 'is_segwit' in payload and payload['is_segwit'] == True:
        for i in range(payload['tx_in count']):
            payload['tx_in'][i]['witness_count'] = getVarInt(payload_m)
            payload['tx_in'][i]['witness'] = []
            for j in range(payload['tx_in'][i]['witness_count']):
                tx_witness = {}
                tx_witness['size'] = getVarInt(payload_m)
                tx_witness['witness'] = payload_m.read(tx_witness['size']).hex()
                payload['tx_in'][i]['witness'].append(tx_witness)
    pread = payload_m.read(4)
    raw_tx += pread
    payload['locktime'] = int.from_bytes(pread, byteorder='little')
    payload['txid'] = hashlib.sha256(hashlib.sha256(raw_tx).digest()).digest()[::-1].hex()
    return payload

tx = '01000000000101c7aacefbc908229647eb1b980e7117c535740f3cd71fff8697ddba7d7f1cadf00100000000ffffffff02411a0000000000001976a9149c4b12bb5a2e7e4b2721a25d8abebd6a8144d41288acee246a7400000000160014c783068b2593c7138d8744956f9d048032c5808002483045022100d7d6a069c404585570208e95c7c88025f75a1a764df077df2c84076013b9b8fd02202f7ebab661d037bda2119d21b58e08cb1442001fbb7e59812286ecb5e3443b34012103f500418025ba3babca935e9f7617c438210ab72ae3ece0b25e5dff579c31ddd100000000'
tx_b = bytes.fromhex(tx)
txlen = len(tx_b)
tx_m = mmap.mmap(-1, txlen + 1)
tx_m.write(tx_b)
tx_m.seek(0)
tx_d = parseTxPayload(tx_m)
print(tx_d)
