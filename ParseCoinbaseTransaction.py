import mmap
def getVarInt(blk_m: mmap):
    b_cnt_d = {'fd': 2, 'fe': 4, 'ff': 8}
    prefix = int.from_bytes(blk_m.read(1), byteorder='little')
    if prefix < 0xFD:
        return prefix
    else:
        b_cnt = b_cnt_d['%x' % prefix]
        size = int.from_bytes(blk_m.read(b_cnt), byteorder='little')
        return size

def printCoinbaseTransactionInfo(blk_m: mmap):
    blkhdr = blk_m.read(80)
    blk_size = getVarInt(blk_m)
    tx = {}
    tx['version'] = blk_m.read(4)[::-1].hex()
    tx['inp_cnt'] = getVarInt(blk_m)
    inp_l = []
    for i in range(tx['inp_cnt']):
        inp = {}
        inp['prev_tx_hash'] = blk_m.read(32)[::-1].hex()
        inp['prev_tx_out_index'] = blk_m.read(4)[::-1].hex()
        inp['bytes_coinbase_data'] = getVarInt(blk_m)
        pos = blk_m.tell()
        inp['bytes_height'] = getVarInt(blk_m)
        inp['height'] = int.from_bytes(blk_m.read(inp['bytes_height']), byteorder='little')
        size = blk_m.tell() - pos
        coinbase_arb_data_size = inp['bytes_coinbase_data'] - size
        inp['coinbase_arb_data'] = blk_m.read(coinbase_arb_data_size).hex()
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
    tx['locktime'] = int.from_bytes(blk_m.read(4), byteorder='little')
    print(tx)

# trimmed block for block hash 000000000000000004ec466ce4732fe6f1ed1cddc2ed4b328fff5224276e3f6f
blk_b = bytes.fromhex('0400000039fa821848781f027a2e6dfabbf6bda920d9ae61b63400030000000000000000ecae536a304042e3154be0e3e9a8220e5568c3433a9ab49ac4cbb74f8df8e8b0cc2acf569fb9061806652c27fd7c0601000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3f03801a060004cc2acf560433c30f37085d4a39ad543b0c000a425720537570706f727420384d200a666973686572206a696e78696e092f425720506f6f6c2fffffffff012fd8ff96000000001976a914721afdf638d570285d02d3076d8be6a03ee0794d88ac00000000')
blk_m = mmap.mmap(-1, len(blk_b) + 1)
blk_m.write(blk_b)
blk_m.seek(0)
printCoinbaseTransactionInfo(blk_m)
