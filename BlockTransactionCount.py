def getTransactionCount(blk: bytes):
    prefix = blk[80]
    b_cnt_m = {'fd': 2, 'fe': 4, 'ff': 8}
    if prefix < 0xFD:
        tx_cnt = blk[81]
    else:
        b_cnt = b_cnt_m['%x' % prefix]
        tx_cnt = int.from_bytes(blk[81:81+b_cnt], byteorder='little')
    return tx_cnt

# trimmed block for block hash 0000000000000000000e51a8e8f1bda1ddc86cec2d33a992b05a517a5b749f32
blk_h = '00e0ff376a2079af63073c47184cd091819d506f12cb6b68887c040000000000000000001036e0b1059b1ec79cb36897ccf8bc5aef4c7996897b83754ab590bb2774bc2726c0475fea0710178ffaf153fda4090100000000010100000000000000000000'
blk_b = bytes.fromhex(blk_h)
tx_count = getTransactionCount(blk_b)
print('Transaction Count = %d' % tx_count)
