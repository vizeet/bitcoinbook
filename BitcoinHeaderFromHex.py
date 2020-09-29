import datetime
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

#blkhdr = bytes.fromhex("000000202ce1d4bd512bd141cd155c9871dc12f9e7df43c6d9d90a000000000000000000746fd47bfdd13843c939ad0f6217b777d57df663c2d96bcfe3816f59cfad8873b6fc475fea07101726a0f9b3")
blkhdr = bytes.fromhex("")
jsonobj = getBlockHeader(blkhdr)
print(jsonobj)
