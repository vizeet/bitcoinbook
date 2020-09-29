import hashlib
blk_b = bytes.fromhex('000000202ce1d4bd512bd141cd155c9871dc12f9e7df43c6d9d90a000000000000000000746fd47bfdd13843c939ad0f6217b777d57df663c2d96bcfe3816f59cfad8873b6fc475fea07101726a0f9b3')
h1 = hashlib.sha256(blk_b).digest()
h2 = hashlib.sha256(h1).digest()
print(h2[::-1].hex())
