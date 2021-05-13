import bech32

witprog = bytes.fromhex('d0862d6e40d240ea1711f6d897f5e7b07e974a593704077edffb7b67fd34b091')
witver = 0x00
hrp = 'bc'
address = bech32.encode(hrp, witver, witprog)
print(address)

witver, witprog_l = bech32.decode(address[:2], address)
witprog_b = bytes(witprog_l)
scriptpubkey_b = bytes([witver]) + bytes([len(witprog_b)]) + witprog_b
print('scriptpubkey = ', scriptpubkey_b.hex())

print('')

witprog = bytes.fromhex('122bf8b77dceee01c0fa1f2b36d155fea2a5b016')
witver = 0x00
hrp = 'bc'
address = bech32.encode(hrp, witver, witprog)
print(address)

witver, witprog_l = bech32.decode(address[:2], address)
witprog_b = bytes(witprog_l)
scriptpubkey_b = bytes([witver]) + bytes([len(witprog_b)]) + witprog_b
print('scriptpubkey = ', scriptpubkey_b.hex())
