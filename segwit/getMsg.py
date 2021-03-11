import hashlib
import ecdsa
import mmap
import struct

#01 00 00 00
#00
#01
#01
#15e180dc28a2327e687facc33f10f2a20da717e5548406f7ae8b4c811072f856
#01 00 00 00
#00
#ff ff ff ff
#01
#00 b4 f5 05 00 00 00 00
#1976a9141d7cd6c75c2e86f4cbf98eaed221b30bd9a0b92888ac
#02483045
#022100df7b7e5cda14ddf91290e02ea10786e03eb11ee36ec02dd862fe9a326bbcb7fd
#02203f5b4496b667e6e281cc654a2da9e4f08660c620a1051337fa8965f727eb1919
#01
#21038262a6c6cec93c2d3ecd6c6072efea86d02ff8e3328bbd0242b20af3425990ac
#00000000

def bytes2Mmap(b: bytes):
    m = mmap.mmap(-1, len(b) + 1)
    m.write(b)
    m.seek(0)
    return m

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

def getYFromX(x: int):
    y_sq = (pow(x, 3, p)  + 7) % p
    y = pow(y_sq, ((p+1) >> 2), p)
    return y

def getFullPubKeyFromCompressed(x_b: bytes):
    x = int.from_bytes(x_b[1:], byteorder='big')
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if y & 1 != x_b[0] & 1:
        y = p - y
    y = y.to_bytes(32, byteorder='big')
    return b'\x04' + x_b[1:] + y

def getRandSFromSig(sig_b: bytes):
    sig_m = bytes2Mmap(sig_b)
    struct = sig_m.read(1)
    size = sig_m.read(1)
    rheader = sig_m.read(1)
    rsize_b = sig_m.read(1)
    rsize = int.from_bytes(rsize_b, byteorder='big')
    if rsize == 33:
        sig_m.read(1)
    r = sig_m.read(32)
    sheader = sig_m.read(1)
    ssize_b = sig_m.read(1)
    ssize = int.from_bytes(ssize_b, byteorder='big')
    if ssize == 33:
        sig_m.read(1)
    s = sig_m.read(32)
    return r + s

def hash256(bstr: bytes):
    return hashlib.sha256(hashlib.sha256(bstr).digest()).digest()

version = bytes.fromhex('01000000')
print('version = ', version.hex())
h = bytes.fromhex('56f87210814c8baef7068454e517a70da2f2103fc3ac7f687e32a228dc80e115')[::-1]
index = struct.pack('<L', 1)
prevouts = h + index
print('prevouts = ', prevouts.hex())
hashPrevouts = hash256(prevouts)
amount = struct.pack('<Q', 100000000)
print('amount = ', amount.hex())
sequence = bytes.fromhex('ffffffff')
print('sequence = ', sequence.hex())
hashSequence = hash256(sequence)
outpoint = prevouts
print('outpoint = ', outpoint.hex())
scriptcode = bytes.fromhex('76a9141d7cd6c75c2e86f4cbf98eaed221b30bd9a0b92888ac')
scriptcode_bytes = bytes.fromhex('%x' % len(scriptcode))
print('scriptcode_bytes = ', scriptcode_bytes.hex())
print('scriptcode = ', scriptcode.hex())
value = struct.pack('<Q', 99988480)
print('value = ', value.hex())
pk_script = bytes.fromhex('76a9141d7cd6c75c2e86f4cbf98eaed221b30bd9a0b92888ac')
pk_script_bytes = bytes.fromhex('%x' % len(pk_script))
outputs = value + pk_script_bytes + pk_script
print('outputs = ', outputs.hex())
hashOutputs = hash256(outputs)
nLockTime = bytes(4)
print('nLockTime = ', nLockTime.hex())
sigHash = bytes.fromhex('01000000')
print('sigHash = ', sigHash.hex())

msg = (
  version
  + hashPrevouts
  + hashSequence
  + outpoint
  + scriptcode_bytes
  + scriptcode
  + amount
  + sequence
  + hashOutputs
  + nLockTime
  + sigHash
)

print('msg = ', msg.hex())

msg_h = hash256(msg)

print('msg_h = ', msg_h.hex())

pubkey_b = bytes.fromhex('038262a6c6cec93c2d3ecd6c6072efea86d02ff8e3328bbd0242b20af3425990ac')
print('pubkey = ', pubkey_b.hex())

prefix = pubkey_b[0:1]
if prefix == b"\x02" or prefix == b"\x03":
    fullpubkey_b = getFullPubKeyFromCompressed(pubkey_b)[1:]
elif prefix == b"\x04":
    fullpubkey_b = pubkey_b[1:]
print('fullpubkey = ', fullpubkey_b.hex())

fullpubkey_b = bytes.fromhex('8262a6c6cec93c2d3ecd6c6072efea86d02ff8e3328bbd0242b20af3425990ac417d1cd70c8f0d829c1d4d46f37ef93d9862db4e0c9262a50876fdeb5e298c8d')
print('fullpubkey = ', fullpubkey_b.hex())


sig_b = bytes.fromhex('3045022100df7b7e5cda14ddf91290e02ea10786e03eb11ee36ec02dd862fe9a326bbcb7fd02203f5b4496b667e6e281cc654a2da9e4f08660c620a1051337fa8965f727eb191901')

rs_b = bytes.fromhex('df7b7e5cda14ddf91290e02ea10786e03eb11ee36ec02dd862fe9a326bbcb7fd3f5b4496b667e6e281cc654a2da9e4f08660c620a1051337fa8965f727eb1919')
print('rs = %s' % rs_b.hex())
rs_b = getRandSFromSig(sig_b)
print('rs = %s' % rs_b.hex())
vk = ecdsa.VerifyingKey.from_string(fullpubkey_b, curve=ecdsa.SECP256k1)
if vk.verify(rs_b, msg_h, hashlib.sha256) == True:
    print("Signature is Valid")
else:
    print("Signature is not Valid")

