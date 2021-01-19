import ecdsa
import hashlib
import binascii

def getFullPubKeyFromCompressed(x_str: str):
        prefix = x_str[0:2]
        print("prefix = %s" % (prefix))
        x_str = x_str[2:]
        x = int(x_str, 16)
        print("x = %x" % (x))
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        y_square = (pow(x, 3, p)  + 7) % p
        y_square_square_root = pow(y_square, ((p+1) >> 2), p)
        print('y_sq_sqrt = %x' % y_square_square_root)
#        if (prefix == b"\x02" and y_square_square_root & 1) or (prefix == b"\x03" and not y_square_square_root & 1):
#            y = (-y_square_square_root) % p
#        else:
#            y = y_square_square_root
        y = y_square_square_root
        
        y_str = "%x" % y
        print("y_str = %s" % (y_str))
        y_is_even = (int(y_str[-1], 16) % 2 == 0)
        if prefix == "02" and y_is_even == False or prefix == "03" and y_is_even == True:
                y = p - y
                y_str = "%x" % y
        print("y = %s" % (y_str))
        return "04" + x_str + y_str

#pubkey = "b726d7eae11a6d5cf3b2362e773e116a6140347dcee1b2943f4a2897351e5d903533a9823cfc90d0314e490e9989d7a4eac7de14867da251edb4e8451d6b8264"
#sig = "d8629403cd3b49950da9293653c6279149c029e6b7b15371342d0d2ce286c8f278787985a644e94fd9246f6c25733336c94af5f00d9d34a07dc2f9e0987ef990"
#txn_sha256 = "3d3b8997cc9c0e2275bd0f694b862f7d0bee4f7aee2456891e038322884070ad"

#pubkey = "02b726d7eae11a6d5cf3b2362e773e116a6140347dcee1b2943f4a2897351e5d90"
#sig = "d8629403cd3b49950da9293653c6279149c029e6b7b15371342d0d2ce286c8f278787985a644e94fd9246f6c25733336c94af5f00d9d34a07dc2f9e0987ef990"
#raw_txn = "01000000017f950ab790838e0c05e79856d25d586823fe139e1807405a3f207ff33f9b7663010000001976a914d5f950abe0b559b2b7a7ab3d18a507ea1c3e4ac688acffffffff021bf03c000000000017a91469f3757380a56820abc7052867216599e575cddd8777c1ca1c000000001976a914d5f950abe0b559b2b7a7ab3d18a507ea1c3e4ac688ac0000000001000000"

pubkey = "03cdc126cd2676890d54545d05b578c2b894c892baf3ec6a405466a451626f010f"
sig = "6174721d66fb173da5f913c86ff0026bcabd70a0c8a69a96b2f7c5d65d53aff310109aa9d9c2bcdbaf2b40d0d3a5a80ad3b73ae51ea3013198eafc49943c0db5"
raw_txn = "010000000267d4447e428a846e2d667ed62850f83e444e2d2d771e0d075d47384822596aac0100000000feffffffe675e3df015607bda31b588a4be919ff5accb3d6b904f38b733dd9bb5418d00c010000001976a91488ba173b1fb00f8dc527523f57eb1f296c84138c88acfeffffff02eac1a804000000001976a91449f120df2e9bb6564fe731de22aaf4e1248102a188ac7b214c01000000001976a91446b6b235d8dab4976410cac6d54d1f4fd5796ad688ac751a060001000000"


txn_sha256 = hashlib.sha256(bytes.fromhex(raw_txn)).digest().hex()

prefix = pubkey[0:2]
if prefix == "02" or prefix == "03":
        pubkey = getFullPubKeyFromCompressed(pubkey)[2:]
elif prefix == "04":
                pubkey = pubkey[2:]
print("full public key = %s" % pubkey)

sig_b = bytes.fromhex(sig)
txn_sha256_b = bytes.fromhex(txn_sha256)
vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(pubkey),curve=ecdsa.SECP256k1)
if vk.verify(sig_b, txn_sha256_b, hashlib.sha256) == True: # True
        print("Signature is Valid")
else:
        print("Signature is not Valid")
