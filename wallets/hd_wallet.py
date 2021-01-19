################
#MIT License
#
#Copyright (c) 2018 vizeet srivastava
#
#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.
################

import pubkey_address
import mnemonic_code
from utility_adapters import bitcoin_secp256k1, hash_utils
from utils import pbkdf2
import json
import binascii
import hashlib
import hmac
from ecdsa import SigningKey, SECP256k1
import os

class HDWallet:
        def __init__(self, salt: str):
                self.salt = salt

        def setCrypto(self, network: str, crypto: str):
                print('network = %s' % network)
                self.network = network
                self.crypto_utility = pubkey_address.CryptoUtility(network, crypto)

        def getNetwork(self):
                return self.network

        def generateSeedFromStr(self, code: str, salt: str):
                seed = pbkdf2.pbkdf2(hashlib.sha512, code, salt, 2048, 64)
                return seed

        def get_addresses(self, seed_b: bytes, key_selector_first: str, key_selector_last: str):
                addresses = []

                first = int(key_selector_first.rsplit('/', 1)[1])
                last = int(key_selector_last.rsplit('/', 1)[1])

                for index in range(first, last + 1):
                        key_selector = '%s/%d' % (key_selector_first.rsplit('/', 1)[0], index)
                        print('key_selector = %s' % key_selector)
                        privkey_i, chaincode = self.generatePrivkeyPubkeyPair(key_selector, seed_b, True)
                        privkey_wif = self.crypto_utility.privkey2Wif(privkey_i)
                        pubkey = bytes.decode(binascii.hexlify(chaincode))
                        hash160_b = hash_utils.hash160(chaincode)
                        script_b = b'\x00\x14' + hash160_b
                        hash160_script_b = hash_utils.hash160(script_b)
                        address = self.crypto_utility.sh2address(hash160_script_b)
#                        print('privkey = %s, pubkey = %s, hash160 = %s, script = %s, hash160_script = %s, address = %s' % (privkey_wif, pubkey, bytes.decode(binascii.hexlify(hash160_b)), bytes.decode(binascii.hexlify(script_b)), bytes.decode(binascii.hexlify(hash160_script_b)), address ))
                        addresses.append(address)

                return addresses

        def getAddressPrivkeyMap(self, seed_b: bytes, key_selector_first: str, key_selector_last: str):
                address_privkey_map = {}

                first = int(key_selector_first.rsplit('/', 1)[1])
                last = int(key_selector_last.rsplit('/', 1)[1])

                for index in range(first, last + 1):
                        key_selector = '%s/%d' % (key_selector_first.rsplit('/', 1)[0], index)
                        print('key_selector = %s' % key_selector)
                        privkey_i, chaincode = self.generatePrivkeyPubkeyPair(key_selector, seed_b, True)
                        privkey_wif = self.crypto_utility.privkey2Wif(privkey_i)
                        pubkey = bytes.decode(binascii.hexlify(chaincode))
                        hash160_b = hash_utils.hash160(chaincode)
                        script_b = b'\x00\x14' + hash160_b
                        hash160_script_b = hash_utils.hash160(script_b)
                        address = self.crypto_utility.sh2address(hash160_script_b)
                        address_privkey_map[address] = privkey_wif

                return address_privkey_map

        def generateChildAtIndex(self, privkey: int, chaincode: bytes, index: int):
                if index >= (1<<31):
                        # hardened
                        #print('hardened')
                        h = hmac.new(chaincode, b'\x00' + binascii.unhexlify('%064x' % privkey) + binascii.unhexlify('%08x' % index), hashlib.sha512).digest()
                else:
                        # normal
                        privkey_s = '%064x' % privkey
                        privkey_b = binascii.unhexlify(privkey_s)
                        sk = SigningKey.from_string(privkey_b, curve=SECP256k1)
                        vk = sk.get_verifying_key()

                        full_pubkey_b = b'\x04' + vk.to_string()
                        pubkey = self.crypto_utility.compressPubkey(full_pubkey_b)
                        h = hmac.new(chaincode, pubkey + binascii.unhexlify('%08x' % index), hashlib.sha512).digest()
                childprivkey = (int(binascii.hexlify(h[0:32]), 16) + privkey) % bitcoin_secp256k1.N
                child_chaincode = h[32:64]
                return childprivkey, child_chaincode

        def generateMasterKeys(self, seed: bytes):
                h = hmac.new(bytes("Bitcoin seed", 'utf-8'),seed, hashlib.sha512).digest()
                private_key = int(binascii.hexlify(h[0:32]), 16)
                chaincode = h[32:64]
                return private_key, chaincode

        def generatePrivkeyPubkeyPair(self, keypath: str, seed: bytes, compressed: bool):
                keypath_list = keypath.replace(' ', '').split('/')
                if keypath_list[0] != 'm':
                        return None
                for key in keypath_list:
                        if key == 'm':
                                privkey, chaincode = self.generateMasterKeys(seed)
                        else:
                                if "'" in key:
                                        index = int(key[:-1]) + (1<<31)
                                else:
                                        index = int(key)
                                privkey, chaincode = self.generateChildAtIndex(privkey, chaincode, index)
                privkey_s = '%064x' % privkey
                privkey_b = binascii.unhexlify(privkey_s)
                sk = SigningKey.from_string(privkey_b, curve=SECP256k1)
                vk = sk.get_verifying_key()

                full_pubkey_b = b'\x04' + vk.to_string()
                pubkey = self.crypto_utility.compressPubkey(full_pubkey_b)
                return privkey, pubkey

