##########
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
##########

from optparse import OptionParser
import json
import sign_raw_txn
import mnemonic_code
import os
import tkinter
import hd_wallet
import time
from bitcoinutils.setup import setup
from bitcoinutils.script import Script
from bitcoinutils.keys import P2wpkhAddress, P2wshAddress, P2shAddress, PrivateKey, PublicKey

setup('mainnet')

transfer_info_map_g = {
        'regtest': 'transfer_info_regtest',
        'mainnet': 'transfer_info'
}

# Example mnenomic code
#mnemonic_code_s = "ill virus lottery repair poem injury filter mammal play erase gym camera"
entries_g = []
message_g = []
key_selector_first_g = ''
key_selector_last_g = ''

def on_button(y, entry, toplevel):
        global entries_g, message_g

        word_list = mnemonic_code.getMnemonicWordList()

        #print("%d: %s" % (y, entry.get()))
        entries_g[y] = entry.get()
        if entries_g[y] in word_list:
                message_g[y].set('%d:correct' % (y+1))
        else:
                message_g[y].set('%d:wrong' % (y+1))
        toplevel.destroy()
 
def callback2(test_message):
        global entries_g

        #print('entries = %s' % entries)
        joined_word_key_list = ' '.join(entries_g)
        is_valid = mnemonic_code.verifyMnemonicWordCodeString(joined_word_key_list)
#        print('is valid = %r' % is_valid)
        if is_valid:
                test_message.set("Correct")
        else:
                test_message.set("Wrong")

def callback(y: int):
        toplevel = tkinter.Toplevel()
        toplevel.title('%d' % (y + 1))
        message = tkinter.StringVar()
        entry = tkinter.Entry(toplevel, textvariable=message, width=20)
        button = tkinter.Button(toplevel, text="Get", command=lambda y=y, entry=entry, toplevel=toplevel: on_button(y, entry, toplevel))
        entry.pack()
        button.pack()

def on_button_selector(e1, e2, root):
        global key_selector_first_g, key_selector_last_g

        key_selector_first_g = str(e1.get()).replace(' ', '')
        key_selector_last_g = str(e2.get()).replace(' ', '')
        root.destroy()

        if key_selector_first_g[0:2] != 'm/' or key_selector_last_g[0:2] != 'm/' or key_selector_first_g.rsplit('/', 1)[0] != key_selector_last_g.rsplit('/', 1)[0]:
                print('Invalid selectors')

def wallet_ui(salt: str, network: str):
        global entries_g, message_g, key_selector_first_g, key_selector_last_g, tkvar_g

        top = tkinter.Toplevel()
        top.title("Hierarchical Deterministic Wallet")

        testvar = tkinter.StringVar()
        testvar.set("Test")
        get = tkinter.Button(top, textvariable=testvar, command=lambda:callback2(testvar))

        for y in range(0,12):
                entries_g.append('')
                message_g.append(tkinter.StringVar())
                message_g[y].set('%d:unset' % (y+1))
                b = tkinter.Button(textvariable=message_g[y],   command=lambda y=y: callback(y))
                b.grid(row=0,column=y)
        get.pack()

        top.mainloop()

        wallet = hd_wallet.HDWallet(salt)

        mnemonic_code_str = " ".join(entries_g)
#        print('is valid = %r' % mnemonic_code.verifyMnemonicWordCodeString(mnemonic_code_str))

        seed_b = wallet.generateSeedFromStr(mnemonic_code_str, "mnemonic" + wallet.salt)

        root = tkinter.Tk()
        tkinter.Label(root, text="Access Key First:").grid(row=0)
        tkinter.Label(root, text="Access Key Last").grid(row=1)
        tkinter.Label(root, text="Choose Crypto").grid(row = 2, column = 1)

        tkvar_g = tkinter.StringVar(root)

        choices = { 'bitcoin', 'litecoin'}
        tkvar_g.set('bitcoin') # set the default option

        e1 = tkinter.Entry(root)
        e2 = tkinter.Entry(root)
        popupMenu = tkinter.OptionMenu(root, tkvar_g, *choices)

        e1.grid(row=0, column=1)
        e2.grid(row=1, column=1)
        popupMenu.grid(row = 3, column =1)

        tkinter.Button(root, text='Get', command=lambda e1=e1, e2=e2, root=root: on_button_selector(e1, e2, root)).grid(row=5, column=1, sticky=tkinter.W, pady=4)

        tkvar_g.trace('w', change_dropdown)

        root.mainloop()

        return seed_b, wallet

# on change dropdown value
def change_dropdown(*args):
        global tkvar_g
        print( tkvar_g.get() )

def verify_address_list(seed_b: bytes, wallet):
        global file_path_g, key_selector_first_g, key_selector_last_g, tkvar_g

        with open(file_path_g, 'rt') as transfer_info_f:
                jsonobj = json.load(transfer_info_f)

        address_privkey_map = wallet.getAddressPrivkeyMap(seed_b, key_selector_first_g, key_selector_last_g)

        status = True
 
        for address, privkey_wif in address_privkey_map.items():
                addr = PrivateKey.from_wif(privkey_wif).get_public_key().get_segwit_address()
                shaddr = P2shAddress.from_script(addr.to_script_pub_key())
                if address == shaddr.to_string():
                        print("address = %s, derived_address = %s, wif = %s, Matched" % (address, shaddr.to_string(), privkey_wif))
                else:
                        status = False
                        print("address = %s, derived_address = %s, wif = %s, Unmatched" % (address, shaddr.to_string(), privkey_wif))

        if status == False:
                print('Failed')
        else:
                print('Success')

def generate_signed_transaction(seed_b: bytes, wallet):
        global file_path_g, key_selector_first_g, key_selector_last_g, tkvar_g

        with open(file_path_g, 'rt') as transfer_info_f:
                jsonobj = json.load(transfer_info_f)

        address_privkey_map = wallet.getAddressPrivkeyMap(seed_b, key_selector_first_g, key_selector_last_g)

        jsonobj = sign_raw_txn.return_signed_txn(jsonobj, address_privkey_map, wallet.getNetwork(), tkvar_g.get())

        with open(file_path_g, 'wt') as transfer_info_f:
                json.dump(jsonobj, transfer_info_f)

def generate_address_list(seed_b: bytes, wallet):
        global file_path_g, key_selector_first_g, key_selector_last_g

        if os.path.isfile(file_path_g):
                with open(file_path_g, 'rt') as transfer_info_f:
                        jsonobj = json.load(transfer_info_f)
        else:
                jsonobj = {}

        jsonobj['Addresses'] = wallet.get_addresses(seed_b, key_selector_first_g, key_selector_last_g)

        with open(file_path_g, 'wt') as transfer_info_f:
                json.dump(jsonobj, transfer_info_f)

if __name__ == '__main__':
        parser = OptionParser()
        parser.add_option("-t", "--test",
                  action="store_true", dest="test",
                  help="Execute in Test Mode")
        (options, _) = parser.parse_args()

        if options.test:
                config_filename = 'hd_wallet_regtest.conf'
        else:
                config_filename = 'hd_wallet.conf'

        with open(os.path.join(os.getenv('WALLET_HOME'), 'config', config_filename), 'rt') as conf_f:
                jsonobj = json.load(conf_f)
                network = jsonobj['network']
                datadir = jsonobj['datadir']
                salt = jsonobj['salt']

        seed_b, wallet = wallet_ui(salt, network)

        wallet.setCrypto(network, tkvar_g.get())

        user = input('Username: ').lower()

        file_path_g = os.path.join(datadir, '%s.%s.%s.json' % (transfer_info_map_g[network], tkvar_g.get(), user))
 
        print('1:\tGenerate Addresses')
        print('2:\tSign Transaction')
        print('3:\tVerify Addresses')

        choice = int(input('Selection:'))

        if choice == 1:
                generate_address_list(seed_b, wallet)
        elif choice == 2:
                generate_signed_transaction(seed_b, wallet)
        elif choice == 3:
                verify_address_list(seed_b, wallet)
        else:
                print('Invalid choice')
