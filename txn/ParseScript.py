import json

#with open('opcode.json', 'rt+') as opcode_f:
#    op_d = json.load(opcode_f)

op_d = {
    '76': 'OP_DUP', 
    'a9': 'OP_HASH160', 
    '88': 'OP_EQUALVERIFY', 
    '87': 'OP_EQUAL',
    'ac' : 'OP_CHECKSIG'
}

OP_PUSHDATA1 = 0x4c
OP_PUSHDATA2 = 0x4d
OP_PUSHDATA4 = 0x4f

g_pushdata = range(0x01, 0x4b)

def prepare_readable_script(script_b: bytes):
    script_sl = []
    script_len = script_b[0]
    script_b = script_b[1:]
    i = 0
    while i < script_len:
        if script_b[i] in g_pushdata:
            script_sl.append(script_b[i: i+1].hex())
            script_sl.append(script_b[i+1: i+script_b[i]+1][::-1].hex())
            i += 1 + script_b[i]
        elif script_b[i] == OP_PUSHDATA1:
            script_sl.append(op_d[script_b[i]])
            script_sl.append(script_b[i + 1: i + 2].hex())
            script_sl.append(script_b[i + 2: i + script_b[i] + 2][::-1].hex())
        elif script_b[i] == OP_PUSHDATA2:
            script_sl.append(op_d[script_b[i]])
            script_str_list.append(script_b[i + 1: i + 3].hex())
            data_size = int.from_bytes(script_b[i+1: i+3], byteorder='big')
            script_sl.append(script_b[i + 3: i + data_size + 3][::-1].hex())
        elif script_b[i] == OP_PUSHDATA4:
            script_sl.append(op_d[script_b[i]])
            script_sl.append(script_b[i + 1: i + 5].hex())
            data_size = int.from_bytes(script_b[i + 1: i + 5], byteorder='big')
            script_sl.append(script_b[i + 5: i + data_size + 5][::-1].hex())
        else:
            script_sl.append(op_d[script_b[i: i+1].hex()])
            i += 1
    script_str = ' '.join(script_sl)
    return script_str

if __name__ == '__main__':
    script_b = bytes.fromhex("1976a91461cf5af7bb84348df3fd695672e53c7d5b3f3db988ac")
    print(prepare_readable_script(script_b))
