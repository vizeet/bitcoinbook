import json

mempool = {}
with open('mempool.dat', 'rb') as m_f:
    print(m_f.read(200).hex())
#    mempool['version'] = int.from_bytes(m_f.read(8), 'little')
#    mempool['tx_count'] = int.from_bytes(m_f.read(8), 'little')

#    print(mempool)
#    tx_list = []
#    for i in range(mempool['tx_count']):
#        tx = {}
#        tx['timestamp'] = int.from_bytes(m_f.read(8), 'little')
#        tx['fee_delta'] = int.from_bytes(m_f.read(8), 'little')
#        print(tx)
#        exit()
#        tx_list.append(tx)
#
#    mempool['tx_id'] = tx_list
#
#    print(mempool)

