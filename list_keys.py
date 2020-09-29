import plyvel
import os
import binascii

txindex_db_g = plyvel.DB(os.getenv('TX_INDEX_DB'), compression=None)

blocks_path_g = os.getenv('BLOCKS_PATH')

for key in txindex_db_g.iterator(include_value=False):
    c = '%c' % key[0]
    if c != 't':
        print(key)

