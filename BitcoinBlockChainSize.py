import plotly.express as px
import datetime
import pandas as pd
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

rpc_connection = AuthServiceProxy("http://%s:%s@127.0.0.1:8332"%('test', 'test'))

def getBlockHash(block_height: int):
        block_hash = rpc_connection.getblockhash(block_height)
        return block_hash

def getBlock(block_height: int):
        block_hash = getBlockHash(block_height)
        block = rpc_connection.getblock(block_hash)
        return block

def getCurrentBlockHeight():
        current_block_height = rpc_connection.getblockcount()
        return current_block_height

def getDateTimeAndSize(block_height: int):
        current_block_height = getCurrentBlockHeight()
        block = getBlock(block_height)
        size = block['size']
        date_time = datetime.datetime.fromtimestamp(block['mediantime']).strftime('%Y-%m-%d %H:%M:%S')
        return date_time, size

def getDfDatetimeBlockchainSize():
    h = getCurrentBlockHeight()

    df = pd.DataFrame(columns=['Date', 'Blockchain Size'])
    total_size = 0
    for i in range(1, h):
        print(i)
        date_time,size = getDateTimeAndSize(i)
        total_size += size
        gb = 1024*1024*1024
        df = df.append({'Date': date_time, 'Blockchain Size': total_size//gb}, ignore_index=True)

    return df

if __name__ == '__main__':
    df = getDfDatetimeBlockchainSize()
    fig = px.line(df, x='Date', y='Blockchain Size')
    fig.update_layout(title_text="Bitcoin Blockchain Size", title_x=0.5)
#    fig.update_yaxes(title_text="Blockchain size", ticksuffix = 'GB')
    fig.update_yaxes(title_text="Blockchain size(GB)")
    fig.update_xaxes(title_text="Year")
    fig.show()
