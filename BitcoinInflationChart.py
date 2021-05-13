import plotly.express as px
import datetime
import pandas as pd
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

rpc_connection = AuthServiceProxy("http://%s:%s@127.0.0.1:8332"%('test', 'test'), timeout = 120)

init_block_reward = 50
final_bitcoin_in_circulation = 21000000

SANTOSIS_IN_BTC = 10**8
BLOCK_REWARD_HALVING = 210000
BLOCK_REWARD_1 = 50 * SANTOSIS_IN_BTC

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

def getBitcoinsInCirculation(block_height: int):
    block_halving_count = int(block_height / BLOCK_REWARD_HALVING)
    block_reward = BLOCK_REWARD_1 / SANTOSIS_IN_BTC
    bitcoin_in_circulation = 0
    for block_halfing_index in range(block_halving_count):
        bitcoin_in_circulation += (BLOCK_REWARD_HALVING * block_reward)
        block_reward = block_reward / 2
    bitcoin_in_circulation += (block_height % BLOCK_REWARD_HALVING) * block_reward
    return bitcoin_in_circulation

def getDateTime(block_height: int):
        current_block_height = getCurrentBlockHeight()
        if block_height < current_block_height:
            block = getBlock(block_height)
            date_time = datetime.datetime.fromtimestamp(block['mediantime']).strftime('%Y-%m-%d %H:%M:%S')
        else:
            current_block = getBlock(current_block_height)
            min_from_current = 10 * (block_height - current_block_height)
            dt = datetime.datetime.fromtimestamp(current_block['mediantime']) + datetime.timedelta(minutes = min_from_current)
            date_time = dt.strftime('%Y-%m-%d %H:%M:%S')
        return date_time

def getDfDateTimeInflation():
    df = pd.DataFrame(columns=['Date', 'Inflation'])
    for i in range(1, 1200001, 10000):
        print(i)
        date_time = getDateTime(i)
        bitcoin_in_circulation = getBitcoinsInCirculation(i)
        percent_mined = (bitcoin_in_circulation * 100) / final_bitcoin_in_circulation 
        df = df.append({'Date': date_time, 'Inflation': percent_mined}, ignore_index=True)

    return df

if __name__ == '__main__':
    df = getDfDateTimeInflation()
    fig = px.line(df, x='Date', y='Inflation')
    fig.update_layout(
        title_text="Bitcoin Inflation Rate",
        title_x=0.5, font=dict(size=20), hoverlabel=dict(font_size=20))
    fig.update_yaxes(title_text="Bitcoin Mined", ticksuffix = '%')
    fig.update_xaxes(
        title_text="Year",
#        tickvals=['2009', '2010', '2011', '2012', '2013', '2014', '2015', '2016', '2017', '2018', '2019', '2020', '2021'],
        tickformat="%Y")
    fig.show()
