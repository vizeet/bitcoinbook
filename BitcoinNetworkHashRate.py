import plotly.express as px
import datetime
import pandas as pd
from pandas import DataFrame

def getTargetThreshold(bits: bytes):
    shift = bits[3]
    value = int.from_bytes(bits[0:3], byteorder='little')
    target_threshold = value * 2 ** (8 * (shift - 3))
    return target_threshold

def getNetworkHashRate(bits: bytes):
    target_threshold = getTargetThreshold(bits)
    network_hashrate = (1<<256)/(600*target_threshold)
    return network_hashrate

def importDF():
    df = pd.read_csv("metrics/bitcoinmetrics.csv")
    return df

def updateDF(df: DataFrame):
    df['Network Hashrate'] = df.apply(lambda x: getNetworkHashRate(bytes.fromhex(x['bits'])[::-1]), axis=1)
    return df

if __name__ == '__main__':
    df = importDF()
    df = updateDF(df)
#    df = getDfDatetimeBlockchainSize()
    fig = px.line(df, x='date_time', y='Network Hashrate')
    fig.update_layout(title_text="Bitcoin Network Hashrate", title_x=0.5)
##    fig.update_yaxes(title_text="Blockchain size", ticksuffix = 'GB')
#    fig.update_yaxes(title_text="Blockchain size(GB)")
    fig.update_xaxes(title_text="Year")
    fig.show()
