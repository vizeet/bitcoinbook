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
    df = pd.read_csv("../metrics/bitcoinmetrics.csv")
    df['date_time'] = pd.to_datetime(df['date_time'])
    df = df.iloc[::-1]
    return df

def updateDF(df: DataFrame):
    df['gap_sec'] = df['timestamp'] - df['timestamp'].shift(1)
    df = df.dropna()
    df = df[df.gap_sec != 0]
#    df['gap_sec'] = df['date_diff'].dt.seconds.astype(int)
#    df['gap_sec'] = df['date_diff']/ pd.Timedelta(seconds=1)
#    print(df['gap_sec'])
#    df['tx_rate'] = df['tx_count'] / df['gap_sec']
    df['tx_rate'] = df.apply(lambda x: x['tx_count']/x['gap_sec'], axis=1)
#    print(df.to_string())
    return df

def windowDF(df: DataFrame):
    df['tx_rate_avg'] = df['tx_rate'].rolling(2016).mean()
#    print(df.to_string())
    return df

if __name__ == '__main__':
    df = importDF()
    df = updateDF(df)
    df = windowDF(df)
#    fig = px.line(df, x='date_time', y='tx_rate_avg')
    fig = px.line(df, x = 'date_time', y="tx_rate_avg", labels={
                     "date_time": "Date",
                     "tx_rate_avg": "Average Transactions per second"
                 }, title='Bitcoin Average Transactions per Second')
    fig.update_layout(font=dict(size=20), hoverlabel=dict(font_size=20))
    fig.update_xaxes(
        tickvals=['2010', '2011', '2012', '2013', '2014', '2015', '2016', '2017', '2018', '2019', '2020', '2021'],
        tickformat="%Y")

#    fig.update_layout(title_text="Bitcoin", title_x=0.5)
#    fig.update_xaxes(title_text="Year")
    fig.show()
