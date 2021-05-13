import plotly.express as px
import datetime
import pandas as pd
from pandas import DataFrame

def importDF():
    df = pd.read_csv("../metrics/bitcoinInvStat.csv")
    df['datetime_1'] = pd.to_datetime(df['unix_timestamp_1'], unit='ms')
    df['datetime_2'] = pd.to_datetime(df['unix_timestamp_2'], unit='ms')
    return df

def windowDF(df: DataFrame):
    df = df.set_index('datetime_1')
    df = df.resample('D').mean()
    df['90pct_blk_s_avg'] = df['90pct_blk_s'].rolling(14).mean()
    return df

def updateDF(df: DataFrame):
    df['90pct_blk_s'] = df.apply(lambda x: x['90pct_blk_ms']//1000, axis=1)
    return df


if __name__ == '__main__':
    df = importDF()
    df = updateDF(df)
    df = windowDF(df)
    fig = px.line(df, x=df.index, y="90pct_blk_s_avg", labels={
                        "datetime_1": "Year",
                        "90pct_blk_s_avg": "30-day Rolling Average for Time for Block to reach 90% Nodes"
                    }, title='Historic Bitcoin Block Propogation Delays')
    fig.update_layout(font=dict(size=18), hoverlabel=dict(font_size=20))
    fig.update_xaxes(
        tickvals=['2015', '2016', '2017', '2018', '2019', '2020', '2021'],
        tickformat="%Y")
    fig.update_yaxes(ticksuffix=' sec')

    fig.show()
