import pandas as pd
import plotly.express as px


df = pd.read_csv("metrics/bitcoinmetrics.csv")

df['date_time'] =  pd.to_datetime(df['date_time'])
df = df.sort_values('date_time')
df['Blockchain Size Change Rate'] = df.rolling("365d", on='date_time')["block_size"].sum() / (1024*1024*1024)
print(df)

fig = px.line(df, x='date_time', y='Blockchain Size Change Rate')
fig.update_layout(
        title_text="Bitcoin Blockchain Size Change Rate (365 days rolling sum)", 
        title_x=0.5, font=dict(size=20), hoverlabel=dict(font_size=20))
#    fig.update_yaxes(title_text="Blockchain size", ticksuffix = 'GB')
fig.update_yaxes(title_text="Blockchain size(GB)")
fig.update_xaxes(
        title_text="Year",
        tickvals=['2009', '2010', '2011', '2012', '2013', '2014', '2015', '2016', '2017', '2018', '2019', '2020', '2021'],
        tickformat="%Y")

fig.show()

