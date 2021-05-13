import pandas as pd
import plotly.express as px
import orca


file_path = '../metrics/Bitcoin Historical Data - Investing.com India.csv'

df = pd.read_csv(file_path).iloc[::-1]
df['Date'] = pd.to_datetime(df.Date)
fig = px.line(df, x = 'Date', y="Price", labels={
                     "Price": "Price (USD)"
                 }, title='Bitcoin Historical Price Chart')
fig.update_layout(font=dict(size=20))
fig.update_xaxes(
    tickvals=['2010', '2011', '2012', '2013', '2014', '2015', '2016', '2017', '2018', '2019', '2020', '2021'],
    tickformat="%Y")
fig.show()
