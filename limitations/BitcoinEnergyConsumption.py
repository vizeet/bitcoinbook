import plotly.express as px
import datetime
import pandas as pd
from pandas import DataFrame
import plotly.graph_objects as go
from plotly.subplots import make_subplots

def importCSV():
    df = pd.read_csv("../metrics/CountrywiseAnnualEnergyConsumption.csv")
    df['Year'] = pd.to_datetime(df['Year'])
    df.loc[df.Country == 'United Arab Emirates', 'Country'] = 'UAE'
    df['EnergyConsumption'] = pd.to_numeric(df['EnergyConsumption']) // 1000
    df['current_btc_energy'] = 110
    df = df.sort_values(by = 'EnergyConsumption', ignore_index=True)
    df = df[df.EnergyConsumption > 50]
    row = ['', ''] + [0]*(len(df.columns)-3) + [110]
    row1 = [' ', ' '] + [-1000]*(len(df.columns)-3) + [110]
    newdf = pd.DataFrame([row, row1], columns=df.columns)
    df = df.append(newdf, ignore_index=True)
    print(df.to_string())
    return df

if __name__ == '__main__':
    df = importCSV()
    fig = px.line(df, x = "Country", y='current_btc_energy', title='Bitcoin Estimated Annual Power Consumption', labels={
                     "current_btc_energy": "BTC Mining Energy"
                 })
    fig.update_traces(line=dict(width=4))
    fig.add_bar(x=df.Country, y=df.EnergyConsumption, hovertemplate="Energy Consumption: %{y}")
    fig.update_layout(font=dict(size=17), hoverlabel=dict(font_size=20), hovermode = "x unified")
    fig.update_yaxes(ticksuffix=' TWh', tickvals=[0, 1000, 2000, 3000, 4000, 5000, 6000, 7000])

    fig.show()

