import pycountry
import plotly.express as px
import pandas as pd
import requests

def rowFunc(row):
    country = pycountry.countries.get(alpha_2=row.name)
    return country.name

def rowFunc2(row):
    country = pycountry.countries.get(alpha_2=row.name)
    return country.alpha_3

url = 'https://bitnodes.io/api/v1/snapshots/latest/'
headers = {'Accept': 'application/json'}
r = requests.get(url=url, headers=headers)
jsonobj = r.json()

df = pd.DataFrame.from_dict(jsonobj['nodes'], orient='index', columns=[ 'Protocol version', 'User agent', 'Connected since', 'Services', 'Height', 'Hostname', 'City', 'Country code', 'Latitude', 'Longitude', 'Timezone', 'ASN', 'Organization name' ])

df = df.groupby('Country code').size().to_frame('count')
df['Country'] = df.apply(rowFunc, axis=1)
df['code'] = df.apply(rowFunc2, axis=1)
print(df)
fig = px.scatter_geo(df, locations='code',
#                     color="continent", # which column to use to set the color of markers
                     hover_name="Country", # column added to hover information
                     size="count", # size of markers
                     projection="natural earth")
fig.update_layout(title_text="Global Bitcoin Node distribution", title_x=0.5)
fig.show()
