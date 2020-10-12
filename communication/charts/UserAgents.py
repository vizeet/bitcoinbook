import ipaddress
import plotly.express as px
import pandas as pd
import requests
from urllib.parse import urlparse

url = 'https://bitnodes.io/api/v1/snapshots/latest/'
headers = {'Accept': 'application/json'}
r = requests.get(url=url, headers=headers)
jsonobj = r.json()

df = pd.DataFrame.from_dict(jsonobj['nodes'], orient='index', columns=[ 'Protocol version', 'User agent', 'Connected since', 'Services', 'Height', 'Hostname', 'City', 'Country code', 'Latitude', 'Longitude', 'Timezone', 'ASN', 'Organization name' ])
df = df.groupby('User agent').size().to_frame('count')
#fig = px.pie(df, values='count', names=df.index, title='User Agent')
#fig = px.pie(df, values='count', names=df.index)
fig = px.bar(df, x=df.index, y='count')

fig.show()
