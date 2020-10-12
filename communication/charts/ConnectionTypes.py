import ipaddress
import plotly.express as px
import pandas as pd
import requests
from urllib.parse import urlparse

def func(row):
    ip_port = row.name
    if row['ASN'] == 'TOR':
        return 'TOR'
    else:
        val = row.name.rsplit(':', 1)[0]
        parsed = urlparse('//{}'.format(val))
        addr = ipaddress.ip_address(parsed.hostname)
        if addr.version == 4:
            return 'IPv4'
        elif addr.version == 6:
            return 'IPv6'
    return 'Unclassified'

url = 'https://bitnodes.io/api/v1/snapshots/latest/'
headers = {'Accept': 'application/json'}
r = requests.get(url=url, headers=headers)
jsonobj = r.json()

df = pd.DataFrame.from_dict(jsonobj['nodes'], orient='index', columns=[ 'Protocol version', 'User agent', 'Connected since', 'Services', 'Height', 'Hostname', 'City', 'Country code', 'Latitude', 'Longitude', 'Timezone', 'ASN', 'Organization name' ])
df['Type'] = df.apply(func, axis=1)
df = df.groupby('Type').size().to_frame('count')
print(df)
fig = px.bar(df, x=df.index, y='count')
fig.update_layout(title_text="Types of Network Connections", title_x=0.5)
fig.show()

#fig = px.scatter_geo(df, locations='code',
##                     color="continent", # which column to use to set the color of markers
#                     hover_name="Country", # column added to hover information
#                     size="count", # size of markers
#                     projection="natural earth")
#fig.update_layout(title_text="Global Bitcoin Node distribution", title_x=0.5)
#fig.show()
