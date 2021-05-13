import plotly.express as px
import pandas as pd

file_path = '../metrics/Cryptocurrency regulation.csv'
df = pd.read_csv(file_path)
df = df.replace({'Regulation': {0: 'Unknown', 1: 'Permissive', 2: 'Restrictive', 3: 'Contentious', 4: 'Prohibitive'}})


fig = px.choropleth(locations=df['Country'], 
                    locationmode="country names",
                    color=df['Regulation'],
                    color_discrete_map={'Unknown':'White',
                                        'Permissive':'Green',
                                        'Restrictive':'Orange',
                                        'Contentious': 'Grey',
                                        'Prohibitive': 'Red'}
                   )
fig.update_layout(font=dict(size=20))
fig.show()
