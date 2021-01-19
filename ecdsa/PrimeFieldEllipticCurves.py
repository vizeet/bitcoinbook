import plotly.express as px

def drawPrimeFieldEC(p: int, a: int, b: int):
    x_l = []
    y_l = []
    for x in range(100000000):
        y_m = pow(x**3 + a*x + b, 0.5) % p
        if y_m.is_integer():
            y_l.append(y_m)
            y_p = (p/2 + (p/2 - y_m)) % p
            y_l.append(y_p)
            x_l.append(x % p)
            x_l.append(x % p)
            print(x, y_m, y_p)

    fig = px.scatter(x=x_l, y=y_l)
    fig.show()


#drawPrimeFieldEC(19, -7, 10)
drawPrimeFieldEC(487, -7, 10)
