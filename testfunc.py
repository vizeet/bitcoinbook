def f1(a:int):
    return a*a

def f2(a:int):
    return a+a

funcs = {'f1': f1, 'f2': f2}

v = funcs['f1'](10)
print(v)
