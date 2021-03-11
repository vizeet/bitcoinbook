import json

def calculateTransactionFee(vsize: int, feerate: float):
    return feerate * vsize/1000


feerate = 0.00075062
vsize = 208
fee = calculateTransactionFee(vsize, feerate)
print('Estimated Minimum Fee in bitcoin = ', fee)
