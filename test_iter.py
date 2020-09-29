from itertools import tee
import copy

l = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

it = iter(l)
for i, x in enumerate(it):
    if x == 5:
        new_it = copy.copy(it)
        for j, y in enumerate(new_it):
            if y == 7:
                l.insert(6, 7)
                next(new_it)
            print('y', i+j+1, y)
    print('x', i, x)
