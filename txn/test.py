import json

with open('opcode.json', 'rt') as f:
    jo = json.load(f)

oo = {}
for x in jo:
    oo[jo[x]] = x

with open('opcode.mod.json', 'wt') as f:
    json.dump(oo, f, indent=4)
