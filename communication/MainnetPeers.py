import requests
import socket

def isValidIPv4Addr(addr: str):
    try:
        socket.inet_pton(socket.AF_INET, addr)
    except socket.error:
            return False
    return True

def parseNodeInfo(ip_port: str, nodeinfo: dict):
    node = {}
    node['valid'] = True
    node['port'] = int(ip_port.split(':')[-1])
    addr = ip_port.split(':')[0]
    if isValidIPv4Addr(addr) == False:
        node['valid'] = False
        return node
    node['ipaddr'] = addr
    node['type'] = nodeinfo[11]
    node['time'] = nodeinfo[2]
    return node

def getMainnetPeers():
    port = 8333
    url = 'https://bitnodes.io/api/v1/snapshots/latest/'
    headers = {'Accept': 'application/json'}
    r = requests.get(url=url, headers=headers)
    jsonobj = r.json()
    peers = []
    for k, v in jsonobj['nodes'].items():
        node = parseNodeInfo(k, v)
        if node['valid'] == True and node['port'] == 8333 and node['type'] != 'TOR':
            peers.append(node)
    return peers

peers = getMainnetPeers()
for peer in peers:
    print(peer['ipaddr'])
print(len(peers))
