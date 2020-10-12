import requests
import socket

def parseNodeInfo(ip_port: str, nodeinfo: dict):
    node = {}
    node['port'] = int(ip_port.split(':')[-1])
    addr = ip_port.split(':')[0]
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
        if node['type'] == 'TOR':
            peers.append(node)
    return peers

if __name__ == '__main__':
    peers = getMainnetPeers()
    for peer in peers:
        print(peer)
