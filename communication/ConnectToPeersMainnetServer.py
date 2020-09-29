import socket
import time
import dns.name
import dns.message
import dns.query
import dns.flags
import netifaces as ni
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
import struct
import random
import hashlib
import datetime
import mmap
import json
import ipaddress
import threading

rpc_connection = AuthServiceProxy("http://%s:%s@127.0.0.1:8332"%('test', 'test'))

def getLastBlockHeight():
    height = rpc_connection.getblockcount()
    return height

def getNodeAddresses(dnsseed: str):
    dest = '8.8.8.8'
    rdclass = 65535

    domain = dns.name.from_text(dnsseed)
    if not domain.is_absolute():
        domain = domain.concatenate(dns.name.root)

    request = dns.message.make_query(domain, dns.rdatatype.A, dns.rdataclass.IN)
    request.flags |= dns.flags.RD|dns.flags.RA|dns.flags.AD
    request.find_rrset(request.additional, dns.name.root, rdclass,
                       dns.rdatatype.OPT, create=True, force_unique=True)
    responseudp = dns.query.udp(request, dest)

    rrset = responseudp.answer

    rrset_l = []
    for rrset_val in rrset:
        rrset_l.extend(str(rrset_val).split("\n"))

    ipaddr_l = []
    for rrset_s in rrset_l:
        ipaddr_l.append(rrset_s.split(" ")[4])

    return ipaddr_l
 
def getMainnetPeers():
    port = 8333
    dns_seeds = [
            "seed.bitcoin.sipa.be",
            "dnsseed.bluematt.me",
            "dnsseed.bitcoin.dashjr.org",
            "seed.bitcoinstats.com",
            "seed.bitcoin.jonasschnelli.ch",
            "seed.btc.petertodd.org",
            "seed.bitcoin.sprovoost.nl",
            "dnsseed.emzy.de",
            "seed.bitcoin.wiz.biz"
    ]

    ipaddr_l = []
    for seed in dns_seeds:
        ipaddr_l.extend(getNodeAddresses(seed))

    peers = []
    for ipaddr in ipaddr_l:
        peers.append((ipaddr, port))

    return peers

def createRecvIPAddress(ip, port):
    service_b = struct.pack('>8s', b'\x01')
    ipv6addr_b = struct.pack('>16s', bytearray.fromhex("00000000000000000000ffff") + socket.inet_aton(ip))
    port_b = struct.pack('>H', port)
#    address_b = struct.pack('>8s16sH', b'\x01',
#        bytearray.fromhex("00000000000000000000ffff") + socket.inet_aton(ip), port)
    addr_b = service_b + ipv6addr_b + port_b
    return(addr_b)

def createTransIPAddress():
    service_b = struct.pack('>8s', b'\x01')
    ipv6addr_b = struct.pack('>16s', bytearray.fromhex("000000000000000000000000") + socket.inet_aton("0.0.0.0"))
    port_b = struct.pack('>H', 0)
#    address_b = struct.pack('>8s16sH', b'\x01',
#        bytearray.fromhex("000000000000000000000000") + socket.inet_aton("0.0.0.0"), 0)
    addr_b = service_b + ipv6addr_b + port_b
    return(addr_b)

def createUserAgent():
    sub_version = "/Satoshi:0.7.2/"
    return b'\x0F' + sub_version.encode()

def createVersionMessage(peer_ip, s):
    version_b = struct.pack('<L', 70015)
    services_b = struct.pack('<Q', 1)
    timestamp_b = struct.pack('<Q', int(time.time()))
    myip, myport = s.getsockname()
    addr_recv_b = struct.pack('<26s', createRecvIPAddress(myip, myport))
    addr_trans_b = struct.pack('<26s', createTransIPAddress())
    nonce_b = struct.pack('<Q', random.getrandbits(64))
    user_agent = createUserAgent()
    user_agent_b = struct.pack('<%ds' % len(user_agent), user_agent)
    start_height_b = struct.pack('<L', getLastBlockHeight())
#    payload = struct.pack('<LQQ26s26sQ16sL', version, services, timestamp, addr_recv,
#                          addr_trans, nonce, user_agent, start_height)
    payload = version_b + services_b + timestamp_b + addr_recv_b + addr_trans_b + nonce_b + user_agent_b + start_height_b
    return payload;

def createMessage(magic, command, payload):
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[0:4]
    magic_b = struct.pack('<L', magic)
    cmd_b = struct.pack('<12s', command.encode('ascii'))
    payload_len_b = struct.pack('<L', len(payload))
    checksum_b = struct.pack('<4s', checksum)

    msg = magic_b + cmd_b + payload_len_b + checksum + payload

#    return(struct.pack('<L12sL4s', magic, command.encode(), len(payload), checksum) + payload)
    return msg

def sendVersion(s: socket):
    host, port = s.getpeername()
    print('host = %s' % host)
    vermsg = b''
    try:
        payload = createVersionMessage(host, s)
        print(vermsg.hex())
    except Exception as e:
        print('Exception closed because of ', e.message)
        s.close()
    magic = 0xD9B4BEF9
    command = 'version'
    msg = createMessage(magic, command, payload)
    print('sent_msg = %s' % msg.hex())

    buffer_size = 1024
    s.send(msg)
    response_data = s.recv(buffer_size)
    print('response = %s' % response_data.hex())
    return response_data

def getVarInt(m: mmap):
    b_cnt_d = {'fd': 2, 'fe': 4, 'ff': 8}
    prefix = int.from_bytes(m.read(1), byteorder='little')
    if prefix < 0xFD:
        return prefix
    else:
        b_cnt = b_cnt_d['%x' % prefix]
        size = int.from_bytes(m.read(b_cnt), byteorder='little')
        return size

def parseIPAddress(ip_m: mmap):
    addr = {}
    addr['services'] = ip_m.read(8).hex()
    ip = ip_m.read(16)
    if ip[0:12].hex() == "00000000000000000000ffff":
        addr['version'] = 'IPv4'
        addr['address'] = str(ipaddress.IPv4Address(ip[12:16]))
    else:
        addr['version'] = 'IPv6'
        addr['address'] = str(ipaddress.IPv6Address(ip[0:16]))
    addr['port'] = int.from_bytes(ip_m.read(2), byteorder='big')
    return addr

def parseVersionMessage(payload_m: mmap, size: int):
    msg = {}
    start = payload_m.tell()
    msg['version'] = int.from_bytes(payload_m.read(4), byteorder='little')
    msg['services'] = int.from_bytes(payload_m.read(8), byteorder='little')
    msg['timestamp'] = int.from_bytes(payload_m.read(8), byteorder='little')
    msg['dt'] = datetime.datetime.fromtimestamp(msg['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
    msg['addr_recv'] = parseIPAddress(payload_m)
    msg['addr_trans'] = parseIPAddress(payload_m)
    msg['nonce'] = int.from_bytes(payload_m.read(8), byteorder='little')
    msg['user_agent_size'] = getVarInt(payload_m)
    msg['user_agent'] = payload_m.read(msg['user_agent_size'])
    msg['block_height'] = int.from_bytes(payload_m.read(4), byteorder='little')
    if payload_m.tell() - start != size:
        msg['relay'] = int.from_bytes(payload_m.read(1), byteorder='little')
    return msg

def calculateChecksum(b: bytes):
    checksum = hashlib.sha256(hashlib.sha256(b).digest()).digest()[0:4]
    return checksum

connects_g = {}

def parseResponse(data_m: mmap, reslen: int):
    global connects
    res = {}
    res['magic'] = data_m.read(4)[::-1].hex()
    res['command'] = data_m.read(12).decode("ascii").strip('\0')
    res['length'] = int.from_bytes(data_m.read(4), byteorder='little')
    res['checksum'] = data_m.read(4)
    start = data_m.tell()

    if res['magic'] == 'd9b4bef9':
        print('Magic check passed')
    else:
        print('Magic check failed')
        print('magic = %s' % res['magic'])
        raise Exception('Invalid Magic')

    if res['length'] <= reslen:
        print('Length check passed')
    else:
        print('Length check failed')
        print('expected length = %d' % res['length'])
        print('received length = %d' % (reslen - start))
        raise Exception('Invalid Message Length')

    checksum_calc = calculateChecksum(data_m.read(res['length']))
    if res['checksum'] == checksum_calc:
        print('checksum check passed')
    else:
        print('checksum check failed')
        print('expected checksum = %s' % res['checksum'].hex())
        print('received checksum = %s' % checksum_calc.hex())
        raise Exception('Invalid Checksum')

    if res['command'] == 'version':
        data_m.seek(start)
        res['version'] = parseVersionMessage(data_m, res['length'])

        # set connection information
        address = res['version']['addr_recv']['address']
        connects_g[address] = {}
        connects_g[address]['command'] = 'version'
        connects_g[address]['services'] = res['version']['addr_trans']['services']
        connects_g[address]['block_height'] = res['version']['block_height']
        if 'relay' in res['version']:
            connects_g[address]['relay'] = res['version']['relay']
    return res

def sendVerack(s: socket):
    pass

def connectedClient(clientsocket,addr):
    while True:
        msg = clientsocket.recv(1024)
        clientsocket.send(msg)
    clientsocket.close()

def createServerSocket():
    s = socket.socket()
    host = socket.gethostname()
    port = 8333

    s.bind((host, port))
    s.listen(5)
    while True:
       c, addr = s.accept()
       thread.start_new_thread(connectedClient,(c,addr))
    s.close()

sock_clients = []

def connectedServer(s):
    try:
        resdata = sendVersion(s)
        reslen = len(resdata)
        resdata_m = mmap.mmap(-1, reslen + 1)
        resdata_m.write(resdata)
        resdata_m.seek(0)
        res = parseResponse(resdata_m, reslen)
    finally:
        ip, _ = s.getpeername()
        if ip in connects_g:
            del(connects_g[ip])
        s.close()

def createClientSocket(peers: list):
    global sock_clients
    for p in peers:
        try:
            print("Trying to connect to ", p)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(p)
            socket_l.append(s)
            thread.start_new_thread(connectedServer, s)
        except socket.error as e:
            print("Error while connecting : %s" % e)
            continue
    return None

if __name__ == '__main__':
    peers = getMainnetPeers()
    createServerSocket()
    createClientSocket(peers)
