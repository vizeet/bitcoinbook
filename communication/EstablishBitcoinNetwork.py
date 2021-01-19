import socket
import time
import dns.name
import dns.message
import dns.query
import dns.flags
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
import struct
import random
import hashlib
import datetime
import mmap
import json
import ipaddress
import threading

rpc_connection = AuthServiceProxy("http://%s:%s@127.0.0.1:18332"%('test', 'test'))

flog = open('communication.log', 'wt+')

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
 
def getTestnetPeers():
    port = 18333
    dns_seeds = [
            "testnet-seed.bitcoin.jonasschnelli.ch",
            "seed.tbtc.petertodd.org",
            "seed.testnet.bitcoin.sprovoost.nl",
            "testnet-seed.bluematt.me"
    ]

    ipaddr_l = []
    for seed in dns_seeds:
        ipaddr_l.extend(getNodeAddresses(seed))

    peers = []
    for ipaddr in ipaddr_l:
        peers.append((ipaddr, port))

    return peers

def isValidIPv4Addr(addr: str):
    try:
        socket.inet_pton(socket.AF_INET, addr)
    except socket.error:
            return False
    return True

def createUserAgent():
    sub_version = "/MyTestAgent:0.0.1/"
    sub_version_b = sub_version.encode()
    len_b = setVarInt(len(sub_version_b))
    return len_b + sub_version_b

def createRecvIPAddress(ip, port):
    service_b = struct.pack('<Q', 1)
    ip_b = socket.inet_aton(ip)
    ipv4_to_ipv6 = bytearray.fromhex("00000000000000000000ffff") + ip_b
    ipv6addr_b = struct.pack('>16s', ipv4_to_ipv6)
    port_b = struct.pack('>H', port)
    addr_b = service_b + ipv6addr_b + port_b
    return(addr_b)

def createTransIPAddress():
    service_b = struct.pack('<Q', 1)
    ip_b = socket.inet_aton("0.0.0.0")
    ipv4_to_ipv6 = bytearray.fromhex("000000000000000000000000") + ip_b
    ipv6addr_b = struct.pack('>16s', ipv4_to_ipv6)
    port_b = struct.pack('>H', 0)
    addr_b = service_b + ipv6addr_b + port_b
    return(addr_b)

#def createUserAgent():
#    sub_version = "/Satoshi:0.7.2/"
#    return b'\x0F' + sub_version.encode()

def getVarInt(m: mmap):
    b_cnt_d = {'fd': 2, 'fe': 4, 'ff': 8}
    prefix = int.from_bytes(m.read(1), byteorder='little')
    if prefix < 0xFD:
        return prefix
    else:
        b_cnt = b_cnt_d['%x' % prefix]
        size = int.from_bytes(m.read(b_cnt), byteorder='little')
        return size

def setVarInt(n: int):
    if n < 0xfd:
        n_h = '%02x' % n
    elif n > 0xfd and n < 0xffff:
        n_h = 'fd%04x' % n
    elif n > 0xffff and n < 0xFFFFFFFF:
        n_h = 'fe%08x' % n
    else:
        n_h = 'ff%016x' % n
    return bytes.fromhex(n_h)

def parseIPAddress(ip_m: mmap):
    addr = {}
    addr['service'] = int.from_bytes(ip_m.read(8), byteorder='little')
    parseServices(addr['service'])
    ip = ip_m.read(16)
    if ip[0:12].hex() == "00000000000000000000ffff":
        addr['version'] = 'IPv4'
        addr['address'] = str(ipaddress.IPv4Address(ip[12:16]))
    else:
        addr['version'] = 'IPv6'
        addr['address'] = str(ipaddress.IPv6Address(ip[0:16]))
    addr['port'] = int.from_bytes(ip_m.read(2), byteorder='big')
    return addr

def calculateChecksum(b: bytes):
    checksum = hashlib.sha256(hashlib.sha256(b).digest()).digest()[0:4]
    return checksum

# message = header + payload
def checkMessage(msghdr: dict, payload_b: bytes):
    if msghdr['magic'] == '0709110b':
        print('Magic check passed', file=flog)
    else:
        print('Magic check failed', file=flog)
        print('payload = %s' % payload_b.hex(), file=flog)
        print('magic = %s' % msghdr['magic'], file=flog)
        raise Exception('Invalid Magic', file=flog)

    checksum_calc = calculateChecksum(payload_b)
    if msghdr['checksum'] == checksum_calc:
        print('checksum check passed', file=flog)
    else:
        print('checksum check failed', file=flog)
        print('payload = %s' % payload_b.hex(), file=flog)
        print('expected checksum = %s' % msghdr['checksum'].hex(), file=flog)
        print('received checksum = %s' % checksum_calc.hex(), file=flog)
        raise Exception('Invalid Checksum')

def parseServices(services: int):
    service_l = []
    if services == 0x00:
        service_l.append('Unnamed')
    if services & 0x01 == 0x01:
        service_l.append('NODE_NETWORK')
    if services & 0x02:
        service_l.append('NODE_GETUTXO')
    if services & 0x04:
        service_l.append('NODE_BLOOM')
    if services & 0x08:
        service_l.append('NODE_WITNESS')
    if services & 1024:
        service_l.append('NODE_NETWORK_LIMITED')
    print(service_l, file=flog)

def parseVersionPayload(payload_m: mmap, payloadlen: int):
    payload = {}
    start = payload_m.tell()
    payload['version'] = int.from_bytes(payload_m.read(4), byteorder='little')
    payload['services'] = int.from_bytes(payload_m.read(8), byteorder='little')
    parseServices(payload['services'])
    payload['timestamp'] = int.from_bytes(payload_m.read(8), byteorder='little')
    payload['dt'] = datetime.datetime.fromtimestamp(payload['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
    payload['addr_recv'] = parseIPAddress(payload_m)
    payload['addr_trans'] = parseIPAddress(payload_m)
    payload['nonce'] = int.from_bytes(payload_m.read(8), byteorder='little')
    payload['user_agent_size'] = getVarInt(payload_m)
    payload['user_agent'] = payload_m.read(payload['user_agent_size'])
    payload['block_height'] = int.from_bytes(payload_m.read(4), byteorder='little')
    if payload_m.tell() - start != payloadlen:
        payload['relay'] = int.from_bytes(payload_m.read(1), byteorder='little')
    return payload

CMD_FN_MAP = {
    'version': parseVersionPayload
}

def parseMsgHdr(msghdr_b: bytes):
    msghdr = {}
    msghdr['magic'] = msghdr_b[0:4][::-1].hex()
    msghdr['command'] = msghdr_b[4:16].decode("ascii").strip('\0')
    msghdr['length'] = int.from_bytes(msghdr_b[16:20], byteorder='little')
    msghdr['checksum'] = msghdr_b[20:24]
    return msghdr

def createMessage(command, payload):
    magic = 0x0709110B
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[0:4]
    magic_b = struct.pack('<L', magic)
    cmd_b = struct.pack('<12s', command.encode('ascii'))
    payload_len_b = struct.pack('<L', len(payload))
    checksum_b = struct.pack('<4s', checksum)

    msg = magic_b + cmd_b + payload_len_b + checksum + payload
    return msg

def getRandomPeer():
    peers = getTestnetPeers()
    peer = random.choice(peers)
    return peer

def createVersionPayload(s: socket):
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
    payload = version_b + services_b + timestamp_b + addr_recv_b + addr_trans_b + nonce_b + user_agent_b + start_height_b
    return payload

MSGHDR_SIZE = 24

def recvMsg(s: socket):
    global MSGHDR_SIZE, CMD_FN_MAP
    msghdr_b = s.recv(MSGHDR_SIZE)
    msg = parseMsgHdr(msghdr_b)
    payloadlen = msg['length']
    payload_b = s.recv(payloadlen)
    checkMessage(msg, payload_b)
    payload_m = mmap.mmap(-1, payloadlen + 1)
    payload_m.write(payload_b)
    payload_m.seek(0)
    msg['payload'] = {}
    if payloadlen > 0:
        msg['payload'] = CMD_FN_MAP[msg['command']](payload_m, payloadlen)
    print('<== msg = %s' % msg, file=flog)
    return msg

def sendVersionMessage(s: socket):
    sndcmd = 'version'
    payload = createVersionPayload(s)
    sndmsg = createMessage(sndcmd, payload)
    s.send(sndmsg)
    print('==> cmd = %s, msg = %s' % (sndcmd, sndmsg.hex()), file=flog)
    return True

def waitForVersion(s: socket):
    recvmsg = recvMsg(s)
    vers_recvd = False
    if recvmsg['command'] != 'version':
        print('Invalid Response')
        return False
    services = recvmsg['payload']['services']
    if services & 1 == 0x00:
        print('Peer is not full node')
        return False
    return True

def sendVerackMessage(s: socket):
    sndcmd = 'verack'
    payload = b''
    sndmsg = createMessage(sndcmd, payload)
    s.send(sndmsg)
    print('==> cmd = %s, msg = %s' % (sndcmd, sndmsg.hex()), file=flog)
    return True

def waitForVerack(s: socket):
    recvmsg = recvMsg(s)
    verack_recvd = False
    if recvmsg['command'] != 'verack':
        return False
    return True
        

def establishConnection(s: socket):
    vers_sent = sendVersionMessage(s)
    vers_recvd = waitForVersion(s)
    if vers_recvd == False:
        return False
    verack_sent = sendVerackMessage(s)
    verack_recvd = waitForVerack(s)
    if vers_sent and vers_recvd and verack_sent and verack_recvd:
        print('Connection is established', file=flog)
        return True
    return False

if __name__ == '__main__':
    peers = getTestnetPeers()
    p = random.choice(peers)
    s = None
    peerinfo = {}
    print("Trying to connect to ", p, file=flog)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    err = s.connect(p)
    print('connected', file=flog)
    if establishConnection(s) == False:
        print('Establish connection failed', file=flog)
    s.close()
    flog.close()
