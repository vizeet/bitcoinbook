# Import socket and time library
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

rpc_connection = AuthServiceProxy("http://%s:%s@127.0.0.1:8332"%('test', 'test'))

def getMyIP():
    ni.ifaddresses('wlp2s0')
    ip = ni.ifaddresses('wlp2s0')[ni.AF_INET][0]['addr']
    return ip

def getLastBlockHeight():
    height = rpc_connection.getblockcount()
    return height

def getNodeAddresses(dnsseed: str):
    domain = 'seed.tbtc.petertodd.org'
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

# Connect to the first responding peer from our dns list
def connect(peers):
    for p in peers:
        try:
            print("Trying to connect to ", p)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            err = s.connect(p)
            return s
        except Exception as e:
            print("Exception in connection to ", p)
            continue
    return None

port_g = {"testnet": 18333, "mainnet": 8333}

nettype_g = "testnet"

def createIPAddress(ip, port):
    address_b = struct.pack('>8s16sH', b'\x01',
        bytearray.fromhex("00000000000000000000ffff") + socket.inet_aton(ip), port)
    return(address_b)

def createUserAgent():
    sub_version = "/Satoshi:0.7.2/"
    return b'\x0F' + sub_version.encode()

def createVersionMessage(peer_ip, port):
    version = 70015
    services = 1
    timestamp = int(time.time())
    ip = getMyIP()
    port = port_g[nettype_g]
    addr_local = createIPAddress(ip, port)
    addr_peer = createIPAddress(peer_ip, port)
    nonce = random.getrandbits(64)
    start_height = getLastBlockHeight()
    subversion = createUserAgent()
    payload = struct.pack('<LQQ26s26sQ16sL', version, services, timestamp, addr_peer,
                          addr_local, nonce, subversion, start_height)
    return payload;

def createMessage(magic, command, payload):
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[0:4]
    return(struct.pack('<L12sL4s', magic, command.encode(), len(payload), checksum) + payload)

def sendVersion(s: socket):
    host, port = s.getpeername()
    print('host = %s' % host)
    vermsg = b''
    try:
        payload = createVersionMessage(host, port)
        print(vermsg.hex())
    except Exception as e:
        print('Exception closed because of ', e.message)
        s.close()
    magic = 0x0709110B
    command = 'version'
    msg = createMessage(magic, command, payload)
    print('sent_msg = %s' % msg.hex())

    buffer_size = 1024
    s.send(msg)
    response_data = s.recv(buffer_size)
    print('response = %s' % response_data.hex())

peers = getTestnetPeers()
s = connect(peers)
if s == None:
    exit()

sendVersion(s)
s.close()

