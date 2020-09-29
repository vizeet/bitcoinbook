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
 
#def getMainnetPeers():
#    port = 8333
#    dns_seeds = [
#            "seed.bitcoin.sipa.be",
#            "dnsseed.bluematt.me",
#            "dnsseed.bitcoin.dashjr.org",
#            "seed.bitcoinstats.com",
#            "seed.bitcoin.jonasschnelli.ch",
#            "seed.btc.petertodd.org",
#            "seed.bitcoin.sprovoost.nl",
#            "dnsseed.emzy.de",
#            "seed.bitcoin.wiz.biz"
#    ]
#
#    ipaddr_l = []
#    for seed in dns_seeds:
#        ipaddr_l.extend(getNodeAddresses(seed))
#
#    peers = []
#    for ipaddr in ipaddr_l:
#        peers.append((ipaddr, port))
#
#    return peers

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
    addr['service'] = ip_m.read(8).hex()
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
def checkMessage(data_m: mmap, msg: dict, msglen: int):
    start = data_m.tell()
    payloadlen = msglen - start

    if msg['magic'] == 'd9b4bef9':
        print('Magic check passed')
    else:
        print('Magic check failed')
        print('magic = %s' % msg['magic'])
        data_m.close()
        raise Exception('Invalid Magic')

    if payloadlen == 0 and msg['length'] != 0:
        print('data length is zero')
        data_m.close()
        payload = getPayload(s)
        payloadlen = len(payload)
        data_m = mmap.mmap(-1, payloadlen + 1)
        data_m.write(payload)
        data_m.seek(0)
        start = 0

    if res['length'] <= payloadlen:
        print('Length check passed')
    else:
        print('Length check failed')
        print('expected length = %d' % msg['length'])
        print('received length = %d' % payloadlen)
        raise Exception('Invalid Message Length')

    checksum_calc = calculateChecksum(data_m.read(msg['length']))
    if res['checksum'] == checksum_calc:
        print('checksum check passed')
    else:
        print('checksum check failed')
        print('expected checksum = %s' % msg['checksum'].hex())
        print('received checksum = %s' % checksum_calc.hex())
        raise Exception('Invalid Checksum')

    data_m.seek(start)
    return data_m

def parseVersionPayload(payload_m: mmap, msglen: int):
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
    if payload_m.tell() - start != msglen:
        msg['relay'] = int.from_bytes(payload_m.read(1), byteorder='little')
    return msg

def parseAddrPayload(payload_m: mmap):
    msg = {}
    msg['count'] = getVarInt(payload_m)
    msg['addrs'] = []
    for i in range(msg['count']):
        addr = {}
        addr['timestamp'] = int.from_bytes(payload_m.read(4), byteorder='little')
        addr['addr'] = parseIPAddress(payload_m)
    return msg

def parseFilterLoadPayload(payload_m: mmap):
    msg = {}
    msg['filter'] = getVarInt(payload_m)
    msg['nHashFuncs'] = int.from_bytes(payload_m.read(4), byteorder='little')
    msg['nTweak'] = int.from_bytes(payload_m.read(4), byteorder='little')
    msg['nFlags'] = int.from_bytes(payload_m.read(1), byteorder='little')
    return msg

def parseFilterAddPayload(payload_m: mmap, msg: dict, msglen: int):
    msg = {}
    msg['data'] = getVarInt(payload_m)
    return msg

def parseMerkleBlockPayload(payload_m: mmap):
    msg = {}
    msg['version'] = int.from_bytes(payload_m.read(4), byteorder='little')
    msg['prev_block'] = payload_m.read(32)[::-1].hex()
    msg['merkle_root'] = payload_m.read(32)[::-1].hex()
    msg['timestamp'] = int.from_bytes(payload_m.read(4), byteorder='little')
    msg['dt'] = datetime.datetime.fromtimestamp(msg['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
    msg['bits'] = payload_m.read(4)[::-1].hex()
    msg['nonce'] = int.from_bytes(payload_m.read(4), byteorder='little')
    msg['total_transactions'] = int.from_bytes(payload_m.read(4), byteorder='little')
    msg['hash_count'] = getVarInt(payload_m)
    msg['hashes'] = []
    for i in msg['hash_count']:
        txhash = payload_m.read(32)[::-1].hex()
        msg['hashes'].append(txhash)
    msg['flag_bytes'] = getVarInt(payload_m)
    msg['flags'] = payload_m.read(msg['flag_bytes'])[::-1].hex()
    return msg

def parsePingPongPayload(payload_m: mmap):
    msg = {}
    msg['nonce'] = int.from_bytes(payload_m.read(8), byteorder='little')
    return msg

def parseFeeFilterPayload(payload_m: mmap):
    msg = {}
    msg['feerate'] = int.from_bytes(payload_m.read(8), byteorder='little')
    return msg

def parseInvPayload(payload_m: mmap):
    msg = {}
    msg['count'] = getVarInt(payload_m)
    msg['inventory'] = {}
    for i in msg['count']:
        msg['inventory']['type'] = payload_m.read(4)[::-1].hex()
        msg['inventory']['hash'] = payload_m.read(32)[::-1].hex()
    return msg

def parseGetDataPayload(payload_m: mmap):
    msg = {}
    msg['count'] = getVarInt(payload_m)
    msg['inventory'] = {}
    for i in msg['count']:
        msg['inventory']['type'] = payload_m.read(4)[::-1].hex()
        msg['inventory']['hash'] = payload_m.read(32)[::-1].hex()
    return msg

def parseNotFoundPayload(payload_m: mmap):
    msg = {}
    msg['count'] = getVarInt(payload_m)
    msg['inventory'] = {}
    for i in msg['count']:
        msg['inventory']['type'] = payload_m.read(4)[::-1].hex()
        msg['inventory']['hash'] = payload_m.read(32)[::-1].hex()
    return msg

def parseTxPayload(payload_m: mmap):
    msg = {}
    msg['version'] = int.from_bytes(payload_m.read(4), byteorder='little')
    msg['tx_in count'] = getVarInt(payload_m)
    if msg['tx_in count'] == 0:
        # check if segwit
        msg['is_segwit'] = bool(int.from_bytes(payload_m.read(1), byteorder='little'))
        if msg['is_segwit'] == True:
                msg['tx_in count'] = getVarInt(payload_m)
    msg['tx_in'] = []
    for i in range(msg['tx_in count']):
        txin = {}
        txin['prev_tx_hash'] = payload_m.read(32)[::-1].hex()
        txin['prev_tx_out_index'] = int.from_bytes(payload_m.read(4), byteorder='little')
        txin['bytes_scriptsig'] = getVarInt(payload_m)
        txin['sriptsig'] = blk_m.read(inp['bytes_scriptsig']).hex()
        txin['sequence'] = blk_m.read(4)[::-1].hex()
        msg['tx_in'].append(txin)
    tx['out_cnt'] = getVarInt(payload_m)
    msg['tx_out'] = []
    for i in range(msg['tx_out count']):
        txout = {}
        txout['satoshis'] = int.from_bytes(payload_m.read(8), byteorder='little')
        txout['bytes_scriptpubkey'] = getVarInt(payload_m)
        txout['scriptpubkey'] = payload_m.read(txout['bytes_scriptpubkey']).hex()
        msg['tx_out'].append(txout)
    msg['locktime'] = int.from_bytes(payload_m.read(4), byteorder='little')

    if 'is_segwit' in msg and msg['is_segwit'] == True:
        for i in range(msg['tx_in count']):
            txn['tx_in'][i]['witness_count'] = getVarInt(payload_m)
            txn['tx_in'][i]['witness'] = []
            for j in range(msg['tx_in'][i]['witness_count']):
                tx_witness = {}
                tx_witness['size'] = getVarInt(payload_m)
                tx_witness['witness'] = bytes.fromhex(payload_m.read(txn_witness['size']).hex())
                txn['tx_in'][i]['witness'].append(tx_witness)
        msg['locktime'] = int.from_bytes(payload_m.read(4), byteorder='little')

        return msg

def parseBlockPayload(payload_m: mmap):
    msg = {}
    msg['version'] = int.from_bytes(payload_m.read(4), byteorder='little')
    msg['prev_blockhash'] = payload_m.read(32)[::-1].hex()
    msg['merkle_root'] = payload_m.read(32)[::-1].hex()
    msg['timestamp'] = int.from_bytes(payload_m.read(4), byteorder='little')
    msg['bits'] = payload_m.read(4)[::-1].hex()
    msg['nonce'] = payload_m.read(4)[::-1].hex()
    msg['txn_count'] = getVarInt(payload_m)
    msg['txns'] = []
    for i in msg['txn_count']:
        msg['txns'].append(parseTxPayload(payload_m))
    return msg

def parseGetBlocksGetHeadersPayload(payload_m: mmap):
    msg = {}
    msg['version'] = int.from_bytes(payload_m.read(4), byteorder='little')
    msg['hash count'] = getVarInt(payload_m)
    msg['block locator hashes'] = []
    for i in msg['hash count']:
        h = payload_m.read(32)[::-1].hex()
        msg['block locator hashes'].append(h)
    msg['hash_stop'] = payload_m.read(32)[::-1].hex()
    return msg

def parseHeadersPayload(payload_m: mmap):
    msg = {}
    msg['count'] = getVarInt(payload_m)
    msg['headers'] = []
    for i in msg['count']:
        hdr = {}
        hdr['version'] = int.from_bytes(payload_m.read(4), byteorder='little')
        hdr['prev_blockhash'] = payload_m.read(32)[::-1].hex()
        hdr['merkle_root'] = payload_m.read(32)[::-1].hex()
        hdr['timestamp'] = int.from_bytes(payload_m.read(4), byteorder='little')
        hdr['bits'] = payload_m.read(4)[::-1].hex()
        hdr['nonce'] = payload_m.read(4)[::-1].hex()
        hdr['txn_count'] = getVarInt(payload_m)
        msg['headers'].append(hdr)
    return msg

def parseRejectPayload(payload_m: mmap, msglen: int):
    msg = {}
    start = payload_m.tell()
    msg['message'] = getVarInt(payload_m)
    hdr['ccode'] = payload_m.read(1)[::-1].hex()
    msg['reason'] = getVarInt(payload_m)
    datalen = payload_m.tell() - start - msglen
    print('parseRejectPayload: datalen = %d' % datalen)
    if datalen > 0:
        msg['data'] = payload_m.read(datalen).hex()
    return msg


CMD_FN_MAP = {
    'addr': parseAddrPayload,
    'filterload': parseFilterLoadPayload,
    'filteradd': parseFilterAddPayload,
    'merkleblock': parseMerkleBlockPayload,
    'ping': parsePingPongPayload,
    'pong': parsePingPongPayload,
    'feefilter': parseFeeFilterPayload,
    'inv': parseInvPayload,
    'getdata': parseInvPayload,
    'notfound': parseInvPayload,
    'tx': parseTxPayload,
    'block': parseBlockPayload,
    'getblocks': parseGetBlocksGetHeadersPayload,
    'getheaders': parseGetBlocksGetHeadersPayload,
    'headers': parseHeadersPayload,
    'reject': parseRejectPayload,
    'sendcmpct': parseSendCompactPayload,
    'cmpctblock': parseCompactBlockPayload,
    'getblocktxn': parseGetBlockTxnPayload,
    'blocktxn': parseBlockTxnPayload
}

def parseMsg(data_m: mmap:dict, msglen: int):
    global CMDS_WITHOUT_PAYLOAD, CMD_FN_MAP
    msg = {}
    msg['magic'] = data_m.read(4)[::-1].hex()
    msg['command'] = data_m.read(12).decode("ascii").strip('\0')
    msg['length'] = int.from_bytes(data_m.read(4), byteorder='little')
    msg['checksum'] = data_m.read(4)

    payload_m = checkMessage(payload_m, msg, msglen)

    if is_connected == False:
        if msg['command'] == 'version':
            msg['version'] = parseVersionMessage(data_m, msg, msglen)
        elif msg['command'] == 'verack':
            if msg['length'] != 0:
                data_m.close()
                raise Exception('Invalid message length: %d' % msg['length'])
        else:
            raise Exception('Expected version/verack but got %s' % msg['command'])
    else:
        if msg['command'] not in CMDS_WITHOUT_PAYLOAD:
            # call mapping methods based on received command
            msg[msg['command']] = CMD_FN_MAP[msg['command']](data_m, msg, msglen)
    return msg

def getPayload(s):
    buffer_size = 1024
    payload_data = s.recv(buffer_size)
    print('length = %d, payload = %s' % (len(payload_data),payload_data.hex()))
    return payload_data

def createMessage(command, payload):
    magic = 0xD9B4BEF9
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[0:4]
    magic_b = struct.pack('<L', magic)
    cmd_b = struct.pack('<12s', command.encode('ascii'))
    payload_len_b = struct.pack('<L', len(payload))
    checksum_b = struct.pack('<4s', checksum)

    msg = magic_b + cmd_b + payload_len_b + checksum + payload

#    return(struct.pack('<L12sL4s', magic, command.encode(), len(payload), checksum) + payload)
    return msg

def getRandomPeer():
    peers = getMainnetPeers()
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
#    payload = struct.pack('<LQQ26s26sQ16sL', version, services, timestamp, addr_recv,
#                          addr_trans, nonce, user_agent, start_height)
    payload = version_b + services_b + timestamp_b + addr_recv_b + addr_trans_b + nonce_b + user_agent_b + start_height_b
    return payload

def createAddrPayload(ipaddr_l: list):
    count = len(ipaddr_l)
    count_b = setVarInt(count)
    addr_b = b''
    for i in count:
        ipaddr = ipaddr_l[i]['ipaddr']
        port = ipaddr_l[i]['port']
        timestamp = ipaddr_l[i]['time']
        timestamp_b = struct.pack('<L', timestamp)
        ipaddr_b = struct.pack('<26s', createRecvIPAddress(ipaddr, port))
        addr_b += timestamp_b + ipaddr_b
    payload = count_b + addr_b
    return payload

def createPingPayload():
    nonce_b = struct.pack('<Q', random.getrandbits(64))
    return nonce_b

def createPongPayload(nonce: int):
    nonce_b = struct.pack('<Q', nonce)
    return nonce_b

SATOSHIS_PER_BTC = 10**8

def createFeeFilterPayload():
    global SATOSHIS_PER_BTC
    fee = rpc_connection.estimatesmartfee(1)
    feerate = SATOSHIS_PER_BTC * fee['feerate']
    feerate_b = struct.pack('<Q', feerate)
    return feerate_b

def createInvBlkPayload():
    MSG_BLOCK = 2
    count = 1
    count_b = setVarInt(count)
    blk_height = rpc_connection.getblockcount()
    blk_hash = rpc_connection.getblockhash(blk_height)
    blk_hash_b = bytes.fromhex(blk_hash)[::-1]
    inv_vect_b = b''
    for i in count:
        blk_type_b = struct.pack('<L', MSG_BLOCK)
        inv_vect_b += blk_type_b + blk_hash_b
    payload = count_b + inv_vect_b
    return payload

def createGetDataPayload():

CMDS_WITHOUT_PAYLOAD = ['verack', 'sendheaders', 'getaddr', 'filterclear', 'mempool']

def sendcmd(s: socket, peerinfo: dict, cmd: str):
    global CMDS_WITHOUT_PAYLOAD
    if cmd in CMDS_WITHOUT_PAYLOAD:
        payload = b''
    elif cmd == 'version':
        payload = createVersionPayload(s)
    elif cmd == 'addr':
        peer = getRandomPeer()
        payload = createAddrPayload(s, [peer])
    elif cmd == 'ping' or cmd == 'pong':
        payload = createPingPongPayload(s)
    elif cmd == 'feefilter':
        payload = createFeeFilterPayload(s)
    elif cmd == 'inv':
        createInvBlkPayload(s)
    elif cmd == 'getdata':
        createInvBlkPayload(s)
    createMessage(cmd, payload)

CMD_RESP_D = {
        'version': 'verack', 
        'getaddr': 'addr', 
        'ping': 'pong', 
        'filterload': ['filteradd', 'filterclear'], 
        'getheaders': 'headers', 
        'geblocks': 'inv',
        'mempool': 'inv',
        'inv': 'getdata',
        'getdata': 'getdatalist'
}

def recvMsg(s: socket, is_connected: bool, wairesplist: list, getall: bool):
    msg = getMsg(s)
    msglen = len(msg)
    msg_m = mmap.mmap(-1, msglen + 1)
    msg_m.write(msgdata)
    msgdata_m.seek(0)
    msg = parseMsg(msg_m, msglen, is_connected, waitresplist, getall=False)
    msg_m.close()
    return msg

def sendMsg(s: socket, msg: bytes):
    buffer_size = 1024
    s.send(msg)
    response_data = s.recv(buffer_size)
    print('response = %s' % response_data.hex())
    return response_data

def sendrecvHandler(s: socket, peerinfo: dict, cmdlist: list):
    is_connected = False
    version_recvd = False
    verack_recvd = False
    verack_sent = False

    itr = iter(cmdlist)
    sndcmd = 'version'
    payload = createVersionPayload(s)
    sndmsg = createMessage(cmd, payload)
    sendMsg(s, sndmsg)
    while sndcmd != None:
        recvmsg = recvMsg(s, is_connected, waitresplist, getall=False)
        if recvmsg['command'] == 'version':
            version_recvd = True
            sndcmd = 'verack'
            payload = b''
            verack_sent = True
            is_connected = version_recvd and verack_recvd and verack_sent
        elif recvmsg['command'] == 'verack':
            is_connected = version_recvd and verack_recvd and verack_sent
        elif recvmsg['command'] == 'getaddr':
            cmd = 'addr'
            peer = getRandomPeer()
            payload = createAddrPayload(s, [peer])
        elif recvmsg['command'] == 'ping':
            recvmsg['']
            sndcmd = 'pong'
            payload = createPongPayload(s, nonce)
        elif recvmsg['command'] == 'filterload':
            sndcmd = 'filteradd'
        elif recvmsg['command'] == 'sendheaders':
            if 'opt' not in peerinfo:
                peerinfo['opt'] = []
            peerinfo['opt'].append('sendheaders')
        elif recvmsg['command'] == 'feefilter':
            if 'feefilter' not in peerinfo:
                peerinfo['feefilter']
            peerinfo['feefilter'] = recvmsg['feefilter']['feerate']
        elif recvmsg['command'] == 'getheaders':
            sndcmd = 'headers'
            params = (recvmsg['getheaders']['headerhashes'], recvmsg['getheaders']['stophash'])
        elif recvmsg['command'] == 'getblocks':
            sndcmd = 'inv'
            params = (msg['getheaders']['headerhashes'], msg['getheaders']['stophash'])
        elif recvmsg['command'] == 'mempool':
            sndcmd = 'inv'
        elif recvmsg['command'] == 'inv':
            sndcmd = 'getdata'
            params = msg['inv']
        elif recvmsg['command'] == 'getdata':
            sndcmd = 'getdatalist'
            params = msg['getdata']

        sndmsg = createMessage(sndcmd, payload)
            sndcmd = next(itr)
            if msg['command'] == 'verack':
                verack_recvd = True
                is_connected = version_recvd and verack_recvd and verack_sent
        if cmd == None: # get all unprocessed messages
            recvmsg = recvMsg(s, is_connected, wairesplist, getall=True)
        print(recvmsg)

if __name__ == '__main__':
    peers = getMainnetPeers()
    for p in peers:
        try:
            peerinfo = {}
            cmds = ['getaddr', 'mempool']
            print("Trying to connect to ", (p['ipaddr'], p['port']))
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            err = s.connect(p)
            sendrecvHandler(s, peerinfo, cmds)
            s.close()
            exit()
        except Exception as e:
            print("Exception in connection to ", p)
            continue
#        finally:
#            s.close()
