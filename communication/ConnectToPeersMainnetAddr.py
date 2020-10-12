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

def parseVersionPayload(payload_m: mmap, payloadlen: int):
    payload = {}
    start = payload_m.tell()
    payload['version'] = int.from_bytes(payload_m.read(4), byteorder='little')
    payload['services'] = int.from_bytes(payload_m.read(8), byteorder='little')
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

def parseAddrPayload(payload_m: mmap):
    payload = {}
    payload['count'] = getVarInt(payload_m)
    payload['addrs'] = []
    for i in range(payload['count']):
        addr = {}
        addr['timestamp'] = int.from_bytes(payload_m.read(4), byteorder='little')
        addr['addr'] = parseIPAddress(payload_m)
    return payload

def parseFilterLoadPayload(payload_m: mmap):
    payload = {}
    payload['filter'] = getVarInt(payload_m)
    payload['nHashFuncs'] = int.from_bytes(payload_m.read(4), byteorder='little')
    payload['nTweak'] = int.from_bytes(payload_m.read(4), byteorder='little')
    payload['nFlags'] = int.from_bytes(payload_m.read(1), byteorder='little')
    return payload

def parseFilterAddPayload(payload_m: mmap, payload: dict, payloadlen: int):
    payload = {}
    payload['data'] = getVarInt(payload_m)
    return payload

def parseMerkleBlockPayload(payload_m: mmap):
    payload = {}
    payload['version'] = int.from_bytes(payload_m.read(4), byteorder='little')
    payload['prev_block'] = payload_m.read(32)[::-1].hex()
    payload['merkle_root'] = payload_m.read(32)[::-1].hex()
    payload['timestamp'] = int.from_bytes(payload_m.read(4), byteorder='little')
    payload['dt'] = datetime.datetime.fromtimestamp(payload['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
    payload['bits'] = payload_m.read(4)[::-1].hex()
    payload['nonce'] = int.from_bytes(payload_m.read(4), byteorder='little')
    payload['total_transactions'] = int.from_bytes(payload_m.read(4), byteorder='little')
    payload['hash_count'] = getVarInt(payload_m)
    payload['hashes'] = []
    for i in payload['hash_count']:
        txhash = payload_m.read(32)[::-1].hex()
        payload['hashes'].append(txhash)
    payload['flag_bytes'] = getVarInt(payload_m)
    payload['flags'] = payload_m.read(payload['flag_bytes'])[::-1].hex()
    return payload

def parsePingPongPayload(payload_m: mmap):
    payload = {}
    payload['nonce'] = int.from_bytes(payload_m.read(8), byteorder='little')
    return payload

def parseFeeFilterPayload(payload_m: mmap):
    payload = {}
    payload['feerate'] = int.from_bytes(payload_m.read(8), byteorder='little')
    return payload

def parseInvPayload(payload_m: mmap):
    payload = {}
    payload['count'] = getVarInt(payload_m)
    payload['inventory'] = {}
    for i in payload['count']:
        payload['inventory']['type'] = payload_m.read(4)[::-1].hex()
        payload['inventory']['hash'] = payload_m.read(32)[::-1].hex()
    return msg

def parseGetDataPayload(payload_m: mmap):
    payload = {}
    payload['count'] = getVarInt(payload_m)
    payload['inventory'] = {}
    for i in payload['count']:
        inv = {}
        inv['type'] = payload_m.read(4)[::-1].hex()
        inv['hash'] = payload_m.read(32)[::-1].hex()
        payload['inventory'].append(inv)
    return payload

def parseNotFoundPayload(payload_m: mmap):
    payload = {}
    payload['count'] = getVarInt(payload_m)
    payload['inventory'] = []
    for i in payload['count']:
        inv = {}
        inv['type'] = payload_m.read(4)[::-1].hex()
        inv['hash'] = payload_m.read(32)[::-1].hex()
        payload['inventory'].append(inv)
    return payload

def parseTxPayload(payload_m: mmap):
    payload = {}
    payload['version'] = int.from_bytes(payload_m.read(4), byteorder='little')
    payload['tx_in count'] = getVarInt(payload_m)
    if payload['tx_in count'] == 0:
        # check if segwit
        payload['is_segwit'] = bool(int.from_bytes(payload_m.read(1), byteorder='little'))
        if payload['is_segwit'] == True:
                payload['tx_in count'] = getVarInt(payload_m)
    payload['tx_in'] = []
    for i in range(payload['tx_in count']):
        txin = {}
        txin['prev_tx_hash'] = payload_m.read(32)[::-1].hex()
        txin['prev_tx_out_index'] = int.from_bytes(payload_m.read(4), byteorder='little')
        txin['bytes_scriptsig'] = getVarInt(payload_m)
        txin['sriptsig'] = blk_m.read(inp['bytes_scriptsig']).hex()
        txin['sequence'] = blk_m.read(4)[::-1].hex()
        payload['tx_in'].append(txin)
    tx['out_cnt'] = getVarInt(payload_m)
    payload['tx_out'] = []
    for i in range(payload['tx_out count']):
        txout = {}
        txout['satoshis'] = int.from_bytes(payload_m.read(8), byteorder='little')
        txout['bytes_scriptpubkey'] = getVarInt(payload_m)
        txout['scriptpubkey'] = payload_m.read(txout['bytes_scriptpubkey']).hex()
        payload['tx_out'].append(txout)
    payload['locktime'] = int.from_bytes(payload_m.read(4), byteorder='little')

    if 'is_segwit' in payload and payload['is_segwit'] == True:
        for i in range(payload['tx_in count']):
            txn['tx_in'][i]['witness_count'] = getVarInt(payload_m)
            txn['tx_in'][i]['witness'] = []
            for j in range(payload['tx_in'][i]['witness_count']):
                tx_witness = {}
                tx_witness['size'] = getVarInt(payload_m)
                tx_witness['witness'] = bytes.fromhex(payload_m.read(txn_witness['size']).hex())
                txn['tx_in'][i]['witness'].append(tx_witness)
        payload['locktime'] = int.from_bytes(payload_m.read(4), byteorder='little')

        return payload

def parseBlockPayload(payload_m: mmap):
    payload = {}
    payload['version'] = int.from_bytes(payload_m.read(4), byteorder='little')
    payload['prev_blockhash'] = payload_m.read(32)[::-1].hex()
    payload['merkle_root'] = payload_m.read(32)[::-1].hex()
    payload['timestamp'] = int.from_bytes(payload_m.read(4), byteorder='little')
    payload['bits'] = payload_m.read(4)[::-1].hex()
    payload['nonce'] = payload_m.read(4)[::-1].hex()
    payload['txn_count'] = getVarInt(payload_m)
    payload['txns'] = []
    for i in payload['txn_count']:
        payload['txns'].append(parseTxPayload(payload_m))
    return payload

def parseGetBlocksGetHeadersPayload(payload_m: mmap):
    payload = {}
    payload['version'] = int.from_bytes(payload_m.read(4), byteorder='little')
    payload['hash count'] = getVarInt(payload_m)
    payload['block locator hashes'] = []
    for i in payload['hash count']:
        h = payload_m.read(32)[::-1].hex()
        payload['block locator hashes'].append(h)
    payload['hash_stop'] = payload_m.read(32)[::-1].hex()
    return payload

def parseHeadersPayload(payload_m: mmap):
    payload = {}
    payload['count'] = getVarInt(payload_m)
    payload['headers'] = []
    for i in payload['count']:
        hdr = {}
        hdr['version'] = int.from_bytes(payload_m.read(4), byteorder='little')
        hdr['prev_blockhash'] = payload_m.read(32)[::-1].hex()
        hdr['merkle_root'] = payload_m.read(32)[::-1].hex()
        hdr['timestamp'] = int.from_bytes(payload_m.read(4), byteorder='little')
        hdr['bits'] = payload_m.read(4)[::-1].hex()
        hdr['nonce'] = payload_m.read(4)[::-1].hex()
        hdr['txn_count'] = getVarInt(payload_m)
        payload['headers'].append(hdr)
    return payload

def parseRejectPayload(payload_m: mmap, payloadlen: int):
    payload = {}
    start = payload_m.tell()
    payload['message'] = getVarInt(payload_m)
    hdr['ccode'] = payload_m.read(1)[::-1].hex()
    payload['reason'] = getVarInt(payload_m)
    datalen = payload_m.tell() - start - payloadlen
    print('parseRejectPayload: datalen = %d' % datalen)
    if datalen > 0:
        payload['data'] = payload_m.read(datalen).hex()
    return payload

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
        inv_type_b = struct.pack('<L', MSG_BLOCK)
        inv_vect_b += inv_type_b + blk_hash_b
    payload = count_b + inv_vect_b
    return payload

def createInvTxPayload():
    MSG_TX = 1
    tx_list = rpc_connection.getrawmempool()
    count = len(tx_list)
    count_b = setVarInt(count)
    inv_vect_b = b''
    for tx in txlist:
        tx_b = bytes.fromhex(tx)[::-1]
        inv_type_b = struct.pack('<L', MSG_TX)
        inv_vect_b += inv_type_b + tx_b
    payload = count_b + inv_vect_b
    return payload

def createGetDataPayload(recvdpayload: dict):
    MSG_TX = 1
    MSG_BLOCK = 2
    MSG_FILTERED_BLOCK = 3
    MSG_CMPCT_BLOCK = 4

    inv_vect_b = b''
    tx_list = rpc_connection.getrawmempool()
    count = 0
    for i in recvdpayload['count']:
        inv_type_b = recvdpayload['inventory'][i]['type']
        tx_type_b = struct.pack('<L', inv_type)
        if inv_type == MSG_TX: 
            if tx in tx_list:
                tx_b = bytes.fromhex(tx)[::-1]
                tx = recvdpayload['inventory'][i]['hash']
                inv_vect_b += inv_type_b + tx_b
                count++
        elif inv_type == MSG_BLOCK:
            blk_hash = recvdpayload['inventory'][i]['hash']
            try:
                blk = rpc_connection.getblock(blk_hash)
                inv_vect_b += inv_type_b + blk_hash_b
                count++
            except Exception as e:
                continue
    count_b = setVarInt(count)
    payload = count_b + inv_vext_b
    return payload

def createHeadersPayload(hashes, stophash):
    b_cnt_d = {'fd': 2, 'fe': 4, 'ff': 8}
    revhashes = hashes[::-1]
    found = False
    for blk_hash in revhashes:
        try:
            blk = rpc_connection.getblock(blk_hash)
            found = True
            break
        except Exception as e:
            continue
    if found == True:
        txcnt = 0
        txcnt_b = setVarInt(txcnt)
        headers_b = b''
        count = 0
        while True:
            # returns block hex
            blk = rpc_connection.getblock(blk_hash, False)
            blk_b = bytes.fromhex(blk)
            blkhdr_b = blk_b[:80]
            headers_b += blkhdr_b + txcnt_b
            blk = rpc_connection.getblock(blk_hash)
            count += 1
            if count == 2000 or 'nextblockhash' not in blk_hash or stophash == blk_hash:
                break
            blk_hash = blk['nextblockhash']
        cnt_b = setVarInt(count)
        payload = cnt_b + headers_b
        return payload


CMDS_WITHOUT_PAYLOAD = ['verack', 'sendheaders', 'getaddr', 'filterclear', 'mempool']

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

def recvMsg(s: socket):
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

CMD_RESP_D = {
        'version': ['verack'], 
        'verack': [],
        'getaddr': ['addr'],
        'addr': [],
        'ping': ['pong'],
        'pong': [],
        'filterload': ['filteradd', 'filterclear'], 
        'sendheaders': [],
        'feefilter': [],
        'getheaders': ['headers'],
        'getblocks': ['inv'],
        'mempool': ['inv'],
        'inv': ['getdata'],
        'getdata': ['tx', 'block', 'merkleblock', 'cmpctblock', 'notfound'],
        'reject': [],
        'sendcmpct': [],
        'cmpctblock': [],
        'getblocktxn': ['blocktxn', 'block']
        }

def removeExpectedResponse(cmd: str):
    global CMD_RESP_D
    CMD_RESP_D = [x for x in CMD_RESP_D if cmd not in x]

def sendrecvHandler(s: socket, peerinfo: dict, cmdlist: list):
    is_connected = False
    version_recvd = False
    verack_recvd = False
    verack_sent = False

    itr = iter(cmdlist)
    sndcmd = 'version'
    payload = createVersionPayload(s)
    sndmsg = createMessage(sndcmd, payload)
    sendMsg(s, sndmsg)
    wait_resp_l = [CMD_RESP_D[sndcmd]]
    while True:
        sndcmd = None
        if len(wait_resp_l) != 0:
            recvmsg = recvMsg(s)
            if is_connected == False:
                if recvmsg['command'] == 'version':
                    version_recvd = True
                    sndcmd = 'verack'
                    payload = b''
                    verack_sent = True
                    is_connected = version_recvd and verack_recvd and verack_sent
                elif recvmsg['command'] == 'verack':
                    is_connected = version_recvd and verack_recvd and verack_sent
                else:
                    raise Exception('Not connected yet but got %s' % recvmsg['command'])
            else:
                removeExpectedResponse(recvmsg['command'])
                if recvmsg['command'] == 'getaddr':
                    cmd = 'addr'
                    peer = getRandomPeer()
                    payload = createAddrPayload(s, [peer])
                elif recvmsg['command'] == 'ping':
                    sndcmd = 'pong'
                    payload = createPongPayload(s, nonce)
                elif recvmsg['command'] == 'filterload':
                    sndcmd = 'filteradd'
                    payload = createFilteraddPayload(s)
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
                    hashes = recvmsg['getheaders']['block locator hashes']
                    stophash = recvmsg['getheaders']['hash_stop']
                    payload = createHeadersPayload(s, hashes, stophash)
                elif recvmsg['command'] == 'getblocks':
                    sndcmd = 'inv'
                    payload = createInvBlkPayload()
                elif recvmsg['command'] == 'mempool':
                    sndcmd = 'inv'
                    payload = createInvTxPayload()
                elif recvmsg['command'] == 'inv':
                    sndcmd = 'getdata'
                    payload = createGetDataPayload(msg['getdata'])
                elif recvmsg['command'] == 'getdata':
                    # this will initiate multiple commands
                    sndcmd = 'senddatalist'
                    params = msg['getdata']
                    payload = createSendDataListPayload(s, msg['getdata'])
        else:
            sndcmd = next(itr)
            if sndcmd in CMDS_WITHOUT_PAYLOAD:
                payload = b''
            elif sndcmd == 'invtx': # inv with tx payload
                payload = createInvTxPayload()
            elif sndcmd == 'invblk': # inv with block payload
                payload = createInvBlkPayload()
            elif sndcmd == 'ping':
                payload = createPingPayload()
            elif sndcmd == 'getblocks':
                payload = createGetBlocksPayload(s)
            elif sndcmd == 'sendcmpct':
                payload = createSendCmpctPayload(s)
            elif sndcmd == 'cmpctblock':
                payload = createCmpctBlockPayload(s)
            elif sndcmd == 'feefilter':
                payload = createFeeFilterPayload(s)
        wait_resp_l.append(CMD_RESP_D[sndcmd])
        if sndcmd != None:
            sndmsg = createMessage(sndcmd, payload)
            sendMsg(s, sndmsg)

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
