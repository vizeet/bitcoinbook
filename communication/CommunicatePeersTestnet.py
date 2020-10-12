import dns.name
import dns.message
import dns.query
import dns.flags
import netifaces as ni
import hashlib
import mmap
import json
import threading

flog = open('communication.log', 'wt+')

from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
import struct
import random
import socket
import time

rpc_connection = AuthServiceProxy("http://%s:%s@127.0.0.1:18332"%('test', 'test'))

def getLastBlockHeight():
    height = rpc_connection.getblockcount()
    return height

def createUserAgent():
    sub_version = "/MyTestAgent:0.0.1/"
    return b'\x0F' + sub_version.encode()

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
    payload = version_b \
                + services_b \
                + timestamp_b \
                + addr_recv_b \
                + addr_trans_b \
                + nonce_b \
                + user_agent_b \
                + start_height_b
    return payload

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

#def getMainnetPeers():
#    port = 8333
#    url = 'https://bitnodes.io/api/v1/snapshots/latest/'
#    headers = {'Accept': 'application/json'}
#    r = requests.get(url=url, headers=headers)
#    jsonobj = r.json()
#    peers = []
#    for k, v in jsonobj['nodes'].items():
#        node = parseNodeInfo(k, v)
#        if node['valid'] == True and node['port'] == 8333 and node['type'] != 'TOR':
#            peers.append(node)
#    return peers

#    address_b = struct.pack('>8s16sH', b'\x01',
#        bytearray.fromhex("000000000000000000000000") + socket.inet_aton("0.0.0.0"), 0)
#    address_b = struct.pack('>8s16sH', b'\x01',
#        bytearray.fromhex("00000000000000000000ffff") + socket.inet_aton(ip), port)
#sub_version = "/Satoshi:0.7.2/"

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

from datetime import datetime
import ipaddress

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
    dt_fmt = '%Y-%m-%d %H:%M:%S'
    payload['dt'] = datetime.fromtimestamp(payload['timestamp']).strftime(dt_fmt)
    payload['addr_recv'] = parseIPAddress(payload_m)
    payload['addr_trans'] = parseIPAddress(payload_m)
    payload['nonce'] = int.from_bytes(payload_m.read(8), byteorder='little')
    payload['user_agent_size'] = getVarInt(payload_m)
    payload['user_agent'] = payload_m.read(payload['user_agent_size'])
    payload['block_height'] = int.from_bytes(payload_m.read(4), byteorder='little')
    if payload_m.tell() - start != payloadlen:
        payload['relay'] = int.from_bytes(payload_m.read(1), byteorder='little')
    return payload

def parseAddrPayload(payload_m: mmap, payloadlen = 0):
    payload = {}
    payload['count'] = getVarInt(payload_m)
    payload['addrs'] = []
    for i in range(payload['count']):
        addr = {}
        addr['timestamp'] = int.from_bytes(payload_m.read(4), byteorder='little')
        addr['addr'] = parseIPAddress(payload_m)
    return payload

def parseFilterLoadPayload(payload_m: mmap, payloadlen = 0):
    payload = {}
    payload['filter'] = getVarInt(payload_m)
    payload['nHashFuncs'] = int.from_bytes(payload_m.read(4), byteorder='little')
    payload['nTweak'] = int.from_bytes(payload_m.read(4), byteorder='little')
    payload['nFlags'] = int.from_bytes(payload_m.read(1), byteorder='little')
    return payload

def parseFilterAddPayload(payload_m: mmap, payloadlen: int):
    payload = {}
    payload['data'] = getVarInt(payload_m)
    return payload

def parseMerkleBlockPayload(payload_m: mmap, payloadlen = 0):
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
    for i in range(payload['hash_count']):
        txhash = payload_m.read(32)[::-1].hex()
        payload['hashes'].append(txhash)
    payload['flag_bytes'] = getVarInt(payload_m)
    payload['flags'] = payload_m.read(payload['flag_bytes'])[::-1].hex()
    return payload

def parsePingPongPayload(payload_m: mmap, payloadlen = 0):
    payload = {}
    payload['nonce'] = int.from_bytes(payload_m.read(8), byteorder='little')
    return payload

def parseFeeFilterPayload(payload_m: mmap, payloadlen = 0):
    payload = {}
    payload['feerate'] = int.from_bytes(payload_m.read(8), byteorder='little')
    return payload

def parseInvPayload(payload_m: mmap, payloadlen = 0):
    payload = {}
    payload['count'] = getVarInt(payload_m)
    payload['inventory'] = []
    for i in range(payload['count']):
        inv = {}
        inv['type'] = int.from_bytes(payload_m.read(4), byteorder='little')
        inv['hash'] = payload_m.read(32)[::-1].hex()
        payload['inventory'].append(inv)
    return payload

def parseGetDataPayload(payload_m: mmap, payloadlen = 0):
    payload = {}
    payload['count'] = getVarInt(payload_m)
    payload['inventory'] = {}
    for i in range(payload['count']):
        inv = {}
        inv['type'] = int.from_bytes(payload_m.read(4), byteorder='little')
        inv['hash'] = payload_m.read(32)[::-1].hex()
        payload['inventory'].append(inv)
    return payload

def parseNotFoundPayload(payload_m: mmap, payloadlen = 0):
    payload = {}
    payload['count'] = getVarInt(payload_m)
    payload['inventory'] = []
    for i in range(payload['count']):
        inv = {}
        inv['type'] = int.from_bytes(payload_m.read(4), byteorder='little')
        inv['hash'] = payload_m.read(32)[::-1].hex()
        payload['inventory'].append(inv)
    return payload

def parseTxPayload(payload_m: mmap, payloadlen = 0):
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
        txin['sriptsig'] = payload_m.read(txin['bytes_scriptsig']).hex()
        txin['sequence'] = payload_m.read(4)[::-1].hex()
        payload['tx_in'].append(txin)
    payload['tx_out count'] = getVarInt(payload_m)
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
            payload['tx_in'][i]['witness_count'] = getVarInt(payload_m)
            payload['tx_in'][i]['witness'] = []
            for j in range(payload['tx_in'][i]['witness_count']):
                tx_witness = {}
                tx_witness['size'] = getVarInt(payload_m)
                tx_witness['witness'] = bytes.fromhex(payload_m.read(txn_witness['size']).hex())
                txn['tx_in'][i]['witness'].append(tx_witness)
        payload['locktime'] = int.from_bytes(payload_m.read(4), byteorder='little')

        return payload

def parseBlockPayload(payload_m: mmap, payloadlen = 0):
    payload = {}
    payload['version'] = int.from_bytes(payload_m.read(4), byteorder='little')
    payload['prev_blockhash'] = payload_m.read(32)[::-1].hex()
    payload['merkle_root'] = payload_m.read(32)[::-1].hex()
    payload['timestamp'] = int.from_bytes(payload_m.read(4), byteorder='little')
    payload['bits'] = payload_m.read(4)[::-1].hex()
    payload['nonce'] = payload_m.read(4)[::-1].hex()
    payload['txn_count'] = getVarInt(payload_m)
    payload['txns'] = []
    for i in range(payload['txn_count']):
        payload['txns'].append(parseTxPayload(payload_m))
    return payload

def parseGetBlocksGetHeadersPayload(payload_m: mmap, payloadlen = 0):
    payload = {}
    payload['version'] = int.from_bytes(payload_m.read(4), byteorder='little')
    payload['hash count'] = getVarInt(payload_m)
    payload['block locator hashes'] = []
    for i in range(payload['hash count']):
        h = payload_m.read(32)[::-1].hex()
        payload['block locator hashes'].append(h)
    payload['hash_stop'] = payload_m.read(32)[::-1].hex()
    return payload

def parseBlockHeader(payload_m: mmap):
    hdr = {}
    hdr['version'] = int.from_bytes(payload_m.read(4), byteorder='little')
    hdr['prev_blockhash'] = payload_m.read(32)[::-1].hex()
    hdr['merkle_root'] = payload_m.read(32)[::-1].hex()
    hdr['timestamp'] = int.from_bytes(payload_m.read(4), byteorder='little')
    hdr['bits'] = payload_m.read(4)[::-1].hex()
    hdr['nonce'] = payload_m.read(4)[::-1].hex()
    return hdr

def parseHeadersPayload(payload_m: mmap, payloadlen = 0):
    payload = {}
    payload['count'] = getVarInt(payload_m)
    payload['headers'] = []
    for i in range(payload['count']):
        hdr = {}
        start = payload_m.tell()
        hdr['blkhash'] = hashlib.sha256(hashlib.sha256(payload_m.read(80)).digest()).digest()
        payload_m.seek(start)
        hdr['header'] = parseBlockHeader(payload_m)
        hdr['txn_count'] = getVarInt(payload_m)
        payload['headers'].append(hdr)
    return payload

def parseRejectPayload(payload_m: mmap, payloadlen: int):
    ANY_MESSAGE     = 0x01
    # blk
    BLK_INVALID     = 0x10
    BLK_VERSION_NOT_SUPPORTED   = 0x11
    INVALID_BLKCHAIN            = 0x43
    #tx codes
    TX_INVALID      = 0x10
    DOUBLE_SPEND    = 0x12
    NON_STANDARD    = 0x40
    DUST            = 0x41
    LOW_FEE         = 0x42
    #version codes
    NOT_SUPPORTED   = 0x11
    REPEATED        = 0x12
    start = payload_m.tell()
    payload = {}
    payload['message bytes'] = getVarInt(payload_m)
    payload['message'] = payload_m.read(payload['message bytes']).decode('ascii')
    print('rejected message = %s' % payload['message'], file=flog)
    if payload['message'] != 'version':
        extra_bytes = 32
    payload['code'] = int.from_bytes(payload_m.read(1), byteorder='little')
    payload['reason bytes'] = getVarInt(payload_m)
    payload['reason'] = payload_m.read(payload['reason bytes'])
    datalen = payloadlen - (payload_m.tell() - start)
    if datalen > 0:
        payload['extra data'] = payload_m.read(datalen).hex()
    return payload

def parseSendCompactPayload(payload_m: mmap, payloadlen = 0):
    payload = {}
    payload['announce'] = int.from_bytes(payload_m.read(1), byteorder='little')
    payload['version'] = int.from_bytes(payload_m.read(8), byteorder='little')
    return payload

def parseCompactBlockPayload(payload_m: mmap, payloadlen = 0):
    payload = {}
    payload['block header'] = parseBlockHeader(payload_m)
    payload['nonce'] = int.from_bytes(payload_m.read(8), byteorder='little')
    payload['shortids length'] = getVarInt(payload_m)
    payload['shortids'] = []
    for i in range(payload['shortids length']):
        payload['shortids'].append(payload_m.read(8)[::-1])
    payload['prefilled txn length'] = getVarInt(payload_m)
    payload['prefilled txn'] = []
    for i in range(payload['prefilled txn length']):
        prefilled_tx = {}
        prefilled_tx['index'] = getVarInt(payload_m)
        prefilled_tx['tx'] = parseTxPayload(payload_m)
        payload['prefilled txn'].append(prefilled_tx)
    return payload

def parseGetBlockTxnPayload(payload_m: mmap, payloadlen = 0):
    payload = {}
    payload['block hash'] = payload_m.read(32)[::-1]
    payload['indexes length'] = getVarInt(payload_m)
    payload['indexes'] = []
    for i in range(payload['indexes length']):
        index = getVarInt(payload_m)
        payload['indexes'].append(index)
    return payload

def parseBlockTxnPayload(payload_m: mmap, payloadlen = 0):
    payload = {}
    payload['block hash'] = payload_m.read(32)[::-1]
    payload['transactions length'] = getVarInt(payload_m)
    payload['transactions'] = []
    for i in range(payload['transactions length']):
        tx = getVarInt(payload_m)
        payload['transactions'].append(tx)
    return payload


#def getPayload(s):
#    buffer_size = 4096
#    payload_data = s.recv(buffer_size)
#    print('length = %d, payload = %s' % (len(payload_data),payload_data.hex()))
#    return payload_data

def createMessage(command, payload):
    magic = 0x0709110B
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[0:4]
    magic_b = struct.pack('<L', magic)
    cmd_b = struct.pack('<12s', command.encode('ascii'))
    payload_len_b = struct.pack('<L', len(payload))
    checksum_b = struct.pack('<4s', checksum)

    msg = magic_b + cmd_b + payload_len_b + checksum + payload
    return msg
#    return(struct.pack('<L12sL4s', magic, command.encode(), len(payload), checksum) + payload)

def getRandomPeer():
    peers = getTestnetPeers()
    peer = random.choice(peers)
    return peer

#    payload = struct.pack('<LQQ26s26sQ16sL', version, services, timestamp, addr_recv,
#                          addr_trans, nonce, user_agent, start_height)

def createAddrPayload(ipaddr_l: list):
    count = len(ipaddr_l)
    count_b = setVarInt(count)
    addr_b = b''
    for i in rane(count):
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
    for i in range(count):
        inv_type_b = struct.pack('<L', MSG_BLOCK)
        inv_vect_b += inv_type_b + blk_hash_b
    payload = count_b + inv_vect_b
    return payload

def createInvTxPayload(feefilter = 0):
    MSG_TX = 1
    tx_list = []
    if feefilter == 0:
        tx_list = rpc_connection.getrawmempool()
    else:
        tx_dict = rpc_connection.getrawmempool(True)
        tx_list = [tx for tx, v in tx_dict.items() if (v['fee'] * 10**8) > feefilter]

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
    print(recvdpayload, file=flog)
    for i in range(recvdpayload['count']):
        inv_tx = recvdpayload['inventory'][i]['hash']
        inv_type = recvdpayload['inventory'][i]['type']
        inv_type_b = struct.pack('<L', inv_type)
        if inv_type == MSG_TX: 
            for tx in tx_list:
                if tx == inv_tx:
                    print(tx, inv_tx, file=flog)
                    tx_b = bytes.fromhex(tx)[::-1]
                    inv_vect_b += inv_type_b + tx_b
                    count += 1
        elif inv_type == MSG_BLOCK:
            blk_hash = recvdpayload['inventory'][i]['hash']
            try:
                blk = rpc_connection.getblock(blk_hash)
                inv_vect_b += inv_type_b + blk_hash_b
                count += 1
            except Exception as e:
                continue
    if count == 0:
        payload = b''
    else:
        count_b = setVarInt(count)
        payload = count_b + inv_vect_b
    return payload

def createGetDataPayloadFromHeaders(recvdpayload: dict):
    MSG_BLOCK = 2

    inv_vect_b = b''
    count = 0
    for i in range(recvdpayload['count']):
        tx_type_b = struct.pack('<L', MSG_BLOCK)
        blk_hash = recvdpayload[i]['blkhash']
        try:
            blk = rpc_connection.getblock(blk_hash)
        # blk is not found
        except Exception as e:
            print('e.code = %d' % e.code, file=flog)
            blk_hash_b = bytes.fromhex(blk_hash)[::-1]
            inv_vect_b += inv_type_b + blk_hash_b
            count += 1
            continue
    if count == 0:
        payload = b''
    else:
        count_b = setVarInt(count)
        payload = count_b + inv_vect_b
    return payload

def createHeadersPayload(hashes, stophash):
    b_cnt_d = {'fd': 2, 'fe': 4, 'ff': 8}
    found = False
    for blk_hash in hashes:
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
            print('block_hash = %s' % blk_hash, file=flog)
            blk = rpc_connection.getblock(blk_hash, False)
            blk_b = bytes.fromhex(blk)
            blkhdr_b = blk_b[:80]
            headers_b += blkhdr_b + txcnt_b
            blk = rpc_connection.getblock(blk_hash)
            count += 1
            if count == 2000 or 'nextblockhash' not in blk or stophash == blk_hash:
                print(count, file=flog)
                print(stophash, file=flog)
                break
            blk_hash = blk['nextblockhash']
        cnt_b = setVarInt(count)
        payload = cnt_b + headers_b
        return payload

def createSendCmpctPayload():
    announce_b = bytes([1])
    version_b = struct.pack('<Q', 1)
    payload = announce_b + version_b
    return payload

CMDS_WITHOUT_PAYLOAD = ['verack', 'sendheaders', 'getaddr', 'filterclear', 'mempool']

def recvall(s: socket, size: int):
    pass

MSGHDR_SIZE = 24

CMD_FN_MAP = {
    'version': parseVersionPayload,
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

flog = open('communication.log', 'wt+')

def calculateChecksum(b: bytes):
    checksum = hashlib.sha256(hashlib.sha256(b).digest()).digest()[0:4]
    return checksum

# message = header + payload
def checkMessage(msghdr: dict, payload_b: bytes):
    if msghdr['magic'] == '0709110b':
        print('Magic check passed', file=flog)
    else:
        print('Magic check failed', file=flog)
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

def parseMsgHdr(msghdr_b: bytes):
    msghdr = {}
    msghdr['magic'] = msghdr_b[0:4][::-1].hex()
    msghdr['command'] = msghdr_b[4:16].decode("ascii").strip('\0')
    msghdr['length'] = int.from_bytes(msghdr_b[16:20], byteorder='little')
    msghdr['checksum'] = msghdr_b[20:24]
    return msghdr

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
        'headers': [],
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

def sendrecvHandler(s: socket, peerinfo: dict, cmdlist: list):
    peerinfo = {}
    peerinfo['is_connected'] = False
    version_sent = False
    version_recvd = False
    verack_sent = False
    verack_recvd = False

    peerinfo['sendheaders'] = False
    peerinfo['sendcmcpt'] = False

    ping_nonce = 0

    itr = iter(cmdlist)
    sndcmd = 'version'
    payload = createVersionPayload(s)
    sndmsg = createMessage(sndcmd, payload)
    s.send(sndmsg)
    version_sent = True
    print('==> cmd = %s, msg = %s' % (sndcmd, sndmsg.hex()), file=flog)
    wait_resp_l = [CMD_RESP_D[sndcmd]]
    print(wait_resp_l)
    recvmsg = None
    while True:
        sndcmd = None
        if len(wait_resp_l) != 0:
            recvmsg = recvMsg(s)
            if peerinfo['is_connected'] == False:
                if recvmsg['command'] == 'version':
                    version_recvd = True
                    sndcmd = 'verack'
                    payload = b''
                elif recvmsg['command'] == 'verack':
                    verack_recvd = True
                    peerinfo['is_connected'] = version_sent and version_recvd and verack_sent and verack_recvd
                else:
                    raise Exception('Not connected yet but got %s' % recvmsg['command'])
            else:
                # remove command already recieved
                wait_resp_l = [x for x in wait_resp_l if recvmsg['command'] not in x]
                if recvmsg['command'] == 'getaddr':
                    cmd = 'addr'
                    peer = getRandomPeer()
                    payload = createAddrPayload([peer])
                elif recvmsg['command'] == 'pong':
                    nonce = recvmsg['payload']['nonce']
                    if ping_nonce != nonce:
                        raise Exception('Invalid pong nonce: %d, expected: %d' % (nonce, ping_nonce))
                elif recvmsg['command'] == 'ping':
                    sndcmd = 'pong'
                    nonce = recvmsg['payload']['nonce']
                    payload = createPongPayload(nonce)
#                elif recvmsg['command'] == 'filterload':
#                    sndcmd = 'filteradd'
#                    payload = createFilteraddPayload(s)
                elif recvmsg['command'] == 'sendheaders':
                    peerinfo['sendheaders'] = True
                elif recvmsg['command'] == 'sendcmpct':
                    peerinfo['sendcmpct'] = bool(recvmsg['payload']['announce'])
                elif recvmsg['command'] == 'feefilter':
                    if 'feefilter' not in peerinfo:
                        peerinfo['feefilter'] = recvmsg['payload']['feerate']
                    peerinfo['feefilter'] = recvmsg['payload']['feerate']
                elif recvmsg['command'] == 'getheaders':
                    sndcmd = 'headers'
                    hashes = recvmsg['payload']['block locator hashes']
                    stophash = recvmsg['payload']['hash_stop']
                    payload = createHeadersPayload(hashes, stophash)
                elif peerinfo['sendheaders'] == True and recvmsg['command'] == 'headers':
                    sndcmd = 'getdata'
                    payload = createGetDataPayloadFromHeaders(recvmsg['payload'])
                    if payload == b'':
                        print('nothing to getData', file=flog)
                        sndcmd = None
                elif recvmsg['command'] == 'getblocks':
                    sndcmd = 'inv'
                    payload = createInvBlkPayload()
                elif recvmsg['command'] == 'mempool':
                    sndcmd = 'inv'
                    if 'feefilter' in peerinfo:
                        payload = createInvTxPayload(peerinfo['feefilter'])
                    else:
                        payload = createInvTxPayload()
                elif recvmsg['command'] == 'inv':
                    sndcmd = 'getdata'
                    payload = createGetDataPayload(recvmsg['payload'])
                    if payload == b'':
                        print('nothing to getData', file=flog)
                        sndcmd = None
                elif recvmsg['command'] == 'getdata':
                    # this will initiate multiple commands
                    sndcmd = 'senddatalist'
                    payload = createSendDataListPayload(recvmsg['payload'])
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
                ping_nonce = int.from_bytes(payload, byteorder='little')
            elif sndcmd == 'getblocks':
                payload = createGetBlocksPayload(s)
            elif sndcmd == 'cmpctblock':
                payload = createCmpctBlockPayload(s)
            elif sndcmd == 'feefilter':
                payload = createFeeFilterPayload(s)
        if sndcmd != None:
            sndmsg = createMessage(sndcmd, payload)
            s.send(sndmsg)
            print('==> cmd = %s, msg = %s' % (sndcmd, sndmsg.hex()), file=flog)
            if sndcmd == 'verack':
                verack_sent = True
                peerinfo['is_connected'] = version_sent and version_recvd and verack_sent and verack_recvd
                sndmsg = createMessage('sendheaders', b'')
                s.send(sndmsg)
                payload = createSendCmpctPayload()
                sndmsg = createMessage('sendcmpct', payload)
                s.send(sndmsg)
            print('sndcmd = ', sndcmd, file=flog)
            if len(CMD_RESP_D[sndcmd]) > 0:
                wait_resp_l.append(CMD_RESP_D[sndcmd])
        # get new command from peer
        if sndcmd == None and len(wait_resp_l) == 0:
            recvmsg = recvMsg(s)

if __name__ == '__main__':
    peers = getTestnetPeers()
    p = random.choice(peers)
    s = None
    try:
        peerinfo = {}
        cmds = ['getaddr', 'mempool']
        print("Trying to connect to ", p, file=flog)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        err = s.connect(p)
        print('connected', file=flog)
        sendrecvHandler(s, peerinfo, cmds)
        s.close()
    except Exception as e:
        print(e, file=flog)
        print("Exception in connection to ", p, file=flog)
#        continue
    finally:
        flog.close()
        if s != None:
            s.close()
