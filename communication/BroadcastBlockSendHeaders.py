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
    print('height = %d' % height)
    return height

def getGenesisBlockHash():
    blkhash = rpc_connection.getblockhash(0)
    return blkhash

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
        print('expected length = %d' % msghdr['length'])
        print('received length = %d' % len(payload_b))
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

def parseAddrPayload(payload_m: mmap, payloadlen = 0):
    payload = {}
    payload['count'] = getVarInt(payload_m)
    payload['addrs'] = []
    for i in range(payload['count']):
        addr = {}
        addr['timestamp'] = int.from_bytes(payload_m.read(4), byteorder='little')
        addr['addr'] = parseIPAddress(payload_m)
        payload['addrs'].append(addr)
    return payload

def parseSendCompactPayload(payload_m: mmap, payloadlen = 0):
    payload = {}
    payload['announce'] = int.from_bytes(payload_m.read(1), byteorder='little')
    payload['version'] = int.from_bytes(payload_m.read(8), byteorder='little')
    return payload

def parsePingPongPayload(payload_m: mmap, payloadlen = 0):
    payload = {}
    payload['nonce'] = int.from_bytes(payload_m.read(8), byteorder='little')
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
        h_b = hashlib.sha256(payload_m.read(80)).digest()
        hdr['blkhash'] = hashlib.sha256(h_b).digest()[::-1].hex()
        payload_m.seek(start)
        hdr['header'] = parseBlockHeader(payload_m)
        hdr['txn_count'] = getVarInt(payload_m)
        payload['headers'].append(hdr)
    return payload

#def parseTxPayload(payload_m: mmap, payloadlen = 0):
#    payload = {}
#    payload['version'] = int.from_bytes(payload_m.read(4), byteorder='little')
#    payload['tx_in count'] = getVarInt(payload_m)
#    if payload['tx_in count'] == 0:
#        # check if segwit
#        payload['is_segwit'] = bool(int.from_bytes(payload_m.read(1), byteorder='little'))
#        if payload['is_segwit'] == True:
#                payload['tx_in count'] = getVarInt(payload_m)
#    payload['tx_in'] = []
#    for i in range(payload['tx_in count']):
#        txin = {}
#        txin['prev_tx_hash'] = payload_m.read(32)[::-1].hex()
#        txin['prev_tx_out_index'] = int.from_bytes(payload_m.read(4), byteorder='little')
#        txin['bytes_scriptsig'] = getVarInt(payload_m)
#        txin['sriptsig'] = payload_m.read(txin['bytes_scriptsig']).hex()
#        txin['sequence'] = payload_m.read(4)[::-1].hex()
#        payload['tx_in'].append(txin)
#    payload['tx_out count'] = getVarInt(payload_m)
#    payload['tx_out'] = []
#    for i in range(payload['tx_out count']):
#        txout = {}
#        txout['satoshis'] = int.from_bytes(payload_m.read(8), byteorder='little')
#        txout['bytes_scriptpubkey'] = getVarInt(payload_m)
#        txout['scriptpubkey'] = payload_m.read(txout['bytes_scriptpubkey']).hex()
#        payload['tx_out'].append(txout)
#    payload['locktime'] = int.from_bytes(payload_m.read(4), byteorder='little')
#
#    if 'is_segwit' in payload and payload['is_segwit'] == True:
#        for i in range(payload['tx_in count']):
#            payload['tx_in'][i]['witness_count'] = getVarInt(payload_m)
#            payload['tx_in'][i]['witness'] = []
#            for j in range(payload['tx_in'][i]['witness_count']):
#                tx_witness = {}
#                tx_witness['size'] = getVarInt(payload_m)
#                tx_witness['witness'] = bytes.fromhex(payload_m.read(txn_witness['size']).hex())
#                txn['tx_in'][i]['witness'].append(tx_witness)
#        payload['locktime'] = int.from_bytes(payload_m.read(4), byteorder='little')
#
#    return payload

def parseTxPayload(payload_m: mmap, payloadlen = 0):
    payload = {}
    payload['version'] = int.from_bytes(payload_m.read(4), byteorder='little')
    payload['tx_in count'] = getVarInt(payload_m)
    payload['tx_in'] = []
    for i in range(payload['tx_in count']):
        txin = {}
        txin['prev_tx_hash'] = payload_m.read(32)[::-1].hex()
        txin['prev_tx_out_index'] = int.from_bytes(payload_m.read(4), 
                byteorder='little')
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

CMD_FN_MAP = {
    'version': parseVersionPayload,
    'addr': parseAddrPayload,
    'sendcmpct': parseSendCompactPayload,
    'ping': parsePingPongPayload,
    'getheaders': parseGetBlocksGetHeadersPayload,
    'getblocks': parseGetBlocksGetHeadersPayload,
    'headers': parseHeadersPayload,
    'block': parseBlockPayload,
    'feefilter': parseFeeFilterPayload,
    'inv': parseInvPayload
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
#    version_b = struct.pack('<L', 70013)
    services_b = struct.pack('<Q', 1)
    timestamp_b = struct.pack('<Q', int(time.time()))
    myip, myport = s.getsockname()
    addr_recv_b = struct.pack('<26s', createRecvIPAddress(myip, myport))
    addr_trans_b = struct.pack('<26s', createTransIPAddress())
    nonce_b = struct.pack('<Q', random.getrandbits(64))
    user_agent = createUserAgent()
    user_agent_b = struct.pack('<%ds' % len(user_agent), user_agent)
    start_height_b = struct.pack('<L', getLastBlockHeight())
    relay_b = struct.pack('<B', 1)
    payload = version_b + services_b + timestamp_b + addr_recv_b + addr_trans_b + nonce_b + user_agent_b + start_height_b + relay_b
    return payload

def createPongPayload(nonce: int):
    nonce_b = struct.pack('<Q', nonce)
    return nonce_b

def createGetHeadersPayload(hdr_info_l: list):
    version_b = struct.pack('<L', 70015)
#    version_b = struct.pack('<L', 70013)
    blk_locator_hashes_b = b''
    count = 0
    for i in range(len(hdr_info_l) - 1, len(hdr_info_l) - 32, -1):
        if i < 1: # assuming first block is genesis
            break
        blk_locator_hashes_b += bytes.fromhex(hdr_info_l[i]['blkhash'])[::-1]
        count += 1
    blk_locator_hashes_b += bytes.fromhex(getGenesisBlockHash())[::-1]
    count += 1
    hash_count_b = setVarInt(count)
    stop_hash_b = bytes(32)
    payload = version_b \
            + hash_count_b \
            + blk_locator_hashes_b \
            + stop_hash_b
    return payload

def createGetDataPayload(count: int, hash_l: list):
    MSG_BLOCK = 2
    hash_count_b = setVarInt(count)
    hashes_b = b''
    for i in range(count):
        type_b = struct.pack('<L', MSG_BLOCK)
        hashes_b += type_b + bytes.fromhex(hash_l[i]['blkhash'])[::-1]

    payload_b = hash_count_b + hashes_b
    return payload_b

def createGetHeadersPayloadFromCoreCLI():
    version_b = struct.pack('<L', 70015)
    blk_locator_hashes_b = b''
    count = 32
    height = getLastBlockHeight()
    for i in range(0, 31):
        print(height - i)
        blkhash = rpc_connection.getblockhash(height - i)
        blk_locator_hashes_b += bytes.fromhex(blkhash)[::-1]
    blk_locator_hashes_b += bytes.fromhex(getGenesisBlockHash())[::-1]
    hash_count_b = setVarInt(count)
    stop_hash_b = bytes(32)
    payload = version_b \
            + hash_count_b \
            + blk_locator_hashes_b \
            + stop_hash_b
    return payload

def createSendCompactPayload(announce: int, version: int):
    announce_b = struct.pack('<B', announce)
    version_b = struct.pack('<Q', version)
    payload = announce_b + version_b
    return payload

MSGHDR_SIZE = 24

def recvAll(s: socket, payloadlen: int):
    payload_b = b''
    length = payloadlen
    while True:
        recvd_b = s.recv(length)
        payload_b += recvd_b
        if len(payload_b) == payloadlen:
            break
        length = payloadlen - len(payload_b)
    return payload_b

def recvMsg(s: socket):
    global MSGHDR_SIZE, CMD_FN_MAP
    msghdr_b = s.recv(MSGHDR_SIZE)
    msg = parseMsgHdr(msghdr_b)
    payloadlen = msg['length']
    payload_b = recvAll(s, payloadlen)
    checkMessage(msg, payload_b)
    payload_m = mmap.mmap(-1, payloadlen + 1)
    payload_m.write(payload_b)
    payload_m.seek(0)
    msg['payload'] = {}
    if payloadlen > 0:
        msg['payload'] = CMD_FN_MAP[msg['command']](payload_m, payloadlen)
    print('<== msg = %s' % msg, file=flog)
    print('<== msg = %s' % msg)
    return msg

def sendPongMessage(s: socket, recvmsg: dict):
    sndcmd = 'pong'
    nonce = recvmsg['payload']['nonce']
    payload = createPongPayload(nonce)
    sndmsg = createMessage(sndcmd, payload)
    s.send(sndmsg)
    print('==> cmd = %s, msg = %s' % (sndcmd, sndmsg.hex()), file=flog)

def sendSendHeadersMessage(s: socket):
    sndcmd = 'sendheaders'
    payload = b''
    sndmsg = createMessage(sndcmd, payload)
    s.send(sndmsg)
    print('==> cmd = %s, msg = %s' % (sndcmd, sndmsg.hex()), file=flog)

def createHeadersPayloadNoHeaders():
    cnt_b = setVarInt(0)
    headers_b = b''
    payload = cnt_b + headers_b
    return payload

def sendHeadersMessage(s: socket):
    sndcmd = 'headers'
    payload = createHeadersPayloadNoHeaders()
    sndmsg = createMessage(sndcmd, payload)
    s.send(sndmsg)
    print('==> cmd = %s, msg = %s' % (sndcmd, sndmsg.hex()), file=flog)

def sendGetHeadersMessage(s: socket):
    sndcmd = 'getheaders'
    payload = createGetHeadersPayloadFromCoreCLI()
    sndmsg = createMessage(sndcmd, payload)
    s.send(sndmsg)
    print('==> cmd = %s, msg = %s' % (sndcmd, sndmsg.hex()), file=flog)

def waitForHeaders(s: socket):
    while True:
        recvmsg = recvMsg(s)
        if recvmsg['command'] == 'headers':
            break
        elif recvmsg['command'] == 'ping':
            sendPongMessage(s, recvmsg)
        elif recvmsg['command'] == 'getheaders':
            sendHeadersMessage(s)

    return recvmsg

def sendGetDataMessage(s: socket, count: int, hash_l: list):
    sndcmd = 'getdata'
    payload = createGetDataPayload(count, hash_l)
    sndmsg = createMessage(sndcmd, payload)
    s.send(sndmsg)
    print('==> cmd = %s, msg = %s' % (sndcmd, sndmsg.hex()), file=flog)

def waitForBlock(s: socket):
    while True:
        recvmsg = recvMsg(s)
        if recvmsg['command'] == 'block':
            break
        elif recvmsg['command'] == 'ping':
            sendPongMessage(s, recvmsg)
    return recvmsg

def sendAndHandleGetHeaders(s: socket):
    sendGetHeadersMessage(s)
    recvmsg = waitForHeaders(s)
    count = recvmsg['payload']['count']
    for i in range(0, count, 16):
        lindex = i + 16 if i + 16 < count else count
        blk_l = recvmsg['payload']['headers'][i:lindex]
        sendGetDataMessage(s, lindex - i, blk_l)
        for j in range(i, lindex):
            waitForBlock(s)

def waitForHeaders(s: socket):
    while True:
        recvmsg = recvMsg(s)
        if recvmsg['command'] == 'headers':
            break
        elif recvmsg['command'] == 'ping':
            sendPongMessage(s, recvmsg)

    return recvmsg

def waitAndHandleHeaderResponse(s: socket):
    recvmsg = waitForHeaders(s)
    count = recvmsg['payload']['count']
    for i in range(0, count, 16):
        lindex = i + 16 if i + 16 < count else count
        blk_l = recvmsg['payload']['headers'][i:lindex]
        sendGetDataMessage(s, lindex - i, blk_l)
        for j in range(i, lindex):
            waitForBlock(s)

def establishConnection(s: socket):
    # send version messsage
    sndcmd = 'version'
    payload = createVersionPayload(s)
    sndmsg = createMessage(sndcmd, payload)
    print('==> cmd = %s, msg = %s' % (sndcmd, sndmsg.hex()), file=flog)
    s.send(sndmsg)
    vers_sent = True
    # received version message
    recvmsg = recvMsg(s)
    vers_recvd = False
    if recvmsg['command'] == 'version':
        vers_recvd = True
    services = recvmsg['payload']['services']
    if services & 1 == 0x00:
        print('Peer is pruned node')
        return False
    # send verack message
    sndcmd = 'verack'
    payload = b''
    sndmsg = createMessage(sndcmd, payload)
    s.send(sndmsg)
    verack_sent = True
    print('==> cmd = %s, msg = %s' % (sndcmd, sndmsg.hex()), file=flog)
    # received verack message
    recvmsg = recvMsg(s)
    verack_recvd = False
    if recvmsg['command'] == 'verack':
        verack_recvd = True
    if vers_sent and vers_recvd and verack_sent and verack_recvd:
        print('Connection is established', file=flog)
        return True
    return False

def sendrecvHeadersData(s: socket):
    sendSendHeadersMessage(s)
    sendAndHandleGetHeaders(s)
    waitAndHandleHeaderResponse(s)

def sendrecvHandler(s: socket):
    if establishConnection(s) == False:
        print('Establish connection failed', file=flog)
        return
    sendrecvHeadersData(s)
    
if __name__ == '__main__':
    peers = getTestnetPeers()
    p = random.choice(peers)
    s = None
    peerinfo = {}
    print("Trying to connect to ", p, file=flog)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    err = s.connect(p)
    print('connected', file=flog)
    sendrecvHandler(s)
    s.close()
    flog.close()
