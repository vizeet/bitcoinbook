import socket;
import time;
import hashlib;
import struct;
import random;

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
HOST = "5.182.39.200";
PORT = 8333;

def create_version_message():
    version = struct.pack("i",70015);
    services = struct.pack("Q",0);
    timestamp = struct.pack("q",int(time.time()));
    addr_recv_services = struct.pack("Q",0);
    addr_recv_ip = struct.pack(">16s",bytes(HOST, 'utf-8'));
    addr_recv_port = struct.pack(">H",8333);
    addr_trans_services = struct.pack("Q",0);
    addr_trans_ip = struct.pack(">16s",bytes("127.0.0.1",'utf-8'));
    addr_trans_port = struct.pack(">H",8333);
    nonce = struct.pack("Q", random.getrandbits(64));
    user_agent_byes = struct.pack("B",0);
    start_height = struct.pack("i",596306);
    relay = struct.pack("?",False);
    payload = version + services + timestamp + addr_recv_services + addr_recv_ip + addr_recv_port + addr_trans_services + addr_trans_ip + addr_trans_port + nonce + user_agent_byes + start_height + relay;
    magic = bytes.fromhex("F9BEB4D9");
    command = b"version" + 5 * b"\00";
    length = struct.pack("I", len(payload));
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4];
    return magic + command + length + checksum + payload;

def create_getaddr_message():
    magic = bytes.fromhex("F9BEB4D9");
    command = b"getaddr" + 5 * b"\00";
    payload = b"";
    length = struct.pack("I", len(payload));
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4];
    return magic + command + length + checksum + payload;

 sock.connect((HOST,PORT));
 sock.send(create_version_message());
 sock.recv(1024);
 time.sleep(5);
 sock.send(create_verack_message());
 time.sleep(5);
 sock.send(create_getaddr_message());
 sock.recv(1024);
