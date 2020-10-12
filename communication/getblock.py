from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

rpc_connection = AuthServiceProxy("http://%s:%s@127.0.0.1:8332"%('test', 'test'))

#blkhash = "2afb3e31cbb474a29c91ca0012760b56575670136a0c8d66f48ab5657d24e821"
blkhash = "0000000000000000000a3e7cd6d8e3741a4f11c41a2b09f0bf99b0bdacfea499"
try:
    blk = rpc_connection.getblock(blkhash, False)
except Exception as e:
    print(e.code)
print(blk)
