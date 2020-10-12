from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

rpc_connection = AuthServiceProxy("http://%s:%s@127.0.0.1:18332"%('test', 'test'))

tx_list = rpc_connection.getrawmempool()
#tx_list = rpc_connection.getrawmempool(True)
print(tx_list)
