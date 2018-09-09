from server import *
from client import *
import sys

port = 4243
host = 'localhost'

if len(sys.argv) > 2:
    addr = sys.argv[2].split(':')
    host = addr[0]
    port = int(addr[1])

flag = sys.argv[1]
if flag == '-s':
    server = RSAServer(port)
    server.start()
else:
    client = RSAClient(host, port)
    if flag == '-c':
        client.request('legitimate message')
    elif flag == '-a':
        client.attack('spam')

