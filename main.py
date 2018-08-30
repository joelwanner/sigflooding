from server import *
from client import *
import sys

port = 4243
if len(sys.argv) > 2:
    port = int(sys.argv[2])

flag = sys.argv[1]
if flag == '-s':
    server = RSAServer(port)
    server.start()
else:
    client = RSAClient(port)
    if flag == '-c':
        client.request('legitimate message')
    elif flag == '-a':
        client.attack('spam')

