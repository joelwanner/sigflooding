import socket
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
import base64
import datetime

class Server(object):
    def __init__(self, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('localhost', port))
        self.pkeys = {}

    def start(self):
        while True:
            msg, addr = self.sock.recvfrom(1024)
            s = msg.decode('ascii')
            fields = s.split('|')
            if fields[0] == 'pkey':
                self._recv_pkey(addr, fields[1])
            elif fields[0] == 'req':
                time = datetime.datetime.now()
                msg = fields[1]
                sig = fields[2]
                if self._verify(addr, msg, sig):
                    print(time, addr, msg)
                else:
                    print(time, addr, '[invalid signature]')
    
    def _recv_pkey(self, addr, key):
        raise NotImplementedError

    def _verify(self, addr, msg, sig):
        raise NotImplementedError

class RSAServer(Server):
    def _recv_pkey(self, addr, key):
        self.pkeys[addr] = RSA.importKey(key)

    def _verify(self, addr, msg, sig):
        h = SHA.new(msg.encode('ascii'))
        s = base64.b64decode(sig.encode('ascii'))
        verifier = PKCS1_v1_5.new(self.pkeys[addr])
        return verifier.verify(h, s)

