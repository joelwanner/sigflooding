import socket
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
import base64
import datetime

def diff_microseconds(ta, tb):
    d = ta - tb
    return d.seconds * 1000000 + d.microseconds

class Server(object):
    def __init__(self, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('localhost', port))
        self.pkeys = {}

    def start(self):
        start_time = datetime.datetime.now()
        verify_us = 0 # Time spent verifying signatures

        try:
            while True:
                msg, addr = self.sock.recvfrom(1024)
                s = msg.decode('ascii')
                fields = s.split('|')
                if fields[0] == 'pkey':
                    self._recv_pkey(addr, fields[1])
                elif fields[0] == 'req':
                    t0 = datetime.datetime.now()
                    msg = fields[1]
                    sig = fields[2]
                    if not self._verify(addr, msg, sig):
                        msg = '[invalid signature]'
                    t1 = datetime.datetime.now()
                    time = t1.strftime('%H:%M:%S.%f')
                    delta = diff_microseconds(t1, t0)
                    verify_us += delta
                    print(f"{time} d[{delta:04d}us] {addr[0]}:{addr[1]} | {msg}")
        except KeyboardInterrupt:
            total_us = diff_microseconds(datetime.datetime.now(), start_time)
            verify_load = verify_us / total_us
            print()
            print(f"Running time: {total_us/1000000:.3f}s")
            print(f"Signature verification load: {verify_load*100:.2f}%")
    
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
        try:
            verifier = PKCS1_v1_5.new(self.pkeys[addr])
        except KeyError:
            return False
        return verifier.verify(h, s)

