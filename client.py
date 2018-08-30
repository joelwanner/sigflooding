import socket
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
import base64

class Client(object):
    def __init__(self, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addr = ('localhost', port)

    def request(self, msg):
        sig = self._sign(msg)
        payload = msg + '|' + sig
        self._send('req', payload)

    def attack(self, msg):
        while True:
            self.request('spam')

    def _send(self, mtype, payload):
        self.sock.sendto(bytearray(mtype + '|' + payload, 'ascii'), self.addr)

    def _sign(self, msg):
        raise NotImplementedError

class RSAClient(Client):
    def __init__(self, port):
        super().__init__(port)
        with open('pkey.pem') as f:
            self.pkey = RSA.importKey(f.read())
        with open('skey.pem') as f:
            self.skey = RSA.importKey(f.read())
        self._send('pkey', self.pkey.exportKey().decode('ascii'))

    def _sign(self, msg):
        h = SHA.new(msg.encode('ascii'))
        signer = PKCS1_v1_5.new(self.skey)
        sig = signer.sign(h)
        return base64.b64encode(sig).decode('ascii')

