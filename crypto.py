import base64
from Crypto.Cipher import PKCS1_OAEP


class RSASucker:
    def __init__(self, bits=2048, e=65537):
        from Crypto.PublicKey import RSA
        new_key = RSA.generate(bits, e=e)
        self._pub = base64.b64encode(new_key.publickey().exportKey("DER"))
        self._rsa = PKCS1_OAEP.new(new_key)

    def decrypt(self, json, keys):
        for k in keys:
            b64decoded = base64.b64decode(json[k])
            json[k] = self._rsa.decrypt(b64decoded)
        return json


class AESSucker:
    def __init__(self, k, iv):
        from Crypto.Cipher import AES
        self._aes = AES.new(k, AES.MODE_OFB, IV=iv)

    def encrypt(self, data):
        return self._aes.encrypt(data)

    def decrypt(self, data):
        return self._aes.decrypt(data)
