import base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA


class RSASucker:
    def __init__(self, bits=2048, e=65537):
        new_key = RSA.generate(bits, e=e)
        self.public = base64.b64encode(new_key.publickey().exportKey("DER")).decode()
        self._rsa = PKCS1_OAEP.new(new_key)

    def decrypt(self, json, keys):
        for k in keys:
            b64decoded = base64.b64decode(json[k])
            json[k] = self._rsa.decrypt(b64decoded)
        return json


class AESSucker:
    LENGTH = 16

    def __init__(self, key, iv):
        self.key = key
        self.iv = iv

    @property
    def cipher(self):
        return AES.new(self.key, AES.MODE_OFB, IV=self.iv)

    def encrypt(self, data):
        if len(data) % self.LENGTH != 0:
            missing = (self.LENGTH - len(data) % self.LENGTH)
        else:
            missing = self.LENGTH
        data += chr(missing) * missing
        return base64.b64encode(self.cipher.encrypt(data)).decode()

    def decrypt(self, data):
        decrypted = self.cipher.decrypt(data)
        return decrypted[:-ord(decrypted[-1])]
