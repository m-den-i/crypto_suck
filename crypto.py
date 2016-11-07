import base64
import time
import hashlib
from hmac import new as hmac
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA


class RSASucker:
    def __init__(self, bits=2048, e=65537):
        new_key = RSA.generate(bits, e=e)
        self.public = base64.b64encode(new_key.publickey().exportKey("DER")).decode()
        self._rsa = PKCS1_OAEP.new(new_key)

    def decrypt(self, data):
        return self._rsa.decrypt(base64.b64decode(data))


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
        decrypted = self.cipher.decrypt(base64.b64decode(data))
        return decrypted[:-decrypted[-1]]


class TOTP:
    def __init__(self, secret):
        self.secret = secret

    def token(self):
        timestamp = int(time.time() // 30).to_bytes(8, 'big')
        hash_value = hmac(self.secret, timestamp, hashlib.sha1).digest()

        offset = hash_value[19] & 0xf
        truncated = hash_value[offset] & 0x7f
        for i in range(1, 4):
            truncated <<= 8
            truncated |= hash_value[offset + i] & 0xff

        return truncated % 1000000
