import base64
import time
import hashlib
from hmac import new as hmac
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA


class RSASucker:
    """ Rivest Shamir Adleman public-key cryptosystem wrapper. """

    def __init__(self, bits=2048, e=65537):
        new_key = RSA.generate(bits, e=e)
        self.public = base64.b64encode(new_key.publickey().exportKey("DER")).decode()
        self._rsa = PKCS1_OAEP.new(new_key)

    def decrypt(self, data):
        return self._rsa.decrypt(base64.b64decode(data))

    def encrypt(self, data):
        return self._rsa.encrypt(base64.b64encode(data))


class AESSucker:
    """ AES cypher wrapper. """

    def __init__(self, key, iv, mode=AES.MODE_OFB, length=16):
        self.key = key
        self.iv = iv
        self.mode = mode
        self.length = length

    @property
    def cipher(self):
        return AES.new(self.key, self.mode, IV=self.iv)

    def encrypt(self, data):
        """ Encrypts a plaintext and adds PKCS7 padding. """
        if len(data) % self.length != 0:
            missing = (self.length - len(data) % self.length)
        else:
            missing = self.length
        if type(data) is str:
            data = data.encode()
        data += chr(missing).encode() * missing
        result = self.cipher.encrypt(data)

        return result

    def decrypt(self, data):
        """ Decrypts a ciphertext and removes PKCS7 padding."""
        decrypted = self.cipher.decrypt(data)
        return decrypted[:-decrypted[-1]]


class TOTP:
    """ Time-based One-Time Password algorithm. """

    def __init__(self, secret):
        self.secret = secret

    def compute(self):
        """ Computes an one-time password. """
        timestamp = int(time.time() // 30).to_bytes(8, 'big')
        hash_value = hmac(self.secret, timestamp, hashlib.sha1).digest()

        offset = hash_value[19] & 0xf
        truncated = hash_value[offset] & 0x7f
        for i in range(1, 4):
            truncated <<= 8
            truncated |= hash_value[offset + i] & 0xff

        return truncated % 1000000
