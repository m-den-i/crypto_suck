import crypto
import requests
import time
import base64

class ServerError(Exception):
    pass


class Client:
    def __init__(self, base_url, use_encryption=True, use_verification=False):
        self.base_url = base_url
        self.rsa = crypto.RSASucker()
        self.session_id = None
        self.aes = None
        self.totp = None
        self.use_encryption = use_encryption
        self.use_verification = use_verification

    def make_request(self, endpoint, data):
        response = requests.post(self.base_url + endpoint, json=data)
        self.check_response(response)
        return response.json()['data']

    def check_response(self, response):
        if response.status_code != 200:
            raise ServerError('HTTP Response error: {} {}'.format(response.status_code, response.reason))
        data = response.json()
        if data['errorDto']['code'] is not None:
            raise ServerError(response.json()['errorDto']['message'])
        elif self.session_id and 'sessionId' in data and self.session_id != response.json()['data']['sessionId']:
            # Should be another exception
            raise ServerError('Invalid SessionID. ')

    def connect(self):
        data = {
            'rsaKey': self.rsa.public if self.use_encryption else '',
            'encryption': self.use_encryption,
            'postCode': self.use_verification
        }
        data = self.make_request('rsakey', data)

        self.session_id = data['sessionId']
        if self.use_encryption:
            self.aes = crypto.AESSucker(self.rsa.decrypt(data['aesKey']),
                                        self.rsa.decrypt(data['ivector']))

    def login(self, login, password):
        data = {
            'sessionId': self.session_id,
            'login': self.encrypt(login),
            'password': self.encrypt(password),
        }

        data = self.make_request('login', data)

        if not self.use_verification:
            self.build_token(data)

    def verify(self, code):
        data = {
            'code': self.encrypt(code),
            'sessionId': self.session_id
        }

        data = self.make_request('verify', data)
        self.build_token(data)

    def build_token(self, data):
        self.totp = crypto.TOTP(self.decrypt(data['secret']))
        token = self.totp.token()
        data = self.make_request('token', data={'sessionId': self.session_id, 'token': token})

    def decrypt(self, data):
        return base64.b64decode(data) if not self.use_encryption else self.aes.decrypt(data)

    def encrypt(self, data):
        return base64.b64encode(bytes(data, 'utf-8')).decode() if not self.use_encryption else self.aes.encrypt(data)


if __name__ == '__main__':
    import os
    import sys
    client = Client(os.environ.get('BASE_URL', 'http://127.0.0.1:8080/'))
    client.connect()
    client.login(*sys.argv[1:])
