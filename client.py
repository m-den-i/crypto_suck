import crypto
import requests
import base64
import functools as _fn

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

    def make_request(self, endpoint, data, include_session=True, check_session=True, method='post'):
        if include_session:
            data['sessionId'] = self.session_id
        request = _fn.partial(getattr(requests, method), self.base_url + endpoint)
        response = request(json=data)
        if response.status_code != 200:
            raise ServerError('HTTP Response error: {} {}'.format(response.status_code, response.reason))

        data = response.json()

        if data['errorDto']['code'] is not None:
            raise ServerError(data['errorDto']['message'])
        elif check_session and self.session_id != data['data']['sessionId']:
            # Should be another exception
            raise ServerError('Invalid SessionID. ')

        return data['data']

    def connect(self):
        data = {
            'rsaKey': self.rsa.public if self.use_encryption else '',
            'encryption': self.use_encryption,
            'postCode': self.use_verification
        }
        data = self.make_request('rsakey', data, check_session=False)

        self.session_id = data['sessionId']
        if self.use_encryption:
            self.aes = crypto.AESSucker(self.rsa.decrypt(data['aesKey']),
                                        self.rsa.decrypt(data['ivector']))

    def login(self, login, password):
        data = {
            'login': self.encrypt(login),
            'password': self.encrypt(password),
        }

        data = self.make_request('login', data)

        if not self.use_verification:
            self.build_token(data)

    def verify(self, code):
        data = {
            'code': self.encrypt(code),
        }

        data = self.make_request('verify', data)
        self.build_token(data)

    def build_token(self, data):
        self.totp = crypto.TOTP(self.decrypt(data['secret']))
        token = self.totp.token()
        data = self.make_request('token', data={'token': token}, check_session=False)

    def send_file(self, file_name):
        data = {'token': self.totp.token(), 'sessionId': self.session_id}
        with open(file_name, 'rb') as f:
            response = requests.post(self.base_url + 'files?name={}'.format(file_name), data=data, files={'file': f})
        # print(response, response['data'])
        return response, response.json()

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
