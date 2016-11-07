import crypto
import requests

class ServerError(Exception):
    pass


class Client:
    def __init__(self, base_url, use_encryption=True, use_verification=False):
        self.base_url = base_url
        self.rsa = crypto.RSASucker()
        self.session_id = None
        self.aes = None
        self.use_encryption = use_encryption
        self.use_verification = use_verification

    @staticmethod
    def check_response(response):
        if response.status_code != 200:
            raise ServerError("HTTP Response error: {} {}".format(response.status_code, response.reason))
        elif response.json()['errorDto']['code'] is not None:
            raise ServerError(response.json()['errorDto']['message'])

    def connect(self):
        resp = requests.post(self.base_url + 'rsakey', json={'rsaKey': self.rsa.public,
                                                             'encryption': self.use_encryption,
                                                             'postCode': self.use_verification})
        dt = resp.json()['data']
        self.session_id = dt['sessionId']
        dt = self.rsa.decrypt(dt, ['aesKey', 'ivector'])
        self.aes = crypto.AESSucker(dt['aesKey'], dt['ivector'])

    def login(self, login, password):
        data = {
            'sessionId': self.session_id,
            'login': self.encrypt(login),
            'password': self.encrypt(password),
        }
        resp = requests.post(self.base_url + 'login', json=data)
        self.check_response(resp)

    def verify(self, code):
        data = {
            'code': self.encrypt(code),
            'sessionId': self.session_id
        }

        resp = requests.post(self.base_url + 'verify', json=data)
        self.check_response(resp)

    def encrypt(self, data):
        return data if not self.use_encryption else self.aes.encrypt(data)


if __name__ == '__main__':
    import os
    import sys
    client = Client(os.environ.get('BASE_URL', 'http://127.0.0.1:8080/'))
    client.connect()
    client.login(*sys.argv[1:])
