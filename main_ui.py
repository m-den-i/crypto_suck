import os
import sys
from PyQt5.QtWidgets import QApplication
from ui import ClientApp
import crypto
import requests


class Client:
    def __init__(self, base_url, use_encryption=True, use_verification=False):
        self.base_url = base_url
        self.rsa = crypto.RSASucker()
        self.session_id = None
        self.aes = None
        self.use_encryption = use_encryption
        self.use_verification = use_verification

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

        if resp.status_code == 200:
            return True
        return False

    def verify(self, code):
        data = {
            'code': self.encrypt(code),
            'sessionId': self.session_id
        }

        resp = requests.post(self.base_url + 'verify', json=data)
        # todo: check

    def encrypt(self, data):
        return data if not self.use_encryption else self.aes.encrypt(data)


def main():
    client = Client(os.environ.get('BASE_URL', 'http://127.0.0.1:8080/'))

    app = QApplication(sys.argv)
    ex = ClientApp(client)
    ex.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
