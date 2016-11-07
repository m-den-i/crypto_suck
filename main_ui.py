import os
import sys
from PyQt5.QtWidgets import QMainWindow, QPushButton, QApplication
from ui import LoginWidget
import crypto
import requests


class Client:
    def __init__(self, base_url):
        self.base_url = base_url
        self.rsa = crypto.RSASucker()
        self.session_id = None
        self.aes = None

    def connect(self):
        resp = requests.post(self.base_url + 'rsakey', data=self.rsa._pub)
        dt = resp.json()['data']
        self.session_id = dt['sessionId']
        dt = self.rsa.decrypt(dt, ['aesKey', 'ivector'])
        self.aes = crypto.AESSucker(dt['aesKey'], dt['ivector'])

    def login(self, login, password):
        data = {
            'sessionId': self.session_id,
            'login': self.aes.encrypt(login),
            'password': self.aes.encrypt(password),
        }
        resp = requests.post(self.base_url + 'login', json=data)

        if resp.status_code == 200:
            return True
        return False


def main():
    client = Client(os.environ.get('BASE_URL', 'http://127.0.0.1:8084/google/'))

    app = QApplication(sys.argv)
    ex = LoginWidget()
    ex.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
