import sys
from PyQt5.QtWidgets import QMainWindow, QPushButton, QApplication
from ui import LoginWidget
import crypto
import requests


def connect():
    rsa_sucker = crypto.RSASucker()
    resp = requests.post("http://127.0.0.1:8084/google/rsakey", data=rsa_sucker._pub)
    dt = resp.json()['data']
    dt = rsa_sucker.decrypt(dt, ['aesKey', 'ivector'])
    aes_sucker = crypto.AESSucker(dt['aesKey'], dt['ivector'])
    del dt['aesKey']
    del dt['ivector']




def main():
    app = QApplication(sys.argv)
    ex = LoginWidget()
    ex.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    connect()
    main()
