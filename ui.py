# -*- coding: utf-8 -*-

from PyQt5 import QtCore, QtGui, QtWidgets


class ClientApp(QtWidgets.QWidget):
    def __init__(self, client, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client = client
        self.stacked = QtWidgets.QStackedLayout(self)

        self.login = LoginWidget(self)
        self.stacked.addWidget(self.login)

        self.verify = CodeVerificationWidget(self)
        self.stacked.addWidget(self.verify)

    def on_login(self, login, password):
        if self.client.login(login, password):
            self.stacked.setCurrentIndex(1)
        else:
            # TODO: show an error message
            self.stacked.setCurrentIndex(0)

    def on_verify(self, code):
        if self.client.verify(code):
            self.stacked.setCurrentIndex(2)
        else:
            # TODO: show an error message
            self.stacked.setCurrentIndex(1)


class LoginWidget(QtWidgets.QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app

        self.setObjectName('Login')
        self.setMinimumWidth(250)

        layout = QtWidgets.QFormLayout()
        self.setLayout(layout)

        self.login_edit = QtWidgets.QLineEdit()
        layout.addRow('Login:', self.login_edit)

        self.password_edit = QtWidgets.QLineEdit()
        self.password_edit.setEchoMode(QtWidgets.QLineEdit.Password)
        layout.addRow('Password:', self.password_edit)

        self.submit_button = QtWidgets.QPushButton('Login')
        self.submit_button.clicked.connect(self.on_submit)
        layout.addWidget(self.submit_button)

    def on_submit(self):
        self.app.on_login(self.login_edit.text(), self.password_edit.text())


class CodeVerificationWidget(QtWidgets.QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app

        layout = QtWidgets.QFormLayout(self)

        self.code_edit = QtWidgets.QLineEdit()
        layout.addRow('Code', self.code_edit)

        self.submit_button = QtWidgets.QPushButton()
        self.submit_button.clicked.connect(self.submit)
        layout.addWidget(self.submit_button)

    def submit(self):
        self.app.verify(self.code_edit.text())
