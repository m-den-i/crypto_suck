# -*- coding: utf-8 -*-

from PyQt5 import QtCore, QtGui, QtWidgets


class ClientApp(QtWidgets.QWidget):
    STACK, LOGIN, VERIFY, DOCUMENTS = range(4)

    def __init__(self, client, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client = client
        self.stacked = QtWidgets.QStackedLayout(self)

        self.stack = StackWidget(self)
        self.stacked.addWidget(self.stack)

        self.login = LoginWidget(self)
        self.stacked.addWidget(self.login)

        self.verify = CodeVerificationWidget(self)
        self.stacked.addWidget(self.verify)

        self.documents = DocumentsWidget(self)
        self.stacked.addWidget(self.documents)

    def set_stack(self, encryption, verification):
        self.client.use_encryption = encryption
        self.client.use_verification = verification
        self.client.connect()
        self.stacked.setCurrentIndex(self.LOGIN)

    def on_login(self, login, password):
        if self.client.login(login, password):
            self.stacked.setCurrentIndex(self.VERIFY if self.client.use_verification else self.DOCUMENTS)
        else:
            # TODO: show an error message
            self.stacked.setCurrentIndex(self.LOGIN)

    def on_verify(self, code):
        if self.client.verify(code):
            self.stacked.setCurrentIndex(self.DOCUMENTS)
        else:
            # TODO: show an error message
            self.stacked.setCurrentIndex(self.VERIFY)


class StackWidget(QtWidgets.QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app

        layout = QtWidgets.QVBoxLayout(self)

        self.encryption_check = QtWidgets.QCheckBox('Encryption', checked=True)
        layout.addWidget(self.encryption_check)

        self.verify_code = QtWidgets.QCheckBox('Verify')
        layout.addWidget(self.verify_code)

        self.ok = QtWidgets.QPushButton('Ok')
        self.ok.clicked.connect(self.submit)
        layout.addWidget(self.ok)

    def submit(self):
        self.app.set_stack(self.encryption_check.isChecked(),
                           self.verify_code.isChecked())


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


class DocumentsWidget(QtWidgets.QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app

        layout = QtWidgets.QVBoxLayout(self)

        layout.addWidget(QtWidgets.QLabel('Well done!'))
