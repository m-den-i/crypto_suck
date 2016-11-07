# -*- coding: utf-8 -*-

from PyQt5 import QtCore, QtGui, QtWidgets


class LoginWidget(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
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
        login = self.login_edit.text()
        password = self.password_edit.text()
