# -*- coding: utf-8 -*-

from PyQt5 import QtCore, QtGui, QtWidgets
from client import ServerError


class ClientApp(QtWidgets.QWidget):
    STACK, LOGIN, VERIFY, DOCUMENTS, FILE = range(5)

    def __init__(self, client, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client = client
        self.cycle = True

        layout = QtWidgets.QVBoxLayout(self)
        self.error_message = QtWidgets.QLabel()
        layout.addWidget(self.error_message)

        self.stacked = QtWidgets.QStackedLayout()
        layout.addLayout(self.stacked)

        self.stack = StackWidget(self)
        self.stacked.addWidget(self.stack)

        self.login = LoginWidget(self)
        self.stacked.addWidget(self.login)

        self.verify = CodeVerificationWidget(self)
        self.stacked.addWidget(self.verify)

        self.documents = DocumentsWidget(self)
        self.stacked.addWidget(self.documents)

        self.file = FileWidget(self)
        self.stacked.addWidget(self.file)

    def show_error(self, message):
        self.error_message.setText(message)

    def hide_error(self):
        self.error_message.setText('')

    def change_view(self, index):
        self.hide_error()
        self.stacked.setCurrentIndex(index)

    def set_stack(self, encryption, verification):
        self.client.use_encryption = encryption
        self.client.use_verification = verification
        self.client.connect()
        self.change_view(self.LOGIN)

    def on_login(self, login, password):
        if not login or not password:
            self.show_error('Login and/or password cannot be empty.')
            return
        try:
            self.client.login(login, password)
            if self.client.use_verification:
                self.change_view(self.VERIFY)
            else:
                self.show_documents()
        except ServerError as e:
            self.show_error(str(e))

    def on_verify(self, code):
        try:
            self.client.verify(code)
            self.show_documents()
        except ServerError as e:
            self.show_error(str(e))

    def show_documents(self):
        self.change_view(self.DOCUMENTS)
        self.documents.show_documents(self.client.get_files())
        if self.cycle:
            self.cycle = False
            self.update_documents()

    @QtCore.pyqtSlot()
    def update_documents(self):
        self.documents.show_documents(self.client.get_files())
        QtCore.QTimer.singleShot(1000, self.update_documents)

    def show_file(self, name):
        self.change_view(self.FILE)
        self.file.show_file(self.client.get_file(name))


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

        self.submit_button = QtWidgets.QPushButton('OK')
        self.submit_button.clicked.connect(self.submit)
        layout.addWidget(self.submit_button)

    def submit(self):
        self.app.on_verify(self.code_edit.text())


class DocumentsWidget(QtWidgets.QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app

        layout = QtWidgets.QVBoxLayout(self)

        open_file = QtWidgets.QPushButton('Add file')
        open_file.clicked.connect(self.select_file)
        layout.addWidget(open_file)

        layout.addWidget(QtWidgets.QLabel('Well done!'))
        self.list_view = QtWidgets.QListWidget()
        self.list_view.itemDoubleClicked.connect(lambda: self.app.show_file(self.list_view.currentItem().text()))
        layout.addWidget(self.list_view)

    def select_file(self):
        filename, _ = QtWidgets.QFileDialog.getOpenFileName()
        self.app.client.send_file(filename)
        self.app.update_documents()

    def show_documents(self, documents):
        self.list_view.clear()
        self.list_view.addItems([doc['name'] for doc in documents])


class FileWidget(QtWidgets.QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app

        layout = QtWidgets.QVBoxLayout(self)

        back_button = QtWidgets.QPushButton('Back')
        back_button.clicked.connect(self.app.show_documents)
        layout.addWidget(back_button)

        self.title = QtWidgets.QLabel()
        self.label = QtWidgets.QLabel()
        layout.addWidget(self.title)
        layout.addWidget(self.label)

    def show_file(self, data):
        self.title.setText(data['name'])
        self.label.setText(data['content'])


if __name__ == '__main__':
    import os
    import sys
    from client import Client

    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = os.environ.get('BASE_URL', 'http://127.0.0.1:8080/')
    client = Client(url)
    app = QtWidgets.QApplication(sys.argv)
    ex = ClientApp(client)
    ex.show()
    sys.exit(app.exec_())
