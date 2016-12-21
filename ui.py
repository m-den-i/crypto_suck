# -*- coding: utf-8 -*-

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtGui import QPixmap

from client import ServerError
from settings import SETTINGS


class ClientApp(QtWidgets.QWidget):
    LOGIN, VERIFY, DOCUMENTS, FILE = range(4)

    def __init__(self, url, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.url = url
        self.client = None
        self.updating = False

        layout = QtWidgets.QVBoxLayout(self)
        self.error_message = QtWidgets.QLabel()
        layout.addWidget(self.error_message)

        self.stacked = QtWidgets.QStackedLayout()
        layout.addLayout(self.stacked)

        self.login = LoginWidget()
        self.login.submit.connect(self.on_login)
        self.stacked.addWidget(self.login)

        self.verify = CodeVerificationWidget()
        self.stacked.addWidget(self.verify)

        self.documents = DocumentsWidget()
        self.documents.add_file.connect(self.send_file)
        self.documents.select_file.connect(self.show_file)
        self.stacked.addWidget(self.documents)

        self.file = FileWidget()
        self.file.go_back.connect(self.show_documents)
        self.file.delete_file.connect(self.delete_file)
        self.stacked.addWidget(self.file)

    def show_error(self, message):
        self.error_message.setText(message)

    def hide_error(self):
        self.error_message.setText('')

    def change_view(self, index):
        self.hide_error()
        self.stacked.setCurrentIndex(index)

    @QtCore.pyqtSlot(str)
    def delete_file(self, name):
        if self.client.delete_file(name):
            self.show_error("File '{}' was deleted.".format(name))
        self.show_documents()

    @QtCore.pyqtSlot(bool, bool)
    def set_stack(self, encryption, verification):
        self.client.use_encryption = encryption
        self.client.use_verification = verification
        self.client.connect()
        self.change_view(self.LOGIN)

    @QtCore.pyqtSlot(str, str, bool, bool)
    def on_login(self, login, password, use_encryption, use_verification):
        if not login or not password:
            self.show_error('Login and/or password cannot be empty.')
            return
        try:
            self.client = Client(login, password, base_url=self.url,
                                 use_encryption=use_encryption, use_verification=use_verification)
            self.client.connect()
            if self.client.use_verification:
                self.change_view(self.VERIFY)
            else:
                self.show_documents()
        except (ServerError, ValueError) as e:
            self.show_error(str(e))

    @QtCore.pyqtSlot(str)
    def on_verify(self, code):
        try:
            self.client.verify(code)
            self.show_documents()
        except ServerError as e:
            self.show_error(str(e))

    def show_documents(self):
        self.change_view(self.DOCUMENTS)
        self.documents.display(self.client.get_files())

        if not self.updating:
            self.updating = True
            self.update_documents()

    @QtCore.pyqtSlot(str)
    def send_file(self, filename):
        self.client.send_file(filename)

    @QtCore.pyqtSlot()
    def update_documents(self):
        self.documents.display(self.client.get_files())
        QtCore.QTimer.singleShot(1000, self.update_documents)

    @QtCore.pyqtSlot(str)
    def show_file(self, name):
        self.change_view(self.FILE)
        self.file.display(self.client.get_file(name))

    def sizeHint(self):
        return QtCore.QSize(400, 300)


class LoginWidget(QtWidgets.QWidget):
    submit = QtCore.pyqtSignal(str, str, bool, bool)

    def __init__(self):
        super().__init__()

        self.setObjectName('Login')
        self.setMinimumWidth(300)

        layout = QtWidgets.QGridLayout()
        self.setLayout(layout)

        self.login_edit = QtWidgets.QLineEdit()
        self.login_edit.setMinimumWidth(200)
        layout.addWidget(QtWidgets.QLabel('Login:'), 0, 0)
        layout.addWidget(self.login_edit, 0, 1)

        self.password_edit = QtWidgets.QLineEdit()
        self.password_edit.setEchoMode(QtWidgets.QLineEdit.Password)
        self.password_edit.setMinimumWidth(200)
        layout.addWidget(QtWidgets.QLabel('Password:'), 1, 0)
        layout.addWidget(self.password_edit, 1, 1)

        self.encryption_check = QtWidgets.QCheckBox('Encryption', checked=True)
        layout.addWidget(self.encryption_check)

        self.verify_code = QtWidgets.QCheckBox('Verify')
        layout.addWidget(self.verify_code)

        submit_button = QtWidgets.QPushButton('Login')
        submit_button.clicked.connect(self.on_submit)
        layout.addWidget(submit_button, 3, 0, 1, 2, QtCore.Qt.AlignHCenter)
        layout.setAlignment(QtCore.Qt.AlignHCenter)

    def on_submit(self):
        self.submit.emit(self.login_edit.text().strip(),
                         self.password_edit.text().strip(),
                         self.encryption_check.isChecked(),
                         self.verify_code.isChecked())


class CodeVerificationWidget(QtWidgets.QWidget):
    submit = QtCore.pyqtSignal(str)

    def __init__(self):
        super().__init__()

        layout = QtWidgets.QFormLayout(self)

        self.code_edit = QtWidgets.QLineEdit()
        layout.addRow('Code', self.code_edit)

        submit_button = QtWidgets.QPushButton('OK')
        submit_button.clicked.connect(self.on_submit)
        layout.addWidget(submit_button)

    def on_submit(self):
        self.submit.emit(self.code_edit.text())


class DocumentsWidget(QtWidgets.QWidget):
    add_file = QtCore.pyqtSignal(str)
    select_file = QtCore.pyqtSignal(str)

    def __init__(self):
        super().__init__()

        layout = QtWidgets.QVBoxLayout(self)

        self.list_view = QtWidgets.QListWidget()
        self.list_view.itemDoubleClicked.connect(self.on_select)
        layout.addWidget(self.list_view)

        open_file = QtWidgets.QPushButton('Add file')
        open_file.clicked.connect(self.open_file_dialog)
        layout.addWidget(open_file)

    def open_file_dialog(self):
        file_filter = ';;'.join('{} ({})'.format(name.capitalize(), ' '.join('*.' + name for name in formats))
                                for name, formats in SETTINGS['formats'].items())
        filename, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Add file', filter=file_filter)
        if filename:
            self.add_file.emit(filename)

    def on_select(self):
        self.select_file.emit(self.list_view.currentItem().text())

    def display(self, documents):
        self.list_view.clear()
        self.list_view.addItems([doc['name'] for doc in documents])


class FileWidget(QtWidgets.QWidget):
    go_back = QtCore.pyqtSignal()
    delete_file = QtCore.pyqtSignal(str)

    def __init__(self):
        super().__init__()

        layout = QtWidgets.QVBoxLayout(self)

        self.title = QtWidgets.QLabel()
        self.title.setStyleSheet("font-size: 18px; font-weight: bold;")
        self.label = QtWidgets.QLabel()

        layout.addWidget(self.title)
        layout.addWidget(self.label)
        layout.addStretch()

        back_button = QtWidgets.QPushButton('Back')
        delete_button = QtWidgets.QPushButton('Delete')
        layout.addWidget(back_button)
        layout.addWidget(delete_button)
        back_button.clicked.connect(self.go_back)
        delete_button.clicked.connect(self.on_delete)

    def display(self, data):
        self._data = data
        ext = data['name'].split('.')[-1]
        if ext in SETTINGS['formats']['text']:
            self.title.setText(data['name'])
            self.label.setText(data['content'].decode())
        elif ext in SETTINGS['formats']['image']:
            self.title.setText(data['name'])
            qp = QPixmap()
            qp.loadFromData(data['content'])
            self.label.setPixmap(qp)
        else:
            self.label.setText('Format is not supported.')

    def on_delete(self):
        self.delete_file.emit(self._data['name'])
        self.label.setText('No file.')


if __name__ == '__main__':
    import sys
    from client import Client

    url = SETTINGS['URL']
    app = QtWidgets.QApplication(sys.argv)
    ex = ClientApp(url)
    ex.show()
    sys.exit(app.exec_())
