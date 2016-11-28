import crypto
import requests
import base64
import os


class Session(requests.Session):

    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url

    def get(self, url, **kwargs):
        return super().get(self.base_url + url, **kwargs)

    def post(self, url, **kwargs):
        return super().post(self.base_url + url, **kwargs)

    def delete(self, url, **kwargs):
        return super().delete(self.base_url + url, **kwargs)


class ServerError(Exception):
    pass


class Client:
    def __init__(self, base_url, use_encryption=True, use_verification=False):
        self.session = Session(base_url)
        self.rsa = crypto.RSASucker()
        self.session_id = None
        self.aes = None
        self.totp = None
        self.use_encryption = use_encryption
        self.use_verification = use_verification
        self._files = {}

    def make_request(self, endpoint, data, include_session=True, check_session=True, method='post'):
        if include_session:
            data['sessionId'] = self.session_id
        request = getattr(self.session, method)
        response = request(endpoint, json=data)
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
        return data

    def get_files(self):
        data = self.session.get('files', params={'token': self.totp.token(),
                                                 'sessionId': self.session_id}).json()['data']
        data = [
            {'name': self.decrypt(f.pop('name')).decode(),
             'googleId': self.decrypt(f.pop('googleId')).decode(),
             **f} for f in data
        ]
        self._files = {f['name']: f for f in data}
        return data

    def send_file(self, file_name):
        data = {'token': self.totp.token(), 'sessionId': self.session_id}
        with open(file_name, 'rb') as f:
            encrypted = self.aes.encrypt(f.read().decode(), use_b64=False)
            response = self.session.post('files?name={}'.format(os.path.basename(file_name)),
                                         data=data, files={'file': encrypted})
        return response, response.json()

    def decrypt(self, data):
        return base64.b64decode(data) if not self.use_encryption else self.aes.decrypt(data)

    def encrypt(self, data):
        return base64.b64encode(bytes(data, 'utf-8')).decode() if not self.use_encryption else self.aes.encrypt(data)

    def get_file(self, name):
        if name not in self._files:
            self.get_files()

        response = self.session.get('files/' + self._files[name]['googleId'],
                                    params={'sessionId': self.session_id, 'token': self.totp.token()})
        if response.status_code == 200:
            content = response.json()['data']['content']
            return dict(name=name, content=self.decrypt(content).decode())

        ServerError('HTTP Response error: {} {}'.format(response.status_code, response.reason))

    def delete_file(self, name):
        if name not in self._files:
            self.get_files()

        response = self.session.delete('files/' + self._files[name]['googleId'],
                                       params={'sessionId': self.session_id, 'token': self.totp.token()})
        return response.content


if __name__ == '__main__':
    import os
    import sys
    client = Client(os.environ.get('BASE_URL', 'http://127.0.0.1:8080/'))
    client.connect()
    client.login(*sys.argv[1:])
