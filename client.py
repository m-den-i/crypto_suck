import hashlib
import crypto
import requests
import base64
import os
import utils


class Session(requests.Session):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.id = None
        self.totp = None

    def request(self, method, url, *args, **kwargs):
        return super().request(method, self.base_url + url, *args, **kwargs)

    def post(self, url, data=None, json=None, **kwargs):
        json = self.add_credentials(json or {})
        kwargs['params'] = self.add_credentials(kwargs.get('params', {}) or {})

        response = super().post(url, data, json, **kwargs)

        if response.status_code >= 300:
            raise ServerError(response)

        data = response.json()

        if data['errorDto']['code'] is not None:
            raise ValueError(data['errorDto']['message'])

        return response.json()['data']

    def get(self, url, **kwargs):
        kwargs['params'] = self.add_credentials(kwargs.get('params', {}))
        response = super().get(url, **kwargs)
        if response.status_code >= 300:
            raise ServerError(response)
        data = response.json()

        if data['errorDto']['code'] is not None:
            raise ValueError(data['errorDto']['message'])

        return data['data']

    def delete(self, url, **kwargs):
        kwargs['params'] = self.add_credentials(kwargs.get('params', {}))
        response = super().delete(url, **kwargs)
        if response.content:
            return response.json()
        return {}

    def add_credentials(self, data):
        if self.id:
            data['sessionId'] = self.id
        if self.totp:
            data['token'] = self.totp.compute()
        return data


class ServerError(Exception):
    def __init__(self, response):
        self.response = response
        super().__init__('HTTP Response error: {} {}'.format(response.status_code, response.reason))


def decode(line):
    if isinstance(line, bytes):
        return line.decode()
    return line


def encode(line):
    if isinstance(line, str):
        return line.encode()
    return line


class Client:
    def __init__(self, login, password, base_url, use_encryption=True, use_verification=False):
        self.login = login
        self.password = password
        self.session = Session(base_url)
        self.aes = None
        self.use_encryption = use_encryption
        self.use_verification = use_verification
        if self.use_encryption:
            with open('key.priv', 'rb') as f:
                self.rsa = crypto.RSASucker(f.read())

        self._files = {}

    def connect(self):
        """ Exchange public and aes keys with the server. """
        data = {
            'login': self.login,
            'encryption': self.use_encryption,
            'postCode': self.use_verification
        }

        data = self.session.post('logindto', json=data)
        self.session.id = data['sessionId']

        if self.use_encryption:
            rsa = crypto.RSASucker(key=self.rsa.decrypt(data['rsaPublicPart1']) + self.rsa.decrypt(data['rsaPublicPart2']))

            dh_public_o = self.rsa.decrypt(data['dhPublicPart1']) + self.rsa.decrypt(data['dhPublicPart2'])
            dh_public, module, g, length = utils.DerCoder.load(dh_public_o)
            # Note: dh_public more than module. It's curiously.

            private = int.from_bytes(crypto.get_random_bytes(length + 1), 'big')

            # Inline Diffie Hellman
            public = pow(g, private, module)
            shared = pow(dh_public, private, module).to_bytes(64, 'big')

            # Compute shared AES key. I'm sure it's incorrect.
            h = hashlib.sha256()
            h.update(shared)
            key = h.digest()[:16]

            # A little hack here. The second line should be omitted, but it won't work.
            # But it works in case you send back server's public key (as if you have the same private key)
            public = utils.DerCoder.dump(public)
            public = utils.DerCoder.dump(dh_public)

            data = self.session.post('dh', json={
                'dhPublicPart1': base64.b64encode(rsa._rsa.encrypt(public[:200])).decode(),
                'dhPublicPart2': base64.b64encode(rsa._rsa.encrypt(public[200:])).decode(),
            })

            self.aes = crypto.AESSucker(key,
                                        self.rsa.decrypt(data['ivector']))

        data = {
            'login': self.encrypt(self.login),
            'password': self.encrypt(self.password),
        }

        data = self.session.post('login', json=data)

        if not self.use_verification:
            self.build_token(data)

    def verify(self, code):
        """ Verify email code. """
        data = {
            'code': self.encrypt(code),
        }

        data = self.session.post('verify', json=data)
        self.build_token(data)

    def build_token(self, data):
        self.session.totp = crypto.TOTP(self.decrypt(data['secret']))

        data = self.session.post('token')
        return data

    def get_files(self):
        """ Get list of files. """
        data = self.session.get('files')
        data = [
            {'name': decode(self.decrypt(f.pop('name'), use_b64=self.use_encryption)),
             'googleId': decode(self.decrypt(f.pop('googleId'), use_b64=self.use_encryption)),
             **f} for f in data
            ]
        self._files = {f['name']: f for f in data}
        return data

    def send_file(self, file_name):
        """ Send a file to the server.

        Arguments:
             file_name: absolute or relative path to a file.

        """
        with open(file_name, 'rb') as f:
            content = f.read()
            encrypted = self.encrypt(content, use_b64=False)
            response = self.session.post('files', params={'name': os.path.basename(file_name)},
                                         files={'file': encrypted})
        return response

    def default(self):
        self.base_url = 'http://127.0.0.1:8080/'
        self.connect()
        self.login('m-den-i@yandex.by', 'password')

    def decrypt(self, data, use_b64=True):
        if use_b64:
            data = base64.b64decode(data)
        return data if not self.use_encryption else self.aes.decrypt(data)

    def encrypt(self, data, use_b64=True):
        if self.use_encryption:
            data = self.aes.encrypt(data)
        if use_b64:
            data = base64.b64encode(encode(data)).decode()
        return data

    def get_file(self, name):
        """ Get file by its name. """
        if name not in self._files:
            self.get_files()

        data = self.session.get('files/' + self._files[name]['googleId'])
        return dict(name=name, content=self.decrypt(data['content']))

    def delete_file(self, name):
        """ Delete a file. """
        if name not in self._files:
            self.get_files()

        data = self.session.delete('files/' + self._files[name]['googleId'])
        return data


if __name__ == '__main__':
    import sys

    client = Client(*sys.argv[1:], base_url=os.environ.get('BASE_URL', 'http://127.0.0.1:8080/'))
    client.connect()
    print(client.get_files())
