from pyasn1.type import univ
from pyasn1.codec.der.decoder import decode as decode_der
from pyasn1.codec.der.encoder import encode as encode_der


class DerCoder:
    template = None
    prefix = '00000010010000000'

    @classmethod
    def load(cls, der):
        cls.template, _ = decode_der(der)
        params, public = cls.template
        module, g, length = params[1]

        cls.prefix = ''.join(map(str, public[:-length]))
        public = int(''.join(map(str, public[-length:])), 2)
        return public, int(module), int(g), int(length)

    @classmethod
    def dump(cls, key):
        cls.template.setComponentByPosition(1, univ.BitString("'{}{:0511b}'B".format(cls.prefix, key)))
        return encode_der(cls.template)
