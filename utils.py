from pyasn1.type import univ
from pyasn1.codec.der.decoder import decode as decode_der
from pyasn1.codec.der.encoder import encode as encode_der


class DerCoder:
    template = None

    @classmethod
    def load(cls, der):
        cls.template, _ = decode_der(der)
        params, public = cls.template
        public = int(''.join(map(str, public)), 2)

        module, g, length = params[1]
        return public, int(module), int(g), int(length)

    @classmethod
    def dump(cls, key):
        cls.template.setComponentByPosition(1, univ.BitString("'{:0528b}'B".format(key)))
        return encode_der(cls.template)
