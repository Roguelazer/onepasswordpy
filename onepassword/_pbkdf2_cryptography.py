from .util import make_utf8

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA1, SHA512
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

_backend = default_backend()


def pbkdf2_sha1(password, salt, length, iterations):
    password, salt = make_utf8(password, salt)
    kdf = PBKDF2HMAC(algorithm=SHA1(), length=length, salt=salt,
                     iterations=iterations, backend=_backend)
    return kdf.derive(password)


def pbkdf2_sha512(password, salt, length, iterations):
    password, salt = make_utf8(password, salt)
    kdf = PBKDF2HMAC(algorithm=SHA512(), length=length, salt=salt,
                     iterations=iterations, backend=_backend)
    return kdf.derive(password)
