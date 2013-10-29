from __future__ import absolute_import
from __future__ import print_function

from .util import make_utf8

import hashlib
import math

import six


class PBKDF1(object):
    """Reimplement the simple PKCS#5 v1.5 key derivation function from
    OpenSSL. Tries to look like PBKDF2 as much as possible.

    (as in `openssl enc`). Technically, this is only PBKDF1 if the key size
    is 20 bytes or less. But whatever.
    """

    # TODO: Call openssl's EVP_BytesToKey instead of reimplementing by hand
    # (through m2crypto?). Alternatively, figure out how to make PyCrypto's
    # built-in PBKDF1 work without yelling at me that MD5 is an unacceptable
    # hash algorithm
    def __init__(self, key, salt, hash_algo=hashlib.md5, iterations=1):
        if salt is None:
            salt = b'\x00'*(int(math.ceil(len(key)/2)))
        key, salt = make_utf8(key, salt)
        self.key = key
        self.salt = salt
        self._ks = key + salt
        self._d = [b'']
        self._i = 1
        self.result = bytes()
        self._read = 0
        self.iterations = iterations
        self.hash_algo = hash_algo

    def read(self, nbytes):
        while len(self.result) - self._read < nbytes:
            tohash = self._d[self._i - 1] + self._ks
            for hash_application in six.moves.range(self.iterations):
                tohash = self.hash_algo(tohash).digest()
            self._d.append(tohash)
            self.result += tohash
            self._i += 1
        to_return = self.result[self._read:self._read + nbytes]
        self._read += nbytes
        return to_return
