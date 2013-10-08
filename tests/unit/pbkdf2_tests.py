import testify as T
from functools import wraps


def ignore_import_error(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            f(*args, **kwargs)
        except ImportError as ex:
            print 'ignoring ImportError: {0}'.format(ex)
    return wrapper

class PBKDF2SHA1TestCase(T.TestCase):
    VECTORS = (
        ('password', '', 1, '\x87T\xc3,d\xb0\xf5$\xfcP\xc0\x0fx\x815\xde'),
        ('password', '', 16, '\x0bP|}r\x13\xe9\x9e\x0f\x0cj\xd0\xbdH\xa7\xc9'),
        ('password', 'salt', 1, '\x0c`\xc8\x0f\x96\x1f\x0eq\xf3\xa9\xb5$\xaf`\x12\x06'),
        ('password', 'salt', 16, '\x1e\x84Lf\xb5|\x0e\xed\xf6\xfdx\x1b\xca\xfc\xe8"'),
        ('password', 'salt', 163840, '\xc2\x03/\xb4\xfe\xf4\xa8n\x15\\\x1a\x93kY\xa9\xda'),
    )

    def test_vectors_pycrypto(self):
        from onepassword import _pbkdf2_pycrypto
        for password, salt, iterations, expected_key in self.VECTORS:
            generated = _pbkdf2_pycrypto.pbkdf2_sha1(password, salt, length=16, iterations=iterations)
            T.assert_equal(generated, expected_key)
    
    @ignore_import_error
    def test_vectors_m2crypto(self):
        from onepassword import _pbkdf2_m2crypto
        for password, salt, iterations, expected_key in self.VECTORS:
            generated = _pbkdf2_m2crypto.pbkdf2_sha1(password, salt, length=16, iterations=iterations)
            T.assert_equal(generated, expected_key)

    @ignore_import_error
    def test_vectors_nettle(self):
        from onepassword import _pbkdf2_nettle
        for password, salt, iterations, expected_key in self.VECTORS:
            generated = _pbkdf2_nettle.pbkdf2_sha1(password, salt, length=16, iterations=iterations)
            T.assert_equal(generated, expected_key)


class PBKDF2SHA512TestCase(T.TestCase):
    VECTORS = (
        ('password', '', 1, '\xae\x16\xcem\xfdJj\x0c B\x1f\xf8\x0e\xb3\xbaJ'),
        ('password', '', 16, 'T\xe1\xd5T\xa6{\x15\x1d\x19;\x82\nbXbI'),
        ('password', 'salt', 1, '\x86\x7fp\xcf\x1a\xde\x02\xcf\xf3u%\x99\xa3\xa5=\xc4'),
        ('password', 'salt', 16, '\x884\xdc\xaf\xec\xf51&\xcc\xfeMF\xc6v\x16M'),
        ('password', 'salt', 163840, '|\xc2\xa2i\xe7\xa2j\x9e\x8f\xfb\x93\xd7\xb7f\x88\x05'),
    )

    def test_vectors_pycrypto(self):
        from onepassword import _pbkdf2_pycrypto
        for password, salt, iterations, expected_key in self.VECTORS:
            generated = _pbkdf2_pycrypto.pbkdf2_sha512(password, salt, length=16, iterations=iterations)
            T.assert_equal(generated, expected_key)

    @ignore_import_error
    def test_vectors_m2crypto(self):
        from onepassword import _pbkdf2_m2crypto
        for password, salt, iterations, expected_key in self.VECTORS:
            generated = _pbkdf2_m2crypto.pbkdf2_sha512(password, salt, length=16, iterations=iterations)
            T.assert_equal(generated, expected_key)

    @ignore_import_error
    def test_vectors_nettle(self):
        from onepassword import _pbkdf2_nettle
        for password, salt, iterations, expected_key in self.VECTORS:
            generated = _pbkdf2_nettle.pbkdf2_sha512(password, salt, length=16, iterations=iterations)
            T.assert_equal(generated, expected_key)

