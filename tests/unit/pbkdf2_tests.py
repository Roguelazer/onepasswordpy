import mock
import testify as T

from onepassword import pbkdf2


class PBKDF2SHA1TestCase(T.TestCase):
    VECTORS = (
        ('password', '', 1, '\x87T\xc3,d\xb0\xf5$\xfcP\xc0\x0fx\x815\xde'),
        ('password', '', 16, '\x0bP|}r\x13\xe9\x9e\x0f\x0cj\xd0\xbdH\xa7\xc9'),
        ('password', 'salt', 1, '\x0c`\xc8\x0f\x96\x1f\x0eq\xf3\xa9\xb5$\xaf`\x12\x06'),
        ('password', 'salt', 16, '\x1e\x84Lf\xb5|\x0e\xed\xf6\xfdx\x1b\xca\xfc\xe8"'),
    )

    def test_vectors(self):
        for password, salt, iterations, expected_key in self.VECTORS:
            generated = pbkdf2.pbkdf2_sha1(password, salt, length=16, iterations=iterations)
            T.assert_equal(generated, expected_key)

class PBKDF2SHA512TestCase(T.TestCase):
    VECTORS = (
        ('password', '', 1, '\xae\x16\xcem\xfdJj\x0c B\x1f\xf8\x0e\xb3\xbaJ'),
        ('password', '', 16, 'T\xe1\xd5T\xa6{\x15\x1d\x19;\x82\nbXbI'),
        ('password', 'salt', 1, '\x86\x7fp\xcf\x1a\xde\x02\xcf\xf3u%\x99\xa3\xa5=\xc4'),
        ('password', 'salt', 16, '\x884\xdc\xaf\xec\xf51&\xcc\xfeMF\xc6v\x16M'),
    )

    def test_vectors(self):
        for password, salt, iterations, expected_key in self.VECTORS:
            generated = pbkdf2.pbkdf2_sha512(password, salt, length=16, iterations=iterations)
            T.assert_equal(generated, expected_key)
