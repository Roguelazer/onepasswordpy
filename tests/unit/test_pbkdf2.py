from __future__ import print_function

from functools import wraps

import pytest


@pytest.mark.benchmark(group='PBKDF2 SHA1')
class TestPBKDF2SHA1:
    VECTORS = (
        (b'password', b'', 1, b'\x87T\xc3,d\xb0\xf5$\xfcP\xc0\x0fx\x815\xde'),
        (b'password', b'', 16, b'\x0bP|}r\x13\xe9\x9e\x0f\x0cj\xd0\xbdH\xa7\xc9'),
        (b'password', b'salt', 1, b'\x0c`\xc8\x0f\x96\x1f\x0eq\xf3\xa9\xb5$\xaf`\x12\x06'),
        (b'password', b'salt', 16, b'\x1e\x84Lf\xb5|\x0e\xed\xf6\xfdx\x1b\xca\xfc\xe8"'),
        (b'password', b'salt', 163840, b'\xc2\x03/\xb4\xfe\xf4\xa8n\x15\\\x1a\x93kY\xa9\xda'),
    )

    @pytest.mark.parametrize('password, salt, iterations, expected_key', VECTORS)
    def test_vectors_cryptography(self, password, salt, iterations, expected_key):
        from onepassword import _pbkdf2_cryptography
        generated = _pbkdf2_cryptography.pbkdf2_sha1(password, salt, length=16, iterations=iterations)
        assert generated == expected_key

    @pytest.mark.parametrize('password, salt, iterations, expected_key', VECTORS)
    def test_vectors_nettle(self, password, salt, iterations, expected_key):
        _pbkdf2_nettle = pytest.importorskip('onepassword._pbkdf2_nettle')
        generated = _pbkdf2_nettle.pbkdf2_sha1(password, salt, length=16, iterations=iterations)
        assert generated == expected_key

    def test_benchmark_cryptography(self, benchmark):
        benchmark(self.test_vectors_cryptography, *self.VECTORS[-1])

    def test_benchmark_nettle(self, benchmark):
        benchmark(self.test_vectors_nettle, *self.VECTORS[-1])


@pytest.mark.benchmark(group='PBKDF2 SHA512')
class TestPBKDF2SHA512:
    VECTORS = (
        (b'password', b'', 1, b'\xae\x16\xcem\xfdJj\x0c B\x1f\xf8\x0e\xb3\xbaJ'),
        (b'password', b'', 16, b'T\xe1\xd5T\xa6{\x15\x1d\x19;\x82\nbXbI'),
        (b'password', b'salt', 1, b'\x86\x7fp\xcf\x1a\xde\x02\xcf\xf3u%\x99\xa3\xa5=\xc4'),
        (b'password', b'salt', 16, b'\x884\xdc\xaf\xec\xf51&\xcc\xfeMF\xc6v\x16M'),
        (b'password', b'salt', 163840, b'|\xc2\xa2i\xe7\xa2j\x9e\x8f\xfb\x93\xd7\xb7f\x88\x05'),
    )

    @pytest.mark.parametrize('password, salt, iterations, expected_key', VECTORS)
    def test_vectors_cryptography(self, password, salt, iterations, expected_key):
        from onepassword import _pbkdf2_cryptography
        generated = _pbkdf2_cryptography.pbkdf2_sha512(password, salt, length=16, iterations=iterations)
        assert generated == expected_key

    @pytest.mark.parametrize('password, salt, iterations, expected_key', VECTORS)
    def test_vectors_nettle(self, password, salt, iterations, expected_key):
        _pbkdf2_nettle = pytest.importorskip('onepassword._pbkdf2_nettle')
        generated = _pbkdf2_nettle.pbkdf2_sha512(password, salt, length=16, iterations=iterations)
        assert generated == expected_key

    def test_benchmark_cryptography(self, benchmark):
        benchmark(self.test_vectors_cryptography, *self.VECTORS[-1])

    def test_benchmark_nettle(self, benchmark):
        benchmark(self.test_vectors_nettle, *self.VECTORS[-1])

