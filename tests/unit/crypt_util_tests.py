import base64
import hashlib
import hmac
import struct

import simplejson
import testify as T

from onepassword import crypt_util


class HexizeTestCase(T.TestCase):
    VECTORS = (
        ('', ''),
        ('\x00', '00'),
        ('abcd', '61626364'),
        ('\x00,123', '002C313233'),
    )
    def test_hexize_simple(self):
        for unhexed, hexed in self.VECTORS:
            T.assert_equal(crypt_util.hexize(unhexed), hexed)

    def test_unhexize_simple(self):
        for unhexed, hexed in self.VECTORS:
            T.assert_equal(crypt_util.unhexize(hexed), unhexed)


class OPData1KeyDerivationTestCase(T.TestCase):
    VECTORS = (
            (('', ''), ('\xcb\x93\tl:\x02\xbe\xeb\x1c_\xac6v\\\x90\x11\xfe\x99\xf8\xd8\xeab6`H\xfc\x98\xcb\x98\xdf\xea\x8f', 'O\x8d0U\xa5\xef\x9bz\xf2\x97s\xad\x82R\x95Ti9\x9d%\xd3\nS1(\x89(X\x1f\xb8n\xcb')),
            (('', '', 10000), ('I\xb4\xa7!=\xfc\xeeN\xad\xde\xc1\xe2\x1e\xa6\xfc\x8b\x9a,FZ\xe7\xcdPOA\x1e\xeek!\xd2\xe5\xef', 'v4\x8a\xe1\xa9\xea\xa8\x1bUUm\x13\xa2CM\t\x02,\xc4\x07\xd9\x13bF\xef5(\x05\xf4\xb4\xab\xb5')),
            # with iterations=1, is just hmac-sha512 of (key, salt + "\x00\x00\x00\x01)
            (('fred', '', 1), ('v\x08\xb1\xd6\x9a\x16\xbe\x11\x8b\x7fa\x86\x99\xdc\xc9\xbd\xb2\xe5a\xf2wld,\xfa\xd6V\x16\x8bV\x88`', '\xad\x96\xd3\xe7S\x10\xa8L!\xf3\xa7\xb9w\xf0%2\x91\x94\xbb\xf0f\x00\x11\xcb\xa4\xaa\xf2\x8d\x81\x0fb\xa9')),
            (('fred', ''), ('P\x9b\xe2\xb9\xc0C"\xaf\xf2>\xc0zF\xe8\xff\x06j\x88\x91\xe3\t\x82\x96VZ0\x8e\xd6\x11\xcc\xa7\xd4', 'b$\x81(\xd4\xf4\x0e8M\xf0\x0c\x18)!r\xcf\x02>\xf3hK_\x95\xa4\x8c\xa0\x91\x9c\xf97 W')),
    )
    def test_vectors(self):
        for args, expected in self.VECTORS:
            T.assert_equal(crypt_util.opdata1_derive_keys(*args), expected)


class OPData1UnpackTestCase(T.TestCase):
    def build_opdata1(self):
        header = "opdata01"
        plaintext = ""
        plaintext_len = struct.pack("<Q", len(plaintext))
        iv = "".join(chr(x) for x in range(16))
        cryptext = plaintext
        msg = plaintext_len + iv + cryptext
        hmac_val = hmac.new(digestmod=hashlib.sha256, key="", msg=msg).digest()
        msg += hmac_val
        return header + msg

    def test_bad_header_fails(self):
        with T.assert_raises(TypeError):
            crypt_util.opdata1_unpack("")
        with T.assert_raises(TypeError):
            crypt_util.opdata1_unpack("opdata02abcdef")

    def test_basic(self):
        packed = self.build_opdata1()
        plaintext_length, iv, cryptext, expected_hmac = crypt_util.opdata1_unpack(packed)
        T.assert_equal(plaintext_length, 0)
        T.assert_equal(cryptext, "")

    def test_basic_auto_b64decode(self):
        packed = self.build_opdata1()
        packed = base64.b64encode(packed)
        plaintext_length, iv, cryptext, expected_hmac = crypt_util.opdata1_unpack(packed)
        T.assert_equal(plaintext_length, 0)
        T.assert_equal(cryptext, "")


class OPdata1DecryptTestCase(T.TestCase):
    """test specific data from the example keychain provided by AgileBits"""

    PASSPHRASE = "fred"
    SALT = "LlfotX7aTZnfL+AjJJYARA=="
    ITERATIONS = 227272
    DERIVED_KEY = '`\x8c\x9f\x19<p\xd5U\xec!Sx\xd6\xe8\x9b\xaf\xbc&:\x8f\x82T\xff\xfbZ\xae{LAf\xaaI'
    DERIVED_HMAC = '\xb9\xeaO\xdc\xeb\x8e<\xee68\xa8\xc0\x9b\xe1\xbdV\xf94\xf5g\x165\xca\x1a\n\x98Hl\x8bT2"'
    OVERVIEW_KEY = '\x12*D\x01\xaeL\x16\x80\x91(\xbd\xc5$\xbc\x04\xc6\xd6\xd2\xccrx\x84\xdb\x83`+\xb6\xcc\xbb=\xb9 '
    OVERVIEW_HMAC = '\xee\xa8[K\xfe9\x1c`\xc4\x1e}\xb2\xd7\xd7\xa8\x91|\x9d\xdf~\x14c\tJC]h\xd5\x1a\xa3\xcf\x0b'

    def test_key_derivation(self):
        # TODO: make a test that doesn't take 9 seconds for this
        key, hmac = crypt_util.opdata1_derive_keys(password=self.PASSPHRASE, salt=base64.b64decode(self.SALT), iterations=self.ITERATIONS)
        T.assert_equal(key, self.DERIVED_KEY)
        T.assert_equal(hmac, self.DERIVED_HMAC)

    def test_master_key_decryption(self):
        data = "b3BkYXRhMDEAAQAAAAAAAIgdZa9rhj9meNSE/1UbyEOpX68om5FOVwoZkzU3ibZqnGvUC0LFiJI+iGmGIznQbvPVwJHAupl6cEYZs//BIbSxJgcengoIEvci+Vote4DCK8kfwjfLPfq6G+4cnTy0yUMyM1qyA7sPB8p3TBlynOgYL5HNIorhj7grF1NeyuAS8UkEpqzpDZurHZNOuVfqmKaLSy2zyOAtJ/ev+SA829kcK3xqqm+cLKPB1fl2/J7Ya4AIKuPjnC8wo10mwsFNvWQ4a+m1rkCFGCTcWWO1RwO6F9ILQk3qqkUnk6HvhBjbLdpmmwZAdeRQQEpGQz9lM9/goTs0+h9VI4/+pQYqTyLoIbnpljnJ0OziffZcrwqqrXIAsBh+ezE0EH44WC73O2/eEARBA5JNgnW/m/rcmFQK5hxeWb4GxbypgUYDRb0p"
        crypt_util.opdata1_decrypt_master_key(data, self.DERIVED_KEY, self.DERIVED_HMAC)

    def test_overview_key_decryption(self):
        data = "b3BkYXRhMDFAAAAAAAAAAMggp7KPfHsgxuBvQ1mn3YPVxJ7Sc+gvnTCZXQMop2osF7qQUohQHXRTftuCriAAUYgmK6bytJVdIz5JIXCUZEq6xWFekj5L3Br6MO55+bPz1qei50DwFs27eh0+tjpSGm3dMcCqhMAqMmqkENbur0f5t73xlvAEkPwpZzWcrPKe"
        key, hmac = crypt_util.opdata1_decrypt_master_key(data, self.DERIVED_KEY, self.DERIVED_HMAC)
        T.assert_equal(key, self.OVERVIEW_KEY)
        T.assert_equal(hmac, self.OVERVIEW_HMAC)

    def test_item_key_decryption(self):
        key = '\x8c\r\x8d\xb6p\xb0\xb7\xd5l\xb1\x1aF5w\xe1A\x03W4@\x80\xb9\xae\xec!Q\x19\x1c\xf3\xde\xc5\x9d'
        hmac_key = '\xc9S\x10w\xbf|g\xb3\x1aI\xa7\x13\x93\xcf\xd6v_,\x9a\xd8"\xc9\xa8\x8ctX\x1d>k\xe8\xf6V'
        data = "R+JJyjeDfDC49x0XwaW5eJkJhG9COpfzFPSo8P2ZDa6ZYeLRzyjeukgdtDj5Yg7F0l2fMCbHKmOtQUXRQxCfsaCcsTeDR10WGMlzQtJoygmdMreG9joX18JPFWtDo/P94sbn8Wd0Q+Sx18Whdo0lRA=="
        data = base64.b64decode(data)
        crypt_util.opdata1_decrypt_key(data, key, hmac_key)

    def test_item_overview_decryption(self):
        data = "b3BkYXRhMDEuAAAAAAAAACCvfWbzwBJIcF501hFPJGgqwKPA+y333FXC2LG9W+M9GGIyd9wBW6DToRRV5964EkpEs4zlwz5FHNt25FfGuC2TPYnVl+zKLH0GFPXVvFYz3XP5COQ3fHhX2SmeHHsviw=="
        expected_data = {"title":"Personal","ainfo":"Wendy Appleseed"}
        data = simplejson.loads(crypt_util.opdata1_decrypt_item(data, self.OVERVIEW_KEY, self.OVERVIEW_HMAC))
        T.assert_equal(data, expected_data)


if __name__ == '__main__':
    T.run()
