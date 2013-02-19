import base64
import hashlib
import hmac
import struct

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
    def test_specific(self):
        key = '>P\xb9\xb4\xfe\x1b\x06\x02umR\x03tne\xefRJ"\x17\xb9\x83\x85\xc2\x10\x12\x92\x98\x99\x8c\xf6\xbf'
        hmac_key = 'Cw\x1f\xa2\xb4\xa2\xc0%\xca,\xb2B{\xc5\xfb_\xf9FT\xbb\xb5\x8eX$\xb1\x85\xd1\xef\xfc\xdd\x80W'
        data = "b3BkYXRhMDFAAAAAAAAAAMggp7KPfHsgxuBvQ1mn3YPVxJ7Sc+gvnTCZXQMop2osF7qQUohQHXRTftuCriAAUYgmK6bytJVdIz5JIXCUZEq6xWFekj5L3Br6MO55+bPz1qei50DwFs27eh0+tjpSGm3dMcCqhMAqMmqkENbur0f5t73xlvAEkPwpZzWcrPKe"
        crypt_util.opdata1_decrypt_item(data, key, hmac_key)


if __name__ == '__main__':
    T.run()
