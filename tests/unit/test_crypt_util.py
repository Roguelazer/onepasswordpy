import base64
import hashlib
import hmac
import struct

import simplejson
import pytest

from onepassword import crypt_util


class TestHexize:
    VECTORS = (
        (b'', b''),
        (b'\x00', b'00'),
        (b'abcd', b'61626364'),
        (b'\x00,123', b'002C313233'),
    )

    @pytest.mark.parametrize('unhexed, hexed', VECTORS)
    def test_hexize_simple(self, unhexed, hexed):
        assert crypt_util.hexize(unhexed) == hexed

    @pytest.mark.parametrize('unhexed, hexed', VECTORS)
    def test_unhexize_simple(self, unhexed, hexed):
        assert crypt_util.unhexize(hexed) == unhexed

class TestOPData1KeyDerivation:
    VECTORS = (
        (('', b''), (b'\xcb\x93\tl:\x02\xbe\xeb\x1c_\xac6v\\\x90\x11\xfe\x99\xf8\xd8\xeab6`H\xfc\x98\xcb\x98\xdf\xea\x8f', b'O\x8d0U\xa5\xef\x9bz\xf2\x97s\xad\x82R\x95Ti9\x9d%\xd3\nS1(\x89(X\x1f\xb8n\xcb')),
        (('', b'', 10000), (b'I\xb4\xa7!=\xfc\xeeN\xad\xde\xc1\xe2\x1e\xa6\xfc\x8b\x9a,FZ\xe7\xcdPOA\x1e\xeek!\xd2\xe5\xef', b'v4\x8a\xe1\xa9\xea\xa8\x1bUUm\x13\xa2CM\t\x02,\xc4\x07\xd9\x13bF\xef5(\x05\xf4\xb4\xab\xb5')),
        # with iterations=1, is just hmac-sha512 of (key, salt + "\x00\x00\x00\x01)
        (('fred', b'', 1), (b'v\x08\xb1\xd6\x9a\x16\xbe\x11\x8b\x7fa\x86\x99\xdc\xc9\xbd\xb2\xe5a\xf2wld,\xfa\xd6V\x16\x8bV\x88`', b'\xad\x96\xd3\xe7S\x10\xa8L!\xf3\xa7\xb9w\xf0%2\x91\x94\xbb\xf0f\x00\x11\xcb\xa4\xaa\xf2\x8d\x81\x0fb\xa9')),
        (('fred', b''), (b'P\x9b\xe2\xb9\xc0C"\xaf\xf2>\xc0zF\xe8\xff\x06j\x88\x91\xe3\t\x82\x96VZ0\x8e\xd6\x11\xcc\xa7\xd4', b'b$\x81(\xd4\xf4\x0e8M\xf0\x0c\x18)!r\xcf\x02>\xf3hK_\x95\xa4\x8c\xa0\x91\x9c\xf97 W')),
    )

    @pytest.mark.parametrize('args, expected', VECTORS)
    def test_vectors(self, args, expected):
        assert crypt_util.opdata1_derive_keys(*args) == expected


class TestOPData1Unpack:
    def build_opdata1(self):
        header = b"opdata01"
        plaintext = b""
        plaintext_len = struct.pack(b"<Q", len(plaintext))
        iv = b"".join(chr(x).encode('utf-8') for x in range(16))
        cryptext = plaintext
        msg = plaintext_len + iv + cryptext
        hmac_val = hmac.new(digestmod=hashlib.sha256, key=b"", msg=msg).digest()
        msg += hmac_val
        return header + msg

    def test_bad_header_fails(self):
        with pytest.raises(TypeError):
            crypt_util.opdata1_unpack(b"")
        with pytest.raises(TypeError):
            crypt_util.opdata1_unpack(b"opdata02abcdef")

    def test_basic(self):
        packed = self.build_opdata1()
        plaintext_length, iv, cryptext, expected_hmac, _ = crypt_util.opdata1_unpack(packed)
        assert plaintext_length == 0
        assert cryptext == b""

    def test_basic_auto_b64decode(self):
        packed = self.build_opdata1()
        packed = base64.b64encode(packed)
        plaintext_length, iv, cryptext, expected_hmac, _ = crypt_util.opdata1_unpack(packed)
        assert plaintext_length == 0
        assert cryptext == b""


class TestOPdata1Decrypt:
    """test specific data from the example keychain provided by AgileBits"""

    DERIVED_KEY = b'`\x8c\x9f\x19<p\xd5U\xec!Sx\xd6\xe8\x9b\xaf\xbc&:\x8f\x82T\xff\xfbZ\xae{LAf\xaaI'
    DERIVED_HMAC = b'\xb9\xeaO\xdc\xeb\x8e<\xee68\xa8\xc0\x9b\xe1\xbdV\xf94\xf5g\x165\xca\x1a\n\x98Hl\x8bT2"'
    OVERVIEW_KEY = b'\x12*D\x01\xaeL\x16\x80\x91(\xbd\xc5$\xbc\x04\xc6\xd6\xd2\xccrx\x84\xdb\x83`+\xb6\xcc\xbb=\xb9 '
    OVERVIEW_HMAC = b'\xee\xa8[K\xfe9\x1c`\xc4\x1e}\xb2\xd7\xd7\xa8\x91|\x9d\xdf~\x14c\tJC]h\xd5\x1a\xa3\xcf\x0b'
    MASTER_KEY = b'\x8c\r\x8d\xb6p\xb0\xb7\xd5l\xb1\x1aF5w\xe1A\x03W4@\x80\xb9\xae\xec!Q\x19\x1c\xf3\xde\xc5\x9d'
    MASTER_HMAC = b'\xc9S\x10w\xbf|g\xb3\x1aI\xa7\x13\x93\xcf\xd6v_,\x9a\xd8"\xc9\xa8\x8ctX\x1d>k\xe8\xf6V'

    def test_master_key_decryption(self):
        data = "b3BkYXRhMDEAAQAAAAAAAIgdZa9rhj9meNSE/1UbyEOpX68om5FOVwoZkzU3ibZqnGvUC0LFiJI+iGmGIznQbvPVwJHAupl6cEYZs//BIbSxJgcengoIEvci+Vote4DCK8kfwjfLPfq6G+4cnTy0yUMyM1qyA7sPB8p3TBlynOgYL5HNIorhj7grF1NeyuAS8UkEpqzpDZurHZNOuVfqmKaLSy2zyOAtJ/ev+SA829kcK3xqqm+cLKPB1fl2/J7Ya4AIKuPjnC8wo10mwsFNvWQ4a+m1rkCFGCTcWWO1RwO6F9ILQk3qqkUnk6HvhBjbLdpmmwZAdeRQQEpGQz9lM9/goTs0+h9VI4/+pQYqTyLoIbnpljnJ0OziffZcrwqqrXIAsBh+ezE0EH44WC73O2/eEARBA5JNgnW/m/rcmFQK5hxeWb4GxbypgUYDRb0p"
        master_key, master_hmac = crypt_util.opdata1_decrypt_master_key(data, self.DERIVED_KEY, self.DERIVED_HMAC)
        assert master_key, sel == MASTER_KEY
        assert master_hmac, sel == MASTER_HMAC

    def test_overview_key_decryption(self):
        data = "b3BkYXRhMDFAAAAAAAAAAMggp7KPfHsgxuBvQ1mn3YPVxJ7Sc+gvnTCZXQMop2osF7qQUohQHXRTftuCriAAUYgmK6bytJVdIz5JIXCUZEq6xWFekj5L3Br6MO55+bPz1qei50DwFs27eh0+tjpSGm3dMcCqhMAqMmqkENbur0f5t73xlvAEkPwpZzWcrPKe"
        key, hmac = crypt_util.opdata1_decrypt_master_key(data, self.DERIVED_KEY, self.DERIVED_HMAC)
        assert key, sel == OVERVIEW_KEY
        assert hmac, sel == OVERVIEW_HMAC

    def test_item_decryption(self):
        source_data = base64.b64decode("R+JJyjeDfDC49x0XwaW5eJkJhG9COpfzFPSo8P2ZDa6ZYeLRzyjeukgdtDj5Yg7F0l2fMCbHKmOtQUXRQxCfsaCcsTeDR10WGMlzQtJoygmdMreG9joX18JPFWtDo/P94sbn8Wd0Q+Sx18Whdo0lRA==")
        item_data = "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"
        item_key, item_hmac = crypt_util.opdata1_decrypt_key(source_data, self.MASTER_KEY, self.MASTER_HMAC)
        plaintext_item = crypt_util.opdata1_decrypt_item(item_data, item_key, item_hmac)
        item_dict = simplejson.loads(plaintext_item)
        assert 'sections' in item_dict
        assert item_dict['sections'][0]['title'], 'se == name'

    def test_item_overview_decryption(self):
        source_data = "b3BkYXRhMDEuAAAAAAAAACCvfWbzwBJIcF501hFPJGgqwKPA+y333FXC2LG9W+M9GGIyd9wBW6DToRRV5964EkpEs4zlwz5FHNt25FfGuC2TPYnVl+zKLH0GFPXVvFYz3XP5COQ3fHhX2SmeHHsviw=="
        expected_data = {"title":"Personal","ainfo":"Wendy Appleseed"}
        data = simplejson.loads(crypt_util.opdata1_decrypt_item(source_data, self.OVERVIEW_KEY, self.OVERVIEW_HMAC))
        assert data == expected_data

    def test_ignore_hmac(self):
        expected_data = {"title":"Personal","ainfo":"Wendy Appleseed"}
        source_data = base64.b64decode("b3BkYXRhMDEuAAAAAAAAACCvfWbzwBJIcF501hFPJGgqwKPA+y333FXC2LG9W+M9GGIyd9wBW6DToRRV5964EkpEs4zlwz5FHNt25FfGuC2TPYnVl+zKLH0GFPXVvFYz3XP5COQ3fHhX2SmeHHsviw==")
        source_data = source_data[:-2] + b".."
        with pytest.raises(ValueError):
            decrypted = crypt_util.opdata1_decrypt_item(source_data, self.OVERVIEW_KEY, self.OVERVIEW_HMAC)
        decrypted = crypt_util.opdata1_decrypt_item(source_data, self.OVERVIEW_KEY, self.OVERVIEW_HMAC, ignore_hmac=True)
        data = simplejson.loads(decrypted)
        assert data == expected_data
