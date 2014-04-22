import mock
from unittest2 import TestCase

from onepassword import pbkdf1
from onepassword import crypt_util

class PBKDF1TestCase(TestCase):
    # test vectors generated with
    # openssl enc -aes-128-cbc -p -k <PASSWORD> -a -nosalt -p < /dev/null
    VECTORS = (
        (b'password', b'', '5F4DCC3B5AA765D61D8327DEB882CF99', '2B95990A9151374ABD8FF8C5A7A0FE08'),
        (b'', b'', 'D41D8CD98F00B204E9800998ECF8427E', '59ADB24EF3CDBE0297F05B395827453F'),
        (b'', b'E3936A9A8ACFE9BE', 'E9FAB75961E5DE62D6982C3F569114A5', '652D875150F652F75154666E1FD0E8AC'),
        (b'012345678910111231415161717', b'F7560045C70A96DB', '2E14B2EC7E2F8CDC18F15BB773CCD6F2', '5C8AADA268F9B86F960DF0464AE5E981'),
    )

    def test_vectors(self):
        for password, hex_salt, expected_key, expected_iv in self.VECTORS:
            salt = crypt_util.unhexize(hex_salt)
            pb_gen = pbkdf1.PBKDF1(password, salt)
            derived_key = pb_gen.read(16)
            derived_iv = pb_gen.read(16)
            hex_derived_key = crypt_util.hexize(derived_key)
            hex_derived_iv = crypt_util.hexize(derived_iv)
            self.assertEqual(hex_derived_key, expected_key)
            self.assertEqual(hex_derived_iv, expected_iv)

    def test_count(self):
        # can't use vectors as easily here because openssl never passes
        # count != 1
        sigil = b"SENTINTEL VALUE THAT IS A STRING"
        mock_hash = mock.Mock()
        mock_hash.digest = mock.Mock(return_value=sigil)
        mock_md5 = mock.Mock(return_value=mock_hash)
        # choose parameters so that key + salt is already desired length
        key = b'aaaaaaaa'
        salt = b'bbbbbbbb'
        pb_gen = pbkdf1.PBKDF1(key, salt, iterations=4, hash_algo=mock_md5)
        keyish = pb_gen.read(16)
        ivish = pb_gen.read(16)
        self.assertEqual((keyish, ivish), (sigil[:-16], sigil[-16:]))
        self.assertEqual(mock_md5.mock_calls, [
            mock.call(key+salt),
            mock.call(sigil),
            mock.call(sigil),
            mock.call(sigil),
        ])
