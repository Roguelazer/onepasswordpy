from unittest2 import TestCase

from onepassword import padding
import six


class PKCS5PaddingTestCase(TestCase):
    """Test our PKCS#5 padding"""
    VECTORS = (
        (b"", 1, b"\x01"),
        (b"abcd", 8, b"abcd\x04\x04\x04\x04"),
        (b"abcdefg\x00", 16, b"abcdefg\x00\x08\x08\x08\x08\x08\x08\x08\x08"),
    )

    def test_pad(self):
        for unpadded, bs, padded in self.VECTORS:
            self.assertEqual(padding.pkcs5_pad(unpadded, bs), padded)

    def test_unpad(self):
        for unpadded, _, padded in self.VECTORS:
            self.assertEqual(padding.pkcs5_unpad(padded), unpadded)
        self.assertEqual(padding.pkcs5_unpad(""), "")


class ABPaddingTestCase(TestCase):
    """Test the custom AgileBits padding"""
    VECTORS = (
        (b"", 4, b"\x00\x00\x00\x00"),
        (b"ab", 4, b"\x00\x00ab"),
        (b"abcd", 4, b"\x00\x00\x00\x00abcd"),
        (b"\x01\x02", 10, b"\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02"),
    )

    def zeros(self, count):
        return b''.join([six.int2byte(0) for x in range(count)])

    def test_pad(self):
        for unpadded, bs, padded in self.VECTORS:
            self.assertEqual(padding.ab_pad(unpadded, bs, random_generator=self.zeros), padded)

    def test_unpad(self):
        for unpadded, _, padded in self.VECTORS:
            size = len(unpadded)
            self.assertEqual(padding.ab_unpad(padded, size), unpadded)
