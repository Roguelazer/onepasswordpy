from unittest2 import TestCase

from onepassword import padding

class PKCS5PaddingTestCase(TestCase):
    """Test our PKCS#5 padding"""
    VECTORS = (
        ("", 1, "\x01"),
        ("abcd", 8, "abcd\x04\x04\x04\x04"),
        ("abcdefg\x00", 16, "abcdefg\x00\x08\x08\x08\x08\x08\x08\x08\x08"),
    )
    def test_pad(self):
        for unpadded, bs, padded in self.VECTORS:
            self.assertEqual(padding.pkcs5_pad(unpadded, bs), padded)

    def test_unpad(self):
        for unpadded, _, padded in self.VECTORS:
            self.assertEqual(padding.pkcs5_unpad(padded), unpadded)
        self.assertEqual(padding.pkcs5_unpad(""), "")


class TestABPaddingTestCase(TestCase):
    """Test the custom AgileBits padding"""
    VECTORS = (
        ("", 4, "\x00\x00\x00\x00"),
        ("ab", 4, "\x00\x00ab"),
        ("abcd", 4, "\x00\x00\x00\x00abcd"),
        ("\x01\x02", 10, "\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02"),
    )

    def zeros(self, count):
        return ''.join([chr(0) for x in range(count)])

    def test_pad(self):
        for unpadded, bs, padded in self.VECTORS:
            self.assertEqual(padding.ab_pad(unpadded, bs, random_generator=self.zeros), padded)

    def test_unpad(self):
        for unpadded, _, padded in self.VECTORS:
            size = len(unpadded)
            self.assertEqual(padding.ab_unpad(padded, size), unpadded)
