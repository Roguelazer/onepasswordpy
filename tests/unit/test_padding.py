import pytest
import six

from onepassword import padding


class TestPKCS5Padding:
    """Test our PKCS#5 padding"""
    VECTORS = (
        (b"", 1, b"\x01"),
        (b"abcd", 8, b"abcd\x04\x04\x04\x04"),
        (b"abcdefg\x00", 16, b"abcdefg\x00\x08\x08\x08\x08\x08\x08\x08\x08"),
    )

    @pytest.mark.parametrize('unpadded, bs, padded', VECTORS)
    def test_pad(self, unpadded, bs, padded):
        assert padding.pkcs5_pad(unpadded, bs) == padded

    @pytest.mark.parametrize('unpadded, padded', [(unpadded, padded) for (unpadded, _, padded) in VECTORS])
    def test_unpad(self, unpadded, padded):
        assert padding.pkcs5_unpad(padded) == unpadded

    def test_unpad_empty(self):
        assert padding.pkcs5_unpad("") == ""


class TestABPadding:
    """Test the custom AgileBits padding"""
    VECTORS = (
        (b"", 4, b"\x00\x00\x00\x00"),
        (b"ab", 4, b"\x00\x00ab"),
        (b"abcd", 4, b"\x00\x00\x00\x00abcd"),
        (b"\x01\x02", 10, b"\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02"),
    )

    def zeros(self, count):
        return b''.join([six.int2byte(0) for x in range(count)])

    @pytest.mark.parametrize('unpadded, bs, padded', VECTORS)
    def test_pad(self, unpadded, bs, padded):
        assert padding.ab_pad(unpadded, bs, random_generator=self.zeros) == padded

    @pytest.mark.parametrize('unpadded, padded', [(unpadded, padded) for (unpadded, _, padded) in VECTORS])
    def test_unpad(self, unpadded, padded):
        size = len(unpadded)
        assert padding.ab_unpad(padded, size) == unpadded
