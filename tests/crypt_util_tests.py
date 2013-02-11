import testify as T

from onepassword import crypt_util


class PaddingTestCase(T.TestCase):
    def test_pad(self):
        T.assert_equal(crypt_util.pad("", 1), "\x01")
        T.assert_equal(crypt_util.pad("abcd", 8), "abcd\x04\x04\x04\x04")


if __name__ == '__main__':
    T.run()
