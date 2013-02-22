import os.path

import testify as T

import onepassword.keychain

class CloudKeychainIntegrationTestCase(T.TestCase):
    test_file_root = os.path.realpath(os.path.join(__file__, '..', '..', '..', 'data', 'sample.cloudkeychain'))

    def test_open(self):
        c = onepassword.keychain.CKeychain(self.test_file_root)
        c.unlock("fred")


if __name__ == '__main__':
    T.run()
