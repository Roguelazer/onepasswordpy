import os.path

from unittest2 import TestCase

import onepassword.keychain

class CloudKeychainIntegrationTestCase(TestCase):
    test_file_root = os.path.realpath(os.path.join(__file__, '..', '..', '..', 'data', 'sample.cloudkeychain'))

    def test_open(self):
        c = onepassword.keychain.CKeychain(self.test_file_root)
        c.unlock("fred")
