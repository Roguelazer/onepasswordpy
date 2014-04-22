import os.path

from unittest2 import TestCase

import onepassword.keychain

class AgileKeychainIntegrationTestCase(TestCase):
    test_file_root = os.path.realpath(os.path.join(__file__, '..', '..', '..', 'data', 'sample.agilekeychain'))

    def test_open(self):
        c = onepassword.keychain.AKeychain(self.test_file_root)
        c.unlock("george")
