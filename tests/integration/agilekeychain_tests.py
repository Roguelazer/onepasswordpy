import os.path

from unittest2 import TestCase

import onepassword.keychain


class AgileKeychainIntegrationTestCase(TestCase):
    test_file_root = os.path.realpath(os.path.join(__file__, '..', '..', '..', 'data', 'sample.agilekeychain'))

    def test_open(self):
        c = onepassword.keychain.AKeychain(self.test_file_root)
        c.unlock("george")
        self.assertEqual(len(c.items), 2)

    def test_item_parsing(self):
        c = onepassword.keychain.AKeychain(self.test_file_root)
        c.unlock("george")
        google = c.get_by_uuid('00925AACC28B482ABFE650FCD42F82CD')
        self.assertEqual(google.title, 'Google')
        self.assertEqual(google.decrypt()['fields'][1]['value'], 'test_password')
