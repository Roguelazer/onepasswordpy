import os.path

import onepassword.keychain


class TestAgileKeychainIntegration:
    test_file_root = os.path.realpath(os.path.join(__file__, '..', '..', '..', 'data', 'sample.agilekeychain'))

    def test_open(self):
        c = onepassword.keychain.AKeychain(self.test_file_root)
        c.unlock("george")
        assert len(c.items) == 2

    def test_item_parsing(self):
        c = onepassword.keychain.AKeychain(self.test_file_root)
        c.unlock("george")
        google = c.get_by_uuid('00925AACC28B482ABFE650FCD42F82CD')
        assert google.title == 'Google'
        assert google.decrypt()['fields'][1]['value'] == 'test_password'
