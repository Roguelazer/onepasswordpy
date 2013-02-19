import os.path

import testify as T


class CloudKeychainIntegrationTestCase(T.TestCase):
    test_file_root = os.path.realpath(os.path.join(__file__, '..', '..', 'data', 'sample_cloudkeychain'))


if __name__ == '__main__':
    T.run()
