import os.path


EXPECTED_VERSION = 30645


class Keychain(object):
    def __init__(self, path):
        self._open(path)

    def _open(self, path):
        self.base_path = path
        self.check_version(path)

    def check_version(self, path):
        version_file = os.path.join(path, 'config', 'buildnum')
        with open(version_file, 'r') as f:
            version_num = int(f.read().strip())
        if version_num != EXPECTED_VERSION:
            raise ValueError("I only understand 1Password build %s" % EXPECTED_VERSION)
