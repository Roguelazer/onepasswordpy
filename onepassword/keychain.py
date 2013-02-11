import glob
import os.path

import simplejson

from . import crypt_util
from . import padding
from .item import Item

EXPECTED_VERSION = 30645


class AbstractKeychain(object):
    """Implementation of common keychain logic (MP design, etc)."""
    def check_version(self):
        version_file = os.path.join(self.base_path, 'config', 'buildnum')
        with open(version_file, 'r') as f:
            version_num = int(f.read().strip())
        if version_num != EXPECTED_VERSION:
            raise ValueError("I only understand 1Password build %s" % EXPECTED_VERSION)


class AKeychain(AbstractKeychain):
    """Implementation of the classic .agilekeychain storage format"""
    def __init__(self, path):
        self._open(path)

    def _open(self, path):
        self.base_path = path
        if not(os.path.exists(self.base_path)):
            raise ValueError("Proported 1Password key file %s does not exist" % self.base_path)
        self.check_version()

    def unlock(self, password):
        keys = self._load_keys(password)
        self._load_items(keys)

    def _load_keys(self, password):
        self.keys = {}
        keys_file = os.path.join(self.base_path, 'data', 'default', 'encryptionKeys.js')
        with open(keys_file, 'r') as f:
            data = simplejson.load(f)
        levels = dict((k, v) for (k, v) in data.iteritems() if k != 'list')
        for level, identifier in levels.iteritems():
            keys = [k for k in data['list'] if k.get('identifier') == identifier]
            assert len(keys) == 1, "There should be exactly one key for level %s, got %d" % (level, len(keysS))
            key = keys[0]
            self.keys[identifier] = crypt_util.a_decrypt_key(key, password)
        self.levels = levels

    def _load_items(self, keys):
        items = []
        for f in glob.glob(os.path.join(self.base_path, 'data', 'default', '*.1password')):
            items.append(Item.new_from_file(f, self))
        self.items = items

    def decrypt(self, keyid, string):
        if keyid not in self.keys:
            raise ValueError("Item encrypted with unknown key %s" % keyid)
        return crypt_util.a_decrypt_item(padding.pkcs5_pad(string), self.keys[keyid])


class CKeychain(AbstractKeychain):
    """Implementation of the modern .cloudkeychain format

    Documentation at http://learn.agilebits.com/1Password4/Security/keychain-design.html
    """
    pass
