import base64
import glob
import os.path

import simplejson

from . import crypt_util
from . import padding
from .item import AItem, CItem

EXPECTED_VERSION_MIN = 30000
EXPECTED_VERSION_MAX = 40000


class _AbstractKeychain(object):
    """Implementation of common keychain logic (MP design, etc)."""

    def __init__(self, path):
        self._open(path)

    def _open(self, path):
        self.base_path = path
        self.check_paths()
        self.check_version()

    def check_paths(self):
        if not(os.path.exists(self.base_path)):
            raise ValueError("Proported 1Password keychain %s does not exist" % self.base_path)

    def check_version(self):
        pass

    def get_by_uuid(self, uuid):
        try:
            return [i for i in self.items if i.uuid == uuid][0]
        except Exception:
            raise KeyError(uuid)


class AKeychain(_AbstractKeychain):
    """Implementation of the classic .agilekeychain storage format"""

    def check_paths(self):
        super(AKeychain, self).check_paths()
        files_to_check = {
            'keys': os.path.join(self.base_path, 'data', 'default', 'encryptionKeys.js')
        }
        for descriptor, expected_path in files_to_check.items():
            if not os.path.exists(expected_path):
                raise Exception("Missing %s, expected at %s" % (descriptor, expected_path))

    def check_version(self):
        super(AKeychain, self).check_version()
        version_file = os.path.join(self.base_path, 'config', 'buildnum')
        if not os.path.exists(version_file):
            return  # AgileBits stopped writing this file in newer versions
        with open(version_file, 'r') as f:
            version_num = int(f.read().strip())
        if version_num < EXPECTED_VERSION_MIN or version_num > EXPECTED_VERSION_MAX:
            raise ValueError("I only understand 1Password builds in [%s,%s]" % (
                EXPECTED_VERSION_MIN,
                EXPECTED_VERSION_MAX
            ))

    def unlock(self, password):
        keys = self._load_keys(password)
        self._load_items(keys)

    def _load_keys(self, password):
        self.keys = {}
        keys_file = os.path.join(self.base_path, 'data', 'default', 'encryptionKeys.js')
        with open(keys_file, 'r') as f:
            data = simplejson.load(f)
        levels = dict((l, v) for (l, v) in data.items() if l != 'list')
        for level, identifier in levels.items():
            keys = [k for k in data['list'] if k.get('identifier') == identifier]
            assert len(keys) == 1, "There should be exactly one key for level %s, got %d" % (level, len(keys))
            key = keys[0]
            self.keys[identifier] = crypt_util.a_decrypt_key(key, password)
        self.levels = levels

    def _load_items(self, keys):
        items = []
        for f in glob.glob(os.path.join(self.base_path, 'data', 'default', '*.1password')):
            items.append(AItem.new_from_file(f, self))
        self.items = items

    def decrypt(self, keyid, string):
        if keyid not in self.keys:
            raise ValueError("Item encrypted with unknown key %s" % keyid)
        string = base64.b64decode(string)
        return crypt_util.a_decrypt_item(string, self.keys[keyid])


class CKeychain(_AbstractKeychain):
    """Implementation of the modern .cloudkeychain format

    Documentation at http://learn.agilebits.com/1Password4/Security/keychain-design.html
    """

    INITIAL_KEY_OFFSET = 12
    KEY_SIZE = 32

    def check_paths(self):
        super(CKeychain, self).check_paths()
        files_to_check = {
            'profile': os.path.join(self.base_path, 'default', 'profile.js'),
        }
        for descriptor, expected_path in files_to_check.items():
            if not os.path.exists(expected_path):
                raise Exception("Missing %s, expected at %s" % (descriptor, expected_path))

    def unlock(self, password):
        self._load_keys(password)
        self._load_items()

    def _load_keys(self, password):
        with open(os.path.join(self.base_path, 'default', 'profile.js'), 'r') as f:
            ds = f.read()[self.INITIAL_KEY_OFFSET:-1]
            data = simplejson.loads(ds)
        super_master_key, super_hmac_key = crypt_util.opdata1_derive_keys(
            password,
            base64.b64decode(data['salt']),
            iterations=int(data['iterations'])
        )
        self.master_key, self.master_hmac = crypt_util.opdata1_decrypt_master_key(
            base64.b64decode(data['masterKey']),
            super_master_key,
            super_hmac_key
        )
        self.overview_key, self.overview_hmac = crypt_util.opdata1_decrypt_master_key(
            base64.b64decode(data['overviewKey']),
            super_master_key,
            super_hmac_key
        )

    def _load_items(self):
        items = []
        items_by_category = {}
        for band in range(0, 15):
            band = hex(band)[-1:].upper()
            path = os.path.join(self.base_path, 'default', 'band_%s.js' % band)
            if not os.path.exists(path):
                continue
            with open(path) as f:
                items.extend(self._load_band_file(f))
        for item in items:
            items_by_category.setdefault(item.category, [])
            items_by_category[item.category].append(item)
        self.items = items
        self.items_by_category = items_by_category

    def _load_band_file(self, f):
        items = []
        band_data = simplejson.loads(f.read()[3:-2])
        for uuid, blob in band_data.items():
            crypt_util.opdata1_verify_overall_hmac(self.overview_hmac, blob)
            items.append(CItem(self, blob))
        return items

    def decrypt_overview(self, blob):
        return crypt_util.opdata1_decrypt_item(
            base64.b64decode(blob),
            self.overview_key,
            self.overview_hmac
        )

    def decrypt_data(self, key_blob, data_blob):
        key, hmac = crypt_util.opdata1_decrypt_key(
            base64.b64decode(key_blob),
            self.master_key,
            self.master_hmac
        )
        return crypt_util.opdata1_decrypt_item(
            base64.b64decode(data_blob),
            key,
            hmac
        )
