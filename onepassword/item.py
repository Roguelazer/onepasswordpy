import simplejson
import datetime

C_CATEGORIES = {
    '001': 'Login',
    '002': 'Credit Card',
    '003': 'Secure Note',
    '004': 'Identity',
    '005': 'Password',
    '099': 'Tombstone',
    '100': 'Software License',
    '101': 'Bank Account',
    '102': 'Database',
    '103': 'Driver License',
    '104': 'Outdoor License',
    '105': 'Membership',
    '106': 'Passport',
    '107': 'Rewards',
    '108': 'SSN',
    '109': 'Router',
    '110': 'Server',
    '111': 'Email',
}


class AItem(object):
    def __init__(self, keychain):
        self.keychain = keychain

    @classmethod
    def new_from_file(cls, path, keychain):
        o = cls(keychain)
        o.load_from(path)
        return o

    def load_from(self, path):
        with open(path, "r") as f:
            data = simplejson.load(f)
        self.uuid = data['uuid']
        self.data = data
        self.title = self.data['title']
        if 'keyID' in data:
            identifier = data['keyID']
        elif 'securityLevel' in data:
            identifier = self.keychain.levels[data['securityLevel']]
        else:
            raise KeyError("Neither keyID or securityLevel present in %s" % self.uuid)
        self.key_identifier = identifier

    def decrypt(self):
        return simplejson.loads(self.keychain.decrypt(self.key_identifier, self.data['encrypted']))

    def __repr__(self):
        return '%s<uuid=%s, keyid=%s>' % (self.__class__.__name__, self.uuid, self.key_identifier)


class CItem(object):
    def __init__(self, keychain, d):
        self.keychain = keychain
        self.uuid = d['uuid']
        self.category = C_CATEGORIES[d['category']]
        self.updated_at = datetime.datetime.fromtimestamp(d['updated'])
        self.overview = simplejson.loads(self.keychain.decrypt_overview(d['o']))
        self.title = self.overview['title']
        self.encrypted_data = d['k'], d['d']

    def __repr__(self):
        return '%s<uuid=%s, cat=%s>' % (
            self.__class__.__name__,
            self.uuid,
            self.category,
        )

    def decrypt(self):
        return simplejson.loads(self.keychain.decrypt_data(*self.encrypted_data))
