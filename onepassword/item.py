import simplejson


class Item(object):
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
        if 'keyID' in data:
            identifier = data['keyID']
        elif 'securityLevel' in data:
            identifier = self.keychain.levels[data['securityLevel']]
        else:
            raise KeyError("Neither keyID or securityLevel present in %s" % self.uuid)
        self._decrypted = self.keychain.decrypt(identifier, data['encrypted'])
