import base64
import hashlib
import os.path

import Crypto.Cipher.AES
import pbkdf2
import simplejson
import ssl


EXPECTED_VERSION = 30645


class BadKeyError(Exception):
    pass


def _decrypt_key(key_obj, password):
    data = base64.b64decode(key_obj['data'])
    salt = '\x00'*8
    if data[:8] == 'Salted__':
        salt = data[8:16]
        data = data[16:]
    iterations = max(int(key_obj.get('iterations', 1000)), 1000)
    pb_gen = pbkdf2.PBKDF2(password, salt, iterations)
    key = pb_gen.read(16)
    iv = pb_gen.read(16)
    aes_er = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv)
    potential_key = aes_er.decrypt(data)
    validation = base64.b64decode(key_obj['validation'])
    decrypted_validation = _decrypt_item(validation, potential_key)
    if decrypted_validation != potential_key:
        print "Potential key: %r" % potential_key
        print "Validation: %r" % decrypted_validation
        raise BadKeyError("Validation did not match")
    return key_obj, potential_key


def _openssl_kdf(key, salt):
    # TODO: Call m2crypto's EVP_BytesToKey instead
    rounds = 2
    hashes = []
    ks = key + salt
    result = bytes()
    hashes.append(hashlib.md5(ks).digest())
    for i in range(rounds):
        tohash = ks if i == 0 else (hashes[i-1] + ks)
        this_hash = hashlib.md5(tohash).digest()
        hashes.append(this_hash)
        result += this_hash
    print len(result[:-16]), len(result[-16:])
    return result[:-16], result[-16:]


def _decrypt_item(data, key):
    if data[:8] == 'Salted__':
        salt = data[8:16]
        data = data[16:]
        nkey, iv = _openssl_kdf(key, salt)
    else:
        nkey = hashlib.md5(key)
        iv = '\x00'*8
    aes_er = Crypto.Cipher.AES.new(nkey, Crypto.Cipher.AES.MODE_CBC, iv)
    return aes_er.decrypt(data)


class Keychain(object):
    def __init__(self, path):
        self._open(path)

    def _open(self, path):
        self.base_path = path
        if not(os.path.exists(self.base_path)):
            raise ValueError("Proported 1Password key file %s does not exist" % self.base_path)
        self.check_version()

    def check_version(self):
        version_file = os.path.join(self.base_path, 'config', 'buildnum')
        with open(version_file, 'r') as f:
            version_num = int(f.read().strip())
        if version_num != EXPECTED_VERSION:
            raise ValueError("I only understand 1Password build %s" % EXPECTED_VERSION)

    def load_keys(self, password):
        keys_file = os.path.join(self.base_path, 'data', 'default', 'encryptionKeys.js')
        with open(keys_file, 'r') as f:
            data = simplejson.load(f)
        levels = dict((k, v) for (k, v) in data.iteritems() if k != 'list')
        for level, identifier in levels.iteritems():
            keys = [k for k in data['list'] if k.get('identifier') == identifier]
            assert len(keys) == 1, "There should be exactly one key for level %s, got %d" % (level, len(keysS))
            key = keys[0]
            decrypted = _decrypt_key(key, password)

