import base64
import hashlib

import Crypto.Cipher.AES
import pbkdf2


class BadKeyError(Exception):
    pass

# Algo parameters
BITS = 128
BS = 16


# PKCS#5 padding from
# http://stackoverflow.com/questions/12562021/aes-decryption-padding-with-pkcs5-python
# because I'm too lazy to import the Padding module
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]


def decrypt_key(key_obj, password):
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
    potential_key = unpad(aes_er.decrypt(data))
    validation = base64.b64decode(key_obj['validation'])
    decrypted_validation = decrypt_item(validation, potential_key)
    if decrypted_validation != potential_key:
        raise BadKeyError("Validation did not match")
    return potential_key


def _openssl_kdf(key, salt=('\x00'*16)):
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
    return result[:-16], result[-16:]


def decrypt_item(data, key):
    if data[:8] == 'Salted__':
        salt = data[8:16]
        data = data[16:]
        nkey, iv = _openssl_kdf(key, salt)
    else:
        nkey = hashlib.md5(key).digest()
        iv = '\x00'*16
    aes_er = Crypto.Cipher.AES.new(nkey, Crypto.Cipher.AES.MODE_CBC, iv)
    return unpad(aes_er.decrypt(data))
